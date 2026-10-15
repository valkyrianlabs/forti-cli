#include "client.hpp"
#include "process.hpp"

#include <forti/engine/error.hpp>

#include <algorithm>
#include <format>

namespace forti::install {

    using engine::Code;
    using engine::Failure;

    std::string_view to_string(Scope scope) {
        switch (scope) {
            case Scope::user: return "user";
            case Scope::project: return "project";
            case Scope::local: return "local";
        }
        return "user";
    }

    std::optional<Scope> parse_scope(std::string_view text) {
        if (text == "user" || text == "global") return Scope::user;
        if (text == "project") return Scope::project;
        if (text == "local") return Scope::local;
        return std::nullopt;
    }

    bool Entry::is_forti_mcp() const { return fs::path(command).filename() == "forti-mcp"; }

    Context Context::from_environment(const std::optional<fs::path>& project_dir) {
        Context context;
        auto home = env("HOME");
        if (!home) throw Failure(Code::config, "HOME is not set");
        context.home = *home;
        context.project_dir = canonical_or_absolute(project_dir ? *project_dir : fs::current_path());
        if (auto dir = env("CLAUDE_CONFIG_DIR")) context.claude_config_dir = fs::path(*dir);
        if (auto dir = env("CODEX_HOME")) context.codex_home = fs::path(*dir);
        return context;
    }

    // ---- ClientAdapter defaults ----

    bool ClientAdapter::supports(Scope scope) const { return std::ranges::contains(scopes(), scope); }

    Detection ClientAdapter::detect(const Context& context) const {
        Detection detection;
        auto path = find_executable(executable());
        if (!path) return detection;
        detection.found = true;
        detection.path = path->string();
        try {
            auto result = run_process({detection.path, "--version"}, {.cwd = std::nullopt, .timeout = context.timeout});
            if (result.ok()) {
                std::string text = result.out.substr(0, result.out.find('\n'));
                detection.version = text;
            }
        } catch (const Failure&) {
            // Found but not runnable: reported as found without a version.
        }
        return detection;
    }

    std::vector<Action> ClientAdapter::repair(Scope scope, const Entry& desired, const Registration& current,
                                              const Context& context) const {
        return install(scope, desired, current, context);
    }

    std::vector<std::string> ClientAdapter::warnings(Scope, const Context&) const { return {}; }

    std::vector<Action> ClientAdapter::install_skill(Scope scope, std::string_view content, const Context& context) const {
        auto path = skill_file(scope, context);
        std::string text(content);
        std::optional<fs::path> root;
        if (scope != Scope::user) root = context.project_dir;   // .claude/skills, .agents/skills in the project
        return {{"write", std::format("write {}", path.string()), [path, text, root] {
                     if (root) require_inside(path, *root);
                     write_file_atomic(path, text, 0644);
                 }}};
    }

    std::vector<Action> ClientAdapter::remove_skill(Scope scope, const Context& context) const {
        auto path = skill_file(scope, context);
        auto content = read_file(path);
        if (!content || !is_forti_skill(*content)) return {};
        // Remove SKILL.md, then directories left empty: up to the project for project files, up to the
        // client's own directory (~/.claude, ~/.agents) for user files, which is never removed itself.
        auto stop = scope == Scope::user ? path.parent_path().parent_path().parent_path() : context.project_dir;
        bool confined = scope != Scope::user;
        return {{"remove", std::format("remove {}", path.string()), [path, stop, confined] {
                     if (confined) require_inside(path, stop);
                     remove_file(path, stop);
                 }}};
    }

    std::optional<std::string> ClientAdapter::installed_skill(Scope scope, const Context& context) const {
        return read_file(skill_file(scope, context));
    }

    bool is_forti_skill(std::string_view content) {
        if (!content.starts_with("---\n")) return false;
        auto end = content.find("\n---", 3);
        if (end == std::string_view::npos) return false;
        auto frontmatter = content.substr(0, end + 1);
        return frontmatter.find("\nname: forti\n") != std::string_view::npos;
    }

    void run_client(const std::vector<std::string>& argv, const Context& context, const std::optional<fs::path>& cwd) {
        auto result = run_process(argv, {.cwd = cwd, .timeout = context.timeout});
        if (result.ok()) return;
        std::string why = result.timed_out ? std::format("timed out after {} s", context.timeout.count() / 1000)
                                           : std::format("exit status {}", result.status);
        std::string message = result.err.empty() ? result.out : result.err;
        while (!message.empty() && (message.back() == '\n' || message.back() == ' ')) message.pop_back();
        throw Failure(Code::config, std::format("`{}` failed ({}){}{}", display_command(argv), why,
                                                message.empty() ? "" : ": ", message),
                      {{"command", argv}, {"status", result.status}});
    }

    // ---- Registry ----

    const std::vector<std::unique_ptr<ClientAdapter>>& adapters() {
        static const auto all = [] {
            std::vector<std::unique_ptr<ClientAdapter>> list;
            list.push_back(make_claude_adapter());
            list.push_back(make_codex_adapter());
            return list;
        }();
        return all;
    }

    const ClientAdapter* find_adapter(std::string_view id) {
        for (const auto& adapter: adapters())
            if (adapter->id() == id) return adapter.get();
        return nullptr;
    }

}  // namespace forti::install
