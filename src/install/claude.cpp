//
// Claude Code. local and user scopes live in ~/.claude.json (or $CLAUDE_CONFIG_DIR/.claude.json),
// which running sessions rewrite constantly, so forti changes them only through the official CLI
// (`claude mcp add/remove -s <scope>`) and only reads the file for status. `claude mcp get/list`
// are not used: both start the server to health-check it (get waits up to 30 s). Project scope is
// `<project>/.mcp.json`, edited directly so other servers and keys (even `$schema`) survive.
//

#include "client.hpp"
#include "mcp_json.hpp"
#include "process.hpp"

#include <forti/engine/error.hpp>

#include <format>

namespace forti::install {

    using engine::Code;
    using engine::Failure;

    namespace {

        class ClaudeAdapter final : public ClientAdapter {
        public:
            [[nodiscard]] std::string_view id() const override { return "claude"; }
            [[nodiscard]] std::string_view display_name() const override { return "Claude Code"; }
            [[nodiscard]] std::string_view executable() const override { return "claude"; }
            [[nodiscard]] std::vector<Scope> scopes() const override { return {Scope::local, Scope::user, Scope::project}; }

            [[nodiscard]] Registration status(Scope scope, const Context& context) const override {
                Registration registration;
                try {
                    if (scope == Scope::project) {
                        auto path = mcp_json_path(context);
                        registration.location = path.string();
                        auto text = read_file(path);
                        if (text) registration.entry = mcp_json::find_server(mcp_json::parse(*text, path.string()), server_name);
                        registration.notes.emplace_back("Claude Code asks each person to approve project servers on first use");
                        if (project_server_disabled(context))
                            registration.notes.emplace_back("you declined this project's forti server in Claude Code; re-enable it with /mcp");
                    } else {
                        auto path = claude_json_path(context);
                        registration.location = scope == Scope::user
                                ? std::format("{} (user)", path.string())
                                : std::format("{} [project: {}] (local)", path.string(), context.project_dir.string());
                        auto document = read_claude_json(context);
                        if (document) {
                            const nlohmann::ordered_json* servers = nullptr;
                            if (scope == Scope::user) {
                                if (auto it = document->find("mcpServers"); it != document->end()) servers = &*it;
                            } else if (auto projects = document->find("projects"); projects != document->end() && projects->is_object()) {
                                auto project = projects->find(context.project_dir.string());
                                if (project != projects->end() && project->is_object())
                                    if (auto it = project->find("mcpServers"); it != project->end()) servers = &*it;
                            }
                            if (servers) registration.entry = mcp_json::find(*servers, server_name);
                        }
                    }
                } catch (const Failure& failure) {
                    registration.error = failure.what();
                }
                registration.registered = registration.entry.has_value();
                return registration;
            }

            [[nodiscard]] std::vector<Action> install(Scope scope, const Entry& desired, const Registration& current,
                                                      const Context& context) const override {
                if (scope == Scope::project) return write_project(desired, current.registered, context);
                auto exe = require_cli();
                std::vector<Action> actions;
                auto cwd = scope == Scope::local ? std::optional(context.project_dir) : std::nullopt;
                if (current.registered) actions.push_back(remove_action(exe, scope, context));
                // `add` refuses an existing name (exit 1), hence remove first. If add then fails, put the
                // old entry back, unless it carried env/other keys argv cannot reproduce without secrets.
                std::vector<std::string> argv = add_argv(exe, scope, desired);
                std::optional<std::vector<std::string>> restore;
                if (current.registered && current.entry && !current.entry->extra && !current.entry->command.empty())
                    restore = add_argv(exe, scope, *current.entry);
                actions.push_back({"run", display_command(argv), [argv, restore, cwd, context] {
                                       try {
                                           run_client(argv, context, cwd);
                                       } catch (const Failure&) {
                                           if (restore) {
                                               try {
                                                   run_client(*restore, context, cwd);
                                               } catch (const Failure&) {
                                               }
                                           }
                                           throw;
                                       }
                                   }});
                return actions;
            }

            [[nodiscard]] std::vector<Action> uninstall(Scope scope, const Registration& current,
                                                        const Context& context) const override {
                if (!current.registered) return {};
                if (scope == Scope::project) {
                    auto path = mcp_json_path(context);
                    return {{"write", std::format("edit {} (remove mcpServers.{})", path.string(), server_name), [path] {
                                 auto text = read_file(path).value_or("");
                                 auto document = mcp_json::parse(text, path.string());
                                 if (!mcp_json::remove(document, server_name)) return;
                                 if (mcp_json::is_empty(document)) remove_file(path);
                                 else write_file_atomic(path, mcp_json::dump(document, text));
                             }}};
                }
                return {remove_action(require_cli(), scope, context)};
            }

            [[nodiscard]] std::vector<std::string> warnings(Scope scope, const Context&) const override {
                if (scope == Scope::project)
                    return {"Claude Code asks each person to approve project servers (.mcp.json) the first time they open the project"};
                return {};
            }

            [[nodiscard]] fs::path skill_file(Scope scope, const Context& context) const override {
                if (scope == Scope::user)
                    return (context.claude_config_dir ? *context.claude_config_dir : context.home / ".claude") / "skills" / "forti" / "SKILL.md";
                // local has no skill location of its own: the project's skills directory is the closest.
                return context.project_dir / ".claude" / "skills" / "forti" / "SKILL.md";
            }

        private:
            static fs::path claude_json_path(const Context& context) {
                return context.claude_config_dir ? *context.claude_config_dir / ".claude.json" : context.home / ".claude.json";
            }
            static fs::path mcp_json_path(const Context& context) { return context.project_dir / ".mcp.json"; }

            // Read-only. Claude rewrites the file atomically, but retry once in case a write raced us.
            static std::optional<nlohmann::ordered_json> read_claude_json(const Context& context) {
                auto path = claude_json_path(context);
                for (int attempt = 0;; ++attempt) {
                    auto text = read_file(path);
                    if (!text) return std::nullopt;
                    auto document = nlohmann::ordered_json::parse(*text, nullptr, false);
                    if (!document.is_discarded() && document.is_object()) return document;
                    if (attempt == 1) throw Failure(Code::config, std::format("cannot parse {}", path.string()));
                }
            }

            static bool project_server_disabled(const Context& context) {
                try {
                    auto document = read_claude_json(context);
                    if (!document) return false;
                    auto projects = document->find("projects");
                    if (projects == document->end() || !projects->is_object()) return false;
                    auto project = projects->find(context.project_dir.string());
                    if (project == projects->end() || !project->is_object()) return false;
                    auto disabled = project->find("disabledMcpjsonServers");
                    if (disabled == project->end() || !disabled->is_array()) return false;
                    for (const auto& name: *disabled)
                        if (name == server_name) return true;
                } catch (const Failure&) {
                }
                return false;
            }

            [[nodiscard]] std::string require_cli() const {
                auto path = find_executable(executable());
                if (!path) throw Failure(Code::config, "Claude Code (`claude`) is not on PATH; install it or use --scope project");
                return path->string();
            }

            static std::vector<std::string> add_argv(const std::string& exe, Scope scope, const Entry& entry) {
                std::vector<std::string> argv{exe, "mcp", "add", "-s", std::string(to_string(scope)), std::string(server_name), "--", entry.command};
                argv.insert(argv.end(), entry.args.begin(), entry.args.end());
                return argv;
            }

            static Action remove_action(const std::string& exe, Scope scope, const Context& context) {
                std::vector<std::string> argv{exe, "mcp", "remove", "-s", std::string(to_string(scope)), std::string(server_name)};
                auto cwd = scope == Scope::local ? std::optional(context.project_dir) : std::nullopt;
                return {"run", display_command(argv), [argv, cwd, context] { run_client(argv, context, cwd); }};
            }

            static std::vector<Action> write_project(const Entry& desired, bool replace, const Context& context) {
                auto path = mcp_json_path(context);
                std::string summary = std::format("{} {} ({} mcpServers.{})", fs::exists(path) ? "edit" : "create", path.string(),
                                                  replace ? "replace" : "add", server_name);
                return {{"write", summary, [path, desired] {
                             // Re-read at execution time: never write back a stale copy.
                             auto text = read_file(path).value_or("");
                             auto document = mcp_json::parse(text, path.string());
                             mcp_json::upsert(document, server_name, desired);
                             write_file_atomic(path, mcp_json::dump(document, text), 0644);
                         }}};
            }
        };

    }  // namespace

    std::unique_ptr<ClientAdapter> make_claude_adapter() { return std::make_unique<ClaudeAdapter>(); }

}  // namespace forti::install
