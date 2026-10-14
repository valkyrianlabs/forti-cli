//
// OpenAI Codex CLI. The user ("global") scope is $CODEX_HOME/config.toml (default ~/.codex), changed
// only through `codex mcp add/remove` (which keep the rest of the file) and read with
// `codex mcp get forti --json` (spawns nothing). Project scope is `<project>/.codex/config.toml`,
// which the CLI cannot write: forti edits only the [mcp_servers.forti] block of it. Codex loads a
// project config only for trusted projects, and forti never adds a trust entry (that would be a
// silent change to the global config), it warns instead.
//
// Skills: Codex 0.162.1 loads $CODEX_HOME/skills, ~/.agents/skills, and <repo>/.codex/skills and
// <repo>/.agents/skills (verified with `codex debug prompt-input`, docs/agent-integration.md).
// forti uses the documented ~/.agents/skills and <project>/.agents/skills.
//

#include "client.hpp"
#include "process.hpp"
#include "toml_table.hpp"

#include <forti/engine/error.hpp>

#include <nlohmann/json.hpp>

#include <format>

namespace forti::install {

    using engine::Code;
    using engine::Failure;

    namespace {

        class CodexAdapter final : public ClientAdapter {
        public:
            [[nodiscard]] std::string_view id() const override { return "codex"; }
            [[nodiscard]] std::string_view display_name() const override { return "Codex"; }
            [[nodiscard]] std::string_view executable() const override { return "codex"; }
            [[nodiscard]] std::vector<Scope> scopes() const override { return {Scope::user, Scope::project}; }

            [[nodiscard]] Registration status(Scope scope, const Context& context) const override {
                Registration registration;
                try {
                    if (scope == Scope::project) {
                        auto path = project_config(context);
                        registration.location = path.string();
                        if (auto text = read_file(path)) registration.entry = toml::read_server(*text, server_name);
                        if (!trusted(context))
                            registration.notes.push_back(std::format("Codex ignores {} until the project is trusted", path.string()));
                    } else {
                        registration.location = global_config(context).string();
                        registration.entry = global_entry(context);
                    }
                } catch (const Failure& failure) {
                    registration.error = failure.what();
                }
                registration.registered = registration.entry.has_value();
                return registration;
            }

            [[nodiscard]] std::vector<Action> install(Scope scope, const Entry& desired, const Registration& current,
                                                      const Context& context) const override {
                if (scope == Scope::project) {
                    auto path = project_config(context);
                    std::string summary = std::format("{} {} ({} [mcp_servers.{}])", fs::exists(path) ? "edit" : "create",
                                                      path.string(), current.registered ? "replace" : "add", server_name);
                    return {{"write", summary, [path, desired] {
                                 auto text = read_file(path).value_or("");
                                 auto updated = toml::set_table(text, {"mcp_servers", std::string(server_name)},
                                                                toml::render_server(server_name, desired));
                                 write_file_atomic(path, updated, 0644);
                             }}};
                }
                auto exe = require_cli(context);
                // `codex mcp add` replaces an existing table of the same name in one step.
                std::vector<std::string> argv{exe, "mcp", "add", std::string(server_name), "--", desired.command};
                argv.insert(argv.end(), desired.args.begin(), desired.args.end());
                auto cwd = neutral_dir(context);
                return {{"run", display_command(argv), [argv, cwd, context] { run_client(argv, context, cwd); }}};
            }

            [[nodiscard]] std::vector<Action> uninstall(Scope scope, const Registration& current,
                                                        const Context& context) const override {
                if (!current.registered) return {};
                if (scope == Scope::project) {
                    auto path = project_config(context);
                    auto stop = context.project_dir;
                    return {{"write", std::format("edit {} (remove [mcp_servers.{}])", path.string(), server_name), [path, stop] {
                                 auto text = read_file(path).value_or("");
                                 auto updated = toml::remove_table(text, {"mcp_servers", std::string(server_name)});
                                 if (updated == text) return;
                                 // A file that held only our table goes away (with .codex/ if then empty).
                                 if (updated.find_first_not_of(" \t\r\n") == std::string::npos) remove_file(path, stop);
                                 else write_file_atomic(path, updated);
                             }}};
                }
                std::vector<std::string> argv{require_cli(context), "mcp", "remove", std::string(server_name)};
                auto cwd = neutral_dir(context);
                return {{"run", display_command(argv), [argv, cwd, context] { run_client(argv, context, cwd); }}};
            }

            [[nodiscard]] std::vector<std::string> warnings(Scope scope, const Context& context) const override {
                if (scope != Scope::project || trusted(context)) return {};
                return {std::format("Codex loads {} only for trusted projects. forti does not change trust (that is a global "
                                    "setting); Codex asks to trust the project when you start it there",
                                    project_config(context).string())};
            }

            [[nodiscard]] fs::path skill_file(Scope scope, const Context& context) const override {
                auto root = scope == Scope::user ? context.home : context.project_dir;
                return root / ".agents" / "skills" / "forti" / "SKILL.md";
            }

        private:
            static fs::path codex_home(const Context& context) { return context.codex_home ? *context.codex_home : context.home / ".codex"; }
            static fs::path global_config(const Context& context) { return codex_home(context) / "config.toml"; }
            static fs::path project_config(const Context& context) { return context.project_dir / ".codex" / "config.toml"; }

            // `codex mcp get` merges a trusted project's config from its cwd; run it where there is none.
            static std::optional<fs::path> neutral_dir(const Context& context) {
                std::error_code ec;
                auto home = codex_home(context);
                return fs::is_directory(home, ec) ? home : fs::path("/");
            }

            static bool trusted(const Context& context) {
                try {
                    auto text = read_file(global_config(context));
                    if (!text) return false;
                    return toml::project_trusted(*text, context.project_dir.string());
                } catch (const Failure&) {
                    return false;
                }
            }

            [[nodiscard]] std::string require_cli(const Context& context) const {
                auto path = find_executable(executable());
                if (!path) throw Failure(Code::config, "Codex (`codex`) is not on PATH; install it or use --scope project");
                std::error_code ec;
                if (context.codex_home && !fs::is_directory(*context.codex_home, ec))
                    throw Failure(Code::config, std::format("CODEX_HOME points to {}, which does not exist (codex refuses to run); "
                                                            "create it or unset CODEX_HOME", context.codex_home->string()));
                return path->string();
            }

            [[nodiscard]] std::optional<Entry> global_entry(const Context& context) const {
                auto exe = find_executable(executable());
                if (!exe) {
                    // No CLI: read the file instead, so status still works.
                    auto text = read_file(global_config(context));
                    return text ? toml::read_server(*text, server_name) : std::nullopt;
                }
                std::error_code ec;
                if (context.codex_home && !fs::is_directory(*context.codex_home, ec))
                    throw Failure(Code::config, std::format("CODEX_HOME ({}) does not exist", context.codex_home->string()));
                auto result = run_process({exe->string(), "mcp", "get", std::string(server_name), "--json"},
                                          {.cwd = neutral_dir(context), .timeout = context.timeout});
                if (!result.ok()) {
                    if (!result.timed_out && (result.err + result.out).find("No MCP server named") != std::string::npos) return std::nullopt;
                    throw Failure(Code::config, std::format("`codex mcp get {} --json` failed (exit status {})", server_name, result.status));
                }
                auto json = nlohmann::json::parse(result.out, nullptr, false);
                if (json.is_discarded() || !json.contains("transport"))
                    throw Failure(Code::config, "unexpected output from `codex mcp get --json`");
                const auto& transport = json["transport"];
                Entry entry;
                entry.command = transport.value("command", "");
                if (transport.contains("args") && transport["args"].is_array())
                    for (const auto& arg: transport["args"])
                        if (arg.is_string()) entry.args.push_back(arg.get<std::string>());
                auto non_empty = [&](const char* key) {
                    return transport.contains(key) && !transport[key].is_null() && !transport[key].empty();
                };
                entry.extra = transport.value("type", "stdio") != "stdio" || non_empty("env") || non_empty("env_vars") ||
                              non_empty("cwd") || entry.command.empty();
                return entry;
            }
        };

    }  // namespace

    std::unique_ptr<ClientAdapter> make_codex_adapter() { return std::make_unique<CodexAdapter>(); }

}  // namespace forti::install
