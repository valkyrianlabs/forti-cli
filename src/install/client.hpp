//
// AI client adapters for `forti install mcp`. Each client (Claude Code, Codex, ...) is one class
// implementing ClientAdapter in its own file plus one line in registry.cpp; the installer only talks
// to this interface. Adapters never execute anything while planning: install/uninstall/repair return
// Actions (an exact description plus a function), so the installer can show them, ask, dry-run, then run.
//

#ifndef FORTI_INSTALL_CLIENT_HPP
#define FORTI_INSTALL_CLIENT_HPP

#include "files.hpp"

#include <chrono>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace forti::install {

    // The name every client registers forti-mcp under.
    inline constexpr std::string_view server_name = "forti";

    // workspace is project scope in the forti home (~/.forti, $FORTI_HOME): the recommended place for
    // the firewall tools, so an agent started anywhere else does not get them (workspace.hpp).
    enum class Scope { user, project, local, workspace };
    std::string_view to_string(Scope scope);
    std::optional<Scope> parse_scope(std::string_view text);
    // project and workspace: files in a directory (.mcp.json, .codex/config.toml, skills).
    inline bool in_directory(Scope scope) { return scope == Scope::project || scope == Scope::workspace; }

    // A stdio MCP server entry, as far as forti cares: the command and its arguments. `extra` notes
    // keys beyond those (env, cwd, timeouts...), which forti never writes.
    struct Entry {
        std::string command;
        std::vector<std::string> args;
        bool extra = false;

        // Same command and arguments: re-installing it changes nothing.
        [[nodiscard]] bool same_target(const Entry& other) const { return command == other.command && args == other.args; }
        // The command is a forti-mcp executable (any path), so the entry is ours to repair or remove.
        [[nodiscard]] bool is_forti_mcp() const;
    };

    struct Registration {
        bool registered = false;
        std::optional<Entry> entry;
        std::string location;              // where the entry lives ("~/.claude.json (user)", a file path)
        std::vector<std::string> notes;    // facts worth showing (approval needed, project not trusted...)
        std::optional<std::string> error;  // the state could not be determined
    };

    struct Detection {
        bool found = false;
        std::string path;      // the executable on PATH
        std::string version;   // first line of `--version`
    };

    // Everything adapters may depend on, gathered once (tests build it by hand).
    struct Context {
        fs::path home;
        fs::path project_dir;                        // absolute and canonical
        fs::path forti_home;                         // the forti home, the workspace scope's directory
        std::optional<fs::path> claude_config_dir;   // $CLAUDE_CONFIG_DIR
        std::optional<fs::path> codex_home;          // $CODEX_HOME
        std::chrono::milliseconds timeout{30'000};   // per client CLI call

        // From $HOME, $CLAUDE_CONFIG_DIR, $CODEX_HOME, $FORTI_HOME; the project directory defaults to the cwd.
        static Context from_environment(const std::optional<fs::path>& project_dir = std::nullopt);

        // The context a scope's files live in: for workspace, the project directory is the forti home.
        [[nodiscard]] Context for_scope(Scope scope) const;
    };

    struct Action {
        std::string kind;      // "run" (a client CLI call), "write", "remove"
        std::string summary;   // exactly what happens: the command line, or the file and the change
        std::function<void()> run;   // throws forti::engine::Failure
    };

    class ClientAdapter {
    public:
        virtual ~ClientAdapter() = default;

        [[nodiscard]] virtual std::string_view id() const = 0;             // "claude"
        [[nodiscard]] virtual std::string_view display_name() const = 0;   // "Claude Code"
        [[nodiscard]] virtual std::string_view executable() const = 0;     // "claude"
        [[nodiscard]] virtual std::vector<Scope> scopes() const = 0;
        [[nodiscard]] bool supports(Scope scope) const;

        // Default: the executable on PATH and its `--version`.
        [[nodiscard]] virtual Detection detect(const Context& context) const;

        // Whether `forti` is registered in this scope, read without starting any MCP server.
        [[nodiscard]] virtual Registration status(Scope scope, const Context& context) const = 0;

        // Actions that make the scope hold exactly `desired`, replacing `current` when it is
        // registered (the installer has already decided that replacing is allowed).
        [[nodiscard]] virtual std::vector<Action> install(Scope scope, const Entry& desired, const Registration& current,
                                                          const Context& context) const = 0;
        [[nodiscard]] virtual std::vector<Action> uninstall(Scope scope, const Registration& current,
                                                            const Context& context) const = 0;
        // Points an existing registration at `desired`. Default: install() (which replaces).
        [[nodiscard]] virtual std::vector<Action> repair(Scope scope, const Entry& desired, const Registration& current,
                                                         const Context& context) const;

        // Warnings shown before an install in this scope (e.g. Codex project trust).
        [[nodiscard]] virtual std::vector<std::string> warnings(Scope scope, const Context& context) const;

        // ---- Agent skill ----
        // Where this client loads the forti skill from for a scope.
        [[nodiscard]] virtual fs::path skill_file(Scope scope, const Context& context) const = 0;
        // Defaults write/remove skill_file(); remove only touches a file whose frontmatter is `name: forti`.
        [[nodiscard]] virtual std::vector<Action> install_skill(Scope scope, std::string_view content,
                                                                const Context& context) const;
        [[nodiscard]] virtual std::vector<Action> remove_skill(Scope scope, const Context& context) const;
        // nullopt: not installed; otherwise the file content.
        [[nodiscard]] std::optional<std::string> installed_skill(Scope scope, const Context& context) const;
    };

    // Every known client, in display order (client.cpp). A new client is one adapter file plus one line there.
    const std::vector<std::unique_ptr<ClientAdapter>>& adapters();
    const ClientAdapter* find_adapter(std::string_view id);

    // Factories, one per adapter file.
    std::unique_ptr<ClientAdapter> make_claude_adapter();
    std::unique_ptr<ClientAdapter> make_codex_adapter();

    // Whether a SKILL.md was written by forti (frontmatter `name: forti`), so it is ours to remove.
    bool is_forti_skill(std::string_view content);

    // Runs a client CLI command and throws Failure(config) with the client's stderr when it fails.
    void run_client(const std::vector<std::string>& argv, const Context& context,
                    const std::optional<fs::path>& cwd = std::nullopt);

}  // namespace forti::install

#endif  // FORTI_INSTALL_CLIENT_HPP
