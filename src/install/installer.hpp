//
// What `forti mcp install|status|repair|uninstall` decide, independent of the
// terminal: locate forti-mcp, compare each (client, scope) target with what it should hold, and
// produce a plan of Actions that the CLI shows, confirms, and then executes and validates.
//
// Rules the planner enforces: a target already holding the same entry is left untouched
// (idempotent); a `forti` entry pointing somewhere else is a conflict unless --force; uninstall and
// repair touch only entries whose command is a forti-mcp executable; a scope is never widened
// (a project install writes project files only).
//

#ifndef FORTI_INSTALL_INSTALLER_HPP
#define FORTI_INSTALL_INSTALLER_HPP

#include "client.hpp"
#include "workspace.hpp"

#include <forti/engine/error.hpp>

#include <nlohmann/json.hpp>

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace forti::install {

    // The agent skill (skill/forti/SKILL.md), embedded at build time.
    std::string_view skill_text();

    // forti-mcp next to the running forti (a Homebrew Cellar path is mapped to the prefix's bin link),
    // else on PATH. The path is absolute and keeps symlinks.
    std::optional<fs::path> locate_forti_mcp(const std::optional<fs::path>& self = self_executable());

    // Failure(not_found) telling the person how to install forti-mcp. forti never runs a package manager.
    engine::Failure forti_mcp_missing();

    // First line of `forti-mcp --version`, or nullopt when it does not answer.
    std::optional<std::string> forti_mcp_version(const fs::path& path, std::chrono::milliseconds timeout);

    // Throws Failure(usage) unless NAME is a plain profile name (it ends up in client config, so it
    // must not look like an option or carry anything else).
    void validate_profile_name(std::string_view name);

    // The entry forti registers: the absolute forti-mcp path, plus `--profile NAME` when asked.
    Entry desired_entry(const fs::path& forti_mcp, const std::optional<std::string>& profile);

    struct Target {
        const ClientAdapter* client;
        Scope scope;
    };

    struct TargetPlan {
        Target target;
        Registration current;
        std::string state;     // see plan_* below
        std::string message;   // why, for the person
        std::vector<Action> actions;
        std::vector<std::string> warnings;
        std::optional<Entry> desired;

        std::string skill_state;   // "" (not requested), install, update, already_installed, remove, conflict, error
        std::string skill_message;
        fs::path skill_path;
        std::vector<Action> skill_actions;

        std::vector<workspace::Item> workspace;   // workspace scope: the scaffold in the forti home

        [[nodiscard]] bool has_actions() const;
        [[nodiscard]] bool blocked() const;   // conflict or error: the command must fail
    };

    struct InstallRequest {
        std::vector<Target> targets;
        Entry desired;
        bool skill = false;
        bool force = false;
        // Workspace scope: the person agreed to mark the forti home trusted in the global Codex config.
        bool trust_codex_workspace = false;
    };

    // States: install, replace, already_registered, conflict, unsupported, error. Workspace targets
    // also get the scaffold (workspace.hpp); its conflicts are reported, never overwritten, and do not
    // block the registration.
    std::vector<TargetPlan> plan_install(const InstallRequest& request, const Context& context);

    // States: remove, not_registered, foreign (not forti-mcp; kept unless force), unsupported, error.
    // Workspace targets also remove forti's scaffold files (never config.json, credentials, certs or state).
    std::vector<TargetPlan> plan_uninstall(const std::vector<Target>& targets, bool keep_skill, bool force,
                                           const Context& context);

    // States: repair (command missing, or a versioned Homebrew Cellar path), ok, differs (another
    // working forti-mcp: left alone), custom (extra keys: left alone), foreign, not_registered, error.
    std::vector<TargetPlan> plan_repair(const std::vector<Target>& targets, const fs::path& forti_mcp,
                                        const Context& context);

    // Runs every plan's actions in order. A failure marks that target "failed" and moves on to the
    // next target. Installs and repairs are then validated by reading the status back.
    void execute(std::vector<TargetPlan>& plans, const Context& context);

    nlohmann::json to_json(const TargetPlan& plan);

    // `forti mcp status`: clients (detected or not), every scope they support, skill state, workspace health.
    nlohmann::json status_report(const std::optional<fs::path>& forti_mcp, const Context& context);

    // Every supported (client, scope) pair for these clients.
    std::vector<Target> all_targets(const std::vector<const ClientAdapter*>& clients, const std::optional<Scope>& scope);

}  // namespace forti::install

#endif  // FORTI_INSTALL_INSTALLER_HPP
