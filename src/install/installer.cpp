#include "installer.hpp"
#include "process.hpp"

#include "forti_skill.hpp"   // generated from skill/forti/SKILL.md

#include <algorithm>
#include <format>
#include <map>

namespace forti::install {

    using engine::Code;
    using engine::Failure;
    using json = nlohmann::json;

    std::string_view skill_text() { return embedded_skill; }

    // ---- forti-mcp ----

    std::optional<fs::path> locate_forti_mcp(const std::optional<fs::path>& self) {
        if (self) {
            std::string text = self->string();
            if (auto cellar = text.find("/Cellar/"); cellar != std::string::npos) {
                // Homebrew: <prefix>/Cellar/forti-cli/<version>/bin/forti. The Cellar path changes on every
                // upgrade; <prefix>/bin/forti-mcp is the link that keeps working.
                auto link = fs::path(text.substr(0, cellar)) / "bin" / "forti-mcp";
                if (is_executable(link)) return link;
            } else if (auto sibling = self->parent_path() / "forti-mcp"; is_executable(sibling)) {
                return sibling;
            }
        }
        return find_executable("forti-mcp");
    }

    Failure forti_mcp_missing() {
        static constexpr std::string_view brew = "brew install valkyrianlabs/tap/forti-mcp";
        static constexpr std::string_view apt = "sudo apt install forti-mcp   (after adding the apt.valkyrianlabs.com repository)";
        return Failure(Code::not_found,
                       "forti-mcp is not installed (looked next to forti and on PATH). Install it, then run this again",
                       {{"hint", std::format("macOS: {}\n        Debian/Ubuntu: {}", brew, apt)},
                        {"install", {{"homebrew", brew}, {"apt", "sudo apt install forti-mcp"}}}});
    }

    std::optional<std::string> forti_mcp_version(const fs::path& path, std::chrono::milliseconds timeout) {
        try {
            auto result = run_process({path.string(), "--version"}, {.cwd = std::nullopt, .timeout = timeout});
            if (!result.ok()) return std::nullopt;
            auto line = result.out.substr(0, result.out.find('\n'));
            if (line.empty()) return std::nullopt;
            return line;
        } catch (const Failure&) {
            return std::nullopt;
        }
    }

    void validate_profile_name(std::string_view name) {
        bool ok = !name.empty() && name.size() <= 64 && name.front() != '-' &&
                  std::ranges::all_of(name, [](char c) {
                      return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' ||
                             c == '-';
                  });
        // The engine's rule ([A-Za-z0-9_-]{1,64}): forti-mcp refuses any other --profile at startup.
        if (!ok) throw Failure(Code::usage, "--profile expects a profile name (letters, digits, '_', '-')");
    }

    Entry desired_entry(const fs::path& forti_mcp, const std::optional<std::string>& profile) {
        Entry entry{forti_mcp.string(), {}, false};
        if (profile) entry.args = {"--profile", *profile};
        return entry;
    }

    // ---- Planning ----

    bool TargetPlan::blocked() const {
        return state == "conflict" || state == "error" || state == "failed" || skill_state == "conflict" ||
               skill_state == "error" || std::ranges::any_of(workspace, [](const auto& item) { return item.state == "error"; });
    }

    bool TargetPlan::has_actions() const {
        return !actions.empty() || !skill_actions.empty() ||
               std::ranges::any_of(workspace, [](const auto& item) { return !item.actions.empty(); });
    }

    namespace {

        std::string describe(const Entry& entry) {
            std::vector<std::string> argv{entry.command};
            argv.insert(argv.end(), entry.args.begin(), entry.args.end());
            return display_command(argv) + (entry.extra ? " (with other settings)" : "");
        }

        bool same_file(const std::string& a, const std::string& b) {
            std::error_code ec;
            return fs::equivalent(a, b, ec);
        }

        TargetPlan start(const Target& target, const Context& context) {
            TargetPlan plan;
            plan.target = target;
            plan.skill_path = target.client->supports(target.scope) ? target.client->skill_file(target.scope, context) : fs::path();
            if (!target.client->supports(target.scope)) {
                plan.state = "unsupported";
                plan.message = std::format("{} has no {} scope", target.client->display_name(), to_string(target.scope));
                return plan;
            }
            plan.current = target.client->status(target.scope, context);
            if (plan.current.error) {
                plan.state = "error";
                plan.message = *plan.current.error;
            }
            return plan;
        }

        void plan_skill_install(TargetPlan& plan, bool force, const Context& context) {
            const auto& [client, scope] = plan.target;
            try {
                auto existing = client->installed_skill(scope, context);
                if (existing && *existing == skill_text()) {
                    plan.skill_state = "already_installed";
                    return;
                }
                if (existing && !is_forti_skill(*existing) && !force) {
                    plan.skill_state = "conflict";
                    plan.skill_message = std::format("{} exists and was not written by forti; pass --force to replace it",
                                                     plan.skill_path.string());
                    return;
                }
                plan.skill_actions = client->install_skill(scope, skill_text(), context);
                plan.skill_state = existing ? "update" : "install";
            } catch (const Failure& failure) {
                plan.skill_state = "error";
                plan.skill_message = failure.what();
            }
        }

        template<typename Make>
        void add_actions(TargetPlan& plan, Make&& make) {
            try {
                plan.actions = make();
            } catch (const Failure& failure) {
                plan.state = "error";
                plan.message = failure.what();
                plan.actions.clear();
            }
        }

    }  // namespace

    std::vector<TargetPlan> plan_install(const InstallRequest& request, const Context& context) {
        std::vector<TargetPlan> plans;
        bool shared_done = false;
        for (const auto& target: request.targets) {
            auto plan = start(target, context);
            plan.desired = request.desired;
            if (plan.state.empty()) {
                const auto& current = plan.current;
                if (current.registered && current.entry->same_target(request.desired)) {
                    plan.state = "already_registered";
                    plan.message = "already registered";
                } else if (current.registered && !request.force) {
                    plan.state = "conflict";
                    plan.message = std::format("forti is already registered here as `{}`{}; pass --force to replace it",
                                               describe(*current.entry),
                                               current.entry->command != request.desired.command &&
                                                               same_file(current.entry->command, request.desired.command)
                                                       ? " (the same executable through another path)" : "");
                } else {
                    plan.state = current.registered ? "replace" : "install";
                    add_actions(plan, [&] { return target.client->install(target.scope, request.desired, current, context); });
                    if (plan.state != "error") plan.warnings = target.client->warnings(target.scope, context);
                }
            }
            if (request.skill && plan.state != "unsupported") plan_skill_install(plan, request.force, context);
            if (target.scope == Scope::workspace && !plan.blocked() && plan.state != "unsupported") {
                // The first workspace target creates the home (before .mcp.json lands in it) and AGENTS.md.
                bool first = !shared_done;
                shared_done = true;
                if (first)
                    if (auto action = workspace::create_home(context)) plan.actions.insert(plan.actions.begin(), std::move(*action));
                plan.workspace = workspace::plan_install(*target.client, first, request.trust_codex_workspace, context);
            }
            plans.push_back(std::move(plan));
        }
        return plans;
    }

    std::vector<TargetPlan> plan_uninstall(const std::vector<Target>& targets, bool keep_skill, bool force,
                                           const Context& context) {
        std::vector<TargetPlan> plans;
        bool shared_done = false;
        for (const auto& target: targets) {
            auto plan = start(target, context);
            if (plan.state.empty()) {
                const auto& current = plan.current;
                if (!current.registered) {
                    plan.state = "not_registered";
                    plan.message = "not registered";
                } else if (!current.entry->is_forti_mcp() && !force) {
                    plan.state = "foreign";
                    plan.message = std::format("the `forti` entry runs `{}`, not forti-mcp; left alone (--force removes it)",
                                               describe(*current.entry));
                } else {
                    plan.state = "remove";
                    add_actions(plan, [&] { return target.client->uninstall(target.scope, current, context); });
                }
            }
            if (!keep_skill && plan.state != "unsupported") {
                try {
                    auto existing = target.client->installed_skill(target.scope, context);
                    if (existing && is_forti_skill(*existing)) {
                        plan.skill_actions = target.client->remove_skill(target.scope, context);
                        plan.skill_state = "remove";
                    }
                } catch (const Failure& failure) {
                    plan.skill_state = "error";
                    plan.skill_message = failure.what();
                }
            }
            if (target.scope == Scope::workspace && (plan.state == "remove" || plan.state == "not_registered")) {
                // AGENTS.md serves every client: it goes with the last workspace registration.
                bool shared = !shared_done && std::ranges::none_of(adapters(), [&](const auto& adapter) {
                    bool leaving = std::ranges::any_of(targets, [&](const Target& t) {
                        return t.client == adapter.get() && t.scope == Scope::workspace;
                    });
                    return !leaving && adapter->status(Scope::workspace, context).registered;
                });
                shared_done = true;
                plan.workspace = workspace::plan_uninstall(*target.client, shared, context);
            }
            plans.push_back(std::move(plan));
        }
        return plans;
    }

    std::vector<TargetPlan> plan_repair(const std::vector<Target>& targets, const fs::path& forti_mcp,
                                        const Context& context) {
        std::vector<TargetPlan> plans;
        for (const auto& target: targets) {
            auto plan = start(target, context);
            if (plan.state.empty()) {
                const auto& current = plan.current;
                if (!current.registered) {
                    plan.state = "not_registered";
                    plan.message = "not registered";
                } else if (!current.entry->is_forti_mcp()) {
                    plan.state = "foreign";
                    plan.message = std::format("the `forti` entry runs `{}`, not forti-mcp; left alone", describe(*current.entry));
                } else {
                    const auto& entry = *current.entry;
                    bool runnable = is_executable(entry.command);
                    bool versioned = entry.command.find("/Cellar/") != std::string::npos;
                    if (entry.command == forti_mcp.string()) {
                        plan.state = runnable ? "ok" : "repair";
                        plan.message = runnable ? "ok" : "the registered forti-mcp is not executable";
                    } else if (runnable && !versioned) {
                        plan.state = "differs";
                        plan.message = std::format("registered `{}` works but is not the installed {}; "
                                                   "`forti install mcp --force` switches it", entry.command, forti_mcp.string());
                    } else if (entry.extra) {
                        plan.state = "custom";
                        plan.message = std::format("`{}` is broken but the entry has custom settings; re-register it with "
                                                   "`forti install mcp --force`", entry.command);
                    } else {
                        plan.state = "repair";
                        plan.message = runnable ? std::format("{} is a versioned Homebrew path that breaks on upgrade", entry.command)
                                                : std::format("{} no longer exists", entry.command);
                    }
                    if (plan.state == "repair") {
                        plan.desired = Entry{forti_mcp.string(), entry.args, false};
                        add_actions(plan, [&] { return target.client->repair(target.scope, *plan.desired, current, context); });
                    }
                }
            }
            if (plan.state != "unsupported") {
                // A forti skill from an older forti is refreshed; a missing one is not added.
                try {
                    auto existing = target.client->installed_skill(target.scope, context);
                    if (existing && is_forti_skill(*existing) && *existing != skill_text()) {
                        plan.skill_actions = target.client->install_skill(target.scope, skill_text(), context);
                        plan.skill_state = "update";
                    }
                } catch (const Failure& failure) {
                    plan.skill_state = "error";
                    plan.skill_message = failure.what();
                }
            }
            plans.push_back(std::move(plan));
        }
        return plans;
    }

    // ---- Execution ----

    void execute(std::vector<TargetPlan>& plans, const Context& context) {
        for (auto& plan: plans) {
            // A conflicting or unreadable target changes nothing, skill included.
            if (plan.state == "conflict" || plan.state == "error" || plan.state == "unsupported") continue;
            bool registration_ok = true;
            try {
                for (auto& action: plan.actions) action.run();
            } catch (const Failure& failure) {
                registration_ok = false;
                plan.state = "failed";
                plan.message = failure.what();
            }
            if (registration_ok && !plan.actions.empty()) {
                // Validate by reading the state back (never by starting the server through the client).
                auto after = plan.target.client->status(plan.target.scope, context);
                bool removing = plan.state == "remove";
                bool good = removing ? !after.registered
                                     : after.registered && plan.desired && after.entry->same_target(*plan.desired);
                static const std::map<std::string, std::string, std::less<>> done = {
                        {"install", "installed"}, {"replace", "replaced"}, {"remove", "removed"}, {"repair", "repaired"}};
                if (good) {
                    plan.state = done.at(plan.state);
                } else {
                    plan.state = "failed";
                    plan.message = after.error ? *after.error : "the change did not show up when read back";
                }
                plan.current = std::move(after);
            }
            if (plan.skill_state == "conflict" || plan.skill_state == "error" || plan.state == "failed") continue;
            try {
                for (auto& action: plan.skill_actions) action.run();
                if (!plan.skill_actions.empty()) {
                    static const std::map<std::string, std::string, std::less<>> done = {
                            {"install", "installed"}, {"update", "updated"}, {"remove", "removed"}};
                    if (auto it = done.find(plan.skill_state); it != done.end()) plan.skill_state = it->second;
                }
            } catch (const Failure& failure) {
                plan.skill_state = "error";
                plan.skill_message = failure.what();
            }
            static const std::map<std::string, std::string, std::less<>> done = {
                    {"create", "created"}, {"update", "updated"}, {"remove", "removed"}, {"trust", "trusted"}};
            for (auto& item: plan.workspace) {
                if (item.actions.empty()) continue;
                try {
                    for (auto& action: item.actions) action.run();
                    if (auto it = done.find(item.state); it != done.end()) item.state = it->second;
                } catch (const Failure& failure) {
                    item.state = "error";
                    item.message = failure.what();
                }
            }
        }
    }

    json to_json(const TargetPlan& plan) {
        json out = {{"client", plan.target.client->id()}, {"scope", to_string(plan.target.scope)}, {"state", plan.state}};
        if (!plan.message.empty()) out["message"] = plan.message;
        if (!plan.current.location.empty()) out["location"] = plan.current.location;
        if (plan.current.entry) out["current"] = {{"command", plan.current.entry->command}, {"args", plan.current.entry->args}};
        if (plan.desired) out["desired"] = {{"command", plan.desired->command}, {"args", plan.desired->args}};
        json actions = json::array();
        for (const auto& action: plan.actions) actions.push_back(action.summary);
        for (const auto& action: plan.skill_actions) actions.push_back(action.summary);
        for (const auto& item: plan.workspace)
            for (const auto& action: item.actions) actions.push_back(action.summary);
        out["actions"] = std::move(actions);
        if (!plan.workspace.empty()) {
            json items = json::array();
            for (const auto& item: plan.workspace) {
                json row = {{"name", item.name}, {"path", item.path.string()}, {"state", item.state}};
                if (!item.message.empty()) row["message"] = item.message;
                items.push_back(std::move(row));
            }
            out["workspace"] = std::move(items);
        }
        if (!plan.warnings.empty()) out["warnings"] = plan.warnings;
        if (!plan.current.notes.empty()) out["notes"] = plan.current.notes;
        if (!plan.skill_state.empty()) {
            out["skill"] = {{"state", plan.skill_state}, {"path", plan.skill_path.string()}};
            if (!plan.skill_message.empty()) out["skill"]["message"] = plan.skill_message;
        }
        return out;
    }

    // ---- Status ----

    std::vector<Target> all_targets(const std::vector<const ClientAdapter*>& clients, const std::optional<Scope>& scope) {
        std::vector<Target> targets;
        for (const auto* client: clients)
            for (auto s: client->scopes())
                if (!scope || *scope == s) targets.push_back({client, s});
        return targets;
    }

    json status_report(const std::optional<fs::path>& forti_mcp, const Context& context) {
        json report = json::object();
        report["forti_mcp"] = forti_mcp ? json{{"path", forti_mcp->string()}} : json{{"path", nullptr}};
        if (forti_mcp) {
            auto version = forti_mcp_version(*forti_mcp, std::chrono::milliseconds(10'000));
            report["forti_mcp"]["version"] = version ? json(*version) : json(nullptr);
        }
        report["project_dir"] = context.project_dir.string();
        json clients = json::array();
        for (const auto& adapter: adapters()) {
            auto detection = adapter->detect(context);
            json client = {{"id", adapter->id()}, {"name", adapter->display_name()}, {"found", detection.found}};
            if (detection.found) {
                client["path"] = detection.path;
                client["version"] = detection.version;
            }
            json scopes = json::array();
            for (auto scope: adapter->scopes()) {
                auto registration = adapter->status(scope, context);
                json row = {{"scope", to_string(scope)}, {"registered", registration.registered}, {"location", registration.location}};
                if (registration.entry) {
                    const auto& entry = *registration.entry;
                    row["command"] = entry.command;
                    row["args"] = entry.args;
                    row["command_exists"] = is_executable(entry.command);
                    row["matches_installed"] = forti_mcp && entry.command == forti_mcp->string();
                    if (entry.extra) row["custom_settings"] = true;
                }
                if (registration.error) row["error"] = *registration.error;
                if (!registration.notes.empty() && registration.registered) row["notes"] = registration.notes;
                auto skill_path = adapter->skill_file(scope, context);
                std::optional<std::string> skill;
                try {
                    skill = adapter->installed_skill(scope, context);
                } catch (const Failure&) {
                }
                row["skill"] = {{"installed", skill.has_value() && is_forti_skill(*skill)},
                                {"path", skill_path.string()}};
                if (skill && is_forti_skill(*skill)) row["skill"]["current"] = *skill == skill_text();
                scopes.push_back(std::move(row));
            }
            client["scopes"] = std::move(scopes);
            clients.push_back(std::move(client));
        }
        report["clients"] = std::move(clients);
        report["workspace"] = workspace::status(context);
        return report;
    }

}  // namespace forti::install
