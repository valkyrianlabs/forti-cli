//
// `forti mcp install|status|repair|uninstall` (`forti install mcp` is the same as `forti mcp install`):
// register the locally installed forti-mcp with AI clients. The decisions live in src/install
// (installer.hpp); this file handles arguments, the interactive dialogue on /dev/tty, and output.
//
// Interactive mode (a terminal on stdin, no --yes, no --json) asks for whatever was not given,
// shows every command and file that will change, and asks before changing anything. Otherwise
// nothing is ever asked: --client and --scope are required, and the plan runs as given.
//

#include "commands.hpp"
#include "tty.hpp"

#include <installer.hpp>

#include <algorithm>
#include <charconv>
#include <cstdio>
#include <memory>
#include <sstream>
#include <format>
#include <iostream>
#include <ostream>
#include <unistd.h>

namespace forti::cli {

    using engine::Code;
    using engine::Failure;
    using json = nlohmann::json;
    namespace inst = forti::install;

    namespace {

        // ---- The terminal ----

        struct Interaction {
            bool interactive = false;
            std::unique_ptr<Tty> tty;
        };

        Interaction interaction(const Context& context, const Args& args) {
            Interaction mode;
            if (args.flag("yes") || context.output.format == Format::json || !::isatty(STDIN_FILENO)) return mode;
            auto tty = std::make_unique<Tty>();
            if (!tty->available()) return mode;
            mode.tty = std::move(tty);
            mode.interactive = true;
            return mode;
        }

        // ---- Arguments ----

        std::vector<const inst::ClientAdapter*> detected_clients(const inst::Context& context) {
            std::vector<const inst::ClientAdapter*> found;
            for (const auto& adapter: inst::adapters())
                if (adapter->detect(context).found) found.push_back(adapter.get());
            return found;
        }

        std::string client_names() {
            std::string names;
            for (const auto& adapter: inst::adapters()) names += std::string(names.empty() ? "" : "|") + std::string(adapter->id());
            return names + "|all";
        }

        // --client: one id, or "all" (= the detected clients). nullopt when not given.
        std::optional<std::vector<const inst::ClientAdapter*>> clients_option(const Args& args, const inst::Context& context,
                                                                             bool detected_only) {
            auto value = args.value("client");
            if (!value) return std::nullopt;
            if (*value == "all") {
                if (!detected_only) {
                    std::vector<const inst::ClientAdapter*> every;
                    for (const auto& adapter: inst::adapters()) every.push_back(adapter.get());
                    return every;
                }
                auto found = detected_clients(context);
                if (found.empty()) throw Failure(Code::config, "no supported AI client (claude, codex) was found on PATH");
                return found;
            }
            const auto* adapter = inst::find_adapter(*value);
            if (!adapter) throw Failure(Code::usage, std::format("--client expects {}", client_names()));
            return std::vector{adapter};
        }

        std::optional<inst::Scope> scope_option(const Args& args) {
            auto value = args.value("scope");
            if (!value) return std::nullopt;
            auto scope = inst::parse_scope(*value);
            if (!scope) throw Failure(Code::usage, "--scope expects workspace, user, project or local");
            return scope;
        }

        inst::Context install_context(const Args& args) {
            std::optional<inst::fs::path> project;
            if (auto dir = args.value("project-dir")) {
                std::error_code ec;
                if (!inst::fs::is_directory(*dir, ec)) throw Failure(Code::usage, std::format("--project-dir {} is not a directory", *dir));
                project = inst::fs::path(*dir);
            }
            return inst::Context::from_environment(project);
        }

        // ---- Output ----

        // `text` with the home directory written as ~ in every path that starts with it, also inside
        // messages and command lines ("write /Users/me/.forti/AGENTS.md" → "write ~/.forti/AGENTS.md").
        // A quoted path is file content (a TOML key, a JSON value) and stays exactly as written.
        std::string tilde(const std::string& text, const inst::Context& context) {
            std::string home = context.home.string();
            while (home.size() > 1 && home.back() == '/') home.pop_back();
            if (home.empty() || home == "/") return text;
            static constexpr std::string_view before = " (=:[,";
            static constexpr std::string_view after = "/ )],:.";
            std::string out;
            std::size_t copied = 0;
            for (std::size_t at = text.find(home); at != std::string::npos; at = text.find(home, at + 1)) {
                std::size_t end = at + home.size();
                bool starts = at == 0 || before.find(text[at - 1]) != std::string_view::npos;
                bool ends = end == text.size() || after.find(text[end]) != std::string_view::npos;
                if (!starts || !ends || at < copied) continue;
                out.append(text, copied, at - copied);
                out += '~';
                copied = end;
            }
            out.append(text, copied, std::string::npos);
            return out;
        }

        std::string scope_label(inst::Scope scope, const inst::Context& context) {
            switch (scope) {
                case inst::Scope::workspace:
                    return std::format("{} workspace (recommended): agents started there get the firewall tools, nowhere else",
                                       tilde(context.forti_home.string(), context));
                case inst::Scope::project: return std::format("this project ({})", tilde(context.project_dir.string(), context));
                case inst::Scope::user: return "user-wide (every project)";
                case inst::Scope::local: return std::format("this project, only you ({}; Claude Code only)",
                                                            tilde(context.project_dir.string(), context));
            }
            return "";
        }

        void render_plans_raw(std::ostream& out, const std::vector<inst::TargetPlan>& plans, const inst::Context& context,
                              bool show_actions);

        // Messages quote entries read from project files (.mcp.json, .codex/config.toml) that a
        // repository controls: escape terminal controls, keep the line structure.
        void render_plans(std::ostream& out, const std::vector<inst::TargetPlan>& plans, const inst::Context& context,
                          bool show_actions) {
            std::ostringstream text;
            render_plans_raw(text, plans, context, show_actions);
            out << printable(text.str(), true);
        }

        void render_plans_raw(std::ostream& out, const std::vector<inst::TargetPlan>& plans, const inst::Context& context,
                              bool show_actions) {
            for (const auto& plan: plans) {
                out << std::format("{} ({}): {}", plan.target.client->display_name(), inst::to_string(plan.target.scope),
                                   plan.state);
                if (!plan.message.empty() && plan.message != plan.state) out << " — " << tilde(plan.message, context);
                out << "\n";
                if (show_actions) {
                    for (const auto* list: {&plan.actions, &plan.skill_actions})
                        for (const auto& action: *list)
                            out << std::format("    {}{}\n", action.kind == "run" ? "$ " : "", tilde(action.summary, context));
                }
                if (!plan.skill_state.empty() && (plan.skill_actions.empty() || !show_actions))
                    out << std::format("    skill {}: {}\n", plan.skill_state,
                                       tilde(plan.skill_message.empty() ? plan.skill_path.string() : plan.skill_message, context));
                for (const auto& item: plan.workspace) {
                    if (show_actions && !item.actions.empty()) {
                        for (const auto& action: item.actions) out << std::format("    {}\n", tilde(action.summary, context));
                        continue;
                    }
                    out << std::format("    workspace {}: {}", item.state, item.name);
                    if (!item.message.empty()) out << " — " << tilde(item.message, context);
                    out << "\n";
                }
                for (const auto& warning: plan.warnings) out << "    note: " << tilde(warning, context) << "\n";
            }
        }

        json plans_json(const std::vector<inst::TargetPlan>& plans) {
            json list = json::array();
            for (const auto& plan: plans) list.push_back(inst::to_json(plan));
            return list;
        }

        // Shows the plan, asks, executes, validates and reports. Shared by install, repair and uninstall.
        // `apply_default` is the answer Enter gives: yes for install and repair (the person just chose
        // what to set up), no for uninstall.
        int run_plans(Context& context, std::vector<inst::TargetPlan>& plans, const inst::Context& install, Interaction& mode,
                      bool dry_run, json data, const std::optional<inst::fs::path>& forti_mcp, bool apply_default) {
            auto& out = *context.output.out;
            bool text = context.output.format == Format::text;
            bool blocked = std::ranges::any_of(plans, [](const auto& plan) { return plan.blocked(); });
            bool work = std::ranges::any_of(plans, [](const auto& plan) { return plan.has_actions(); });

            auto finish = [&](bool executed) {
                data["dry_run"] = dry_run;
                data["executed"] = executed;
                data["targets"] = plans_json(plans);
                bool failed = std::ranges::any_of(plans, [](const auto& plan) { return plan.blocked(); });
                if (failed) {
                    if (text) render_plans(out, plans, install, !executed);
                    std::string message = executed ? "some changes failed (see above)"
                                                   : "nothing was changed: resolve the conflicts or errors above first";
                    return emit(context.output, {{"ok", false},
                                                 {"error", Failure(executed ? Code::config : Code::policy_denied, message, data).to_json()}});
                }
                return emit(context.output, {{"ok", true}, {"data", data}}, [&](std::ostream& stream, const json&, const json&) {
                    render_plans(stream, plans, install, !executed);
                    if (dry_run) stream << "\n(dry run: nothing was changed)\n";
                    if (executed && data.contains("forti_mcp") && data["forti_mcp"].contains("check"))
                        stream << "\n" << data["forti_mcp"]["check"].get<std::string>() << "\n";
                    if (executed && data.contains("start")) stream << "Start an agent with the forti tools: " << data["start"].get<std::string>() << "\n";
                });
            };

            if (blocked || !work || dry_run) return finish(false);

            if (mode.interactive) {
                std::ostringstream preview;
                render_plans(preview, plans, install, true);
                mode.tty->say("\n" + preview.str() + "\n");
                if (!mode.tty->confirm("Apply these changes?", apply_default)) {
                    mode.tty->say("Nothing changed.\n");
                    return 0;
                }
            }
            inst::execute(plans, install);
            if (forti_mcp) {
                auto version = inst::forti_mcp_version(*forti_mcp, std::chrono::milliseconds(10'000));
                data["forti_mcp"]["version"] = version ? json(*version) : json(nullptr);
                data["forti_mcp"]["check"] = version ? std::format("forti-mcp answers: {}", *version)
                                                     : std::format("warning: `{} --version` did not answer", tilde(forti_mcp->string(), install));
            }
            if (text && mode.interactive) out << "\n";
            return finish(true);
        }

        // ---- forti mcp install (and its alias, forti install mcp) ----

        int install_mcp(Context& context, const Args& args) {
            if (args.flag("skill") && args.flag("no-skill")) throw Failure(Code::usage, "--skill and --no-skill conflict");
            auto profile = args.value("profile");
            if (profile) inst::validate_profile_name(*profile);

            auto install = install_context(args);
            auto mode = interaction(context, args);
            auto scope = scope_option(args);
            if (scope == inst::Scope::workspace && args.value("project-dir"))
                throw Failure(Code::usage, "--project-dir does not apply to --scope workspace (the workspace is the forti home, "
                                           "~/.forti or $FORTI_HOME)");
            auto clients = clients_option(args, install, true);
            if (!mode.interactive && (!clients || !scope))
                throw Failure(Code::usage, "non-interactive install needs --client and --scope "
                                           "(e.g. forti mcp install --client claude --scope user --yes)");

            auto forti_mcp = inst::locate_forti_mcp();
            if (!forti_mcp) throw inst::forti_mcp_missing();

            if (mode.interactive) {
                auto& tty = *mode.tty;
                tty.say(std::format("forti-mcp: {}\n", tilde(forti_mcp->string(), install)));
                if (!clients) {
                    auto found = detected_clients(install);
                    if (found.empty()) throw Failure(Code::config, "no supported AI client (claude, codex) was found on PATH");
                    std::vector<std::string> options;
                    for (const auto* client: found) {
                        auto detection = client->detect(install);   // answered from the probe of detected_clients
                        options.push_back(std::format("{} ({})", client->display_name(),
                                                      detection.version.empty() ? tilde(detection.path, install) : detection.version));
                    }
                    if (found.size() > 1) options.emplace_back("all of the above");
                    auto choice = found.size() == 1 ? 0 : tty.choose("Register forti-mcp with:", options, options.size() - 1);
                    clients = choice < found.size() ? std::vector{found[choice]} : found;
                    if (found.size() == 1) tty.say(std::format("Client: {}\n", found[0]->display_name()));
                }
                if (!scope) {
                    // Workspace first and the default; local only when a chosen client has it (Claude Code).
                    std::vector<inst::Scope> offered;
                    for (auto s: {inst::Scope::workspace, inst::Scope::project, inst::Scope::user, inst::Scope::local})
                        if (std::ranges::any_of(*clients, [&](const auto* client) { return client->supports(s); })) offered.push_back(s);
                    std::vector<std::string> options;
                    for (auto s: offered) options.push_back(scope_label(s, install));
                    scope = offered[tty.choose("Where should agents get the forti tools?", options, 0)];
                }
            }
            if (clients->size() == 1 && !clients->front()->supports(*scope))
                throw Failure(Code::usage, std::format("{} has no {} scope", clients->front()->display_name(), inst::to_string(*scope)));

            // $HOME as the project: every agent started under it would get the tools.
            if (!inst::workspace::allow_home_directory(
                        *scope, install, mode.interactive, args.flag("force"),
                        [&](std::string_view text) { mode.tty->say(text); },
                        [&](std::string_view question, bool fallback) { return mode.tty->confirm(question, fallback); })) {
                mode.tty->say("Nothing changed. Run `forti mcp install --scope workspace` for the recommended setup.\n");
                return 0;
            }

            bool workspace = *scope == inst::Scope::workspace;
            // The skill belongs to the workspace scaffold; elsewhere it is asked for (default no).
            bool skill = args.flag("skill") || (workspace && !args.flag("no-skill"));
            if (mode.interactive && !workspace && !args.flag("skill") && !args.flag("no-skill"))
                skill = mode.tty->confirm("Also install the forti agent skill (how to use the tools safely)?", false);

            // Codex reads the workspace's .codex/config.toml only for a trusted project. Trusting the forti
            // home is a change to the global Codex config, so it needs a yes (or --trust-codex-workspace).
            // The person chose the Codex workspace, so Enter trusts it; the question is still asked.
            bool trust = args.flag("trust-codex-workspace");
            bool trust_declined = false;
            bool codex = std::ranges::any_of(*clients, [](const auto* client) { return client->id() == "codex"; });
            std::string forti_home = tilde(install.forti_home.string(), install);
            if (workspace && codex && !trust && mode.interactive && inst::workspace::codex_trust_needed(install)) {
                mode.tty->say(std::format("\nCodex loads {0}/.codex/config.toml (the forti server and its deny rules) only for trusted "
                                          "projects.\nTrusting {0} adds exactly this to {1}:\n    [projects.\"{2}\"]\n    trust_level = \"trusted\"\n"
                                          "No: Codex ignores the workspace (no forti tools there) until you trust {0} yourself.\n",
                                          forti_home,
                                          tilde(((install.codex_home ? *install.codex_home : install.home / ".codex") / "config.toml").string(), install),
                                          install.forti_home.string()));
                trust = mode.tty->confirm(std::format("Trust {} in Codex?", forti_home), true);
                trust_declined = !trust;
            }

            inst::InstallRequest request{.targets = inst::all_targets(*clients, scope),
                                         .desired = inst::desired_entry(*forti_mcp, profile),
                                         .skill = skill,
                                         .force = args.flag("force"),
                                         .trust_codex_workspace = trust};
            auto plans = inst::plan_install(request, install);
            // Declined at the prompt just above: say what that means in a few words, not the explanation again.
            if (trust_declined)
                for (auto& plan: plans)
                    for (auto& item: plan.workspace)
                        if (item.name == "Codex trust" && item.state == "untrusted")
                            item.message = std::format("you answered no: Codex ignores the workspace until you trust {}",
                                                       forti_home);
            json data = {{"forti_mcp", {{"path", forti_mcp->string()}}}, {"project_dir", install.project_dir.string()}};
            if (workspace) {
                data["workspace"] = install.forti_home.string();
                std::string agents;
                for (const auto* client: *clients) agents += (agents.empty() ? "" : " (or ") + std::string(client->executable());
                if (clients->size() > 1) agents += ")";
                data["start"] = std::format("cd {} && {}", forti_home, agents);
            }
            return run_plans(context, plans, install, mode, args.flag("dry-run"), std::move(data), forti_mcp, true);
        }

        int run_install(Context& context, const Args& args) {
            if (args.positional != std::vector<std::string>{"mcp"})
                throw Failure(Code::usage, "usage: forti mcp install [options] (forti install mcp is the same command)");
            return install_mcp(context, args);
        }

        // ---- forti mcp status|repair|uninstall ----

        void render_status(std::ostream& out, const json& data, const inst::Context& install) {
            auto path = [&](const json& value) { return tilde(value.get<std::string>(), install); };
            const auto& mcp = data["forti_mcp"];
            if (mcp["path"].is_null()) out << "forti-mcp  not installed (brew install valkyrianlabs/tap/forti-mcp, or sudo apt install forti-mcp)\n";
            else out << std::format("forti-mcp  {}{}\n", path(mcp["path"]),
                                    mcp.value("version", json()).is_string() ? " (" + mcp["version"].get<std::string>() + ")"
                                                                            : " (does not answer --version)");
            out << std::format("project    {}\n", path(data["project_dir"]));
            for (const auto& client: data["clients"]) {
                out << "\n" << client["name"].get<std::string>();
                if (client["found"].get<bool>()) out << std::format(" {} ({})", client.value("version", ""), tilde(client.value("path", ""), install));
                else out << " (not found on PATH)";
                out << "\n";
                for (const auto& row: client["scopes"]) {
                    std::string state;
                    if (row.contains("error")) state = "error: " + row["error"].get<std::string>();
                    else if (!row["registered"].get<bool>()) state = "not registered";
                    else {
                        state = path(row["command"]);
                        for (const auto& arg: row["args"]) state += " " + arg.get<std::string>();
                        if (!row["command_exists"].get<bool>()) state += "  [MISSING: run forti mcp repair]";
                        else if (row["matches_installed"].get<bool>()) state += "  [matches installed]";
                        else state += "  [differs from installed]";
                    }
                    std::string skill = row["skill"]["installed"].get<bool>()
                                                ? (row["skill"].value("current", false) ? "skill: yes" : "skill: outdated")
                                                : "skill: no";
                    out << std::format("  {:<9} {}   {}\n", row["scope"].get<std::string>(), state, skill);
                    for (const auto& note: row.value("notes", json::array())) out << "            note: " << path(note) << "\n";
                }
            }
            if (data.contains("workspace")) {
                const auto& ws = data["workspace"];
                out << std::format("\nworkspace  {}{}\n", path(ws["path"]), ws["exists"].get<bool>() ? "" : " (does not exist yet)");
                // Files of a client that is not registered in the workspace are not expected to be there.
                auto registered = [&](const std::string& id) {
                    for (const auto& client: data["clients"])
                        if (id == "all" || client["id"] == id)
                            for (const auto& row: client["scopes"])
                                if (row["scope"] == "workspace" && row["registered"].get<bool>()) return true;
                    return false;
                };
                for (const auto& file: ws["files"]) {
                    auto name = file["name"].get<std::string>();
                    auto state = file["state"].get<std::string>();
                    if (name == "Codex trust" && ws.value("codex_trust_added_by_forti", false)) state += " (added by forti mcp install)";
                    if (!registered(file["client"].get<std::string>())) state = std::format("{} (not registered in the workspace)", state);
                    out << std::format("  {:<26} {}\n", name, state);
                }
            }
        }

        int run_mcp(Context& context, const Args& args) {
            if (args.positional.size() != 1)
                throw Failure(Code::usage, "usage: forti mcp install|status|repair|uninstall (see forti mcp --help)");
            const auto& sub = args.positional[0];
            if (sub != "install" && (args.flag("skill") || args.flag("no-skill") || args.flag("trust-codex-workspace")))
                throw Failure(Code::usage, "--skill, --no-skill and --trust-codex-workspace apply to forti mcp install only");
            if (sub != "uninstall" && args.flag("keep-skill")) throw Failure(Code::usage, "--keep-skill applies to forti mcp uninstall only");
            if (sub == "install") return install_mcp(context, args);
            auto install = install_context(args);

            if (sub == "status") {
                auto forti_mcp = inst::locate_forti_mcp();
                return emit(context.output, {{"ok", true}, {"data", inst::status_report(forti_mcp, install)}},
                            [&](std::ostream& out, const json& data, const json&) { render_status(out, data, install); });
            }

            auto mode = interaction(context, args);
            auto scope = scope_option(args);
            auto clients = clients_option(args, install, false);

            if (sub == "repair") {
                auto forti_mcp = inst::locate_forti_mcp();
                if (!forti_mcp) throw inst::forti_mcp_missing();
                std::vector<const inst::ClientAdapter*> every;
                for (const auto& adapter: inst::adapters()) every.push_back(adapter.get());
                auto plans = inst::plan_repair(inst::all_targets(clients ? *clients : every, scope), *forti_mcp, install);
                json data = {{"forti_mcp", {{"path", forti_mcp->string()}}}, {"project_dir", install.project_dir.string()}};
                return run_plans(context, plans, install, mode, args.flag("dry-run"), std::move(data), forti_mcp, true);
            }

            if (sub == "uninstall") {
                if (!mode.interactive && (!clients || !scope))
                    throw Failure(Code::usage, "non-interactive uninstall needs --client and --scope "
                                               "(e.g. forti mcp uninstall --client codex --scope user --yes)");
                std::vector<const inst::ClientAdapter*> every;
                for (const auto& adapter: inst::adapters()) every.push_back(adapter.get());
                auto plans = inst::plan_uninstall(inst::all_targets(clients ? *clients : every, scope),
                                                  args.flag("keep-skill"), args.flag("force"), install);
                if (clients && clients->size() == 1 && scope && !clients->front()->supports(*scope))
                    throw Failure(Code::usage, std::format("{} has no {} scope", clients->front()->display_name(), inst::to_string(*scope)));
                if (!clients || !scope) {
                    // Interactive and open-ended: show only what is actually there.
                    std::erase_if(plans, [](const auto& plan) {
                        return plan.state == "unsupported" || (plan.state == "not_registered" && !plan.has_actions());
                    });
                }
                json data = {{"project_dir", install.project_dir.string()}};
                return run_plans(context, plans, install, mode, args.flag("dry-run"), std::move(data), std::nullopt, false);
            }
            throw Failure(Code::usage, std::format("unknown subcommand \"{}\": forti mcp install|status|repair|uninstall", sub));
        }

    }  // namespace

    std::vector<Command> install_commands() {
        return {
            {"mcp", "Register forti-mcp with AI clients (Claude Code, Codex): install, status, repair, uninstall",
             "usage: forti mcp install [options]   register forti-mcp with AI clients (prompts on a terminal)\n"
             "       forti mcp status              where forti-mcp is registered, whether it still matches, workspace health\n"
             "       forti mcp repair              point broken registrations at the installed forti-mcp\n"
             "       forti mcp uninstall           remove forti's registrations (and skill; for the workspace, the files\n"
             "                                     forti wrote there, never config.json, credentials, certs or state)\n"
             "\n"
             "install, in a terminal and without --yes, asks what is missing, shows every command and file it\n"
             "will change, and asks before changing them (Enter applies). `forti install mcp` is the same command.\n"
             "\n"
             "  --client claude|codex|all   which client (all = every client found on PATH); repair/uninstall: limit to it\n"
             "  --scope SCOPE               workspace (recommended): the forti home (~/.forti), so only agents\n"
             "                                started there (cd ~/.forti && claude) get the tools; with AGENTS.md,\n"
             "                                the skill and deny rules that keep credentials out of the agent\n"
             "                              project: files in --project-dir to commit (.mcp.json, .codex/config.toml)\n"
             "                              user: every project; local: you, this project (Claude Code only)\n"
             "  --project-dir DIR           project for project/local scope (default: current directory)\n"
             "  --profile NAME              install: start forti-mcp with this profile (no secrets are ever written)\n"
             "  --skill / --no-skill        install: also the forti agent skill (workspace: yes; else no, asked interactively)\n"
             "  --trust-codex-workspace     install, workspace + Codex: mark the forti home trusted in the global Codex\n"
             "                              config (Codex ignores project config otherwise; asked interactively)\n"
             "  --keep-skill                uninstall: leave the agent skill in place\n"
             "  --yes                       never prompt (install and uninstall then need --client and --scope)\n"
             "  --dry-run                   show what would change, change nothing\n"
             "  --force                     replace (uninstall: remove) a `forti` entry that is not this forti-mcp;\n"
             "                              allow project or local scope in your home directory without a terminal\n"
             "\n"
             "examples:\n"
             "  forti mcp install\n"
             "  forti mcp install --client all --scope workspace --trust-codex-workspace --yes\n"
             "  forti mcp install --client claude --scope user --skill --yes\n"
             "  forti mcp install --client all --scope project --project-dir ~/src/netops --dry-run\n"
             "  forti mcp status\n",
             {{"client", "scope", "project-dir"},
              {"skill", "no-skill", "trust-codex-workspace", "keep-skill", "yes", "dry-run", "force"},
              {{'y', "yes"}}},
             run_mcp},
            {"install", "Same as `forti mcp install` (forti install mcp)",
             "usage: forti install mcp [options]\n"
             "\n"
             "The same command as `forti mcp install`, with the same options: see forti mcp --help.\n",
             {{"client", "scope", "project-dir"}, {"skill", "no-skill", "trust-codex-workspace", "yes", "dry-run", "force"}, {{'y', "yes"}}},
             run_install},
        };
    }

}  // namespace forti::cli
