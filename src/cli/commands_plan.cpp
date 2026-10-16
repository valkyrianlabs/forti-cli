//
// forti plan / forti apply / forti rollback: build, inspect and approve stored plans, execute them,
// and undo the last one.
//
// Plans come from a JSON file (`forti plan --file changes.json`, `-` for stdin) or from the
// convenience forms (set / create / delete / action). `forti plan approve` is the guarded-mode human
// approval; it exists only here, never in forti-mcp.
//
// A person at a terminal (text output, stdin and stdout both terminals) gets shortcuts: a plan can be
// named by `latest`, a unique prefix, or not at all (the newest pending plan, shown first), and a
// guarded apply asks for the approval inline. Scripts and agents' shell tools have no terminal: for
// them every plan is named explicitly and nothing is approved without `forti plan approve`.
//

#include "commands.hpp"
#include "setup_support.hpp"
#include "tty.hpp"

#include <forti/engine/approval.hpp>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <format>
#include <fstream>
#include <iostream>
#include <regex>
#include <sstream>

#include <unistd.h>

namespace forti::cli {

    using engine::Code;
    using engine::Failure;
    using json = nlohmann::json;

    namespace {

        // ---- text rendering ----

        struct Style {
            bool color = false;
            [[nodiscard]] std::string paint(std::string_view text, std::string_view code) const {
                return color ? std::format("\033[{}m{}\033[0m", code, text) : std::string(text);
            }
            [[nodiscard]] std::string red(std::string_view text) const { return paint(text, "31"); }
            [[nodiscard]] std::string green(std::string_view text) const { return paint(text, "32"); }
            [[nodiscard]] std::string yellow(std::string_view text) const { return paint(text, "33"); }
            [[nodiscard]] std::string bold(std::string_view text) const { return paint(text, "1"); }
            [[nodiscard]] std::string dim(std::string_view text) const { return paint(text, "2"); }
        };

        Style style_for(int fd) {
            const char* no_color = std::getenv("NO_COLOR");
            return {::isatty(fd) == 1 && (!no_color || !*no_color)};
        }

        std::string show(const json& value) {
            if (value.is_null()) return "(unset)";
            if (value.is_string()) return std::format("\"{}\"", value.get<std::string>());
            std::string text = value.dump();
            return text.size() > 120 ? text.substr(0, 117) + "..." : text;
        }

        std::string list_ids(const json& ids) {
            std::string out;
            for (const auto& id: ids) out += (out.empty() ? "" : ", ") + (id.is_string() ? id.get<std::string>() : id.dump());
            return out.empty() ? "(none)" : out;
        }

        std::string risk_label(const Style& style, const std::string& risk) {
            if (risk == "critical") return style.red(risk);
            if (risk == "elevated") return style.yellow(risk);
            return risk;
        }

        void render_operation(std::ostream& out, const Style& style, const json& op) {
            std::string key = op.contains("key") ? " " + show(op["key"]) : "";
            out << std::format("{}. {} {}{}  [{}]\n", op.value("index", 0) + 1, style.bold(op.value("op", "")),
                               op.value("resource", ""), key, risk_label(style, op.value("risk", "")));
            if (op.contains("note")) out << "     " << style.dim(op["note"].get<std::string>()) << "\n";
            std::size_t width = 0;
            for (const auto& entry: op.value("diff", json::array()))
                width = std::max(width, entry.value("attribute", "").size());
            for (const auto& entry: op.value("diff", json::array())) {
                std::string name = entry.value("attribute", "");
                std::string change = entry.value("change", "");
                if (entry.contains("table") && entry["table"].is_object()) {
                    const json& table = entry["table"];
                    out << std::format("     {:<{}}  {}\n", name, width, style.yellow("(table: replaced wholesale)"));
                    for (const auto& id: table.value("removed", json::array()))
                        out << std::format("     {:<{}}    {}\n", "", width, style.red("- " + (id.is_string() ? id.get<std::string>() : id.dump())));
                    for (const auto& id: table.value("added", json::array()))
                        out << std::format("     {:<{}}    {}\n", "", width, style.green("+ " + (id.is_string() ? id.get<std::string>() : id.dump())));
                    out << std::format("     {:<{}}    result: [{}]\n", "", width, list_ids(table.value("result", json::array())));
                    continue;
                }
                if (entry.contains("table")) {   // redacted
                    out << std::format("     {:<{}}  {}\n", name, width, show(entry["after"]));
                    continue;
                }
                std::string before = show(entry.contains("before") ? entry["before"] : json());
                std::string after = show(entry.contains("after") ? entry["after"] : json());
                std::string line = change == "add" ? style.green("+ " + after) : std::format("{} → {}", style.red(before), style.green(after));
                if (change == "clear") line += style.dim("  (cleared to default)");
                if (entry.value("unchanged", false)) line += style.dim("  (unchanged)");
                out << std::format("     {:<{}}  {}\n", name, width, line);
            }
            if (op.contains("wire") && op["wire"].is_object()) {
                const json& wire = op["wire"];
                out << "     " << style.dim(std::format("{} {}", wire.value("method", ""), wire.value("path", "")));
                if (wire.contains("body") && !wire["body"].is_null()) out << style.dim(" " + wire["body"].dump());
                out << "\n";
            }
        }

        // `verbose` adds the digest, which only programs and auditors compare (it stays in --json).
        void render_plan(std::ostream& out, const Style& style, const json& data, bool verbose) {
            const json& device = data.value("device", json::object());
            std::string title = data.value("kind", "plan") == "rollback"
                                ? std::format("Rollback plan {} (undoes {})", data.value("id", ""), data.value("rollback_of", ""))
                                : std::format("Plan {}", data.value("id", ""));
            out << style.bold(title) << "  risk " << risk_label(style, data.value("risk", "")) << "\n";
            out << std::format("Device {}  {}:{}  serial {}  {}", device.value("profile", ""), device.value("host", ""),
                               device.value("port", 0), device.value("serial", ""), device.value("version", ""));
            if (!device.value("vdom", "").empty()) out << "  vdom " << device.value("vdom", "");
            out << "\n" << data.value("summary", "") << "\n\n";
            for (const auto& op: data.value("operations", json::array())) render_operation(out, style, op);
            out << "\n";
            if (verbose) out << style.dim("digest " + data.value("digest", "")) << "\n";
            if (data.contains("state") && data["state"].is_object()) {
                const json& state = data["state"];
                out << "state  " << state.value("state", "");
                if (state["approval"].is_object())
                    out << std::format("  (approved by {} at {}, expires {})", state["approval"].value("approved_by", ""),
                                       state["approval"].value("approved_at", ""), state["approval"].value("expires_at", ""));
                out << "\n";
            }
            std::string mode = data.contains("mode") && data["mode"].is_string() ? data["mode"].get<std::string>() : "";
            if (!mode.empty()) out << "mode   " << mode << "\n";
            for (const auto& note: data.value("notes", json::array())) {
                std::string text = note.get<std::string>();
                if (mode == "guarded" && text.starts_with("guarded mode:")) continue;   // the "next" lines below say it
                out << style.yellow("note") << "   " << text << "\n";
            }
            // What to run next. A read-only profile refuses apply: say how to allow changes instead.
            if (mode == "read-only") {
                if (!data.contains("notes")) {
                    std::string profile = device.value("profile", "");
                    out << std::format("next   apply is refused while profile {0} is read-only. To allow changes: "
                                       "forti profile mode {0} guarded (you approve each plan) or autonomous\n", profile);
                }
                return;
            }
            if (data.contains("approve") && data.contains("apply")) {
                out << "next   " << data["apply"].get<std::string>() << "  (shows the plan and asks for your approval)\n"
                    << "       without a terminal: " << data["approve"].get<std::string>() << ", then the same apply\n";
            } else if (data.contains("apply")) out << "next   " << data["apply"].get<std::string>() << "\n";
        }

        std::string status_label(const Style& style, const std::string& status) {
            if (status == "verified") return style.green(status);
            if (status == "applied_unverified") return style.yellow(status);
            if (status == "not_attempted") return style.dim(status);
            return style.red(status);
        }

        void render_record(std::ostream& out, const Style& style, const json& record) {
            for (const auto& op: record.value("operations", json::array())) {
                std::string key = op.contains("key") ? " " + show(op["key"]) : "";
                out << std::format("{}. {} {}{}  {}\n", op.value("index", 0) + 1, op.value("op", ""), op.value("resource", ""), key,
                                   status_label(style, op.value("status", "")));
                if (op.contains("error")) out << "     " << op["error"].value("message", "") << "\n";
                if (op.contains("verification")) out << "     " << op["verification"].get<std::string>() << "\n";
                for (const auto& mismatch: op.value("mismatches", json::array()))
                    out << std::format("     {}: wrote {}, device reports {}\n", mismatch.value("attribute", ""),
                                       show(mismatch["expected"]), show(mismatch["actual"]));
                if (op.contains("note")) out << "     " << style.dim(op["note"].get<std::string>()) << "\n";
                if (op.contains("management_probe") && !op["management_probe"].value("ok", false))
                    out << "     " << style.red("management probe failed: " + op["management_probe"].value("error", "")) << "\n";
            }
            if (record.contains("backup") && record["backup"].is_object()) {
                const json& backup = record["backup"];
                out << "backup    " << backup.value("status", "");
                if (backup.contains("path") && backup["path"].is_string()) out << " " << display_path(backup["path"].get<std::string>());
                if (backup.contains("reason") && backup["reason"].is_string()) out << ": " << backup["reason"].get<std::string>();
                out << "\n";
            }
            if (record.contains("rollback") && record["rollback"].is_object()) {
                const json& rollback = record["rollback"];
                if (rollback["plan_id"].is_string())
                    out << std::format("undo      forti rollback {}  (rollback plan {})\n", record.value("plan_id", ""),
                                       rollback["plan_id"].get<std::string>());
                for (const auto& skipped: rollback.value("skipped", json::array()))
                    out << style.yellow("          no rollback for operation ") << skipped.value("index", 0) + 1 << ": "
                        << skipped.value("reason", "") << "\n";
            }
            if (record.contains("recovery")) out << style.red(record["recovery"].get<std::string>()) << "\n";
        }

        // "1 change applied and verified." / "2 changes applied and verified; 1 applied but not verified."
        std::string outcome(const json& data) {
            std::size_t verified = data.value("verified", 0u), unverified = data.value("applied_unverified", 0u);
            std::string text;
            if (verified) text = std::format("{} change{} applied and verified", verified, verified == 1 ? "" : "s");
            if (unverified)
                text += std::format("{}{} applied but not verified (see below)", text.empty() ? "" : "; ", unverified);
            return text.empty() ? std::string("Nothing was changed.") : text + ".";
        }

        // ---- a person at a terminal ----

        // Text output with stdin and stdout on a terminal. Scripts and agents' shell tools have neither.
        bool at_terminal(const Context& context) {
            return context.output.format == Format::text && ::isatty(STDIN_FILENO) == 1 && ::isatty(STDOUT_FILENO) == 1;
        }

        // A y/n question on stdout, answered on stdin; Enter takes `fallback`, end of input is "no".
        bool ask(Context& context, std::string_view question, bool fallback) {
            *context.output.out << question << (fallback ? " [Y/n] " : " [y/N] ") << std::flush;
            std::string answer;
            if (!std::getline(std::cin, answer)) return false;
            answer = trim(answer);
            if (answer.empty()) return fallback;
            return answer == "y" || answer == "Y" || answer == "yes";
        }

        std::string approver() {
            const char* user = std::getenv("USER");
            return std::string("cli:") + (user && *user ? user : "unknown");
        }

        // ---- naming a plan ----

        // A complete id ("20261016-150540-b75ef1") is passed through; the engine checks it.
        bool complete_id(const std::string& text) {
            static const std::regex pattern("[0-9]{8}-[0-9]{6}-[0-9a-f]{6}");
            return std::regex_match(text, pattern);
        }

        std::optional<std::string> selected_profile(Context& context, const Args& args) {
            if (auto name = args.value("profile")) return *name;
            try {
                return context.engine.profile("").name;
            } catch (const Failure&) {
                return std::nullopt;   // no profile, or several and no default: every profile's plans
            }
        }

        // Newest first. created_at has whole seconds; within one second the plan file's time decides.
        json stored_plans(Context& context) {
            json plans = engine::list_plans(context.engine).value("data", json::array());
            std::filesystem::path dir = context.engine.options().paths.state / "plans";
            auto written = [&](const json& plan) {
                std::error_code error;
                auto time = std::filesystem::last_write_time(dir / (plan.value("id", "") + ".json"), error);
                return error ? std::filesystem::file_time_type::min() : time;
            };
            std::stable_sort(plans.begin(), plans.end(), [&](const json& a, const json& b) {
                std::string at = a.value("created_at", ""), bt = b.value("created_at", "");
                return at != bt ? at > bt : written(a) > written(b);
            });
            return plans;
        }

        bool pending(const json& plan) {
            std::string state = plan.value("state", "");
            return state == "pending" || state == "approved" || state == "approval_expired";
        }

        struct Named {
            std::string id;
            bool exact = true;   // typed in full: nothing to show before acting
        };

        // `given`: a complete id, `latest` (the newest plan of the profile, rollback plans aside), a
        // unique prefix of an id or of its random part, or empty (the newest pending plan of the profile).
        Named name_plan(Context& context, const Args& args, const std::string& given) {
            if (complete_id(given)) return {given, true};
            json plans = stored_plans(context);
            if (given.empty() || given == "latest") {
                auto profile = selected_profile(context, args);
                for (const auto& plan: plans) {
                    if (plan.value("kind", "plan") == "rollback") continue;
                    if (profile && plan.value("profile", "") != *profile) continue;
                    if (given.empty() && !pending(plan)) continue;
                    return {plan.value("id", ""), false};
                }
                std::string whose = profile ? std::format(" for profile {}", *profile) : "";
                throw Failure(Code::not_found, given.empty() ? std::format("no plan waiting to be applied{}", whose)
                                                             : std::format("no plan{}", whose),
                              {{"hint", "forti plan list shows the stored plans"}});
            }
            std::vector<std::string> matches;
            for (const auto& plan: plans) {
                std::string id = plan.value("id", "");
                std::string tail = id.substr(id.rfind('-') + 1);
                if (id.starts_with(given) || tail.starts_with(given)) matches.push_back(id);
            }
            if (matches.size() == 1) return {matches.front(), false};
            if (matches.empty())
                throw Failure(Code::not_found, std::format("no plan matches \"{}\"", given), {{"hint", "forti plan list shows the stored plans"}});
            std::string list;
            for (const auto& id: matches) list += (list.empty() ? "" : ", ") + id;
            throw Failure(Code::usage, std::format("\"{}\" matches {} plans: {}", given, matches.size(), list),
                          {{"candidates", matches}, {"hint", "type more of the id"}});
        }

        // Without a terminal a plan must be named: nothing acts on a plan nobody looked at.
        std::string named_or_terminal(Context& context, const Args& args, std::size_t index, std::string_view usage) {
            if (args.positional.size() > index) return args.positional[index];
            if (!at_terminal(context))
                throw Failure(Code::usage, std::format("usage: {} (a plan id, a unique prefix of one, or latest)", usage));
            return "";
        }

        // ---- requests from arguments ----

        std::string read_input(const std::string& source) {
            std::stringstream text;
            if (source == "-") text << std::cin.rdbuf();
            else {
                std::ifstream in(source);
                if (!in) throw Failure(Code::usage, std::format("cannot read {}", source));
                text << in.rdbuf();
            }
            return text.str();
        }

        json parse_json(const std::string& text, std::string_view what) {
            json value = json::parse(text, nullptr, false);
            if (value.is_discarded()) throw Failure(Code::usage, std::format("{} is not valid JSON", what));
            return value;
        }

        // attr=value: the value is JSON when it parses as a non-string (numbers, booleans, arrays,
        // objects, null, "quoted"), else the literal text (enable, 192.0.2.0/24).
        std::pair<std::string, json> assignment(const std::string& text) {
            auto eq = text.find('=');
            if (eq == std::string::npos || eq == 0) throw Failure(Code::usage, std::format("expected attribute=value, got \"{}\"", text));
            std::string value = text.substr(eq + 1);
            json parsed = json::parse(value, nullptr, false);
            return {text.substr(0, eq), parsed.is_discarded() ? json(value) : parsed};
        }

        void add_globals(json& request, const Args& args) {
            if (auto profile = args.value("profile")) request["profile"] = *profile;
            if (auto vdom = args.value("vdom")) request["vdom"] = *vdom;
        }

        json operation_from_args(const std::string& verb, const Args& args) {
            const auto& positional = args.positional;
            if (positional.size() < 2) throw Failure(Code::usage, std::format("usage: forti plan {} <resource> ...", verb));
            const std::string& resource = positional[1];
            if (verb == "delete") {
                if (positional.size() != 3) throw Failure(Code::usage, "usage: forti plan delete <resource> <key>");
                return {{"op", "delete"}, {"resource", resource}, {"key", positional[2]}};
            }
            if (verb == "create") {
                // The object as JSON (--object), or as attr=value pairs, or both (the pairs win).
                auto given = args.value("object");
                if (!given && positional.size() == 2)
                    throw Failure(Code::usage, "usage: forti plan create <resource> attr=value... | --object JSON|@file");
                json object = json::object();
                if (given) {
                    object = parse_json(given->starts_with('@') ? read_input(given->substr(1)) : *given, "--object");
                    if (!object.is_object()) throw Failure(Code::usage, "--object must be a JSON object");
                }
                for (std::size_t at = 2; at < positional.size(); ++at) {
                    auto [name, value] = assignment(positional[at]);
                    object[name] = std::move(value);
                }
                return {{"op", "create"}, {"resource", resource}, {"object", object}};
            }
            if (verb == "action") {
                json body = json::object();
                if (auto given = args.value("body"))
                    body = parse_json(given->starts_with('@') ? read_input(given->substr(1)) : *given, "--body");
                return {{"op", "action"}, {"resource", resource}, {"body", body}};
            }
            // set: a table needs a key; a singleton takes attributes straight away.
            std::size_t at = 2;
            json op = {{"op", "update"}, {"resource", resource}};
            const engine::Resource* known = engine::Catalog::instance().find(resource);
            bool singleton = known && known->kind == engine::Kind::singleton;
            if (!singleton) {
                if (positional.size() < 3) throw Failure(Code::usage, "usage: forti plan set <resource> <key> attr=value... [--clear attr]");
                op["key"] = positional[2];
                at = 3;
            }
            json set = json::object();
            for (; at < positional.size(); ++at) {
                auto [name, value] = assignment(positional[at]);
                set[name] = std::move(value);
            }
            if (!set.empty()) op["set"] = std::move(set);
            if (auto clear = args.all("clear"); !clear.empty()) op["clear"] = clear;
            return op;
        }

        // ---- apply, shared by apply, rollback, plan approve and plan --apply ----

        // Executes plan `id` and prints the record (on failure, before the error).
        int execute(Context& context, const std::string& id) {
            json envelope = engine::Engine::envelope([&] { return context.engine.apply({{"plan_id", id}}); });
            Style style = style_for(STDOUT_FILENO);
            // A stopped apply still carries its execution record: show it before the error. The error
            // itself names the approval command, so it is not printed twice.
            if (context.output.format == Format::text && !envelope.value("ok", false)) {
                const json& details = envelope["error"].contains("details") ? envelope["error"]["details"] : json();
                if (details.is_object() && details.contains("operations"))
                    render_record(*context.output.err, style_for(STDERR_FILENO), printable_json(details));
            }
            return emit(context.output, envelope, [&](std::ostream& out, const json& data, const json&) {
                out << style.bold(std::format("Applied plan {}", data.value("plan_id", ""))) << ": " << outcome(data) << "\n";
                render_record(out, style, data);
            });
        }

        // At a terminal, before executing `id`: a guarded plan without a valid approval is shown and
        // approved here (the same approval record as `forti plan approve`); a plan the person did not
        // name exactly is shown and confirmed. Returns false when the person declined (already reported).
        bool confirm_at_terminal(Context& context, const Args& args, const std::string& id, bool exact, std::string_view what) {
            if (!at_terminal(context)) return true;
            json shown = engine::Engine::envelope([&] { return engine::show_plan(context.engine, id); });
            if (!shown.value("ok", false)) return true;   // apply reports it
            const json& data = shown["data"];
            std::string mode = data.value("mode", json()).is_string() ? data["mode"].get<std::string>() : "";
            std::string state = data["state"].value("state", "");
            bool needs_approval = mode == "guarded" && state != "approved" && state != "applied";
            if (!needs_approval && exact) return true;
            if (mode == "read-only" || state == "applied") return true;   // apply refuses, with the reason
            Style style = style_for(STDOUT_FILENO);
            // The person deciding reads this: escape anything that could redraw the terminal.
            render_plan(*context.output.out, style, printable_json(data), args.flag("verbose"));
            *context.output.out << "\n";
            if (needs_approval) {
                if (!ask(context, std::format("Approve and apply {} {}?", what, id), false)) {
                    *context.output.err << "forti: not approved; nothing was applied\n";
                    return false;
                }
                json approved = engine::Engine::envelope([&] { return engine::approve_plan(context.engine, id, approver()); });
                if (!approved.value("ok", false)) {
                    emit(context.output, approved);
                    return false;
                }
                return true;
            }
            if (!ask(context, std::format("Apply {} {}?", what, id), true)) {
                *context.output.err << "forti: nothing was applied\n";
                return false;
            }
            return true;
        }

        // ---- commands ----

        int plan_show(Context& context, const Args& args) {
            if (args.positional.size() > 2) throw Failure(Code::usage, "usage: forti plan show [id]");
            Style style = style_for(STDOUT_FILENO);
            bool verbose = args.flag("verbose");
            json envelope = engine::Engine::envelope([&] {
                std::string given = named_or_terminal(context, args, 1, "forti plan show <id>");
                return engine::show_plan(context.engine, name_plan(context, args, given).id);
            });
            return emit(context.output, envelope,
                        [&](std::ostream& out, const json& data, const json&) { render_plan(out, style, data, verbose); });
        }

        int plan_list(Context& context, const Args& args) {
            if (args.positional.size() != 1) throw Failure(Code::usage, "usage: forti plan list");
            return emit(context.output, engine::Engine::envelope([&] { return engine::list_plans(context.engine); }),
                        [](std::ostream& out, const json& data, const json&) {
                            if (data.empty()) {
                                out << "(no stored plans)\n";
                                return;
                            }
                            for (const auto& plan: data)
                                out << std::format("{:<24} {:<16} {:<9} {:<8} {}\n", plan.value("id", ""), plan.value("state", ""),
                                                   plan.value("kind", ""), plan.value("risk", ""), plan.value("summary", ""));
                        });
        }

        int plan_approve(Context& context, const Args& args) {
            if (args.positional.size() > 2) throw Failure(Code::usage, "usage: forti plan approve <id> [--yes]");
            Named named;
            json resolved = engine::Engine::envelope([&] {
                std::string given = named_or_terminal(context, args, 1, "forti plan approve <id> [--yes]");
                named = name_plan(context, args, given);
                return engine::ok(json::object());
            });
            if (!resolved.value("ok", false)) return emit(context.output, resolved);
            const std::string& id = named.id;
            Style style = style_for(STDOUT_FILENO);
            // A person at a terminal sees the plan and answers y/N; scripts (stdout not a TTY) and
            // --yes skip the question. The approval is operator intent, not a security ceremony.
            if (context.output.format == Format::text && !args.flag("yes") && ::isatty(STDOUT_FILENO) == 1) {
                json shown = engine::Engine::envelope([&] { return engine::show_plan(context.engine, id); });
                if (!shown.value("ok", false)) return emit(context.output, shown);
                // The person approving reads this: escape anything that could redraw the terminal.
                render_plan(*context.output.out, style, printable_json(shown["data"]), args.flag("verbose"));
                *context.output.out << "\nApprove plan " << id << "? [y/N] " << std::flush;
                std::string answer;
                if (!std::getline(std::cin, answer) || !(answer == "y" || answer == "Y" || answer == "yes")) {
                    *context.output.err << "forti: not approved\n";
                    return engine::exit_code(Code::approval_required);
                }
            }
            json approved = engine::Engine::envelope([&] { return engine::approve_plan(context.engine, id, approver()); });
            bool apply_now = approved.value("ok", false) && !args.flag("yes") && at_terminal(context);
            int status = emit(context.output, approved, [&](std::ostream& out, const json& data, const json&) {
                if (data.contains("note")) out << data["note"].get<std::string>() << "\n";
                else out << std::format("Approved plan {} until {}.\n", data.value("plan_id", ""), data.value("expires_at", ""));
                if (data.contains("apply") && !apply_now) out << "next   " << data["apply"].get<std::string>() << "\n";
            });
            if (!apply_now) return status;
            if (!ask(context, "Apply now?", true)) {
                *context.output.out << std::format("Not applied. Later: forti apply {}\n", id);
                return status;
            }
            return execute(context, id);
        }

        int run_plan(Context& context, const Args& args) {
            std::string verb = args.positional.empty() ? "" : args.positional[0];
            if (verb == "show") return plan_show(context, args);
            if (verb == "list") return plan_list(context, args);
            if (verb == "approve") return plan_approve(context, args);

            json request = json::object();
            if (verb.empty()) {
                auto file = args.value("file");
                if (!file) throw Failure(Code::usage, "usage: forti plan --file changes.json|- (see forti plan --help)");
                json input = parse_json(read_input(*file), *file == "-" ? "stdin" : *file);
                if (input.is_array()) request["operations"] = std::move(input);
                else if (input.is_object()) request = std::move(input);
                else throw Failure(Code::usage, "the plan file must hold a request object or an array of operations");
            } else if (verb == "set" || verb == "create" || verb == "delete" || verb == "action") {
                if (args.value("file")) throw Failure(Code::usage, "--file cannot be combined with a plan subcommand");
                request["operations"] = json::array({operation_from_args(verb, args)});
            } else throw Failure(Code::usage, std::format("unknown plan subcommand \"{}\" (see forti plan --help)", verb));
            add_globals(request, args);

            Style style = style_for(STDOUT_FILENO);
            bool verbose = args.flag("verbose");
            json planned = engine::Engine::envelope([&] { return context.engine.plan(request); });
            if (!args.flag("apply") || !planned.value("ok", false))
                return emit(context.output, planned,
                            [&](std::ostream& out, const json& data, const json&) { render_plan(out, style, data, verbose); });

            // --apply: plan and apply in one command, as the profile's mode allows.
            std::string id = planned["data"].value("id", "");
            if (context.output.format == Format::json) {
                json applied = engine::Engine::envelope([&] { return context.engine.apply({{"plan_id", id}}); });
                if (applied.value("ok", false)) applied["data"]["plan"] = planned["data"];
                else if (applied["error"].contains("details") && applied["error"]["details"].is_object())
                    applied["error"]["details"]["plan"] = planned["data"];
                return emit(context.output, applied);
            }
            bool guarded = planned["data"].value("mode", "") == "guarded";
            if (guarded && at_terminal(context)) {
                // The plan was just printed in full by the question's preview: approve it here.
                if (!confirm_at_terminal(context, args, id, true, "plan")) return engine::exit_code(Code::approval_required);
            } else emit(context.output, planned, [&](std::ostream& out, const json& data, const json&) {
                render_plan(out, style, data, verbose);
                out << "\n";
            });
            return execute(context, id);
        }

        int run_apply(Context& context, const Args& args) {
            if (args.positional.size() > 1) throw Failure(Code::usage, "usage: forti apply [plan id]");
            Named named;
            json resolved = engine::Engine::envelope([&] {
                std::string given = named_or_terminal(context, args, 0, "forti apply <plan id>");
                named = name_plan(context, args, given);
                return engine::ok(json::object());
            });
            if (!resolved.value("ok", false)) return emit(context.output, resolved);
            if (!named.exact && context.output.format == Format::text)
                *context.output.err << std::format("forti: using plan {}\n", named.id);
            if (!confirm_at_terminal(context, args, named.id, named.exact, "plan"))
                return engine::exit_code(Code::approval_required);
            return execute(context, named.id);
        }

        // The rollback plan to apply: of PLAN (or PLAN itself when it is a rollback plan), else the
        // newest one of the profile not yet applied, which undoes the profile's last apply.
        int run_rollback(Context& context, const Args& args) {
            if (args.positional.size() > 1) throw Failure(Code::usage, "usage: forti rollback [plan id]");
            json target, undone;
            json resolved = engine::Engine::envelope([&] {
                json plans = stored_plans(context);
                auto find = [&](const std::string& id) -> json {
                    for (const auto& plan: plans) if (plan.value("id", "") == id) return plan;
                    return json();
                };
                if (!args.positional.empty()) {
                    std::string id = name_plan(context, args, args.positional[0]).id;
                    json plan = find(id);
                    if (plan.is_null()) throw Failure(Code::not_found, std::format("no plan {}", id));
                    if (plan.value("kind", "plan") == "rollback") target = plan;
                    else
                        for (const auto& candidate: plans)
                            if (candidate.value("kind", "") == "rollback" && candidate.value("rollback_of", "") == id) {
                                target = candidate;
                                break;
                            }
                    if (target.is_null())
                        throw Failure(Code::not_found, std::format("plan {} has no rollback plan: it was not applied, or nothing it "
                                                                   "did can be undone", id));
                } else {
                    auto profile = selected_profile(context, args);
                    for (const auto& plan: plans) {
                        if (plan.value("kind", "") != "rollback" || plan.value("state", "") == "applied") continue;
                        if (profile && plan.value("profile", "") != *profile) continue;
                        target = plan;
                        break;
                    }
                    if (target.is_null())
                        throw Failure(Code::not_found, std::format("nothing to roll back{}: no applied plan has a rollback plan "
                                                                   "waiting", profile ? " for profile " + *profile : ""),
                                      {{"hint", "forti plan list shows the stored plans"}});
                }
                if (target.value("state", "") == "applied")
                    throw Failure(Code::policy_denied, std::format("rollback plan {} was already applied", target.value("id", "")));
                undone = find(target.value("rollback_of", ""));
                return engine::ok(json::object());
            });
            if (!resolved.value("ok", false)) return emit(context.output, resolved);
            std::string id = target.value("id", "");
            if (context.output.format == Format::text) {
                std::string what = "Rolling back plan " + target.value("rollback_of", "");
                if (undone.is_object()) what += ": " + undone.value("summary", "");
                *context.output.out << printable(what) << "\n"
                                    << printable(std::format("with rollback plan {}: {}", id, target.value("summary", ""))) << "\n\n";
            }
            if (!confirm_at_terminal(context, args, id, false, "rollback plan")) return engine::exit_code(Code::approval_required);
            return execute(context, id);
        }

    }  // namespace

    std::vector<Command> plan_commands() {
        return {
            {"plan", "Preview changes as a stored, digest-bound plan",
             "usage: forti plan --file changes.json|-           plan a request ({operations: [...]}) or an array\n"
             "       forti plan set <resource> [key] attr=value... [--clear attr]\n"
             "       forti plan create <resource> attr=value... | --object JSON|@file\n"
             "       forti plan delete <resource> <key>\n"
             "       forti plan action <monitor/path> [--body JSON|@file]\n"
             "       forti plan show [id]\n"
             "       forti plan list\n"
             "       forti plan approve [id] [--yes]            guarded mode: approve a plan (CLI only)\n"
             "\n"
             "Planning reads the device and never changes it. The plan records the before-state, a field\n"
             "diff, the exact request body and a risk tier; `forti apply <id>` executes it once.\n"
             "--apply plans and applies in one command, as the profile's mode allows (guarded: at a\n"
             "terminal it asks for your approval; otherwise it stops at the approval).\n"
             "Values: attr=value is JSON when it parses as a number, boolean, array or object, else text.\n"
             "Table attributes (srcaddr, member, ...) are replaced wholesale by FortiOS: list every entry.\n"
             "Sensitive values (passwords, PSKs, keys, tokens) are redacted in all output; the stored plan\n"
             "file (0600) keeps them because apply needs them.\n"
             "\n"
             "Naming a plan: the full id, a unique prefix of it or of its last part (b75ef1), or latest.\n"
             "At a terminal, show, approve and apply without an id take the newest plan waiting to be\n"
             "applied (shown first). approve at a terminal then offers to apply it.\n"
             "\n"
             "options:\n"
             "  --apply      apply the new plan straight away (plan set/create/delete/action/--file)\n"
             "  --verbose    also print the plan digest\n"
             "  --yes, -y    approve: no question, and no offer to apply\n"
             "\n"
             "examples:\n"
             "  forti plan set firewall/address LAN comment=\"office LAN\" --clear color\n"
             "  forti plan create firewall/address name=web subnet=\"192.0.2.10 255.255.255.255\"\n"
             "  forti plan set system/global hostname=fw-lab --apply\n",
             {{"file", "clear", "object", "body"}, {"yes", "apply", "verbose"}, {{'f', "file"}, {'y', "yes"}}}, run_plan},
            {"apply", "Execute a stored plan (per the profile's mode)",
             "usage: forti apply [plan id]\n"
             "\n"
             "read-only profiles refuse. guarded profiles need a human approval: at a terminal, forti apply\n"
             "shows the plan and asks for it (the same approval as `forti plan approve <id>`); elsewhere run\n"
             "`forti plan approve <id>` first. autonomous profiles run without an approval. Every apply\n"
             "re-checks the plan digest, the device serial and every before-state, runs the operations in\n"
             "order without retries, verifies each one by re-reading, writes a rollback plan (`forti\n"
             "rollback`) and appends to the audit log. Critical-risk operations are followed by a\n"
             "management connectivity probe.\n"
             "\n"
             "The id may be a unique prefix (or its last part) or latest; at a terminal, without an id,\n"
             "the newest plan waiting to be applied (shown first, then confirmed).\n"
             "\n"
             "The rollback plan needs a working management path: it is not independent recovery. Have a\n"
             "console, out-of-band interface or device-side auto-revert before critical changes.\n",
             {{}, {"verbose"}, {}}, run_apply},
            {"rollback", "Undo the last applied plan with its rollback plan",
             "usage: forti rollback [plan id]\n"
             "\n"
             "Applies the rollback plan written when a plan was applied: without an id, the one of the\n"
             "profile's last apply (not yet rolled back); with an id, the rollback of that plan (or that\n"
             "rollback plan). It says what it undoes first, then applies like `forti apply`: guarded\n"
             "profiles need the human approval (asked inline at a terminal), read-only profiles refuse.\n"
             "A rollback is itself a plan: it re-checks the before-state, and it writes a rollback of its\n"
             "own, so `forti rollback` again re-does the change.\n"
             "\n"
             "A rollback needs a working management path to the device; it is not independent recovery.\n",
             {{}, {"verbose"}, {}}, run_rollback},
        };
    }

}  // namespace forti::cli
