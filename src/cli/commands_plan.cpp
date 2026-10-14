//
// forti plan / forti apply: build, inspect and approve stored plans, and execute them.
//
// Plans come from a JSON file (`forti plan --file changes.json`, `-` for stdin) or from the
// convenience forms (set / create / delete / action). `forti plan approve` is the guarded-mode human
// approval; it exists only here, never in forti-mcp.
//

#include "commands.hpp"

#include <forti/engine/approval.hpp>

#include <cstdio>
#include <cstdlib>
#include <format>
#include <fstream>
#include <iostream>
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

        void render_plan(std::ostream& out, const Style& style, const json& data) {
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
            out << "\n" << style.dim("digest " + data.value("digest", "")) << "\n";
            if (data.contains("state") && data["state"].is_object()) {
                const json& state = data["state"];
                out << "state  " << state.value("state", "");
                if (state["approval"].is_object())
                    out << std::format("  (approved by {} at {}, expires {})", state["approval"].value("approved_by", ""),
                                       state["approval"].value("approved_at", ""), state["approval"].value("expires_at", ""));
                out << "\n";
            }
            if (data.contains("mode") && data["mode"].is_string()) out << "mode   " << data["mode"].get<std::string>() << "\n";
            for (const auto& note: data.value("notes", json::array())) out << style.yellow("note") << "   " << note.get<std::string>() << "\n";
            if (data.contains("approve")) out << "approve  " << data["approve"].get<std::string>() << "\n";
            if (data.contains("apply")) out << "apply    " << data["apply"].get<std::string>() << "\n";
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
            if (record.contains("backup") && record["backup"].is_object())
                out << "backup    " << record["backup"].value("status", "") << ": " << record["backup"].value("reason", "") << "\n";
            if (record.contains("rollback") && record["rollback"].is_object()) {
                const json& rollback = record["rollback"];
                if (rollback["plan_id"].is_string())
                    out << "rollback  " << rollback["plan_id"].get<std::string>() << "  (" << rollback.value("apply", "") << ")\n";
                for (const auto& skipped: rollback.value("skipped", json::array()))
                    out << style.yellow("          no rollback for operation ") << skipped.value("index", 0) + 1 << ": "
                        << skipped.value("reason", "") << "\n";
            }
            if (record.contains("recovery")) out << style.red(record["recovery"].get<std::string>()) << "\n";
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
                auto object = args.value("object");
                if (!object || positional.size() != 2) throw Failure(Code::usage, "usage: forti plan create <resource> --object JSON|@file");
                std::string text = object->starts_with('@') ? read_input(object->substr(1)) : *object;
                return {{"op", "create"}, {"resource", resource}, {"object", parse_json(text, "--object")}};
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

        // ---- commands ----

        int plan_show(Context& context, const Args& args) {
            if (args.positional.size() != 2) throw Failure(Code::usage, "usage: forti plan show <id>");
            Style style = style_for(STDOUT_FILENO);
            return emit(context.output, engine::Engine::envelope([&] { return engine::show_plan(context.engine, args.positional[1]); }),
                        [&](std::ostream& out, const json& data, const json&) { render_plan(out, style, data); });
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
            if (args.positional.size() != 2) throw Failure(Code::usage, "usage: forti plan approve <id> [--yes]");
            const std::string& id = args.positional[1];
            Style style = style_for(STDOUT_FILENO);
            // A person at a terminal sees the plan and answers y/N; scripts (stdout not a TTY) and
            // --yes skip the question. The approval is operator intent, not a security ceremony.
            if (context.output.format == Format::text && !args.flag("yes") && ::isatty(STDOUT_FILENO) == 1) {
                json shown = engine::Engine::envelope([&] { return engine::show_plan(context.engine, id); });
                if (!shown.value("ok", false)) return emit(context.output, shown);
                // The person approving reads this: escape anything that could redraw the terminal.
                render_plan(*context.output.out, style, printable_json(shown["data"]));
                *context.output.out << "\nApprove plan " << id << "? [y/N] " << std::flush;
                std::string answer;
                if (!std::getline(std::cin, answer) || !(answer == "y" || answer == "Y" || answer == "yes")) {
                    *context.output.err << "forti: not approved\n";
                    return engine::exit_code(Code::approval_required);
                }
            }
            const char* user = std::getenv("USER");
            std::string by = std::string("cli:") + (user && *user ? user : "unknown");
            return emit(context.output, engine::Engine::envelope([&] { return engine::approve_plan(context.engine, id, by); }),
                        [](std::ostream& out, const json& data, const json&) {
                            if (data.contains("note")) out << data["note"].get<std::string>() << "\n";
                            else out << std::format("approved plan {} until {}\n", data.value("plan_id", ""), data.value("expires_at", ""));
                            if (data.contains("apply")) out << "apply    " << data["apply"].get<std::string>() << "\n";
                        });
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
            return emit(context.output, engine::Engine::envelope([&] { return context.engine.plan(request); }),
                        [&](std::ostream& out, const json& data, const json&) { render_plan(out, style, data); });
        }

        int run_apply(Context& context, const Args& args) {
            if (args.positional.size() != 1) throw Failure(Code::usage, "usage: forti apply <plan id>");
            json envelope = engine::Engine::envelope([&] { return context.engine.apply({{"plan_id", args.positional[0]}}); });
            Style style = style_for(STDOUT_FILENO);
            // A stopped apply still carries its execution record: show it before the error.
            if (context.output.format == Format::text && !envelope.value("ok", false)) {
                const json& details = envelope["error"].contains("details") ? envelope["error"]["details"] : json();
                if (details.is_object() && details.contains("operations"))
                    render_record(*context.output.err, style_for(STDERR_FILENO), printable_json(details));
                if (details.is_object() && details.contains("approve_command") && details["approve_command"].is_string())
                    *context.output.err << "approve with: " << printable(details["approve_command"].get<std::string>()) << "\n";
            }
            return emit(context.output, envelope, [&](std::ostream& out, const json& data, const json&) {
                out << style.bold(std::format("Applied plan {}", data.value("plan_id", ""))) << std::format(
                        "  ({} verified, {} applied but unverified)\n", data.value("verified", 0), data.value("applied_unverified", 0));
                render_record(out, style, data);
            });
        }

    }  // namespace

    std::vector<Command> plan_commands() {
        return {
            {"plan", "Preview changes as a stored, digest-bound plan",
             "usage: forti plan --file changes.json|-           plan a request ({operations: [...]}) or an array\n"
             "       forti plan set <resource> [key] attr=value... [--clear attr]\n"
             "       forti plan create <resource> --object JSON|@file\n"
             "       forti plan delete <resource> <key>\n"
             "       forti plan action <monitor/path> [--body JSON|@file]\n"
             "       forti plan show <id>\n"
             "       forti plan list\n"
             "       forti plan approve <id> [--yes]            guarded mode: approve a plan (CLI only)\n"
             "\n"
             "Planning reads the device and never changes it. The plan records the before-state, a field\n"
             "diff, the exact request body and a risk tier; `forti apply <id>` executes it once.\n"
             "Values: attr=value is JSON when it parses as a number, boolean, array or object, else text.\n"
             "Table attributes (srcaddr, member, ...) are replaced wholesale by FortiOS: list every entry.\n"
             "Sensitive values (passwords, PSKs, keys, tokens) are redacted in all output; the stored plan\n"
             "file (0600) keeps them because apply needs them.\n"
             "\n"
             "examples:\n"
             "  forti plan set firewall/address LAN comment=\"office LAN\" --clear color\n"
             "  forti plan create firewall/address --object '{\"name\":\"web\",\"subnet\":\"192.0.2.10 255.255.255.255\"}'\n"
             "  forti plan set system/global hostname=fw-lab\n",
             {{"file", "clear", "object", "body"}, {"yes"}, {{'f', "file"}, {'y', "yes"}}}, run_plan},
            {"apply", "Execute a stored plan (per the profile's mode)",
             "usage: forti apply <plan id>\n"
             "\n"
             "read-only profiles refuse. guarded profiles need `forti plan approve <id>` first. autonomous\n"
             "profiles run without an approval. Every apply re-checks the plan digest, the device serial and\n"
             "every before-state, runs the operations in order without retries, verifies each one by\n"
             "re-reading, writes a rollback plan and appends to the audit log. Critical-risk operations are\n"
             "followed by a management connectivity probe.\n"
             "\n"
             "The rollback plan needs a working management path: it is not independent recovery. Have a\n"
             "console, out-of-band interface or device-side auto-revert before critical changes.\n",
             {}, run_apply},
        };
    }

}  // namespace forti::cli
