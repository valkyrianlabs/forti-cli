//
// Changing the device: forti set / create / delete (one command, at most one question), forti plan
// (preview and save), forti apply, forti approve and forti rollback.
//
// Every change is a stored plan underneath: the before-state, a field diff, the exact request body,
// a risk tier and a digest. Apply re-checks all of it, verifies by re-reading, writes a rollback plan
// and an audit record. The commands only decide how much of that a person has to see:
//
//   read-only    the change is shown; nothing is written
//   guarded      shown, then one question at a terminal: "Apply these changes?" Without a terminal
//                (scripts, an agent's shell) it stops there: a missing terminal is never a yes. The
//                person approves with `forti approve ID`, or the agent's MCP client asks in the chat.
//   autonomous   shown and applied
//
// Plans can be named by a unique prefix, or (where only one is waiting for the profile) not at all.
//

#include "commands.hpp"
#include "setup_support.hpp"
#include "tty.hpp"

#include <forti/engine/approval.hpp>

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <format>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <regex>
#include <set>
#include <sstream>

#include <ctime>
#include <poll.h>
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

        // " \"web\"", or for a child table entry " \"1\" reserved-address \"7\"".
        std::string target_of(const json& op) {
            std::string out;
            if (op.contains("parent")) out += " " + show(op["parent"]) + " " + op.value("child", "");
            if (op.contains("key")) out += " " + show(op["key"]);
            return out;
        }

        void render_operation(std::ostream& out, const Style& style, const json& op, bool wire = true) {
            std::string key = target_of(op);
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
            if (wire && op.contains("wire") && op["wire"].is_object()) {
                const json& request = op["wire"];
                out << "     " << style.dim(std::format("{} {}", request.value("method", ""), request.value("path", "")));
                if (request.contains("body") && !request["body"].is_null()) out << style.dim(" " + request["body"].dump());
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
                out << "next   " << data["apply"].get<std::string>() << "  (asks once, then applies)\n"
                    << "       or let the agent that made it apply it: " << data["approve"].get<std::string>() << "\n";
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
                std::string key = target_of(op);
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


        // A change as a person reviews it before saying yes: what it does and where, then each operation
        // with its attribute diff. The request lines and the digest only with --verbose (the stored plan
        // keeps them; `forti plan show` prints them).
        void render_change(std::ostream& out, const Style& style, const json& data, bool verbose) {
            out << style.bold(data.value("summary", "")) << "\n";
            if (data.value("kind", "plan") == "rollback") out << "Undoes plan " << data.value("rollback_of", "") << "\n";
            const json& device = data.value("device", json::object());
            if (!device.value("vdom", "").empty()) out << "vdom " << device.value("vdom", "") << "\n";
            for (const auto& op: data.value("operations", json::array())) render_operation(out, style, op, verbose);
            for (const auto& note: data.value("notes", json::array())) {
                std::string text = note.get<std::string>();
                // The mode notes are what the command does next, which it says itself.
                if (text.starts_with("guarded mode:") || text.starts_with("autonomous mode:") ||
                    (text.starts_with("profile ") && text.find("is read-only") != std::string::npos))
                    continue;
                out << style.yellow("note") << " " << text << "\n";
            }
            out << style.dim("plan " + data.value("id", "") + (verbose ? "  digest " + data.value("digest", "") : "")) << "\n";
        }

        // ---- a person at a terminal ----

        // Text output with stdin and stdout both terminals. Scripts and agents' shell tools have
        // neither, and nothing there is ever taken as a person's approval.
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

        // Newest first. created_at has whole seconds; within one second created_ns decides, and for plans
        // made before 0.3 (no created_ns) the plan file's time.
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
                if (at != bt) return at > bt;
                if (a.contains("created_ns") && b.contains("created_ns") && a["created_ns"] != b["created_ns"])
                    return a["created_ns"].get<std::int64_t>() > b["created_ns"].get<std::int64_t>();
                return written(a) > written(b);
            });
            return plans;
        }

        bool pending(const json& plan) {
            std::string state = plan.value("state", "");
            return state == "pending" || state == "approved" || state == "approval_expired";
        }

        // Plans made within this window can be picked without naming them. Older ones are forgotten
        // drafts more often than intended changes: they need their id.
        constexpr auto recent = std::chrono::hours(24);

        bool made_recently(const json& plan) {
            std::string created = plan.value("created_at", "");   // "2026-10-16T15:05:40Z"
            std::tm tm{};
            std::istringstream in(created);
            in >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
            if (in.fail()) return false;
            auto made = std::chrono::system_clock::from_time_t(::timegm(&tm));
            return std::chrono::system_clock::now() - made < recent;
        }

        struct Named {
            std::string id;
            bool exact = true;   // typed in full: nothing to show before acting
        };

        std::string short_line(const json& plan) {
            return std::format("{}  {}", plan.value("id", ""), plan.value("summary", ""));
        }

        // `given`: a complete id or a unique prefix of one (or of its random tail, "b75ef1"), acted on
        // as named. `latest` or nothing: the plan waiting to be applied for the selected profile, made
        // in the last day, but only when exactly one is waiting: with two agents (or two drafts) on one
        // device "the newest" is a guess, and forti never applies a plan it guessed. At a terminal the
        // person picks from the list instead. `for_show`: `latest` is simply the newest plan.
        Named name_plan(Context& context, const Args& args, const std::string& given, bool for_show = false) {
            if (complete_id(given)) return {given, true};
            json plans = stored_plans(context);
            if (given.empty() || given == "latest") {
                auto profile = selected_profile(context, args);
                std::vector<json> waiting;
                for (const auto& plan: plans) {
                    if (plan.value("kind", "plan") == "rollback") continue;
                    if (profile && plan.value("profile", "") != *profile) continue;
                    if (for_show) return {plan.value("id", ""), false};
                    if (pending(plan) && made_recently(plan)) waiting.push_back(plan);
                }
                std::string whose = profile ? std::format(" for profile {}", *profile) : "";
                if (waiting.empty())
                    throw Failure(Code::not_found, std::format("no plan{} is waiting to be applied", whose),
                                  {{"hint", "forti plan list shows the stored plans; name an older one by its id"}});
                if (waiting.size() == 1) return {waiting.front().value("id", ""), false};
                if (at_terminal(context)) {
                    *context.output.out << std::format("{} plans are waiting{}:\n", waiting.size(), whose);
                    for (std::size_t i = 0; i < waiting.size(); ++i)
                        *context.output.out << std::format("  {}) {}\n", i + 1, printable(short_line(waiting[i])));
                    *context.output.out << "Which one? (Enter: none) " << std::flush;
                    std::string answer;
                    std::getline(std::cin, answer);
                    answer = trim(answer);
                    std::size_t choice = 0;
                    auto [end, ec] = std::from_chars(answer.data(), answer.data() + answer.size(), choice);
                    if (answer.empty() || ec != std::errc() || end != answer.data() + answer.size() || choice < 1 ||
                        choice > waiting.size())
                        throw Failure(Code::usage, "no plan chosen; nothing was done");
                    return {waiting[choice - 1].value("id", ""), false};
                }
                std::vector<std::string> ids;
                std::string list;
                for (const auto& plan: waiting) {
                    ids.push_back(plan.value("id", ""));
                    list += "\n  " + short_line(plan);
                }
                throw Failure(Code::usage, std::format("{} plans are waiting{}; name one:{}", waiting.size(), whose, list),
                              {{"candidates", ids}, {"hint", "pass its id (or a unique prefix, or its last part)"}});
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

        // Without a terminal a plan is named: scripts and agents act only on the plan they made.
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

        // An attribute assignment, as opposed to a resource word or a key: FortiOS attribute names are
        // letters, digits, '-' and '_'.
        bool is_assignment(const std::string& word) {
            auto eq = word.find('=');
            return eq != std::string::npos && eq > 0 &&
                   std::all_of(word.begin(), word.begin() + static_cast<std::ptrdiff_t>(eq), [](char c) {
                       return std::isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_';
                   });
        }

        void add_globals(json& request, const Args& args) {
            if (auto profile = args.value("profile")) request["profile"] = *profile;
            if (auto vdom = args.value("vdom")) request["vdom"] = *vdom;
        }

        struct Target {
            std::string resource;
            std::optional<std::string> key;
        };

        // The object a change names, spelled as for `forti get`: firewall/address web,
        // firewall/address/web, firewall address web, or address web (a last word only one resource
        // has). The plan records the resolved name, which the person sees before anything changes. A
        // spelling nothing matches is passed on as typed, so the engine names the problem.
        Target target(const std::vector<std::string>& words) {
            const auto& catalog = engine::Catalog::instance();
            if (words.size() == 1 && !catalog.find(words[0]))
                if (auto keyed = catalog.keyed(words[0])) return {std::string(keyed->resource->name()), keyed->key};
            for (std::size_t take = words.size(); take >= 1 && words.size() - take <= 1; --take) {
                auto found = catalog.match(std::vector<std::string>(words.begin(), words.begin() + static_cast<std::ptrdiff_t>(take)));
                if (found.resource) {
                    Target out{std::string(found.resource->name()), std::nullopt};
                    if (take < words.size()) out.key = words[take];
                    return out;
                }
                if (!found.candidates.empty()) {
                    // Ambiguous: lookup() throws with the candidates.
                    std::string spelled;
                    for (std::size_t i = 0; i < take; ++i) spelled += (i ? " " : "") + words[i];
                    (void) catalog.lookup(spelled);
                    break;
                }
            }
            if (words.size() > 2)
                throw Failure(Code::usage, std::format("no resource is named \"{}\"", [&] {
                                  std::string joined;
                                  for (const auto& word: words) joined += (joined.empty() ? "" : " ") + word;
                                  return joined;
                              }()),
                              {{"hint", "name it as for forti get: firewall/address web, or firewall/address/web"}});
            Target out{words[0], std::nullopt};
            if (words.size() == 2) out.key = words[1];
            return out;
        }

        // --parent KEY --child ATTR: the operation changes one entry of the object's table attribute
        // (a child table) instead of the object; the key (set, delete) is then the entry's.
        json with_child(json op, const Args& args) {
            auto parent = args.value("parent"), child = args.value("child");
            if (!parent && !child) return op;
            if (!parent || !child)
                throw Failure(Code::usage, "--parent and --child go together: the object's key and its table attribute",
                              {{"hint", "forti set system.dhcp/server 7 --parent 1 --child reserved-address description=nas"}});
            op["parent"] = *parent;
            op["child"] = *child;
            return op;
        }

        // The operation from `forti <verb> ...` or `forti plan <verb> ...`; `words` starts at the
        // resource.
        json operation_from_words(const std::string& verb, const std::vector<std::string>& words, const Args& args) {
            std::string usage = verb == "delete" ? "usage: forti delete <resource> <key>"
                              : verb == "create" ? "usage: forti create <resource> attr=value... | --object JSON|@file"
                              : verb == "action" ? "usage: forti plan action <monitor/path> [--body JSON|@file]"
                                                 : "usage: forti set <resource> [key] attr=value... [--clear attr]";
            if (words.empty()) throw Failure(Code::usage, usage);
            if (verb == "action") {
                if (words.size() != 1) throw Failure(Code::usage, usage);
                if (args.value("parent") || args.value("child"))
                    throw Failure(Code::usage, "--parent and --child address a child table entry: not an action");
                json body = json::object();
                if (auto given = args.value("body"))
                    body = parse_json(given->starts_with('@') ? read_input(given->substr(1)) : *given, "--body");
                return {{"op", "action"}, {"resource", words[0]}, {"body", body}};
            }
            std::vector<std::string> names, assignments;
            for (const auto& word: words) (assignments.empty() && !is_assignment(word) ? names : assignments).push_back(word);
            for (const auto& word: assignments)
                if (!is_assignment(word)) throw Failure(Code::usage, std::format("expected attribute=value, got \"{}\"", word), {{"hint", usage}});
            if (names.empty()) throw Failure(Code::usage, usage);
            Target where = target(names);

            if (verb == "delete") {
                if (!assignments.empty() || !where.key) throw Failure(Code::usage, usage);
                return with_child({{"op", "delete"}, {"resource", where.resource}, {"key", *where.key}}, args);
            }
            if (verb == "create") {
                if (where.key)
                    throw Failure(Code::usage, std::format("create takes the new object's attributes, not a key: {} name={} ...",
                                                           where.resource, *where.key), {{"hint", usage}});
                auto given = args.value("object");
                if (!given && assignments.empty()) throw Failure(Code::usage, usage);
                json object = json::object();
                if (given) {
                    object = parse_json(given->starts_with('@') ? read_input(given->substr(1)) : *given, "--object");
                    if (!object.is_object()) throw Failure(Code::usage, "--object must be a JSON object");
                }
                for (const auto& word: assignments) {   // the pairs win over --object
                    auto [name, value] = assignment(word);
                    object[name] = std::move(value);
                }
                return with_child({{"op", "create"}, {"resource", where.resource}, {"object", object}}, args);
            }
            // set: a table needs a key; a singleton takes attributes straight away.
            json op = {{"op", "update"}, {"resource", where.resource}};
            const engine::Resource* known = engine::Catalog::instance().find(where.resource);
            bool singleton = known && known->kind == engine::Kind::singleton;
            if (singleton && where.key)
                throw Failure(Code::usage, std::format("{} is a singleton: it has no key (forti set {} attr=value...)",
                                                       where.resource, where.resource));
            if (!singleton) {
                if (!where.key) throw Failure(Code::usage, "usage: forti set <resource> <key> attr=value... [--clear attr]");
                op["key"] = *where.key;
            }
            json set = json::object();
            for (const auto& word: assignments) {
                auto [name, value] = assignment(word);
                set[name] = std::move(value);
            }
            if (!set.empty()) op["set"] = std::move(set);
            if (auto clear = args.all("clear"); !clear.empty()) op["clear"] = clear;
            if (!op.contains("set") && !op.contains("clear"))
                throw Failure(Code::usage, "nothing to change: give attr=value pairs or --clear attr", {{"hint", usage}});
            return with_child(std::move(op), args);
        }

        // ---- apply, shared by every command that executes a plan ----

        // Executes plan `id` and prints the record (on failure, before the error).
        int execute(Context& context, const std::string& id) {
            json envelope = engine::Engine::envelope([&] { return context.engine.apply({{"plan_id", id}}); });
            Style style = style_for(STDOUT_FILENO);
            // A stopped apply still carries its execution record: show it before the error.
            if (context.output.format == Format::text && !envelope.value("ok", false)) {
                const json& details = envelope["error"].contains("details") ? envelope["error"]["details"] : json();
                if (details.is_object() && details.contains("operations"))
                    render_record(*context.output.err, style_for(STDERR_FILENO), printable_json(details));
            }
            return emit(context.output, envelope, [&](std::ostream& out, const json& data, const json&) {
                out << style.green(outcome(data)) << "\n";
                render_record(out, style, data);
            });
        }

        // The one question of guarded mode, asked of a person at a terminal about the change just
        // shown. Yes records the approval (the same record as `forti approve`, bound to the plan's
        // digest) and returns true.
        bool approve_here(Context& context, const std::string& id, const std::string& digest) {
            if (!ask(context, "Apply these changes?", false)) {
                *context.output.err << "Nothing was changed.\n";
                return false;
            }
            json approved = engine::Engine::envelope(
                    [&] { return engine::approve_plan(context.engine, id, approver(), std::chrono::hours(24), digest); });
            if (!approved.value("ok", false)) {
                emit(context.output, approved);
                return false;
            }
            return true;
        }

        // A guarded plan without an approval, and no terminal to ask on: say how a person approves it.
        int needs_approval(Context& context, const std::string& id) {
            json envelope = {{"ok", false},
                             {"error", {{"code", "approval_required"},
                                        {"message", std::format("this change needs your approval (guarded mode); nothing was changed")},
                                        {"details", {{"plan_id", id},
                                                     {"approve_command", std::format("forti approve {}", id)},
                                                     {"hint", std::format("in a terminal: forti apply {0} (shows it, asks once, applies), or "
                                                                          "forti approve {0} to let the agent that made it apply it", id)}}}}}};
            return emit(context.output, envelope);
        }

        // Shows plan `id` (already loaded as `data`) and executes it as the profile's mode allows:
        // read-only refuses with the command that allows changes; guarded asks once at a terminal
        // (and otherwise stops at the approval); autonomous applies. The way every change is made.
        int review_and_apply(Context& context, const Args& args, const std::string& id, const json& data) {
            Style style = style_for(STDOUT_FILENO);
            std::string mode = data.value("mode", json()).is_string() ? data["mode"].get<std::string>() : "";
            bool approved = data.contains("state") && data["state"].is_object() && data["state"].value("state", "") == "approved";
            // The person deciding reads this: escape anything that could redraw the terminal.
            render_change(*context.output.out, style, printable_json(data), args.flag("verbose"));
            *context.output.out << "\n";
            if (mode == "read-only") {
                std::string profile = data.value("device", json::object()).value("profile", "");
                *context.output.err << std::format("Profile {0} is read-only: nothing was changed.\n"
                                                   "  To allow changes: forti profile mode {0} guarded (you approve each change) or "
                                                   "autonomous. Then: forti apply {1}\n", profile, id);
                return engine::exit_code(Code::policy_denied);
            }
            if (mode == "guarded" && !approved) {
                if (!at_terminal(context)) return needs_approval(context, id);
                if (!approve_here(context, id, data.value("digest", ""))) return engine::exit_code(Code::approval_required);
            }
            return execute(context, id);
        }

        // ---- commands ----

        int plan_show(Context& context, const Args& args) {
            if (args.positional.size() > 2) throw Failure(Code::usage, "usage: forti plan show [id]");
            Style style = style_for(STDOUT_FILENO);
            bool verbose = args.flag("verbose");
            json envelope = engine::Engine::envelope([&] {
                std::string given = named_or_terminal(context, args, 1, "forti plan show <id>");
                return engine::show_plan(context.engine, name_plan(context, args, given, true).id);
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

        // Approves one plan for whoever made it (an agent, a script) to apply. A person at a terminal
        // sees it and answers; without a terminal only an explicit --yes approves.
        int approve_one(Context& context, const Args& args, std::size_t index) {
            if (args.positional.size() > index + 1) throw Failure(Code::usage, "usage: forti approve [id] [--yes] | --watch");
            bool interactive = at_terminal(context) && !args.flag("yes");
            if (!interactive && !args.flag("yes"))
                throw Failure(Code::approval_required, "approving needs a person: run it in a terminal, or pass --yes",
                              {{"hint", "an approval is your decision about a change: forti never takes a missing terminal as a yes"}});
            Named named;
            json resolved = engine::Engine::envelope([&] {
                std::string given = named_or_terminal(context, args, index, "forti approve <id> --yes");
                named = name_plan(context, args, given);
                return engine::ok(json::object());
            });
            if (!resolved.value("ok", false)) return emit(context.output, resolved);
            const std::string& id = named.id;
            std::string digest;   // the plan the person was shown
            if (interactive) {
                json shown = engine::Engine::envelope([&] { return engine::show_plan(context.engine, id); });
                if (!shown.value("ok", false)) return emit(context.output, shown);
                render_change(*context.output.out, style_for(STDOUT_FILENO), printable_json(shown["data"]), args.flag("verbose"));
                *context.output.out << "\n";
                if (!ask(context, "Approve these changes?", false)) {
                    *context.output.err << "Not approved.\n";
                    return engine::exit_code(Code::approval_required);
                }
                digest = shown["data"].value("digest", "");
            }
            json approved = engine::Engine::envelope(
                    [&] { return engine::approve_plan(context.engine, id, approver(), std::chrono::hours(24), digest); });
            return emit(context.output, approved, [&](std::ostream& out, const json& data, const json&) {
                if (data.contains("note")) out << data["note"].get<std::string>() << "\n";
                else out << std::format("Approved plan {} until {}. The agent can apply it now (or: forti apply {}).\n",
                                        data.value("plan_id", ""), data.value("expires_at", ""), data.value("plan_id", ""));
            });
        }

        // `forti approve --watch`: approve plans as agents make them, one question each, in a terminal
        // left open next to the agent. Plans already waiting (made in the last hour) come first.
        int approve_watch(Context& context, const Args& args) {
            if (!at_terminal(context))
                throw Failure(Code::usage, "--watch asks you about each plan: it needs a terminal");
            auto profile = args.value("profile");
            Style style = style_for(STDOUT_FILENO);
            *context.output.out << std::format("Watching for changes that need your approval{}. Ctrl-C (or q) stops.\n\n",
                                               profile ? " on profile " + *profile : "");
            std::set<std::string> seen;
            auto started = std::chrono::system_clock::now();
            std::filesystem::path dir = context.engine.options().paths.state / "plans";
            std::filesystem::file_time_type last{};
            for (;;) {
                std::error_code error;
                auto changed = std::filesystem::last_write_time(dir, error);
                if (!error && changed != last) {
                    last = changed;
                    json plans = stored_plans(context);
                    std::reverse(plans.begin(), plans.end());   // oldest first: in the order they were made
                    for (const auto& plan: plans) {
                        std::string id = plan.value("id", "");
                        if (seen.contains(id)) continue;
                        if (plan.value("state", "") != "pending" && plan.value("state", "") != "approval_expired") continue;
                        if (profile && plan.value("profile", "") != *profile) continue;
                        std::string created = plan.value("created_at", "");
                        std::tm tm{};
                        std::istringstream in(created);
                        in >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
                        if (in.fail() || std::chrono::system_clock::from_time_t(::timegm(&tm)) < started - std::chrono::hours(1)) continue;
                        seen.insert(id);
                        json shown = engine::Engine::envelope([&] { return engine::show_plan(context.engine, id); });
                        if (!shown.value("ok", false) || shown["data"].value("mode", json()) != "guarded") continue;
                        render_change(*context.output.out, style, printable_json(shown["data"]), args.flag("verbose"));
                        *context.output.out << "\n";
                        if (!ask(context, "Approve these changes?", false)) {
                            *context.output.out << "Not approved.\n\n";
                            continue;
                        }
                        std::string digest = shown["data"].value("digest", "");
                        json approved = engine::Engine::envelope([&] {
                            return engine::approve_plan(context.engine, id, approver(), std::chrono::hours(24), digest);
                        });
                        if (!approved.value("ok", false)) emit(context.output, approved);
                        else *context.output.out << style.green("Approved") << ": the agent can apply it now.\n\n";
                    }
                }
                // Wait for the next plan, watching the terminal: end of input (Ctrl-D) or q stops.
                struct pollfd input{STDIN_FILENO, POLLIN, 0};
                if (::poll(&input, 1, 500) > 0) {
                    std::string line;
                    if (!std::getline(std::cin, line) || trim(line) == "q") return 0;
                }
            }
        }

        int run_approve(Context& context, const Args& args) {
            if (args.flag("watch")) {
                if (!args.positional.empty()) throw Failure(Code::usage, "usage: forti approve --watch");
                return approve_watch(context, args);
            }
            return approve_one(context, args, 0);
        }

        // Plans `request` and makes the change as the profile's mode allows (plan --apply, set, create,
        // delete). --json: no questions; a guarded plan stops at the approval.
        int plan_and_apply(Context& context, const Args& args, const json& request) {
            json planned = engine::Engine::envelope([&] { return context.engine.plan(request); });
            if (!planned.value("ok", false)) return emit(context.output, planned);
            std::string id = planned["data"].value("id", "");
            if (context.output.format == Format::json) {
                json applied = engine::Engine::envelope([&] { return context.engine.apply({{"plan_id", id}}); });
                if (applied.value("ok", false)) applied["data"]["plan"] = planned["data"];
                else if (applied["error"].contains("details") && applied["error"]["details"].is_object())
                    applied["error"]["details"]["plan"] = planned["data"];
                return emit(context.output, applied);
            }
            return review_and_apply(context, args, id, planned["data"]);
        }

        int run_plan(Context& context, const Args& args) {
            std::string verb = args.positional.empty() ? "" : args.positional[0];
            if (verb == "show") return plan_show(context, args);
            if (verb == "list") return plan_list(context, args);
            if (verb == "approve") return approve_one(context, args, 1);

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
                std::vector<std::string> words(args.positional.begin() + 1, args.positional.end());
                request["operations"] = json::array({operation_from_words(verb, words, args)});
            } else throw Failure(Code::usage, std::format("unknown plan subcommand \"{}\" (see forti plan --help)", verb));
            add_globals(request, args);

            if (args.flag("apply")) return plan_and_apply(context, args, request);
            Style style = style_for(STDOUT_FILENO);
            bool verbose = args.flag("verbose");
            return emit(context.output, engine::Engine::envelope([&] { return context.engine.plan(request); }),
                        [&](std::ostream& out, const json& data, const json&) { render_plan(out, style, data, verbose); });
        }

        // forti set | create | delete: one command, at most one question.
        int run_change(Context& context, const Args& args, const std::string& verb) {
            json request = {{"operations", json::array({operation_from_words(verb, args.positional, args)})}};
            add_globals(request, args);
            if (args.flag("dry-run")) {
                Style style = style_for(STDOUT_FILENO);
                bool verbose = args.flag("verbose");
                return emit(context.output, engine::Engine::envelope([&] { return context.engine.plan(request); }),
                            [&](std::ostream& out, const json& data, const json&) { render_plan(out, style, data, verbose); });
            }
            return plan_and_apply(context, args, request);
        }

        int run_set(Context& context, const Args& args) { return run_change(context, args, "set"); }
        int run_create(Context& context, const Args& args) { return run_change(context, args, "create"); }
        int run_delete(Context& context, const Args& args) { return run_change(context, args, "delete"); }

        // Shows the named plan and applies it as its profile's mode allows. A plan named exactly (or
        // already approved) in autonomous mode runs without being shown again.
        int apply_named(Context& context, const Args& args, const Named& named) {
            const std::string& id = named.id;
            if (context.output.format == Format::json) return execute(context, id);
            json shown = engine::Engine::envelope([&] { return engine::show_plan(context.engine, id); });
            if (!shown.value("ok", false)) return emit(context.output, shown);
            const json& data = shown["data"];
            std::string state = data["state"].value("state", "");
            if (state == "applied") return execute(context, id);   // apply refuses, with the reason
            return review_and_apply(context, args, id, data);
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
            return apply_named(context, args, named);
        }

        // The rollback plan to apply: of PLAN (or PLAN itself when it is a rollback plan), else the
        // newest one of the profile not yet applied, which undoes the profile's last apply.
        int run_rollback(Context& context, const Args& args) {
            if (args.positional.size() > 1) throw Failure(Code::usage, "usage: forti rollback [plan id]");
            json target;
            json resolved = engine::Engine::envelope([&] {
                json plans = stored_plans(context);
                if (!args.positional.empty()) {
                    std::string id = name_plan(context, args, args.positional[0], true).id;
                    json plan;
                    for (const auto& candidate: plans) if (candidate.value("id", "") == id) plan = candidate;
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
                                      {{"hint", "forti history shows what was applied"}});
                }
                if (target.value("state", "") == "applied")
                    throw Failure(Code::policy_denied, std::format("rollback plan {} was already applied", target.value("id", "")));
                return engine::ok(json::object());
            });
            if (!resolved.value("ok", false)) return emit(context.output, resolved);
            return apply_named(context, args, {target.value("id", ""), false});
        }

    }  // namespace

    std::vector<Command> plan_commands() {
        constexpr std::string_view change_notes =
                "Resources are named as for forti get: firewall/address web, firewall/address/web, firewall\n"
                "address web, or address web. Values: attr=value is JSON when it parses as a number, boolean,\n"
                "array or object, else text. Table attributes (srcaddr, member, ...) are replaced wholesale by\n"
                "FortiOS: list every entry, or change one entry with --parent KEY --child ATTR.\n"
                "\n"
                "What happens follows the profile's mode. read-only: shows the change, changes nothing.\n"
                "guarded: shows the change and asks once, \"Apply these changes?\" (without a terminal it stops\n"
                "there: approve with forti approve ID). autonomous: applies without asking. Every change is\n"
                "planned first (the before-state is read and checked again just before writing), verified by\n"
                "re-reading, recorded in the audit log (forti history), and can be undone with forti rollback.\n";
        static const std::string set_help = std::string(
                "usage: forti set <resource> [key] attr=value... [--clear attr]\n"
                "\n"
                "Change attributes of a table object, or of a singleton (no key).\n"
                "\n") + std::string(change_notes) +
                "\n"
                "options:\n"
                "  --clear ATTR   reset an attribute to its default (repeatable)\n"
                "  --parent KEY   with --child: change one entry of object KEY's table attribute ATTR; the\n"
                "  --child ATTR   key is the entry's, and only that entry is read, written and verified\n"
                "  --dry-run      show the plan; change nothing (same as forti plan set)\n"
                "  --verbose      also show the request lines and the plan digest\n"
                "\n"
                "examples:\n"
                "  forti set firewall/address/web comment=\"Web server\"\n"
                "  forti set system global hostname=fw-lab\n"
                "  forti set firewall/policy 7 status=disable\n"
                "  forti set system.dhcp/server 21 --parent 1 --child reserved-address description=printer\n";
        static const std::string create_help = std::string(
                "usage: forti create <resource> attr=value... [--object JSON|@file]\n"
                "\n"
                "Create a table object. attr=value pairs win over --object.\n"
                "\n") + std::string(change_notes) +
                "\n"
                "options:\n"
                "  --object JSON  the object as JSON (@file reads a file, @- standard input)\n"
                "  --parent KEY   with --child: add one entry to object KEY's table attribute ATTR (a\n"
                "  --child ATTR   numeric id left out or 0 is assigned by the device)\n"
                "  --dry-run      show the plan; change nothing\n"
                "  --verbose      also show the request lines and the plan digest\n"
                "\n"
                "examples:\n"
                "  forti create firewall/address name=web subnet=\"192.0.2.10 255.255.255.255\"\n"
                "  forti create system.dhcp/server --parent 1 --child reserved-address ip=192.0.2.50 \\\n"
                "      mac=00:00:5e:00:53:32 description=printer\n";
        static const std::string delete_help = std::string(
                "usage: forti delete <resource> <key>\n"
                "\n"
                "Delete a table object, or (--parent, --child) one entry of an object's table attribute.\n"
                "\n") + std::string(change_notes) +
                "\n"
                "options:\n"
                "  --parent KEY   with --child: delete entry <key> of object KEY's table attribute ATTR\n"
                "  --child ATTR\n"
                "  --dry-run      show the plan; change nothing\n"
                "  --verbose      also show the request lines and the plan digest\n"
                "\n"
                "examples:\n"
                "  forti delete firewall/address/web\n"
                "  forti delete system.dhcp/server 21 --parent 1 --child reserved-address\n";
        return {
            {"set", "Change an object's attributes", set_help,
             {{"clear", "parent", "child"}, {"dry-run", "verbose"}, {}}, run_set},
            {"create", "Create an object", create_help, {{"object", "parent", "child"}, {"dry-run", "verbose"}, {}}, run_create},
            {"delete", "Delete an object", delete_help, {{"parent", "child"}, {"dry-run", "verbose"}, {}}, run_delete},
            {"rollback", "Undo the last change (or a named one)",
             "usage: forti rollback [plan id]\n"
             "\n"
             "Applies the rollback plan written when a change was applied: without an id, the one of the\n"
             "profile's last change not yet rolled back; with an id, the rollback of that plan (or that\n"
             "rollback plan). It shows what it undoes, then applies as the profile's mode allows (guarded:\n"
             "one question). A rollback is itself a change: it re-checks the before-state, and it writes a\n"
             "rollback of its own, so forti rollback again re-does the change.\n"
             "\n"
             "A rollback needs a working management path to the device; it is not independent recovery.\n",
             {{}, {"verbose"}, {}}, run_rollback},
            {"approve", "Approve a change an agent planned (guarded mode)",
             "usage: forti approve [id] [--yes]\n"
             "       forti approve --watch [-p PROFILE]\n"
             "\n"
             "Approves a plan so the agent (or script) that made it can apply it; the approval is bound to\n"
             "the plan's exact content and is used once. At a terminal it shows the change and asks; without\n"
             "an id it takes the plan waiting for the profile (when only one is). Without a terminal only\n"
             "--yes approves. To approve and apply a plan yourself, use forti apply.\n"
             "\n"
             "--watch keeps asking: each plan an agent makes (and those made in the last hour) is shown\n"
             "and approved with one answer, until Ctrl-C. Keep it open next to an agent whose MCP client\n"
             "cannot ask you in the chat.\n"
             "\n"
             "options:\n"
             "  --watch      approve plans as they arrive\n"
             "  --yes, -y    approve without asking (scripts; your decision, made in advance)\n"
             "  --verbose    also show the request lines and the plan digest\n",
             {{}, {"yes", "watch", "verbose"}, {{'y', "yes"}}}, run_approve},
            {"plan", "Preview, save and inspect changes as plans",
             "usage: forti plan set|create|delete <resource> ... [--apply]   as forti set|create|delete\n"
             "       forti plan action <monitor/path> [--body JSON|@file] [--apply]\n"
             "       forti plan --file changes.json|- [--apply]  a request ({operations: [...]}) or an array\n"
             "       forti plan show [id]\n"
             "       forti plan list\n"
             "       forti plan approve [id] [--yes]            same as forti approve\n"
             "\n"
             "A plan records the before-state, a field diff, the exact request body and a risk tier, and\n"
             "never changes the device. Without --apply it is saved for later: forti apply ID (or forti\n"
             "approve ID for an agent to apply). --apply makes the change straight away, exactly like\n"
             "forti set/create/delete. Sensitive values (passwords, PSKs, keys, tokens) are redacted in all\n"
             "output; the stored plan file (0600) keeps them because apply needs them.\n"
             "\n"
             "Naming a plan: the full id, a unique prefix of it or of its last part (b75ef1), or latest.\n"
             "\n"
             "options:\n"
             "  --apply      make the change now, as the profile's mode allows\n"
             "  --parent KEY --child ATTR   (set, create, delete) one entry of a child table, as for forti set\n"
             "  --verbose    also print the plan digest\n"
             "  --yes, -y    approve: no question (scripts)\n",
             {{"file", "clear", "object", "body", "parent", "child"}, {"yes", "apply", "verbose"}, {{'f', "file"}, {'y', "yes"}}},
             run_plan},
            {"apply", "Apply a saved plan (as the profile's mode allows)",
             "usage: forti apply [plan id]\n"
             "\n"
             "Shows the plan and applies it. read-only profiles refuse. guarded: at a terminal it asks once,\n"
             "\"Apply these changes?\"; a plan already approved (forti approve) applies without asking.\n"
             "autonomous: no question. Every apply re-checks the plan digest, the device serial and every\n"
             "before-state, runs the operations in order without retries, verifies each one by re-reading,\n"
             "writes a rollback plan (forti rollback) and appends to the audit log (forti history).\n"
             "Critical-risk operations are followed by a management connectivity probe.\n"
             "\n"
             "The id may be a unique prefix (or its last part). At a terminal, without an id (or with\n"
             "latest): the plan waiting for the profile, made in the last day; when several are waiting\n"
             "you pick one. Without a terminal a plan is always named.\n"
             "\n"
             "The rollback plan needs a working management path: it is not independent recovery. Have a\n"
             "console, out-of-band interface or device-side auto-revert before critical changes.\n",
             {{}, {"verbose"}, {}}, run_apply},
        };
    }

}  // namespace forti::cli
