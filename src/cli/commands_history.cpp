//
// forti history: the audit log (<state>/audit.jsonl) for people.
//
// The engine appends one canonical JSON object per apply and approve attempt (engine/src/plan.cpp
// Engine::apply, engine/src/approval.cpp approve_plan). This command only reads that file: it needs no
// config.json, no profile and no device, so it works when the configuration is broken or the profile
// that made a change has since been removed. `-p` filters instead of selecting a device.
//
// Lines written by releases up to 0.3.1 lack "summary", "actor", "approved_by" and "approved_at"; the
// text is then built from the operations, and the approver taken from the plan's approve event.
//

#include "commands.hpp"
#include "setup_support.hpp"

#include <algorithm>
#include <cstdio>
#include <ctime>
#include <filesystem>
#include <format>
#include <fstream>
#include <map>
#include <ostream>
#include <utility>

namespace forti::cli {

    using engine::Code;
    using engine::Failure;
    using json = nlohmann::json;
    namespace fs = std::filesystem;

    namespace {

        constexpr std::size_t default_limit = 20;

        // A string member, or "" (old or hand-edited lines may lack a field or hold another type).
        std::string text(const json& object, std::string_view key) {
            if (!object.is_object()) return "";
            auto it = object.find(key);
            return it != object.end() && it->is_string() ? it->get<std::string>() : "";
        }

        const json& member(const json& object, std::string_view key) {
            static const json none;
            if (!object.is_object()) return none;
            auto it = object.find(key);
            return it != object.end() ? *it : none;
        }

        struct Log {
            std::vector<json> events;   // in file order: oldest first
            std::size_t malformed = 0;
            bool exists = false;
        };

        Log read_log(const fs::path& file) {
            Log log;
            std::error_code error;
            if (!fs::exists(file, error)) return log;
            std::ifstream in(file);
            if (!in) throw Failure(Code::config, std::format("cannot read the audit log {}", display_path(file)));
            log.exists = true;
            std::string line;
            while (std::getline(in, line)) {
                if (line.find_first_not_of(" \t\r") == std::string::npos) continue;
                json event = json::parse(line, nullptr, false);
                if (event.is_discarded() || !event.is_object() || text(event, "event").empty()) {
                    ++log.malformed;
                    continue;
                }
                log.events.push_back(std::move(event));
            }
            return log;
        }

        bool is_apply(const json& event) { return text(event, "event") == "apply"; }
        bool is_approve(const json& event) { return text(event, "event") == "approve"; }

        std::string reason_of(const json& event) { return text(member(event, "error"), "reason"); }

        bool changed_something(const json& event) {
            const json& operations = member(event, "operations");
            return operations.is_array() && !operations.empty();
        }

        // Attempts the engine turned away before touching the device: day-to-day noise (an agent
        // trying a read-only profile, an apply waiting for its approval, a plan overtaken by another
        // change). A tampered plan or a failed device request is never hidden.
        bool refusal(const json& event) {
            std::string outcome = text(event, "outcome");
            if (is_approve(event)) return outcome != "approved";
            if (!is_apply(event) || outcome == "ok" || changed_something(event)) return false;
            if (outcome == "approval_required" || outcome == "stale_plan" || outcome == "not_found" || outcome == "usage")
                return true;
            if (outcome != "policy_denied") return false;
            std::string reason = reason_of(event);
            if (!reason.empty()) return reason == "read_only" || reason == "already_applied";
            // Lines from before the error reason was recorded.
            std::string message = text(member(event, "error"), "message");
            return message.find("read-only") != std::string::npos || message.find("already applied") != std::string::npos;
        }

        // ---- text ----

        // "2026-10-16T12:05:09Z" in local time, "2026-10-16 14:05"; as stored when it does not parse.
        std::string local_time(const std::string& stamp) {
            std::tm tm{};
            int year = 0, month = 0, day = 0, hour = 0, minute = 0, second = 0;
            char zone = 0;
            if (stamp.size() != 20 ||
                std::sscanf(stamp.c_str(), "%4d-%2d-%2dT%2d:%2d:%2d%c", &year, &month, &day, &hour, &minute, &second, &zone) != 7 ||
                zone != 'Z')
                return stamp;
            tm.tm_year = year - 1900;
            tm.tm_mon = month - 1;
            tm.tm_mday = day;
            tm.tm_hour = hour;
            tm.tm_min = minute;
            tm.tm_sec = second;
            std::time_t when = ::timegm(&tm);
            std::tm local{};
            if (when == -1 || !::localtime_r(&when, &local)) return stamp;
            char out[32];
            return std::strftime(out, sizeof out, "%Y-%m-%d %H:%M", &local) ? std::string(out) : stamp;
        }

        // The random tail of "20261016-120509-a1b2c3": enough to name the plan (forti plan show a1b2c3).
        std::string short_id(const std::string& id) {
            auto dash = id.rfind('-');
            return dash == std::string::npos || dash + 1 == id.size() ? id : id.substr(dash + 1);
        }

        std::string describe(const json& op) {
            std::string out = text(op, "op") + " " + text(op, "resource");
            // A child table entry: "update system.dhcp/server 1 reserved-address 7".
            if (auto parent = text(op, "parent"); !parent.empty()) out += " " + parent + " " + text(op, "child");
            if (auto key = text(op, "key"); !key.empty()) out += " " + key;
            std::string attributes;
            if (const json& names = member(op, "attributes"); names.is_array())
                for (const auto& name: names)
                    if (name.is_string()) attributes += (attributes.empty() ? "" : ", ") + name.get<std::string>();
            return attributes.empty() ? out : out + " (" + attributes + ")";
        }

        // What an apply changed: its operations (the concrete objects), else the plan summary.
        std::string change_of(const json& event) {
            std::string out;
            if (const json& operations = member(event, "operations"); operations.is_array() && !operations.empty()) {
                std::size_t shown = std::min<std::size_t>(operations.size(), 2);
                for (std::size_t i = 0; i < shown; ++i) out += (i ? "; " : "") + describe(operations[i]);
                if (operations.size() > shown) out += std::format(" (+{} more)", operations.size() - shown);
            } else if (auto summary = text(event, "summary"); !summary.empty()) {
                out = summary;
            } else if (auto id = text(event, "plan_id"); !id.empty()) {
                out = "plan " + id;
            }
            if (auto of = text(event, "rollback_of"); !of.empty()) out = "rollback of " + short_id(of) + ": " + out;
            return out;
        }

        // Did anything change? partial_failure covers a failure at the first operation too.
        bool any_applied(const json& event) {
            for (const auto& op: member(event, "operations")) {
                std::string status = text(op, "status");
                if (status == "verified" || status == "applied_unverified" || status == "outcome_unknown") return true;
            }
            return false;
        }

        std::pair<std::string, Style> result_of(const json& event) {
            std::string outcome = text(event, "outcome");
            if (is_approve(event)) {
                if (outcome == "approved") return {"approved", Style::green};
                if (outcome == "not_required") return {"approval not needed", Style::dim};
                return {"approval refused: " + outcome, Style::yellow};
            }
            if (outcome == "ok") return {"applied", Style::green};
            if (outcome == "policy_denied") {
                std::string reason = reason_of(event);
                std::string message = text(member(event, "error"), "message");
                if (reason == "read_only" || (reason.empty() && message.find("read-only") != std::string::npos))
                    return {"refused: read-only", Style::yellow};
                if (reason == "already_applied" || (reason.empty() && message.find("already applied") != std::string::npos))
                    return {"refused: already applied", Style::yellow};
                if (reason == "tampered") return {"refused: tampered", Style::red};
                return {"refused", Style::yellow};
            }
            if (outcome == "approval_required") return {"needs approval", Style::yellow};
            if (outcome == "stale_plan") return {"stale", Style::yellow};
            if (outcome == "partial_failure") return {any_applied(event) ? "partial" : "failed", Style::red};
            if (outcome == "outcome_unknown") return {"unknown", Style::red};
            if (outcome == "management_connectivity_lost") return {"lost management", Style::red};
            if (outcome.empty()) return {"?", Style::red};
            return {"failed: " + outcome, Style::red};
        }

        // What the renderer needs beyond the shown events, from the whole log.
        struct LogIndex {
            std::map<std::string, std::string, std::less<>> approver;      // plan id → last "approved_by" approving it
            std::map<std::string, std::string, std::less<>> profile_of;    // plan id → profile (approve events have none)
            std::map<std::string, std::string, std::less<>> rolled_back;   // plan id → when its rollback plan was applied
        };

        // `escape`: for text output, where these strings reach the terminal (printable()).
        LogIndex index_of(const std::vector<json>& events, bool escape) {
            LogIndex index;
            auto get = [&](const json& object, std::string_view key) {
                return escape ? printable(text(object, key)) : text(object, key);
            };
            for (const auto& event: events) {
                std::string id = text(event, "plan_id");
                if (id.empty()) continue;
                if (is_approve(event) && text(event, "outcome") == "approved" && !text(event, "approved_by").empty())
                    index.approver[id] = get(event, "approved_by");
                if (is_apply(event) && !text(event, "profile").empty()) index.profile_of[id] = get(event, "profile");
                if (is_apply(event) && text(event, "outcome") == "ok" && !text(event, "rollback_of").empty())
                    index.rolled_back[text(event, "rollback_of")] = get(event, "time");
            }
            return index;
        }

        std::string approval_of(const json& event, const LogIndex& context) {
            if (!is_apply(event)) return "";
            if (auto by = text(event, "approved_by"); !by.empty()) return "approved by " + by;
            std::string mode = text(event, "mode");
            std::string actor = text(event, "actor");
            if (mode == "autonomous") return actor.empty() ? "autonomous" : "autonomous, " + actor;
            if (mode == "guarded" && text(event, "outcome") != "approval_required" && !refusal(event)) {
                // Up to 0.3.1 the apply event did not name the approver; its approve event does.
                auto it = context.approver.find(text(event, "plan_id"));
                return it != context.approver.end() ? "approved by " + it->second : "approved";
            }
            return "";
        }

        std::string profile_column(const json& event, const LogIndex& context) {
            if (auto profile = text(event, "profile"); !profile.empty()) return profile;
            auto it = context.profile_of.find(text(event, "plan_id"));
            return it != context.profile_of.end() ? it->second : "";
        }

        std::string pad(const std::string& text, std::size_t width) {
            std::size_t shown = display_width(text);
            return shown >= width ? text : text + std::string(width - shown, ' ');
        }

        // Cut to `width` columns at a code point boundary, "…" included.
        std::string clip(const std::string& text, std::size_t width) {
            if (display_width(text) <= width) return text;
            std::string out;
            std::size_t columns = 0;
            for (std::size_t i = 0; i < text.size() && columns + 1 < width; ++columns) {
                std::size_t length = 1;
                auto lead = static_cast<unsigned char>(text[i]);
                if (lead >= 0xF0) length = 4;
                else if (lead >= 0xE0) length = 3;
                else if (lead >= 0xC0) length = 2;
                out.append(text, i, length);
                i += length;
            }
            return out + "…";
        }

        // One row per event: the change last and unclipped (it is what people read), unless the
        // terminal is too narrow for it.
        void render_table(std::ostream& out, const json& events, const LogIndex& context, std::size_t width) {
            std::vector<std::string> header = {"when", "profile", "result", "plan", "approval", "change"};
            std::vector<std::vector<std::string>> rows;
            std::vector<Style> colors;
            for (const auto& event: events) {
                auto [result, color] = result_of(event);
                rows.push_back({local_time(text(event, "time")), profile_column(event, context), result,
                                short_id(text(event, "plan_id")), approval_of(event, context), change_of(event)});
                colors.push_back(color);
            }
            std::vector<std::size_t> widths(header.size(), 0);
            for (std::size_t c = 0; c < header.size(); ++c) {
                widths[c] = display_width(header[c]);
                for (const auto& row: rows) widths[c] = std::max(widths[c], display_width(row[c]));
            }
            // The approval column disappears when no row has one.
            bool approvals = std::ranges::any_of(rows, [](const auto& row) { return !row[4].empty(); });
            auto line = [&](const std::vector<std::string>& cells, const Style* color) {
                std::string text;
                std::size_t used = 0;
                for (std::size_t c = 0; c + 1 < cells.size(); ++c) {
                    if (c == 4 && !approvals) continue;
                    std::string cell = pad(cells[c], widths[c]) + "  ";
                    used += display_width(cell);
                    text += c == 2 && color ? styled(cell, *color) : cell;
                }
                std::string last = cells.back();
                if (width > used) last = clip(last, std::max<std::size_t>(width - used, 16));
                return text + last;
            };
            out << styled(line(header, nullptr), Style::bold) << "\n";
            for (std::size_t r = 0; r < rows.size(); ++r) out << line(rows[r], &colors[r]) << "\n";
        }

        // --verbose: a block per apply (every operation, the approval, the error, the rollback plan
        // and the command that undoes it) and a line per approve event.
        void render_verbose(std::ostream& out, const json& events, const LogIndex& context) {
            bool first = true;
            for (const auto& event: events) {
                auto [result, color] = result_of(event);
                std::string id = text(event, "plan_id");
                std::string head = std::format("{}  {}  {}", styled(local_time(text(event, "time")), Style::bold),
                                               profile_column(event, context), styled(result, color));
                if (is_approve(event)) {
                    std::string line = std::format("{}  plan {}", head, id);
                    if (auto by = text(event, "approved_by"); !by.empty()) line += " by " + by;
                    if (auto actor = text(event, "actor"); !actor.empty() && actor != text(event, "approved_by"))
                        line += " (" + actor + ")";
                    if (auto expires = text(event, "expires_at"); !expires.empty()) line += ", expires " + local_time(expires);
                    if (auto message = text(member(event, "error"), "message"); !message.empty()) line += ": " + message;
                    out << line << "\n";
                    first = false;
                    continue;
                }
                if (!first) out << "\n";
                first = false;
                out << head << "\n";
                auto field = [&](std::string_view name, const std::string& value) {
                    if (!value.empty()) out << "  " << styled(pad(std::string(name), 9), Style::dim) << " " << value << "\n";
                };
                std::string plan = id;
                if (auto of = text(event, "rollback_of"); !of.empty()) plan += " (rollback of " + of + ")";
                field("plan", plan);
                std::string device = text(event, "host");
                if (auto serial = text(event, "serial"); !serial.empty()) device += (device.empty() ? "" : ", ") + serial;
                field("device", device);
                field("summary", text(event, "summary"));
                std::string approval = text(event, "mode") == "autonomous" ? "autonomous" : approval_of(event, context);
                if (auto at = text(event, "approved_at"); !at.empty() && !approval.empty()) approval += " at " + local_time(at);
                if (approval.empty()) approval = text(event, "mode");
                field("approval", approval);
                field("by", text(event, "actor"));
                if (const json& error = member(event, "error"); error.is_object()) {
                    std::string what = text(error, "code");
                    if (auto reason = text(error, "reason"); !reason.empty()) what += " (" + reason + ")";
                    if (auto message = text(error, "message"); !message.empty()) what += ": " + message;
                    field("error", what);
                }
                if (const json& operations = member(event, "operations"); operations.is_array())
                    for (const auto& op: operations) {
                        std::string status = text(op, "status");
                        out << "  " << describe(op);
                        if (!status.empty())
                            out << ": " << styled(status, status == "verified" ? Style::green
                                                          : status == "applied_unverified" ? Style::yellow : Style::red);
                        out << "\n";
                    }
                field("backup", text(event, "backup"));
                if (auto rollback = text(event, "rollback_plan"); !rollback.empty()) {
                    auto undone = context.rolled_back.find(id);
                    if (undone != context.rolled_back.end())
                        field("rollback", std::format("{}, applied {}", rollback, local_time(undone->second)));
                    else field("rollback", std::format("{} (undo: forti rollback {})", rollback, id));
                }
            }
        }

        int run_history(Context& context, const Args& args) {
            if (!args.positional.empty())
                throw Failure(Code::usage, "usage: forti history [-p NAME] [-n N] [--all] [--verbose] (see forti history --help)");
            std::size_t limit = default_limit;
            if (auto value = args.value("limit")) limit = to_count("limit", *value);
            auto profile = args.value("profile");
            bool all = args.flag("all");
            bool verbose = args.flag("verbose");

            fs::path file = context.engine.options().paths.state / "audit.jsonl";
            Log log = read_log(file);
            LogIndex raw = index_of(log.events, false);

            // Newest first while selecting, so the limit keeps the most recent entries and the hidden
            // count covers the refusals among them (not every refusal since the log began).
            std::vector<const json*> selected;
            std::size_t hidden = 0, older = 0;
            for (auto it = log.events.rbegin(); it != log.events.rend(); ++it) {
                const json& event = *it;
                if (!is_apply(event) && !(verbose && is_approve(event))) continue;
                if (profile && profile_column(event, raw) != *profile) continue;
                bool room = limit == 0 || selected.size() < limit;
                if (!all && refusal(event)) {
                    if (room) ++hidden;
                    continue;
                }
                if (!room) {
                    ++older;
                    continue;
                }
                selected.push_back(&event);
            }
            // Printed oldest first, newest last, like a log: the latest change ends up right above the
            // prompt, and the order reads the way the changes happened (a rollback after what it undid).
            json data = json::array();
            for (auto it = selected.rbegin(); it != selected.rend(); ++it) data.push_back(**it);
            json meta = {{"log", file.string()}, {"returned", data.size()}, {"hidden", hidden}, {"older", older},
                         {"malformed", log.malformed}};
            if (profile) meta["profile"] = *profile;

            std::size_t width = context.output.width;
            int status = emit(context.output, engine::ok(std::move(data), std::move(meta)),
                              [&](std::ostream& out, const json& events, const json&) {
                                  if (events.empty()) {
                                      out << (profile ? std::format("No changes recorded for profile {}.\n", printable(*profile))
                                                      : std::string("No changes recorded yet.\n"));
                                      return;
                                  }
                                  LogIndex index = index_of(log.events, true);
                                  if (verbose) render_verbose(out, events, index);
                                  else render_table(out, events, index, width);
                              });
            // After the entries, so on a terminal they sit right above the prompt.
            std::ostream& err = *context.output.err;
            if (log.malformed)
                err << std::format("forti: skipped {} malformed line{} in {}\n", log.malformed, log.malformed == 1 ? "" : "s",
                                   printable(display_path(file)));
            if (older)
                err << std::format("forti: {} older entr{} not shown: --limit N (0: all)\n", older, older == 1 ? "y" : "ies");
            if (hidden)
                err << std::format("forti: {} refused attempt{} hidden: --all shows {}\n", hidden, hidden == 1 ? "" : "s",
                                   hidden == 1 ? "it" : "them");
            return status;
        }

    }  // namespace

    std::vector<Command> history_commands() {
        return {
            {"history", "Show what was applied: when, where, by whom, and what changed",
             "usage: forti history [-p NAME] [-n N] [--all] [--verbose]\n"
             "\n"
             "Lists applied plans from the audit log, newest last: the local time, the profile, the result,\n"
             "the plan (the last part of its id: forti plan show a1b2c3), the approval (who approved it, or\n"
             "autonomous) and what changed. Rollbacks say which plan they undo. It reads only the audit log\n"
             "(<state>/audit.jsonl); it needs no configuration and never contacts a device.\n"
             "\n"
             "  -p, --profile NAME   only this profile's entries (default: every profile)\n"
             "  -n, --limit N        the last N entries (default 20; 0: all)\n"
             "  --all                also attempts refused before anything changed: a read-only profile, a\n"
             "                       missing approval, a stale or already applied plan (hidden by default)\n"
             "  --verbose            every operation and its result, the approval, the error, the rollback\n"
             "                       plan and the command that undoes the change; approve events too\n"
             "\n"
             "--json prints the audit events as recorded (data), with meta.hidden and meta.malformed.\n"
             "\n"
             "examples:\n"
             "  forti history\n"
             "  forti history -p fw01 --verbose -n 5\n"
             "  forti history --all --json\n",
             {{"limit"}, {"all", "verbose"}, {{'n', "limit"}}},
             run_history},
        };
    }

}  // namespace forti::cli
