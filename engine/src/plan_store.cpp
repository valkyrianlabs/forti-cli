#include "plan_store.hpp"
#include "sha256.hpp"

#include <forti/engine/catalog.hpp>
#include <forti/engine/error.hpp>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <ctime>
#include <format>
#include <fstream>
#include <sstream>
#include <system_error>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace forti::engine::detail {

    namespace fs = std::filesystem;

    namespace {

        std::optional<std::string> read_file(const fs::path& file) {
            std::ifstream in(file);
            if (!in) return std::nullopt;
            std::stringstream text;
            text << in.rdbuf();
            return text.str();
        }

        [[noreturn]] void tampered(std::string_view id, std::string_view why) {
            throw Failure(Code::policy_denied,
                          std::format("plan {} failed its integrity check ({}); create a new plan", id, why),
                          {{"plan_id", id}, {"reason", "tampered"}, {"check", why}});
        }

        [[noreturn]] void refuse_approval(std::string_view id, std::string_view reason, const std::string& message) {
            throw Failure(Code::approval_required, message,
                          {{"plan_id", id}, {"reason", reason}, {"approve", std::format("forti plan approve {}", id)}});
        }

        fs::path plans_dir(const Paths& paths) { return paths.state / "plans"; }
        fs::path approvals_dir(const Paths& paths) { return paths.state / "approvals"; }

        std::string lower(std::string_view text) {
            std::string out(text);
            for (char& c: out) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            return out;
        }

    }  // namespace

    // ---- time ----

    std::string iso8601(Clock::time_point time) {
        return std::format("{:%Y-%m-%dT%H:%M:%SZ}", std::chrono::floor<std::chrono::seconds>(time));
    }

    std::optional<Clock::time_point> parse_iso8601(std::string_view text) {
        if (text.size() != 20) return std::nullopt;
        std::tm tm{};
        char z = 0;
        std::string copy(text);
        if (std::sscanf(copy.c_str(), "%4d-%2d-%2dT%2d:%2d:%2d%c", &tm.tm_year, &tm.tm_mon, &tm.tm_mday, &tm.tm_hour,
                        &tm.tm_min, &tm.tm_sec, &z) != 7 || z != 'Z')
            return std::nullopt;
        tm.tm_year -= 1900;
        tm.tm_mon -= 1;
        std::time_t seconds = ::timegm(&tm);
        if (seconds == static_cast<std::time_t>(-1)) return std::nullopt;
        return Clock::from_time_t(seconds);
    }

    // ---- digests ----

    std::string canonical(const json& value) { return value.dump(-1, ' ', true, json::error_handler_t::strict); }

    std::string digest_of(const json& value) {
        Digest digest = sha256(canonical(value));
        return hex(digest);
    }

    std::string plan_digest(const json& plan) {
        return digest_of({{"format", plan.value("format", 0)},
                          {"device", plan.value("device", json::object())},
                          {"operations", plan.value("operations", json::array())}});
    }

    // ---- ids and files ----

    void validate_plan_id(std::string_view id) {
        bool valid = !id.empty() && id.size() <= 64;
        for (char c: id) valid = valid && (std::isalnum(static_cast<unsigned char>(c)) || c == '-');
        if (!valid) throw Failure(Code::usage, std::format("invalid plan id \"{}\"", id));
    }

    std::string new_plan_id(Clock::time_point time) {
        auto random = random_bytes(3);
        return std::format("{:%Y%m%d-%H%M%S}-{}", std::chrono::floor<std::chrono::seconds>(time), hex(random));
    }

    fs::path plan_file(const Paths& paths, std::string_view id) {
        validate_plan_id(id);
        return plans_dir(paths) / (std::string(id) + ".json");
    }

    fs::path approval_file(const Paths& paths, std::string_view id) {
        validate_plan_id(id);
        return approvals_dir(paths) / (std::string(id) + ".json");
    }

    void save_plan(const Paths& paths, const json& plan) {
        ensure_private_dir(paths.state);
        ensure_private_dir(plans_dir(paths));
        write_private_file(plan_file(paths, plan.at("id").get<std::string>()), plan.dump(2) + "\n");
    }

    Risk parse_risk(std::string_view text) {
        if (text == "low") return Risk::low;
        if (text == "elevated") return Risk::elevated;
        return Risk::critical;
    }

    Risk plan_risk(const json& plan) {
        Risk risk = Risk::low;
        for (const auto& op: plan.value("operations", json::array()))
            risk = std::max(risk, parse_risk(op.value("risk", "critical")));
        return risk;
    }

    json load_plan(const Paths& paths, std::string_view id) {
        auto text = read_file(plan_file(paths, id));
        if (!text) throw Failure(Code::not_found, std::format("no stored plan {}", id), {{"plan_id", id}});
        json plan = json::parse(*text, nullptr, false);
        if (plan.is_discarded() || !plan.is_object()) tampered(id, "not valid JSON");
        if (plan.value("format", 0) != plan_format) tampered(id, "unknown plan format");
        if (plan.value("id", "") != id) tampered(id, "id");
        if (!plan.contains("operations") || !plan["operations"].is_array() || !plan.contains("device") ||
            !plan["device"].is_object())
            tampered(id, "structure");
        if (!plan.contains("digest") || !plan["digest"].is_string() || plan["digest"] != plan_digest(plan))
            tampered(id, "digest");
        // The risk tier drives the connectivity probe: it must be the catalog's, not the file's word.
        for (const auto& op: plan["operations"]) {
            if (!op.is_object() || !op.contains("resource") || !op["resource"].is_string()) tampered(id, "operation");
            Resource resource = Catalog::instance().resolve(op["resource"].get<std::string>());
            Risk risk = risk_of(resource);
            if (to_string(risk) != op.value("risk", "")) tampered(id, "risk");
        }
        return plan;
    }

    bool plan_applied(const Paths& paths, std::string_view id) {
        validate_plan_id(id);
        return fs::exists(plans_dir(paths) / (std::string(id) + ".applied"));
    }

    void mark_applied(const Paths& paths, std::string_view id, Clock::time_point time) {
        validate_plan_id(id);
        write_private_file(plans_dir(paths) / (std::string(id) + ".applied"),
                           json{{"plan_id", id}, {"applied_at", iso8601(time)}}.dump() + "\n");
    }

    // ---- approvals ----

    std::optional<json> load_approval(const Paths& paths, std::string_view id) {
        auto text = read_file(approval_file(paths, id));
        if (!text) return std::nullopt;
        json record = json::parse(*text, nullptr, false);
        if (record.is_discarded()) return json(nullptr);
        return record;
    }

    void save_approval(const Paths& paths, const json& record) {
        ensure_private_dir(paths.state);
        ensure_private_dir(approvals_dir(paths));
        write_private_file(approval_file(paths, record.at("plan_id").get<std::string>()), record.dump(2) + "\n");
    }

    void verify_approval(const Paths& paths, const json& plan, Clock::time_point time) {
        std::string id = plan.at("id").get<std::string>();
        if (fs::exists(approvals_dir(paths) / (id + ".used")))
            refuse_approval(id, "used", std::format("the approval of plan {} was already used; plan again", id));
        auto record = load_approval(paths, id);
        if (!record)
            refuse_approval(id, "missing", std::format("plan {} needs a human approval (guarded mode): forti plan approve {}", id, id));
        if (!record->is_object() || record->value("format", 0) != approval_format || !(*record)["digest"].is_string() ||
            !(*record)["expires_at"].is_string())
            refuse_approval(id, "malformed", std::format("the approval record of plan {} is malformed; approve again", id));
        if (record->value("plan_id", "") != id || (*record)["digest"] != plan["digest"])
            refuse_approval(id, "digest_mismatch",
                            std::format("the approval of plan {} is for a different plan digest; approve again", id));
        auto expires = parse_iso8601((*record)["expires_at"].get<std::string>());
        if (!expires)
            refuse_approval(id, "malformed", std::format("the approval record of plan {} is malformed; approve again", id));
        if (time >= *expires)
            refuse_approval(id, "expired", std::format("the approval of plan {} expired at {}; approve again", id,
                                                       (*record)["expires_at"].get<std::string>()));
    }

    void consume_approval(const Paths& paths, std::string_view id, Clock::time_point time) {
        validate_plan_id(id);
        fs::path dir = approvals_dir(paths);
        write_private_file(dir / (std::string(id) + ".used"), json{{"plan_id", id}, {"used_at", iso8601(time)}}.dump() + "\n");
        std::error_code ignored;
        fs::remove(dir / (std::string(id) + ".json"), ignored);
    }

    // ---- redaction ----

    bool sensitive_name(std::string_view attribute) {
        std::string name = lower(attribute);
        static constexpr std::string_view fragments[] = {
                "password", "passwd", "passphrase", "psk", "secret", "private-key", "privatekey", "key-material",
                "token", "pwd", "md5-key", "auth-key", "authentication-key", "pre-shared-key", "pin",
                "community", "credential",
        };
        static constexpr std::string_view exact[] = {"key", "keys", "ppk-secret", "auth-code", "radius-secret"};
        if (std::ranges::find(exact, std::string_view(name)) != std::end(exact)) return true;
        for (auto fragment: fragments) {
            auto at = name.find(fragment);
            if (at == std::string::npos) continue;
            // "pin" only as a whole word ("pin", "pin-code"): "pinned", "ping-server" are not secrets.
            if (fragment == "pin") {
                bool start = at == 0 || name[at - 1] == '-';
                bool end = at + 3 == name.size() || name[at + 3] == '-';
                if (!(start && end)) continue;
            }
            // "token" also names FortiToken serial references (fortitoken): still redacted, harmlessly.
            return true;
        }
        return false;
    }

    std::set<std::string, std::less<>> sensitive_from_schema(const json& schema) {
        std::set<std::string, std::less<>> out;
        auto walk = [&](auto& self, const json& node) -> void {
            if (!node.is_object()) return;
            auto children = node.find("children");
            if (children == node.end() || !children->is_object()) return;
            for (auto it = children->begin(); it != children->end(); ++it) {
                if (it.value().is_object() && it.value().value("type", "") == "password") out.insert(it.key());
                self(self, it.value());
            }
        };
        walk(walk, schema);
        return out;
    }

    json redact(const json& value, const std::set<std::string, std::less<>>& extra) {
        if (value.is_array()) {
            json out = json::array();
            for (const auto& item: value) out.push_back(redact(item, extra));
            return out;
        }
        if (!value.is_object()) return value;
        json out = json::object();
        // A diff entry or an error detail names its attribute separately from the values.
        bool named_sensitive = false;
        if (auto it = value.find("attribute"); it != value.end() && it->is_string())
            named_sensitive = sensitive_name(it->get<std::string>()) || extra.contains(it->get<std::string>());
        for (auto it = value.begin(); it != value.end(); ++it) {
            bool secret = sensitive_name(it.key()) || extra.contains(it.key());
            bool value_slot = named_sensitive && (it.key() == "before" || it.key() == "after" || it.key() == "value" ||
                                                  it.key() == "expected" || it.key() == "actual" || it.key() == "table");
            if ((secret || value_slot) && !it.value().is_null()) out[it.key()] = redacted;
            else out[it.key()] = redact(it.value(), extra);
        }
        return out;
    }

    json plan_view(const json& plan, bool full) {
        json view = {{"id", plan.value("id", "")},
                     {"digest", plan.value("digest", "")},
                     {"kind", plan.value("kind", "plan")},
                     {"created_at", plan.value("created_at", "")},
                     {"device", plan.value("device", json::object())},
                     {"risk", to_string(plan_risk(plan))},
                     {"summary", plan.value("summary", "")}};
        if (plan.contains("rollback_of")) view["rollback_of"] = plan["rollback_of"];
        json operations = json::array();
        for (const auto& op: plan.value("operations", json::array())) {
            // Only attribute-bearing subtrees are redacted: the operation's own "key" is an object
            // name, not the attribute "key" (an NTP or OSPF authentication key).
            json entry = json::object();
            for (const char* key: {"index", "op", "resource", "key", "risk", "note"})
                if (auto it = op.find(key); it != op.end()) entry[key] = *it;
            if (auto it = op.find("diff"); it != op.end()) entry["diff"] = redact(*it);
            if (auto it = op.find("wire"); it != op.end() && it->is_object()) {
                entry["wire"] = *it;
                if (it->contains("body")) entry["wire"]["body"] = redact((*it)["body"]);
            }
            if (full) {
                for (const char* key: {"before", "after"})
                    if (auto it = op.find(key); it != op.end()) entry[key] = redact(*it);
                if (auto it = op.find("before_digest"); it != op.end()) entry["before_digest"] = *it;
            }
            operations.push_back(std::move(entry));
        }
        view["operations"] = std::move(operations);
        if (plan.contains("warnings")) view["warnings"] = plan["warnings"];
        return view;
    }

    // ---- audit ----

    bool audit(const Paths& paths, json event) {
        try {
            ensure_private_dir(paths.state);
            json line = {{"time", iso8601(Clock::now())}};
            line.update(event);
            std::string text = canonical(line) + "\n";
            fs::path file = paths.state / "audit.jsonl";
            int fd = ::open(file.c_str(), O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC | O_NOFOLLOW, 0600);
            if (fd < 0) return false;
            ::fchmod(fd, 0600);
            // One write() per line: O_APPEND keeps concurrent writers' lines whole.
            bool ok = ::write(fd, text.data(), text.size()) == static_cast<ssize_t>(text.size());
            ::close(fd);
            return ok;
        } catch (...) {
            return false;
        }
    }

}  // namespace forti::engine::detail
