#include "ops.hpp"
#include "plan_store.hpp"
#include "sha256.hpp"

#include <forti/engine/catalog.hpp>
#include <forti/engine/engine.hpp>
#include <forti/engine/error.hpp>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <format>
#include <fstream>
#include <map>
#include <sstream>
#include <system_error>

#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

namespace forti::engine {

    bool valid_plan_id(std::string_view id) {
        if (id.size() < 12 || id.size() > 32) return false;
        if (!std::isalnum(static_cast<unsigned char>(id.front()))) return false;
        return std::ranges::all_of(id, [](char c) { return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'; });
    }

}  // namespace forti::engine

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
                          {{"plan_id", id}, {"reason", reason}, {"approve_command", std::format("forti approve {}", id)}});
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
        if (!valid_plan_id(id))
            throw Failure(Code::usage, std::format("invalid plan id \"{}\" (expected {})", id, plan_id_pattern),
                          {{"pattern", plan_id_pattern}});
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

    // ---- content-addressed action bodies ----

    namespace {

        fs::path blobs_dir(const Paths& paths) { return paths.state / "blobs"; }

        bool lower_hex(std::string_view text, std::size_t size) {
            return text.size() == size &&
                   std::ranges::all_of(text, [](char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); });
        }

        // Exclusive flock on <state>/blobs/.lock for as long as it lives. Plans that store blobs write
        // them and their plan file under it, and prune_blobs() decides and deletes under it, so a blob is
        // never deleted between being written (or found already there) and its plan becoming visible.
        class BlobLock {
            int fd_ = -1;

        public:
            explicit BlobLock(const Paths& paths) {
                ensure_private_dir(paths.state);
                ensure_private_dir(blobs_dir(paths));
                fs::path file = blobs_dir(paths) / ".lock";
                fd_ = ::open(file.c_str(), O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
                if (fd_ < 0) throw Failure(Code::config, std::format("cannot open {}", file.string()));
                while (::flock(fd_, LOCK_EX) != 0) {
                    if (errno == EINTR) continue;
                    ::close(fd_);
                    throw Failure(Code::config, std::format("cannot lock {}", file.string()));
                }
            }
            ~BlobLock() { ::close(fd_); }   // closing releases the lock
            BlobLock(const BlobLock&) = delete;
            BlobLock& operator=(const BlobLock&) = delete;
        };

        // The file's bytes, or nullopt when it is missing or not a regular file (a symlink is refused).
        std::optional<std::string> read_regular(const fs::path& file) {
            int fd = ::open(file.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
            if (fd < 0) return std::nullopt;
            struct stat info{};
            if (::fstat(fd, &info) != 0 || !S_ISREG(info.st_mode)) {
                ::close(fd);
                return std::nullopt;
            }
            std::string text(static_cast<std::size_t>(info.st_size), '\0');
            std::size_t done = 0;
            while (done < text.size()) {
                ssize_t n = ::read(fd, text.data() + done, text.size() - done);
                if (n < 0 && errno == EINTR) continue;
                if (n <= 0) break;
                done += static_cast<std::size_t>(n);
            }
            ::close(fd);
            if (done != text.size()) return std::nullopt;
            return text;
        }

    }  // namespace

    json body_ref_of(std::string_view text) { return {{"sha256", hex(sha256(text))}, {"bytes", text.size()}}; }

    bool valid_body_ref(const json& ref) {
        if (!ref.is_object() || ref.size() != 2) return false;
        auto sha = ref.find("sha256");
        auto bytes = ref.find("bytes");
        return sha != ref.end() && sha->is_string() && lower_hex(sha->get_ref<const std::string&>(), 64) &&
               bytes != ref.end() && bytes->is_number_unsigned() && bytes->get<std::uint64_t>() > 0;
    }

    fs::path blob_file(const Paths& paths, std::string_view sha256) {
        if (!lower_hex(sha256, 64)) throw Failure(Code::internal, "invalid body digest");
        return blobs_dir(paths) / (std::string(sha256) + ".json");
    }

    void save_plan(const Paths& paths, const json& plan, const Blobs& blobs) {
        if (blobs.empty()) return save_plan(paths, plan);
        BlobLock lock(paths);
        for (const auto& [sha, text]: blobs) {
            fs::path file = blob_file(paths, sha);
            // Identical bodies share one file. One that no longer hashes to its name is rewritten.
            if (auto existing = read_regular(file); existing && *existing == text) continue;
            write_private_file(file, text);
        }
        save_plan(paths, plan);
    }

    json load_body(const Paths& paths, std::string_view plan_id, const json& ref) {
        if (!valid_body_ref(ref)) tampered(plan_id, "body_ref");
        const std::string& sha = ref["sha256"].get_ref<const std::string&>();
        auto text = read_regular(blob_file(paths, sha));
        if (!text) tampered(plan_id, "body blob missing");
        if (text->size() != ref["bytes"].get<std::uint64_t>() || hex(sha256(*text)) != sha)
            tampered(plan_id, "body blob sha256");
        json body = json::parse(*text, nullptr, false);
        if (body.is_discarded() || !body.is_object()) tampered(plan_id, "body blob");
        try {
            check_reply_depth(body, "body");   // the SDK serializes it recursively
        } catch (const Failure&) {
            tampered(plan_id, "body blob");
        }
        return body;
    }

    void prune_blobs(const Paths& paths) noexcept {
        try {
            std::error_code error;
            if (!fs::is_directory(blobs_dir(paths), error)) return;
            BlobLock lock(paths);
            std::set<std::string, std::less<>> referenced;
            for (const auto& entry: fs::directory_iterator(plans_dir(paths), error)) {
                if (entry.path().extension() != ".json") continue;
                std::string id = entry.path().stem().string();
                std::error_code ignored;
                if (!valid_plan_id(id) || fs::exists(plans_dir(paths) / (id + ".applied"), ignored)) continue;
                auto text = read_regular(entry.path());
                if (!text || text->find("\"body_ref\"") == std::string::npos) continue;
                json plan = json::parse(*text, nullptr, false);
                if (!plan.is_object() || !plan.contains("operations") || !plan["operations"].is_array()) continue;
                for (const auto& op: plan["operations"])
                    if (op.is_object() && op.contains("body_ref") && valid_body_ref(op["body_ref"]))
                        referenced.insert(op["body_ref"]["sha256"].get<std::string>());
            }
            if (error) return;   // the plans could not be listed: keep everything
            std::vector<fs::path> unused;
            for (const auto& entry: fs::directory_iterator(blobs_dir(paths), error)) {
                std::string name = entry.path().filename().string();
                if (name == ".lock") continue;
                // <sha256>.json, or a write interrupted by a crash (<sha256>.json.tmp.<pid>): writers
                // hold the lock, so none is in progress now.
                bool blob = entry.path().extension() == ".json" && lower_hex(entry.path().stem().string(), 64);
                if (blob && referenced.contains(entry.path().stem().string())) continue;
                if (blob || name.find(".json.tmp.") != std::string::npos) unused.push_back(entry.path());
            }
            for (const auto& file: unused) {
                std::error_code ignored;
                fs::remove(file, ignored);
            }
        } catch (...) {
            // Best effort: an unpruned blob is only disk space.
        }
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
        // The digest only proves the file is self-consistent (anyone who can write it can recompute
        // it), so apply must also be able to trust the shape it executes: an operation kind it knows,
        // a resource that supports it, the fields it reads, and a recorded request (shown to the person
        // approving) that is the one apply will send.
        for (const auto& op: plan["operations"]) {
            if (!op.is_object() || !op.contains("resource") || !op["resource"].is_string()) tampered(id, "operation");
            Resource resource = Catalog::instance().resolve(op["resource"].get<std::string>());
            Risk risk = risk_of(resource);
            if (to_string(risk) != op.value("risk", "")) tampered(id, "risk");

            auto kind = op.find("op");
            if (kind == op.end() || !kind->is_string()) tampered(id, "operation");
            const std::string& name = kind->get_ref<const std::string&>();
            auto is = [&](const char* field, json::value_t type) {
                auto it = op.find(field);
                return it != op.end() && it->type() == type;
            };
            bool shape = false;
            std::string method, path;
            std::string key = is("key", json::value_t::string) ? op["key"].get<std::string>() : std::string();
            if (op.contains("key") && (!op["key"].is_string() || !addressable_key(key))) tampered(id, "operation");
            // A child table operation names its parent object and table attribute; the attribute must
            // still be one of the resource's tables with keyed entries.
            std::optional<Child> child;
            std::string parent;
            if (op.contains("child") || op.contains("parent")) {
                if (!is("child", json::value_t::string) || !is("parent", json::value_t::string)) tampered(id, "operation");
                parent = op["parent"].get<std::string>();
                if (!addressable_key(parent) || name == "action") tampered(id, "operation");
                try {
                    child = child_of(resource, op["child"].get<std::string>());
                } catch (const Failure&) {
                    tampered(id, "operation");
                }
            }
            auto at = [&](const std::string& entry) {
                try {
                    return child_path(resource, *child, parent, entry);
                } catch (const Failure&) {
                    tampered(id, "operation");
                }
            };
            if (child) {
                if (name == "create") {
                    shape = is("object", json::value_t::object);
                    method = "POST";
                    path = at("");
                } else if (name == "update") {
                    shape = !key.empty() && is("set", json::value_t::object) && is("clear", json::value_t::array) &&
                            std::ranges::all_of(op["clear"], [](const json& item) { return item.is_string(); });
                    method = "PUT";
                    if (!key.empty()) path = at(key);
                } else if (name == "delete") {
                    shape = !key.empty();
                    method = "DELETE";
                    if (!key.empty()) path = at(key);
                }
            } else if (name == "action") {
                // The body inline (as it always was), or a reference to a stored blob (large bodies):
                // exactly one of the two, and the wire record carries the same thing.
                bool inline_body = is("body", json::value_t::object) && !op.contains("body_ref");
                bool stored = op.contains("body_ref") && !op.contains("body") && valid_body_ref(op["body_ref"]);
                shape = resource.kind == Kind::monitor && (inline_body || stored);
                if (auto wire = op.find("wire"); shape && wire != op.end() && wire->is_object()) {
                    if (inline_body) shape = !wire->contains("body_ref") && wire->value("body", json()) == op["body"];
                    else shape = !wire->contains("body") && wire->value("body_ref", json()) == op["body_ref"];
                }
                method = "POST";
                path = resource.path;
            } else if (resource.kind != Kind::monitor && resource.typed()) {
                bool table = resource.kind == Kind::table;
                if (name == "create") {
                    shape = table && is("object", json::value_t::object);
                    method = "POST";
                    path = resource.path;
                } else if (name == "update") {
                    shape = (table ? !key.empty() : key.empty()) && is("set", json::value_t::object) &&
                            is("clear", json::value_t::array) &&
                            std::ranges::all_of(op["clear"], [](const json& item) { return item.is_string(); });
                    method = "PUT";
                    path = key.empty() ? resource.path : fortiapi::path(resource.path, key);
                } else if (name == "delete") {
                    shape = table && !key.empty();
                    method = "DELETE";
                    path = fortiapi::path(resource.path, key);
                }
            }
            if (!shape) tampered(id, "operation");
            if (auto digest = op.find("before_digest"); digest == op.end() || !(digest->is_string() || digest->is_null()))
                tampered(id, "operation");
            auto wire = op.find("wire");
            if (wire == op.end() || !wire->is_object() || wire->value("method", "") != method || wire->value("path", "") != path)
                tampered(id, "wire");
        }
        return plan;
    }

    bool plan_applied(const Paths& paths, std::string_view id) {
        validate_plan_id(id);
        return fs::exists(plans_dir(paths) / (std::string(id) + ".applied"));
    }

    void mark_applied(const Paths& paths, std::string_view id, Clock::time_point time, const json& plan) {
        validate_plan_id(id);
        fs::path marker = plans_dir(paths) / (std::string(id) + ".applied");
        json content = {{"plan_id", id}, {"applied_at", iso8601(time)}};
        if (plan.is_object()) {
            // Outside the plan's digest: what `forti plan list` shows once the plan file is gone.
            const json device = plan.value("device", json::object());
            content["kind"] = plan.value("kind", "plan");
            content["created_at"] = plan.value("created_at", "");
            content["profile"] = device.value("profile", "");
            content["host"] = device.value("host", "");
            content["digest"] = plan.value("digest", "");
            content["risk"] = to_string(plan_risk(plan));
            content["summary"] = summarize(plan);
            content["operations"] = plan.value("operations", json::array()).size();
            if (plan.contains("rollback_of")) content["rollback_of"] = plan["rollback_of"];
        }
        // O_EXCL makes this the one gate: of two concurrent applies of a plan, exactly one creates it.
        int fd = ::open(marker.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (fd < 0) {
            if (errno == EEXIST) refuse_applied(paths, id);
            throw Failure(Code::config, std::format("cannot write {}", marker.string()));
        }
        std::string text = content.dump() + "\n";
        bool written = ::write(fd, text.data(), text.size()) == static_cast<ssize_t>(text.size());
        ::close(fd);
        if (!written) throw Failure(Code::config, std::format("cannot write {}", marker.string()));
    }

    std::optional<json> applied_marker(const Paths& paths, std::string_view id) {
        validate_plan_id(id);
        fs::path marker = plans_dir(paths) / (std::string(id) + ".applied");
        std::error_code error;
        if (!fs::exists(fs::symlink_status(marker, error))) return std::nullopt;
        json content = nullptr;
        if (fs::file_size(marker, error) <= 64 * 1024 && !error)
            if (auto text = read_regular(marker)) content = json::parse(*text, nullptr, false);
        if (!content.is_object() || content.value("plan_id", "") != id) content = {{"plan_id", id}};
        return content;
    }

    void refuse_applied(const Paths& paths, std::string_view id, std::string_view hint) {
        json details = {{"plan_id", id}, {"reason", "already_applied"}};
        std::string when;
        if (auto marker = applied_marker(paths, id)) {
            if (auto at = marker->find("applied_at"); at != marker->end() && at->is_string()) {
                details["applied_at"] = *at;
                when = " at " + at->get<std::string>();
            }
            if (auto outcome = marker->find("outcome"); outcome != marker->end() && outcome->is_string())
                details["outcome"] = *outcome;
        }
        throw Failure(Code::policy_denied, std::format("plan {} was already applied{}; {}", id, when, hint), std::move(details));
    }

    // ---- plan retention ----

    namespace {

        fs::path lock_file(const Paths& paths) { return plans_dir(paths) / ".lock"; }

        int open_lock(const Paths& paths) {
            return ::open(lock_file(paths).c_str(), O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
        }

        // A file's own record of when it was made ("applied_at", "approved_at", "used_at"), read from
        // these small JSON files; nullopt when it has none.
        std::optional<Clock::time_point> recorded_time(const fs::path& file, const char* field) {
            std::error_code error;
            if (fs::file_size(file, error) > 64 * 1024 || error) return std::nullopt;
            auto text = read_regular(file);
            if (!text) return std::nullopt;
            json content = json::parse(*text, nullptr, false);
            if (!content.is_object() || !content.contains(field) || !content[field].is_string()) return std::nullopt;
            return parse_iso8601(content[field].get<std::string>());
        }

        std::optional<Clock::time_point> modified(const fs::path& file) {
            struct stat info{};
            if (::lstat(file.c_str(), &info) != 0) return std::nullopt;
            return Clock::from_time_t(info.st_mtime);
        }

        bool remove_file(const fs::path& file) {
            std::error_code ignored;
            return fs::remove(file, ignored);
        }

        // "<id>.json" / "<id>.applied" / "<id>.used": the id, when valid; else empty.
        std::string id_of(const fs::path& file, std::string_view extension) {
            if (file.extension() != extension) return {};
            std::string id = file.stem().string();
            return valid_plan_id(id) ? id : std::string();
        }

        bool leftover(const fs::path& file) { return file.filename().string().find(".tmp.") != std::string::npos; }

    }  // namespace

    ApplyLock::ApplyLock(const Paths& paths) {
        std::error_code error;
        // No plans directory: there is no plan to protect (apply then fails with not_found).
        if (!fs::is_directory(plans_dir(paths), error)) return;
        fd_ = open_lock(paths);
        if (fd_ < 0) throw Failure(Code::config, std::format("cannot open {}", lock_file(paths).string()));
        while (::flock(fd_, LOCK_SH) != 0) {
            if (errno == EINTR) continue;
            ::close(fd_);
            fd_ = -1;
            throw Failure(Code::config, std::format("cannot lock {}", lock_file(paths).string()));
        }
    }

    ApplyLock::~ApplyLock() {
        if (fd_ >= 0) ::close(fd_);   // closing releases the lock
    }

    std::optional<Clock::time_point> plan_id_time(std::string_view id) {
        // new_plan_id(): "YYYYMMDD-HHMMSS-" then random hex, the plan's created_at to the second.
        auto digits = [&](std::size_t from, std::size_t count) {
            return std::ranges::all_of(id.substr(from, count), [](char c) { return c >= '0' && c <= '9'; });
        };
        if (id.size() < 16 || id[8] != '-' || id[15] != '-' || !digits(0, 8) || !digits(9, 6)) return std::nullopt;
        std::string text = std::format("{}-{}-{}T{}:{}:{}Z", id.substr(0, 4), id.substr(4, 2), id.substr(6, 2),
                                       id.substr(9, 2), id.substr(11, 2), id.substr(13, 2));
        return parse_iso8601(text);
    }

    void forget_applied(const Paths& paths, std::string_view id, const json& outcome) noexcept {
        try {
            validate_plan_id(id);
            std::string name(id);
            if (auto marker = applied_marker(paths, id); marker && outcome.is_object() && !outcome.empty()) {
                marker->update(outcome);
                // Replaced by rename: the marker exists throughout, so a concurrent mark_applied still fails.
                write_private_file(plans_dir(paths) / (name + ".applied"), marker->dump() + "\n");
            }
            remove_file(plans_dir(paths) / (name + ".json"));
            remove_file(approvals_dir(paths) / (name + ".json"));
            remove_file(approvals_dir(paths) / (name + ".used"));
        } catch (...) {
            // Best effort: what is left behind is purged with the next plan or apply.
        }
    }

    Purged purge_plans(const Paths& paths, std::chrono::days retention, Clock::time_point now) noexcept {
        Purged out;
        try {
            std::error_code error;
            if (fs::is_directory(plans_dir(paths), error)) {
                int fd = open_lock(paths);
                if (fd >= 0) {
                    struct Closer {
                        int fd;
                        ~Closer() { ::close(fd); }
                    } closer{fd};
                    int locked;
                    while ((locked = ::flock(fd, LOCK_EX | LOCK_NB)) != 0 && errno == EINTR) {}
                    if (locked != 0) out.skipped = true;   // an apply is running (or the lock failed): next time
                    else {
                        Clock::time_point cutoff = now - retention;
                        auto expired = [&](std::optional<Clock::time_point> recorded, const fs::path& file) {
                            if (!recorded) recorded = modified(file);
                            return recorded && *recorded < cutoff;
                        };

                        std::set<std::string, std::less<>> plans, markers;
                        std::vector<fs::path> leftovers;
                        for (const auto& entry: fs::directory_iterator(plans_dir(paths), error)) {
                            if (auto id = id_of(entry.path(), ".json"); !id.empty()) plans.insert(id);
                            else if (auto marked = id_of(entry.path(), ".applied"); !marked.empty()) markers.insert(marked);
                            else if (leftover(entry.path())) leftovers.push_back(entry.path());
                        }
                        for (const auto& id: plans) {
                            fs::path file = plans_dir(paths) / (id + ".json");
                            if (markers.contains(id)) {
                                // Applied before plans were deleted on apply (or the apply crashed): keep
                                // the tombstone's summary, then drop the plan.
                                if (auto marker = applied_marker(paths, id); marker && !marker->contains("summary"))
                                    if (auto text = read_regular(file)) {
                                        json plan = json::parse(*text, nullptr, false);
                                        if (plan.is_object() && plan.value("id", "") == id) {
                                            json tombstone = {{"kind", plan.value("kind", "plan")},
                                                              {"created_at", plan.value("created_at", "")},
                                                              {"profile", plan.value("device", json::object()).value("profile", "")},
                                                              {"host", plan.value("device", json::object()).value("host", "")},
                                                              {"digest", plan.value("digest", "")},
                                                              {"summary", plan.value("summary", "")},
                                                              {"risk", plan.value("risk", "")},
                                                              {"operations", plan.value("operations", json::array()).size()}};
                                            if (plan.contains("rollback_of")) tombstone["rollback_of"] = plan["rollback_of"];
                                            tombstone.update(*marker);
                                            write_private_file(plans_dir(paths) / (id + ".applied"), tombstone.dump() + "\n");
                                        }
                                    }
                                out.applied += remove_file(file);
                            } else if (expired(plan_id_time(id), file)) {
                                out.plans += remove_file(file);
                            }
                        }
                        for (const auto& id: markers) {
                            fs::path file = plans_dir(paths) / (id + ".applied");
                            if (expired(recorded_time(file, "applied_at"), file)) out.markers += remove_file(file);
                        }
                        for (const auto& file: leftovers)
                            if (expired(std::nullopt, file)) out.leftovers += remove_file(file);

                        // Approvals: past retention, or of a plan that is gone (applied or purged).
                        for (const auto& entry: fs::directory_iterator(approvals_dir(paths), error)) {
                            const fs::path& file = entry.path();
                            std::string id = id_of(file, ".json");
                            const char* field = "approved_at";
                            if (id.empty()) {
                                id = id_of(file, ".used");
                                field = "used_at";
                            }
                            if (id.empty()) {
                                if (leftover(file) && expired(std::nullopt, file)) out.leftovers += remove_file(file);
                                continue;
                            }
                            std::error_code ignored;
                            bool orphan = !fs::exists(plans_dir(paths) / (id + ".json"), ignored);
                            if (orphan || expired(recorded_time(file, field), file)) out.approvals += remove_file(file);
                        }
                    }
                }
            }
        } catch (...) {
            // Best effort: whatever was not purged now is purged next time.
        }
        prune_blobs(paths);
        return out;
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
            refuse_approval(id, "missing", std::format("plan {} needs your approval (guarded mode): forti approve {}", id, id));
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
                // From the 7.4.8 schema snapshot (attributes typed password*, security-audit.md S-08):
                // api-key, aws-api-key, uploadpass, auth-string (RIP), key-string (key-chain, OSPF),
                // preshared-key (FortiAnalyzer), keytab (base64 Kerberos keytab).
                "api-key", "uploadpass", "auth-string", "key-string", "preshared", "keytab",
        };
        static constexpr std::string_view exact[] = {"key", "keys", "ppk-secret", "auth-code", "radius-secret",
                                                     "bmr-hostname"};   // typed password in the schema
        if (std::ranges::find(exact, std::string_view(name)) != std::end(exact)) return true;
        // "<something>-key(s)": enc-key, server-key, secondary-key, ddns-key, inter-controller-key, mpsk-key,
        // n-mhae-key... Public keys and lookup keys are the exceptions.
        if ((name.ends_with("-key") || name.ends_with("-keys")) && name.find("public") == std::string::npos &&
            name != "parent-key" && name != "search-key" && name != "sso-attribute-key")
            return true;
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

    bool sensitive_header(std::string_view header) {
        std::string name = lower(header);
        while (!name.empty() && (name.back() == ' ' || name.back() == '\t')) name.pop_back();
        while (!name.empty() && (name.front() == ' ' || name.front() == '\t')) name.erase(name.begin());
        static constexpr std::string_view exact[] = {"authorization", "proxy-authorization", "cookie", "set-cookie",
                                                     "x-api-key", "x-auth-token"};
        static constexpr std::string_view fragments[] = {"token", "secret", "password", "api-key", "apikey", "api_key"};
        if (std::ranges::find(exact, std::string_view(name)) != std::end(exact)) return true;
        return std::ranges::any_of(fragments, [&](std::string_view fragment) { return name.find(fragment) != std::string::npos; });
    }

    namespace {

        // {"key": "Authorization", "value": "Bearer ..."}: a header entry whose value is a credential.
        bool secret_header_entry(const json& object) {
            auto key = object.find("key");
            return key != object.end() && key->is_string() && object.contains("value") &&
                   sensitive_header(key->get_ref<const std::string&>());
        }

    }  // namespace

    std::set<std::string, std::less<>> redaction_extra(const json& op) {
        if (op.is_object() && op.value("child", "") == header_table) return {"value"};
        return {};
    }

    std::set<std::string, std::less<>> sensitive_from_schema(const json& schema) {
        std::set<std::string, std::less<>> out;
        auto walk = [&](auto& self, const json& node) -> void {
            if (!node.is_object()) return;
            auto children = node.find("children");
            if (children == node.end() || !children->is_object()) return;
            for (auto it = children->begin(); it != children->end(); ++it) {
                // password, password-2, password-3, password_aes256 (all in the 7.4.8 schema).
                if (it.value().is_object() && it.value().value("type", "").starts_with("password")) out.insert(it.key());
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
        bool header = secret_header_entry(value);
        for (auto it = value.begin(); it != value.end(); ++it) {
            bool secret = sensitive_name(it.key()) || extra.contains(it.key()) || (header && it.key() == "value");
            bool value_slot = named_sensitive && (it.key() == "before" || it.key() == "after" || it.key() == "value" ||
                                                  it.key() == "expected" || it.key() == "actual" || it.key() == "table");
            if ((secret || value_slot) && !it.value().is_null()) out[it.key()] = redacted;
            else out[it.key()] = redact(it.value(), extra);
        }
        return out;
    }

    void redact_read(json& value, std::set<std::string, std::less<>>& paths, const std::set<std::string, std::less<>>& extra) {
        // Iterative: device replies are depth-checked, but this keeps the walk off the stack anyway.
        std::vector<std::pair<json*, std::string>> stack{{&value, ""}};
        auto escaped = [](std::string_view key) {
            std::string out;
            for (char c: key) out += c == '~' ? "~0" : c == '/' ? "~1" : std::string(1, c);
            return out;
        };
        while (!stack.empty()) {
            auto [node, pointer] = std::move(stack.back());
            stack.pop_back();
            if (node->is_array()) {
                for (auto& item: *node) stack.emplace_back(&item, pointer + "/*");
            } else if (node->is_object()) {
                // Decided before "key" itself is redacted (sensitive_name("key")) below.
                bool header = secret_header_entry(*node);
                for (auto it = node->begin(); it != node->end(); ++it) {
                    std::string at = pointer + "/" + escaped(it.key());
                    json& child = it.value();
                    bool empty = child.is_null() || (child.is_string() && child.get_ref<const std::string&>().empty()) ||
                                 (child.is_structured() && child.empty());
                    bool secret = sensitive_name(it.key()) || extra.contains(it.key()) || (header && it.key() == "value");
                    if (secret && !empty) {
                        child = redacted;
                        paths.insert(std::move(at));
                    } else {
                        stack.emplace_back(&child, std::move(at));
                    }
                }
            } else if (node->is_string() && node->get_ref<const std::string&>().starts_with("ENC ")) {
                *node = redacted;
                paths.insert(pointer.empty() ? "/" : pointer);
            }
        }
    }

    std::string summarize(const json& plan) {
        const json operations = plan.value("operations", json::array());
        const json device = plan.value("device", json::object());
        std::map<std::string, int> counts;
        for (const auto& op: operations)
            if (op.is_object() && op.contains("op") && op["op"].is_string()) ++counts[op["op"].get<std::string>()];
        std::string parts;
        for (const char* op: {"create", "update", "delete", "action"})
            if (counts[op]) parts += std::format("{}{} {}", parts.empty() ? "" : ", ", counts[op], op);
        auto text = [&](const char* key) {
            auto it = device.find(key);
            return it != device.end() && it->is_string() ? it->get<std::string>() : std::string();
        };
        return std::format("{} operation{} on {} ({}): {}; risk {}", operations.size(), operations.size() == 1 ? "" : "s",
                           text("profile"), text("host"), parts, to_string(plan_risk(plan)));
    }

    json plan_view(const json& plan, bool full) {
        json view = {{"id", plan.value("id", "")},
                     {"digest", plan.value("digest", "")},
                     {"kind", plan.value("kind", "plan")},
                     {"created_at", plan.value("created_at", "")},
                     {"device", plan.value("device", json::object())},
                     {"risk", to_string(plan_risk(plan))},
                     // Recomputed: the stored summary is outside the digest, and a person approving
                     // the plan reads this line first.
                     {"summary", summarize(plan)}};
        if (plan.contains("rollback_of")) view["rollback_of"] = plan["rollback_of"];
        json operations = json::array();
        for (const auto& op: plan.value("operations", json::array())) {
            // Only attribute-bearing subtrees are redacted: the operation's own "key" is an object
            // name, not the attribute "key" (an NTP or OSPF authentication key).
            json entry = json::object();
            // A stored action body is shown by its reference ({"sha256", "bytes"}), never inline.
            for (const char* key: {"index", "op", "resource", "parent", "child", "key", "risk", "note", "body_ref"})
                if (auto it = op.find(key); it != op.end()) entry[key] = *it;
            auto extra = redaction_extra(op);
            if (auto it = op.find("diff"); it != op.end()) entry["diff"] = redact(*it, extra);
            if (auto it = op.find("wire"); it != op.end() && it->is_object()) {
                entry["wire"] = *it;
                if (it->contains("body")) entry["wire"]["body"] = redact((*it)["body"], extra);
            }
            if (full) {
                for (const char* key: {"before", "after"})
                    if (auto it = op.find(key); it != op.end()) entry[key] = redact(*it, extra);
                if (auto it = op.find("before_digest"); it != op.end()) entry["before_digest"] = *it;
            }
            operations.push_back(std::move(entry));
        }
        view["operations"] = std::move(operations);
        if (plan.contains("warnings")) view["warnings"] = plan["warnings"];
        return view;
    }

    // ---- object keys ----

    bool addressable_key(std::string_view key) { return !key.empty() && key != "." && key != ".."; }

    void validate_key(std::string_view key, std::string_view where) {
        if (!addressable_key(key))
            throw Failure(Code::usage, std::format("{}: \"{}\" cannot be used as an object key (it would address the "
                                                   "table or its parent, not one object)", where, key),
                          {{"key", key}});
    }

    // ---- device replies ----

    void check_reply_depth(const json& body, std::string_view what, std::size_t limit) {
        std::vector<std::pair<const json*, std::size_t>> stack{{&body, 0}};
        while (!stack.empty()) {
            auto [node, depth] = stack.back();
            stack.pop_back();
            if (!node->is_structured()) continue;
            if (depth >= limit)
                throw Failure(Code::api, std::format("{}: the device reply is nested more than {} levels deep", what, limit));
            for (const auto& child: *node)
                if (child.is_structured()) stack.emplace_back(&child, depth + 1);
        }
    }

    // ---- audit ----

    bool audit_writable(const Paths& paths) {
        try {
            ensure_private_dir(paths.state);
            int fd = ::open((paths.state / "audit.jsonl").c_str(), O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK, 0600);
            if (fd < 0) return false;
            ::close(fd);
            return true;
        } catch (...) {
            return false;
        }
    }

    bool audit(const Paths& paths, json event) {
        try {
            ensure_private_dir(paths.state);
            json line = {{"time", iso8601(Clock::now())}};
            line.update(event);
            std::string text = canonical(line) + "\n";
            fs::path file = paths.state / "audit.jsonl";
            int fd = ::open(file.c_str(), O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK, 0600);
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
