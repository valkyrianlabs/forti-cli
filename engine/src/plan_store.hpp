//
// Engine-internal: stored plans, approval records, the audit log and sensitive-value redaction
// (architecture.md, "Operating modes and mutation safety"). Shared by plan.cpp (Engine::plan /
// Engine::apply) and approval.cpp (the CLI-facing approve / show / list API).
//
//   <state>/plans/<id>.json          the plan (0600); its digest is recomputed on every load
//   <state>/plans/<id>.applied       written before the first mutation: a plan executes at most once
//   <state>/approvals/<id>.json      guarded mode: the human approval of that plan's digest
//   <state>/approvals/<id>.used      the approval consumed by apply (single use)
//   <state>/audit.jsonl              one JSON object per line: every apply and approve attempt, redacted
//

#ifndef FORTI_ENGINE_PLAN_STORE_HPP
#define FORTI_ENGINE_PLAN_STORE_HPP

#include "policy.hpp"

#include <forti/engine/profile.hpp>

#include <nlohmann/json.hpp>

#include <chrono>
#include <filesystem>
#include <optional>
#include <set>
#include <string>
#include <string_view>

namespace forti::engine::detail {

    using json = nlohmann::json;
    using Clock = std::chrono::system_clock;

    inline constexpr int plan_format = 1;
    inline constexpr int approval_format = 1;
    inline constexpr std::chrono::hours default_approval_ttl{24};

    std::string iso8601(Clock::time_point time);
    // Parses what iso8601() writes ("2026-10-14T15:30:12Z"); nullopt otherwise.
    std::optional<Clock::time_point> parse_iso8601(std::string_view text);

    // Canonical JSON: keys sorted (nlohmann's object is an ordered map), no whitespace, non-ASCII
    // escaped. Equal documents give the same bytes, before and after a file round trip.
    std::string canonical(const json& value);
    // Lowercase hex SHA-256 of canonical(value).
    std::string digest_of(const json& value);
    // The plan digest: SHA-256 of canonical {format, device, operations} (operations carry their
    // before digests, wire bodies and risk).
    std::string plan_digest(const json& plan);

    // Plan ids: forti::engine::plan_id_pattern. Throws Failure(usage).
    void validate_plan_id(std::string_view id);
    std::string new_plan_id(Clock::time_point time);

    std::filesystem::path plan_file(const Paths& paths, std::string_view id);
    std::filesystem::path approval_file(const Paths& paths, std::string_view id);

    void save_plan(const Paths& paths, const json& plan);
    // Loads and re-verifies a plan: not_found when missing; policy_denied (details.reason "tampered")
    // when the stored and recomputed digests, the id, or a per-operation risk tier disagree.
    json load_plan(const Paths& paths, std::string_view id);
    Risk plan_risk(const json& plan);
    Risk parse_risk(std::string_view text);

    bool plan_applied(const Paths& paths, std::string_view id);
    // Creates <id>.applied atomically (O_CREAT|O_EXCL). Throws Failure(policy_denied, reason
    // "already_applied") when it exists: two concurrent applies of one plan cannot both proceed.
    void mark_applied(const Paths& paths, std::string_view id, Clock::time_point time);

    // ---- Approvals (guarded mode) ----

    std::optional<json> load_approval(const Paths& paths, std::string_view id);
    void save_approval(const Paths& paths, const json& record);
    // Checks the record against the plan. Throws Failure(approval_required) with details.reason:
    // missing | malformed | digest_mismatch | expired | used.
    void verify_approval(const Paths& paths, const json& plan, Clock::time_point time);
    // Single use: writes <id>.used and removes the record. Called before the first mutation.
    void consume_approval(const Paths& paths, std::string_view id, Clock::time_point time);

    // ---- Redaction ----

    // True for attribute names that carry credentials (password, passwd, psk, secret, private-key,
    // key-material, token, passphrase, *-pwd, md5/auth keys, ...). Deliberately broad: over-redacting
    // a display is harmless, under-redacting is a leak.
    bool sensitive_name(std::string_view attribute);
    // Attribute names the live schema (?action=schema) types as "password", recursively.
    std::set<std::string, std::less<>> sensitive_from_schema(const json& schema);

    inline constexpr std::string_view redacted = "<redacted>";
    // A copy with every sensitive attribute's value (at any depth) replaced by "<redacted>". Apply it to
    // attribute-bearing JSON only (objects, diffs, wire bodies, error details), not to whole records.
    json redact(const json& value, const std::set<std::string, std::less<>>& extra = {});
    // "2 operations on lab (fortigate.test): 1 create, 1 update; risk elevated", from digest-covered fields.
    std::string summarize(const json& plan);
    // Read results: replaces, at any depth, string values starting "ENC " (FortiOS's reversible secret
    // form) and non-empty values of sensitive_name() attributes with "<redacted>". Adds each redacted
    // location to `paths` once, as a JSON pointer with "*" for array indices ("/*/psksecret").
    void redact_read(json& value, std::set<std::string, std::less<>>& paths);
    // A plan as shown to people and agents: before/after objects (only with `full`), diffs and wire
    // bodies redacted. The stored file keeps real values, because apply needs them.
    json plan_view(const json& plan, bool full = false);

    // ---- Object keys ----

    // A table key becomes one URL path segment. The SDK percent-encodes everything but unreserved
    // characters, '.' included, so a key of "." or ".." stays a dot segment, and libcurl removes dot
    // segments: DELETE cmdb/firewall/address/. is sent as DELETE cmdb/firewall/address/ (the whole
    // table), ".." reaches the parent. False for those (and for empty keys).
    [[nodiscard]] bool addressable_key(std::string_view key);
    // Throws Failure(usage) unless addressable_key(key).
    void validate_key(std::string_view key, std::string_view where);

    // ---- Device replies ----

    // FortiOS replies nest a handful of levels. nlohmann's parser is iterative but its copy constructor
    // and dump() recurse, so a reply nested thousands deep (a hostile or broken device) would overflow
    // the stack the first time the engine copies it. Checked iteratively, right after the SDK returns
    // and before any copy: Failure(api) beyond `limit` levels.
    inline constexpr std::size_t max_reply_depth = 256;
    void check_reply_depth(const json& body, std::string_view what, std::size_t limit = max_reply_depth);

    // ---- Audit ----

    // Appends one line to <state>/audit.jsonl (0600), adding "time". The event must already be
    // redacted. Returns false (never throws) when the log cannot be written.
    bool audit(const Paths& paths, json event);
    // True when <state>/audit.jsonl can be opened for appending (created 0600 if missing). Never throws.
    bool audit_writable(const Paths& paths);

}  // namespace forti::engine::detail

#endif  // FORTI_ENGINE_PLAN_STORE_HPP
