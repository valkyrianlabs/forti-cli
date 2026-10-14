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

    // Plan ids: [A-Za-z0-9-]{1,64}. Throws Failure(usage).
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
    // A plan as shown to people and agents: before/after objects (only with `full`), diffs and wire
    // bodies redacted. The stored file keeps real values, because apply needs them.
    json plan_view(const json& plan, bool full = false);

    // ---- Audit ----

    // Appends one line to <state>/audit.jsonl (0600), adding "time". The event must already be
    // redacted. Returns false (never throws) when the log cannot be written.
    bool audit(const Paths& paths, json event);

}  // namespace forti::engine::detail

#endif  // FORTI_ENGINE_PLAN_STORE_HPP
