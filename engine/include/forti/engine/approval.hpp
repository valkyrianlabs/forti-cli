//
// Stored plans and guarded-mode approvals (architecture.md, "Operating modes and mutation safety").
//
// approve_plan() records a person's approval, and only that: the CLI calls it when someone at a
// terminal says yes (or passes --yes, a decision made in advance), and forti-mcp calls it only for a
// person's answer to the MCP client's own question (form elicitation, accept with approve: true),
// never for anything in tool arguments, which the model writes. Both pass the digest of the plan the
// person was shown, so an approval can never cover a plan they did not see. show_plan() and
// list_plans() only read.
//
// An approval is deliberately simple (maintainer decision): <state>/approvals/<id>.json with
// {plan_id, digest, approved_at, expires_at, approved_by}, single use, default lifetime 24 hours. It is
// a record of operator intent, not a cryptographic control: anything that can write the state
// directory as the user can write one. The FortiOS account's privileges remain the authorization
// boundary; the profile mode is the operator's policy on top of it.
//

#ifndef FORTI_ENGINE_APPROVAL_HPP
#define FORTI_ENGINE_APPROVAL_HPP

#include "engine.hpp"

#include <chrono>
#include <string_view>

namespace forti::engine {

    // Approves a stored plan (guarded mode). Verifies the plan's integrity first. Refuses with
    // policy_denied for read-only profiles and plans already applied; for autonomous profiles nothing
    // is written ({"required": false}). Returns {plan_id, digest, approved_at, expires_at, approved_by}.
    // Never contacts the device. `shown_digest`, when given, is the digest of the plan the person
    // was shown: a plan that no longer has it is refused (stale_plan, reason "plan_changed") and no
    // approval is written.
    nlohmann::json approve_plan(Engine& engine, std::string_view plan_id, std::string_view approved_by,
                                std::chrono::seconds lifetime = std::chrono::hours(24),
                                std::string_view shown_digest = {});

    // The verified plan (redacted, with before/after) plus its state: approval, applied, mode.
    nlohmann::json show_plan(Engine& engine, std::string_view plan_id);

    // Stored plans, newest first: {id, kind, created_at, profile, host, risk, operations, summary, state}.
    // state: pending | approved | approval_expired | applied | invalid | tampered.
    nlohmann::json list_plans(Engine& engine);

}  // namespace forti::engine

#endif  // FORTI_ENGINE_APPROVAL_HPP
