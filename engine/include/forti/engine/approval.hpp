//
// Stored plans and guarded-mode approvals, for the `forti` CLI (architecture.md, "Operating modes
// and mutation safety").
//
// CLI ONLY. forti-mcp must never call approve_plan(): an approval is the human's act in guarded mode,
// and the MCP server never writes approvals (in guarded mode forti_apply answers approval_required
// with the `forti plan approve <id>` command for the human). show_plan() and list_plans() only read.
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
    // Never contacts the device.
    nlohmann::json approve_plan(Engine& engine, std::string_view plan_id, std::string_view approved_by,
                                std::chrono::seconds lifetime = std::chrono::hours(24));

    // The verified plan (redacted, with before/after) plus its state: approval, applied, mode.
    nlohmann::json show_plan(Engine& engine, std::string_view plan_id);

    // Stored plans, newest first: {id, kind, created_at, profile, host, risk, operations, summary, state}.
    // state: pending | approved | approval_expired | applied | invalid | tampered.
    nlohmann::json list_plans(Engine& engine);

}  // namespace forti::engine

#endif  // FORTI_ENGINE_APPROVAL_HPP
