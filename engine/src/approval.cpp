#include "plan_store.hpp"

#include <forti/engine/approval.hpp>

#include <algorithm>
#include <cstdint>
#include <format>

namespace forti::engine {

    namespace {

        using json = nlohmann::json;
        namespace fs = std::filesystem;

        // pending | approved | approval_expired | applied
        json approval_state(Engine& engine, const json& plan) {
            const Paths& paths = engine.options().paths;
            std::string id = plan["id"];
            json state = {{"applied", detail::plan_applied(paths, id)}};
            auto record = detail::load_approval(paths, id);
            if (record && record->is_object() && (*record)["digest"] == plan["digest"]) {
                auto expires = detail::parse_iso8601(record->value("expires_at", ""));
                bool live = expires && detail::Clock::now() < *expires;
                state["approval"] = {{"approved_at", record->value("approved_at", "")},
                                     {"expires_at", record->value("expires_at", "")},
                                     {"approved_by", record->value("approved_by", "")},
                                     {"valid", live}};
            } else state["approval"] = nullptr;
            state["state"] = state["applied"].get<bool>() ? "applied"
                             : state["approval"].is_object() && state["approval"]["valid"].get<bool>() ? "approved"
                             : state["approval"].is_object() ? "approval_expired" : "pending";
            return state;
        }

    }  // namespace

    json approve_plan(Engine& engine, std::string_view plan_id, std::string_view approved_by,
                      std::chrono::seconds lifetime, std::string_view shown_digest) {
        const Paths& paths = engine.options().paths;
        json event = {{"event", "approve"}, {"plan_id", plan_id}, {"approved_by", approved_by}};
        if (!engine.options().actor.empty()) event["actor"] = engine.options().actor;
        try {
            detail::validate_plan_id(plan_id);
            if (approved_by.empty() || approved_by.size() > 128)
                throw Failure(Code::usage, "approve: approved_by must be 1-128 characters");
            if (lifetime <= std::chrono::seconds(0) || lifetime > std::chrono::days(7))
                throw Failure(Code::usage, "approve: the lifetime must be between 1 second and 7 days");
            // Applied plans are deleted: the marker answers before the (missing) plan file would.
            if (detail::plan_applied(paths, plan_id)) detail::refuse_applied(paths, plan_id, "plan again");
            json plan = detail::load_plan(paths, plan_id);
            event["digest"] = plan["digest"];
            if (!shown_digest.empty() && plan["digest"] != shown_digest)
                throw Failure(Code::stale_plan,
                              std::format("plan {} changed after it was shown; nothing was approved. Show it again", plan_id),
                              {{"plan_id", plan_id}, {"reason", "plan_changed"}});
            const Profile& profile = engine.profile(plan["device"].value("profile", ""));
            event["mode"] = to_string(profile.mode);
            if (profile.mode == Mode::read_only)
                throw Failure(Code::policy_denied,
                              std::format("profile {0} is read-only: an approval would not allow apply. To allow changes, "
                                          "run `forti profile mode {0} guarded` first",
                                          profile.name),
                              {{"plan_id", plan_id}, {"reason", "read_only"}, {"profile", profile.name}});
            if (profile.mode == Mode::autonomous) {
                event["outcome"] = "not_required";
                detail::audit(paths, event);
                return ok({{"plan_id", plan_id}, {"digest", plan["digest"]}, {"required", false},
                           {"note", std::format("profile {} is autonomous: apply needs no approval", profile.name)},
                           {"apply", std::format("forti apply {}", plan_id)}});
            }
            auto now = detail::Clock::now();
            json record = {{"format", detail::approval_format},
                           {"plan_id", plan_id},
                           {"digest", plan["digest"]},
                           {"approved_at", detail::iso8601(now)},
                           {"expires_at", detail::iso8601(now + lifetime)},
                           {"approved_by", approved_by}};
            detail::save_approval(paths, record);
            event["outcome"] = "approved";
            event["expires_at"] = record["expires_at"];
            detail::audit(paths, event);
            record.erase("format");
            record["apply"] = std::format("forti apply {}", plan_id);
            return ok(std::move(record));
        } catch (...) {
            Failure failure = translate(std::current_exception());
            event["outcome"] = to_string(failure.code());
            event["error"] = {{"code", to_string(failure.code())}, {"message", failure.what()}};
            detail::audit(paths, event);
            throw failure;
        }
    }

    json show_plan(Engine& engine, std::string_view plan_id) {
        const Paths& paths = engine.options().paths;
        detail::validate_plan_id(plan_id);
        std::error_code missing;
        if (!std::filesystem::exists(detail::plan_file(paths, plan_id), missing))
            if (auto marker = detail::applied_marker(paths, plan_id)) {
                json details = {{"plan_id", plan_id}, {"reason", "already_applied"}};
                for (const char* key: {"applied_at", "outcome", "rollback_plan"})
                    if (auto it = marker->find(key); it != marker->end()) details[key] = *it;
                std::string when = marker->value("applied_at", "");
                throw Failure(Code::not_found,
                              std::format("plan {} was applied{} and is no longer stored (applied plans are deleted); "
                                          "forti history shows what it did", plan_id, when.empty() ? "" : " at " + when),
                              std::move(details));
            }
        json plan = detail::load_plan(paths, plan_id);
        json data = detail::plan_view(plan, true);
        data["state"] = approval_state(engine, plan);
        try {
            const Profile& profile = engine.profile(plan["device"].value("profile", ""));
            data["mode"] = to_string(profile.mode);
        } catch (const Failure&) {
            data["mode"] = nullptr;   // the profile was removed since planning
        }
        return ok(std::move(data));
    }

    json purge_plans(Engine& engine) {
        unsigned days = engine.profiles().retention_days();
        detail::Purged purged = detail::purge_plans(engine.options().paths, std::chrono::days(days), detail::Clock::now());
        return ok({{"retention_days", days},
                   {"skipped", purged.skipped},
                   {"removed", {{"plans", purged.plans}, {"applied", purged.applied}, {"markers", purged.markers},
                                {"approvals", purged.approvals}, {"leftovers", purged.leftovers}}}});
    }

    json list_plans(Engine& engine) {
        const Paths& paths = engine.options().paths;
        (void) purge_plans(engine);
        fs::path dir = paths.state / "plans";
        json list = json::array();
        std::error_code error;
        for (const auto& entry: fs::directory_iterator(dir, error)) {
            std::string id = entry.path().stem().string();
            if (entry.path().extension() == ".applied" && valid_plan_id(id)) {
                // An applied plan, its file deleted: listed from its marker until retention ends.
                std::error_code ignored;
                if (fs::exists(dir / (id + ".json"), ignored)) continue;   // listed below, from the plan
                json marker = detail::applied_marker(paths, id).value_or(json::object());
                json item = {{"id", id}, {"state", "applied"}, {"stored", false}};
                for (const char* key: {"kind", "created_at", "profile", "host", "risk", "summary", "operations",
                                       "rollback_of", "applied_at", "outcome", "rollback_plan"})
                    if (auto it = marker.find(key); it != marker.end()) item[key] = *it;
                if (!item.contains("created_at"))
                    if (auto time = detail::plan_id_time(id)) item["created_at"] = detail::iso8601(*time);
                list.push_back(std::move(item));
                continue;
            }
            if (entry.path().extension() != ".json") continue;
            json item = {{"id", id}, {"stored", true}};
            try {
                json plan = detail::load_plan(paths, id);
                json view = detail::plan_view(plan);
                for (const char* key: {"kind", "created_at", "risk", "summary"}) item[key] = view[key];
                if (plan.contains("created_ns") && plan["created_ns"].is_number_integer()) item["created_ns"] = plan["created_ns"];
                item["profile"] = plan["device"].value("profile", "");
                item["host"] = plan["device"].value("host", "");
                item["operations"] = plan["operations"].size();
                if (plan.contains("rollback_of")) item["rollback_of"] = plan["rollback_of"];
                item["state"] = approval_state(engine, plan)["state"];
            } catch (const Failure& failure) {
                item["state"] = failure.code() == Code::usage ? "invalid" : "tampered";
            }
            list.push_back(std::move(item));
        }
        // Newest first: created_at (whole seconds), then created_ns within a second (plans before 0.3
        // have none), then the id.
        std::sort(list.begin(), list.end(), [](const json& a, const json& b) {
            if (a.value("created_at", "") != b.value("created_at", "")) return a.value("created_at", "") > b.value("created_at", "");
            std::int64_t an = a.value("created_ns", std::int64_t{0}), bn = b.value("created_ns", std::int64_t{0});
            return an != bn ? an > bn : a.value("id", "") > b.value("id", "");
        });
        std::size_t returned = list.size();
        return ok(std::move(list), {{"returned", returned}});
    }

}  // namespace forti::engine
