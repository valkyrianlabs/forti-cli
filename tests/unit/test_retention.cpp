// Plan retention (architecture.md, "Plan retention"): an apply that started executing deletes its plan
// and keeps a marker that refuses a second apply; a refused apply keeps the plan; plans, markers and
// approvals age out after config.json's plan_retention_days; a purge never runs during an apply.
// Against the scripted transport and temporary directories. Nothing here talks to a FortiGate.

#include <fake_transport.hpp>

#include <forti/engine/approval.hpp>

#include "plan_store.hpp"

#include <gtest/gtest.h>

#include <filesystem>
#include <format>
#include <fstream>
#include <functional>
#include <sstream>

#include <sys/stat.h>
#include <sys/time.h>

using namespace forti;
using json = nlohmann::json;
using engine::Mode;
namespace fs = std::filesystem;
using std::chrono::days;

namespace {

    const std::string serial = "FGT60FTK00000000";

    struct TempDir {
        fs::path path;
        TempDir() {
            std::string pattern = (fs::temp_directory_path() / "forti-retention-test-XXXXXX").string();
            path = ::mkdtemp(pattern.data());
        }
        ~TempDir() { fs::remove_all(path); }
    };

    json address(const std::string& comment) {
        return {{"name", "LAN"}, {"q_origin_key", "LAN"}, {"uuid", "8f0c-LAN"}, {"subnet", "192.0.2.0 255.255.255.0"},
                {"type", "ipmask"}, {"comment", comment}, {"color", 0}};
    }

    json written() {
        return {{"status", "success"}, {"http_status", 200}, {"serial", serial}, {"version", "v7.4.8"}, {"vdom", "root"},
                {"mkey", "LAN"}};
    }

    std::string slurp(const fs::path& file) {
        std::ifstream in(file);
        std::stringstream text;
        text << in.rdbuf();
        return text.str();
    }

    void write(const fs::path& file, const std::string& text) {
        fs::create_directories(file.parent_path());
        std::ofstream(file) << text;
    }

    // Sets a file's modification time `age` in the past.
    void age_file(const fs::path& file, std::chrono::seconds age) {
        struct timeval times[2]{};
        times[0].tv_sec = times[1].tv_sec = std::time(nullptr) - static_cast<std::time_t>(age.count());
        ASSERT_EQ(::utimes(file.c_str(), times), 0) << file;
    }

    // Runs `hook` before each request of `method` (a purge "in another process" during an apply).
    struct Hooked final : fortiapi::Transport {
        std::shared_ptr<fake::FakeTransport> inner;
        fortiapi::Method method = fortiapi::Method::Put;
        std::function<void()> hook;
        fortiapi::HttpResponse perform(const fortiapi::HttpRequest& request) override {
            if (request.method == method && hook) hook();
            return inner->perform(request);
        }
    };

    struct RetentionTest : ::testing::Test {
        TempDir dir;
        std::shared_ptr<fake::FakeTransport> transport = std::make_shared<fake::FakeTransport>();
        std::shared_ptr<Hooked> hooked = std::make_shared<Hooked>();
        engine::Paths paths{dir.path / "config", dir.path / "state", dir.path / "cache", {}};
        engine::Options options;
        std::unique_ptr<engine::Engine> sut;
        engine::detail::Clock::time_point now = engine::detail::Clock::now();

        void make(Mode mode, std::optional<unsigned> retention = std::nullopt) {
            options = fake::options(transport, mode);
            options.paths = paths;
            options.profiles->plan_retention_days = retention;
            hooked->inner = transport;
            auto through = hooked;
            options.transport = [through](const fortiapi::Config&) -> std::shared_ptr<fortiapi::Transport> { return through; };
            sut = std::make_unique<engine::Engine>(options);
        }

        RetentionTest() { make(Mode::autonomous); }

        json apply(const std::string& id) { return engine::Engine::envelope([&] { return sut->apply({{"plan_id", id}}); }); }
        json approve(const std::string& id) {
            return engine::Engine::envelope([&] { return engine::approve_plan(*sut, id, "cli:test"); });
        }
        json show(const std::string& id) { return engine::Engine::envelope([&] { return engine::show_plan(*sut, id); }); }

        fs::path plans() const { return paths.state / "plans"; }
        fs::path approvals() const { return paths.state / "approvals"; }
        fs::path plan_file(const std::string& id) const { return plans() / (id + ".json"); }
        fs::path marker(const std::string& id) const { return plans() / (id + ".applied"); }

        // Plans comment "new" on address LAN (now "old").
        std::string plan_comment() {
            transport->reply(200, fake::envelope(json::array({address("old")})));
            json result = engine::Engine::envelope([&] {
                return sut->plan({{"operations", {{{"op", "update"}, {"resource", "firewall/address"}, {"key", "LAN"},
                                                   {"set", {{"comment", "new"}}}}}}});
            });
            EXPECT_TRUE(result["ok"]) << result.dump();
            return result["data"].value("id", "");
        }

        // A successful apply of plan_comment(): re-read, PUT, verify.
        void script_apply() {
            transport->reply(200, fake::envelope(json::array({address("old")})));
            transport->reply(200, written());
            transport->reply(200, fake::envelope(json::array({address("new")})));
        }

        std::size_t writes() const {
            std::size_t n = 0;
            for (const auto& request: transport->requests) n += request.method != fortiapi::Method::Get;
            return n;
        }

        engine::detail::Purged purge(unsigned retention_days, engine::detail::Clock::time_point at) {
            return engine::detail::purge_plans(paths, days(retention_days), at);
        }
    };

    // A plan id made `age` ago (the form new_plan_id writes).
    std::string old_id(std::chrono::seconds age, std::string_view tail) {
        auto time = std::chrono::floor<std::chrono::seconds>(engine::detail::Clock::now() - age);
        return std::format("{:%Y%m%d-%H%M%S}-{}", time, tail);
    }

}  // namespace

// ---- applied plans are deleted ----

TEST_F(RetentionTest, AnAppliedPlanIsDeletedAndARepeatIsRefusedAsAlreadyApplied) {
    std::string id = plan_comment();
    script_apply();
    json result = apply(id);
    ASSERT_TRUE(result["ok"]) << result.dump();
    std::string rollback = result["data"]["rollback"]["plan_id"];

    EXPECT_FALSE(fs::exists(plan_file(id)));
    ASSERT_TRUE(fs::exists(marker(id)));
    json tombstone = json::parse(slurp(marker(id)));
    EXPECT_EQ(tombstone["plan_id"], id);
    EXPECT_EQ(tombstone["outcome"], "ok");
    EXPECT_EQ(tombstone["rollback_plan"], rollback);
    EXPECT_EQ(tombstone["kind"], "plan");
    EXPECT_EQ(tombstone["profile"], "lab");
    EXPECT_EQ(tombstone["operations"], 1);
    EXPECT_TRUE(tombstone["applied_at"].is_string());
    EXPECT_EQ(tombstone.dump().find("\"new\""), std::string::npos);   // no values, only the summary
    // The rollback plan is a plan like any other: kept until it is applied or retention ends.
    EXPECT_TRUE(fs::exists(plan_file(rollback)));

    transport->requests.clear();
    json again = apply(id);
    EXPECT_EQ(again["error"]["code"], "policy_denied") << again.dump();
    EXPECT_EQ(again["error"]["details"]["reason"], "already_applied");
    EXPECT_EQ(again["error"]["details"]["applied_at"], tombstone["applied_at"]);
    EXPECT_NE(again["error"]["message"].get<std::string>().find("already applied"), std::string::npos);
    EXPECT_TRUE(transport->requests.empty());   // nothing read, nothing sent

    json shown = show(id);
    EXPECT_EQ(shown["error"]["code"], "not_found");
    EXPECT_EQ(shown["error"]["details"]["reason"], "already_applied");
    EXPECT_EQ(approve(id)["error"]["details"]["reason"], "already_applied");

    json listed = engine::list_plans(*sut)["data"];
    ASSERT_EQ(listed.size(), 2u);
    json entry = listed[0]["id"] == id ? listed[0] : listed[1];
    EXPECT_EQ(entry["state"], "applied");
    EXPECT_FALSE(entry["stored"].get<bool>());
    EXPECT_EQ(entry["summary"], tombstone["summary"]);
}

TEST_F(RetentionTest, EveryOutcomeOfAStartedApplyDeletesThePlan) {
    struct Case {
        const char* outcome;
        std::function<void(fake::FakeTransport&)> script;
    };
    std::vector<Case> cases = {
            {"partial_failure", [](fake::FakeTransport& t) {
                 t.reply(200, fake::envelope(json::array({address("old")})));
                 t.reply(500, {{"status", "error"}, {"http_status", 500}, {"error", -1}});
                 t.reply(200, fake::envelope(json::array({address("old")})));   // what was left behind
             }},
            {"outcome_unknown", [](fake::FakeTransport& t) {
                 t.reply(200, fake::envelope(json::array({address("old")})));
                 t.fail(28, false);   // timed out after sending
                 t.reply(200, fake::envelope(json::array({address("old")})));
             }},
    };
    for (const auto& c: cases) {
        std::string id = plan_comment();
        c.script(*transport);
        json result = apply(id);
        EXPECT_EQ(result["error"]["code"], c.outcome) << result.dump();
        EXPECT_FALSE(fs::exists(plan_file(id))) << c.outcome;
        ASSERT_TRUE(fs::exists(marker(id))) << c.outcome;
        EXPECT_EQ(json::parse(slurp(marker(id)))["outcome"], c.outcome);
        EXPECT_EQ(apply(id)["error"]["details"]["reason"], "already_applied");
        transport->script.clear();
    }
}

TEST_F(RetentionTest, ALostManagementPathDeletesThePlanToo) {
    json global = {{"hostname", "fw1"}, {"admin-sport", 443}};
    transport->reply(200, fake::envelope(global));
    json planned = engine::Engine::envelope([&] {
        return sut->plan({{"operations", {{{"op", "update"}, {"resource", "system/global"}, {"set", {{"admin-sport", 8443}}}}}}});
    });
    ASSERT_TRUE(planned["ok"]) << planned.dump();
    std::string id = planned["data"]["id"];
    transport->reply(200, fake::envelope(global));
    transport->reply_raw(200, "#config-version=FGT60F-7.4.8\nconfig system global\nend\n");
    transport->reply(200, written());
    transport->reply(200, fake::envelope({{"hostname", "fw1"}, {"admin-sport", 8443}}));
    transport->fail(7, true).fail(7, true);   // the probe
    json result = apply(id);
    EXPECT_EQ(result["error"]["code"], "management_connectivity_lost") << result.dump();
    EXPECT_FALSE(fs::exists(plan_file(id)));
    EXPECT_EQ(json::parse(slurp(marker(id)))["outcome"], "management_connectivity_lost");
    // The rollback plan and the backup stay: they are the recovery aids.
    EXPECT_TRUE(fs::exists(plan_file(result["error"]["details"]["rollback"]["plan_id"])));
    EXPECT_TRUE(fs::exists(result["error"]["details"]["backup"]["path"].get<std::string>()));
}

TEST_F(RetentionTest, AGuardedApplyDeletesItsApprovalRecords) {
    make(Mode::guarded);
    std::string id = plan_comment();
    ASSERT_TRUE(approve(id)["ok"]);
    ASSERT_TRUE(fs::exists(approvals() / (id + ".json")));
    script_apply();
    ASSERT_TRUE(apply(id)["ok"]);
    EXPECT_FALSE(fs::exists(plan_file(id)));
    EXPECT_FALSE(fs::exists(approvals() / (id + ".json")));
    EXPECT_FALSE(fs::exists(approvals() / (id + ".used")));
    EXPECT_EQ(apply(id)["error"]["details"]["reason"], "already_applied");
}

// ---- refused before anything was sent: the plan stays ----

TEST_F(RetentionTest, ARefusedApplyKeepsThePlanForARetry) {
    // approval_required, then approved and applied.
    make(Mode::guarded);
    std::string guarded = plan_comment();
    EXPECT_EQ(apply(guarded)["error"]["code"], "approval_required");
    EXPECT_TRUE(fs::exists(plan_file(guarded)));
    EXPECT_FALSE(fs::exists(marker(guarded)));
    ASSERT_TRUE(approve(guarded)["ok"]);
    script_apply();
    ASSERT_TRUE(apply(guarded)["ok"]);

    // policy_denied (read-only).
    make(Mode::read_only);
    std::string denied = plan_comment();
    EXPECT_EQ(apply(denied)["error"]["code"], "policy_denied");
    EXPECT_TRUE(fs::exists(plan_file(denied)));

    // stale_plan.
    make(Mode::autonomous);
    std::string stale = plan_comment();
    transport->reply(200, fake::envelope(json::array({address("changed meanwhile")})));
    EXPECT_EQ(apply(stale)["error"]["code"], "stale_plan");
    EXPECT_TRUE(fs::exists(plan_file(stale)));
    EXPECT_FALSE(fs::exists(marker(stale)));

    // The audit log cannot be written: refused before the first mutation.
    std::string audit = plan_comment();
    fs::remove(paths.state / "audit.jsonl");
    fs::create_directory(paths.state / "audit.jsonl");
    transport->reply(200, fake::envelope(json::array({address("old")})));
    EXPECT_EQ(apply(audit)["error"]["details"]["reason"], "audit_unwritable");
    EXPECT_TRUE(fs::exists(plan_file(audit)));
    fs::remove(paths.state / "audit.jsonl");

    // Tampered: kept (it is evidence, and retention removes it).
    std::string tampered = plan_comment();
    json stored = json::parse(slurp(plan_file(tampered)));
    stored["operations"][0]["set"]["comment"] = "other";
    write(plan_file(tampered), stored.dump());
    EXPECT_EQ(apply(tampered)["error"]["details"]["reason"], "tampered");
    EXPECT_TRUE(fs::exists(plan_file(tampered)));
    EXPECT_EQ(writes(), 1u);   // only the guarded plan's PUT

    // Each kept plan can still run once the refusal is resolved.
    script_apply();
    EXPECT_TRUE(apply(stale)["ok"]);
}

// ---- retention ----

TEST_F(RetentionTest, PurgeRemovesWhatIsOlderThanTheRetention) {
    auto day = std::chrono::seconds(days(1));
    std::string old_plan = old_id(31 * day, "aaaaaa");
    std::string old_rollback = old_id(40 * day, "bbbbbb");
    std::string young_plan = old_id(29 * day, "cccccc");
    std::string old_applied = old_id(45 * day, "dddddd");
    std::string young_applied = old_id(35 * day, "eeeeee");   // made long ago, applied recently
    write(plans() / (old_plan + ".json"), R"({"kind": "plan"})");
    write(plans() / (old_rollback + ".json"), R"({"kind": "rollback", "rollback_of": "x"})");
    write(plans() / (young_plan + ".json"), R"({"kind": "plan"})");
    write(marker(old_applied), json({{"plan_id", old_applied}, {"applied_at", engine::detail::iso8601(now - 31 * day)}}).dump());
    write(marker(young_applied), json({{"plan_id", young_applied}, {"applied_at", engine::detail::iso8601(now - 2 * day)}}).dump());
    // Approvals: of a plan past retention, of a stored plan (recent, old), and of a plan that is gone.
    write(approvals() / (young_plan + ".json"), json({{"approved_at", engine::detail::iso8601(now - day)}}).dump());
    write(approvals() / (old_plan + ".json"), json({{"approved_at", engine::detail::iso8601(now - day)}}).dump());
    std::string gone = old_id(2 * day, "ffffff");
    write(approvals() / (gone + ".used"), json({{"used_at", engine::detail::iso8601(now - day)}}).dump());
    // Ids without a time, markers without applied_at and interrupted writes: by modification time.
    write(plans() / "handwritten-plan.json", "{}");
    age_file(plans() / "handwritten-plan.json", 31 * day);
    write(plans() / "handwritten-new.json", "{}");
    std::string bare = old_id(60 * day, "121212");
    write(marker(bare), "not json");
    age_file(marker(bare), 31 * day);
    write(plans() / (young_plan + ".json.tmp.4242"), "{");
    age_file(plans() / (young_plan + ".json.tmp.4242"), 31 * day);
    write(plans() / (young_plan + ".json.tmp.4343"), "{");
    write(paths.state / "audit.jsonl", "{}\n");
    age_file(paths.state / "audit.jsonl", 400 * day);
    write(paths.state / "backups" / (old_plan + ".conf"), "config\n");
    age_file(paths.state / "backups" / (old_plan + ".conf"), 400 * day);

    engine::detail::Purged purged = purge(30, now);
    EXPECT_FALSE(purged.skipped);
    EXPECT_EQ(purged.plans, 3u);   // old plan, old rollback plan, handwritten-plan
    EXPECT_EQ(purged.markers, 2u);
    EXPECT_EQ(purged.approvals, 2u);
    EXPECT_EQ(purged.leftovers, 1u);
    EXPECT_FALSE(fs::exists(plans() / (old_plan + ".json")));
    EXPECT_FALSE(fs::exists(plans() / (old_rollback + ".json")));
    EXPECT_TRUE(fs::exists(plans() / (young_plan + ".json")));
    EXPECT_FALSE(fs::exists(marker(old_applied)));
    EXPECT_TRUE(fs::exists(marker(young_applied)));
    EXPECT_FALSE(fs::exists(marker(bare)));
    EXPECT_TRUE(fs::exists(approvals() / (young_plan + ".json")));
    EXPECT_FALSE(fs::exists(approvals() / (old_plan + ".json")));   // its plan is gone
    EXPECT_FALSE(fs::exists(approvals() / (gone + ".used")));
    EXPECT_FALSE(fs::exists(plans() / "handwritten-plan.json"));
    EXPECT_TRUE(fs::exists(plans() / "handwritten-new.json"));
    EXPECT_FALSE(fs::exists(plans() / (young_plan + ".json.tmp.4242")));
    EXPECT_TRUE(fs::exists(plans() / (young_plan + ".json.tmp.4343")));
    // The audit log and config backups are not plan retention's.
    EXPECT_TRUE(fs::exists(paths.state / "audit.jsonl"));
    EXPECT_TRUE(fs::exists(paths.state / "backups" / (old_plan + ".conf")));

    // An approval past retention goes even while its plan is kept.
    write(approvals() / (young_plan + ".json"), json({{"approved_at", engine::detail::iso8601(now - 2 * day)}}).dump());
    EXPECT_EQ(purge(1, now).approvals, 1u);
    EXPECT_FALSE(fs::exists(approvals() / (young_plan + ".json")));

    // Nothing to purge, and no state directory at all: no error.
    EXPECT_EQ(purge(3650, now).plans, 0u);
    fs::remove_all(paths.state);
    EXPECT_FALSE(purge(1, now).skipped);
    EXPECT_FALSE(fs::exists(paths.state));
}

TEST_F(RetentionTest, PlanAndApplyPurgeWithTheConfiguredRetention) {
    auto day = std::chrono::seconds(days(1));
    std::string three_days = old_id(3 * day, "aaaaaa");
    write(plans() / (three_days + ".json"), "{}");

    // The default (30 days) keeps it.
    std::string id = plan_comment();
    EXPECT_TRUE(fs::exists(plans() / (three_days + ".json")));

    // plan_retention_days 2: the next plan removes it; apply and list purge as well.
    make(Mode::autonomous, 2);
    (void) plan_comment();
    EXPECT_FALSE(fs::exists(plans() / (three_days + ".json")));
    write(plans() / (three_days + ".json"), "{}");
    script_apply();
    ASSERT_TRUE(apply(id)["ok"]);
    EXPECT_FALSE(fs::exists(plans() / (three_days + ".json")));
    write(plans() / (three_days + ".json"), "{}");
    json listed = engine::list_plans(*sut)["data"];
    EXPECT_FALSE(fs::exists(plans() / (three_days + ".json")));
    for (const auto& item: listed) EXPECT_NE(item["id"], three_days);

    json purged = engine::purge_plans(*sut);
    EXPECT_EQ(purged["data"]["retention_days"], 2);
    EXPECT_FALSE(purged["data"]["skipped"].get<bool>());
}

TEST_F(RetentionTest, PlansAppliedByEarlierReleasesAreDeletedAndKeepATombstone) {
    // forti before 0.7 left applied plans next to a bare marker.
    std::string id = plan_comment();
    std::string summary = json::parse(slurp(plan_file(id)))["summary"];
    write(marker(id), json({{"plan_id", id}, {"applied_at", engine::detail::iso8601(now)}}).dump());
    engine::detail::Purged purged = purge(30, now);
    EXPECT_EQ(purged.applied, 1u);
    EXPECT_FALSE(fs::exists(plan_file(id)));
    json tombstone = json::parse(slurp(marker(id)));
    EXPECT_EQ(tombstone["summary"], summary);
    EXPECT_EQ(tombstone["kind"], "plan");
    EXPECT_EQ(apply(id)["error"]["details"]["reason"], "already_applied");
}

// ---- blobs ----

TEST_F(RetentionTest, BlobsOfPurgedPlansGoBlobsOfKeptPlansStay) {
    const std::string feed = "monitor/system/external-resource/dynamic";
    auto body = [](std::size_t first) {
        json entries = json::array();
        for (std::size_t i = first; i < first + 6000; ++i) entries.push_back(std::format("host-{}.blocked.example", i));
        return json{{"commands", json::array({{{"name", "dns-block"}, {"command", "snapshot"}, {"entries", entries}}})}};
    };
    auto plan_action = [&](std::size_t first) {
        transport->reply(200, fake::envelope({{"hostname", "fw01"}}));
        json result = engine::Engine::envelope(
                [&] { return sut->plan({{"operations", {{{"op", "action"}, {"resource", feed}, {"body", body(first)}}}}}); });
        EXPECT_TRUE(result["ok"]) << result.dump().substr(0, 400);
        std::string id = result["data"]["id"];
        return std::pair{id, json::parse(slurp(plan_file(id)))["operations"][0]["body_ref"]["sha256"].get<std::string>()};
    };
    auto [kept, kept_sha] = plan_action(0);
    auto [expiring, expiring_sha] = plan_action(10000);
    // Make the second plan 40 days old: same content, an older id.
    std::string old = old_id(std::chrono::seconds(days(40)), "abcdef");
    json stored = json::parse(slurp(plan_file(expiring)));
    stored["id"] = old;
    stored["digest"] = engine::detail::plan_digest(stored);
    write(plan_file(old), stored.dump());
    fs::remove(plan_file(expiring));
    ASSERT_TRUE(fs::exists(paths.state / "blobs" / (expiring_sha + ".json")));

    purge(30, now);
    EXPECT_FALSE(fs::exists(plan_file(old)));
    EXPECT_FALSE(fs::exists(paths.state / "blobs" / (expiring_sha + ".json")));
    EXPECT_TRUE(fs::exists(paths.state / "blobs" / (kept_sha + ".json")));

    // Applying the kept plan deletes it and then its blob.
    transport->reply(200, fake::envelope({{"hostname", "fw01"}}));
    transport->reply(200, {{"http_method", "POST"}, {"status", "success"}, {"http_status", 200},
                           {"results", json::array({{{"status", "success"}}})}, {"serial", serial}, {"version", "v7.4.8"}});
    ASSERT_TRUE(apply(kept)["ok"]);
    EXPECT_FALSE(fs::exists(plan_file(kept)));
    EXPECT_FALSE(fs::exists(paths.state / "blobs" / (kept_sha + ".json")));
}

// ---- locking ----

TEST_F(RetentionTest, NoPurgeWhileAnApplyHoldsTheLock) {
    std::string old = old_id(std::chrono::seconds(days(40)), "aaaaaa");
    write(plans() / (old + ".json"), "{}");
    {
        engine::detail::ApplyLock lock(paths);   // flock: per open file, so this process conflicts too
        engine::detail::Purged purged = purge(30, now);
        EXPECT_TRUE(purged.skipped);
        EXPECT_TRUE(fs::exists(plans() / (old + ".json")));
        engine::detail::ApplyLock second(paths);   // applies share it
    }
    EXPECT_FALSE(purge(30, now).skipped);
    EXPECT_FALSE(fs::exists(plans() / (old + ".json")));
}

TEST_F(RetentionTest, APurgeDuringAnApplyLeavesItsFilesAlone) {
    make(Mode::guarded);
    std::string id = plan_comment();
    ASSERT_TRUE(approve(id)["ok"]);
    std::string other = plan_comment();
    // While the PUT is in flight, another process purges as if a year had passed.
    std::optional<engine::detail::Purged> during;
    bool plan_there = false, marker_there = false, other_there = false;
    hooked->hook = [&] {
        during = purge(1, now + days(365));
        plan_there = fs::exists(plan_file(id));
        marker_there = fs::exists(marker(id));
        other_there = fs::exists(plan_file(other));
    };
    script_apply();
    json result = apply(id);
    ASSERT_TRUE(result["ok"]) << result.dump();
    ASSERT_TRUE(during);
    EXPECT_TRUE(during->skipped);
    EXPECT_TRUE(plan_there);
    EXPECT_TRUE(marker_there);
    EXPECT_TRUE(other_there);
    hooked->hook = nullptr;
    // Afterwards the purge runs: the applied plan's marker is fresh and stays.
    EXPECT_FALSE(purge(30, now).skipped);
    EXPECT_TRUE(fs::exists(marker(id)));
    EXPECT_TRUE(fs::exists(plan_file(other)));
    EXPECT_EQ(fs::status(plans() / ".lock").permissions() & fs::perms::all, fs::perms::owner_read | fs::perms::owner_write);
}

// ---- the setting ----

TEST(PlanRetentionSetting, ConfigJsonTakesWholeDaysFromOne) {
    auto load = [](json value) {
        return engine::ProfileSet::from_json({{"version", 1}, {"profiles", json::object()}, {"plan_retention_days", value}});
    };
    EXPECT_EQ(engine::ProfileSet::from_json({{"version", 1}}).retention_days(), 30u);
    EXPECT_FALSE(engine::ProfileSet::from_json({{"version", 1}}).plan_retention_days);
    EXPECT_EQ(load(1).retention_days(), 1u);
    EXPECT_EQ(load(30).retention_days(), 30u);
    EXPECT_EQ(load(3650).retention_days(), 3650u);
    for (const json& bad: {json(0), json(-1), json(1.5), json::parse("30.0"), json(3651), json("30"), json(true), json(nullptr),
                           json::array({30})}) {
        try {
            (void) load(bad);
            ADD_FAILURE() << "accepted " << bad.dump();
        } catch (const engine::Failure& failure) {
            EXPECT_EQ(failure.code(), engine::Code::config) << bad.dump();
            EXPECT_NE(std::string(failure.what()).find("plan_retention_days"), std::string::npos);
            EXPECT_NE(std::string(failure.what()).find("from 1 to 3650"), std::string::npos) << failure.what();
        }
    }
    // Kept as written; absent stays absent.
    EXPECT_EQ(load(7).to_json()["plan_retention_days"], 7);
    EXPECT_FALSE(engine::ProfileSet::from_json({{"version", 1}}).to_json().contains("plan_retention_days"));
}

TEST(PlanRetentionSetting, PlanIdsCarryTheirCreationTime) {
    auto time = engine::detail::parse_iso8601("2026-10-18T09:30:12Z");
    ASSERT_TRUE(time);
    EXPECT_EQ(engine::detail::plan_id_time("20261018-093012-a1b2c3"), time);
    EXPECT_EQ(engine::detail::plan_id_time(engine::detail::new_plan_id(*time)), time);
    EXPECT_FALSE(engine::detail::plan_id_time("handwritten-plan"));
    EXPECT_FALSE(engine::detail::plan_id_time("2026101x-093012-a1b2c3"));
}
