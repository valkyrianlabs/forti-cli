// forti history: the audit log for people. Most tests write audit.jsonl lines by hand (current and
// older shapes, refusals, malformed lines); one runs real applies through the engine first.

#include <cli_harness.hpp>

#include <cstdlib>
#include <ctime>
#include <format>
#include <fstream>
#include <sstream>

using namespace forti;
using json = nlohmann::json;
namespace fs = std::filesystem;

namespace {

    struct HistoryCli : fake::Cli {
        std::string saved_tz;
        bool had_tz = false;

        // Local time is UTC here, so "12:05:09Z" prints as 12:05.
        void SetUp() override {
            if (const char* tz = std::getenv("TZ")) {
                had_tz = true;
                saved_tz = tz;
            }
            ::setenv("TZ", "UTC", 1);
            ::tzset();
        }
        void TearDown() override {
            if (had_tz) ::setenv("TZ", saved_tz.c_str(), 1);
            else ::unsetenv("TZ");
            ::tzset();
        }

        fs::path log() const { return paths.state / "audit.jsonl"; }

        void write_log(const std::vector<std::string>& lines) {
            fs::create_directories(paths.state);
            std::ofstream out(log());
            for (const auto& line: lines) out << line << "\n";
        }

        static json applied(const std::string& time, const std::string& profile, const std::string& id, json extra = json::object()) {
            json event = {{"event", "apply"}, {"time", time}, {"plan_id", id}, {"profile", profile}, {"host", profile + ".test"},
                          {"serial", "FGT60FTK00000000"}, {"risk", "low"}, {"mode", "autonomous"}, {"outcome", "ok"},
                          {"digest", "d"}, {"rollback_plan", id + "-rb"},
                          {"summary", "1 operation on " + profile + " (" + profile + ".test): 1 update; risk low"},
                          {"operations", json::array({{{"index", 0}, {"op", "update"}, {"resource", "firewall/address"},
                                                       {"key", "web"}, {"status", "verified"},
                                                       {"attributes", json::array({"comment"})}}})}};
            event.update(extra);
            return event;
        }

        static json refused(const std::string& time, const std::string& code, const std::string& reason) {
            json event = {{"event", "apply"}, {"time", time}, {"plan_id", "20261016-120000-0000aa"}, {"profile", "lab"},
                          {"mode", "read-only"}, {"outcome", code}, {"summary", "1 operation on lab (lab.test): 1 update; risk low"},
                          {"error", {{"code", code}, {"message", "refused"}}}};
            if (!reason.empty()) event["error"]["reason"] = reason;
            return event;
        }

        std::vector<std::string> lines() const {
            std::vector<std::string> out;
            std::istringstream in(this->out.str());
            for (std::string line; std::getline(in, line);) out.push_back(line);
            return out;
        }
    };

    std::string dump(const json& value) { return value.dump(); }

}  // namespace

TEST_F(HistoryCli, MissingLogSaysSoAndSucceeds) {
    ASSERT_EQ(run({"history"}), 0) << err.str();
    EXPECT_EQ(out.str(), "No changes recorded yet.\n");
    ASSERT_EQ(run({"--json", "history"}), 0);
    json envelope = json_out();
    EXPECT_TRUE(envelope["ok"]);
    EXPECT_EQ(envelope["data"], json::array());
    // An empty file is the same.
    write_log({});
    ASSERT_EQ(run({"history"}), 0);
    EXPECT_EQ(out.str(), "No changes recorded yet.\n");
    EXPECT_EQ(err.str(), "");
}

TEST_F(HistoryCli, ShowsEveryProfileAndFiltersByOne) {
    // No config.json at all, several profiles in the log: history never needs a profile.
    write_log({dump(applied("2026-10-16T12:05:09Z", "lab", "20261016-120509-a1b2c3")),
               dump(applied("2026-10-16T13:00:00Z", "prod", "20261016-130000-d4e5f6",
                            {{"mode", "guarded"}, {"approved_by", "cli:alice"}, {"approved_at", "2026-10-16T12:59:00Z"}}))});
    ASSERT_FALSE(fs::exists(paths.config_file()));
    ASSERT_EQ(run({"history"}), 0) << err.str();
    auto rows = lines();
    ASSERT_EQ(rows.size(), 3u) << out.str();
    EXPECT_NE(rows[0].find("when"), std::string::npos);
    EXPECT_NE(rows[0].find("change"), std::string::npos);
    // Newest last.
    EXPECT_NE(rows[1].find("2026-10-16 12:05  lab "), std::string::npos) << rows[1];
    EXPECT_NE(rows[1].find("applied"), std::string::npos);
    EXPECT_NE(rows[1].find("a1b2c3"), std::string::npos);
    EXPECT_NE(rows[1].find("autonomous"), std::string::npos);
    EXPECT_NE(rows[1].find("update firewall/address web (comment)"), std::string::npos) << rows[1];
    EXPECT_NE(rows[2].find("prod"), std::string::npos);
    EXPECT_NE(rows[2].find("approved by cli:alice"), std::string::npos) << rows[2];

    ASSERT_EQ(run({"history", "-p", "prod"}), 0) << err.str();
    rows = lines();
    ASSERT_EQ(rows.size(), 2u) << out.str();
    EXPECT_NE(rows[1].find("prod"), std::string::npos);
    ASSERT_EQ(run({"history", "--profile", "nowhere"}), 0);
    EXPECT_EQ(out.str(), "No changes recorded for profile nowhere.\n");
}

TEST_F(HistoryCli, RefusalsAreHiddenUnlessAll) {
    write_log({dump(refused("2026-10-16T10:00:00Z", "policy_denied", "read_only")),
               dump(refused("2026-10-16T10:01:00Z", "approval_required", "missing")),
               dump(refused("2026-10-16T10:02:00Z", "stale_plan", "before_changed")),
               dump(refused("2026-10-16T10:03:00Z", "policy_denied", "already_applied")),
               dump(refused("2026-10-16T10:04:00Z", "policy_denied", "tampered")),   // never hidden
               dump(applied("2026-10-16T10:05:00Z", "lab", "20261016-100500-a1b2c3"))});
    ASSERT_EQ(run({"history"}), 0) << err.str();
    auto rows = lines();
    ASSERT_EQ(rows.size(), 3u) << out.str();
    EXPECT_NE(rows[1].find("refused: tampered"), std::string::npos) << rows[1];
    EXPECT_NE(rows[2].find("applied"), std::string::npos);
    EXPECT_NE(err.str().find("4 refused attempts hidden: --all"), std::string::npos) << err.str();

    ASSERT_EQ(run({"history", "--all"}), 0);
    rows = lines();
    ASSERT_EQ(rows.size(), 7u) << out.str();
    EXPECT_NE(rows[1].find("refused: read-only"), std::string::npos) << rows[1];
    EXPECT_NE(rows[2].find("needs approval"), std::string::npos) << rows[2];
    EXPECT_NE(rows[3].find("stale"), std::string::npos) << rows[3];
    EXPECT_NE(rows[4].find("refused: already applied"), std::string::npos) << rows[4];
    EXPECT_EQ(err.str(), "");

    ASSERT_EQ(run({"--json", "history"}), 0);
    EXPECT_EQ(json_out()["meta"]["hidden"], 4);
    EXPECT_EQ(json_out()["data"].size(), 2u);
}

TEST_F(HistoryCli, OldLinesWithoutTheNewFields) {
    // Up to 0.3.1: no summary, actor, approved_by or approved_at; the approve event names the approver.
    json old = applied("2026-10-15T09:00:00Z", "lab", "20261015-090000-0b0b0b", {{"mode", "guarded"}});
    old.erase("summary");
    json approve = {{"event", "approve"}, {"time", "2026-10-15T08:59:00Z"}, {"plan_id", "20261015-090000-0b0b0b"},
                    {"approved_by", "cli:bob"}, {"digest", "d"}, {"mode", "guarded"}, {"outcome", "approved"},
                    {"expires_at", "2026-10-16T08:59:00Z"}};
    // A refusal from before error.reason existed.
    json old_refusal = refused("2026-10-15T09:01:00Z", "policy_denied", "");
    old_refusal["error"]["message"] = "profile lab is read-only: apply is refused";
    old_refusal.erase("summary");
    write_log({dump(approve), dump(old), dump(old_refusal)});
    ASSERT_EQ(run({"history"}), 0) << err.str();
    auto rows = lines();
    ASSERT_EQ(rows.size(), 2u) << out.str();
    EXPECT_NE(rows[1].find("approved by cli:bob"), std::string::npos) << rows[1];
    EXPECT_NE(rows[1].find("update firewall/address web (comment)"), std::string::npos) << rows[1];
    EXPECT_NE(err.str().find("1 refused attempt hidden"), std::string::npos) << err.str();
    ASSERT_EQ(run({"history", "--all"}), 0);
    EXPECT_NE(out.str().find("refused: read-only"), std::string::npos) << out.str();
}

TEST_F(HistoryCli, MalformedLinesAreSkippedAndCounted) {
    write_log({"not json", "[1, 2]", "{\"no\": \"event\"}", dump(applied("2026-10-16T12:00:00Z", "lab", "20261016-120000-a1b2c3")),
               "{\"event\": \"apply\", \"time\""});
    ASSERT_EQ(run({"history"}), 0) << err.str();
    EXPECT_EQ(lines().size(), 2u) << out.str();
    EXPECT_NE(err.str().find("skipped 4 malformed lines in "), std::string::npos) << err.str();
    ASSERT_EQ(run({"--json", "history"}), 0);
    EXPECT_EQ(json_out()["meta"]["malformed"], 4);
}

TEST_F(HistoryCli, JsonIsTheEventsAsStored) {
    json first = applied("2026-10-16T12:00:00Z", "lab", "20261016-120000-a1b2c3");
    json second = applied("2026-10-16T12:30:00Z", "lab", "20261016-123000-c3d4e5",
                          {{"rollback_of", "20261016-120000-a1b2c3"}, {"actor", "mcp:claude-code"}});
    write_log({dump(first), dump(refused("2026-10-16T12:10:00Z", "stale_plan", "before_changed")), dump(second)});
    ASSERT_EQ(run({"--json", "history"}), 0) << err.str();
    json envelope = json_out();
    EXPECT_EQ(envelope["data"], json::array({first, second}));
    EXPECT_EQ(envelope["meta"]["returned"], 2);
    EXPECT_EQ(envelope["meta"]["hidden"], 1);
    EXPECT_EQ(envelope["meta"]["log"], log().string());
    ASSERT_EQ(run({"--json", "history", "--all", "-n", "1"}), 0);
    EXPECT_EQ(json_out()["data"], json::array({second}));
    EXPECT_EQ(json_out()["meta"]["older"], 2);

    // The rollback is marked as one in text.
    ASSERT_EQ(run({"history"}), 0);
    EXPECT_NE(out.str().find("rollback of a1b2c3: update firewall/address web"), std::string::npos) << out.str();
    EXPECT_NE(out.str().find("autonomous, mcp:claude-code"), std::string::npos) << out.str();
}

TEST_F(HistoryCli, LimitKeepsTheNewest) {
    std::vector<std::string> log_lines;
    for (int i = 0; i < 25; ++i)
        log_lines.push_back(dump(applied(std::format("2026-10-16T12:{:02}:00Z", i), "lab", std::format("20261016-12{:02}00-a1b2{:02}", i, i))));
    write_log(log_lines);
    ASSERT_EQ(run({"history"}), 0);
    auto rows = lines();
    ASSERT_EQ(rows.size(), 21u);   // header + the default 20
    EXPECT_NE(rows.back().find("12:24"), std::string::npos);
    EXPECT_NE(rows[1].find("12:05"), std::string::npos);
    EXPECT_NE(err.str().find("5 older entries not shown"), std::string::npos) << err.str();
    ASSERT_EQ(run({"history", "-n", "0"}), 0);
    EXPECT_EQ(lines().size(), 26u);
    EXPECT_EQ(run({"history", "-n", "x"}), engine::exit_code(engine::Code::usage));
    EXPECT_EQ(run({"history", "extra"}), engine::exit_code(engine::Code::usage));
}

TEST_F(HistoryCli, VerboseShowsOperationsRollbackAndApprovals) {
    json approve = {{"event", "approve"}, {"time", "2026-10-16T11:59:00Z"}, {"plan_id", "20261016-120000-a1b2c3"},
                    {"approved_by", "cli:alice"}, {"digest", "d"}, {"mode", "guarded"}, {"outcome", "approved"},
                    {"expires_at", "2026-10-17T11:59:00Z"}};
    json event = applied("2026-10-16T12:00:00Z", "lab", "20261016-120000-a1b2c3",
                         {{"mode", "guarded"}, {"approved_by", "cli:alice"}, {"approved_at", "2026-10-16T11:59:00Z"}});
    write_log({dump(approve), dump(event)});
    ASSERT_EQ(run({"history", "--verbose"}), 0) << err.str();
    std::string text = out.str();
    EXPECT_NE(text.find("approved  plan 20261016-120000-a1b2c3 by cli:alice, expires 2026-10-17 11:59"), std::string::npos) << text;
    EXPECT_NE(text.find("update firewall/address web (comment): verified"), std::string::npos) << text;
    EXPECT_NE(text.find("approved by cli:alice at 2026-10-16 11:59"), std::string::npos) << text;
    EXPECT_NE(text.find("20261016-120000-a1b2c3-rb (undo: forti rollback 20261016-120000-a1b2c3)"), std::string::npos) << text;
    // Without --verbose, approve events are not rows.
    ASSERT_EQ(run({"history"}), 0);
    EXPECT_EQ(lines().size(), 2u) << out.str();
}

TEST_F(HistoryCli, DeviceTextCannotDriveTheTerminal) {
    json event = applied("2026-10-16T12:00:00Z", "lab", "20261016-120000-a1b2c3");
    event["operations"] = json::array();
    event["outcome"] = "partial_failure";
    event["summary"] = "1 operation \x1b[2J\x1b]0;owned\x07 on lab";
    event["error"] = {{"code", "partial_failure"}, {"message", "FortiOS: \x1b[31mred‮"}};
    write_log({dump(event)});
    for (const char* flag: {"--all", "--verbose"}) {
        ASSERT_EQ(run({"history", flag}), 0) << err.str();
        EXPECT_EQ(out.str().find('\x1b'), std::string::npos) << out.str();
        EXPECT_EQ(out.str().find("‮"), std::string::npos) << out.str();
        EXPECT_NE(out.str().find("\\x1b[2J"), std::string::npos) << out.str();
    }
    // --json keeps the text as recorded (JSON escapes it).
    ASSERT_EQ(run({"--json", "history"}), 0);
    EXPECT_EQ(json_out()["data"][0]["summary"], event["summary"]);
}

TEST_F(HistoryCli, RealAppliesThroughTheEngine) {
    // Apply, roll back and an approval refusal, as the engine records them.
    auto engine_options = fake::options(transport, engine::Mode::autonomous);
    engine_options.paths = paths;
    engine::Engine engine(engine_options);
    auto address = [](const std::string& comment) {
        return json::array({{{"name", "LAN"}, {"q_origin_key", "LAN"}, {"subnet", "192.0.2.0 255.255.255.0"},
                             {"type", "ipmask"}, {"comment", comment}, {"color", 0}}});
    };
    json written = {{"status", "success"}, {"http_status", 200}, {"serial", "FGT60FTK00000000"}, {"version", "v7.4.8"},
                    {"vdom", "root"}, {"mkey", "LAN"}};
    transport->reply(200, fake::envelope(address("old")));
    json plan = engine.plan({{"operations", {{{"op", "update"}, {"resource", "firewall/address"}, {"key", "LAN"},
                                              {"set", {{"comment", "new"}}}}}}});
    std::string id = plan["data"]["id"];
    transport->reply(200, fake::envelope(address("old")));
    transport->reply(200, written);
    transport->reply(200, fake::envelope(address("new")));
    json result = engine.apply({{"plan_id", id}});
    ASSERT_TRUE(result["ok"]) << result.dump();
    std::string rollback = result["data"]["rollback"]["plan_id"];
    // Applying it again is refused (hidden by default).
    EXPECT_FALSE(engine::Engine::envelope([&] { return engine.apply({{"plan_id", id}}); })["ok"]);
    transport->reply(200, fake::envelope(address("new")));
    transport->reply(200, written);
    transport->reply(200, fake::envelope(address("old")));
    ASSERT_TRUE(engine.apply({{"plan_id", rollback}})["ok"]);

    ASSERT_EQ(run({"history"}), 0) << err.str();
    auto rows = lines();
    ASSERT_EQ(rows.size(), 3u) << out.str();
    EXPECT_NE(rows[1].find("update firewall/address LAN (comment)"), std::string::npos) << rows[1];
    EXPECT_NE(rows[2].find("rollback of " + id.substr(16)), std::string::npos) << rows[2];
    EXPECT_NE(err.str().find("1 refused attempt hidden"), std::string::npos) << err.str();
    ASSERT_EQ(run({"history", "--verbose"}), 0);
    EXPECT_NE(out.str().find("applied"), std::string::npos);
    EXPECT_NE(out.str().find(", applied 20"), std::string::npos) << out.str();   // the first plan was rolled back
}
