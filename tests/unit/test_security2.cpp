// Orchestrator decisions after the security audit (security-audit.md): read redaction (S-03), the audit
// log check before mutations (S-14), secrets bound to host:port (S-19) and backup retention. Nothing
// here talks to a FortiGate, the login keychain or the real configuration directories.

#include <fake_transport.hpp>

#include "plan_store.hpp"

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <sstream>

#include <sys/stat.h>
#include <unistd.h>

using namespace forti;
using json = nlohmann::json;
using engine::Mode;
namespace fs = std::filesystem;

namespace {

    const std::string serial = "FGT60FTK00000000";

    struct TempDir {
        fs::path path;
        TempDir() {
            std::string pattern = (fs::temp_directory_path() / "forti-security2-test-XXXXXX").string();
            path = ::mkdtemp(pattern.data());
        }
        ~TempDir() { fs::remove_all(path); }
    };

    json written() {
        return {{"status", "success"}, {"http_status", 200}, {"serial", serial}, {"version", "v7.4.8"}, {"vdom", "root"}};
    }

    json address(const std::string& comment) {
        return {{"name", "LAN"}, {"q_origin_key", "LAN"}, {"subnet", "192.0.2.0 255.255.255.0"}, {"type", "ipmask"},
                {"comment", comment}, {"color", 0}};
    }

    // Runs `hook` when a request with `method` passes, then forwards to the scripted transport.
    struct Hooked final : fortiapi::Transport {
        std::shared_ptr<fake::FakeTransport> inner;
        fortiapi::Method method;
        std::function<void()> hook;
        fortiapi::HttpResponse perform(const fortiapi::HttpRequest& request) override {
            if (request.method == method && hook) hook();
            return inner->perform(request);
        }
    };

    struct Fixture : ::testing::Test {
        TempDir dir;
        std::shared_ptr<fake::FakeTransport> transport = std::make_shared<fake::FakeTransport>();
        engine::Paths paths{dir.path / "config", dir.path / "state", dir.path / "cache"};
        engine::Options options;
        std::unique_ptr<engine::Engine> sut;

        Fixture() {
            options = fake::options(transport, Mode::autonomous);
            options.paths = paths;
            sut = std::make_unique<engine::Engine>(options);
        }

        void rebuild() { sut = std::make_unique<engine::Engine>(options); }

        json read(const json& request, engine::Engine::Secrets secrets = engine::Engine::Secrets::redact) {
            return engine::Engine::envelope([&] { return sut->read(request, secrets); });
        }
        json plan(const json& request) { return engine::Engine::envelope([&] { return sut->plan(request); }); }
        json apply(const std::string& id) { return engine::Engine::envelope([&] { return sut->apply({{"plan_id", id}}); }); }

        std::string plan_comment(const std::string& current = "old") {
            transport->reply(200, fake::envelope(json::array({address(current)})));
            json result = plan({{"operations", {{{"op", "update"}, {"resource", "firewall/address"}, {"key", "LAN"},
                                                 {"set", {{"comment", "new"}}}}}}});
            EXPECT_TRUE(result["ok"]) << result.dump();
            return result["data"]["id"];
        }

        std::size_t writes() const {
            std::size_t n = 0;
            for (const auto& request: transport->requests) n += request.method != fortiapi::Method::Get;
            return n;
        }
    };

}  // namespace

// ---- S-03: reads are redacted by default ----

TEST_F(Fixture, ReadsRedactEncValuesAndSensitiveAttributesAtAnyDepth) {
    json tunnel = {{"name", "hq"}, {"psksecret", "ENC c2VjcmV0"}, {"comment", "ENC looks like a secret"},
                   {"remote-gw", "198.51.100.1"}, {"ppk-secret", ""}, {"authpasswd", nullptr},
                   {"peers", {{{"id", 1}, {"password", "ENC xyz"}}, {{"id", 2}, {"note", "plain"}}}},
                   {"md5-keys", {{{"id", 1}, {"key-string", "x"}}}}};
    transport->reply(200, fake::envelope(json::array({tunnel})));
    json result = read({{"resource", "vpn.ipsec/phase1-interface"}});
    ASSERT_TRUE(result["ok"]) << result.dump();
    const json& row = result["data"][0];
    EXPECT_EQ(row["psksecret"], "<redacted>");
    EXPECT_EQ(row["comment"], "<redacted>");       // an ENC value under any name
    EXPECT_EQ(row["remote-gw"], "198.51.100.1");
    EXPECT_EQ(row["ppk-secret"], "");              // unset stays visibly unset
    EXPECT_TRUE(row["authpasswd"].is_null());
    EXPECT_EQ(row["peers"][0]["password"], "<redacted>");
    EXPECT_EQ(row["peers"][1]["note"], "plain");
    EXPECT_EQ(row["md5-keys"], "<redacted>");      // a sensitive table goes wholesale
    EXPECT_EQ(result.dump().find("c2VjcmV0"), std::string::npos);
    EXPECT_EQ(result["meta"]["redacted"],
              json({"/*/comment", "/*/md5-keys", "/*/peers/*/password", "/*/psksecret"}));
}

TEST_F(Fixture, SingletonsAndKeyedReadsAreRedactedToo) {
    transport->reply(200, fake::envelope({{"hostname", "fw01"}, {"private-data-encryption", "disable"},
                                          {"ldap", {{"password", "ENC a"}}}}));
    json result = read({{"resource", "system/global"}});
    EXPECT_EQ(result["data"]["ldap"]["password"], "<redacted>");
    EXPECT_EQ(result["data"]["hostname"], "fw01");
    EXPECT_EQ(result["meta"]["redacted"], json({"/ldap/password"}));

    transport->reply(200, fake::envelope(json::array({{{"name", "admin"}, {"password", "ENC SH2abc"}}})));
    result = read({{"resource", "system/admin"}, {"key", "admin"}});
    EXPECT_EQ(result["data"]["password"], "<redacted>");
    EXPECT_EQ(result["meta"]["redacted"], json({"/password"}));
}

TEST_F(Fixture, NoRequestFieldTurnsRedactionOff) {
    for (json extra: {json{{"reveal", true}}, json{{"secrets", "reveal"}}, json{{"params", {{"reveal", "1"}}}}}) {
        transport->reply(200, fake::envelope(json::array({{{"name", "a"}, {"psksecret", "ENC x"}}})));
        json request = {{"resource", "vpn.ipsec/phase1-interface"}};
        request.update(extra);
        json result = read(request);
        // Unknown fields are refused; a query parameter is just sent to the device.
        if (result["ok"]) { EXPECT_EQ(result["data"][0]["psksecret"], "<redacted>") << extra.dump(); }
        else EXPECT_EQ(result["error"]["code"], "usage") << extra.dump();
        transport->script.clear();
    }
}

TEST_F(Fixture, RevealIsACallerChoiceInCpp) {
    transport->reply(200, fake::envelope(json::array({{{"name", "a"}, {"psksecret", "ENC x"}}})));
    json result = read({{"resource", "vpn.ipsec/phase1-interface"}}, engine::Engine::Secrets::reveal);
    EXPECT_EQ(result["data"][0]["psksecret"], "ENC x");
    EXPECT_TRUE(result["meta"]["revealed"]);
    EXPECT_FALSE(result["meta"].contains("redacted"));
}

TEST_F(Fixture, PlanAndApplyKeepRealValuesForDigests) {
    // An ENC-looking value in the before-state: redaction must not reach the stored plan or the
    // drift check, or every apply of such an object would be stale.
    std::string id = plan_comment("ENC not-really");
    std::ifstream in(paths.state / "plans" / (id + ".json"));
    json stored = json::parse(in);
    EXPECT_EQ(stored["operations"][0]["before"]["comment"], "ENC not-really");
    EXPECT_EQ(stored["operations"][0]["before_digest"], engine::detail::digest_of(address("ENC not-really")));

    transport->reply(200, fake::envelope(json::array({address("ENC not-really")})));
    transport->reply(200, written());
    transport->reply(200, fake::envelope(json::array({address("new")})));
    json result = apply(id);
    EXPECT_TRUE(result["ok"]) << result.dump();
}

// ---- S-19: stored secrets are bound to host:port ----

TEST_F(Fixture, StoredKeyIsNotReleasedToAnotherHost) {
    auto& lab = options.profiles->profiles.at("lab");
    lab.host = "attacker.example";   // another config.json reusing the profile name
    rebuild();
    json result = read({{"resource", "firewall/address"}});
    EXPECT_EQ(result["error"]["code"], "config") << result.dump();
    EXPECT_NE(result["error"]["message"].get<std::string>().find("belongs to fortigate.test:8443"), std::string::npos);
    EXPECT_TRUE(transport->requests.empty());   // nothing was sent anywhere

    lab.host = "fortigate.test";
    lab.port = 443;   // the port is part of the binding
    rebuild();
    EXPECT_EQ(read({{"resource", "firewall/address"}})["error"]["code"], "config");
    EXPECT_TRUE(transport->requests.empty());
}

TEST(SecretBinding, UnboundFileStoreSecretsAreRefused) {
    TempDir dir;
    engine::Paths paths{dir.path / "config", dir.path / "state", dir.path / "cache"};
    auto store = engine::file_secret_store(paths);
    store->put("home/api-key", "k1", "fw.home:443");
    std::ifstream in(paths.config / "credentials" / "home.api-key");
    std::stringstream text;
    text << in.rdbuf();
    EXPECT_EQ(text.str(), "binding fw.home:443\nk1\n");
    engine::SecretRef ref{engine::SecretRef::Source::store, {}, {}};
    EXPECT_EQ(engine::resolve_secret(ref, "home/api-key", *store, "fw.home:443"), "k1");

    // The format before binding: the secret alone.
    { std::ofstream(paths.config / "credentials" / "old.api-key") << "k2\n"; }
    ::chmod((paths.config / "credentials" / "old.api-key").c_str(), 0600);
    EXPECT_EQ(store->get("old/api-key")->binding, "");
    try {
        (void) engine::resolve_secret(ref, "old/api-key", *store, "fw.home:443");
        FAIL();
    } catch (const engine::Failure& failure) {
        EXPECT_EQ(failure.code(), engine::Code::config);
        EXPECT_NE(std::string(failure.what()).find("run forti configure"), std::string::npos);
        EXPECT_EQ(std::string(failure.what()).find("k2"), std::string::npos);
    }
    // env and command sources are not bound.
    EXPECT_EQ(engine::resolve_secret({engine::SecretRef::Source::command, {}, {"printf", "k3"}}, "x", *store, "any:1"), "k3");
}

// ---- S-14: the audit log must be writable before the first mutation ----

TEST_F(Fixture, UnwritableAuditLogRefusesApplyBeforeAnyWrite) {
    std::string id = plan_comment();
    fs::create_directories(paths.state);
    fs::create_directory(paths.state / "audit.jsonl");   // cannot be opened for appending
    transport->reply(200, fake::envelope(json::array({address("old")})));   // drift check
    transport->reply(200, written());
    json result = apply(id);
    EXPECT_EQ(result["error"]["code"], "config") << result.dump();
    EXPECT_EQ(result["error"]["details"]["reason"], "audit_unwritable");
    EXPECT_EQ(writes(), 0u);
    EXPECT_FALSE(fs::exists(paths.state / "plans" / (id + ".applied")));   // can run once the log is fixed
}

TEST_F(Fixture, AuditFailureAfterTheChangesIsReportedNotDropped) {
    if (::geteuid() == 0) GTEST_SKIP() << "root ignores file modes";
    auto hooked = std::make_shared<Hooked>();
    hooked->inner = transport;
    hooked->method = fortiapi::Method::Put;
    hooked->hook = [this] { ::chmod((paths.state / "audit.jsonl").c_str(), 0400); };
    options.transport = [hooked](const fortiapi::Config&) -> std::shared_ptr<fortiapi::Transport> { return hooked; };
    rebuild();
    std::string id = plan_comment();
    transport->reply(200, fake::envelope(json::array({address("old")})));
    transport->reply(200, written());
    transport->reply(200, fake::envelope(json::array({address("new")})));
    json result = apply(id);
    ::chmod((paths.state / "audit.jsonl").c_str(), 0600);
    ASSERT_TRUE(result["ok"]) << result.dump();
    EXPECT_TRUE(result["data"].contains("audit_error")) << result.dump();
}

// ---- backup retention: the 20 most recent configuration backups ----

TEST_F(Fixture, BackupsBeyondTheMostRecentTwentyAreDeleted) {
    fs::path backups = paths.state / "backups";
    fs::create_directories(backups);
    auto now = fs::file_time_type::clock::now();
    for (int i = 0; i < 25; ++i) {
        fs::path file = backups / std::format("20260101-0000{:02}-aaaaaa.conf", i);
        { std::ofstream(file) << "#config-version=old\n"; }
        fs::last_write_time(file, now - std::chrono::hours(100 - i));   // i = 0 is the oldest
    }
    { std::ofstream(backups / "notes.txt") << "not a backup\n"; }

    transport->reply(200, fake::envelope({{"hostname", "fw01"}}));
    json planned = plan({{"operations", {{{"op", "action"}, {"resource", "monitor/system/os/reboot"}, {"body", json::object()}}}}});
    ASSERT_TRUE(planned["ok"]) << planned.dump();
    std::string id = planned["data"]["id"];
    transport->reply(200, fake::envelope({{"hostname", "fw01"}}));
    transport->reply_raw(200, "#config-version=FGT60F-7.4.8\nconfig system global\nend\n");
    transport->reply(200, written());
    transport->reply(200, fake::envelope({{"hostname", "fw01"}}));   // management probe
    json result = apply(id);
    ASSERT_TRUE(result["ok"]) << result.dump();

    std::size_t conf = 0;
    for (const auto& entry: fs::directory_iterator(backups)) conf += entry.path().extension() == ".conf";
    EXPECT_EQ(conf, 20u);
    EXPECT_TRUE(fs::exists(backups / (id + ".conf")));
    EXPECT_FALSE(fs::exists(backups / "20260101-000000-aaaaaa.conf"));   // oldest gone
    EXPECT_FALSE(fs::exists(backups / "20260101-000005-aaaaaa.conf"));
    EXPECT_TRUE(fs::exists(backups / "20260101-000006-aaaaaa.conf"));    // 19 newest old ones kept
    EXPECT_TRUE(fs::exists(backups / "notes.txt"));                      // only .conf files are touched
}

TEST_F(Fixture, TheRedactedPlaceholderCannotBeWrittenBack) {
    json result = plan({{"operations", {{{"op", "update"}, {"resource", "vpn.ipsec/phase1-interface"}, {"key", "hq"},
                                         {"set", {{"psksecret", "<redacted>"}}}}}}});
    EXPECT_EQ(result["error"]["code"], "validation") << result.dump();
    result = plan({{"operations", {{{"op", "create"}, {"resource", "user/local"},
                                    {"object", {{"name", "u"}, {"passwd", "<redacted>"}}}}}}});
    EXPECT_EQ(result["error"]["code"], "validation");
    EXPECT_TRUE(transport->requests.empty());
}
