// plan / approve / apply against the scripted transport. Nothing here talks to a FortiGate.

#include <fake_transport.hpp>

#include <forti/engine/approval.hpp>

#include "plan_store.hpp"
#include "sha256.hpp"

#include <gtest/gtest.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <thread>

#include <sys/stat.h>

using namespace forti;
using json = nlohmann::json;
using engine::Mode;
namespace fs = std::filesystem;

namespace {

    const std::string serial = "FGT60FTK00000000";

    struct TempDir {
        fs::path path;
        TempDir() {
            std::string pattern = (fs::temp_directory_path() / "forti-plan-test-XXXXXX").string();
            path = ::mkdtemp(pattern.data());
        }
        ~TempDir() { fs::remove_all(path); }
    };

    unsigned mode_of(const fs::path& path) {
        struct stat info{};
        ::stat(path.c_str(), &info);
        return info.st_mode & 0777;
    }

    std::string slurp(const fs::path& file) {
        std::ifstream in(file);
        std::stringstream text;
        text << in.rdbuf();
        return text.str();
    }

    json address(const std::string& name, json extra = json::object()) {
        json object = {{"name", name}, {"q_origin_key", name}, {"uuid", "8f0c-" + name}, {"subnet", "192.0.2.0 255.255.255.0"},
                       {"type", "ipmask"}, {"comment", ""}, {"color", 0}};
        object.update(extra);
        return object;
    }

    json missing() { return {{"status", "error"}, {"http_status", 404}, {"serial", serial}, {"version", "v7.4.8"}}; }

    json written(json mkey = nullptr) {
        json body = {{"status", "success"}, {"http_status", 200}, {"serial", serial}, {"version", "v7.4.8"}, {"vdom", "root"}};
        if (!mkey.is_null()) body["mkey"] = mkey;
        return body;
    }

    struct PlanTest : ::testing::Test {
        TempDir dir;
        std::shared_ptr<fake::FakeTransport> transport = std::make_shared<fake::FakeTransport>();
        std::unique_ptr<engine::Engine> sut;
        engine::Paths paths{dir.path / "config", dir.path / "state", dir.path / "cache"};

        void make(Mode mode) {
            auto options = fake::options(transport, mode);
            options.paths = paths;
            sut = std::make_unique<engine::Engine>(options);
        }

        PlanTest() { make(Mode::autonomous); }

        json plan(const json& request) { return engine::Engine::envelope([&] { return sut->plan(request); }); }
        json apply(const std::string& id) { return engine::Engine::envelope([&] { return sut->apply({{"plan_id", id}}); }); }
        json approve(const std::string& id) {
            return engine::Engine::envelope([&] { return engine::approve_plan(*sut, id, "cli:test"); });
        }

        fs::path plan_path(const std::string& id) const { return paths.state / "plans" / (id + ".json"); }
        fs::path approval_path(const std::string& id) const { return paths.state / "approvals" / (id + ".json"); }

        // Plans "set comment" on address LAN (current comment "old").
        std::string plan_comment(const std::string& comment = "new") {
            transport->reply(200, fake::envelope(json::array({address("LAN", {{"comment", "old"}})})));
            json result = plan({{"operations", {{{"op", "update"}, {"resource", "firewall/address"}, {"key", "LAN"},
                                                 {"set", {{"comment", comment}}}}}}});
            EXPECT_TRUE(result["ok"]) << result.dump();
            return result["data"]["id"];
        }

        // Scripts a successful apply of plan_comment(): re-read, PUT, verify.
        void script_comment_apply(const std::string& comment = "new") {
            transport->reply(200, fake::envelope(json::array({address("LAN", {{"comment", "old"}})})));
            transport->reply(200, written("LAN"));
            transport->reply(200, fake::envelope(json::array({address("LAN", {{"comment", comment}})})));
        }

        std::vector<json> audit_lines() const {
            std::vector<json> out;
            std::istringstream in(slurp(paths.state / "audit.jsonl"));
            for (std::string line; std::getline(in, line);) out.push_back(json::parse(line));
            return out;
        }

        std::size_t writes() const {
            std::size_t n = 0;
            for (const auto& request: transport->requests) n += request.method != fortiapi::Method::Get;
            return n;
        }
    };

    const std::string backup_text = "#config-version=FGT60F-7.4.8-FW-build2795-250523:opmode=0:vdom=0\n"
                                    "config system global\n    set hostname \"fw1\"\nend\n";

    std::string digest_hex(std::string_view text) { return engine::detail::hex(engine::detail::sha256(text)); }

}  // namespace

// ---- SHA-256 (FIPS 180-4 / NIST CAVP vectors) ----

TEST(Sha256, NistVectors) {
    EXPECT_EQ(digest_hex(""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    EXPECT_EQ(digest_hex("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    EXPECT_EQ(digest_hex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
              "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    EXPECT_EQ(digest_hex("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrst"
                         "nopqrstu"),
              "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1");
    EXPECT_EQ(digest_hex(std::string(1000000, 'a')), "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
}

TEST(Sha256, IncrementalUpdatesMatchOneShot) {
    std::string text(1000, 'x');
    for (std::size_t i = 0; i < text.size(); ++i) text[i] = static_cast<char>('a' + i % 26);
    for (std::size_t split: {0u, 1u, 55u, 56u, 63u, 64u, 65u, 127u, 999u}) {
        engine::detail::Sha256 hash;
        hash.update(std::string_view(text).substr(0, split)).update(std::string_view(text).substr(split));
        auto digest = hash.finish();
        EXPECT_EQ(engine::detail::hex(digest), digest_hex(text)) << split;
    }
}

TEST(Redaction, SensitiveNamesAtAnyDepth) {
    using engine::detail::sensitive_name;
    for (auto name: {"password", "passwd", "psksecret", "private-key", "key-material", "auth-pwd", "ppk-secret", "key",
                     "md5-key", "pre-shared-key", "sae-password", "token"})
        EXPECT_TRUE(sensitive_name(name)) << name;
    for (auto name: {"name", "subnet", "comment", "keylife", "ping-server", "member", "pinned"})
        EXPECT_FALSE(sensitive_name(name)) << name;
    json redacted = engine::detail::redact({{"name", "u"}, {"members", {{{"name", "x"}, {"psksecret", "s3cret"}}}},
                                            {"diff", {{{"attribute", "passwd"}, {"before", "a"}, {"after", "b"}}}}});
    EXPECT_EQ(redacted["name"], "u");
    EXPECT_EQ(redacted["members"][0]["psksecret"], "<redacted>");
    EXPECT_EQ(redacted["diff"][0]["after"], "<redacted>");
    EXPECT_EQ(redacted.dump().find("s3cret"), std::string::npos);
    json schema = {{"children", {{"comment", {{"type", "string"}}}, {"secret-x", {{"type", "password"}}},
                                 {"peer", {{"children", {{"opaque", {{"type", "password"}}}}}}}}}};
    auto extra = engine::detail::sensitive_from_schema(schema);
    EXPECT_TRUE(extra.contains("opaque"));
    EXPECT_EQ(engine::detail::redact({{"opaque", "v"}}, extra)["opaque"], "<redacted>");
}

// ---- plan ----

TEST_F(PlanTest, PlanOnlyReadsAndStoresAPrivateDigestBoundPlan) {
    transport->reply(200, fake::envelope(json::array({address("LAN", {{"comment", "old"}, {"color", 3}})})));
    transport->reply(404, missing());
    json result = plan({{"operations", {{{"op", "update"}, {"resource", "firewall/address"}, {"key", "LAN"},
                                         {"set", {{"comment", "new"}}}, {"clear", {"color"}}},
                                        {{"op", "create"}, {"resource", "firewall/address"},
                                         {"object", {{"name", "web"}, {"subnet", "192.0.2.10 255.255.255.255"}}}}}}});
    ASSERT_TRUE(result["ok"]) << result.dump();
    EXPECT_EQ(writes(), 0u);
    const json& data = result["data"];
    std::string id = data["id"];
    EXPECT_EQ(data["risk"], "low");
    EXPECT_EQ(data["digest"].get<std::string>().size(), 64u);
    EXPECT_EQ(data["apply"], "forti apply " + id);
    const json& diff = data["operations"][0]["diff"];
    ASSERT_EQ(diff.size(), 2u);
    EXPECT_EQ(diff[0], json({{"attribute", "comment"}, {"change", "set"}, {"before", "old"}, {"after", "new"}}));
    EXPECT_EQ(diff[1]["change"], "clear");
    EXPECT_EQ(diff[1]["after"], 0);   // the SDK's reset value
    EXPECT_EQ(data["operations"][0]["wire"]["method"], "PUT");
    EXPECT_EQ(data["operations"][0]["wire"]["body"], json({{"comment", "new"}, {"color", 0}}));
    EXPECT_EQ(data["operations"][1]["wire"]["method"], "POST");

    EXPECT_EQ(mode_of(paths.state / "plans"), 0700u);
    EXPECT_EQ(mode_of(plan_path(id)), 0600u);
    json stored = engine::detail::load_plan(paths, id);
    EXPECT_EQ(stored["digest"], data["digest"]);
    EXPECT_EQ(stored["device"]["serial"], serial);
}

TEST_F(PlanTest, DigestIsStableAcrossPlansAndKeyOrder) {
    auto request = [](json set) {
        return json{{"operations", {{{"op", "update"}, {"resource", "firewall/address"}, {"key", "LAN"}, {"set", set}}}}};
    };
    json set_a = json::parse(R"({"comment": "x", "color": 5})");
    json set_b = json::parse(R"({"color": 5, "comment": "x"})");
    transport->reply(200, fake::envelope(json::array({address("LAN")})));
    json first = plan(request(set_a));
    transport->reply(200, fake::envelope(json::array({address("LAN")})));
    json second = plan(request(set_b));
    ASSERT_TRUE(first["ok"] && second["ok"]);
    EXPECT_NE(first["data"]["id"], second["data"]["id"]);
    EXPECT_EQ(first["data"]["digest"], second["data"]["digest"]);
    // A different before-state is a different plan.
    transport->reply(200, fake::envelope(json::array({address("LAN", {{"comment", "changed"}})})));
    EXPECT_NE(plan(request(set_a))["data"]["digest"], first["data"]["digest"]);
}

TEST_F(PlanTest, ValidationHappensAtPlanTime) {
    transport->reply(200, fake::envelope(json::array({address("LAN")})));
    json result = plan({{"operations", {{{"op", "update"}, {"resource", "firewall/address"}, {"key", "LAN"}, {"set", {{"colour", 1}}}}}}});
    EXPECT_EQ(result["error"]["code"], "validation");
    transport->reply(200, fake::envelope(json::array({address("web")})));
    result = plan({{"operations", {{{"op", "create"}, {"resource", "firewall/address"}, {"object", {{"name", "web"}}}}}}});
    EXPECT_EQ(result["error"]["code"], "validation");   // already exists
    transport->reply(200, fake::envelope(json::array({address("LAN")})));
    result = plan({{"operations", {{{"op", "update"}, {"resource", "firewall/address"}, {"key", "LAN"}, {"set", {{"name", "WAN"}}}}}}});
    EXPECT_EQ(result["error"]["code"], "validation");   // renames are refused
    result = plan({{"operations", {{{"op", "delete"}, {"resource", "system/global"}}}}});
    EXPECT_EQ(result["error"]["code"], "usage");
    result = plan({{"operations", {{{"op", "update"}, {"resource", "firewall/address"}, {"key", "a"}, {"set", {{"comment", "1"}}}},
                                   {{"op", "delete"}, {"resource", "firewall/address"}, {"key", "a"}}}}});
    EXPECT_EQ(result["error"]["code"], "usage");   // one operation per object
    EXPECT_EQ(writes(), 0u);
}

TEST_F(PlanTest, TableAttributesShowWholesaleReplacement) {
    transport->reply(200, fake::envelope(json::array({{{"name", "grp"}, {"member", {{{"name", "a"}, {"q_origin_key", "a"}},
                                                                                    {{"name", "b"}, {"q_origin_key", "b"}}}}}})));
    json result = plan({{"operations", {{{"op", "update"}, {"resource", "firewall/addrgrp"}, {"key", "grp"},
                                         {"set", {{"member", {{{"name", "a"}}, {{"name", "c"}}}}}}}}}});
    ASSERT_TRUE(result["ok"]) << result.dump();
    const json& table = result["data"]["operations"][0]["diff"][0]["table"];
    EXPECT_TRUE(table["replaced"]);
    EXPECT_EQ(table["added"], json({"c"}));
    EXPECT_EQ(table["removed"], json({"b"}));
    EXPECT_EQ(table["result"], json({"a", "c"}));
}

TEST_F(PlanTest, SensitiveValuesAreRedactedEverywhereButTheStoredPlan) {
    transport->reply(200, fake::envelope(json::array({{{"name", "alice"}, {"type", "password"}, {"passwd", "ENC old"}}})));
    json result = plan({{"operations", {{{"op", "update"}, {"resource", "user/local"}, {"key", "alice"},
                                         {"set", {{"passwd", "hunter2-secret"}}}}}}});
    ASSERT_TRUE(result["ok"]) << result.dump();
    EXPECT_EQ(result.dump().find("hunter2-secret"), std::string::npos);
    EXPECT_EQ(result["data"]["operations"][0]["diff"][0]["after"], "<redacted>");
    EXPECT_EQ(result["data"]["operations"][0]["wire"]["body"]["passwd"], "<redacted>");
    std::string id = result["data"]["id"];
    EXPECT_NE(slurp(plan_path(id)).find("hunter2-secret"), std::string::npos);   // apply needs it
    json shown = engine::Engine::envelope([&] { return engine::show_plan(*sut, id); });
    EXPECT_EQ(shown.dump().find("hunter2-secret"), std::string::npos);
    EXPECT_EQ(shown.dump().find("ENC old"), std::string::npos);

    transport->reply(200, fake::envelope(json::array({{{"name", "alice"}, {"type", "password"}, {"passwd", "ENC old"}}})));
    transport->reply(200, written("alice"));
    transport->reply(200, fake::envelope(json::array({{{"name", "alice"}, {"type", "password"}, {"passwd", "ENC new"}}})));
    json applied = apply(id);
    EXPECT_EQ(applied["error"].is_null() ? "" : applied["error"]["code"], "");
    EXPECT_EQ(applied.dump().find("hunter2-secret"), std::string::npos);
    std::string audit = slurp(paths.state / "audit.jsonl");
    EXPECT_EQ(audit.find("hunter2-secret"), std::string::npos);
    EXPECT_NE(audit.find("passwd"), std::string::npos);   // attribute names only
    // The rollback plan restores the old (encrypted) value; its display is redacted too.
    std::string rollback = applied["data"]["rollback"]["plan_id"];
    EXPECT_EQ(engine::Engine::envelope([&] { return engine::show_plan(*sut, rollback); }).dump().find("ENC"), std::string::npos);
}

// ---- modes and approvals ----

TEST_F(PlanTest, ReadOnlyProfilesPlanButNeverApply) {
    make(Mode::read_only);
    std::string id = plan_comment();
    json result = apply(id);
    EXPECT_EQ(result["error"]["code"], "policy_denied");
    EXPECT_EQ(result["error"]["details"]["reason"], "read_only");
    EXPECT_EQ(writes(), 0u);
    auto lines = audit_lines();
    ASSERT_FALSE(lines.empty());
    EXPECT_EQ(lines.back()["event"], "apply");
    EXPECT_EQ(lines.back()["outcome"], "policy_denied");
    EXPECT_EQ(approve(id)["error"]["code"], "policy_denied");
    EXPECT_EQ(audit_lines().back()["event"], "approve");
    EXPECT_EQ(mode_of(paths.state / "audit.jsonl"), 0600u);
}

TEST_F(PlanTest, GuardedApplyNeedsASingleUseApproval) {
    make(Mode::guarded);
    std::string id = plan_comment();
    json result = apply(id);
    EXPECT_EQ(result["error"]["code"], "approval_required");
    EXPECT_EQ(result["error"]["details"]["reason"], "missing");
    EXPECT_EQ(result["error"]["details"]["approve_command"], "forti plan approve " + id);
    EXPECT_EQ(result["error"]["details"]["plan_id"], id);

    json approval = approve(id);
    ASSERT_TRUE(approval["ok"]) << approval.dump();
    EXPECT_EQ(approval["data"]["approved_by"], "cli:test");
    json record = json::parse(slurp(approval_path(id)));
    EXPECT_EQ(record["digest"], engine::detail::load_plan(paths, id)["digest"]);
    EXPECT_EQ(mode_of(approval_path(id)), 0600u);
    std::string copy = slurp(approval_path(id));

    script_comment_apply();
    result = apply(id);
    ASSERT_TRUE(result["ok"]) << result.dump();
    EXPECT_FALSE(fs::exists(approval_path(id)));

    // Reuse: neither the same plan nor a restored copy of the approval runs again.
    std::ofstream(approval_path(id)) << copy;
    std::size_t before = transport->requests.size();
    result = apply(id);
    EXPECT_EQ(result["error"]["code"], "policy_denied");
    EXPECT_EQ(result["error"]["details"]["reason"], "already_applied");
    EXPECT_EQ(approve(id)["error"]["code"], "policy_denied");
    EXPECT_EQ(transport->requests.size(), before);
}

TEST_F(PlanTest, ExpiredAndForeignApprovalsAreRefused) {
    make(Mode::guarded);
    std::string id = plan_comment();
    ASSERT_TRUE(approve(id)["ok"]);
    json record = json::parse(slurp(approval_path(id)));

    json expired = record;
    expired["expires_at"] = "2020-01-01T00:00:00Z";
    std::ofstream(approval_path(id)) << expired.dump();
    json result = apply(id);
    EXPECT_EQ(result["error"]["code"], "approval_required");
    EXPECT_EQ(result["error"]["details"]["reason"], "expired");

    json foreign = record;
    foreign["digest"] = std::string(64, '0');
    std::ofstream(approval_path(id)) << foreign.dump();
    result = apply(id);
    EXPECT_EQ(result["error"]["details"]["reason"], "digest_mismatch");

    // An approval of another plan's digest, renamed into place, does not carry over.
    std::string other = plan_comment("other");
    ASSERT_TRUE(approve(other)["ok"]);
    json moved = json::parse(slurp(approval_path(other)));
    moved["plan_id"] = id;
    std::ofstream(approval_path(id)) << moved.dump();
    EXPECT_EQ(apply(id)["error"]["details"]["reason"], "digest_mismatch");
    EXPECT_EQ(writes(), 0u);
}

TEST_F(PlanTest, AutonomousNeedsNoApproval) {
    std::string id = plan_comment();
    json approval = approve(id);
    ASSERT_TRUE(approval["ok"]);
    EXPECT_FALSE(approval["data"]["required"]);
    EXPECT_FALSE(fs::exists(approval_path(id)));
    script_comment_apply();
    json result = apply(id);
    ASSERT_TRUE(result["ok"]) << result.dump();
    EXPECT_EQ(result["data"]["operations"][0]["status"], "verified");
    EXPECT_EQ(audit_lines().back()["outcome"], "ok");
}

// ---- integrity and freshness ----

TEST_F(PlanTest, TamperedPlansAreRefused) {
    make(Mode::guarded);
    std::string id = plan_comment();
    ASSERT_TRUE(approve(id)["ok"]);
    json stored = json::parse(slurp(plan_path(id)));

    json edited = stored;
    edited["operations"][0]["set"]["comment"] = "evil";
    std::ofstream(plan_path(id)) << edited.dump();
    json result = apply(id);
    EXPECT_EQ(result["error"]["code"], "policy_denied");
    EXPECT_EQ(result["error"]["details"]["reason"], "tampered");

    // Re-sealing the digest does not help: the approval names the original digest.
    edited["digest"] = engine::detail::plan_digest(edited);
    std::ofstream(plan_path(id)) << edited.dump();
    result = apply(id);
    EXPECT_EQ(result["error"]["code"], "approval_required");
    EXPECT_EQ(result["error"]["details"]["reason"], "digest_mismatch");

    // Downgrading the risk tier is caught against the catalog.
    edited = stored;
    edited["operations"][0]["risk"] = "critical";
    edited["digest"] = engine::detail::plan_digest(edited);
    std::ofstream(plan_path(id)) << edited.dump();
    EXPECT_EQ(apply(id)["error"]["details"]["reason"], "tampered");
    EXPECT_EQ(writes(), 0u);
}

TEST_F(PlanTest, StalePlansAreRefusedBeforeAnyWrite) {
    std::string id = plan_comment();
    transport->reply(200, fake::envelope(json::array({address("LAN", {{"comment", "someone else"}})})));
    json result = apply(id);
    EXPECT_EQ(result["error"]["code"], "stale_plan");
    EXPECT_EQ(result["error"]["details"]["reason"], "before_changed");
    EXPECT_EQ(result["error"]["details"]["key"], "LAN");   // an object name, not a secret
    EXPECT_EQ(writes(), 0u);
    // Not consumed: nothing ran, so the plan is not marked applied.
    EXPECT_FALSE(engine::detail::plan_applied(paths, id));
}

TEST_F(PlanTest, AnotherDeviceSerialIsRefused) {
    std::string id = plan_comment();
    json body = fake::envelope(json::array({address("LAN", {{"comment", "old"}})}));
    body["serial"] = "FGT60FTK99999999";
    transport->reply(200, body);
    json result = apply(id);
    EXPECT_EQ(result["error"]["code"], "stale_plan");
    EXPECT_EQ(result["error"]["details"]["reason"], "device_serial");
    EXPECT_EQ(writes(), 0u);
}

// ---- execution ----

TEST_F(PlanTest, WireBodiesMatchThePlanExactly) {
    transport->reply(404, missing());
    transport->reply(200, fake::envelope(json::array({address("LAN", {{"comment", "old"}, {"color", 3}})})));
    transport->reply(200, fake::envelope(json::array({address("old")})));
    json planned = plan({{"operations", {{{"op", "create"}, {"resource", "firewall/address"},
                                          {"object", {{"name", "web"}, {"subnet", "192.0.2.10 255.255.255.255"}, {"comment", "w"}}}},
                                         {{"op", "update"}, {"resource", "firewall/address"}, {"key", "LAN"},
                                          {"set", {{"comment", "new"}}}, {"clear", {"color"}}},
                                         {{"op", "delete"}, {"resource", "firewall/address"}, {"key", "old"}}}}});
    ASSERT_TRUE(planned["ok"]) << planned.dump();
    std::string id = planned["data"]["id"];
    json stored = engine::detail::load_plan(paths, id);

    transport->requests.clear();
    transport->reply(404, missing());
    transport->reply(200, fake::envelope(json::array({address("LAN", {{"comment", "old"}, {"color", 3}})})));
    transport->reply(200, fake::envelope(json::array({address("old")})));
    transport->reply(200, written("web"));
    transport->reply(200, fake::envelope(json::array({address("web", {{"subnet", "192.0.2.10 255.255.255.255"}, {"comment", "w"}})})));
    transport->reply(200, written("LAN"));
    transport->reply(200, fake::envelope(json::array({address("LAN", {{"comment", "new"}, {"color", 0}})})));
    transport->reply(200, written("old"));
    transport->reply(404, missing());
    json result = apply(id);
    ASSERT_TRUE(result["ok"]) << result.dump();
    for (const auto& op: result["data"]["operations"]) { EXPECT_EQ(op["status"], "verified") << op.dump(); }

    std::vector<fortiapi::HttpRequest> sent;
    for (const auto& request: transport->requests) if (request.method != fortiapi::Method::Get) sent.push_back(request);
    ASSERT_EQ(sent.size(), 3u);
    EXPECT_EQ(sent[0].method, fortiapi::Method::Post);
    EXPECT_EQ(sent[0].body, stored["operations"][0]["wire"]["body"].dump());
    EXPECT_EQ(sent[1].method, fortiapi::Method::Put);
    EXPECT_EQ(sent[1].body, stored["operations"][1]["wire"]["body"].dump());
    EXPECT_EQ(sent[1].url, "https://fortigate.test:8443/api/v2/cmdb/firewall/address/LAN");
    EXPECT_EQ(sent[2].method, fortiapi::Method::Delete);
    EXPECT_TRUE(sent[2].body.empty());
    EXPECT_EQ(sent[2].url, "https://fortigate.test:8443/api/v2/cmdb/firewall/address/old");
}

TEST_F(PlanTest, ApiErrorStopsWithPartialFailure) {
    transport->reply(200, fake::envelope(json::array({address("a")})));
    transport->reply(200, fake::envelope(json::array({address("b")})));
    transport->reply(200, fake::envelope(json::array({address("c")})));
    json planned = plan({{"operations", {{{"op", "update"}, {"resource", "firewall/address"}, {"key", "a"}, {"set", {{"comment", "1"}}}},
                                         {{"op", "update"}, {"resource", "firewall/address"}, {"key", "b"}, {"set", {{"comment", "2"}}}},
                                         {{"op", "update"}, {"resource", "firewall/address"}, {"key", "c"}, {"set", {{"comment", "3"}}}}}}});
    ASSERT_TRUE(planned["ok"]) << planned.dump();
    std::string id = planned["data"]["id"];
    transport->reply(200, fake::envelope(json::array({address("a")})));
    transport->reply(200, fake::envelope(json::array({address("b")})));
    transport->reply(200, fake::envelope(json::array({address("c")})));
    transport->reply(200, written("a"));
    transport->reply(200, fake::envelope(json::array({address("a", {{"comment", "1"}})})));
    transport->reply(500, {{"status", "error"}, {"http_status", 500}, {"error", -651}, {"cli_error", {"invalid comment"}}});
    transport->reply(200, fake::envelope(json::array({address("b")})));   // re-read after the failure: unchanged
    json result = apply(id);
    EXPECT_EQ(result["error"]["code"], "partial_failure") << result.dump();
    const json& ops = result["error"]["details"]["operations"];
    EXPECT_EQ(ops[0]["status"], "verified");
    EXPECT_EQ(ops[1]["status"], "failed");
    EXPECT_EQ(ops[1]["error"]["details"]["fortios_error"], -651);
    EXPECT_FALSE(ops[1].contains("changed_after_failure"));
    EXPECT_EQ(ops[2]["status"], "not_attempted");
    // Object names are not secrets: the record of a stopped apply says which objects it touched.
    EXPECT_EQ(ops[0]["key"], "a");
    EXPECT_EQ(ops[1]["key"], "b");
    EXPECT_EQ(ops[2]["key"], "c");
    EXPECT_EQ(writes(), 2u);
    // The rollback undoes only what changed: operation 1.
    std::string rollback = result["error"]["details"]["rollback"]["plan_id"];
    json undo = engine::detail::load_plan(paths, rollback);
    ASSERT_EQ(undo["operations"].size(), 1u);
    EXPECT_EQ(undo["operations"][0]["key"], "a");
    EXPECT_EQ(undo["operations"][0]["set"], json({{"comment", ""}}));
    EXPECT_EQ(audit_lines().back()["outcome"], "partial_failure");
}

TEST_F(PlanTest, FailedCreateThatLeftTheObjectBehindIsReported) {
    transport->reply(404, missing());
    json planned = plan({{"operations", {{{"op", "create"}, {"resource", "firewall/address"}, {"object", {{"name", "web"}, {"comment", "x"}}}}}}});
    std::string id = planned["data"]["id"];
    transport->reply(404, missing());
    transport->reply(500, {{"status", "error"}, {"http_status", 500}, {"error", -1}});
    transport->reply(200, fake::envelope(json::array({address("web")})));
    json result = apply(id);
    EXPECT_EQ(result["error"]["code"], "partial_failure");
    EXPECT_TRUE(result["error"]["details"]["operations"][0]["exists_after_failure"]);
    std::string rollback = result["error"]["details"]["rollback"]["plan_id"];
    EXPECT_EQ(engine::detail::load_plan(paths, rollback)["operations"][0]["op"], "delete");
}

TEST_F(PlanTest, NotSentIsAFailureButSentWithoutReplyIsUnknown) {
    std::string id = plan_comment();
    transport->reply(200, fake::envelope(json::array({address("LAN", {{"comment", "old"}})})));
    transport->fail(7, true).fail(7, true).fail(7, true);   // connect failed: nothing sent (the SDK may retry that)
    json result = apply(id);
    EXPECT_EQ(result["error"]["code"], "partial_failure");
    const json& op = result["error"]["details"]["operations"][0];
    EXPECT_EQ(op["status"], "failed");
    EXPECT_FALSE(op["sent"]);
    EXPECT_TRUE(result["error"]["details"]["rollback"]["plan_id"].is_null());   // nothing changed

    std::string second = plan_comment("again");
    transport->requests.clear();
    transport->reply(200, fake::envelope(json::array({address("LAN", {{"comment", "old"}})})));
    transport->fail(28, false);   // timed out after sending
    result = apply(second);
    EXPECT_EQ(result["error"]["code"], "outcome_unknown");
    const json& unknown = result["error"]["details"]["operations"][0];
    EXPECT_EQ(unknown["status"], "outcome_unknown");
    EXPECT_TRUE(unknown["sent"]);
    // Exactly one PUT went out: never retried after send.
    std::size_t puts = 0;
    for (const auto& request: transport->requests) puts += request.method == fortiapi::Method::Put;
    EXPECT_EQ(puts, 1u);
    json undo = engine::detail::load_plan(paths, result["error"]["details"]["rollback"]["plan_id"].get<std::string>());
    EXPECT_TRUE(undo["operations"][0]["before_digest"].is_null());   // post-state unknown
}

TEST_F(PlanTest, NormalizedValuesAreAppliedButUnverified) {
    transport->reply(404, missing());
    json planned = plan({{"operations", {{{"op", "create"}, {"resource", "firewall/address"},
                                          {"object", {{"name", "net"}, {"subnet", "192.0.2.0/24"}}}}}}});
    ASSERT_TRUE(planned["ok"]) << planned.dump();
    transport->reply(404, missing());
    transport->reply(200, written("net"));
    transport->reply(200, fake::envelope(json::array({address("net", {{"subnet", "192.0.2.0 255.255.255.0"}})})));
    json result = apply(planned["data"]["id"]);
    ASSERT_TRUE(result["ok"]) << result.dump();
    const json& op = result["data"]["operations"][0];
    EXPECT_EQ(op["status"], "applied_unverified");
    EXPECT_EQ(op["mismatches"][0], json({{"attribute", "subnet"}, {"expected", "192.0.2.0/24"}, {"actual", "192.0.2.0 255.255.255.0"}}));
    EXPECT_EQ(result["data"]["applied_unverified"], 1);
}

TEST_F(PlanTest, RollbackPlanInvertsAndCanBeApplied) {
    json gone = address("gone", {{"comment", "keep me"}, {"color", 4}});
    transport->reply(200, fake::envelope(json::array({address("LAN", {{"comment", "old"}})})));
    transport->reply(200, fake::envelope(json::array({gone})));
    json planned = plan({{"operations", {{{"op", "update"}, {"resource", "firewall/address"}, {"key", "LAN"}, {"set", {{"comment", "new"}}}},
                                         {{"op", "delete"}, {"resource", "firewall/address"}, {"key", "gone"}}}}});
    ASSERT_TRUE(planned["ok"]) << planned.dump();
    transport->reply(200, fake::envelope(json::array({address("LAN", {{"comment", "old"}})})));
    transport->reply(200, fake::envelope(json::array({gone})));
    transport->reply(200, written("LAN"));
    transport->reply(200, fake::envelope(json::array({address("LAN", {{"comment", "new"}})})));
    transport->reply(200, written("gone"));
    transport->reply(404, missing());
    json result = apply(planned["data"]["id"]);
    ASSERT_TRUE(result["ok"]) << result.dump();
    std::string rollback_id = result["data"]["rollback"]["plan_id"];
    EXPECT_NE(result["data"]["rollback"]["limitation"].get<std::string>().find("not independent recovery"), std::string::npos);
    json rollback = engine::detail::load_plan(paths, rollback_id);
    EXPECT_EQ(rollback["kind"], "rollback");
    EXPECT_EQ(rollback["rollback_of"], planned["data"]["id"]);
    ASSERT_EQ(rollback["operations"].size(), 2u);
    EXPECT_EQ(rollback["operations"][0]["op"], "create");   // reverse order
    EXPECT_EQ(rollback["operations"][0]["object"]["comment"], "keep me");
    EXPECT_FALSE(rollback["operations"][0]["object"].contains("q_origin_key"));
    EXPECT_EQ(rollback["operations"][1]["op"], "update");
    EXPECT_EQ(rollback["operations"][1]["set"], json({{"comment", "old"}}));

    transport->requests.clear();
    transport->reply(404, missing());
    transport->reply(200, fake::envelope(json::array({address("LAN", {{"comment", "new"}})})));
    transport->reply(200, written("gone"));
    transport->reply(200, fake::envelope(json::array({gone})));
    transport->reply(200, written("LAN"));
    transport->reply(200, fake::envelope(json::array({address("LAN", {{"comment", "old"}})})));
    json undone = apply(rollback_id);
    ASSERT_TRUE(undone["ok"]) << undone.dump();
    EXPECT_EQ(undone["data"]["operations"][0]["status"], "verified");
    EXPECT_EQ(undone["data"]["operations"][1]["status"], "verified");
}

TEST_F(PlanTest, CriticalOperationsAreFollowedByAFreshManagementProbe) {
    json global = {{"hostname", "fw1"}, {"admin-sport", 443}};
    transport->reply(200, fake::envelope(global));
    transport->reply(200, fake::envelope(json::array({address("LAN")})));
    json planned = plan({{"operations", {{{"op", "update"}, {"resource", "system/global"}, {"set", {{"admin-sport", 8443}}}},
                                         {{"op", "update"}, {"resource", "firewall/address"}, {"key", "LAN"}, {"set", {{"comment", "x"}}}}}}});
    ASSERT_TRUE(planned["ok"]) << planned.dump();
    EXPECT_EQ(planned["data"]["risk"], "critical");
    std::string notes = planned["data"]["notes"].dump();
    EXPECT_NE(notes.find("not independent recovery"), std::string::npos);

    transport->reply(200, fake::envelope(global));
    transport->reply(200, fake::envelope(json::array({address("LAN")})));
    transport->reply_raw(200, backup_text);   // the pre-change configuration backup
    transport->reply(200, written());
    transport->reply(200, fake::envelope({{"hostname", "fw1"}, {"admin-sport", 8443}}));
    transport->fail(7, true).fail(7, true);   // the probe: no management path any more
    json result = apply(planned["data"]["id"]);
    EXPECT_EQ(result["error"]["code"], "management_connectivity_lost") << result.dump();
    const json& details = result["error"]["details"];
    EXPECT_EQ(details["operations"][0]["status"], "verified");
    EXPECT_FALSE(details["operations"][0]["management_probe"]["ok"]);
    EXPECT_EQ(details["operations"][1]["status"], "not_attempted");
    EXPECT_TRUE(details["rollback"]["plan_id"].is_string());
    EXPECT_EQ(details["before"]["admin-sport"], 443);
    EXPECT_EQ(details["backup"]["status"], "saved");
    fs::path backup = details["backup"]["path"].get<std::string>();
    EXPECT_EQ(backup.parent_path(), paths.state / "backups");
    EXPECT_EQ(mode_of(backup), 0600u);
    EXPECT_EQ(mode_of(backup.parent_path()), 0700u);
    EXPECT_EQ(slurp(backup), backup_text);
    EXPECT_EQ(details["backup"]["sha256"], digest_hex(backup_text));
    EXPECT_EQ(result.dump().find("config system global"), std::string::npos);   // never in output
    EXPECT_EQ(slurp(paths.state / "audit.jsonl").find("config system global"), std::string::npos);
    std::string message = result["error"]["message"];
    EXPECT_NE(message.find("console, out-of-band interface, or a device-side auto-revert"), std::string::npos);
    EXPECT_EQ(writes(), 1u);
    EXPECT_EQ(audit_lines().back()["outcome"], "management_connectivity_lost");
}

TEST_F(PlanTest, AHealthyProbeLetsExecutionContinue) {
    json global = {{"hostname", "fw1"}};
    transport->reply(200, fake::envelope(global));
    json planned = plan({{"operations", {{{"op", "update"}, {"resource", "system/global"}, {"set", {{"hostname", "fw2"}}}}}}});
    ASSERT_TRUE(planned["ok"]) << planned.dump();
    transport->reply(200, fake::envelope(global));
    transport->reply_raw(200, backup_text);
    transport->reply(200, written());
    transport->reply(200, fake::envelope({{"hostname", "fw2"}}));
    transport->reply(200, fake::envelope({{"hostname", "fw2"}}));   // monitor/system/status through a fresh client
    json result = apply(planned["data"]["id"]);
    ASSERT_TRUE(result["ok"]) << result.dump();
    EXPECT_TRUE(result["data"]["operations"][0]["management_probe"]["ok"]);
    EXPECT_EQ(transport->requests.back().url, "https://fortigate.test:8443/api/v2/monitor/system/status");
}

TEST_F(PlanTest, ListAndShowReportState) {
    make(Mode::guarded);
    std::string id = plan_comment();
    json listed = engine::Engine::envelope([&] { return engine::list_plans(*sut); });
    ASSERT_TRUE(listed["ok"]);
    ASSERT_EQ(listed["data"].size(), 1u);
    EXPECT_EQ(listed["data"][0]["state"], "pending");
    ASSERT_TRUE(approve(id)["ok"]);
    json shown = engine::Engine::envelope([&] { return engine::show_plan(*sut, id); });
    EXPECT_EQ(shown["data"]["state"]["state"], "approved");
    EXPECT_EQ(shown["data"]["operations"][0]["before"]["comment"], "old");
    EXPECT_EQ(engine::Engine::envelope([&] { return engine::show_plan(*sut, "../../etc/passwd"); })["error"]["code"], "usage");
    EXPECT_EQ(engine::Engine::envelope([&] { return engine::show_plan(*sut, "20200101-000000-000000"); })["error"]["code"],
              "not_found");
}

TEST_F(PlanTest, ApplyAcceptsOnlyAPlanId) {
    json result = engine::Engine::envelope([&] { return sut->apply({{"plan_id", "x"}, {"operations", json::array()}}); });
    EXPECT_EQ(result["error"]["code"], "usage");
    EXPECT_EQ(apply("20200101-000000-000000")["error"]["code"], "not_found");
    for (auto id: {"short", "-20200101-000000", "20200101-000000-ABCDEF", "20200101_000000_0000", "../../etc/passwd-x",
                   "20200101-000000-000000-000000-0000"})
        EXPECT_EQ(apply(id)["error"]["code"], "usage") << id;
    EXPECT_TRUE(engine::valid_plan_id("20261014-153012-a1b2c3"));
}

namespace {

    // Delegates to a FakeTransport and calls `hook` before each mutating request: lets a test look at
    // the state directory at the moment a write leaves.
    class Hooked final : public fortiapi::Transport {
    public:
        std::shared_ptr<fake::FakeTransport> inner;
        std::function<void(const fortiapi::HttpRequest&)> hook;

        fortiapi::HttpResponse perform(const fortiapi::HttpRequest& request) override {
            if (request.method != fortiapi::Method::Get && hook) hook(request);
            return inner->perform(request);
        }
    };

}  // namespace

TEST_F(PlanTest, ARollbackPlanExistsBeforeTheFirstWriteAndIsFinalizedAfter) {
    auto hooked = std::make_shared<Hooked>();
    hooked->inner = transport;
    auto options = fake::options(transport, Mode::autonomous);
    options.paths = paths;
    options.transport = [hooked](const fortiapi::Config&) -> std::shared_ptr<fortiapi::Transport> { return hooked; };
    sut = std::make_unique<engine::Engine>(options);

    transport->reply(200, fake::envelope(json::array({address("LAN", {{"comment", "old"}})})));
    json planned = plan({{"operations", {{{"op", "update"}, {"resource", "firewall/address"}, {"key", "LAN"}, {"set", {{"comment", "new"}}}},
                                         {{"op", "create"}, {"resource", "firewall/policy"},
                                          {"object", {{"policyid", 0}, {"name", "allow-web"}, {"action", "accept"}}}}}}});
    ASSERT_TRUE(planned["ok"]) << planned.dump();
    std::string id = planned["data"]["id"];

    std::vector<json> seen;   // the rollback plans on disk when each write leaves
    hooked->hook = [&](const fortiapi::HttpRequest&) {
        for (const auto& entry: fs::directory_iterator(paths.state / "plans")) {
            if (entry.path().extension() != ".json") continue;
            json stored = json::parse(slurp(entry.path()));
            if (stored.value("kind", "") == "rollback") seen.push_back(stored);
        }
    };
    transport->reply(200, fake::envelope(json::array({address("LAN", {{"comment", "old"}})})));
    transport->reply(200, written("LAN"));
    transport->reply(200, fake::envelope(json::array({address("LAN", {{"comment", "new"}})})));
    transport->reply(200, written(7));   // the device assigns policyid 7
    transport->reply(200, fake::envelope(json::array({{{"policyid", 7}, {"name", "allow-web"}, {"action", "accept"}}})));
    json result = apply(id);
    ASSERT_TRUE(result["ok"]) << result.dump();

    // Before the first write: provisional, covering what the plan alone can invert.
    ASSERT_EQ(seen.size(), 2u);
    const json& provisional = seen.front();
    EXPECT_TRUE(provisional.value("provisional", false));
    EXPECT_EQ(provisional["rollback_of"], id);
    ASSERT_EQ(provisional["operations"].size(), 1u);   // the create's key is not known yet
    EXPECT_EQ(provisional["operations"][0]["set"], json({{"comment", "old"}}));
    EXPECT_TRUE(provisional["operations"][0]["before_digest"].is_null());
    EXPECT_EQ(engine::detail::load_plan(paths, provisional["id"].get<std::string>())["id"], provisional["id"]);

    // After: the same id, finalized with the device-assigned key.
    std::string rollback_id = result["data"]["rollback"]["plan_id"];
    EXPECT_EQ(json(rollback_id), provisional["id"]);
    json final_plan = engine::detail::load_plan(paths, rollback_id);
    EXPECT_FALSE(final_plan.contains("provisional"));
    ASSERT_EQ(final_plan["operations"].size(), 2u);
    EXPECT_EQ(final_plan["operations"][0]["op"], "delete");
    EXPECT_EQ(final_plan["operations"][0]["key"], "7");
    EXPECT_EQ(final_plan["operations"][1]["op"], "update");
    EXPECT_TRUE(final_plan["operations"][1]["before_digest"].is_string());
    EXPECT_EQ(audit_lines().back()["rollback_plan"], json(rollback_id));
}

TEST_F(PlanTest, NeverAttemptedOperationsLeaveTheRollbackPlan) {
    std::string id = plan_comment();
    transport->reply(200, fake::envelope(json::array({address("LAN", {{"comment", "old"}})})));
    transport->fail(7, true).fail(7, true).fail(7, true);
    json result = apply(id);
    EXPECT_EQ(result["error"]["code"], "partial_failure");
    // The provisional rollback was written, then removed: nothing reached the device.
    for (const auto& entry: fs::directory_iterator(paths.state / "plans"))
        if (entry.path().extension() == ".json") { EXPECT_NE(json::parse(slurp(entry.path())).value("kind", ""), "rollback"); }
}

TEST_F(PlanTest, TheAppliedMarkerIsAnAtomicGate) {
    std::string id = plan_comment();
    engine::detail::mark_applied(paths, id, engine::detail::Clock::now());
    try {
        engine::detail::mark_applied(paths, id, engine::detail::Clock::now());
        ADD_FAILURE() << "a second marker was created";
    } catch (const engine::Failure& failure) {
        EXPECT_EQ(failure.code(), engine::Code::policy_denied);
        EXPECT_EQ(failure.details()["reason"], "already_applied");
    }
}

TEST_F(PlanTest, ConcurrentAppliesOfOnePlanRunItOnce) {
    std::string id = plan_comment();
    constexpr int runners = 4;
    std::vector<std::shared_ptr<fake::FakeTransport>> transports;
    std::vector<std::unique_ptr<engine::Engine>> engines;
    for (int i = 0; i < runners; ++i) {
        auto own = std::make_shared<fake::FakeTransport>();
        own->reply(200, fake::envelope(json::array({address("LAN", {{"comment", "old"}})})));
        own->reply(200, written("LAN"));
        own->reply(200, fake::envelope(json::array({address("LAN", {{"comment", "new"}})})));
        auto options = fake::options(own, Mode::autonomous);
        options.paths = paths;
        transports.push_back(own);
        engines.push_back(std::make_unique<engine::Engine>(options));
    }
    std::vector<json> results(runners);
    std::vector<std::thread> threads;
    for (int i = 0; i < runners; ++i)
        threads.emplace_back([&, i] {
            results[i] = engine::Engine::envelope([&] { return engines[i]->apply({{"plan_id", id}}); });
        });
    for (auto& thread: threads) thread.join();
    int applied = 0, refused = 0;
    std::size_t puts = 0;
    for (int i = 0; i < runners; ++i) {
        if (results[i]["ok"]) ++applied;
        else if (results[i]["error"]["details"].value("reason", "") == "already_applied") ++refused;
        for (const auto& request: transports[i]->requests) puts += request.method == fortiapi::Method::Put;
    }
    EXPECT_EQ(applied, 1);
    EXPECT_EQ(refused, runners - 1);
    EXPECT_EQ(puts, 1u);
}

// ---- pre-change configuration backup (critical plans) ----

namespace {
    std::string plan_hostname(PlanTest& test) {
        test.transport->reply(200, fake::envelope({{"hostname", "fw1"}}));
        json planned = test.plan({{"operations", {{{"op", "update"}, {"resource", "system/global"}, {"set", {{"hostname", "fw2"}}}}}}});
        EXPECT_TRUE(planned["ok"]) << planned.dump();
        return planned["data"]["id"];
    }
}  // namespace

TEST_F(PlanTest, ABackupThatCannotBeTakenStopsACriticalPlanBeforeAnyWrite) {
    std::string id = plan_hostname(*this);
    transport->reply(200, fake::envelope({{"hostname", "fw1"}}));
    transport->reply(403, json{{"status", "error"}, {"http_status", 403}});
    json result = apply(id);
    EXPECT_EQ(result["error"]["code"], "policy_denied") << result.dump();
    EXPECT_EQ(result["error"]["details"]["reason"], "backup_failed");
    EXPECT_EQ(writes(), 0u);
    EXPECT_FALSE(fs::exists(paths.state / "backups" / (id + ".conf.partial")));
    EXPECT_FALSE(fs::exists(paths.state / "backups" / (id + ".conf")));

    // Nothing was committed: the same plan can run once the cause is fixed.
    transport->reply(200, fake::envelope({{"hostname", "fw1"}}));
    transport->reply_raw(200, backup_text);
    transport->reply(200, written());
    transport->reply(200, fake::envelope({{"hostname", "fw2"}}));
    transport->reply(200, fake::envelope({{"hostname", "fw2"}}));
    json retried = apply(id);
    ASSERT_TRUE(retried["ok"]) << retried.dump();
    EXPECT_EQ(retried["data"]["backup"]["status"], "saved");
}

TEST_F(PlanTest, ABackupMustBeAFortiOSConfiguration) {
    std::string id = plan_hostname(*this);
    transport->reply(200, fake::envelope({{"hostname", "fw1"}}));
    transport->reply_raw(200, "<html>login</html>", "text/html");
    json result = apply(id);
    EXPECT_EQ(result["error"]["details"]["reason"], "backup_failed") << result.dump();
    EXPECT_EQ(writes(), 0u);
}

TEST_F(PlanTest, ProfilesCanOptOutOfTheCriticalBackup) {
    auto options = fake::options(transport, Mode::autonomous);
    options.paths = paths;
    options.profiles->profiles.at("lab").backup_before_critical = false;
    sut = std::make_unique<engine::Engine>(options);
    std::string id = plan_hostname(*this);
    transport->reply(200, fake::envelope({{"hostname", "fw1"}}));
    transport->reply(200, written());
    transport->reply(200, fake::envelope({{"hostname", "fw2"}}));
    transport->reply(200, fake::envelope({{"hostname", "fw2"}}));
    json result = apply(id);
    ASSERT_TRUE(result["ok"]) << result.dump();
    EXPECT_EQ(result["data"]["backup"]["status"], "skipped");
}
