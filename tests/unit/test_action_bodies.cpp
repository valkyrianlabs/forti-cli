// Monitor actions with large bodies (content-addressed blobs) and action replies (per-command errors),
// against the scripted transport. Nothing here talks to a FortiGate.

#include <fake_transport.hpp>

#include <forti/engine/approval.hpp>

#include "plan_store.hpp"
#include "sha256.hpp"

#include <gtest/gtest.h>

#include <filesystem>
#include <format>
#include <fstream>
#include <sstream>

#include <sys/stat.h>

using namespace forti;
using json = nlohmann::json;
using engine::Mode;
namespace fs = std::filesystem;

namespace {

    const std::string feed_path = "monitor/system/external-resource/dynamic";

    struct TempDir {
        fs::path path;
        TempDir() {
            std::string pattern = (fs::temp_directory_path() / "forti-blob-test-XXXXXX").string();
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

    // A threat-feed push of `count` entries: well over the inline limit from a few thousand on.
    json feed_body(std::size_t count, const std::string& command = "snapshot", std::size_t first = 0) {
        json entries = json::array();
        for (std::size_t i = first; i < first + count; ++i) entries.push_back(std::format("host-{}.blocked.example", i));
        return {{"commands", json::array({{{"name", "dns-block"}, {"command", command}, {"entries", entries}}})}};
    }

    json feed_reply(json results) {
        return {{"http_method", "POST"}, {"status", "success"}, {"http_status", 200}, {"results", std::move(results)},
                {"vdom", "root"}, {"serial", "FGT60FTK00000000"}, {"version", "v7.4.8"}};
    }

    struct BlobTest : ::testing::Test {
        TempDir dir;
        std::shared_ptr<fake::FakeTransport> transport = std::make_shared<fake::FakeTransport>();
        std::unique_ptr<engine::Engine> sut;
        engine::Paths paths{dir.path / "config", dir.path / "state", dir.path / "cache", {}};

        void make(Mode mode) {
            auto options = fake::options(transport, mode);
            options.paths = paths;
            sut = std::make_unique<engine::Engine>(options);
        }

        BlobTest() { make(Mode::autonomous); }

        json plan(const json& request) { return engine::Engine::envelope([&] { return sut->plan(request); }); }
        json apply(const std::string& id) { return engine::Engine::envelope([&] { return sut->apply({{"plan_id", id}}); }); }

        // Plans the actions (one GET for the device identity).
        std::string plan_actions(const std::vector<json>& bodies) {
            json operations = json::array();
            for (const auto& body: bodies) operations.push_back({{"op", "action"}, {"resource", feed_path}, {"body", body}});
            transport->reply(200, fake::envelope({{"hostname", "fw01"}}));
            json result = plan({{"operations", operations}});
            EXPECT_TRUE(result["ok"]) << result.dump().substr(0, 500);
            return result["data"].value("id", "");
        }

        fs::path plan_path(const std::string& id) const { return paths.state / "plans" / (id + ".json"); }
        fs::path blobs() const { return paths.state / "blobs"; }

        std::vector<std::string> blob_names() const {
            std::vector<std::string> out;
            std::error_code ignored;
            for (const auto& entry: fs::directory_iterator(blobs(), ignored))
                if (entry.path().filename() != ".lock") out.push_back(entry.path().filename().string());
            std::ranges::sort(out);
            return out;
        }

        std::vector<fortiapi::HttpRequest> writes() const {
            std::vector<fortiapi::HttpRequest> out;
            for (const auto& request: transport->requests)
                if (request.method != fortiapi::Method::Get) out.push_back(request);
            return out;
        }

        void reseal(const std::string& id, json plan) {
            plan["digest"] = engine::detail::plan_digest(plan);
            std::ofstream(plan_path(id)) << plan.dump();
        }
    };

}  // namespace

// ---- storage ----

TEST_F(BlobTest, ALargeBodyIsStoredOnceByItsDigest) {
    json body = feed_body(8000);
    std::string text = engine::detail::canonical(body);
    ASSERT_GT(text.size(), engine::detail::inline_body_limit);
    std::string sha = engine::detail::hex(engine::detail::sha256(text));

    transport->reply(200, fake::envelope({{"hostname", "fw01"}}));
    json result = plan({{"operations", {{{"op", "action"}, {"resource", feed_path}, {"body", body}}}}});
    ASSERT_TRUE(result["ok"]) << result.dump().substr(0, 500);
    std::string id = result["data"]["id"];

    // The plan file references the body; it holds no copy of it.
    std::string stored_text = slurp(plan_path(id));
    EXPECT_LT(stored_text.size(), 8192u);
    EXPECT_EQ(stored_text.find("blocked.example"), std::string::npos);
    json stored = json::parse(stored_text);
    const json& op = stored["operations"][0];
    json ref = {{"sha256", sha}, {"bytes", text.size()}};
    EXPECT_EQ(op["body_ref"], ref);
    EXPECT_FALSE(op.contains("body"));
    EXPECT_EQ(op["wire"], json({{"method", "POST"}, {"path", feed_path}, {"body_ref", ref}}));

    // The blob: exactly the canonical body, owner-only, named by its SHA-256.
    fs::path blob = blobs() / (sha + ".json");
    ASSERT_TRUE(fs::exists(blob));
    EXPECT_EQ(slurp(blob), text);
    EXPECT_EQ(mode_of(blob), 0600u);
    EXPECT_EQ(mode_of(blobs()), 0700u);
    EXPECT_EQ(blob_names(), std::vector<std::string>{sha + ".json"});

    // Every view shows the reference and size, never the entries.
    for (const json& view: {result, engine::show_plan(*sut, id), engine::list_plans(*sut)}) {
        EXPECT_EQ(view.dump().find("blocked.example"), std::string::npos);
        EXPECT_LT(view.dump().size(), 8192u);
    }
    EXPECT_EQ(result["data"]["operations"][0]["body_ref"], ref);
    EXPECT_EQ(result["data"]["operations"][0]["wire"]["body_ref"], ref);
    EXPECT_EQ(engine::list_plans(*sut)["data"][0]["state"], "pending");
}

TEST_F(BlobTest, IdenticalBodiesShareOneBlob) {
    json body = feed_body(6000);
    std::string first = plan_actions({body});
    std::string second = plan_actions({body});
    std::string third = plan_actions({body, feed_body(6000, "add", 1)});
    EXPECT_EQ(blob_names().size(), 2u);   // body, and the third plan's second body
    json a = json::parse(slurp(plan_path(first))), b = json::parse(slurp(plan_path(second)));
    EXPECT_EQ(a["operations"][0]["body_ref"], b["operations"][0]["body_ref"]);
    json c = json::parse(slurp(plan_path(third)));
    EXPECT_EQ(c["operations"][0]["body_ref"], a["operations"][0]["body_ref"]);
    EXPECT_NE(c["operations"][1]["body_ref"], a["operations"][0]["body_ref"]);
}

TEST_F(BlobTest, SmallBodiesStayInlineAsBefore) {
    json body = feed_body(3);
    std::string id = plan_actions({body});
    json op = json::parse(slurp(plan_path(id)))["operations"][0];
    EXPECT_EQ(op["body"], body);
    EXPECT_EQ(op["wire"]["body"], body);
    EXPECT_FALSE(op.contains("body_ref"));
    EXPECT_FALSE(op["wire"].contains("body_ref"));
    EXPECT_FALSE(fs::exists(blobs()));

    transport->reply(200, fake::envelope({{"hostname", "fw01"}}));
    transport->reply(200, feed_reply(json::array({{{"name", "dns-block"}, {"status", "success"}}})));
    json result = apply(id);
    ASSERT_TRUE(result["ok"]) << result.dump();
    ASSERT_EQ(writes().size(), 1u);
    EXPECT_EQ(json::parse(writes()[0].body), body);
    EXPECT_FALSE(fs::exists(blobs()));
}

TEST_F(BlobTest, TheDigestBindsTheBodyContent) {
    std::string a = plan_actions({feed_body(6000)});
    std::string b = plan_actions({feed_body(6000, "snapshot", 1)});   // one entry differs at each end
    json pa = engine::detail::load_plan(paths, a), pb = engine::detail::load_plan(paths, b);
    EXPECT_NE(pa["digest"], pb["digest"]);
    // The reference is inside the digested record: editing it without resealing is tampering.
    json edited = json::parse(slurp(plan_path(a)));
    edited["operations"][0]["body_ref"] = pb["operations"][0]["body_ref"];
    edited["operations"][0]["wire"]["body_ref"] = pb["operations"][0]["body_ref"];
    std::ofstream(plan_path(a)) << edited.dump();
    json result = apply(a);
    EXPECT_EQ(result["error"]["code"], "policy_denied") << result.dump();
    EXPECT_EQ(result["error"]["details"]["check"], "digest");
    EXPECT_TRUE(writes().empty());
}

// ---- apply ----

TEST_F(BlobTest, ApplySendsTheStoredBodyAndThenDeletesTheBlob) {
    json body = feed_body(8000);
    std::string id = plan_actions({body});
    ASSERT_EQ(blob_names().size(), 1u);

    transport->requests.clear();
    transport->reply(200, fake::envelope({{"hostname", "fw01"}}));   // apply: device identity
    json results = json::array({{{"name", "dns-block"}, {"status", "success"}, {"entries", 8000}}});
    transport->reply(200, feed_reply(results));
    json result = apply(id);
    ASSERT_TRUE(result["ok"]) << result.dump().substr(0, 500);
    const json& op = result["data"]["operations"][0];
    EXPECT_EQ(op["status"], "applied_unverified");
    EXPECT_EQ(op["reply"], results);
    EXPECT_FALSE(op.contains("reply_truncated"));

    auto sent = writes();
    ASSERT_EQ(sent.size(), 1u);
    EXPECT_EQ(sent[0].url, "https://fortigate.test:8443/api/v2/" + feed_path);
    EXPECT_EQ(sent[0].body, body.dump());
    EXPECT_EQ(result.dump().find("blocked.example"), std::string::npos);

    // Applied: no plan waiting to run references the blob any more.
    EXPECT_TRUE(blob_names().empty());
    // The audit record names the body's attributes, never its values.
    std::string audit = slurp(paths.state / "audit.jsonl");
    EXPECT_NE(audit.find("\"attributes\":[\"commands\"]"), std::string::npos) << audit;
    EXPECT_EQ(audit.find("blocked.example"), std::string::npos);
}

TEST_F(BlobTest, PruningKeepsTheBlobsOfPlansStillWaiting) {
    std::string applied = plan_actions({feed_body(6000)});
    std::string waiting = plan_actions({feed_body(6000, "add", 7)});
    std::string waiting_ref = json::parse(slurp(plan_path(waiting)))["operations"][0]["body_ref"]["sha256"];
    // Leftovers: a blob no plan references and an interrupted write.
    std::ofstream(blobs() / (std::string(64, 'a') + ".json")) << "{}";
    std::ofstream(blobs() / (std::string(64, 'b') + ".json.tmp.12345")) << "{";

    transport->reply(200, fake::envelope({{"hostname", "fw01"}}));
    transport->reply(200, feed_reply(json::array({{{"status", "success"}}})));
    ASSERT_TRUE(apply(applied)["ok"]);
    EXPECT_EQ(blob_names(), std::vector<std::string>{waiting_ref + ".json"});

    // Any outcome prunes, a refused apply included; the waiting plan's blob stays.
    std::ofstream(blobs() / (std::string(64, 'c') + ".json")) << "{}";
    EXPECT_FALSE(apply("not a plan id")["ok"]);
    EXPECT_EQ(blob_names(), std::vector<std::string>{waiting_ref + ".json"});
    EXPECT_EQ(engine::list_plans(*sut)["data"].size(), 2u);   // plan files are untouched (actions have no rollback)
}

TEST_F(BlobTest, AnAlteredOrMissingBlobRefusesThePlanBeforeAnythingIsSent) {
    json body = feed_body(6000);
    std::string id = plan_actions({body});
    std::string sha = json::parse(slurp(plan_path(id)))["operations"][0]["body_ref"]["sha256"];
    fs::path blob = blobs() / (sha + ".json");
    std::string original = slurp(blob);

    transport->requests.clear();
    // Same size, other content.
    std::string altered = original;
    altered[altered.find("host-1.")] = 'H';
    std::ofstream(blob, std::ios::trunc) << altered;
    json result = apply(id);
    EXPECT_EQ(result["error"]["code"], "policy_denied") << result.dump();
    EXPECT_EQ(result["error"]["details"]["reason"], "tampered");
    EXPECT_EQ(result["error"]["details"]["check"], "body blob sha256");
    EXPECT_TRUE(transport->requests.empty());
    EXPECT_FALSE(engine::detail::plan_applied(paths, id));
    // The refused apply pruned nothing the plan still needs.
    EXPECT_TRUE(fs::exists(blob));

    fs::remove(blob);
    result = apply(id);
    EXPECT_EQ(result["error"]["details"]["check"], "body blob missing") << result.dump();
    EXPECT_TRUE(transport->requests.empty());

    // A symlink in place of the blob is not followed.
    fs::path elsewhere = dir.path / "elsewhere.json";
    std::ofstream(elsewhere) << original;
    fs::create_symlink(elsewhere, blob);
    result = apply(id);
    EXPECT_EQ(result["error"]["details"]["check"], "body blob missing") << result.dump();
    fs::remove(blob);

    // Restored, the plan runs.
    std::ofstream(blob) << original;
    transport->reply(200, fake::envelope({{"hostname", "fw01"}}));
    transport->reply(200, feed_reply(json::array({{{"status", "success"}}})));
    result = apply(id);
    EXPECT_TRUE(result["ok"]) << result.dump();
    EXPECT_EQ(writes()[0].body, body.dump());
}

TEST_F(BlobTest, AnApprovalCoversOnlyTheBodyItWasGivenFor) {
    make(Mode::guarded);
    std::string a = plan_actions({feed_body(6000)});
    std::string b = plan_actions({feed_body(6000, "remove")});
    ASSERT_TRUE(engine::Engine::envelope([&] { return engine::approve_plan(*sut, a, "cli:test"); })["ok"]);
    // Point the approved plan at the other (valid) blob and reseal its digest.
    json edited = json::parse(slurp(plan_path(a)));
    json other = json::parse(slurp(plan_path(b)))["operations"][0]["body_ref"];
    edited["operations"][0]["body_ref"] = other;
    edited["operations"][0]["wire"]["body_ref"] = other;
    reseal(a, edited);
    json result = apply(a);
    EXPECT_EQ(result["error"]["code"], "approval_required") << result.dump();
    EXPECT_EQ(result["error"]["details"]["reason"], "digest_mismatch");
    EXPECT_TRUE(writes().empty());
}

TEST_F(BlobTest, MalformedReferencesAreTampering) {
    std::string id = plan_actions({feed_body(6000)});
    json stored = json::parse(slurp(plan_path(id)));
    json body = feed_body(6000);
    auto expect_tampered = [&](json edited) {
        reseal(id, std::move(edited));
        json result = apply(id);
        EXPECT_EQ(result["error"]["details"]["reason"], "tampered") << result.dump();
    };
    json edited = stored;
    edited["operations"][0]["body_ref"]["bytes"] = 1;
    edited["operations"][0]["wire"]["body_ref"]["bytes"] = 1;
    reseal(id, edited);
    EXPECT_EQ(apply(id)["error"]["details"]["check"], "body blob sha256");
    edited = stored;
    edited["operations"][0]["wire"]["body"] = body;   // a body to show that is not the one sent
    expect_tampered(edited);
    edited = stored;
    edited["operations"][0]["wire"].erase("body_ref");
    expect_tampered(edited);
    edited = stored;
    edited["operations"][0]["body"] = body;           // both an inline body and a reference
    expect_tampered(edited);
    // Last: a plan whose reference is unreadable no longer holds on to its blob.
    edited = stored;
    edited["operations"][0]["body_ref"]["sha256"] = "../../../etc/passwd";
    edited["operations"][0]["wire"]["body_ref"] = edited["operations"][0]["body_ref"];
    expect_tampered(edited);
    EXPECT_TRUE(writes().empty());
}

TEST_F(BlobTest, InlineBodiesShownMustBeTheOnesSent) {
    std::string id = plan_actions({feed_body(2)});
    json edited = json::parse(slurp(plan_path(id)));
    edited["operations"][0]["wire"]["body"] = feed_body(1);
    reseal(id, edited);
    EXPECT_EQ(apply(id)["error"]["details"]["reason"], "tampered");
    EXPECT_TRUE(writes().empty());
}

// ---- replies ----

TEST_F(BlobTest, TheReplyIsKeptRedactedAndBounded) {
    std::string id = plan_actions({feed_body(2)});
    json results = json::array({{{"name", "dns-block"}, {"status", "success"}, {"psksecret", "ENC c2VjcmV0"},
                                 {"note", "ENC abc"}}});
    transport->reply(200, fake::envelope({{"hostname", "fw01"}}));
    transport->reply(200, feed_reply(results));
    json result = apply(id);
    ASSERT_TRUE(result["ok"]) << result.dump();
    const json& op = result["data"]["operations"][0];
    EXPECT_EQ(op["reply"][0]["status"], "success");
    EXPECT_EQ(op["reply"][0]["psksecret"], "<redacted>");
    EXPECT_EQ(op["reply"][0]["note"], "<redacted>");
    EXPECT_EQ(op["reply_redacted"], json({"/*/note", "/*/psksecret"}));
    EXPECT_EQ(result.dump().find("c2VjcmV0"), std::string::npos);

    // A large reply keeps its leading entries only.
    id = plan_actions({feed_body(2)});
    json many = json::array();
    for (int i = 0; i < 2000; ++i) many.push_back({{"name", std::format("feed-{}", i)}, {"status", "success"}});
    transport->reply(200, fake::envelope({{"hostname", "fw01"}}));
    transport->reply(200, feed_reply(many));
    result = apply(id);
    ASSERT_TRUE(result["ok"]) << result.dump().substr(0, 300);
    const json& big = result["data"]["operations"][0];
    EXPECT_TRUE(big["reply_truncated"]);
    ASSERT_TRUE(big["reply"].is_array());
    EXPECT_GT(big["reply"].size(), 10u);
    EXPECT_LT(big["reply"].size(), many.size());
    EXPECT_LE(big["reply"].dump().size(), 16u * 1024);
    EXPECT_EQ(big["reply"][0], many[0]);

    // A reply without results.
    id = plan_actions({feed_body(2)});
    transport->reply(200, fake::envelope({{"hostname", "fw01"}}));
    transport->reply(200, {{"status", "success"}, {"http_status", 200}, {"serial", "FGT60FTK00000000"}});
    result = apply(id);
    ASSERT_TRUE(result["ok"]) << result.dump();
    EXPECT_TRUE(result["data"]["operations"][0]["reply"].is_null());
}

TEST_F(BlobTest, AFailedCommandInASuccessfulReplyFailsTheOperationAndStops) {
    std::string id = plan_actions({feed_body(6000), feed_body(2, "add")});
    json results = json::array({{{"name", "dns-block"}, {"status", "error"}, {"message", "Connect pending"}}});
    transport->requests.clear();
    transport->reply(200, fake::envelope({{"hostname", "fw01"}}));
    transport->reply(200, feed_reply(results));
    json result = apply(id);
    EXPECT_FALSE(result["ok"]);
    EXPECT_EQ(result["error"]["code"], "partial_failure") << result.dump();
    const json& ops = result["error"]["details"]["operations"];
    ASSERT_EQ(ops.size(), 2u);
    EXPECT_EQ(ops[0]["status"], "failed");
    EXPECT_EQ(ops[0]["error"]["code"], "api");
    EXPECT_NE(ops[0]["error"]["message"].get<std::string>().find("1 of 1 command failed: Connect pending"), std::string::npos)
            << ops[0].dump();
    const json& details = ops[0]["error"]["details"];
    EXPECT_EQ(details["reason"], "command_failed");
    EXPECT_EQ(details["errors"], results);
    EXPECT_EQ(details["error_indexes"], json::array({0}));
    EXPECT_EQ(details["error_count"], 1);
    EXPECT_EQ(ops[0]["reply"], results);
    EXPECT_EQ(ops[1]["status"], "not_attempted");
    EXPECT_EQ(writes().size(), 1u);   // the second action was never sent
    // Monitor actions cannot be rolled back: the record says so.
    EXPECT_TRUE(result["error"]["details"]["rollback"]["plan_id"].is_null());
    EXPECT_EQ(result["error"]["details"]["rollback"]["skipped"][0]["index"], 0);

    std::string audit = slurp(paths.state / "audit.jsonl");
    EXPECT_NE(audit.find("\"outcome\":\"partial_failure\""), std::string::npos);
    EXPECT_TRUE(blob_names().empty());   // applied (it ran, then stopped): its blob is gone
}

TEST_F(BlobTest, ManyFailedCommandsAreBoundedInTheDetails) {
    std::string id = plan_actions({feed_body(2)});
    json results = json::array({{{"status", "success"}}});
    for (int i = 0; i < 100; ++i) results.push_back({{"name", std::format("feed-{}", i)}, {"status", "error"}, {"error", -651}});
    transport->reply(200, fake::envelope({{"hostname", "fw01"}}));
    transport->reply(200, feed_reply(results));
    json result = apply(id);
    const json& details = result["error"]["details"]["operations"][0]["error"]["details"];
    EXPECT_EQ(details["error_count"], 100) << result.dump().substr(0, 500);
    EXPECT_EQ(details["commands"], 101);
    EXPECT_EQ(details["errors"].size(), 20u);
    EXPECT_EQ(details["error_indexes"][0], 1);
    EXPECT_TRUE(details["errors_truncated"]);
    EXPECT_NE(result["error"]["details"]["operations"][0]["error"]["message"].get<std::string>().find(
                      "100 of 101 commands failed: -651"),
              std::string::npos);
}
