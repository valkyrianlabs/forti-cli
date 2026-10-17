// Child tables: one entry of a table attribute (a DHCP server's reserved-address) read, planned,
// applied, verified and rolled back on FortiOS's child paths, against the scripted transport.

#include <fake_transport.hpp>

#include "plan_store.hpp"

#include <gtest/gtest.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>

using namespace forti;
using json = nlohmann::json;
using engine::Mode;
namespace fs = std::filesystem;

namespace {

    const std::string serial = "FGT60FTK00000000";
    const std::string base = "https://fortigate.test:8443/api/v2/";
    const std::string reservations = base + "cmdb/system.dhcp/server/1/reserved-address";

    struct TempDir {
        fs::path path;
        TempDir() {
            std::string pattern = (fs::temp_directory_path() / "forti-child-test-XXXXXX").string();
            path = ::mkdtemp(pattern.data());
        }
        ~TempDir() { fs::remove_all(path); }
    };

    json reservation(unsigned id, const std::string& ip, const std::string& mac, const std::string& description = "") {
        return {{"id", id},       {"q_origin_key", id}, {"type", "mac"},          {"ip", ip},       {"mac", mac},
                {"action", "reserved"}, {"circuit-id-type", "string"}, {"circuit-id", ""}, {"remote-id-type", "string"},
                {"remote-id", ""}, {"description", description}};
    }

    // Replies on child paths, as FortiOS 7.4.8 sends them (observed live by forti-api). A GET names
    // the parent's key as mkey.
    json child_reply(json results) {
        json body = fake::envelope(std::move(results));
        body["path"] = "system.dhcp";
        body["name"] = "server";
        body["mkey"] = 1;
        body["child_path"] = "reserved-address";
        return body;
    }

    json missing() { return {{"status", "error"}, {"http_status", 404}, {"serial", serial}, {"version", "v7.4.8"}}; }

    json write_reply(const std::string& method, json mkey) {
        return {{"http_method", method}, {"status", "success"}, {"http_status", 200}, {"serial", serial},
                {"version", "v7.4.8"}, {"vdom", "root"}, {"path", "system.dhcp"}, {"name", "server"},
                {"child_path", "reserved-address"}, {"mkey", std::move(mkey)}, {"revision", "41"},
                {"old_revision", "40"}, {"revision_changed", true}};
    }

    // POST: mkey is the NEW ENTRY's key, and there is no child_mkey.
    json posted(unsigned id) { return write_reply("POST", id); }
    // PUT: mkey is the parent's key, child_mkey the entry's (as text).
    json put(unsigned id) {
        json r = write_reply("PUT", 1);
        r["child_mkey"] = std::to_string(id);
        return r;
    }
    // DELETE: mkey and child_mkey are the entry's.
    json deleted(unsigned id) {
        json r = write_reply("DELETE", id);
        r["child_mkey"] = std::to_string(id);
        return r;
    }

    json status() { return fake::envelope({{"hostname", "fw"}}); }

    struct ChildTest : ::testing::Test {
        TempDir dir;
        std::shared_ptr<fake::FakeTransport> transport = std::make_shared<fake::FakeTransport>();
        std::unique_ptr<engine::Engine> sut;
        engine::Paths paths{dir.path / "config", dir.path / "state", dir.path / "cache", {}};

        ChildTest() {
            auto options = fake::options(transport, Mode::autonomous);
            options.paths = paths;
            sut = std::make_unique<engine::Engine>(options);
        }

        json read(const json& request) { return engine::Engine::envelope([&] { return sut->read(request); }); }
        json plan(const json& request) { return engine::Engine::envelope([&] { return sut->plan(request); }); }
        json apply(const std::string& id) { return engine::Engine::envelope([&] { return sut->apply({{"plan_id", id}}); }); }

        static json op(json fields) {
            json out = {{"resource", "system.dhcp/server"}, {"parent", "1"}, {"child", "reserved-address"}};
            out.update(fields);
            return out;
        }

        std::vector<fortiapi::HttpRequest> writes() const {
            std::vector<fortiapi::HttpRequest> out;
            for (const auto& request: transport->requests)
                if (request.method != fortiapi::Method::Get) out.push_back(request);
            return out;
        }

        std::vector<json> audit_lines() const {
            std::vector<json> out;
            std::ifstream in(paths.state / "audit.jsonl");
            for (std::string line; std::getline(in, line);) out.push_back(json::parse(line));
            return out;
        }
    };

}  // namespace

// ---- read ----

TEST_F(ChildTest, ReadListsOneObjectsEntriesOnTheChildPath) {
    transport->reply(200, child_reply(json::array({reservation(7, "192.0.2.7", "00:00:5e:00:53:07"),
                                                   reservation(21, "192.0.2.21", "00:00:5e:00:53:15")})));
    json result = read({{"resource", "system.dhcp/server"}, {"key", "1"}, {"child", "reserved-address"},
                        {"fields", {"id", "ip", "mac"}}, {"filter", "ip==192.0.2.21"}, {"count", 1}});
    ASSERT_TRUE(result["ok"]) << result.dump();
    ASSERT_EQ(transport->requests.size(), 1u);
    // No start/count: the engine windows child lists itself, like monitor results.
    EXPECT_EQ(transport->requests[0].url, reservations + "?format=id%7Cip%7Cmac&filter=ip%3D%3D192.0.2.21");
    EXPECT_EQ(result["data"].size(), 1u);
    EXPECT_EQ(result["data"][0]["id"], 7);
    const json& meta = result["meta"];
    EXPECT_EQ(meta["resource"], "system.dhcp/server");
    EXPECT_EQ(meta["key"], "1");
    EXPECT_EQ(meta["child"], "reserved-address");
    EXPECT_EQ(meta["total"], 2);
    EXPECT_EQ(meta["next_start"], 1);
    EXPECT_FALSE(meta.contains("child_key"));
}

TEST_F(ChildTest, ReadOneEntryByItsKey) {
    transport->reply(200, child_reply(json::array({reservation(21, "192.0.2.21", "00:00:5e:00:53:15", "ENC c2VjcmV0")})));
    json result = read({{"resource", "system.dhcp/server/1"}, {"child", "reserved-address"}, {"child_key", 21}});
    ASSERT_TRUE(result["ok"]) << result.dump();
    EXPECT_EQ(transport->requests[0].url, reservations + "/21");
    EXPECT_TRUE(result["data"].is_object());
    EXPECT_EQ(result["data"]["ip"], "192.0.2.21");
    EXPECT_EQ(result["meta"]["child_key"], "21");
    // Redaction applies to child reads as to any read.
    EXPECT_EQ(result["data"]["description"], "<redacted>");
    EXPECT_EQ(result["meta"]["redacted"], json::array({"/description"}));

    transport->reply(404, missing());
    result = read({{"resource", "system.dhcp/server"}, {"key", "1"}, {"child", "reserved-address"}, {"child_key", "99"}});
    EXPECT_EQ(result["error"]["code"], "not_found");
    EXPECT_EQ(result["error"]["details"]["child"], "reserved-address");
    EXPECT_EQ(result["error"]["details"]["child_key"], "99");
}

TEST_F(ChildTest, ReadValidatesTheChildBeforeAnyRequest) {
    auto code = [&](json request) { return read(request)["error"].value("code", ""); };
    json base_request = {{"resource", "system.dhcp/server"}, {"key", "1"}, {"child", "reserved-address"}};
    auto with = [&](json extra) {
        json out = base_request;
        out.update(extra);
        return out;
    };

    // fields and filters name the entry's attributes, not the server's.
    json result = read(with({{"fields", {"ip", "lease-time"}}}));
    ASSERT_EQ(result["error"]["code"], "validation") << result.dump();
    EXPECT_EQ(result["error"]["details"]["unknown"], json::array({"lease-time"}));
    EXPECT_EQ(result["error"]["details"]["child"], "reserved-address");
    json filtered = base_request;
    filtered["filter"] = "lease-time==60";
    EXPECT_EQ(code(filtered), "validation");

    result = read({{"resource", "system.dhcp/server"}, {"key", "1"}, {"child", "reserved-adress"}});
    EXPECT_EQ(result["error"]["code"], "validation");
    EXPECT_EQ(result["error"]["details"]["suggestions"][0], "reserved-address");
    EXPECT_NE(result["error"]["message"].get<std::string>().find("did you mean reserved-address"), std::string::npos);
    result = read({{"resource", "system.dhcp/server"}, {"key", "1"}, {"child", "dns-service"}});
    EXPECT_EQ(result["error"]["code"], "validation");   // an attribute, but not a table
    EXPECT_NE(result["error"]["message"].get<std::string>().find("not a table attribute"), std::string::npos);

    EXPECT_EQ(code({{"resource", "system.dhcp/server"}, {"child", "reserved-address"}}), "usage");   // no parent key
    EXPECT_EQ(code({{"resource", "system.dhcp/server"}, {"key", "1"}, {"child_key", "7"}}), "usage");   // no child
    EXPECT_EQ(code({{"resource", "system/global"}, {"child", "reserved-address"}}), "usage");
    EXPECT_EQ(code(with({{"child_key", ".."}})), "usage");   // G13
    EXPECT_EQ(code({{"resource", "system.dhcp/server"}, {"key", "x"}, {"child", "reserved-address"}}), "validation");
    EXPECT_EQ(code(with({{"child_key", "seven"}})), "validation");
    EXPECT_EQ(code(with({{"childkey", "7"}})), "usage");   // strict keys
    EXPECT_TRUE(transport->requests.empty());
}

// ---- plan and apply ----

TEST_F(ChildTest, CreateWithADeviceAssignedIdRecordsTheReportedEntryKey) {
    transport->reply(200, child_reply(json::array({reservation(7, "192.0.2.7", "00:00:5e:00:53:07")})));   // parent exists
    json planned = plan({{"operations", {op({{"op", "create"},
                                            {"object", {{"ip", "192.0.2.50"}, {"mac", "00:00:5e:00:53:32"},
                                                        {"description", "printer"}}}})}}});
    ASSERT_TRUE(planned["ok"]) << planned.dump();
    ASSERT_EQ(transport->requests.size(), 1u);
    EXPECT_EQ(transport->requests[0].url, reservations);
    const json& view = planned["data"]["operations"][0];
    EXPECT_EQ(view["parent"], "1");
    EXPECT_EQ(view["child"], "reserved-address");
    EXPECT_EQ(view["risk"], "elevated");   // the parent resource's tier
    EXPECT_FALSE(view.contains("key"));
    EXPECT_EQ(view["wire"], json({{"method", "POST"}, {"path", "cmdb/system.dhcp/server/1/reserved-address"},
                                  {"body", {{"ip", "192.0.2.50"}, {"mac", "00:00:5e:00:53:32"}, {"description", "printer"}}}}));
    EXPECT_EQ(view["diff"].size(), 3u);
    std::string id = planned["data"]["id"];
    json stored = engine::detail::load_plan(paths, id);
    EXPECT_TRUE(stored["operations"][0]["before_digest"].is_null());

    transport->requests.clear();
    transport->reply(200, status());                       // the serial (nothing to re-read)
    transport->reply(200, posted(21));                     // the new entry's key, as mkey
    transport->reply(200, child_reply(json::array({reservation(21, "192.0.2.50", "00:00:5e:00:53:32", "printer")})));
    json result = apply(id);
    ASSERT_TRUE(result["ok"]) << result.dump();
    const json& done = result["data"]["operations"][0];
    EXPECT_EQ(done["status"], "verified") << done.dump();
    EXPECT_EQ(done["key"], "21");
    EXPECT_EQ(done["parent"], "1");
    EXPECT_EQ(done["child"], "reserved-address");
    ASSERT_EQ(writes().size(), 1u);
    EXPECT_EQ(writes()[0].url, reservations);
    EXPECT_EQ(writes()[0].body, stored["operations"][0]["wire"]["body"].dump());
    EXPECT_EQ(transport->requests.back().url, reservations + "/21");   // verified by re-reading the entry

    auto audit = audit_lines();
    ASSERT_FALSE(audit.empty());
    EXPECT_EQ(audit.back()["operations"][0]["key"], "21");
    EXPECT_EQ(audit.back()["operations"][0]["parent"], "1");
    EXPECT_EQ(audit.back()["operations"][0]["child"], "reserved-address");

    // The rollback deletes exactly the entry the device assigned.
    std::string rollback_id = result["data"]["rollback"]["plan_id"];
    json rollback = engine::detail::load_plan(paths, rollback_id);
    ASSERT_EQ(rollback["operations"].size(), 1u);
    const json& undo = rollback["operations"][0];
    EXPECT_EQ(undo["op"], "delete");
    EXPECT_EQ(undo["key"], "21");
    EXPECT_EQ(undo["parent"], "1");
    EXPECT_EQ(undo["child"], "reserved-address");
    EXPECT_EQ(undo["wire"], json({{"method", "DELETE"}, {"path", "cmdb/system.dhcp/server/1/reserved-address/21"}, {"body", nullptr}}));
    EXPECT_TRUE(undo["before_digest"].is_string());

    transport->requests.clear();
    transport->reply(200, child_reply(json::array({reservation(21, "192.0.2.50", "00:00:5e:00:53:32", "printer")})));
    transport->reply(200, deleted(21));
    transport->reply(404, missing());
    json undone = apply(rollback_id);
    ASSERT_TRUE(undone["ok"]) << undone.dump();
    EXPECT_EQ(undone["data"]["operations"][0]["status"], "verified");
    ASSERT_EQ(writes().size(), 1u);
    EXPECT_EQ(writes()[0].method, fortiapi::Method::Delete);
    EXPECT_EQ(writes()[0].url, reservations + "/21");
}

// Which reply fields name the new entry: child_mkey when present, else mkey, but only from a reply
// that echoes the POST and this child table (elsewhere mkey can be the parent's key).
TEST_F(ChildTest, TheCreatedEntrysKeyIsTakenOnlyFromAReplyThatNamesIt) {
    json object = {{"id", 0}, {"ip", "192.0.2.50"}, {"mac", "00:00:5e:00:53:32"}};
    auto create = [&](const json& reply, json verify = nullptr) {
        transport->reply(200, child_reply(json::array()));
        json planned = plan({{"operations", {op({{"op", "create"}, {"object", object}})}}});
        EXPECT_TRUE(planned["ok"]) << planned.dump();
        EXPECT_EQ(planned["data"]["operations"][0]["wire"]["body"]["id"], 0);   // 0: the device assigns the id
        transport->reply(200, status());
        transport->reply(200, reply);
        if (!verify.is_null()) transport->reply(200, verify);
        return apply(planned["data"]["id"]);
    };
    auto unnamed = [&](const json& reply) {
        json result = create(reply);
        EXPECT_TRUE(result["ok"]) << result.dump();
        const json& done = result["data"]["operations"][0];
        EXPECT_EQ(done["status"], "applied_unverified") << reply.dump();
        EXPECT_FALSE(done.contains("key")) << reply.dump();
        EXPECT_NE(done["verification"].get<std::string>().find("key was not reported"), std::string::npos);
        EXPECT_TRUE(result["data"]["rollback"]["plan_id"].is_null());
        EXPECT_EQ(result["data"]["rollback"]["skipped"].size(), 1u);
    };
    json no_child_path = posted(1);
    no_child_path.erase("child_path");
    unnamed(no_child_path);                                       // not a child reply: mkey may be anything
    unnamed(write_reply("PUT", 1));                               // not the POST
    json other_table = posted(1);
    other_table["child_path"] = "ip-range";
    unnamed(other_table);
    json not_a_number = posted(1);
    not_a_number["mkey"] = "server-1";
    unnamed(not_a_number);

    json named = posted(1);
    named["child_mkey"] = "22";                                   // child_mkey wins when present
    json result = create(named, child_reply(json::array({reservation(22, "192.0.2.50", "00:00:5e:00:53:32")})));
    ASSERT_TRUE(result["ok"]) << result.dump();
    EXPECT_EQ(result["data"]["operations"][0]["key"], "22");
}

TEST_F(ChildTest, ACreateForAMissingParentIsNotFoundAtPlanTime) {
    transport->reply(404, missing());
    json result = plan({{"operations", {op({{"op", "create"}, {"parent", "9"}, {"object", {{"ip", "192.0.2.50"}, {"mac", "00:00:5e:00:53:32"}}}})}}});
    EXPECT_EQ(result["error"]["code"], "not_found");
    EXPECT_EQ(transport->requests[0].url, base + "cmdb/system.dhcp/server/9/reserved-address");

    // An explicit id is checked for existence instead.
    transport->reply(200, child_reply(json::array({reservation(7, "192.0.2.7", "00:00:5e:00:53:07")})));
    result = plan({{"operations", {op({{"op", "create"}, {"object", {{"id", 7}, {"ip", "192.0.2.8"}, {"mac", "00:00:5e:00:53:08"}}}})}}});
    EXPECT_EQ(result["error"]["code"], "validation");
    EXPECT_NE(result["error"]["message"].get<std::string>().find("reserved-address 7 already exists"), std::string::npos);
    EXPECT_EQ(transport->requests.back().url, reservations + "/7");
}

TEST_F(ChildTest, UpdateSendsOnlyTheChangedAttributesAndReReadsOnlyThatEntry) {
    json entry = reservation(7, "192.0.2.7", "00:00:5e:00:53:07", "old");
    transport->reply(200, child_reply(json::array({entry})));
    json planned = plan({{"operations", {op({{"op", "update"}, {"key", "7"}, {"set", {{"description", "new"}}}, {"clear", {"circuit-id"}}})}}});
    ASSERT_TRUE(planned["ok"]) << planned.dump();
    EXPECT_EQ(transport->requests[0].url, reservations + "/7");
    const json& view = planned["data"]["operations"][0];
    EXPECT_EQ(view["key"], "7");
    EXPECT_EQ(view["wire"]["method"], "PUT");
    EXPECT_EQ(view["wire"]["path"], "cmdb/system.dhcp/server/1/reserved-address/7");
    EXPECT_EQ(view["wire"]["body"], json({{"description", "new"}, {"circuit-id", ""}}));
    EXPECT_EQ(view["diff"][0], json({{"attribute", "description"}, {"change", "set"}, {"before", "old"}, {"after", "new"}}));
    std::string id = planned["data"]["id"];
    json stored = engine::detail::load_plan(paths, id);
    EXPECT_EQ(stored["operations"][0]["before"], entry);   // the entry, not the whole server
    EXPECT_EQ(stored["operations"][0]["before_digest"], engine::detail::digest_of(entry));

    transport->requests.clear();
    transport->reply(200, child_reply(json::array({entry})));
    transport->reply(200, put(7));
    transport->reply(200, child_reply(json::array({reservation(7, "192.0.2.7", "00:00:5e:00:53:07", "new")})));
    json result = apply(id);
    ASSERT_TRUE(result["ok"]) << result.dump();
    EXPECT_EQ(result["data"]["operations"][0]["status"], "verified");
    // The parent and its other entries are never read or written.
    for (const auto& request: transport->requests) EXPECT_EQ(request.url, reservations + "/7");
    ASSERT_EQ(writes().size(), 1u);
    EXPECT_EQ(writes()[0].method, fortiapi::Method::Put);
    EXPECT_EQ(writes()[0].body, json({{"description", "new"}, {"circuit-id", ""}}).dump());

    json rollback = engine::detail::load_plan(paths, result["data"]["rollback"]["plan_id"].get<std::string>());
    const json& undo = rollback["operations"][0];
    EXPECT_EQ(undo["op"], "update");
    EXPECT_EQ(undo["key"], "7");
    EXPECT_EQ(undo["parent"], "1");
    EXPECT_EQ(undo["set"], json({{"description", "old"}, {"circuit-id", ""}}));
    EXPECT_EQ(undo["wire"]["path"], "cmdb/system.dhcp/server/1/reserved-address/7");
}

TEST_F(ChildTest, OnlyAChangeToThePlannedEntryMakesThePlanStale) {
    json entry = reservation(7, "192.0.2.7", "00:00:5e:00:53:07", "old");
    transport->reply(200, child_reply(json::array({entry})));
    json planned = plan({{"operations", {op({{"op", "update"}, {"key", "7"}, {"set", {{"description", "new"}}}})}}});
    ASSERT_TRUE(planned["ok"]) << planned.dump();
    transport->reply(200, child_reply(json::array({reservation(7, "192.0.2.77", "00:00:5e:00:53:07", "old")})));
    json result = apply(planned["data"]["id"]);
    EXPECT_EQ(result["error"]["code"], "stale_plan") << result.dump();
    EXPECT_EQ(result["error"]["details"]["reason"], "before_changed");
    EXPECT_EQ(result["error"]["details"]["parent"], "1");
    EXPECT_EQ(result["error"]["details"]["child"], "reserved-address");
    EXPECT_NE(result["error"]["message"].get<std::string>().find("system.dhcp/server 1 reserved-address 7 changed"),
              std::string::npos);
    EXPECT_TRUE(writes().empty());

    // The entry deleted since: stale too.
    transport->reply(200, child_reply(json::array({entry})));
    planned = plan({{"operations", {op({{"op", "delete"}, {"key", "7"}})}}});
    ASSERT_TRUE(planned["ok"]) << planned.dump();
    transport->reply(404, missing());
    EXPECT_EQ(apply(planned["data"]["id"])["error"]["code"], "stale_plan");
    EXPECT_TRUE(writes().empty());
}

TEST_F(ChildTest, DeleteIsUndoneByRecreatingTheEntryWithItsId) {
    json entry = reservation(7, "192.0.2.7", "00:00:5e:00:53:07", "nas");
    transport->reply(200, child_reply(json::array({entry})));
    json planned = plan({{"operations", {op({{"op", "delete"}, {"key", 7}})}}});
    ASSERT_TRUE(planned["ok"]) << planned.dump();
    const json& view = planned["data"]["operations"][0];
    EXPECT_EQ(view["wire"], json({{"method", "DELETE"}, {"path", "cmdb/system.dhcp/server/1/reserved-address/7"}, {"body", nullptr}}));
    EXPECT_NE(view["note"].get<std::string>().find("other entries are left alone"), std::string::npos);

    transport->reply(200, child_reply(json::array({entry})));
    transport->reply(200, deleted(7));
    transport->reply(404, missing());
    json result = apply(planned["data"]["id"]);
    ASSERT_TRUE(result["ok"]) << result.dump();
    EXPECT_EQ(result["data"]["operations"][0]["status"], "verified");
    EXPECT_EQ(writes().back().url, reservations + "/7");

    json rollback = engine::detail::load_plan(paths, result["data"]["rollback"]["plan_id"].get<std::string>());
    const json& undo = rollback["operations"][0];
    EXPECT_EQ(undo["op"], "create");
    EXPECT_EQ(undo["key"], "7");
    EXPECT_EQ(undo["object"]["id"], 7);
    EXPECT_EQ(undo["object"]["description"], "nas");
    EXPECT_FALSE(undo["object"].contains("q_origin_key"));
    EXPECT_EQ(undo["wire"]["path"], "cmdb/system.dhcp/server/1/reserved-address");

    transport->requests.clear();
    transport->reply(404, missing());   // still absent
    transport->reply(200, posted(7));
    transport->reply(200, child_reply(json::array({entry})));
    json undone = apply(rollback["id"]);
    ASSERT_TRUE(undone["ok"]) << undone.dump();
    EXPECT_EQ(undone["data"]["operations"][0]["status"], "verified");
    EXPECT_EQ(undone["data"]["operations"][0]["key"], "7");
    ASSERT_EQ(writes().size(), 1u);
    EXPECT_EQ(writes()[0].method, fortiapi::Method::Post);
    EXPECT_EQ(json::parse(writes()[0].body)["id"], 7);
}

TEST_F(ChildTest, PlanValidationErrors) {
    auto planned = [&](json operation) { return plan({{"operations", {operation}}}); };
    // Entry attributes, not the server's: refused before any request.
    json result = planned(op({{"op", "create"}, {"object", {{"ip", "192.0.2.5"}, {"lease-time", 60}}}}));
    ASSERT_EQ(result["error"]["code"], "validation") << result.dump();
    EXPECT_EQ(result["error"]["message"], "cmdb/system.dhcp/server reserved-address: unknown attribute(s): lease-time");
    result = planned(op({{"op", "create"}, {"object", {{"id", "seven"}}}}));
    EXPECT_EQ(result["error"]["code"], "validation");
    EXPECT_EQ(result["error"]["details"]["attribute"], "id");
    EXPECT_EQ(planned(op({{"op", "update"}, {"key", "7"}, {"child", "dns-service"}, {"set", {{"ip", "x"}}}}))["error"]["code"], "validation");
    EXPECT_EQ(planned(op({{"op", "update"}, {"key", "7"}, {"child", "ip-rnage"}, {"set", {{"ip", "x"}}}}))["error"]["details"]["suggestions"][0],
              "ip-range");
    EXPECT_EQ(planned(op({{"op", "update"}, {"key", "x"}, {"set", {{"ip", "192.0.2.5"}}}}))["error"]["code"], "validation");   // numeric id
    EXPECT_EQ(planned(op({{"op", "update"}, {"parent", "x"}, {"key", "7"}, {"set", {{"ip", "192.0.2.5"}}}}))["error"]["code"], "validation");

    // Shape: both parent and child, keys as today, strict fields.
    EXPECT_EQ(planned({{"op", "delete"}, {"resource", "system.dhcp/server"}, {"parent", "1"}, {"key", "7"}})["error"]["code"], "usage");
    EXPECT_EQ(planned({{"op", "delete"}, {"resource", "system.dhcp/server"}, {"child", "reserved-address"}, {"key", "7"}})["error"]["code"], "usage");
    EXPECT_EQ(planned(op({{"op", "delete"}}))["error"]["code"], "usage");                       // no entry key
    EXPECT_EQ(planned(op({{"op", "delete"}, {"key", "."}}))["error"]["code"], "usage");         // G13
    EXPECT_EQ(planned(op({{"op", "delete"}, {"parent", ".."}, {"key", "7"}}))["error"]["code"], "usage");
    EXPECT_EQ(planned(op({{"op", "delete"}, {"key", "7"}, {"child_key", "7"}}))["error"]["code"], "usage");
    EXPECT_EQ(planned({{"op", "action"}, {"resource", "monitor/system/dhcp/revoke"}, {"parent", "1"}, {"child", "x"}})["error"]["code"], "usage");
    EXPECT_EQ(planned({{"op", "update"}, {"resource", "system/global"}, {"parent", "1"}, {"child", "reserved-address"},
                       {"set", {{"hostname", "x"}}}})["error"]["code"], "usage");
    EXPECT_TRUE(transport->requests.empty());

    // The entry key cannot be changed by an update; one operation per entry.
    transport->reply(200, child_reply(json::array({reservation(7, "192.0.2.7", "00:00:5e:00:53:07")})));
    result = planned(op({{"op", "update"}, {"key", "7"}, {"set", {{"id", 8}}}}));
    EXPECT_EQ(result["error"]["code"], "validation");
    EXPECT_NE(result["error"]["message"].get<std::string>().find("key attribute id cannot be changed"), std::string::npos);
    result = plan({{"operations", {op({{"op", "update"}, {"key", "7"}, {"set", {{"description", "a"}}}}),
                                   op({{"op", "delete"}, {"key", "7"}})}}});
    EXPECT_EQ(result["error"]["code"], "usage");
    EXPECT_NE(result["error"]["message"].get<std::string>().find("more than once"), std::string::npos);
}

TEST_F(ChildTest, StoredChildPlansAreIntegrityChecked) {
    transport->reply(200, child_reply(json::array({reservation(7, "192.0.2.7", "00:00:5e:00:53:07")})));
    json planned = plan({{"operations", {op({{"op", "delete"}, {"key", "7"}})}}});
    ASSERT_TRUE(planned["ok"]) << planned.dump();
    std::string id = planned["data"]["id"];
    fs::path file = paths.state / "plans" / (id + ".json");
    json stored = engine::detail::load_plan(paths, id);

    // Re-targeted at another table attribute or parent (digest recomputed): the wire path no longer matches.
    for (auto [field, value]: {std::pair<const char*, json>{"child", "ip-range"}, {"parent", "2"}, {"child", "dns-service"},
                               {"parent", 1}}) {
        json changed = stored;
        changed["operations"][0][field] = value;
        changed["digest"] = engine::detail::plan_digest(changed);
        engine::detail::save_plan(paths, changed);
        json result = apply(id);
        EXPECT_EQ(result["error"]["code"], "policy_denied") << field;
        EXPECT_EQ(result["error"]["details"]["reason"], "tampered") << field;
    }
    // Without its child fields the operation would address the server itself.
    json changed = stored;
    changed["operations"][0].erase("child");
    changed["digest"] = engine::detail::plan_digest(changed);
    engine::detail::save_plan(paths, changed);
    EXPECT_EQ(apply(id)["error"]["details"]["reason"], "tampered");
    EXPECT_TRUE(writes().empty());
}

TEST_F(ChildTest, OrdinaryPlansCarryNoChildFields) {
    transport->reply(200, fake::envelope(json::array({{{"id", 1}, {"q_origin_key", 1}, {"lease-time", 600}}})));
    json planned = plan({{"operations", {{{"op", "update"}, {"resource", "system.dhcp/server"}, {"key", "1"},
                                          {"set", {{"lease-time", 300}}}}}}});
    ASSERT_TRUE(planned["ok"]) << planned.dump();
    json stored = engine::detail::load_plan(paths, planned["data"]["id"].get<std::string>());
    EXPECT_FALSE(stored["operations"][0].contains("parent"));
    EXPECT_FALSE(stored["operations"][0].contains("child"));
    EXPECT_EQ(stored["operations"][0]["wire"]["path"], "cmdb/system.dhcp/server/1");
    for (const auto& note: planned["data"]["notes"]) EXPECT_EQ(note.get<std::string>().find("replaces the whole"), std::string::npos);
}

TEST_F(ChildTest, WritingTheWholeTableThroughTheParentPointsAtChildOperations) {
    json server = {{"id", 1}, {"q_origin_key", 1}, {"reserved-address", {reservation(7, "192.0.2.7", "00:00:5e:00:53:07")}}};
    transport->reply(200, fake::envelope(json::array({server})));
    json planned = plan({{"operations", {{{"op", "update"}, {"resource", "system.dhcp/server"}, {"key", "1"},
                                          {"set", {{"reserved-address", json::array()}}}}}}});
    ASSERT_TRUE(planned["ok"]) << planned.dump();
    bool noted = false;
    for (const auto& note: planned["data"]["notes"])
        noted = noted || note.get<std::string>().find("--parent 1 --child reserved-address") != std::string::npos;
    EXPECT_TRUE(noted) << planned["data"]["notes"].dump();
    // The whole object stays the before-state: any change to the list since planning is drift.
    json stored = engine::detail::load_plan(paths, planned["data"]["id"].get<std::string>());
    EXPECT_EQ(stored["operations"][0]["before_digest"], engine::detail::digest_of(server));
    json changed = server;
    changed["reserved-address"].push_back(reservation(8, "192.0.2.8", "00:00:5e:00:53:08"));
    transport->reply(200, fake::envelope(json::array({changed})));
    EXPECT_EQ(apply(planned["data"]["id"])["error"]["code"], "stale_plan");
    EXPECT_TRUE(writes().empty());
}

// Revoking DHCP leases is a monitor action (untyped, as every monitor POST): body {"ip": [...]}, as
// Fortinet's fortios_monitor selector revoke.system.dhcp documents it. Elevated: it cuts no management
// path and restarts nothing.
TEST_F(ChildTest, RevokingLeasesIsAnElevatedMonitorAction) {
    transport->reply(200, status());
    json planned = plan({{"operations", {{{"op", "action"}, {"resource", "monitor/system/dhcp/revoke"},
                                          {"body", {{"ip", {"192.0.2.50"}}}}}}}});
    ASSERT_TRUE(planned["ok"]) << planned.dump();
    const json& view = planned["data"]["operations"][0];
    EXPECT_EQ(view["risk"], "elevated");
    EXPECT_EQ(view["wire"], json({{"method", "POST"}, {"path", "monitor/system/dhcp/revoke"}, {"body", {{"ip", {"192.0.2.50"}}}}}));

    transport->reply(200, status());
    transport->reply(200, {{"status", "success"}, {"http_status", 200}, {"serial", serial}, {"results", json::object()}});
    json result = apply(planned["data"]["id"]);
    ASSERT_TRUE(result["ok"]) << result.dump();
    EXPECT_EQ(result["data"]["operations"][0]["status"], "applied_unverified");
    ASSERT_EQ(writes().size(), 1u);
    EXPECT_EQ(writes()[0].url, base + "monitor/system/dhcp/revoke");
    EXPECT_EQ(writes()[0].body, R"({"ip":["192.0.2.50"]})");
}
