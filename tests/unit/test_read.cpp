#include <fake_transport.hpp>

#include <gtest/gtest.h>

using namespace forti;
using json = nlohmann::json;

namespace {

    struct ReadTest : ::testing::Test {
        std::shared_ptr<fake::FakeTransport> transport = std::make_shared<fake::FakeTransport>();
        engine::Engine sut{fake::options(transport)};

        json run(const json& request) {
            return engine::Engine::envelope([&] { return sut.read(request); });
        }
    };

}  // namespace

TEST_F(ReadTest, ListsThroughTheSdkClientWithPagingAndProjection) {
    transport->reply(200, fake::envelope(json::array({{{"name", "a"}, {"subnet", "192.0.2.0 255.255.255.0"}},
                                                          {{"name", "b"}, {"subnet", "198.51.100.0 255.255.255.0"}}})));
    json result = run({{"resource", "firewall/address"}, {"fields", {"name", "subnet"}}, {"filter", "type==ipmask"}, {"count", 2}});
    ASSERT_TRUE(result["ok"]) << result.dump();
    EXPECT_EQ(result["data"].size(), 2u);
    EXPECT_EQ(result["meta"]["next_start"], 2);
    EXPECT_EQ(result["meta"]["device"]["serial"], "FGT60FTK00000000");

    ASSERT_EQ(transport->requests.size(), 1u);
    const auto& request = transport->requests[0];
    EXPECT_EQ(request.method, fortiapi::Method::Get);
    EXPECT_EQ(request.url, "https://fortigate.test:8443/api/v2/cmdb/firewall/address"
                           "?format=name%7Csubnet&filter=type%3D%3Dipmask&start=0&count=2");
    EXPECT_NE(std::ranges::find(request.headers, "Authorization: Bearer test-key"), request.headers.end());
}

TEST_F(ReadTest, KeyedReadEncodesTheKeyAndReturnsOneObject) {
    transport->reply(200, fake::envelope(json::array({{{"name", "LAN 10.0.0.0/24"}}})));
    json result = run({{"resource", "firewall/address"}, {"key", "LAN 10.0.0.0/24"}});
    ASSERT_TRUE(result["ok"]) << result.dump();
    EXPECT_EQ(result["data"]["name"], "LAN 10.0.0.0/24");
    EXPECT_EQ(transport->requests[0].url, "https://fortigate.test:8443/api/v2/cmdb/firewall/address/LAN%2010.0.0.0%2F24");
}

TEST_F(ReadTest, UnknownAttributesAreRejectedBeforeAnyRequest) {
    json result = run({{"resource", "firewall/address"}, {"fields", {"name", "subnett"}}});
    EXPECT_FALSE(result["ok"]);
    EXPECT_EQ(result["error"]["code"], "validation");
    result = run({{"resource", "firewall/address"}, {"filter", "colour==3"}});
    EXPECT_EQ(result["error"]["code"], "validation");
    result = run({{"resource", "firewall/address"}, {"filtr", "name==x"}});
    EXPECT_EQ(result["error"]["code"], "usage");
    result = run({{"resource", "firewall/address"}, {"params", {{"access_token", "x"}}}});
    EXPECT_EQ(result["error"]["code"], "usage");
    EXPECT_TRUE(transport->requests.empty());
}

TEST_F(ReadTest, ErrorsMapToStableCodes) {
    transport->reply(404, json{{"status", "error"}, {"http_status", 404}});
    EXPECT_EQ(run({{"resource", "firewall/address"}, {"key", "missing"}})["error"]["code"], "not_found");
    transport->reply(401, json{{"status", "error"}, {"http_status", 401}});
    EXPECT_EQ(run({{"resource", "firewall/address"}})["error"]["code"], "auth");
    transport->fail(7, true).fail(7, true).fail(7, true);   // a GET is retried, then gives up
    json result = run({{"resource", "system/global"}});
    EXPECT_EQ(result["error"]["code"], "connection");
    EXPECT_EQ(result["error"]["message"].get<std::string>().find("test-key"), std::string::npos);
}

TEST_F(ReadTest, MonitorReadsAreBoundedClientSide) {
    json rows = json::array();
    for (int i = 0; i < 120; ++i) rows.push_back({{"i", i}});
    transport->reply(200, fake::envelope(rows));
    json result = run({{"resource", "monitor/firewall/session"}});
    ASSERT_TRUE(result["ok"]) << result.dump();
    EXPECT_EQ(result["data"].size(), 50u);
    EXPECT_TRUE(result["meta"]["truncated"]);
    EXPECT_EQ(result["meta"]["total"], 120);
    EXPECT_EQ(result["meta"]["next_start"], 50);
    EXPECT_EQ(transport->requests[0].url, "https://fortigate.test:8443/api/v2/monitor/firewall/session");

    // The next page is windowed locally from the same (full) device reply; start/count never reach
    // the device, so a monitor that ignores them cannot make paging repeat itself.
    transport->reply(200, fake::envelope(rows));
    result = run({{"resource", "monitor/firewall/session"}, {"start", 100}, {"count", 50}});
    ASSERT_EQ(result["data"].size(), 20u);
    EXPECT_EQ(result["data"][0]["i"], 100);
    EXPECT_FALSE(result["meta"].contains("next_start"));
    EXPECT_EQ(transport->requests[1].url, "https://fortigate.test:8443/api/v2/monitor/firewall/session");
}

TEST_F(ReadTest, DiscoverResourceDescribesFieldsAndPolicy) {
    json result = engine::Engine::envelope([&] {
        return sut.discover({{"what", "resource"}, {"resource", "firewall/policy"}, {"fields", {"action"}}});
    });
    ASSERT_TRUE(result["ok"]) << result.dump();
    EXPECT_EQ(result["data"]["key"], "policyid");
    EXPECT_EQ(result["data"]["risk"], "elevated");
    EXPECT_EQ(result["data"]["fields"].size(), 1u);
    EXPECT_EQ(result["data"]["fields"][0]["default"], "deny");
    result = engine::Engine::envelope([&] { return sut.discover({{"what", "resource"}, {"resource", "system/interface"}}); });
    EXPECT_EQ(result["data"]["risk"], "critical");
    result = engine::Engine::envelope([&] { return sut.discover({{"what", "resource"}, {"resource", "firewall/address"}}); });
    EXPECT_EQ(result["data"]["risk"], "low");
    EXPECT_TRUE(transport->requests.empty());
}
