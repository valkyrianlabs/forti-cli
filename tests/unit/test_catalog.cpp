#include <forti/engine/catalog.hpp>
#include <forti/engine/engine.hpp>

#include <gtest/gtest.h>

using namespace forti::engine;

TEST(Catalog, ReflectsEveryGeneratedEndpoint) {
    const auto& catalog = Catalog::instance();
    std::size_t tables = 0, singletons = 0, monitors = 0;
    for (const auto& resource: catalog.resources()) {
        tables += resource.kind == Kind::table;
        singletons += resource.kind == Kind::singleton;
        monitors += resource.kind == Kind::monitor;
        EXPECT_TRUE(resource.typed()) << resource.path;
        if (resource.kind == Kind::table) { EXPECT_FALSE(resource.key.empty()) << resource.path; }
    }
    // forti-api 1.0.0: 487 cmdb endpoints (360 tables, 127 singletons) and 47 typed monitor GETs.
    EXPECT_EQ(tables, 360u);
    EXPECT_EQ(singletons, 127u);
    EXPECT_EQ(monitors, 47u);
}

TEST(Catalog, ResolvesNamesAndPaths) {
    const auto& catalog = Catalog::instance();
    const Resource* address = catalog.find("firewall/address");
    ASSERT_NE(address, nullptr);
    EXPECT_EQ(address->path, "cmdb/firewall/address");
    EXPECT_EQ(address->name(), "firewall/address");
    EXPECT_EQ(address->key, "name");
    EXPECT_EQ(catalog.find("cmdb/firewall/address"), address);
    EXPECT_EQ(catalog.find("/api/v2/cmdb/firewall/address/"), address);

    const Resource* policy = catalog.find("firewall/policy");
    ASSERT_NE(policy, nullptr);
    EXPECT_EQ(policy->key, "policyid");
    EXPECT_TRUE(policy->numeric_key);

    EXPECT_EQ(catalog.find("firewall.service/custom")->kind, Kind::table);
    EXPECT_EQ(catalog.find("system/global")->kind, Kind::singleton);
}

TEST(Catalog, UntypedMonitorPathsResolveButAreValidated) {
    const auto& catalog = Catalog::instance();
    Resource untyped = catalog.resolve("monitor/router/ipv4");
    EXPECT_EQ(untyped.kind, Kind::monitor);
    EXPECT_FALSE(untyped.typed());
    for (const char* bad: {"monitor/../cmdb/system/admin", "monitor/system/status?access_token=x", "monitor/a%2Fb",
                           "monitor/", "monitor//x", "monitor/x#y"}) {
        try {
            (void) catalog.resolve(bad);
            ADD_FAILURE() << bad << " was accepted";
        } catch (const Failure& failure) {
            EXPECT_EQ(failure.code(), Code::usage) << bad;
        }
    }
}

TEST(Catalog, UnknownResourcesSuggestAlternatives) {
    try {
        (void) Catalog::instance().resolve("firewall/adress");
        FAIL();
    } catch (const Failure& failure) {
        EXPECT_EQ(failure.code(), Code::unknown_resource);
        ASSERT_FALSE(failure.details()["suggestions"].empty());
    }
    try {
        (void) Catalog::instance().resolve("address");
        FAIL();
    } catch (const Failure& failure) {
        auto suggestions = failure.details()["suggestions"];
        EXPECT_NE(std::ranges::find(suggestions, "firewall/address"), suggestions.end()) << suggestions.dump();
    }
}

TEST(Catalog, FieldsComeFromTheSdkModels) {
    auto fields = Catalog::instance().find("firewall/address")->fields();
    ASSERT_EQ(fields.size(), 43u);
    EXPECT_EQ(fields[0].name, "name");
    EXPECT_EQ(fields[0].type, "string");
    auto type = std::ranges::find(fields, "type", &FieldInfo::name);
    EXPECT_EQ(type->reset, "\"ipmask\"");
    auto tagging = std::ranges::find(fields, "tagging", &FieldInfo::name);
    EXPECT_EQ(tagging->type, "table");
    EXPECT_EQ(tagging->children.size(), 3u);
}
