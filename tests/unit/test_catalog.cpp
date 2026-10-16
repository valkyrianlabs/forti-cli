#include <forti/engine/catalog.hpp>
#include <forti/engine/engine.hpp>

#include <gtest/gtest.h>

#include <algorithm>

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

TEST(Catalog, LookupTakesTheSpellingsPeopleUse) {
    const auto& catalog = Catalog::instance();
    auto name = [&](std::string_view spelling) { return std::string(catalog.lookup(spelling).name()); };
    // Paths, as before.
    EXPECT_EQ(name("firewall/address"), "firewall/address");
    EXPECT_EQ(name("monitor/system/status"), "monitor/system/status");
    EXPECT_EQ(name("monitor/router/ipv4"), "monitor/router/ipv4");   // untyped monitors too
    // FortiOS CLI words, one string or one word each.
    EXPECT_EQ(name("firewall address"), "firewall/address");
    EXPECT_EQ(name("firewall service custom"), "firewall.service/custom");
    EXPECT_EQ(name("system interface"), "system/interface");
    EXPECT_EQ(name("  system   global "), "system/global");
    EXPECT_EQ(name("monitor system status"), "monitor/system/status");
    EXPECT_EQ(std::string(catalog.match({"vpn", "certificate", "ca"}).resource->name()), "vpn.certificate/ca");
    // An unambiguous tail: the last word, or the last words.
    EXPECT_EQ(name("address"), "firewall/address");
    EXPECT_EQ(name("firewall policy"), "firewall/policy");
    EXPECT_EQ(catalog.match({"policy"}).candidates,
              (std::vector<std::string>{"firewall/policy", "router/policy", "switch-controller.dsl/policy"}));
    EXPECT_EQ(name("service custom"), "firewall.service/custom");
    EXPECT_EQ(name("ADDRESS"), "firewall/address");
    // Configuration wins over a monitor with the same tail.
    auto interface = catalog.match({"interface"});
    ASSERT_TRUE(interface.resource || !interface.candidates.empty());

    // Ambiguous: every candidate, as suggestions.
    auto custom = catalog.match({"custom"});
    EXPECT_FALSE(custom.resource);
    EXPECT_GT(custom.candidates.size(), 1u);
    EXPECT_NE(std::ranges::find(custom.candidates, "firewall.service/custom"), custom.candidates.end());
    try {
        (void) catalog.lookup("custom");
        ADD_FAILURE() << "an ambiguous name resolved";
    } catch (const Failure& failure) {
        EXPECT_EQ(failure.code(), Code::unknown_resource);
        EXPECT_NE(std::string(failure.what()).find("firewall.service/custom"), std::string::npos) << failure.what();
        EXPECT_GT(failure.details()["candidates"].size(), 1u);
    }
    // Unknown: resolve's error with suggestions, as before.
    try {
        (void) catalog.lookup("firewall/adress");
        ADD_FAILURE();
    } catch (const Failure& failure) {
        EXPECT_EQ(failure.code(), Code::unknown_resource);
        EXPECT_EQ(failure.details()["suggestions"].front(), "firewall/address");
    }
    EXPECT_THROW((void) catalog.lookup("no such thing"), Failure);
    EXPECT_THROW((void) catalog.lookup(""), Failure);
    // A word with '/' is never part of CLI words: it is a path or a key.
    EXPECT_FALSE(catalog.match({"firewall/address", "web"}).resource);
    EXPECT_TRUE(catalog.match({"firewall", "address", "LAN 10.0.0.0/24"}).candidates.empty());
    // Plans keep exact names.
    EXPECT_THROW((void) catalog.resolve("address"), Failure);
    EXPECT_THROW((void) catalog.resolve("firewall address"), Failure);
}

TEST(Catalog, KeyedPathsNameATableAndAKey) {
    const auto& catalog = Catalog::instance();
    auto keyed = catalog.keyed("firewall/address/web");
    ASSERT_TRUE(keyed);
    EXPECT_EQ(keyed->resource->name(), "firewall/address");
    EXPECT_EQ(keyed->key, "web");
    keyed = catalog.keyed("firewall/address/LAN 10.0.0.0/24");   // a key with '/'
    ASSERT_TRUE(keyed);
    EXPECT_EQ(keyed->key, "LAN 10.0.0.0/24");
    keyed = catalog.keyed("/api/v2/cmdb/firewall.service/custom/HTTPS");
    ASSERT_TRUE(keyed);
    EXPECT_EQ(keyed->resource->name(), "firewall.service/custom");
    EXPECT_EQ(keyed->key, "HTTPS");
    EXPECT_EQ(catalog.keyed("firewall/policy/7")->key, "7");
    EXPECT_FALSE(catalog.keyed("firewall/address"));        // a resource itself
    EXPECT_FALSE(catalog.keyed("firewall/address/"));       // no key
    EXPECT_FALSE(catalog.keyed("system/global/x"));         // singletons have no keyed objects
    EXPECT_FALSE(catalog.keyed("monitor/system/status/x")); // monitor paths are never split
    EXPECT_FALSE(catalog.keyed("nothing/here/x"));
}

TEST(Catalog, ClosestNamesFindTypos) {
    std::vector<std::string> fields = {"name", "color", "comment", "subnet", "type", "uuid"};
    EXPECT_EQ(closest_names("colour", fields), std::vector<std::string>{"color"});
    EXPECT_EQ(closest_names("subnett", fields).front(), "subnet");
    EXPECT_EQ(closest_names("comments", fields).front(), "comment");
    EXPECT_TRUE(closest_names("zzzzzz", fields).empty());
    EXPECT_LE(closest_names("e", fields, 2).size(), 2u);
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
