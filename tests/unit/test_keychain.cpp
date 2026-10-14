// The macOS Keychain store against the real login keychain. Off by default: it runs only with
// FORTI_TEST_KEYCHAIN=1, uses its own service name ("forti-test") and removes what it wrote.

#include <forti/engine/error.hpp>
#include <forti/engine/profile.hpp>

#include <gtest/gtest.h>

#include <cstdlib>
#include <string_view>

using namespace forti::engine;

TEST(Keychain, RoundTripWhenExplicitlyEnabled) {
    const char* enabled = std::getenv("FORTI_TEST_KEYCHAIN");
    if (!enabled || std::string_view(enabled) != "1") GTEST_SKIP() << "set FORTI_TEST_KEYCHAIN=1 to use the login keychain";
#ifndef __APPLE__
    GTEST_SKIP() << "the Keychain exists only on macOS";
#else
    auto store = keychain_secret_store("forti-test");
    const std::string account = "forti-cli-test/api-key";
    (void) store->erase(account);
    EXPECT_EQ(store->kind(), "keychain");
    EXPECT_FALSE(store->get(account));
    store->put(account, "first");
    EXPECT_EQ(store->get(account), "first");
    store->put(account, "second");   // update in place
    EXPECT_EQ(store->get(account), "second");
    EXPECT_TRUE(store->erase(account));
    EXPECT_FALSE(store->erase(account));
#endif
}

TEST(Keychain, DefaultStoreHonoursOverride) {
    Paths paths{"/nonexistent/forti-test/config", "/nonexistent/forti-test/state", "/nonexistent/forti-test/cache"};
    const char* saved = std::getenv("FORTI_SECRET_STORE");
    std::string previous = saved ? saved : "";
    ::setenv("FORTI_SECRET_STORE", "file", 1);
    EXPECT_EQ(default_secret_store(paths)->kind(), "file");
    ::setenv("FORTI_SECRET_STORE", "vault", 1);
    EXPECT_THROW(default_secret_store(paths), Failure);
    ::unsetenv("FORTI_SECRET_STORE");
#ifdef __APPLE__
    EXPECT_EQ(default_secret_store(paths)->kind(), "keychain");   // constructing it touches nothing
#else
    EXPECT_EQ(default_secret_store(paths)->kind(), "file");
#endif
    if (saved) ::setenv("FORTI_SECRET_STORE", previous.c_str(), 1);
}
