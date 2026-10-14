#include <forti/engine/engine.hpp>

#include <gtest/gtest.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>

#include <sys/stat.h>

using namespace forti::engine;
namespace fs = std::filesystem;

namespace {

    struct TempDir {
        fs::path path;
        TempDir() {
            std::string pattern = (fs::temp_directory_path() / "forti-test-XXXXXX").string();
            path = ::mkdtemp(pattern.data());
        }
        ~TempDir() { fs::remove_all(path); }
    };

    unsigned mode(const fs::path& path) {
        struct stat info{};
        ::stat(path.c_str(), &info);
        return info.st_mode & 0777;
    }

}  // namespace

TEST(Profiles, RoundTripWithoutSecretsAndPrivateModes) {
    TempDir dir;
    Paths paths{dir.path / "config", dir.path / "state", dir.path / "cache"};
    ProfileSet set;
    Profile home = Profile::from_json("home", {{"host", "fw.example.net"}, {"port", 8443}, {"vdom", "root"},
                                               {"api_key", {{"source", "env"}, {"env", "FORTI_HOME_KEY"}}}});
    set.profiles.emplace("home", home);
    set.default_profile = "home";
    ProfileStore store(paths);
    store.save(set);
    EXPECT_EQ(mode(paths.config), 0700u);
    EXPECT_EQ(mode(paths.config_file()), 0600u);

    ProfileSet loaded = store.load();
    const Profile& profile = loaded.select("");
    EXPECT_EQ(profile.host, "fw.example.net");
    EXPECT_EQ(profile.port, 8443u);
    EXPECT_EQ(profile.mode, Mode::read_only);   // no mutations unless the operator opts in
    EXPECT_EQ(profile.api_key.source, SecretRef::Source::env);
}

TEST(Profiles, ModesRoundTrip) {
    for (auto mode: {Mode::read_only, Mode::guarded, Mode::autonomous}) {
        Profile profile = Profile::from_json("p", {{"host", "h"}, {"mode", to_string(mode)}});
        EXPECT_EQ(profile.mode, mode);
        EXPECT_EQ(Profile::from_json("p", profile.to_json()).mode, mode);
    }
    EXPECT_THROW(Profile::from_json("p", {{"host", "h"}, {"mode", "yolo"}}), Failure);
}

TEST(Profiles, SecretsInConfigAreRefused) {
    EXPECT_THROW(Profile::from_json("x", {{"host", "h"}, {"token", "abc"}}), Failure);
    EXPECT_THROW(Profile::from_json("bad name", {{"host", "h"}}), Failure);
}

TEST(Secrets, FileStoreIsPrivateAndRefusesLooseModes) {
    TempDir dir;
    Paths paths{dir.path / "config", dir.path / "state", dir.path / "cache"};
    auto store = file_secret_store(paths);
    store->put("home/api-key", "s3cret");
    EXPECT_EQ(mode(paths.config / "credentials"), 0700u);
    EXPECT_EQ(mode(paths.config / "credentials" / "home.api-key"), 0600u);
    EXPECT_EQ(store->get("home/api-key"), "s3cret");
    ::chmod((paths.config / "credentials" / "home.api-key").c_str(), 0644);
    EXPECT_THROW((void) store->get("home/api-key"), Failure);
    EXPECT_TRUE(store->erase("home/api-key"));
}

TEST(Secrets, ResolutionNamesTheSourceNeverTheValue) {
    auto store = memory_secret_store();
    SecretRef ref{SecretRef::Source::env, "FORTI_TEST_UNSET_VARIABLE", {}};
    try {
        (void) resolve_secret(ref, "home/api-key", *store);
        FAIL();
    } catch (const Failure& failure) {
        EXPECT_EQ(failure.code(), Code::config);
        EXPECT_NE(std::string(failure.what()).find("FORTI_TEST_UNSET_VARIABLE"), std::string::npos);
    }
    ::setenv("FORTI_TEST_SECRET", "from-env", 1);
    EXPECT_EQ(resolve_secret({SecretRef::Source::env, "FORTI_TEST_SECRET", {}}, "a", *store), "from-env");
    EXPECT_EQ(resolve_secret({SecretRef::Source::command, {}, {"printf", "from-command\\nignored"}}, "a", *store),
              "from-command");
}
