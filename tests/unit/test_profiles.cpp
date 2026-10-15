#include <forti/engine/engine.hpp>

#include <gtest/gtest.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <optional>

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

    // Sets (or, with nullptr, unsets) an environment variable for one scope.
    struct ScopedEnv {
        std::string name;
        std::optional<std::string> saved;
        ScopedEnv(std::string variable, const char* value) : name(std::move(variable)) {
            if (const char* old = std::getenv(name.c_str())) saved = old;
            if (value) ::setenv(name.c_str(), value, 1);
            else ::unsetenv(name.c_str());
        }
        ~ScopedEnv() {
            if (saved) ::setenv(name.c_str(), saved->c_str(), 1);
            else ::unsetenv(name.c_str());
        }
        ScopedEnv(const ScopedEnv&) = delete;
        ScopedEnv& operator=(const ScopedEnv&) = delete;
    };

    // A HOME of its own with every forti and XDG location variable unset.
    struct CleanHome {
        TempDir dir;
        ScopedEnv home{"HOME", dir.path.c_str()};
        ScopedEnv vars[7] = {{"FORTI_HOME", nullptr},      {"FORTI_CONFIG_DIR", nullptr}, {"FORTI_STATE_DIR", nullptr},
                             {"FORTI_CACHE_DIR", nullptr}, {"XDG_CONFIG_HOME", nullptr},  {"XDG_STATE_HOME", nullptr},
                             {"XDG_CACHE_HOME", nullptr}};

        void touch(const fs::path& file) const {
            fs::create_directories(file.parent_path());
            std::ofstream(file) << "{}\n";
        }
    };

    void write_mode(const fs::path& file, const std::string& text, unsigned permissions) {
        std::ofstream(file) << text;
        ::chmod(file.c_str(), permissions);
    }

}  // namespace

TEST(Home, DefaultsToDotFortiWithEverythingInside) {
    CleanHome env;
    Paths paths = Paths::from_env();
    fs::path home = env.dir.path / ".forti";
    EXPECT_EQ(paths.home, home);
    EXPECT_EQ(paths.config, home);
    EXPECT_EQ(paths.config_file(), home / "config.json");
    EXPECT_EQ(paths.state, home / "state");
    EXPECT_EQ(paths.cache, home / "cache");
    EXPECT_EQ(paths.certs(), home / "certs");
    EXPECT_FALSE(paths.legacy);
    // XDG variables alone change nothing without a pre-0.2 config.
    ScopedEnv xdg("XDG_CONFIG_HOME", (env.dir.path / "xdg").c_str());
    EXPECT_EQ(Paths::from_env().config, home);
}

TEST(Home, FortiHomeAndSingleLocationOverridesTakePrecedence) {
    CleanHome env;
    {
        ScopedEnv home("FORTI_HOME", "/srv/forti");
        Paths paths = Paths::from_env();
        EXPECT_EQ(paths.home, "/srv/forti");
        EXPECT_EQ(paths.config, "/srv/forti");
        EXPECT_EQ(paths.state, "/srv/forti/state");
        EXPECT_EQ(paths.certs(), "/srv/forti/certs");
        ScopedEnv state("FORTI_STATE_DIR", "/var/lib/forti");
        EXPECT_EQ(Paths::from_env().state, "/var/lib/forti");
        EXPECT_EQ(Paths::from_env().config, "/srv/forti");
    }
    {
        ScopedEnv config("FORTI_CONFIG_DIR", "/etc/forti");
        Paths paths = Paths::from_env();
        EXPECT_EQ(paths.config, "/etc/forti");
        EXPECT_EQ(paths.state, env.dir.path / ".forti" / "state");   // the rest stays in the home
        EXPECT_EQ(paths.certs(), env.dir.path / ".forti" / "certs");
    }
    ScopedEnv relative("FORTI_HOME", "forti");
    EXPECT_THROW((void) Paths::from_env(), Failure);   // never relative to the working directory
}

TEST(Home, APre02SetupStaysInUseUntilMigrated) {
    CleanHome env;
    env.touch(env.dir.path / ".config/forti/config.json");
    Paths paths = Paths::from_env();
    EXPECT_TRUE(paths.legacy);
    EXPECT_EQ(paths.home, env.dir.path / ".forti");
    EXPECT_EQ(paths.config, env.dir.path / ".config/forti");
    EXPECT_EQ(paths.state, env.dir.path / ".local/state/forti");
    EXPECT_EQ(paths.cache, env.dir.path / ".cache/forti");
    EXPECT_EQ(paths.certs(), env.dir.path / ".forti/certs");   // certificates are new: always in the home

    {   // The XDG variables locate a legacy setup.
        CleanHome xdg_env;
        fs::path xdg = xdg_env.dir.path / "xdg-config";
        ScopedEnv config("XDG_CONFIG_HOME", xdg.c_str());
        ScopedEnv state("XDG_STATE_HOME", (xdg_env.dir.path / "xdg-state").c_str());
        xdg_env.touch(xdg / "forti/config.json");
        Paths legacy = Paths::from_env();
        EXPECT_TRUE(legacy.legacy);
        EXPECT_EQ(legacy.config, xdg / "forti");
        EXPECT_EQ(legacy.state, xdg_env.dir.path / "xdg-state/forti");
    }
    {   // FORTI_HOME or FORTI_CONFIG_DIR means the operator chose: no legacy.
        ScopedEnv home("FORTI_HOME", (env.dir.path / "elsewhere").c_str());
        EXPECT_FALSE(Paths::from_env().legacy);
    }
    {
        ScopedEnv config("FORTI_CONFIG_DIR", (env.dir.path / "cfg").c_str());
        EXPECT_FALSE(Paths::from_env().legacy);
    }
    // Once the home has a config.json, it wins.
    env.touch(env.dir.path / ".forti/config.json");
    paths = Paths::from_env();
    EXPECT_FALSE(paths.legacy);
    EXPECT_EQ(paths.config, env.dir.path / ".forti");
}

TEST(Secrets, FileSourceReadsAnOwnerOnlyFileAndRefusesLooseOnes) {
    TempDir dir;
    auto store = memory_secret_store();
    fs::path file = dir.path / "client.pass";
    write_mode(file, "0123abcd\nignored\n", 0600);
    SecretRef ref = SecretRef::from_json({{"source", "file"}, {"path", file.string()}});
    EXPECT_EQ(ref.source, SecretRef::Source::file);
    EXPECT_EQ(SecretRef::from_json(ref.to_json()).path, file.string());
    EXPECT_EQ(resolve_secret(ref, "p/cert-password", *store, "h:443"), "0123abcd");   // first line, unbound

    for (unsigned loose: {0640u, 0604u, 0660u}) {
        ::chmod(file.c_str(), loose);
        try {
            (void) resolve_secret(ref, "p/cert-password", *store, "h:443");
            FAIL() << std::oct << loose;
        } catch (const Failure& failure) {
            EXPECT_EQ(failure.code(), Code::config);
            EXPECT_NE(std::string(failure.what()).find("chmod 600"), std::string::npos);
            EXPECT_EQ(std::string(failure.what()).find("0123abcd"), std::string::npos);
        }
    }
    ::chmod(file.c_str(), 0600);
    fs::path link = dir.path / "link.pass";
    fs::create_symlink(file, link);
    EXPECT_THROW((void) resolve_secret({SecretRef::Source::file, {}, {}, link.string()}, "a", *store, "h:443"), Failure);
    EXPECT_THROW((void) resolve_secret({SecretRef::Source::file, {}, {}, (dir.path / "missing").string()}, "a", *store, "h:443"), Failure);
    write_mode(dir.path / "empty.pass", "", 0600);
    EXPECT_THROW((void) resolve_secret({SecretRef::Source::file, {}, {}, (dir.path / "empty.pass").string()}, "a", *store, "h:443"), Failure);
    EXPECT_THROW((void) SecretRef::from_json({{"source", "file"}, {"path", "relative/client.pass"}}), Failure);
    EXPECT_THROW((void) SecretRef::from_json({{"source", "file"}}), Failure);

    // A profile carries it through config.json.
    Profile profile = Profile::from_json("p", {{"host", "h"}, {"client_cert", "/c.p12"}, {"cert_password", ref.to_json()}});
    EXPECT_EQ(profile.cert_password.path, file.string());
    EXPECT_EQ(Profile::from_json("p", profile.to_json()).cert_password.source, SecretRef::Source::file);
}

TEST(Profiles, RoundTripWithoutSecretsAndPrivateModes) {
    TempDir dir;
    Paths paths{dir.path / "config", dir.path / "state", dir.path / "cache", {}};
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
    Paths paths{dir.path / "config", dir.path / "state", dir.path / "cache", {}};
    auto store = file_secret_store(paths);
    store->put("home/api-key", "s3cret", "fw.home:443");
    EXPECT_EQ(mode(paths.config / "credentials"), 0700u);
    EXPECT_EQ(mode(paths.config / "credentials" / "home.api-key"), 0600u);
    EXPECT_EQ(store->get("home/api-key")->secret, "s3cret");
    EXPECT_EQ(store->get("home/api-key")->binding, "fw.home:443");
    ::chmod((paths.config / "credentials" / "home.api-key").c_str(), 0644);
    EXPECT_THROW((void) store->get("home/api-key"), Failure);
    EXPECT_TRUE(store->erase("home/api-key"));
}

TEST(Secrets, ResolutionNamesTheSourceNeverTheValue) {
    auto store = memory_secret_store();
    SecretRef ref{SecretRef::Source::env, "FORTI_TEST_UNSET_VARIABLE", {}, {}};
    try {
        (void) resolve_secret(ref, "home/api-key", *store, "h:443");
        FAIL();
    } catch (const Failure& failure) {
        EXPECT_EQ(failure.code(), Code::config);
        EXPECT_NE(std::string(failure.what()).find("FORTI_TEST_UNSET_VARIABLE"), std::string::npos);
    }
    ::setenv("FORTI_TEST_SECRET", "from-env", 1);
    EXPECT_EQ(resolve_secret({SecretRef::Source::env, "FORTI_TEST_SECRET", {}, {}}, "a", *store, "h:443"), "from-env");
    EXPECT_EQ(resolve_secret({SecretRef::Source::command, {}, {"printf", "from-command\\nignored"}, {}}, "a", *store, "h:443"),
              "from-command");
}

TEST(ErrorCodes, RoundTrip) {
    for (int c = 0; c <= static_cast<int>(Code::outcome_unknown) + 4; ++c) {
        auto name = to_string(static_cast<Code>(c));
        if (name == "internal" && c != 0) continue;   // past the last enumerator
        ASSERT_EQ(parse_code(name), static_cast<Code>(c)) << name;
    }
    EXPECT_EQ(exit_code(*parse_code("management_connectivity_lost")), 8);
    EXPECT_FALSE(parse_code("nope"));
}
