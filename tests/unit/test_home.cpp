// `forti home` (and migrate), `forti cert create|show|remove` with the real openssl command, and
// `forti profile set|rename|copy`. Every test runs against a temporary HOME / forti home and a
// memory secret store: never the user's home or login keychain. Network-free.

#include <cli_harness.hpp>

#include <certs.hpp>
#include <commands.hpp>
#include <process.hpp>
#include <tty.hpp>

#include <algorithm>
#include <fstream>
#include <optional>

#include <unistd.h>

using namespace forti;
using json = nlohmann::json;
namespace fs = std::filesystem;

namespace {

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

    unsigned mode_of(const fs::path& path) {
        struct stat info{};
        ::lstat(path.c_str(), &info);
        return info.st_mode & 0777;
    }

    std::string slurp(const fs::path& path) {
        std::ifstream in(path);
        return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
    }

    json check(const json& checks, std::string_view id) {
        for (const auto& c: checks)
            if (c["check"] == id) return c;
        return nullptr;
    }

    std::size_t count(const std::string& text, std::string_view needle) {
        std::size_t n = 0;
        for (auto at = text.find(needle); at != std::string::npos; at = text.find(needle, at + 1)) ++n;
        return n;
    }

    // A CLI whose forti home is <tmp>/home/.forti, with HOME pointing at <tmp>/home and every forti
    // and XDG location variable unset, so Paths::from_env() resolves inside the test directory.
    struct HomeCli : fake::Cli {
        fs::path user_home = dir.path / "home";
        ScopedEnv home_var{"HOME", (dir.path / "home").c_str()};
        ScopedEnv vars[7] = {{"FORTI_HOME", nullptr},      {"FORTI_CONFIG_DIR", nullptr}, {"FORTI_STATE_DIR", nullptr},
                             {"FORTI_CACHE_DIR", nullptr}, {"XDG_CONFIG_HOME", nullptr},  {"XDG_STATE_HOME", nullptr},
                             {"XDG_CACHE_HOME", nullptr}};

        HomeCli() {
            fs::create_directories(user_home);
            paths = engine::Paths::from_env();
        }

        fs::path forti_home() const { return user_home / ".forti"; }
    };

    // Writes a pre-0.2 setup: config.json and a file-store credential in ~/.config/forti, plans and
    // an audit log in ~/.local/state/forti, and ~/.cache/forti.
    void legacy_setup(const fs::path& user_home) {
        engine::Paths old{user_home / ".config/forti", user_home / ".local/state/forti", user_home / ".cache/forti", {}};
        engine::ProfileSet set;
        set.profiles.emplace("lab", engine::Profile::from_json("lab", {{"host", "fortigate.test"}}));
        set.default_profile = "lab";
        engine::ProfileStore(old).save(set);
        engine::file_secret_store(old)->put("lab/api-key", "legacy-key", "fortigate.test:443");
        engine::ensure_private_dir(old.state);   // as the engine creates it
        engine::ensure_private_dir(old.state / "plans");
        engine::write_private_file(old.state / "plans" / "p1.json", "{}\n");
        engine::write_private_file(old.state / "audit.jsonl", "{}\n");
        fs::create_directories(old.cache);
    }

}  // namespace

// ---- forti home ----

TEST_F(HomeCli, HomePrintsEveryLocation) {
    ASSERT_EQ(run({"--json", "home"}), 0) << err.str();
    json data = json_out()["data"];
    EXPECT_EQ(data["home"], forti_home().string());
    EXPECT_EQ(data["config_file"], (forti_home() / "config.json").string());
    EXPECT_EQ(data["credentials"], (forti_home() / "credentials").string());
    EXPECT_EQ(data["state"], (forti_home() / "state").string());
    EXPECT_EQ(data["cache"], (forti_home() / "cache").string());
    EXPECT_EQ(data["certs"], (forti_home() / "certs").string());
    EXPECT_EQ(data["legacy"], false);
    EXPECT_EQ(data["secret_store"], "memory");
    EXPECT_FALSE(fs::exists(forti_home()));   // showing creates nothing

    ASSERT_EQ(run({"home"}), 0);
    EXPECT_NE(out.str().find("forti home: ~/.forti"), std::string::npos) << out.str();
    EXPECT_NE(out.str().find("~/.forti/state/"), std::string::npos);
    EXPECT_EQ(out.str().find("legacy"), std::string::npos);
    EXPECT_EQ(run({"home", "frobnicate"}), 2);
}

TEST_F(HomeCli, ConfigureCreatesThePrivateHome) {
    device_replies();
    ASSERT_EQ(run({"configure", "--profile", "lab", "--host", "fortigate.test", "--api-key-stdin"}, "k\n"), 0) << err.str();
    EXPECT_EQ(mode_of(forti_home()), 0700u);
    EXPECT_EQ(mode_of(forti_home() / "config.json"), 0600u);
    EXPECT_FALSE(fs::exists(user_home / ".config/forti"));
}

TEST_F(HomeCli, ALegacySetupIsFlaggedByHomeConfigureAndDoctor) {
    legacy_setup(user_home);
    paths = engine::Paths::from_env();
    ASSERT_TRUE(paths.legacy);
    ASSERT_EQ(run({"--json", "home"}), 0);
    json data = json_out()["data"];
    EXPECT_EQ(data["legacy"], true);
    EXPECT_EQ(data["config_file"], (user_home / ".config/forti/config.json").string());
    EXPECT_NE(data["hint"].get<std::string>().find("forti home migrate"), std::string::npos);
    ASSERT_EQ(run({"home"}), 0);
    EXPECT_NE(out.str().find("legacy: "), std::string::npos);

    secrets->put("lab/api-key", "k", "fortigate.test:443");
    device_replies();
    ASSERT_EQ(run({"--json", "doctor"}), 0) << out.str();
    json home = check(json_out()["data"]["checks"], "home");
    EXPECT_EQ(home["status"], "warn");
    EXPECT_NE(home["hint"].get<std::string>().find("forti home migrate"), std::string::npos);

    // configure keeps using the legacy locations (and says how to move), creating no empty home.
    ASSERT_EQ(run({"configure", "--profile", "lab", "--mode", "guarded", "--skip-check", "--api-key-env", "K"}), 0) << err.str();
    EXPECT_NE(out.str().find("forti home migrate"), std::string::npos) << out.str();
    EXPECT_FALSE(fs::exists(forti_home()));
}

TEST_F(HomeCli, MigrateMovesEverythingKeepsModesAndIsIdempotent) {
    legacy_setup(user_home);
    ::chmod((user_home / ".cache/forti").c_str(), 0750);
    paths = engine::Paths::from_env();
    ASSERT_EQ(run({"--json", "home", "migrate"}), 0) << out.str() << err.str();
    json data = json_out()["data"];
    EXPECT_EQ(data["moved"].size(), 4u);
    EXPECT_EQ(data["moved"].back()["to"], (forti_home() / "config.json").string());   // config.json last

    EXPECT_EQ(mode_of(forti_home()), 0700u);
    EXPECT_EQ(mode_of(forti_home() / "config.json"), 0600u);
    EXPECT_EQ(mode_of(forti_home() / "credentials"), 0700u);
    EXPECT_EQ(mode_of(forti_home() / "credentials" / "lab.api-key"), 0600u);
    EXPECT_EQ(mode_of(forti_home() / "state"), 0700u);
    EXPECT_EQ(mode_of(forti_home() / "state" / "audit.jsonl"), 0600u);
    EXPECT_EQ(mode_of(forti_home() / "state" / "plans" / "p1.json"), 0600u);
    EXPECT_EQ(mode_of(forti_home() / "cache"), 0750u);
    EXPECT_FALSE(fs::exists(user_home / ".config/forti"));   // emptied, so removed
    EXPECT_FALSE(fs::exists(user_home / ".local/state/forti"));
    EXPECT_FALSE(fs::exists(user_home / ".cache/forti"));

    // The engine now resolves the home, and the file-stored key (still bound) moved with it.
    engine::Paths now = engine::Paths::from_env();
    EXPECT_FALSE(now.legacy);
    EXPECT_EQ(now.config, forti_home());
    EXPECT_EQ(engine::ProfileStore(now).load().select("").host, "fortigate.test");
    auto stored = engine::file_secret_store(now)->get("lab/api-key");
    ASSERT_TRUE(stored);
    EXPECT_EQ(stored->secret, "legacy-key");
    EXPECT_EQ(stored->binding, "fortigate.test:443");

    // Again: nothing to do, still success.
    paths = now;
    ASSERT_EQ(run({"--json", "home", "migrate"}), 0) << err.str();
    EXPECT_TRUE(json_out()["data"]["moved"].empty());
    ASSERT_EQ(run({"home", "migrate"}), 0);
    EXPECT_NE(out.str().find("already migrated"), std::string::npos) << out.str();
}

TEST_F(HomeCli, MigrateFinishesAnInterruptedRunAndKeepsForeignFiles) {
    legacy_setup(user_home);
    std::ofstream(user_home / ".config/forti/fw-ca.pem") << "-----BEGIN CERTIFICATE-----\n";
    // A previous run moved the credentials, then stopped.
    engine::ensure_private_dir(forti_home());
    fs::rename(user_home / ".config/forti/credentials", forti_home() / "credentials");
    paths = engine::Paths::from_env();
    ASSERT_TRUE(paths.legacy);
    ASSERT_EQ(run({"--json", "home", "migrate"}), 0) << out.str() << err.str();
    json data = json_out()["data"];
    EXPECT_EQ(data["moved"].size(), 3u);
    EXPECT_EQ(data["left_in_place"], json::array({(user_home / ".config/forti/fw-ca.pem").string()}));
    EXPECT_TRUE(fs::exists(user_home / ".config/forti/fw-ca.pem"));
    EXPECT_TRUE(fs::exists(forti_home() / "config.json"));
}

TEST_F(HomeCli, MigrateNeverOverwritesAHomeConfig) {
    legacy_setup(user_home);
    paths = engine::Paths::from_env();   // legacy
    engine::ensure_private_dir(forti_home());
    engine::write_private_file(forti_home() / "config.json", "{\"profiles\": {}}\n");
    std::string before = slurp(forti_home() / "config.json");
    EXPECT_EQ(run({"--json", "home", "migrate"}), 3);
    json error = json_out()["error"];
    EXPECT_NE(error["message"].get<std::string>().find("never overwrites"), std::string::npos) << error.dump();
    EXPECT_EQ(slurp(forti_home() / "config.json"), before);
    EXPECT_TRUE(fs::exists(user_home / ".config/forti/config.json"));
    EXPECT_TRUE(fs::exists(user_home / ".config/forti/credentials/lab.api-key"));   // nothing moved
    EXPECT_TRUE(fs::exists(user_home / ".local/state/forti/audit.jsonl"));

    // An explicit location override is the operator's choice: migrate leaves it alone.
    ScopedEnv config("FORTI_CONFIG_DIR", (user_home / ".config/forti").c_str());
    EXPECT_EQ(run({"home", "migrate"}), 3);
    EXPECT_NE(err.str().find("FORTI_CONFIG_DIR"), std::string::npos) << err.str();
}

// ---- forti cert ----

namespace {

    // Every openssl this machine has (macOS: LibreSSL in /usr/bin and Homebrew's OpenSSL), each to be
    // put alone on PATH.
    std::vector<fs::path> openssl_programs() {
        std::vector<fs::path> found;
        for (const char* candidate: {"/usr/bin/openssl", "/opt/homebrew/bin/openssl", "/opt/homebrew/opt/openssl@3/bin/openssl", "/usr/local/bin/openssl"}) {
            std::error_code error;
            if (fs::exists(candidate, error) && ::access(candidate, X_OK) == 0) {
                auto real = fs::canonical(candidate, error);
                if (std::ranges::none_of(found, [&](const fs::path& p) { return fs::canonical(p, error) == real; }))
                    found.emplace_back(candidate);
            }
        }
        return found;
    }

    struct CertCli : fake::Cli {
        fake::TempDir bin;
        std::optional<ScopedEnv> path_var;

        void SetUp() override {
            fs::path home = dir.path / "forti";
            paths = {home, home / "state", home / "cache", home};
            device_replies();
            ASSERT_EQ(run({"configure", "--profile", "lab", "--host", "fortigate.test", "--api-key-stdin", "--default"}, "lab-key\n"), 0)
                    << err.str();
            transport->requests.clear();
        }

        // PATH holds only `program`, as "openssl".
        void use(const fs::path& program) {
            fs::remove(bin.path / "openssl");
            fs::create_symlink(program, bin.path / "openssl");
            path_var.emplace("PATH", bin.path.c_str());
        }

        fs::path dir_of(const std::string& profile) const { return paths.certs() / profile; }

        install::RunResult openssl(std::vector<std::string> args) const {
            args.insert(args.begin(), (bin.path / "openssl").string());
            return install::run_process(args);
        }
    };

}  // namespace

TEST_F(CertCli, CreateShowUseRemoveWithEveryLocalOpenssl) {
    auto programs = openssl_programs();
    if (programs.empty()) GTEST_SKIP() << "no openssl on this machine";
    fs::path forti_ca = paths.home / "ca";
    for (const auto& program: programs) {
        SCOPED_TRACE(program.string());
        use(program);
        fs::remove_all(forti_ca);
        fs::path dir = dir_of("lab");
        // Without NAME, for the default profile; issued by the forti CA, made now.
        ASSERT_EQ(run({"--json", "cert", "create", "--days", "30"}), 0) << out.str() << err.str();
        std::string printed = out.str();
        json data = json_out()["data"];

        // Files and modes.
        EXPECT_EQ(mode_of(paths.certs()), 0700u);
        EXPECT_EQ(mode_of(dir), 0700u);
        EXPECT_EQ(mode_of(forti_ca), 0700u);
        EXPECT_EQ(mode_of(forti_ca / "ca.key"), 0600u);
        EXPECT_FALSE(fs::exists(dir / "ca"));   // the forti CA's key stays in one place
        EXPECT_EQ(slurp(dir / "ca.crt"), slurp(forti_ca / "ca.crt"));
        EXPECT_EQ(mode_of(dir / "client.pass"), 0600u);
        EXPECT_EQ(mode_of(dir / "client.p12"), 0600u);
        EXPECT_TRUE(fs::is_regular_file(dir / "client.crt"));
        for (const char* scratch: {"client.key", "client.csr", "client.ext", "ca.srl"}) EXPECT_FALSE(fs::exists(dir / scratch)) << scratch;
        EXPECT_TRUE(std::ranges::none_of(fs::directory_iterator(paths.certs()),
                                         [](const auto& entry) { return entry.path().filename().string().starts_with("."); }));
        EXPECT_TRUE(std::ranges::none_of(fs::directory_iterator(paths.home),
                                         [](const auto& entry) { return entry.path().filename().string().starts_with("."); }));

        // The profile points at them; the password comes from client.pass.
        auto lab = saved().profiles.at("lab");
        EXPECT_EQ(lab.client_cert, (dir / "client.p12").string());
        EXPECT_EQ(lab.cert_password.source, engine::SecretRef::Source::file);
        EXPECT_EQ(lab.cert_password.path, (dir / "client.pass").string());
        std::string password = engine::resolve_secret(lab.cert_password, "lab/cert-password", *secrets, "");
        EXPECT_EQ(password.size(), 48u);
        EXPECT_EQ(printed.find(password), std::string::npos);   // never printed, never in JSON
        EXPECT_EQ(slurp(paths.config_file()).find(password), std::string::npos);
        EXPECT_EQ(data["password_command"], "cat " + (dir / "client.pass").string());
        EXPECT_EQ(data["profile"], "lab");
        EXPECT_EQ(data["cn"], "forti-lab");
        EXPECT_EQ(data["issuer"], "forti CA");
        EXPECT_EQ(data["forti_ca_created"], true);
        EXPECT_EQ(data["fingerprint_sha256"].get<std::string>().size(), 95u);   // 32 bytes as XX:…
        std::string ca_name = data["fortigate"]["ca_name"];
        EXPECT_TRUE(ca_name.starts_with("forti-ca-")) << ca_name;

        // The .p12 opens with the password and holds the client certificate, its key and the forti CA,
        // with the legacy PBE every consumer reads.
        auto dump = openssl({"pkcs12", "-in", (dir / "client.p12").string(), "-passin", "file:" + (dir / "client.pass").string(), "-nodes"});
        ASSERT_TRUE(dump.ok()) << dump.err;
        EXPECT_EQ(count(dump.out, "BEGIN CERTIFICATE"), 2u);
        EXPECT_EQ(count(dump.out, "PRIVATE KEY-----"), 2u);   // BEGIN and END
        EXPECT_NE(dump.out.find("forti CA "), std::string::npos);
        auto info = openssl({"pkcs12", "-in", (dir / "client.p12").string(), "-passin", "file:" + (dir / "client.pass").string(),
                             "-info", "-noout"});
        ASSERT_TRUE(info.ok()) << info.err;
        std::string details = info.out + info.err;
        EXPECT_NE(details.find("pbeWithSHA1And3-KeyTripleDES-CBC"), std::string::npos) << details;
        EXPECT_EQ(details.find("AES"), std::string::npos) << details;
        EXPECT_EQ(openssl({"pkcs12", "-in", (dir / "client.p12").string(), "-passin", "pass:wrong", "-nodes"}).ok(), false);
        auto verify = openssl({"verify", "-CAfile", (forti_ca / "ca.crt").string(), (dir / "client.crt").string()});
        EXPECT_TRUE(verify.ok()) << verify.out << verify.err;
        auto purpose = openssl({"x509", "-in", (dir / "client.crt").string(), "-noout", "-text"});
        EXPECT_NE(purpose.out.find("TLS Web Client Authentication"), std::string::npos);

        // The FortiGate steps use only keywords of the FortiOS 7.4.8 schema, with the CA inline.
        std::string steps;
        for (const auto& line: data["fortigate"]["steps"]) steps += line.get<std::string>() + "\n";
        for (std::string keyword: {std::string("config vpn certificate ca"), "edit \"" + ca_name + "\"", std::string("set ca \"-----BEGIN CERTIFICATE-----"),
                                   std::string("-----END CERTIFICATE-----\""), std::string("once per FortiGate"),
                                   std::string("config user peer\n"), std::string("edit \"forti-lab\""), "set ca \"" + ca_name + "\"",
                                   std::string("set cn \"forti-lab\""), std::string("config user peergrp"), std::string("edit \"forti-lab-peers\""),
                                   std::string("set member \"forti-lab\""), std::string("config system api-user"), std::string("set peer-auth enable"),
                                   std::string("set peer-group \"forti-lab-peers\"")})
            EXPECT_NE(steps.find(keyword), std::string::npos) << keyword << "\n" << steps;
        EXPECT_NE(steps.find(cli::trim(slurp(forti_ca / "ca.crt"))), std::string::npos);

        // Without --force an existing certificate stays.
        std::string client = slurp(dir / "client.crt");
        EXPECT_EQ(run({"cert", "create"}), 3);
        EXPECT_NE(err.str().find("--force"), std::string::npos);
        EXPECT_EQ(slurp(dir / "client.crt"), client);

        // Renewal from the forti CA: same CA and CN, so the FortiGate needs no change.
        std::string ca = slurp(forti_ca / "ca.crt");
        ASSERT_EQ(run({"cert", "create", "--force"}), 0) << err.str();
        std::string text = out.str();
        EXPECT_NE(text.find("Replaced"), std::string::npos);
        EXPECT_NE(text.find("needs no change"), std::string::npos) << text;
        EXPECT_NE(text.find("forti doctor --profile lab"), std::string::npos);
        EXPECT_NE(slurp(dir / "client.crt"), client);
        EXPECT_EQ(slurp(forti_ca / "ca.crt"), ca);
        password = engine::resolve_secret(saved().profiles.at("lab").cert_password, "a", *secrets, "");
        EXPECT_EQ(text.find(password), std::string::npos);

        // A named certificate needs no profile; one with its own CA.
        ASSERT_EQ(run({"cert", "create", "edge", "--own-ca"}), 0) << err.str();
        text = out.str();
        EXPECT_EQ(mode_of(dir_of("edge") / "ca" / "ca.key"), 0600u);
        for (const char* keyword: {"edit \"forti-edge-ca\"", "set ca \"forti-edge-ca\"", "set cn \"forti-edge\"", "forti cert use edge"})
            EXPECT_NE(text.find(keyword), std::string::npos) << keyword << "\n" << text;
        EXPECT_EQ(text.find("once per FortiGate"), std::string::npos);
        ASSERT_EQ(run({"cert", "create", "spare"}), 0) << err.str();
        EXPECT_EQ(saved().profiles.at("lab").client_cert, (dir / "client.p12").string());   // untouched

        // list
        ASSERT_EQ(run({"--json", "cert", "list"}), 0) << err.str();
        json listed = json_out()["data"];
        EXPECT_EQ(listed["forti_ca"]["exists"], true);
        EXPECT_EQ(listed["forti_ca"]["fortigate_name"], ca_name);
        ASSERT_EQ(listed["certificates"].size(), 3u);
        EXPECT_EQ(listed["certificates"][0]["name"], "edge");
        EXPECT_EQ(listed["certificates"][0]["issuer"], "own CA");
        EXPECT_EQ(listed["certificates"][1]["name"], "lab");
        EXPECT_EQ(listed["certificates"][1]["used_by"], json::array({"lab"}));
        EXPECT_EQ(listed["certificates"][2]["issuer"], "forti CA");
        EXPECT_EQ(listed["certificates"][2]["used_by"], json::array());
        ASSERT_EQ(run({"cert", "list"}), 0);
        EXPECT_NE(out.str().find(ca_name), std::string::npos) << out.str();

        // show: NAME, else the default profile's certificate.
        ASSERT_EQ(run({"--json", "cert", "show"}), 0) << err.str();
        json shown = json_out()["data"];
        EXPECT_EQ(shown["name"], "lab");
        EXPECT_NE(shown["subject"].get<std::string>().find("forti-lab"), std::string::npos);
        EXPECT_EQ(shown["expired"], false);
        EXPECT_GE(shown["days_left"].get<long long>(), 1095 - 1);
        EXPECT_EQ(shown["profiles"][0]["profile"], "lab");
        EXPECT_EQ(shown["files"]["client_pass"]["mode"], "0600");
        EXPECT_EQ(out.str().find(password), std::string::npos);
        ASSERT_EQ(run({"cert", "show", "edge"}), 0);
        EXPECT_NE(out.str().find("SHA-256"), std::string::npos);
        EXPECT_NE(out.str().find("not used by a profile"), std::string::npos);

        // use: the profile switches certificate; the old one stays.
        ASSERT_EQ(run({"cert", "use", "spare"}), 0) << err.str();
        EXPECT_NE(out.str().find("forti-ca-"), std::string::npos);
        lab = saved().profiles.at("lab");
        EXPECT_EQ(lab.client_cert, (dir_of("spare") / "client.p12").string());
        EXPECT_EQ(lab.cert_password.path, (dir_of("spare") / "client.pass").string());
        EXPECT_TRUE(fs::exists(dir));
        EXPECT_EQ(run({"cert", "use", "nope"}), 3);
        ASSERT_EQ(run({"cert", "use", "lab", "--profile", "lab"}), 0) << err.str();

        // doctor resolves the file-sourced password and finds the .p12.
        device_replies();
        ASSERT_EQ(run({"--json", "doctor"}), 0) << out.str();
        json checks = json_out()["data"]["checks"];
        EXPECT_EQ(check(checks, "secrets")["status"], "pass");
        EXPECT_NE(check(checks, "secrets")["message"].get<std::string>().find("client.pass"), std::string::npos);
        EXPECT_EQ(check(checks, "tls_files")["status"], "pass");

        // remove: the default profile's certificate, then named ones. The forti CA stays.
        ASSERT_EQ(run({"--json", "cert", "remove"}), 0) << err.str();
        EXPECT_EQ(json_out()["data"]["profiles_updated"], json::array({"lab"}));
        EXPECT_FALSE(fs::exists(dir));
        lab = saved().profiles.at("lab");
        EXPECT_TRUE(lab.client_cert.empty());
        EXPECT_EQ(lab.cert_password.source, engine::SecretRef::Source::none);
        EXPECT_EQ(run({"cert", "show"}), 3);
        EXPECT_EQ(run({"cert", "remove"}), 3);
        ASSERT_EQ(run({"cert", "remove", "edge"}), 0) << err.str();
        ASSERT_EQ(run({"cert", "remove", "spare"}), 0) << err.str();
        EXPECT_TRUE(fs::exists(forti_ca / "ca.key"));
    }
}

TEST_F(CertCli, CertificatesNeedNoProfile) {
    auto programs = openssl_programs();
    if (programs.empty()) GTEST_SKIP() << "no openssl on this machine";
    use(programs.front());
    ASSERT_EQ(run({"profile", "remove", "lab"}), 0) << err.str();
    ASSERT_TRUE(saved().profiles.empty());

    // No profile at all: the certificate is named "default".
    ASSERT_EQ(run({"--json", "cert", "create"}), 0) << out.str() << err.str();
    json data = json_out()["data"];
    EXPECT_EQ(data["name"], "default");
    EXPECT_TRUE(data["profile"].is_null());
    EXPECT_EQ(data["password_command"], "cat " + (dir_of("default") / "client.pass").string());
    ASSERT_EQ(run({"cert", "create", "fw"}), 0) << err.str();
    EXPECT_NE(out.str().find("forti cert use fw --profile NAME"), std::string::npos) << out.str();
    EXPECT_EQ(run({"cert", "create", "other", "--keychain"}), 2);   // a stored password belongs to a profile

    // configure picks it up by name; the password comes from its client.pass.
    device_replies();
    ASSERT_EQ(run({"--json", "configure", "--profile", "fw01", "--host", "fortigate.test", "--api-key-stdin", "--cert", "default"}, "k\n"), 0)
            << err.str();
    EXPECT_EQ(json_out()["data"]["client_cert"], "certificate \"default\"");
    // and a second device reuses it.
    ASSERT_EQ(run({"configure", "--profile", "fw02", "--host", "fw02.test", "--api-key-stdin", "--cert", "default", "--skip-check"}, "k\n"), 0)
            << err.str();
    auto set = saved();
    for (const char* name: {"fw01", "fw02"}) {
        EXPECT_EQ(set.profiles.at(name).client_cert, (dir_of("default") / "client.p12").string()) << name;
        EXPECT_EQ(set.profiles.at(name).cert_password.source, engine::SecretRef::Source::file) << name;
        EXPECT_EQ(set.profiles.at(name).cert_password.path, (dir_of("default") / "client.pass").string()) << name;
    }
    ASSERT_EQ(run({"--json", "cert", "list"}), 0);
    EXPECT_EQ(json_out()["data"]["certificates"][0]["used_by"], json::array({"fw01", "fw02"}));

    EXPECT_EQ(run({"configure", "--profile", "fw03", "--host", "x.test", "--api-key-env", "K", "--cert", "nope", "--skip-check"}), 3);
    EXPECT_EQ(run({"configure", "--profile", "fw03", "--host", "x.test", "--api-key-env", "K", "--cert", "fw", "--client-cert",
                   (dir_of("fw") / "client.p12").string(), "--skip-check"}), 2);
    EXPECT_FALSE(saved().profiles.contains("fw03"));

    // remove detaches every profile that used it.
    ASSERT_EQ(run({"--json", "cert", "remove", "default"}), 0) << err.str();
    EXPECT_EQ(json_out()["data"]["profiles_updated"], json::array({"fw01", "fw02"}));
    EXPECT_TRUE(saved().profiles.at("fw02").client_cert.empty());
}

TEST_F(CertCli, KeychainOptionKeepsThePasswordInTheSecretStore) {
    auto programs = openssl_programs();
    if (programs.empty()) GTEST_SKIP() << "no openssl on this machine";
    use(programs.front());
    ASSERT_EQ(run({"--json", "cert", "create", "--keychain"}), 0) << out.str() << err.str();
    json data = json_out()["data"];
    EXPECT_FALSE(fs::exists(dir_of("lab") / "client.pass"));
    EXPECT_FALSE(data["files"].contains("client_pass"));
    auto lab = saved().profiles.at("lab");
    EXPECT_EQ(lab.cert_password.source, engine::SecretRef::Source::store);
    auto stored = secrets->get("lab/cert-password");
    ASSERT_TRUE(stored);
    EXPECT_EQ(stored->binding, "fortigate.test:443");
    EXPECT_EQ(out.str().find(stored->secret), std::string::npos);
    EXPECT_EQ(data["password_source"], "memory store");

    // The stored password opens the .p12 (written to a private temp file only for this check).
    fs::path pass = dir.path / "check.pass";
    engine::write_private_file(pass, stored->secret + "\n");
    EXPECT_TRUE(openssl({"pkcs12", "-in", (dir_of("lab") / "client.p12").string(), "-passin", "file:" + pass.string(), "-nodes"}).ok());

    // Another profile reusing it gets the password from the store too.
    ASSERT_EQ(run({"configure", "--profile", "edge", "--host", "edge.test", "--api-key-env", "EDGE_KEY", "--cert", "lab", "--skip-check"}), 0)
            << err.str();
    EXPECT_EQ(saved().profiles.at("edge").cert_password.source, engine::SecretRef::Source::store);
    ASSERT_TRUE(secrets->get("edge/cert-password"));
    EXPECT_EQ(secrets->get("edge/cert-password")->secret, stored->secret);
    EXPECT_EQ(secrets->get("edge/cert-password")->binding, "edge.test:443");

    // Back to a file: the stored password is erased.
    ASSERT_EQ(run({"cert", "create", "--force"}), 0) << err.str();
    EXPECT_FALSE(secrets->get("lab/cert-password"));
    EXPECT_EQ(saved().profiles.at("lab").cert_password.source, engine::SecretRef::Source::file);

    // remove erases stored passwords of every profile using it.
    ASSERT_EQ(run({"cert", "create", "--force", "--keychain"}), 0) << err.str();
    ASSERT_EQ(run({"cert", "remove"}), 0) << err.str();
    EXPECT_FALSE(secrets->get("lab/cert-password"));
    EXPECT_FALSE(secrets->get("edge/cert-password"));
}

TEST_F(CertCli, CreateNeedsOpensslAndValidNames) {
    path_var.emplace("PATH", bin.path.c_str());   // a PATH without openssl
    EXPECT_EQ(run({"--json", "cert", "create"}), 3);
    EXPECT_NE(json_out()["error"]["details"]["hint"].get<std::string>().find("install openssl"), std::string::npos);
    EXPECT_FALSE(fs::exists(dir_of("lab")));
    EXPECT_FALSE(fs::exists(paths.home / "ca"));
    EXPECT_EQ(saved().profiles.at("lab").client_cert, "");
    EXPECT_EQ(run({"cert", "create", "--profile", "nope"}), 3);
    EXPECT_EQ(run({"cert", "create", "--profile", "../x"}), 2);
    EXPECT_EQ(run({"cert", "create", "../x"}), 2);
    EXPECT_EQ(run({"cert", "create", "a", "b"}), 2);
    EXPECT_EQ(run({"cert", "show", "--days", "3"}), 2);
    EXPECT_EQ(run({"cert", "use"}), 2);
    EXPECT_EQ(run({"cert"}), 2);
    EXPECT_EQ(run({"cert", "create", "--days", "0"}), 2);
    EXPECT_EQ(run({"cert", "create", "--days", "9000"}), 3);   // missing openssl first; see below for the CA limit
}

TEST_F(CertCli, TheFortiCaLimitsTheValidity) {
    auto programs = openssl_programs();
    if (programs.empty()) GTEST_SKIP() << "no openssl on this machine";
    use(programs.front());
    EXPECT_EQ(run({"--json", "cert", "create", "--days", "9000"}), 2);
    EXPECT_NE(json_out()["error"]["details"]["hint"].get<std::string>().find("--own-ca"), std::string::npos);
    EXPECT_FALSE(fs::exists(dir_of("lab")));
    ASSERT_EQ(run({"cert", "create", "--days", "9000", "--own-ca"}), 0) << err.str();
}

// ---- configure --cert-password-file ----

TEST_F(CertCli, ConfigureTakesAnOwnerOnlyPasswordFile) {
    fs::path p12 = dir.path / "client.p12", pass = dir.path / "client.pass";
    std::ofstream(p12) << "p12";
    std::ofstream(pass) << "pw\n";
    ::chmod(pass.c_str(), 0644);
    EXPECT_EQ(run({"configure", "--profile", "lab", "--client-cert", p12.string(), "--cert-password-file", pass.string(), "--skip-check"}), 3);
    EXPECT_NE(err.str().find("readable by other users"), std::string::npos) << err.str();
    ::chmod(pass.c_str(), 0600);
    ASSERT_EQ(run({"configure", "--profile", "lab", "--client-cert", p12.string(), "--cert-password-file", pass.string(), "--skip-check"}), 0)
            << err.str();
    auto lab = saved().profiles.at("lab");
    EXPECT_EQ(lab.cert_password.source, engine::SecretRef::Source::file);
    EXPECT_EQ(lab.cert_password.path, pass.string());
    EXPECT_EQ(lab.api_key.source, engine::SecretRef::Source::store);   // untouched
    EXPECT_EQ(run({"configure", "--profile", "lab", "--cert-password-file", pass.string(), "--cert-password-env", "X", "--skip-check"}), 2);
}

// ---- profile set / rename / copy ----

using ProfileCli = CertCli;

TEST_F(ProfileCli, SetValidatesLikeConfigJsonAndRebindsSecrets) {
    ASSERT_EQ(run({"--json", "profile", "set", "lab", "port=8443", "vdom=root", "timeout_ms=60000", "backup_before_critical=false",
                   "mode=guarded"}), 0) << err.str();
    json changed = json_out()["data"]["changed"];
    EXPECT_EQ(changed["port"]["from"], 443);
    EXPECT_EQ(changed["port"]["to"], 8443);
    auto lab = saved().profiles.at("lab");
    EXPECT_EQ(lab.port, 8443u);
    EXPECT_EQ(lab.vdom, "root");
    EXPECT_EQ(lab.timeout_ms, 60000u);
    EXPECT_FALSE(lab.backup_before_critical);
    EXPECT_EQ(lab.mode, engine::Mode::guarded);
    // The stored key follows the profile to its new address.
    EXPECT_EQ(secrets->get("lab/api-key")->binding, "fortigate.test:8443");
    EXPECT_EQ(json_out()["data"]["secrets_rebound"], json::array({"lab/api-key"}));

    ASSERT_EQ(run({"profile", "set", "lab", "host=fw2.test", "vdom=", "timeout_ms="}), 0) << err.str();
    lab = saved().profiles.at("lab");
    EXPECT_EQ(lab.host, "fw2.test");
    EXPECT_EQ(lab.vdom, "");
    EXPECT_EQ(lab.timeout_ms, 30000u);   // default again
    EXPECT_EQ(secrets->get("lab/api-key")->binding, "fw2.test:8443");

    // A key bound to another device is not re-bound (no laundering).
    secrets->put("lab/api-key", "k", "elsewhere:443");
    ASSERT_EQ(run({"profile", "set", "lab", "port=9443"}), 0);
    EXPECT_EQ(secrets->get("lab/api-key")->binding, "elsewhere:443");

    // Autonomous states the risk.
    ASSERT_EQ(run({"profile", "set", "lab", "mode=autonomous"}), 0);
    EXPECT_NE(out.str().find("trusted hosts"), std::string::npos);

    std::string before = slurp(paths.config_file());
    for (std::vector<std::string> bad: {std::vector<std::string>{"port=0"}, {"port=x"}, {"host=https://fw/"}, {"host=fw:8443"},
                                        {"host="}, {"mode=yolo"}, {"vdom=a b"}, {"resolve_ip=fw.lan"}, {"timeout_ms=0"},
                                        {"backup_before_critical=maybe"}, {"api_key=x"}, {"token=x"}, {"novalue"}, {"=x"}}) {
        std::vector<std::string> argv = {"profile", "set", "lab"};
        argv.insert(argv.end(), bad.begin(), bad.end());
        EXPECT_EQ(run(argv), 2) << bad[0] << " " << err.str();
    }
    EXPECT_EQ(run({"profile", "set", "lab", "ca_bundle=/nonexistent/ca.pem"}), 3);
    EXPECT_EQ(run({"profile", "set", "nope", "port=1"}), 3);
    EXPECT_EQ(run({"profile", "set", "lab"}), 2);
    EXPECT_EQ(slurp(paths.config_file()), before);   // a refused set changes nothing
    EXPECT_EQ(run({"profile", "set", "lab", "host=https://fw/"}), 2);
    EXPECT_NE(err.str().find("not a host name or address"), std::string::npos) << err.str();
    EXPECT_EQ(err.str().find("--host"), std::string::npos) << err.str();

    // Clearing the client certificate clears its password reference too.
    fs::path p12 = dir.path / "c.p12";
    std::ofstream(p12) << "x";
    ASSERT_EQ(run({"profile", "set", "lab", "client_cert=" + p12.string()}), 0) << err.str();
    secrets->put("lab/cert-password", "pw", saved().profiles.at("lab").secret_binding());
    ASSERT_EQ(run({"configure", "--profile", "lab", "--cert-password-env", "PW", "--skip-check"}), 0) << err.str();
    ASSERT_EQ(run({"profile", "set", "lab", "client_cert="}), 0) << err.str();
    EXPECT_EQ(saved().profiles.at("lab").cert_password.source, engine::SecretRef::Source::none);
}

TEST_F(ProfileCli, RenameMovesSecretsCertificatesReferencesAndTheDefault) {
    // A certificate directory as `forti cert create` leaves it, referenced by lab and by a second profile.
    fs::path old_dir = dir_of("lab");
    engine::ensure_private_dir(old_dir);
    engine::write_private_file(old_dir / "client.p12", "p12");
    engine::write_private_file(old_dir / "client.pass", "pw\n");
    ASSERT_EQ(run({"configure", "--profile", "lab", "--client-cert", (old_dir / "client.p12").string(), "--cert-password-file",
                   (old_dir / "client.pass").string(), "--skip-check"}), 0) << err.str();
    ASSERT_EQ(run({"configure", "--profile", "edge", "--host", "edge.test", "--api-key-env", "EDGE_KEY", "--client-cert",
                   (old_dir / "client.p12").string(), "--skip-check"}), 0) << err.str();
    secrets->put("lab/cert-password", "stored", "fortigate.test:443");

    ASSERT_EQ(run({"--json", "profile", "rename", "lab", "fw01"}), 0) << err.str();
    json data = json_out()["data"];
    EXPECT_EQ(data["default"], true);
    auto set = saved();
    EXPECT_FALSE(set.profiles.contains("lab"));
    EXPECT_EQ(set.default_profile, "fw01");
    const auto& fw01 = set.profiles.at("fw01");
    fs::path new_dir = dir_of("fw01");
    EXPECT_FALSE(fs::exists(old_dir));
    EXPECT_TRUE(fs::exists(new_dir / "client.p12"));
    EXPECT_EQ(mode_of(new_dir), 0700u);
    EXPECT_EQ(fw01.client_cert, (new_dir / "client.p12").string());
    EXPECT_EQ(fw01.cert_password.path, (new_dir / "client.pass").string());
    EXPECT_EQ(set.profiles.at("edge").client_cert, (new_dir / "client.p12").string());   // every reference follows
    EXPECT_EQ(engine::resolve_secret(fw01.cert_password, "x", *secrets, ""), "pw");

    EXPECT_FALSE(secrets->get("lab/api-key"));
    ASSERT_TRUE(secrets->get("fw01/api-key"));
    EXPECT_EQ(secrets->get("fw01/api-key")->secret, "lab-key");
    EXPECT_EQ(secrets->get("fw01/api-key")->binding, "fortigate.test:443");
    EXPECT_EQ(engine::resolve_secret(fw01.api_key, fw01.api_key_account(), *secrets, fw01.secret_binding()), "lab-key");
    // Not referenced by the profile (its password is a file): left alone.
    EXPECT_TRUE(secrets->get("lab/cert-password"));

    // The renamed profile works.
    device_replies();
    ASSERT_EQ(run({"--json", "doctor", "--profile", "fw01"}), 0) << out.str();

    EXPECT_EQ(run({"profile", "rename", "fw01", "edge"}), 3);    // taken
    EXPECT_EQ(run({"profile", "rename", "nope", "x"}), 3);
    EXPECT_EQ(run({"profile", "rename", "fw01", "bad name"}), 2);
    EXPECT_EQ(run({"profile", "rename", "fw01"}), 2);
    EXPECT_TRUE(saved().profiles.contains("fw01"));
}

TEST_F(ProfileCli, CopyTakesSettingsButNoSecrets) {
    fs::path ca = dir.path / "ca.pem";
    std::ofstream(ca) << "-----BEGIN CERTIFICATE-----\n";
    fs::path p12 = dir.path / "c.p12";
    std::ofstream(p12) << "x";
    ASSERT_EQ(run({"profile", "set", "lab", "port=8443", "vdom=root", "ca_bundle=" + ca.string(), "client_cert=" + p12.string(),
                   "mode=guarded"}), 0) << err.str();
    ASSERT_EQ(run({"--json", "profile", "copy", "lab", "fw02"}), 0) << err.str();
    EXPECT_EQ(json_out()["data"]["next"], "forti configure --profile fw02");
    auto set = saved();
    const auto& fw02 = set.profiles.at("fw02");
    EXPECT_EQ(fw02.host, "fortigate.test");
    EXPECT_EQ(fw02.port, 8443u);
    EXPECT_EQ(fw02.vdom, "root");
    EXPECT_EQ(fw02.ca_bundle, ca.string());
    EXPECT_EQ(fw02.mode, engine::Mode::guarded);
    EXPECT_EQ(fw02.api_key.source, engine::SecretRef::Source::none);
    EXPECT_TRUE(fw02.client_cert.empty());
    EXPECT_FALSE(secrets->get("fw02/api-key"));
    EXPECT_EQ(set.default_profile, "lab");
    ASSERT_EQ(run({"profile", "copy", "lab", "fw03"}), 0);
    EXPECT_NE(out.str().find("forti configure --profile fw03"), std::string::npos);
    EXPECT_EQ(run({"profile", "copy", "lab", "fw02"}), 3);

    // A copy without a key does not connect until configured; configure then only needs the key.
    EXPECT_EQ(run({"get", "monitor/system/status", "--profile", "fw02"}), 3);
    EXPECT_EQ(run({"profile", "set", "fw02", "host=fw02.test"}), 0);
    device_replies();
    ASSERT_EQ(run({"configure", "--profile", "fw02", "--api-key-stdin"}, "fw02-key\n"), 0) << err.str();
    EXPECT_EQ(transport->requests.back().url, "https://fw02.test:8443/api/v2/monitor/system/status?vdom=root");
    EXPECT_EQ(secrets->get("fw02/api-key")->binding, "fw02.test:8443");
    EXPECT_EQ(saved().profiles.at("fw02").mode, engine::Mode::guarded);

    // The list marks the default and shows host and mode.
    ASSERT_EQ(run({"profile", "list"}), 0);
    EXPECT_NE(out.str().find("lab *"), std::string::npos) << out.str();
    EXPECT_NE(out.str().find("fw02.test:8443"), std::string::npos);
    EXPECT_NE(out.str().find("guarded"), std::string::npos);
}

// ---- help ----

TEST_F(HomeCli, HelpCoversTheNewCommands) {
    ASSERT_EQ(run({"--help"}), 0);
    for (const char* text: {"home", "cert", "FORTI_HOME"}) EXPECT_NE(out.str().find(text), std::string::npos) << text;
    ASSERT_EQ(run({"help", "home"}), 0);
    EXPECT_NE(out.str().find("forti home migrate"), std::string::npos);
    ASSERT_EQ(run({"cert", "--help"}), 0);
    for (const char* text: {"--days", "--force", "--keychain", "--own-ca", "forti CA", "client.p12", "never printed", "cert use", "cert list"})
        EXPECT_NE(out.str().find(text), std::string::npos) << text;
    ASSERT_EQ(run({"profile", "--help"}), 0);
    for (const char* text: {"profile set NAME key=value", "profile rename OLD NEW", "profile copy SOURCE NEW", "backup_before_critical"})
        EXPECT_NE(out.str().find(text), std::string::npos) << text;
    ASSERT_EQ(run({"configure", "--help"}), 0);
    EXPECT_NE(out.str().find("--cert-password-file"), std::string::npos);
    ASSERT_EQ(run({"doctor", "--help"}), 0);
    EXPECT_NE(out.str().find("forti home migrate"), std::string::npos);
}

// ---- trust on first use: the names a certificate carries ----

TEST(Certs, CoversMatchesNamesIpsAndOneWildcardLabel) {
    json cert = {{"cn", "FGT60FTK20000000"}, {"names", {"DNS:fw.example.net", "DNS:*.lab.example.net", "IP:192.0.2.1", "IP:2001:DB8::1"}}};
    EXPECT_TRUE(cli::certs::covers(cert, "fw.example.net"));
    EXPECT_TRUE(cli::certs::covers(cert, "FW.Example.Net"));
    EXPECT_TRUE(cli::certs::covers(cert, "a.lab.example.net"));
    EXPECT_FALSE(cli::certs::covers(cert, "a.b.lab.example.net"));   // one label only
    EXPECT_FALSE(cli::certs::covers(cert, "lab.example.net"));
    EXPECT_TRUE(cli::certs::covers(cert, "192.0.2.1"));
    EXPECT_TRUE(cli::certs::covers(cert, "[2001:db8::1]"));
    EXPECT_FALSE(cli::certs::covers(cert, "192.0.2.2"));
    EXPECT_FALSE(cli::certs::covers(cert, "FGT60FTK20000000"));   // names present: the CN does not count
    json factory = {{"cn", "FGT60FTK20000000"}, {"names", json::array()}};
    EXPECT_TRUE(cli::certs::covers(factory, "fgt60ftk20000000"));
    EXPECT_FALSE(cli::certs::covers(factory, "192.0.2.1"));
}
