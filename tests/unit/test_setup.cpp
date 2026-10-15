// `forti configure` (non-interactive), `forti profile …` and `forti doctor`, against a temporary
// config directory, a memory secret store and the scripted transport.

#include <cli_harness.hpp>

#include <fstream>

using namespace forti;
using json = nlohmann::json;
namespace fs = std::filesystem;

namespace {

    using SetupCli = fake::Cli;

    std::string slurp(const fs::path& path) {
        std::ifstream in(path);
        return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
    }

    unsigned mode_of(const fs::path& path) {
        struct stat info{};
        ::stat(path.c_str(), &info);
        return info.st_mode & 0777;
    }

    bool has_header(const fortiapi::HttpRequest& request, std::string_view header) {
        return std::ranges::find(request.headers, header) != request.headers.end();
    }

    json check(const json& checks, std::string_view id) {
        for (const auto& c: checks)
            if (c["check"] == id) return c;
        return nullptr;
    }

}  // namespace

// ---- configure ----

TEST_F(SetupCli, ConfigureFromStdinVerifiesThenSavesWithoutTheSecretInConfig) {
    device_replies();
    ASSERT_EQ(run({"--json", "configure", "--profile", "home", "--host", "fw.example.net", "--port", "8443", "--vdom",
                   "root", "--api-key-stdin"}, "  s3cret-key  \n"), 0) << err.str() << out.str();
    json result = json_out();
    EXPECT_TRUE(result["ok"]);
    EXPECT_EQ(result["data"]["device"]["hostname"], "fw01");
    EXPECT_TRUE(result["data"]["verified"]);
    EXPECT_TRUE(result["data"]["default"]);   // the first profile becomes the default

    ASSERT_EQ(transport->requests.size(), 1u);
    EXPECT_EQ(transport->requests[0].url, "https://fw.example.net:8443/api/v2/monitor/system/status?vdom=root");
    EXPECT_TRUE(has_header(transport->requests[0], "Authorization: Bearer s3cret-key"));

    EXPECT_EQ(secrets->get("home/api-key")->secret, "s3cret-key");
    EXPECT_EQ(secrets->get("home/api-key")->binding, "fw.example.net:8443");   // configure writes the binding
    std::string config = slurp(paths.config_file());
    EXPECT_EQ(config.find("s3cret"), std::string::npos);
    EXPECT_EQ(out.str().find("s3cret"), std::string::npos);
    EXPECT_EQ(mode_of(paths.config_file()), 0600u);
    EXPECT_EQ(mode_of(paths.config), 0700u);

    auto set = saved();
    const auto& home = set.select("");
    EXPECT_EQ(home.name, "home");
    EXPECT_EQ(home.port, 8443u);
    EXPECT_EQ(home.vdom, "root");
    EXPECT_EQ(home.mode, engine::Mode::read_only);   // default
    EXPECT_EQ(home.api_key.source, engine::SecretRef::Source::store);
}

TEST_F(SetupCli, ConfigureRefusesSecretsAsArgumentsAndBadInput) {
    EXPECT_EQ(run({"configure", "--profile", "x", "--host", "h", "--api-key", "abc"}), 2);   // no such option
    EXPECT_EQ(run({"configure", "--profile", "x", "--host", "h"}), 2);                       // no credential
    EXPECT_NE(err.str().find("--api-key-stdin"), std::string::npos);
    EXPECT_EQ(run({"configure", "--profile", "x", "--host", "https://fw/", "--api-key-env", "K"}), 2);
    EXPECT_EQ(run({"configure", "--profile", "x", "--host", "fw:8443", "--api-key-env", "K"}), 2);
    EXPECT_EQ(run({"configure", "--profile", "x", "--host", "fw", "--api-key-env", "not a name"}), 2);
    EXPECT_EQ(run({"configure", "--profile", "x", "--host", "fw", "--api-key-env", "K", "--mode", "yolo"}), 2);
    EXPECT_EQ(run({"configure", "--profile", "x", "--host", "fw", "--api-key-env", "K", "--resolve-ip", "fw.lan"}), 2);
    EXPECT_EQ(run({"configure", "--profile", "x", "--host", "fw", "--api-key-env", "K", "--ca-bundle", "/nonexistent/ca.pem"}), 3);
    EXPECT_EQ(run({"configure", "--profile", "x", "--host", "fw", "--api-key-stdin"}, ""), 2);   // empty stdin
    EXPECT_EQ(run({"configure", "--host", "fw", "--api-key-env", "K"}), 2);                      // --profile required
    EXPECT_FALSE(fs::exists(paths.config_file()));
    EXPECT_TRUE(transport->requests.empty());
}

TEST_F(SetupCli, ConfigureStopsAtTheFirstAuthFailureAndSavesNothing) {
    transport->reply(401, json{{"status", "error"}, {"http_status", 401}});
    EXPECT_EQ(run({"configure", "--profile", "home", "--host", "fw.example.net", "--api-key-stdin"}, "wrong\n"), 4);
    EXPECT_EQ(transport->requests.size(), 1u);   // never retried: FortiOS locks the API user out
    EXPECT_NE(err.str().find("rejected the API key"), std::string::npos) << err.str();
    EXPECT_NE(err.str().find("did not retry"), std::string::npos);
    EXPECT_EQ(err.str().find("wrong"), std::string::npos);
    EXPECT_FALSE(fs::exists(paths.config_file()));
    EXPECT_FALSE(secrets->get("home/api-key"));
}

TEST_F(SetupCli, ConfigureTlsFailureSuggestsCaBundleNeverInsecure) {
    ::setenv("FORTI_K", "env-key", 1);
    transport->fail(60, true).fail(60, true).fail(60, true);   // the SDK retries a GET that never reached the device
    EXPECT_EQ(run({"--json", "configure", "--profile", "home", "--host", "fw.example.net", "--api-key-env", "FORTI_K"}), 4);
    json error = json_out()["error"];
    EXPECT_EQ(error["code"], "connection");
    EXPECT_EQ(error["details"]["stage"], "tls");
    std::string hint = error["details"]["hint"];
    EXPECT_NE(hint.find("--ca-bundle"), std::string::npos);
    EXPECT_NE(hint.find("--resolve-ip"), std::string::npos);
    EXPECT_NE(hint.find("never disables"), std::string::npos);
    EXPECT_FALSE(fs::exists(paths.config_file()));
}

TEST_F(SetupCli, ConfigureEnvSourceSkipCheckAndUpdatesKeepOtherValues) {
    std::string ca = (dir.path / "ca.pem").string();
    std::ofstream(ca) << "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";
    ASSERT_EQ(run({"configure", "--profile", "lab", "--host", "192.0.2.10", "--ca-bundle", ca, "--resolve-ip", "192.0.2.10",
                   "--api-key-command", "pass show 'fw/lab key'", "--skip-check"}), 0) << err.str();
    EXPECT_TRUE(transport->requests.empty());
    EXPECT_NE(out.str().find("not checked"), std::string::npos);
    auto lab = saved().profiles.at("lab");
    EXPECT_EQ(lab.api_key.command, (std::vector<std::string>{"pass", "show", "fw/lab key"}));
    EXPECT_EQ(lab.ca_bundle, ca);

    // An update changes only what is given.
    ASSERT_EQ(run({"configure", "--profile", "lab", "--mode", "guarded", "--skip-check"}), 0) << err.str();
    lab = saved().profiles.at("lab");
    EXPECT_EQ(lab.mode, engine::Mode::guarded);
    EXPECT_EQ(lab.host, "192.0.2.10");
    EXPECT_EQ(lab.api_key.source, engine::SecretRef::Source::command);

    // Choosing autonomous states the risk once.
    ASSERT_EQ(run({"configure", "--profile", "lab", "--mode", "autonomous", "--skip-check"}), 0);
    EXPECT_NE(out.str().find("anything this FortiOS API account is permitted to do"), std::string::npos);
    ASSERT_EQ(run({"configure", "--profile", "lab", "--mode", "autonomous", "--skip-check"}), 0);
    EXPECT_EQ(out.str().find("anything this FortiOS API account"), std::string::npos);
}

TEST_F(SetupCli, SwitchingAwayFromTheStoreErasesTheStoredKey) {
    configure_lab();
    ASSERT_TRUE(secrets->get("lab/api-key"));
    ASSERT_EQ(run({"configure", "--profile", "lab", "--api-key-env", "FORTI_LAB_KEY", "--skip-check"}), 0) << err.str();
    EXPECT_FALSE(secrets->get("lab/api-key"));
    EXPECT_EQ(saved().profiles.at("lab").api_key.env, "FORTI_LAB_KEY");
}

// ---- profile ----

TEST_F(SetupCli, ProfileListShowDefaultModeRemove) {
    configure_lab();
    device_replies();
    ASSERT_EQ(run({"configure", "--profile", "edge", "--host", "edge.test", "--api-key-stdin"}, "edge-key\n"), 0) << err.str();
    EXPECT_EQ(saved().default_profile, "lab");
    transport->requests.clear();

    ASSERT_EQ(run({"profile", "list"}), 0);
    EXPECT_NE(out.str().find("lab *"), std::string::npos) << out.str();
    EXPECT_NE(out.str().find("edge"), std::string::npos);

    ASSERT_EQ(run({"--json", "profile", "show", "edge"}), 0);
    json shown = json_out()["data"];
    EXPECT_EQ(shown["host"], "edge.test");
    EXPECT_EQ(shown["api_key_stored"], true);
    EXPECT_EQ(out.str().find("edge-key"), std::string::npos);

    ASSERT_EQ(run({"profile", "default", "edge"}), 0);
    EXPECT_EQ(saved().default_profile, "edge");
    EXPECT_EQ(run({"profile", "default", "nope"}), 3);

    ASSERT_EQ(run({"profile", "mode", "lab", "guarded"}), 0) << err.str();
    EXPECT_EQ(saved().profiles.at("lab").mode, engine::Mode::guarded);
    ASSERT_EQ(run({"profile", "mode", "autonomous"}), 0) << err.str();   // the default profile (edge)
    EXPECT_EQ(saved().profiles.at("edge").mode, engine::Mode::autonomous);
    EXPECT_NE(out.str().find("trusted hosts"), std::string::npos);
    EXPECT_EQ(run({"profile", "mode", "lab", "reckless"}), 2);

    ASSERT_EQ(run({"profile", "remove", "edge"}), 0) << err.str();
    EXPECT_FALSE(saved().profiles.contains("edge"));
    EXPECT_FALSE(secrets->get("edge/api-key"));
    EXPECT_EQ(saved().default_profile, "lab");   // the only one left
    EXPECT_EQ(run({"profile", "remove", "edge"}), 3);
    EXPECT_EQ(run({"profile", "frobnicate"}), 2);
    EXPECT_TRUE(transport->requests.empty());
}

// ---- doctor ----

TEST_F(SetupCli, DoctorPassesInOrderAndReportsTheMode) {
    configure_lab();
    fake::TempDir bin;
    std::string mcp = (bin.path / "forti-mcp").string();
    std::ofstream(mcp) << "#!/bin/sh\n";
    ::chmod(mcp.c_str(), 0755);
    std::string path = std::getenv("PATH") ? std::getenv("PATH") : "";
    ::setenv("PATH", (bin.path.string() + ":" + path).c_str(), 1);
    device_replies();
    int status = run({"--json", "doctor"});
    ::setenv("PATH", path.c_str(), 1);
    ASSERT_EQ(status, 0) << out.str();
    json data = json_out()["data"];
    std::vector<std::string> order;
    for (const auto& c: data["checks"]) order.push_back(c["check"]);
    EXPECT_EQ(order, (std::vector<std::string>{"config", "profile", "secrets", "tls_files", "connection", "auth", "version",
                                               "mode", "mcp"}));
    for (const auto& c: data["checks"]) EXPECT_NE(c["status"], "fail") << c.dump();
    EXPECT_NE(check(data["checks"], "mcp")["message"].get<std::string>().find(mcp), std::string::npos);
    EXPECT_NE(check(data["checks"], "mode")["message"].get<std::string>().find("read-only"), std::string::npos);
    EXPECT_EQ(data["summary"]["fail"], 0);
    EXPECT_EQ(transport->requests.size(), 1u);

    device_replies();
    ASSERT_EQ(run({"doctor"}), 0);
    EXPECT_NE(out.str().find("ok    connection"), std::string::npos) << out.str();
}

TEST_F(SetupCli, DoctorWithoutConfigurationFailsWithConfigExit) {
    EXPECT_EQ(run({"doctor"}), 3);
    EXPECT_NE(out.str().find("fail  config"), std::string::npos) << out.str();
    EXPECT_NE(out.str().find("forti configure"), std::string::npos);
    EXPECT_NE(err.str().find("1 check failed"), std::string::npos);

    EXPECT_EQ(run({"--json", "doctor"}), 3);
    json error = json_out()["error"];
    EXPECT_EQ(error["code"], "config");
    EXPECT_EQ(check(error["details"]["checks"], "auth")["status"], "skip");
}

TEST_F(SetupCli, DoctorSeparatesConnectionFromAuthAndNeverRetriesAuth) {
    configure_lab();
    transport->reply(403, json{{"status", "error"}, {"http_status", 403}});
    EXPECT_EQ(run({"--json", "doctor"}), 4);
    json checks = json_out()["error"]["details"]["checks"];
    EXPECT_EQ(check(checks, "connection")["status"], "pass");
    EXPECT_EQ(check(checks, "auth")["status"], "fail");
    EXPECT_NE(check(checks, "auth")["hint"].get<std::string>().find("trusted hosts"), std::string::npos);
    EXPECT_EQ(transport->requests.size(), 1u);

    transport->requests.clear();
    transport->fail(6, true).fail(6, true).fail(6, true);
    EXPECT_EQ(run({"--json", "doctor"}), 4);
    checks = json_out()["error"]["details"]["checks"];
    EXPECT_EQ(check(checks, "connection")["status"], "fail");
    EXPECT_NE(check(checks, "connection")["message"].get<std::string>().find("dns"), std::string::npos);
    EXPECT_NE(check(checks, "connection")["hint"].get<std::string>().find("--resolve-ip"), std::string::npos);
    EXPECT_EQ(check(checks, "auth")["status"], "skip");
}

TEST_F(SetupCli, DoctorWarnsOnVersionMismatchAndLooseModes) {
    configure_lab();
    ::chmod(paths.config_file().c_str(), 0644);
    device_replies("v7.2.5");
    ASSERT_EQ(run({"--json", "doctor"}), 0) << out.str();
    json checks = json_out()["data"]["checks"];
    EXPECT_EQ(check(checks, "version")["status"], "warn");
    EXPECT_NE(check(checks, "version")["message"].get<std::string>().find("v7.2.5"), std::string::npos);
    EXPECT_EQ(check(checks, "config")["status"], "warn");
    EXPECT_NE(check(checks, "config")["hint"].get<std::string>().find("chmod 600"), std::string::npos);
}

TEST_F(SetupCli, DoctorFailsOnAMissingSecretOrCaBundle) {
    configure_lab();
    secrets->erase("lab/api-key");
    EXPECT_EQ(run({"--json", "doctor"}), 3);
    json checks = json_out()["error"]["details"]["checks"];
    EXPECT_EQ(check(checks, "secrets")["status"], "fail");
    EXPECT_EQ(check(checks, "connection")["status"], "skip");
    EXPECT_TRUE(transport->requests.empty());
}

TEST_F(SetupCli, DoctorWarnsWhenAutonomousUsesSuperAdmin) {
    configure_lab("autonomous");
    device_replies();
    transport->reply(200, fake::envelope(json::array({{{"name", "agent"}, {"accprofile", "super_admin"}}})));
    ASSERT_EQ(run({"--json", "doctor"}), 0) << out.str();
    json checks = json_out()["data"]["checks"];
    EXPECT_NE(check(checks, "mode")["message"].get<std::string>().find("autonomous"), std::string::npos);
    EXPECT_EQ(check(checks, "privileges")["status"], "warn");
    EXPECT_NE(transport->requests[1].url.find("cmdb/system/api-user"), std::string::npos);

    device_replies();
    transport->reply(403, json{{"status", "error"}, {"http_status", 403}});
    ASSERT_EQ(run({"--json", "doctor"}), 0) << out.str();
    EXPECT_EQ(check(json_out()["data"]["checks"], "privileges")["status"], "pass");
}
