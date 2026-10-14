// Security regression tests (../.claude/context/security-audit.md in the parent workspace). Each test
// names the finding it pins down. Nothing here talks to a FortiGate, the login keychain or the real
// configuration directories.

#include <fake_transport.hpp>

#include <forti/engine/approval.hpp>

#include "plan_store.hpp"

#include <gtest/gtest.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

using namespace forti;
using json = nlohmann::json;
using engine::Mode;
namespace fs = std::filesystem;

namespace {

    const std::string serial = "FGT60FTK00000000";

    struct TempDir {
        fs::path path;
        TempDir() {
            std::string pattern = (fs::temp_directory_path() / "forti-security-test-XXXXXX").string();
            path = ::mkdtemp(pattern.data());
        }
        ~TempDir() { fs::remove_all(path); }
    };

    void write(const fs::path& file, const std::string& text, mode_t mode) {
        fs::create_directories(file.parent_path());
        { std::ofstream(file) << text; }
        ::chmod(file.c_str(), mode);
    }

    // Sets an environment variable for one scope.
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
    };

    json written() {
        return {{"status", "success"}, {"http_status", 200}, {"serial", serial}, {"version", "v7.4.8"}, {"vdom", "root"}};
    }

    json address(const std::string& name, const std::string& comment) {
        return {{"name", name}, {"q_origin_key", name}, {"subnet", "192.0.2.0 255.255.255.0"}, {"type", "ipmask"},
                {"comment", comment}, {"color", 0}};
    }

    struct Engine : ::testing::Test {
        TempDir dir;
        std::shared_ptr<fake::FakeTransport> transport = std::make_shared<fake::FakeTransport>();
        engine::Paths paths{dir.path / "config", dir.path / "state", dir.path / "cache"};
        std::unique_ptr<engine::Engine> sut;

        explicit Engine(Mode mode = Mode::autonomous) {
            auto options = fake::options(transport, mode);
            options.paths = paths;
            sut = std::make_unique<engine::Engine>(options);
        }

        json plan(const json& request) { return engine::Engine::envelope([&] { return sut->plan(request); }); }
        json apply(const std::string& id) { return engine::Engine::envelope([&] { return sut->apply({{"plan_id", id}}); }); }
        json read(const json& request) { return engine::Engine::envelope([&] { return sut->read(request); }); }

        std::string plan_comment() {
            transport->reply(200, fake::envelope(json::array({address("LAN", "old")})));
            json result = plan({{"operations", {{{"op", "update"}, {"resource", "firewall/address"}, {"key", "LAN"},
                                                 {"set", {{"comment", "new"}}}}}}});
            EXPECT_TRUE(result["ok"]) << result.dump();
            return result["data"]["id"];
        }

        fs::path plan_file(const std::string& id) const { return paths.state / "plans" / (id + ".json"); }

        json stored(const std::string& id) const {
            std::ifstream in(plan_file(id));
            return json::parse(in);
        }

        // Rewrites a stored plan the way an attacker with write access would: valid JSON, recomputed digest.
        void tamper(const std::string& id, const std::function<void(json&)>& edit) const {
            json plan = stored(id);
            edit(plan);
            plan["digest"] = engine::detail::plan_digest(plan);
            std::ofstream(plan_file(id)) << plan.dump(2);
        }

        std::size_t writes() const {
            std::size_t n = 0;
            for (const auto& request: transport->requests) n += request.method != fortiapi::Method::Get;
            return n;
        }
    };

}  // namespace

// ---- S-08: redaction covers the attributes the 7.4.8 schema types as password* ----

TEST(Redaction, SchemaPasswordAttributesAreSensitive) {
    // Every attribute typed password, password-2, password-3 or password_aes256 in
    // forti-api/codegen/schema/7.4.8 that the name heuristic missed before.
    for (const char* name: {"api-key", "auth-string", "aws-api-key", "azure-api-key", "bmr-hostname", "ddns-key", "enc-key",
                            "inter-controller-key", "key-string", "n-mhae-key", "secondary-key", "server-key",
                            "tertiary-key", "uploadpass", "preshared-key", "keytab", "mpsk-key"})
        EXPECT_TRUE(engine::detail::sensitive_name(name)) << name;
    for (const char* name: {"name", "comment", "parent-key", "search-key", "public-key", "ssh-public-key1", "keyword-match",
                            "q_origin_key", "subnet", "pinned"})
        EXPECT_FALSE(engine::detail::sensitive_name(name)) << name;
}

TEST(Redaction, LiveSchemaPasswordVariantsAreSensitive) {
    json schema = {{"children", {{"a", {{"type", "password-2"}}},
                                 {"b", {{"type", "password_aes256"}}},
                                 {"c", {{"type", "password-3"}}},
                                 {"d", {{"type", "string"}}}}}};
    auto names = engine::detail::sensitive_from_schema(schema);
    EXPECT_TRUE(names.contains("a"));
    EXPECT_TRUE(names.contains("b"));
    EXPECT_TRUE(names.contains("c"));
    EXPECT_FALSE(names.contains("d"));
}

// ---- S-06: the file secret store checks what it opened ----

TEST(FileSecretStore, RefusesSymlinksForeignModesAndFifos) {
    TempDir dir;
    engine::Paths paths{dir.path / "config", dir.path / "state", dir.path / "cache"};
    auto store = engine::file_secret_store(paths);
    fs::path credentials = paths.config / "credentials";

    write(credentials / "lab.api-key", "real-key\n", 0600);
    EXPECT_EQ(store->get("lab/api-key"), "real-key");

    write(dir.path / "elsewhere", "planted\n", 0600);
    fs::create_symlink(dir.path / "elsewhere", credentials / "sym.api-key");
    EXPECT_THROW((void) store->get("sym/api-key"), engine::Failure);

    write(credentials / "open.api-key", "k\n", 0644);
    EXPECT_THROW((void) store->get("open/api-key"), engine::Failure);

    ASSERT_EQ(::mkfifo((credentials / "fifo.api-key").c_str(), 0600), 0);
    EXPECT_THROW((void) store->get("fifo/api-key"), engine::Failure);   // and does not block

    EXPECT_EQ(store->get("absent/api-key"), std::nullopt);
}

// ---- S-07: a credential command gets /dev/null as stdin and no inherited descriptors ----

TEST(CredentialCommand, DoesNotReadTheCallersStdinOrInheritDescriptors) {
    auto store = engine::memory_secret_store();
    engine::SecretRef ref{engine::SecretRef::Source::command, {}, {}};

    // In forti-mcp, fd 0 is the JSON-RPC stream: a helper must not be able to read it.
    int saved_stdin = ::dup(STDIN_FILENO);
    int fds[2];
    ASSERT_EQ(::pipe(fds), 0);
    std::string message = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n";
    ASSERT_EQ(::write(fds[1], message.data(), message.size()), static_cast<ssize_t>(message.size()));
    ::close(fds[1]);
    ::dup2(fds[0], STDIN_FILENO);
    ::close(fds[0]);
    ref.command = {"/bin/sh", "-c", "IFS= read -r line; printf 'got:%s\\n' \"$line\""};
    std::string secret = engine::resolve_secret(ref, "lab/api-key", *store);
    ::dup2(saved_stdin, STDIN_FILENO);
    ::close(saved_stdin);
    EXPECT_EQ(secret, "got:");

    // A descriptor the engine holds (a plan file, a socket) is not visible to the helper.
    int held = ::open("/dev/null", O_RDONLY);   // deliberately without O_CLOEXEC
    ASSERT_GE(held, 3);
    ref.command = {"/bin/sh", "-c", std::format("if [ -e /dev/fd/{} ]; then echo leaked; else echo clean; fi", held)};
    EXPECT_EQ(engine::resolve_secret(ref, "lab/api-key", *store), "clean");
    ::close(held);

    // stderr stays open for helper prompts.
    ref.command = {"/bin/sh", "-c", ": >&2 && echo open || echo closed"};
    EXPECT_EQ(engine::resolve_secret(ref, "lab/api-key", *store), "open");
}

// ---- S-05: configuration locations and config.json integrity ----

TEST(Paths, RelativeOverridesAreRefused) {
    ScopedEnv config("FORTI_CONFIG_DIR", ".forti");
    EXPECT_THROW((void) engine::Paths::from_env(), engine::Failure);
}

TEST(ProfileStore, RefusesConfigWritableByOthers) {
    TempDir dir;
    engine::Paths paths{dir.path / "config", dir.path / "state", dir.path / "cache"};
    engine::ProfileStore store(paths);
    engine::ProfileSet set;
    engine::Profile lab;
    lab.name = "lab";
    lab.host = "fortigate.test";
    set.profiles.emplace("lab", lab);
    store.save(set);
    EXPECT_EQ(store.load().profiles.size(), 1u);

    ::chmod(paths.config_file().c_str(), 0620);   // group-writable: anyone in the group could set autonomous
    EXPECT_THROW((void) store.load(), engine::Failure);
    ::chmod(paths.config_file().c_str(), 0600);
    ::chmod(paths.config.c_str(), 0777);           // a world-writable directory lets others replace the file
    EXPECT_THROW((void) store.load(), engine::Failure);
    ::chmod(paths.config.c_str(), 0700);
    EXPECT_EQ(store.load().profiles.size(), 1u);
}

// ---- S-09: a tampered plan file is refused even with a recomputed digest ----

TEST_F(Engine, TamperedOperationKindIsRefusedBeforeAnyRequest) {
    std::string id = plan_comment();
    tamper(id, [](json& plan) { plan["operations"][0]["op"] = "frobnicate"; });
    transport->requests.clear();
    json result = apply(id);
    EXPECT_EQ(result["error"]["code"], "policy_denied") << result.dump();
    EXPECT_EQ(result["error"]["details"]["reason"], "tampered");
    EXPECT_TRUE(transport->requests.empty());
}

TEST_F(Engine, TamperedOperationOnATypedMonitorIsRefusedNotDereferenced) {
    // Typed monitor endpoints have no create/update ops (null function pointers in the catalog).
    std::string id = plan_comment();
    tamper(id, [](json& plan) {
        auto& op = plan["operations"][0];
        op["resource"] = "monitor/system/status";
        op["risk"] = "elevated";
        op["op"] = "create";
        op["object"] = json::object();
    });
    json result = apply(id);
    EXPECT_EQ(result["error"]["code"], "policy_denied") << result.dump();
    EXPECT_EQ(writes(), 0u);
}

TEST_F(Engine, TamperedWirePathShownToTheApproverIsRefused) {
    std::string id = plan_comment();
    tamper(id, [](json& plan) { plan["operations"][0]["wire"]["path"] = "cmdb/firewall/address/HARMLESS"; });
    json result = apply(id);
    EXPECT_EQ(result["error"]["code"], "policy_denied") << result.dump();
    EXPECT_EQ(result["error"]["details"]["check"], "wire");
}

TEST_F(Engine, StoredSummaryIsNotTrusted) {
    std::string id = plan_comment();
    json plan = stored(id);
    plan["summary"] = "nothing to see here";   // outside the digest
    std::ofstream(plan_file(id)) << plan.dump(2);
    json shown = engine::Engine::envelope([&] { return engine::show_plan(*sut, id); });
    ASSERT_TRUE(shown["ok"]) << shown.dump();
    EXPECT_NE(shown["data"]["summary"], "nothing to see here");
    EXPECT_NE(shown["data"]["summary"].get<std::string>().find("1 update"), std::string::npos);
}

// ---- S-10: a write the device accepted with an unreadable reply is outcome_unknown, never retried ----

TEST_F(Engine, UndecodableReplyAfterSendIsOutcomeUnknown) {
    std::string id = plan_comment();
    transport->requests.clear();
    transport->reply(200, fake::envelope(json::array({address("LAN", "old")})));   // before-state re-read
    transport->script.emplace_back(fortiapi::HttpResponse{200, "<html>proxy</html>"});
    json result = apply(id);
    EXPECT_EQ(result["error"]["code"], "outcome_unknown") << result.dump();
    EXPECT_EQ(result["error"]["details"]["operations"][0]["status"], "outcome_unknown");
    EXPECT_EQ(writes(), 1u);   // sent once, not retried
    EXPECT_TRUE(transport->script.empty());
}

// ---- S-11: reserved query parameters cannot be smuggled through params by case ----

TEST_F(Engine, ReservedParamsAreCaseInsensitive) {
    for (const char* name: {"Action", "ACTION", " action", "Access_Token", "VDOM", ""}) {
        json result = read({{"resource", "firewall/address"}, {"params", {{name, "x"}}}});
        EXPECT_EQ(result["error"]["code"], "usage") << name << ": " << result.dump();
    }
    EXPECT_TRUE(transport->requests.empty());
}

// ---- S-04: monitor actions that restart or reconfigure the device are critical and probed ----

TEST_F(Engine, RebootIsCriticalAndFollowedByAManagementProbe) {
    json described = engine::Engine::envelope([&] { return sut->discover({{"resource", "monitor/system/os/reboot"}}); });
    EXPECT_EQ(described["data"]["risk"], "critical") << described.dump();
    json harmless = engine::Engine::envelope([&] { return sut->discover({{"resource", "monitor/wifi/managed_ap/led-blink"}}); });
    EXPECT_EQ(harmless["data"]["risk"], "elevated");

    transport->reply(200, fake::envelope({{"hostname", "fw01"}}));   // plan: device identity
    json planned = plan({{"operations", {{{"op", "action"}, {"resource", "monitor/system/os/reboot"}, {"body", json::object()}}}}});
    ASSERT_TRUE(planned["ok"]) << planned.dump();
    EXPECT_EQ(planned["data"]["risk"], "critical");

    transport->reply(200, fake::envelope({{"hostname", "fw01"}}));   // apply: device identity
    transport->reply(200, written());                                   // the POST
    transport->fail(7, true);                                           // probe: CURLE_COULDNT_CONNECT
    transport->fail(7, true);                                           // probe retry (retries = 1)
    json result = apply(planned["data"]["id"]);
    EXPECT_EQ(result["error"]["code"], "management_connectivity_lost") << result.dump();
    EXPECT_EQ(writes(), 1u);
    // Honest about recovery: never claims it can recover from a lockout.
    std::string message = result["error"]["message"];
    EXPECT_NE(message.find("not independent recovery"), std::string::npos);
}
