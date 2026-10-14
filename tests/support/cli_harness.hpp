//
// Runs the `forti` CLI in-process (cli::run) against a temporary config directory, an in-memory
// secret store and a scripted transport. Nothing touches ~/.config/forti, the login keychain or
// the network.
//

#ifndef FORTI_TESTS_CLI_HARNESS_HPP
#define FORTI_TESTS_CLI_HARNESS_HPP

#include "fake_transport.hpp"

#include <app.hpp>

#include <gtest/gtest.h>

#include <filesystem>
#include <sstream>
#include <string>
#include <vector>

#include <sys/stat.h>

namespace forti::fake {

    struct TempDir {
        std::filesystem::path path;
        TempDir() {
            std::string pattern = (std::filesystem::temp_directory_path() / "forti-cli-test-XXXXXX").string();
            path = ::mkdtemp(pattern.data());
        }
        ~TempDir() { std::filesystem::remove_all(path); }
        TempDir(const TempDir&) = delete;
        TempDir& operator=(const TempDir&) = delete;
    };

    struct Cli : ::testing::Test {
        TempDir dir;
        engine::Paths paths{dir.path / "config", dir.path / "state", dir.path / "cache"};
        std::shared_ptr<engine::SecretStore> secrets = engine::memory_secret_store();
        std::shared_ptr<FakeTransport> transport = std::make_shared<FakeTransport>();
        std::ostringstream out, err;
        bool color = false;
        std::size_t width = 0;

        engine::Options options() const {
            engine::Options options;
            options.paths = paths;
            options.secrets = secrets;
            auto fake = transport;
            options.transport = [fake](const fortiapi::Config&) -> std::shared_ptr<fortiapi::Transport> { return fake; };
            return options;
        }

        int run(std::vector<std::string> arguments, const std::string& input = "") {
            out.str("");
            err.str("");
            std::istringstream in(input);
            cli::Output output{.out = &out, .err = &err, .in = &in, .color = color, .err_color = color, .width = width};
            return cli::run(arguments, output, options());
        }

        nlohmann::json json_out() const { return nlohmann::json::parse(out.str()); }

        engine::ProfileSet saved() const { return engine::ProfileStore(paths).load(); }

        // The reply to the verification read (monitor/system/status).
        void device_replies(const std::string& version = "v7.4.8") {
            auto body = envelope({{"hostname", "fw01"}, {"model_name", "FortiGate"}, {"model_number", "60F"}});
            body["version"] = version;
            transport->reply(200, body);
        }

        // A configured profile "lab" with its key in the memory store.
        void configure_lab(const std::string& extra_mode = "read-only") {
            device_replies();
            ASSERT_EQ(run({"configure", "--profile", "lab", "--host", "fortigate.test", "--api-key-stdin", "--mode", extra_mode},
                          "lab-key\n"), 0) << err.str();
            transport->requests.clear();
        }
    };

}  // namespace forti::fake

#endif  // FORTI_TESTS_CLI_HARNESS_HPP
