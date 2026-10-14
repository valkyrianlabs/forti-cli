//
// A scripted fortiapi::Transport: records requests, replays queued responses. forti-api has the same
// fixture in its tests but does not install it (gap G4), so this implements the public interface.
//

#ifndef FORTI_TESTS_FAKE_TRANSPORT_HPP
#define FORTI_TESTS_FAKE_TRANSPORT_HPP

#include <forti/engine/engine.hpp>

#include <forti_api/client.hpp>

#include <deque>
#include <memory>
#include <stdexcept>
#include <variant>

namespace forti::fake {

    class FakeTransport final : public fortiapi::Transport {
    public:
        using Step = std::variant<fortiapi::HttpResponse, fortiapi::TransportError>;

        std::vector<fortiapi::HttpRequest> requests;
        std::deque<Step> script;

        FakeTransport& reply(long status, const nlohmann::json& body) {
            script.emplace_back(fortiapi::HttpResponse{status, body.dump()});
            return *this;
        }

        // A non-JSON reply (file downloads such as a configuration backup).
        FakeTransport& reply_raw(long status, std::string body, std::string content_type = "application/octet-stream") {
            fortiapi::HttpResponse response{status, std::move(body)};
            response.headers.emplace_back("Content-Type", std::move(content_type));
            script.emplace_back(std::move(response));
            return *this;
        }

        FakeTransport& fail(int code, bool before_send) {
            script.emplace_back(fortiapi::TransportError("scripted transport failure", code, before_send));
            return *this;
        }

        fortiapi::HttpResponse perform(const fortiapi::HttpRequest& request) override {
            requests.push_back(request);
            if (script.empty()) throw std::logic_error("FakeTransport: no scripted response left");
            Step step = std::move(script.front());
            script.pop_front();
            if (auto* error = std::get_if<fortiapi::TransportError>(&step)) throw *error;
            return std::get<fortiapi::HttpResponse>(step);
        }
    };

    inline nlohmann::json envelope(nlohmann::json results, long status = 200) {
        return {{"http_method", "GET"}, {"status", status < 400 ? "success" : "error"}, {"http_status", status},
                {"results", std::move(results)}, {"vdom", "root"}, {"serial", "FGT60FTK00000000"},
                {"version", "v7.4.8"}, {"build", 2795}};
    }

    // An Engine with one profile ("lab", host fortigate.test, API key "test-key" in a memory store)
    // whose every client talks to `transport`.
    inline engine::Options options(std::shared_ptr<FakeTransport> transport, engine::Mode mode = engine::Mode::read_only) {
        engine::Options options;
        options.paths = {"/nonexistent/forti-test/config", "/nonexistent/forti-test/state", "/nonexistent/forti-test/cache"};
        options.secrets = engine::memory_secret_store();
        options.secrets->put("lab/api-key", "test-key");
        engine::ProfileSet profiles;
        engine::Profile lab;
        lab.name = "lab";
        lab.host = "fortigate.test";
        lab.port = 8443;
        lab.api_key.source = engine::SecretRef::Source::store;
        lab.mode = mode;
        profiles.profiles.emplace("lab", lab);
        profiles.default_profile = "lab";
        options.profiles = profiles;
        options.transport = [transport](const fortiapi::Config&) -> std::shared_ptr<fortiapi::Transport> { return transport; };
        return options;
    }

}  // namespace forti::fake

#endif  // FORTI_TESTS_FAKE_TRANSPORT_HPP
