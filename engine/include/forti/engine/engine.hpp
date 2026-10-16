//
// forti::engine::Engine: the command semantics shared by `forti` and `forti-mcp`.
//
// JSON request in, JSON result out (architecture.md, "Engine contract"). The CLI turns argv into a
// request; the MCP server passes tool arguments through. Both render the same result envelope:
//
//   {"ok": true,  "data": ..., "meta": {...}}
//   {"ok": false, "error": {"code": "...", "message": "...", "details": {...}}}
//
// Operations throw Failure; envelope() / run() turn a call into the envelope. Not thread-safe: one
// Engine per thread (both executables are single-threaded).
//

#ifndef FORTI_ENGINE_ENGINE_HPP
#define FORTI_ENGINE_ENGINE_HPP

#include "catalog.hpp"
#include "error.hpp"
#include "profile.hpp"

#include <forti_api/client.hpp>

#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>

namespace forti::engine {

    struct Options {
        Paths paths = Paths::from_env();
        // null: default_secret_store(paths)
        std::shared_ptr<SecretStore> secrets;
        // null: the SDK's libcurl transport. Tests inject a scripted fortiapi::Transport here.
        std::function<std::shared_ptr<fortiapi::Transport>(const fortiapi::Config&)> transport;
        // Set: use these profiles instead of config.json (tests, embedding).
        std::optional<ProfileSet> profiles;
        // Who drives this engine, recorded in audit events ("cli:alice", "mcp:claude-code"). Empty: not recorded.
        std::string actor;
    };

    // Plan ids: 12-32 characters of [a-z0-9-], starting with a letter or digit, so an id is safe to
    // paste into a shell command and never parses as an option. The engine generates
    // "YYYYMMDD-HHMMSS-xxxxxx" (UTC time, 6 random hex digits). apply/show/approve reject anything else
    // with `usage`. forti-mcp's inputSchema uses the same pattern.
    inline constexpr std::string_view plan_id_pattern = "^[a-z0-9][a-z0-9-]{11,31}$";
    [[nodiscard]] bool valid_plan_id(std::string_view id);

    // Read-size limits (the MCP adapter applies its own byte budget on top).
    inline constexpr std::size_t default_page = 50;
    inline constexpr std::size_t max_page = 1000;

    class Engine {
        Options options_;
        std::shared_ptr<SecretStore> secrets_;
        std::optional<ProfileSet> profiles_;
        std::map<std::string, std::shared_ptr<fortiapi::Client>, std::less<>> clients_;

    public:
        explicit Engine(Options options = {});

        [[nodiscard]] const Options& options() const { return options_; }
        [[nodiscard]] SecretStore& secrets() { return *secrets_; }
        [[nodiscard]] const ProfileSet& profiles();   // loaded on first use
        [[nodiscard]] const Profile& profile(std::string_view name);

        // A connected SDK client for a profile (created on first use, secrets resolved then).
        fortiapi::Client& client(const Profile& profile);

        // ---- The four operations (requests: architecture.md, "Requests") ----
        nlohmann::json discover(const nlohmann::json& request);
        // Device secrets in the result are redacted (architecture.md, "Read redaction"): string values
        // starting "ENC " and values of sensitive attribute names become "<redacted>", listed in
        // meta.redacted. Only a C++ caller can pass Secrets::reveal (the CLI's `forti get --reveal`);
        // no request field turns redaction off, so MCP cannot.
        enum class Secrets { redact, reveal };
        nlohmann::json read(const nlohmann::json& request, Secrets secrets = Secrets::redact);
        nlohmann::json plan(const nlohmann::json& request);
        nlohmann::json apply(const nlohmann::json& request);

        // Calls `operation` and wraps its result (or the translated failure) in the envelope.
        static nlohmann::json envelope(const std::function<nlohmann::json()>& operation);
    };

    // Successful envelope from data and meta.
    nlohmann::json ok(nlohmann::json data, nlohmann::json meta = nlohmann::json::object());

}  // namespace forti::engine

#endif  // FORTI_ENGINE_ENGINE_HPP
