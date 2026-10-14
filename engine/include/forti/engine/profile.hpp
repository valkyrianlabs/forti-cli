//
// Device profiles and credentials. A profile says where a FortiGate is and how to reach it; it holds
// references to secrets, never the secrets. Locations never depend on the working directory.
//
//   config  $FORTI_CONFIG_DIR | $XDG_CONFIG_HOME/forti | ~/.config/forti   config.json, credentials/
//   state   $FORTI_STATE_DIR  | $XDG_STATE_HOME/forti  | ~/.local/state/forti   plans/, approvals/, audit.jsonl
//   cache   $FORTI_CACHE_DIR  | $XDG_CACHE_HOME/forti  | ~/.cache/forti   schema/<fortios version>/
//

#ifndef FORTI_ENGINE_PROFILE_HPP
#define FORTI_ENGINE_PROFILE_HPP

#include <nlohmann/json.hpp>

#include <filesystem>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace forti::engine {

    struct Paths {
        std::filesystem::path config, state, cache;

        static Paths from_env();
        [[nodiscard]] std::filesystem::path config_file() const { return config / "config.json"; }
    };

    // Where a secret comes from. The secret itself is never stored in config.json.
    struct SecretRef {
        enum class Source { none, store, env, command };
        Source source = Source::none;
        std::string env;                    // Source::env: variable name
        std::vector<std::string> command;   // Source::command: argv; stdout's first line is the secret

        [[nodiscard]] nlohmann::json to_json() const;
        static SecretRef from_json(const nlohmann::json& json);
    };

    // What the engine may do on a device (architecture.md, "Operating modes"). The FortiOS account's
    // own privileges remain the primary authorization boundary; the mode is the operator's policy on top.
    enum class Mode {
        read_only,    // no mutations (default)
        guarded,      // mutations need a human approval of the exact plan (`forti plan approve`)
        autonomous,   // mutations run without interactive approval; safeguards still apply
    };

    std::string_view to_string(Mode mode);
    // "read-only" | "guarded" | "autonomous"; throws Failure(config) otherwise.
    Mode parse_mode(std::string_view text);

    struct Profile {
        std::string name;
        std::string host;
        unsigned port = 443;
        std::string vdom;          // empty: the device default
        std::string ca_bundle;     // PEM; empty: system trust store
        std::string client_cert;   // PKCS#12 path; empty: none
        std::string resolve_ip;    // connect here while verifying TLS for `host`
        SecretRef api_key;         // default: Source::store
        SecretRef cert_password;   // default: none
        Mode mode = Mode::read_only;
        unsigned connect_timeout_ms = 5000;
        unsigned timeout_ms = 30000;

        [[nodiscard]] nlohmann::json to_json() const;          // config.json form (no secrets)
        [[nodiscard]] nlohmann::json describe() const;         // safe summary for output
        static Profile from_json(std::string name, const nlohmann::json& json);

        // Secret-store account names.
        [[nodiscard]] std::string api_key_account() const { return name + "/api-key"; }
        [[nodiscard]] std::string cert_password_account() const { return name + "/cert-password"; }
    };

    // [A-Za-z0-9_-]{1,64}; throws Failure(usage) otherwise.
    void validate_profile_name(std::string_view name);

    struct ProfileSet {
        std::string default_profile;
        std::map<std::string, Profile> profiles;

        [[nodiscard]] nlohmann::json to_json() const;
        static ProfileSet from_json(const nlohmann::json& json);

        // The named profile, or the default (or the only one) when `name` is empty. Throws Failure(config).
        [[nodiscard]] const Profile& select(std::string_view name) const;
    };

    // config.json: read, and written atomically with mode 0600 in a 0700 directory.
    class ProfileStore {
        Paths paths_;

    public:
        explicit ProfileStore(Paths paths) : paths_(std::move(paths)) {}

        [[nodiscard]] const Paths& paths() const { return paths_; }
        [[nodiscard]] bool exists() const;
        [[nodiscard]] ProfileSet load() const;   // empty set when the file does not exist
        void save(const ProfileSet& set) const;
    };

    // Secret storage backends. Accounts are "<profile>/api-key", "<profile>/cert-password".
    class SecretStore {
    public:
        virtual ~SecretStore() = default;
        [[nodiscard]] virtual std::string_view kind() const = 0;   // "keychain", "file", "memory"
        virtual std::optional<std::string> get(std::string_view account) = 0;
        virtual void put(std::string_view account, std::string_view secret) = 0;
        virtual bool erase(std::string_view account) = 0;
    };

    // <config>/credentials/<account with '/' → '.'>, mode 0600, directory 0700.
    std::shared_ptr<SecretStore> file_secret_store(const Paths& paths);
    // macOS: the login Keychain (service "forti"); elsewhere: file_secret_store.
    std::shared_ptr<SecretStore> default_secret_store(const Paths& paths);
    // In-memory, for tests and embedding.
    std::shared_ptr<SecretStore> memory_secret_store();

    // Resolves a SecretRef. Throws Failure(config) naming the profile and source, never the value.
    std::string resolve_secret(const SecretRef& ref, std::string_view account, SecretStore& store);

    // Creates `dir` (and parents) and restricts it to the owner (0700).
    void ensure_private_dir(const std::filesystem::path& dir);
    // Writes `content` to `file` atomically (temp file + rename) with mode 0600.
    void write_private_file(const std::filesystem::path& file, std::string_view content);

}  // namespace forti::engine

#endif  // FORTI_ENGINE_PROFILE_HPP
