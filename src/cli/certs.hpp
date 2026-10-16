//
// Client certificates for FortiOS PKI (peer) authentication of the REST API user, shared by
// `forti cert` and `forti configure`. A certificate is a named set, independent of any profile, so one
// certificate can serve several FortiGates:
//
//   <home>/ca/ca.crt, ca/ca.key       the forti CA (directory 0700, key 0600), made on first use. A
//                                     FortiGate imports it once and then trusts every certificate it
//                                     issues. The key never leaves this machine.
//   <home>/certs/<name>/ca.crt        the issuing CA: a copy of the forti CA, or the set's own CA
//   <home>/certs/<name>/ca/ca.key     the set's own CA key (--own-ca only)
//   <home>/certs/<name>/client.crt    the client certificate, CN forti-<name>
//   <home>/certs/<name>/client.p12    certificate, key and CA: what a profile's client_cert names
//   <home>/certs/<name>/client.pass   the .p12 password (0600): a profile's cert_password, source "file"
//

#ifndef FORTI_CLI_CERTS_HPP
#define FORTI_CLI_CERTS_HPP

#include <forti/engine/profile.hpp>

#include <nlohmann/json.hpp>

#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <string_view>

namespace forti::cli::certs {

    // <home>/ca (beside <home>/certs).
    std::filesystem::path forti_ca_dir(const engine::Paths& paths);

    struct Set {
        std::string name;
        std::filesystem::path dir, ca_cert, ca_dir, ca_key, client_cert, client_p12, client_pass;

        Set(const engine::Paths& paths, std::string name);
        Set(std::string name, std::filesystem::path dir);   // the files of a set in `dir` (staging)
        [[nodiscard]] bool exists() const;
    };

    // Same rules as profile names (letters, digits, - and _). Throws Failure(usage).
    void validate_name(std::string_view name);

    // The set a profile's client_cert lies in, if any.
    std::optional<std::string> used_by(const engine::Paths& paths, const engine::Profile& profile);

    // One set as JSON: name, dir, cn, issuer ("forti CA" | "own CA" | "other"), expires, expired,
    // days_left, fingerprint_sha256, password_file, used_by (profile names). The certificate details
    // need the openssl command and are left out without it.
    nlohmann::json describe(const engine::Paths& paths, const engine::ProfileSet& set, const std::string& name);
    // Every set, sorted by name.
    nlohmann::json list(const engine::Paths& paths, const engine::ProfileSet& set);
    // The forti CA: exists, path, and (when it exists) subject, expiry, fingerprint and FortiGate name.
    nlohmann::json forti_ca(const engine::Paths& paths);

    struct CreateOptions {
        bool own_ca = false;
        unsigned days = 1095;
        bool replace = false;   // replace an existing set of that name
        // Receives the .p12 password before anything is replaced; client.pass is then left out.
        std::function<void(const std::string&)> keep_password;
    };

    // Creates set `name` (issued by the forti CA, made first if needed, unless own_ca). Everything is
    // generated in a private staging directory and renamed into place, so a failure leaves the
    // previous set (or nothing) behind. Returns describe() plus files, days, replaced, forti_ca_created
    // and fortigate_unchanged (a replacement the FortiGate already accepts: same CA, same CN).
    nlohmann::json create(const engine::Paths& paths, const engine::ProfileSet& set, const std::string& name,
                          const CreateOptions& options);

    // Points `profile` at set `name`: client_cert, and cert_password from client.pass. A set made with
    // --keychain has no client.pass; its password is then taken from a profile that already uses it,
    // and returned when it came from the secret store, for the caller to store under `profile`
    // (cert_password then has source "store"). Throws Failure(config) when there is no such set or
    // no known password.
    std::optional<std::string> attach(engine::Profile& profile, const engine::Paths& paths, const engine::ProfileSet& set,
                                      engine::SecretStore& store, const std::string& name);

    // What a FortiGate needs to accept set `name` for an API user: ca_name, peer, peer_group, and
    // steps (FortiOS CLI, one line per element, with the CA certificate inline, ready to paste).
    nlohmann::json fortigate(const engine::Paths& paths, const std::string& name);
    std::string steps_text(const nlohmann::json& fortigate);

}  // namespace forti::cli::certs

#endif  // FORTI_CLI_CERTS_HPP
