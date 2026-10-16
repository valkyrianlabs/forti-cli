//
// Setup commands: `forti configure` (create or update a profile and verify it against the device),
// `forti profile …` (list, show, default, mode, remove) and `forti doctor` (ordered diagnostics).
//
// Secrets are never accepted as argument values. They come from a hidden prompt on /dev/tty, from
// stdin (--api-key-stdin), or are referenced by name (--api-key-env VAR, --api-key-command "argv").
// Nothing is written until the device accepted the profile (or --skip-check), and an authentication
// failure is never retried: FortiOS locks the API user out after a few failed attempts.
//

#include "certs.hpp"
#include "commands.hpp"
#include "setup_support.hpp"
#include "tty.hpp"

#include <algorithm>
#include <cerrno>
#include <charconv>
#include <csignal>
#include <cstdlib>
#include <filesystem>
#include <format>
#include <fstream>
#include <iostream>
#include <ostream>
#include <tuple>

#include <arpa/inet.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>

namespace forti::cli {

    using engine::Code;
    using engine::Failure;
    using engine::Mode;
    using engine::Profile;
    using engine::ProfileSet;
    using engine::ProfileStore;
    using engine::SecretRef;
    using json = nlohmann::json;
    namespace fs = std::filesystem;

    namespace {

        constexpr std::string_view autonomous_notice =
                "Autonomous mode: an agent using this profile (for example through forti-mcp) applies changes\n"
                "without asking you first. It can do anything this FortiOS API account is permitted to do,\n"
                "including changes that interrupt management access. Plans are still validated, checked for\n"
                "drift, verified after each step, audited and paired with a rollback plan. The account's admin\n"
                "profile and trusted hosts are the real boundary: scope them to what the agent should manage.\n";


        // ---- validation ----

        void validate_host(std::string_view host) {
            bool bracketed = host.starts_with('[') && host.ends_with(']');
            if (host.empty()) throw Failure(Code::usage, "--host is required");
            if (host.find("://") != std::string_view::npos || host.find('/') != std::string_view::npos)
                throw Failure(Code::usage, std::format("--host takes a host name or address, not a URL: {}", host),
                              {{"hint", "e.g. --host fw.example.net --port 8443"}});
            if (!bracketed && host.find(':') != std::string_view::npos)
                throw Failure(Code::usage, std::format("--host must not contain a port: {}", host),
                              {{"hint", "pass the port with --port; write an IPv6 address as [2001:db8::1]"}});
            for (char c: host)
                if (std::isspace(static_cast<unsigned char>(c)) || std::iscntrl(static_cast<unsigned char>(c)))
                    throw Failure(Code::usage, "--host contains whitespace");
        }

        unsigned parse_port(const std::string& text) {
            std::size_t value = to_count("port", text);
            if (value == 0 || value > 65535) throw Failure(Code::usage, "--port must be between 1 and 65535");
            return static_cast<unsigned>(value);
        }

        void validate_vdom(std::string_view vdom) {
            bool valid = vdom.size() <= 31;
            for (char c: vdom) valid = valid && (std::isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_' || c == '.');
            if (!valid) throw Failure(Code::usage, std::format("invalid VDOM name: {}", vdom));
        }

        void validate_ip(std::string_view ip) {
            unsigned char buffer[16];
            std::string text(ip);
            if (::inet_pton(AF_INET, text.c_str(), buffer) != 1 && ::inet_pton(AF_INET6, text.c_str(), buffer) != 1)
                throw Failure(Code::usage, std::format("--resolve-ip expects an IPv4 or IPv6 address: {}", ip));
        }

        void validate_env_name(std::string_view name) {
            bool valid = !name.empty() && !std::isdigit(static_cast<unsigned char>(name.front()));
            for (char c: name) valid = valid && (std::isalnum(static_cast<unsigned char>(c)) || c == '_');
            if (!valid) throw Failure(Code::usage, std::format("not an environment variable name: {}", name),
                                      {{"hint", "pass the variable's name (FORTI_API_KEY), not its value"}});
        }

        // An absolute path to a readable regular file (config must not depend on the working directory).
        std::string readable_file(std::string_view option, const std::string& text) {
            if (text.empty()) return "";
            std::error_code error;
            fs::path path = fs::absolute(text, error).lexically_normal();
            if (error || !fs::is_regular_file(path, error))
                throw Failure(Code::config, std::format("--{}: no such file: {}", option, text));
            if (::access(path.c_str(), R_OK) != 0)
                throw Failure(Code::config, std::format("--{}: cannot read {}", option, path.string()));
            return path.string();
        }

        Mode parse_mode_option(const std::string& text) {
            try {
                return engine::parse_mode(text);
            } catch (const Failure& failure) {
                throw Failure(Code::usage, failure.what(), {{"hint", "--mode read-only | guarded | autonomous"}});
            }
        }

        // ---- connection advice (configure and doctor) ----

        struct Advice {
            std::string stage;   // dns | tcp | timeout | tls | network
            std::string summary;
            std::string hint;
        };

        // curl codes as reported by the SDK's TransportError (forti::engine details.curl_code).
        Advice connection_advice(int curl_code, const Profile& profile) {
            std::string where = std::format("{}:{}", profile.host, profile.port);
            switch (curl_code) {
                case 6:
                    return {"dns", std::format("cannot resolve {}", profile.host),
                            "check the host name, or pin its address with --resolve-ip IP (TLS is still verified "
                            "against the host name)"};
                case 7:
                    return {"tcp", std::format("cannot connect to {}", where),
                            "check the address and the admin HTTPS port (--port), and that HTTPS administrative "
                            "access is enabled on the interface you connect to"};
                case 28:
                    return {"timeout", std::format("timed out connecting to {}", where),
                            "the traffic may be filtered or the port wrong; check the route, --port, and that this "
                            "machine is within the API user's trusted hosts"};
                case 51:
                case 60:
                case 83:
                    return {"tls", std::format("the certificate presented by {} is not trusted", where),
                            "export the FortiGate's CA (or its self-signed certificate) as PEM and set --ca-bundle "
                            "PATH; if the certificate names another host, use that name as --host and --resolve-ip "
                            "for the address. forti never disables certificate verification"};
                case 77:
                    return {"tls", "the CA bundle cannot be loaded",
                            "check that --ca-bundle points to a readable PEM file"};
                case 58:
                    return {"tls", "the client certificate cannot be loaded",
                            "check --client-cert (PKCS#12) and its password source"};
                case 35:
                    return {"tls", std::format("the TLS handshake with {} failed", where),
                            "check that --port is the HTTPS admin port; if the device requires a client "
                            "certificate, set --client-cert"};
                case 52:
                case 55:
                case 56:
                    return {"network", std::format("{} closed the connection", where),
                            "check the port and that HTTPS administrative access is enabled"};
                default:
                    return {"network", std::format("cannot reach {}", where), "run `forti doctor` for details"};
            }
        }

        // Adds an actionable hint to a verification failure.
        Failure with_advice(const Failure& failure, const Profile& profile, bool saved) {
            json details = failure.details();
            std::string message = failure.what();
            std::string nothing = saved ? "" : "Nothing was saved. ";
            if (failure.code() == Code::connection) {
                auto advice = connection_advice(details.value("curl_code", 0), profile);
                message = advice.summary;
                details["stage"] = advice.stage;
                details["hint"] = nothing + advice.hint + " (or save without checking: --skip-check)";
                details["transport_error"] = failure.what();
            } else if (failure.code() == Code::auth) {
                message = std::format("{} rejected the API key (HTTP {})", profile.host, details.value("http_status", 401));
                details["hint"] = nothing + "forti did not retry: FortiOS locks an API user out after repeated failures. "
                                            "Check the key, that this machine is within the API user's trusted hosts, "
                                            "and the user's admin profile";
            }
            return {failure.code(), message, details};
        }

        // ---- configure ----

        // The real store plus secrets not yet written, so a profile is verified before anything is saved.
        // Everything read through it is bound to the profile being configured (`binding`): the operator
        // is pointing this profile at that device now, so a kept key is re-bound to it on save.
        class PendingStore final : public engine::SecretStore {
            engine::SecretStore& base_;
            std::map<std::string, std::string, std::less<>> pending_;
            std::string binding_;

        public:
            explicit PendingStore(engine::SecretStore& base) : base_(base) {}
            void bind(std::string binding) { binding_ = std::move(binding); }
            void stage(std::string account, std::string secret) { pending_.insert_or_assign(std::move(account), std::move(secret)); }

            std::string_view kind() const override { return base_.kind(); }
            std::optional<engine::StoredSecret> get(std::string_view account) override {
                if (auto it = pending_.find(account); it != pending_.end()) return engine::StoredSecret{it->second, binding_};
                auto stored = base_.get(account);
                if (stored) stored->binding = binding_;
                return stored;
            }
            void put(std::string_view account, std::string_view secret, std::string_view) override {
                stage(std::string(account), std::string(secret));
            }
            bool erase(std::string_view account) override { return pending_.erase(std::string(account)) > 0; }

            // Writes staged secrets, and re-binds kept ones, for the store-source accounts of `profile`.
            void commit(const Profile& profile) {
                auto binding = profile.secret_binding();
                auto write = [&](const engine::SecretRef& ref, const std::string& account) {
                    if (ref.source != engine::SecretRef::Source::store) return;
                    if (auto it = pending_.find(account); it != pending_.end()) base_.put(account, it->second, binding);
                    else if (auto stored = base_.get(account); stored && stored->binding != binding)
                        base_.put(account, stored->secret, binding);
                };
                write(profile.api_key, profile.api_key_account());
                write(profile.cert_password, profile.cert_password_account());
            }
        };

        std::string read_stdin_secret(const Context& context, std::string_view what) {
            std::optional<std::string> line;
            if (context.output.in) {
                std::string text;
                if (std::getline(*context.output.in, text)) line = text;
            } else {
                if (::isatty(STDIN_FILENO)) std::cerr << what << ": " << std::flush;
                line = read_line(STDIN_FILENO, true);
            }
            std::string secret = line ? trim(*line) : "";
            if (secret.empty()) throw Failure(Code::usage, std::format("no {} on standard input", what));
            return secret;
        }

        struct Draft {
            Profile profile;
            Profile previous;
            bool existed = false;
            bool make_default = false;
            PendingStore* secrets = nullptr;
            std::optional<std::string> certificate;   // a forti certificate newly chosen: the FortiGate may not know it
            bool created_certificate = false;
        };

        // An owner-only secret file (SecretRef source "file"), as an absolute path. The engine checks it
        // again on every read; checking now reports a loose mode while the operator is at the keyboard.
        std::string private_file(std::string_view option, const std::string& text) {
            std::error_code error;
            fs::path path = fs::absolute(text, error).lexically_normal();
            struct stat info{};
            if (error || ::lstat(path.c_str(), &info) != 0 || !S_ISREG(info.st_mode))
                throw Failure(Code::config, std::format("--{}: no such regular file: {}", option, text));
            if (info.st_uid != ::geteuid())
                throw Failure(Code::config, std::format("--{}: {} is owned by another user", option, path.string()));
            if (info.st_mode & (S_IRWXG | S_IRWXO))
                throw Failure(Code::config, std::format("--{}: {} is readable by other users", option, path.string()),
                              {{"hint", std::format("chmod 600 {}", shell_quote(path.string()))}});
            return path.string();
        }

        // Applies one credential option family (api-key / cert-password) to `ref`. --cert-password-file
        // exists for the certificate password only (forti cert create writes such a file).
        void credential_options(const Context& context, const Args& args, std::string_view family, SecretRef& ref,
                                const std::string& account, PendingStore& secrets) {
            std::string stdin_flag = std::format("{}-stdin", family), env = std::format("{}-env", family),
                        command = std::format("{}-command", family), file = std::format("{}-file", family);
            int given = args.flag(stdin_flag) + args.value(env).has_value() + args.value(command).has_value() +
                        args.value(file).has_value();
            if (given > 1)
                throw Failure(Code::usage, std::format("pass only one of --{0}-stdin, --{0}-env and --{0}-command{1}", family,
                                                       family == "cert-password" ? " and --cert-password-file" : ""));
            if (args.flag(stdin_flag)) {
                ref = {SecretRef::Source::store, {}, {}, {}};
                secrets.stage(account, read_stdin_secret(context, family == "api-key" ? "API key" : "certificate password"));
            } else if (auto name = args.value(env)) {
                validate_env_name(*name);
                ref = {SecretRef::Source::env, *name, {}, {}};
            } else if (auto line = args.value(command)) {
                auto argv = split_command(*line);
                if (argv.empty()) throw Failure(Code::usage, std::format("--{} is empty", command));
                ref = {SecretRef::Source::command, {}, std::move(argv), {}};
            } else if (auto path = args.value(file)) {
                ref = {SecretRef::Source::file, {}, {}, private_file(file, *path)};
            }
        }

        bool interactive_requested(const Args& args) {
            for (const char* name: {"host", "port", "vdom", "ca-bundle", "client-cert", "cert", "resolve-ip", "api-key-env",
                                    "api-key-command", "cert-password-env", "cert-password-command", "cert-password-file", "mode"})
                if (args.value(name)) return false;
            for (const char* name: {"api-key-stdin", "cert-password-stdin", "default"})
                if (args.flag(name)) return false;
            return true;
        }

        void non_interactive(const Context& context, const Args& args, const ProfileSet& set, Draft& draft) {
            Profile& p = draft.profile;
            if (auto host = args.value("host")) p.host = *host;
            if (p.host.empty())
                throw Failure(Code::usage, std::format("--host is required for the new profile \"{}\"", p.name));
            validate_host(p.host);
            if (auto port = args.value("port")) p.port = parse_port(*port);
            if (auto vdom = args.value("vdom")) validate_vdom(p.vdom = *vdom);
            if (auto path = args.value("ca-bundle")) p.ca_bundle = readable_file("ca-bundle", *path);
            if (args.value("cert") && args.value("client-cert")) throw Failure(Code::usage, "pass --cert NAME or --client-cert PATH, not both");
            if (auto path = args.value("client-cert")) p.client_cert = readable_file("client-cert", *path);
            if (auto ip = args.value("resolve-ip")) {
                if (!ip->empty()) validate_ip(*ip);
                p.resolve_ip = *ip;
            }
            if (auto mode = args.value("mode")) p.mode = parse_mode_option(*mode);
            if (args.flag("api-key-stdin") && args.flag("cert-password-stdin"))
                throw Failure(Code::usage, "standard input can carry only one secret: use --cert-password-env or "
                                           "--cert-password-command for the certificate password");
            credential_options(context, args, "api-key", p.api_key, p.api_key_account(), *draft.secrets);
            if (auto name = args.value("cert")) {
                // One of forti's certificates: its client.p12 and, unless a password option is given, its password.
                const auto& paths = context.engine.options().paths;
                certs::validate_name(*name);
                bool password_given = args.flag("cert-password-stdin") || args.value("cert-password-env") ||
                                      args.value("cert-password-command") || args.value("cert-password-file");
                if (password_given) {
                    certs::Set files(paths, *name);
                    if (!fs::exists(files.client_p12))
                        throw Failure(Code::config, std::format("no certificate named \"{}\"", *name), {{"hint", "forti cert list shows them"}});
                    p.client_cert = files.client_p12.string();
                } else if (auto password = certs::attach(p, paths, set, context.engine.secrets(), *name))
                    draft.secrets->stage(p.cert_password_account(), *password);
            }
            credential_options(context, args, "cert-password", p.cert_password, p.cert_password_account(), *draft.secrets);
            if (p.api_key.source == SecretRef::Source::none)
                throw Failure(Code::usage, "no API key source: pass --api-key-stdin, --api-key-env VAR or --api-key-command \"argv\"",
                              {{"hint", "the key itself is never accepted as an argument"}});
            if (p.cert_password.source != SecretRef::Source::none && p.client_cert.empty())
                throw Failure(Code::usage, "a certificate password needs --client-cert");
            if (args.flag("default")) draft.make_default = true;
        }

        // The password of a PKCS#12 file of the operator's own (not one of forti's certificates).
        void external_password(const Context& context, Draft& draft, const Tty& tty) {
            Profile& p = draft.profile;
            bool had = p.cert_password.source != SecretRef::Source::none;
            if (!tty.confirm("Does the client certificate have a password?", had)) {
                p.cert_password = {};
                return;
            }
            // Enter keeps the current source (a stored password, a variable, a command or a file); a typed
            // password goes to the secret store.
            std::string label = had ? std::format("Certificate password (Enter keeps the {})",
                                                  describe_source(p.cert_password, context.engine.secrets().kind()))
                                    : std::string("Certificate password (stored in the secret store)");
            for (;;) {
                std::string password = tty.ask(label, "", true);
                if (password.empty() && !had) continue;
                if (!password.empty()) {
                    p.cert_password = {SecretRef::Source::store, {}, {}, {}};
                    draft.secrets->stage(p.cert_password_account(), password);
                }
                return;
            }
        }

        // Points the profile at a forti certificate set; a set made with --keychain whose password no
        // profile holds asks for it.
        void attach_certificate(const Context& context, const ProfileSet& set, Draft& draft, const Tty& tty, const std::string& name) {
            Profile& p = draft.profile;
            const auto& paths = context.engine.options().paths;
            try {
                if (auto password = certs::attach(p, paths, set, context.engine.secrets(), name))
                    draft.secrets->stage(p.cert_password_account(), *password);
            } catch (const Failure& failure) {
                tty.say(std::format("  {}\n", failure.what()));
                std::string password;
                while (password.empty()) password = tty.ask("Password of its client.p12 (stored in the secret store)", "", true);
                p.client_cert = certs::Set(paths, name).client_p12.string();
                p.cert_password = {SecretRef::Source::store, {}, {}, {}};
                draft.secrets->stage(p.cert_password_account(), password);
            }
            draft.certificate = name;
        }

        // Client certificate: keep the current one, reuse one of the forti certificates, make a new one
        // (issued by the forti CA, or with its own CA), or name a PKCS#12 file.
        void certificate_step(const Context& context, const ProfileSet& set, Draft& draft, const Tty& tty) {
            Profile& p = draft.profile;
            const auto& paths = context.engine.options().paths;
            if (!p.client_cert.empty()) {
                auto current = certs::used_by(paths, p);
                std::string what = current ? std::format("certificate \"{}\"", *current) : display_path(p.client_cert);
                if (tty.confirm(std::format("\nKeep the client certificate ({})?", what), true)) {
                    if (!current) external_password(context, draft, tty);
                    return;
                }
                p.client_cert.clear();
                p.cert_password = {};
            }
            tty.say("\nA client certificate makes the FortiGate require this machine's certificate on top of the\n"
                    "API key (PKI authentication of the API user). forti makes one and prints the FortiGate commands.\n");
            if (!tty.confirm("Use a client certificate?", false)) return;

            json existing = certs::list(paths, set);
            if (!existing.empty() && tty.confirm("Reuse a certificate you already have?", true)) {
                std::size_t width = 0;
                for (const auto& cert: existing) width = std::max(width, cert.value("name", "").size());
                tty.say("\n");
                for (std::size_t k = 0; k < existing.size(); ++k) {
                    const json& cert = existing[k];
                    std::string users;
                    for (const auto& user: cert["used_by"]) users += (users.empty() ? "" : ", ") + user.get<std::string>();
                    std::string expires = cert.value("expires", "?").substr(0, 10);
                    tty.say(std::format("  {}) {:<{}}  {}, until {}{}{}\n", k + 1, cert.value("name", ""), width, cert.value("issuer", ""),
                                        expires, cert.value("expired", false) ? " (EXPIRED)" : "", users.empty() ? "" : "; used by " + users));
                }
                tty.say("  0) none of these: create a new one\n");
                for (;;) {
                    std::string answer = tty.ask("Certificate", "1");
                    std::size_t value = 0;
                    auto [end, ec] = std::from_chars(answer.data(), answer.data() + answer.size(), value);
                    if (ec != std::errc() || end != answer.data() + answer.size() || value > existing.size()) continue;
                    if (value == 0) break;
                    attach_certificate(context, set, draft, tty, existing[value - 1].value("name", ""));
                    return;
                }
            }

            std::size_t kind = tty.choose("\nNew certificate:",
                                          {"issued by the forti CA (recommended: a FortiGate imports the forti CA once and then\n"
                                           "     accepts every certificate it issues)",
                                           "with a CA of its own (the FortiGate imports that CA as well)",
                                           "a PKCS#12 file I already have"},
                                          0);
            if (kind == 2) {
                for (;;) {
                    try {
                        p.client_cert = readable_file("client-cert", tty.ask("PKCS#12 file"));
                        break;
                    } catch (const Failure& failure) {
                        tty.say(std::format("  {}\n", failure.what()));
                    }
                }
                external_password(context, draft, tty);
                return;
            }
            std::string fallback = p.name;
            for (int n = 2; certs::Set(paths, fallback).exists(); ++n) fallback = std::format("{}-{}", p.name, n);
            std::string name;
            for (;;) {
                name = tty.ask("Certificate name", fallback);
                try {
                    certs::validate_name(name);
                } catch (const Failure& failure) {
                    tty.say(std::format("  {}\n", failure.what()));
                    continue;
                }
                if (!certs::Set(paths, name).exists()) break;
                tty.say(std::format("  \"{}\" already exists: reuse it, or pick another name\n", name));
            }
            tty.say("Making the certificate... ");
            certs::CreateOptions options;
            options.own_ca = kind == 1;
            json made = certs::create(paths, set, name, options);
            tty.say(std::format("done: {}{}\n", display_path(made.value("dir", "")),
                                made.value("forti_ca_created", false) ? " (and the forti CA, " + display_path(certs::forti_ca_dir(paths)) + ")" : ""));
            attach_certificate(context, set, draft, tty, name);
            draft.created_certificate = true;
        }

        void interactive(const Context& context, const Args& args, const ProfileSet& set, Draft& draft, const Tty& tty) {
            Profile& p = draft.profile;
            tty.say("Configure a FortiGate profile. Press Enter to keep the value in [brackets].\n\n");
            if (!args.value("profile")) {
                std::string fallback = set.default_profile.empty() ? "default" : set.default_profile;
                for (;;) {
                    std::string name = tty.ask("Profile name", fallback);
                    try {
                        engine::validate_profile_name(name);
                    } catch (const Failure& failure) {
                        tty.say(std::format("  {}\n", failure.what()));
                        continue;
                    }
                    if (auto it = set.profiles.find(name); it != set.profiles.end()) {
                        p = draft.previous = it->second;
                        draft.existed = true;
                    } else {
                        p = Profile{};
                        p.name = name;
                        p.api_key.source = SecretRef::Source::none;
                        draft.existed = false;
                    }
                    break;
                }
            }
            auto retry = [&](auto&& step) {
                for (;;) {
                    try {
                        step();
                        return;
                    } catch (const Failure& failure) {
                        tty.say(std::format("  {}\n", failure.what()));
                    }
                }
            };
            retry([&] { validate_host(p.host = tty.ask("FortiGate host name or address", p.host)); });
            retry([&] { p.port = parse_port(tty.ask("Admin HTTPS port", std::to_string(p.port))); });
            retry([&] {
                std::string vdom = tty.ask("VDOM (Enter: the device default; - to clear)", p.vdom);
                validate_vdom(p.vdom = vdom == "-" ? "" : vdom);
            });
            retry([&] {
                std::string path = tty.ask("CA bundle, PEM (Enter: system trust store; - to clear)", p.ca_bundle);
                p.ca_bundle = path == "-" ? "" : readable_file("ca-bundle", path);
            });
            retry([&] {
                std::string ip = tty.ask("Connect to this IP instead of resolving the host (optional; - to clear)", p.resolve_ip);
                if (ip == "-") ip.clear();
                if (!ip.empty()) validate_ip(ip);
                p.resolve_ip = ip;
            });

            std::string store = describe_source({SecretRef::Source::store, {}, {}, {}}, context.engine.secrets().kind());
            tty.say(std::format("\nWhere should forti get the API key?\n"
                                "  1) store it in the {} (you type it now, hidden)\n"
                                "  2) read an environment variable each time\n"
                                "  3) run a command that prints it (a password manager, for example)\n", store));
            std::string current = p.api_key.source == SecretRef::Source::env ? "2"
                                  : p.api_key.source == SecretRef::Source::command ? "3" : "1";
            for (;;) {
                std::string choice = tty.ask("Choice", current);
                if (choice == "1") {
                    bool have = draft.existed && p.api_key.source == SecretRef::Source::store &&
                                context.engine.secrets().get(p.api_key_account());
                    std::string key = tty.ask(have ? "API key (Enter keeps the stored key)" : "API key", "", true);
                    if (key.empty() && !have) continue;
                    p.api_key = {SecretRef::Source::store, {}, {}, {}};
                    if (!key.empty()) draft.secrets->stage(p.api_key_account(), key);
                    break;
                }
                if (choice == "2") {
                    std::string name = tty.ask("Variable name", p.api_key.source == SecretRef::Source::env ? p.api_key.env : "FORTI_API_KEY");
                    try {
                        validate_env_name(name);
                    } catch (const Failure& failure) {
                        tty.say(std::format("  {}\n", failure.what()));
                        continue;
                    }
                    p.api_key = {SecretRef::Source::env, name, {}, {}};
                    break;
                }
                if (choice == "3") {
                    std::string line = tty.ask("Command (run without a shell; quotes group words)",
                                               p.api_key.source == SecretRef::Source::command ? shell_join(p.api_key.command) : "");
                    auto argv = split_command(line);
                    if (argv.empty()) continue;
                    p.api_key = {SecretRef::Source::command, {}, std::move(argv), {}};
                    break;
                }
            }
            certificate_step(context, set, draft, tty);

            tty.say("\nOperating mode:\n"
                    "  1) read-only   reads only; every change is refused (recommended to start)\n"
                    "  2) guarded     changes apply after you approve each plan with `forti plan approve`\n"
                    "  3) autonomous  changes apply without approval; automatic safeguards still apply\n");
            std::string mode = p.mode == Mode::guarded ? "2" : p.mode == Mode::autonomous ? "3" : "1";
            for (;;) {
                std::string choice = tty.ask("Mode", mode);
                if (choice == "1" || choice == "read-only") p.mode = Mode::read_only;
                else if (choice == "2" || choice == "guarded") p.mode = Mode::guarded;
                else if (choice == "3" || choice == "autonomous") p.mode = Mode::autonomous;
                else continue;
                break;
            }
            if (p.mode == Mode::autonomous && draft.previous.mode != Mode::autonomous) tty.say(std::format("\n{}", autonomous_notice));

            bool is_default = set.default_profile == p.name || set.profiles.empty() ||
                              (set.default_profile.empty() && set.profiles.size() == 1 && draft.existed);
            draft.make_default = is_default || tty.confirm("\nMake this the default profile?", set.default_profile.empty());
            tty.say("\n");
        }

        json verify(Context& context, const Profile& profile, PendingStore& secrets) {
            engine::Options options;
            options.paths = context.engine.options().paths;
            options.transport = context.engine.options().transport;
            options.secrets = std::shared_ptr<engine::SecretStore>(std::shared_ptr<void>(), &secrets);
            ProfileSet only;
            only.profiles.emplace(profile.name, profile);
            only.default_profile = profile.name;
            options.profiles = std::move(only);
            engine::Engine probe(std::move(options));
            json result = probe.discover({{"what", "capabilities"}, {"profile", profile.name}});
            return result.value("data", json::object());
        }

        void render_configured(std::ostream& out, const json& data, const json&) {
            const json& profile = data["profile"];
            out << styled(std::format("Saved profile \"{}\"{}", profile.value("name", ""),
                                      data.value("default", false) ? " (default)" : ""), Style::bold)
                << " in " << data.value("config_file", "") << "\n";
            auto line = [&](std::string_view label, const std::string& value) { out << std::format("  {:<12} {}\n", label, value); };
            line("host", std::format("{}:{}", profile.value("host", ""), profile.value("port", 443)));
            if (data.contains("device")) {
                const json& device = data["device"];
                std::string text = device.value("hostname", "");
                for (const char* key: {"model_name", "model", "version", "serial"})
                    if (device.contains(key) && device[key].is_string())
                        text += (text.empty() ? "" : "  ") + device[key].get<std::string>();
                line("device", text);
            } else line("device", styled("not checked", Style::yellow));
            line("api key", data.value("api_key_source", ""));
            if (data.contains("client_cert")) line("client cert", data["client_cert"].get<std::string>());
            line("mode", profile.value("mode", "read-only"));
            if (data.contains("schema_note")) out << styled("  note: ", Style::yellow) << data["schema_note"].get<std::string>() << "\n";
            if (data.contains("notice")) out << "\n" << data["notice"].get<std::string>();
            if (data.contains("home_note")) out << styled("  note: ", Style::yellow) << data["home_note"].get<std::string>() << "\n";
            out << "\nNext: `forti doctor`, then `forti get monitor/system/status`.\n";
        }

        int run_configure(Context& context, const Args& args) {
            if (!args.positional.empty())
                throw Failure(Code::usage, "forti configure takes options only (see forti configure --help)");
            const auto& paths = context.engine.options().paths;
            ProfileStore profiles(paths);
            ProfileSet set = profiles.load();
            PendingStore secrets(context.engine.secrets());

            Draft draft;
            draft.secrets = &secrets;
            if (auto name = args.value("profile")) {
                engine::validate_profile_name(*name);
                if (auto it = set.profiles.find(*name); it != set.profiles.end()) {
                    draft.profile = draft.previous = it->second;
                    draft.existed = true;
                } else {
                    draft.profile.name = *name;
                    draft.profile.api_key.source = SecretRef::Source::none;
                }
            }

            std::unique_ptr<Tty> tty;
            if (interactive_requested(args)) {
                tty = std::make_unique<Tty>();
                if (!tty->available())
                    throw Failure(Code::usage, "no terminal to prompt on",
                                  {{"hint", "pass --profile NAME --host HOST and --api-key-stdin, --api-key-env VAR or "
                                            "--api-key-command \"argv\" (see forti configure --help)"}});
                interactive(context, args, set, draft, *tty);
            } else {
                if (!args.value("profile"))
                    throw Failure(Code::usage, "--profile NAME is required with configuration options");
                non_interactive(context, args, set, draft);
            }
            Profile& profile = draft.profile;
            secrets.bind(profile.secret_binding());

            json result = {{"profile", nullptr}};
            bool check = !args.flag("skip-check");
            // A certificate the FortiGate may not know yet: its commands first, then the check.
            if (tty && draft.certificate) {
                json fortigate = certs::fortigate(paths, *draft.certificate);
                tty->say(std::format("On the FortiGate (FortiOS CLI), for certificate \"{}\"; skip what it already has:\n\n{}\n",
                                     *draft.certificate, certs::steps_text(fortigate)));
                if (check) {
                    std::string answer = tty->ask("Press Enter when the FortiGate is ready, to check the connection (s: save without checking)");
                    if (answer == "s" || answer == "S" || answer == "skip") check = false;
                }
            }
            if (draft.certificate) result["certificate"] = *draft.certificate;
            if (check) {
                if (tty) tty->say(std::format("Checking the connection to {}:{}...\n", profile.host, profile.port));
                try {
                    json capabilities = verify(context, profile, secrets);
                    result["device"] = capabilities.value("device", json::object());
                    if (!capabilities.value("schema_matches_device", true))
                        result["schema_note"] = std::format(
                                "the device runs {}; forti's models are generated from FortiOS {}. Reads work; some "
                                "attributes may differ", result["device"].value("version", "another version"),
                                engine::sdk_schema_version);
                } catch (...) {
                    Failure failure = with_advice(engine::translate(std::current_exception()), profile, false);
                    if (draft.created_certificate) {
                        json details = failure.details();
                        details["hint"] = details.value("hint", "") + std::format(
                                " The certificate \"{}\" is kept: choose it again (reuse) when you rerun forti configure.", *draft.certificate);
                        failure = Failure(failure.code(), failure.what(), details);
                    }
                    // A typed secret would be lost; offer to keep the profile when only the network failed.
                    if (!(tty && failure.code() == Code::connection)) throw failure;
                    tty->say(std::format("\nforti: {}\n  hint: {}\n", failure.what(), failure.details().value("hint", "")));
                    if (!tty->confirm("Save the profile anyway (check it later with `forti doctor`)?", false)) throw failure;
                }
            }

            // Verified (or not checked): write secrets first, so a saved profile never points at nothing.
            auto& store = context.engine.secrets();
            secrets.commit(profile);
            if (draft.existed) {
                if (draft.previous.api_key.source == SecretRef::Source::store && profile.api_key.source != SecretRef::Source::store)
                    store.erase(profile.api_key_account());
                if (draft.previous.cert_password.source == SecretRef::Source::store &&
                    profile.cert_password.source != SecretRef::Source::store)
                    store.erase(profile.cert_password_account());
            }
            set.profiles.insert_or_assign(profile.name, profile);
            // The forti home holds more than config.json (state, certs): create it private even when
            // FORTI_CONFIG_DIR puts the configuration elsewhere. A pre-0.2 setup keeps its locations.
            if (!paths.home.empty() && !paths.legacy) engine::ensure_private_dir(paths.home);
            // The first profile (or the first after the default was removed) becomes the default.
            if (draft.make_default || set.default_profile.empty() || !set.profiles.contains(set.default_profile))
                set.default_profile = profile.name;
            profiles.save(set);

            result["profile"] = profile.describe();
            result["default"] = set.default_profile == profile.name;
            result["config_file"] = paths.config_file().string();
            result["api_key_source"] = describe_source(profile.api_key, store.kind());
            result["verified"] = check && result.contains("device");
            if (!profile.client_cert.empty()) {
                auto name = certs::used_by(paths, profile);
                result["client_cert"] = name ? std::format("certificate \"{}\"", *name) : display_path(profile.client_cert);
            }
            if (profile.mode == Mode::autonomous && draft.previous.mode != Mode::autonomous && !tty)
                result["notice"] = autonomous_notice;
            if (paths.legacy)
                result["home_note"] = std::format("this is a pre-0.2 setup ({}); `forti home migrate` moves it into {}",
                                                  display_path(paths.config), display_path(paths.home));
            return emit(context.output, engine::ok(std::move(result), {{"profile", profile.name}}), render_configured);
        }

        // ---- profile ----

        void render_profile(std::ostream& out, const json& data, const json&) {
            std::string name = data.value("name", "");
            out << styled(name, Style::bold) << (data.value("default", false) ? " (default)" : "") << "\n";
            for (auto it = data.begin(); it != data.end(); ++it) {
                if (it.key() == "name" || it.key() == "default") continue;
                const auto& value = it.value();
                out << std::format("  {:<20} {}\n", it.key(), value.is_string() ? value.get<std::string>() : value.dump());
            }
        }

        std::string positional_or_profile(const Args& args, std::size_t index, std::string_view usage) {
            if (args.positional.size() > index) return args.positional[index];
            if (auto profile = args.value("profile")) return *profile;
            throw Failure(Code::usage, std::format("usage: {}", usage));
        }

        Profile& existing(ProfileSet& set, const std::string& name) {
            auto it = set.profiles.find(name);
            if (it == set.profiles.end())
                throw Failure(Code::config, std::format("no profile named \"{}\"", name),
                              {{"hint", "`forti profile list` shows the configured profiles"}});
            return it->second;
        }

        // ---- profile set / rename / copy ----

        constexpr std::string_view settable_keys =
                "host, port, vdom, ca_bundle, client_cert, resolve_ip, connect_timeout_ms, timeout_ms, "
                "backup_before_critical, mode";

        // The CLI validators name options (--host); `profile set` names keys (host).
        template<typename F>
        void as_key(std::string_view key, F&& validate) {
            try {
                validate();
            } catch (const Failure& failure) {
                std::string message = failure.what();
                std::string option = "--" + std::string(key);
                std::ranges::replace(option, '_', '-');
                for (std::size_t at; (at = message.find(option)) != std::string::npos;) message.replace(at, option.size(), key);
                json details = failure.details();
                if (details.is_object() && details.value("hint", "").find("--") != std::string::npos)
                    details["hint"] = std::format("forti profile set NAME {}=VALUE (forti profile --help)", key);
                throw Failure(failure.code(), message, details);
            }
        }

        bool parse_bool(std::string_view key, std::string_view text) {
            if (text == "true" || text == "yes" || text == "on" || text == "1") return true;
            if (text == "false" || text == "no" || text == "off" || text == "0") return false;
            throw Failure(Code::usage, std::format("{} must be true or false, not \"{}\"", key, text));
        }

        // Applies key=value to the profile's config.json form; Profile::from_json then validates the whole
        // profile exactly as loading config.json would. An empty value restores the default (or clears).
        void apply_setting(json& config, const std::string& key, const std::string& value) {
            auto clear_or = [&](auto&& set) {
                if (value.empty()) config.erase(key);
                else set();
            };
            if (key == "host") as_key(key, [&] { validate_host(value); config["host"] = value; });
            else if (key == "port") clear_or([&] { as_key(key, [&] { config["port"] = parse_port(value); }); });
            else if (key == "vdom") clear_or([&] { as_key(key, [&] { validate_vdom(value); config["vdom"] = value; }); });
            else if (key == "ca_bundle") clear_or([&] { as_key(key, [&] { config["ca_bundle"] = readable_file("ca_bundle", value); }); });
            else if (key == "client_cert") {
                clear_or([&] { as_key(key, [&] { config["client_cert"] = readable_file("client_cert", value); }); });
                if (value.empty()) config.erase("cert_password");   // a password belongs to the certificate
            } else if (key == "resolve_ip") clear_or([&] { as_key(key, [&] { validate_ip(value); config["resolve_ip"] = value; }); });
            else if (key == "connect_timeout_ms" || key == "timeout_ms")
                clear_or([&] {
                    std::size_t ms = to_count(key, value);
                    if (ms == 0 || ms > 3'600'000) throw Failure(Code::usage, std::format("{} must be between 1 and 3600000", key));
                    config[key] = ms;
                });
            else if (key == "backup_before_critical") clear_or([&] { config[key] = parse_bool(key, value); });
            else if (key == "mode") as_key(key, [&] { config["mode"] = engine::to_string(parse_mode_option(value)); });
            else throw Failure(Code::usage, std::format("unknown profile setting \"{}\"", key),
                               {{"hint", std::format("settable: {}; secrets go through forti configure", settable_keys)}});
        }

        // Re-binds a profile's stored secrets to its new host:port, when they were bound to the old one.
        // One bound elsewhere stays as it is (doctor reports it): re-binding must not launder it.
        json rebind_secrets(engine::SecretStore& store, const Profile& before, const Profile& after) {
            json rebound = json::array();
            if (before.secret_binding() == after.secret_binding()) return rebound;
            for (auto [ref, account]: {std::pair{&after.api_key, after.api_key_account()},
                                       std::pair{&after.cert_password, after.cert_password_account()}}) {
                if (ref->source != SecretRef::Source::store) continue;
                if (auto stored = store.get(account); stored && stored->binding == before.secret_binding()) {
                    store.put(account, stored->secret, after.secret_binding());
                    rebound.push_back(account);
                }
            }
            return rebound;
        }

        int profile_set(Context& context, const Args& args, ProfileStore& profiles) {
            if (args.positional.size() < 3)
                throw Failure(Code::usage, "usage: forti profile set NAME key=value...", {{"hint", std::format("keys: {}", settable_keys)}});
            ProfileSet set = profiles.load();
            const std::string& name = args.positional[1];
            Profile& profile = existing(set, name);
            Profile before = profile;
            json config = profile.to_json();
            json changed = json::object();
            for (std::size_t k = 2; k < args.positional.size(); ++k) {
                const std::string& pair = args.positional[k];
                auto equals = pair.find('=');
                if (equals == std::string::npos || equals == 0)
                    throw Failure(Code::usage, std::format("expected key=value, not \"{}\"", pair), {{"hint", std::format("keys: {}", settable_keys)}});
                std::string key = pair.substr(0, equals);
                std::ranges::replace(key, '-', '_');
                std::string value = trim(pair.substr(equals + 1));
                json old = config.contains(key) ? config[key] : json(nullptr);
                apply_setting(config, key, value);
                changed[key] = {{"from", old}, {"to", config.contains(key) ? config[key] : json(nullptr)}};
            }
            Profile after = Profile::from_json(name, config);
            json rebound = rebind_secrets(context.engine.secrets(), before, after);
            profile = after;
            profiles.save(set);
            json data = {{"profile", name}, {"changed", changed}, {"secrets_rebound", rebound}};
            if (after.mode == Mode::autonomous && before.mode != Mode::autonomous) data["notice"] = autonomous_notice;
            return emit(context.output, engine::ok(std::move(data), {{"profile", name}}), [](std::ostream& out, const json& data, const json&) {
                out << std::format("Profile {}:\n", data.value("profile", ""));
                auto show = [](const json& value) { return value.is_null() ? std::string("(default)") : value.is_string() ? value.get<std::string>() : value.dump(); };
                for (auto it = data["changed"].begin(); it != data["changed"].end(); ++it)
                    out << std::format("  {:<24} {} → {}\n", it.key(), show(it.value()["from"]), show(it.value()["to"]));
                for (const auto& account: data["secrets_rebound"])
                    out << std::format("  re-bound the stored secret {} to the new address\n", account.get<std::string>());
                if (data.contains("notice")) out << "\n" << data["notice"].get<std::string>();
            });
        }

        // `path` moved from below `from` to below `to`; unchanged when it is not below `from`.
        std::string relocate(const std::string& path, const fs::path& from, const fs::path& to) {
            if (!path_within(path, from)) return path;
            return (to / fs::path(path).lexically_normal().lexically_relative(from.lexically_normal())).lexically_normal().string();
        }

        int profile_rename(Context& context, const Args& args, ProfileStore& profiles) {
            if (args.positional.size() != 3) throw Failure(Code::usage, "usage: forti profile rename OLD NEW");
            const std::string &from = args.positional[1], &to = args.positional[2];
            engine::validate_profile_name(to);
            ProfileSet set = profiles.load();
            Profile old = existing(set, from);
            if (set.profiles.contains(to)) throw Failure(Code::config, std::format("a profile named \"{}\" already exists", to));
            const auto& paths = profiles.paths();
            fs::path certs_from = paths.certs() / from, certs_to = paths.certs() / to;
            std::error_code error;
            bool move_certs = fs::exists(certs_from, error);
            if (move_certs && fs::exists(certs_to, error))
                throw Failure(Code::config, std::format("{} already exists; nothing was changed", display_path(certs_to)));

            Profile renamed = old;
            renamed.name = to;
            // References into certs/<old> follow the directory, in every profile (one may share the certificate).
            json relocated = json::array();
            for (auto& [name, profile]: set.profiles) {
                for (std::string* path: {&profile.ca_bundle, &profile.client_cert, &profile.cert_password.path, &profile.api_key.path}) {
                    std::string moved = relocate(*path, certs_from, certs_to);
                    if (moved != *path) {
                        relocated.push_back({{"profile", name == from ? to : name}, {"from", *path}, {"to", moved}});
                        *path = moved;
                    }
                }
                if (name == from) {
                    renamed.ca_bundle = profile.ca_bundle;
                    renamed.client_cert = profile.client_cert;
                    renamed.cert_password.path = profile.cert_password.path;
                    renamed.api_key.path = profile.api_key.path;
                }
            }

            // Stored secrets: copy to the new accounts first, delete the old ones only once config.json
            // names the new profile, so a failure part-way never loses a key.
            auto& store = context.engine.secrets();
            std::vector<std::pair<std::string, std::string>> secret_moves;   // old account, new account
            for (auto [ref, old_account, new_account]: {std::tuple{&old.api_key, old.api_key_account(), renamed.api_key_account()},
                                                        std::tuple{&old.cert_password, old.cert_password_account(), renamed.cert_password_account()}}) {
                if (ref->source != SecretRef::Source::store) continue;
                auto stored = store.get(old_account);
                if (!stored) continue;
                // Bound to this profile's device: stays bound to it. Otherwise copied as it is (no laundering).
                std::string binding = stored->binding == old.secret_binding() ? renamed.secret_binding() : stored->binding;
                store.put(new_account, stored->secret, binding);
                secret_moves.emplace_back(old_account, new_account);
            }
            auto undo_secrets = [&] {
                for (const auto& [old_account, new_account]: secret_moves) {
                    try {
                        store.erase(new_account);
                    } catch (const Failure&) {
                    }
                }
            };
            if (move_certs && ::rename(certs_from.c_str(), certs_to.c_str()) != 0) {
                undo_secrets();
                throw Failure(Code::config, std::format("cannot move {} to {}", certs_from.string(), certs_to.string()));
            }
            set.profiles.erase(from);
            set.profiles.emplace(to, renamed);
            bool was_default = set.default_profile == from;
            if (was_default) set.default_profile = to;
            try {
                profiles.save(set);
            } catch (...) {
                if (move_certs) ::rename(certs_to.c_str(), certs_from.c_str());
                undo_secrets();
                throw;
            }
            json moved_secrets = json::array();
            for (const auto& [old_account, new_account]: secret_moves) {
                try {
                    store.erase(old_account);
                } catch (const Failure&) {
                    // The profile already uses the new account; a leftover item is only clutter.
                }
                moved_secrets.push_back({{"from", old_account}, {"to", new_account}});
            }
            json data = {{"from", from}, {"to", to}, {"default", was_default}, {"secrets_moved", moved_secrets},
                         {"paths_updated", relocated}};
            if (move_certs) data["certs"] = {{"from", certs_from.string()}, {"to", certs_to.string()}, {"cn", "forti-" + from}};
            return emit(context.output, engine::ok(std::move(data), {{"profile", to}}), [](std::ostream& out, const json& data, const json&) {
                out << std::format("Renamed profile {} to {}{}.\n", data.value("from", ""), data.value("to", ""),
                                   data.value("default", false) ? " (still the default)" : "");
                for (const auto& move: data["secrets_moved"])
                    out << std::format("  stored secret {} → {}\n", move.value("from", ""), move.value("to", ""));
                if (data.contains("certs")) {
                    const json& certs = data["certs"];
                    out << std::format("  certificates {} → {}\n", display_path(certs.value("from", "")), display_path(certs.value("to", "")))
                        << std::format("  (the certificate keeps CN {}; the FortiGate needs no change)\n", certs.value("cn", ""));
                }
                out << "Plans made before the rename name the old profile: plan them again.\n";
            });
        }

        int profile_copy(Context& context, const Args& args, ProfileStore& profiles) {
            if (args.positional.size() != 3) throw Failure(Code::usage, "usage: forti profile copy SOURCE NEW");
            const std::string &from = args.positional[1], &to = args.positional[2];
            engine::validate_profile_name(to);
            ProfileSet set = profiles.load();
            Profile copy = existing(set, from);
            if (set.profiles.contains(to)) throw Failure(Code::config, std::format("a profile named \"{}\" already exists", to));
            // Settings only. The API key reference (and the client certificate with its password) belong
            // to the source device: the copy gets its own through forti configure and forti cert create.
            copy.name = to;
            copy.api_key = {};
            copy.client_cert.clear();
            copy.cert_password = {};
            set.profiles.emplace(to, copy);
            profiles.save(set);
            json data = {{"from", from}, {"profile", copy.describe()},
                         {"not_copied", json::array({"api_key", "client_cert", "cert_password"})},
                         {"next", std::format("forti configure --profile {}", to)}};
            return emit(context.output, engine::ok(std::move(data), {{"profile", to}}), [](std::ostream& out, const json& data, const json&) {
                const json& profile = data["profile"];
                out << std::format("Copied profile {} to {} (host {}, mode {}).\n", data.value("from", ""), profile.value("name", ""),
                                   profile.value("host", ""), profile.value("mode", ""))
                    << "The API key and client certificate were not copied. Point the new profile at its device\n"
                    << "and give it its key:\n  " << data.value("next", "") << "\n";
            });
        }

        int run_profile(Context& context, const Args& args) {
            std::string action = args.positional.empty() ? "list" : args.positional[0];
            ProfileStore profiles(context.engine.options().paths);
            auto& store = context.engine.secrets();

            if (action == "list") {
                if (args.positional.size() > 1) throw Failure(Code::usage, "usage: forti profile list");
                return emit(context.output, engine::Engine::envelope([&] { return context.engine.discover({{"what", "devices"}}); }),
                            render_profiles);
            }
            if (action == "show") {
                if (args.positional.size() > 2) throw Failure(Code::usage, "usage: forti profile show [NAME]");
                ProfileSet set = profiles.load();
                const Profile& profile = args.positional.size() == 2 ? existing(set, args.positional[1])
                                                                     : set.select(args.value("profile").value_or(""));
                json data = profile.describe();
                data["default"] = set.default_profile == profile.name || (set.default_profile.empty() && set.profiles.size() == 1);
                data["api_key"] = describe_source(profile.api_key, store.kind());
                if (profile.api_key.source == SecretRef::Source::store) {
                    try {
                        auto stored = store.get(profile.api_key_account());
                        data["api_key_stored"] = stored.has_value();
                        // Released only to this host:port (see SecretStore); a mismatch needs forti configure.
                        if (stored) data["api_key_bound"] = stored->binding == profile.secret_binding();
                    } catch (const Failure& failure) {
                        data["api_key_stored"] = std::string("unknown: ") + failure.what();
                    }
                } else if (profile.api_key.source == SecretRef::Source::env) {
                    const char* value = std::getenv(profile.api_key.env.c_str());
                    data["api_key_set"] = value && *value;
                }
                return emit(context.output, engine::ok(std::move(data), {{"profile", profile.name}}), render_profile);
            }
            if (action == "default") {
                if (args.positional.size() > 2) throw Failure(Code::usage, "usage: forti profile default NAME");
                ProfileSet set = profiles.load();
                std::string name = positional_or_profile(args, 1, "forti profile default NAME");
                existing(set, name);
                set.default_profile = name;
                profiles.save(set);
                return emit(context.output, engine::ok({{"default_profile", name}}), [](std::ostream& out, const json& data, const json&) {
                    out << std::format("Default profile: {}\n", data["default_profile"].get<std::string>());
                });
            }
            if (action == "mode") {
                if (args.positional.size() < 2 || args.positional.size() > 3)
                    throw Failure(Code::usage, "usage: forti profile mode [NAME] read-only|guarded|autonomous");
                ProfileSet set = profiles.load();
                std::string name = args.positional.size() == 3 ? args.positional[1] : set.select(args.value("profile").value_or("")).name;
                Profile& profile = existing(set, name);
                Mode before = profile.mode;
                profile.mode = parse_mode_option(args.positional.back());
                profiles.save(set);
                json data = {{"profile", name}, {"mode", engine::to_string(profile.mode)}, {"previous", engine::to_string(before)}};
                if (profile.mode == Mode::autonomous && before != Mode::autonomous) data["notice"] = autonomous_notice;
                return emit(context.output, engine::ok(std::move(data), {{"profile", name}}), [](std::ostream& out, const json& data, const json&) {
                    out << std::format("Profile {}: mode {} (was {})\n", data["profile"].get<std::string>(),
                                       data["mode"].get<std::string>(), data["previous"].get<std::string>());
                    if (data.contains("notice")) out << "\n" << data["notice"].get<std::string>();
                });
            }
            if (action == "remove") {
                if (args.positional.size() > 2) throw Failure(Code::usage, "usage: forti profile remove NAME");
                if (args.positional.size() < 2) throw Failure(Code::usage, "usage: forti profile remove NAME (the name is required)");
                ProfileSet set = profiles.load();
                std::string name = args.positional[1];
                Profile profile = existing(set, name);
                // Secrets first: if the store refuses (a locked keychain), the profile stays and can be removed later.
                json erased = json::array();
                for (auto [ref, account]: {std::pair{&profile.api_key, profile.api_key_account()},
                                           std::pair{&profile.cert_password, profile.cert_password_account()}}) {
                    try {
                        if (store.erase(account)) erased.push_back(account);
                    } catch (const Failure&) {
                        if (ref->source == SecretRef::Source::store) throw;
                    }
                }
                set.profiles.erase(name);
                if (set.default_profile == name) set.default_profile = set.profiles.size() == 1 ? set.profiles.begin()->first : "";
                profiles.save(set);
                return emit(context.output, engine::ok({{"removed", name}, {"secrets_removed", erased}, {"default_profile", set.default_profile}}),
                            [](std::ostream& out, const json& data, const json&) {
                                out << std::format("Removed profile {}", data["removed"].get<std::string>());
                                if (!data["secrets_removed"].empty())
                                    out << std::format(" and {} stored secret{}", data["secrets_removed"].size(),
                                                       data["secrets_removed"].size() == 1 ? "" : "s");
                                out << ".\n";
                            });
            }
            if (action == "set") return profile_set(context, args, profiles);
            if (action == "rename") return profile_rename(context, args, profiles);
            if (action == "copy") return profile_copy(context, args, profiles);
            throw Failure(Code::usage, std::format("unknown profile action \"{}\"", action),
                          {{"hint", "forti profile list | show | set | rename | copy | default | mode | remove"}});
        }

        // ---- doctor ----

        struct Check {
            std::string id, status, message, hint, code;   // status: pass | warn | fail | skip | info

            [[nodiscard]] json to_json() const {
                json out = {{"check", id}, {"status", status}, {"message", message}};
                if (!hint.empty()) out["hint"] = hint;
                if (!code.empty()) out["code"] = code;
                return out;
            }
        };

        Check check_home(const engine::Engine& engine) {
            const auto& paths = engine.options().paths;
            if (engine.options().profiles) return {"home", "skip", "profiles are supplied by the embedding application", "", ""};
            if (paths.legacy)
                return {"home", "warn", std::format("pre-0.2 setup in {}", display_path(paths.config)),
                        std::format("move it into {} with `forti home migrate`", display_path(paths.home)), ""};
            if (paths.home.empty()) return {"home", "info", std::format("configuration in {}", display_path(paths.config)), "", ""};
            std::string message = display_path(paths.home);
            if (paths.config != paths.home) message += std::format(" (configuration in {})", display_path(paths.config));
            return {"home", "pass", message, "", ""};
        }

        Check check_config(const engine::Engine& engine) {
            if (engine.options().profiles) return {"config", "skip", "profiles are supplied by the embedding application", "", ""};
            const auto& paths = engine.options().paths;
            std::error_code error;
            const std::string configure = "run `forti configure`";
            if (!fs::exists(paths.config, error))
                return {"config", "fail", std::format("{} does not exist", paths.config.string()), configure, "config"};
            if (!fs::is_directory(paths.config, error))
                return {"config", "fail", std::format("{} is not a directory", paths.config.string()), "", "config"};
            auto file = paths.config_file();
            if (!fs::exists(file, error))
                return {"config", "fail", std::format("no config.json in {}", paths.config.string()), configure, "config"};
            // Group/other access to credential files makes the file store refuse them.
            auto credentials = paths.config / "credentials";
            if (fs::is_directory(credentials, error))
                for (const auto& entry: fs::directory_iterator(credentials, error))
                    if (entry.is_regular_file() && (file_mode(entry.path()) & 077))
                        return {"config", "fail", std::format("{} is accessible by other users", entry.path().string()),
                                std::format("chmod 600 {}", entry.path().string()), "config"};
            std::vector<std::string> loose;
            for (const auto& [path, wanted]: {std::pair{paths.config, 0700u}, std::pair{file, 0600u}, std::pair{credentials, 0700u}})
                if (fs::exists(path, error) && (file_mode(path) & 077))
                    loose.push_back(std::format("chmod {:o} {}", wanted, path.string()));
            if (!loose.empty()) {
                std::string fix;
                for (const auto& line: loose) fix += (fix.empty() ? "" : "; ") + line;
                return {"config", "warn", "configuration files are accessible by other users", fix, ""};
            }
            return {"config", "pass", std::format("{} (0700), config.json (0600)", paths.config.string()), "", ""};
        }

        Check check_files(const Profile& profile) {
            std::vector<std::string> notes;
            for (const auto& [option, path]: {std::pair{"ca_bundle", profile.ca_bundle}, std::pair{"client_cert", profile.client_cert}}) {
                if (path.empty()) continue;
                std::error_code error;
                if (!fs::is_regular_file(path, error))
                    return {"tls_files", "fail", std::format("{} {} does not exist", option, path),
                            std::format("fix the path with `forti configure --profile {}`", profile.name), "config"};
                if (::access(path.c_str(), R_OK) != 0)
                    return {"tls_files", "fail", std::format("{} {} is not readable", option, path), "", "config"};
                if (std::string_view(option) == "ca_bundle") {
                    std::ifstream in(path);
                    std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
                    if (text.find("-----BEGIN CERTIFICATE-----") == std::string::npos)
                        return {"tls_files", "warn", std::format("ca_bundle {} contains no PEM certificate", path),
                                "export the CA certificate in PEM format (-----BEGIN CERTIFICATE-----)", ""};
                }
                notes.push_back(std::format("{} {}", option, path));
            }
            if (notes.empty()) return {"tls_files", "pass", "system trust store; no client certificate", "", ""};
            std::string message;
            for (const auto& note: notes) message += (message.empty() ? "" : ", ") + note;
            return {"tls_files", "pass", message + " readable", "", ""};
        }

        // Autonomous mode with a super_admin-class account deserves a warning. The key's own API user
        // is not identifiable through the API, so this reads the API users the account can see.
        Check check_privileges(engine::Engine& engine, const Profile& profile) {
            json result = engine::Engine::envelope([&] {
                return engine.read({{"resource", "system/api-user"}, {"fields", {"name", "accprofile"}}, {"profile", profile.name}});
            });
            if (!result.value("ok", false)) {
                std::string code = result["error"].value("code", "");
                if (code == "auth" || code == "not_found")
                    return {"privileges", "pass", "the account cannot read system/api-user, so it is not super_admin-class", "", ""};
                return {"privileges", "info", "could not read system/api-user to assess the account's privileges", "", ""};
            }
            std::size_t total = 0, super = 0;
            for (const auto& user: result.value("data", json::array())) {
                ++total;
                if (user.value("accprofile", "") == "super_admin") ++super;
            }
            std::string scope = "in autonomous mode an agent can change anything, including admins and management access; "
                                "consider an admin profile limited to what the agent manages";
            if (total > 0 && super == total)
                return {"privileges", "warn", "this API user has the super_admin profile (every API user on the device does)", scope, ""};
            if (super > 0)
                return {"privileges", "warn", std::format("{} of {} API users have the super_admin profile; this key may be one of them",
                                                          super, total), scope, ""};
            return {"privileges", "pass", "no API user has the super_admin profile", "", ""};
        }

        std::string_view mode_meaning(Mode mode) {
            switch (mode) {
                case Mode::read_only: return "read-only: reads only, every change is refused";
                case Mode::guarded: return "guarded: changes apply after a human approves the plan (`forti plan approve`)";
                case Mode::autonomous: return "autonomous: changes apply without interactive approval; safeguards still apply";
            }
            return "";
        }

        void render_checks(std::ostream& out, const json& data, const json&) {
            out << styled(std::format("forti doctor{}", data.contains("profile") && data["profile"].is_string()
                                                        ? ": profile " + data["profile"].get<std::string>() : ""), Style::bold)
                << "\n\n";
            for (const auto& check: data["checks"]) {
                std::string status = check.value("status", "");
                Style style = status == "pass" ? Style::green : status == "warn" ? Style::yellow
                              : status == "fail" ? Style::red : Style::dim;
                std::string label = status == "pass" ? "ok" : status;
                out << "  " << styled(std::format("{:<4}", label), style) << "  " << std::format("{:<11}", check.value("check", ""))
                    << " " << check.value("message", "") << "\n";
                if (check.contains("hint")) out << std::string(20, ' ') << styled("hint: ", Style::cyan) << check["hint"].get<std::string>() << "\n";
            }
            const json& summary = data["summary"];
            out << "\n" << std::format("{} ok, {} warning{}, {} failed", summary.value("pass", 0), summary.value("warn", 0),
                                       summary.value("warn", 0) == 1 ? "" : "s", summary.value("fail", 0))
                << "\n";
        }

        int run_doctor(Context& context, const Args& args) {
            if (!args.positional.empty()) throw Failure(Code::usage, "usage: forti doctor [--profile NAME]");
            auto& engine = context.engine;
            std::vector<Check> checks;
            auto failed = [&] { return std::ranges::any_of(checks, [](const Check& c) { return c.status == "fail"; }); };
            auto skip = [&](std::initializer_list<const char*> ids, const std::string& why) {
                for (const char* id: ids) checks.push_back({id, "skip", why, "", ""});
            };

            checks.push_back(check_home(engine));
            checks.push_back(check_config(engine));

            const Profile* profile = nullptr;
            if (checks.back().status != "fail") {
                try {
                    profile = &engine.profile(args.value("profile").value_or(""));
                    std::string where = std::format("{} → {}:{}", profile->name, profile->host, profile->port);
                    if (!profile->vdom.empty()) where += std::format(" (vdom {})", profile->vdom);
                    if (!profile->resolve_ip.empty()) where += std::format(" via {}", profile->resolve_ip);
                    checks.push_back({"profile", "pass", where, "", ""});
                } catch (...) {
                    auto failure = engine::translate(std::current_exception());
                    checks.push_back({"profile", "fail", failure.what(), failure.details().value("hint", ""),
                                      std::string(engine::to_string(failure.code()))});
                }
            } else skip({"profile"}, "needs a configuration");

            if (profile) {
                try {
                    (void) engine.client(*profile);   // resolves every secret; no network
                    std::string message = "API key from the " + describe_source(profile->api_key, engine.secrets().kind());
                    if (profile->cert_password.source != SecretRef::Source::none)
                        message += ", certificate password from the " + describe_source(profile->cert_password, engine.secrets().kind());
                    checks.push_back({"secrets", "pass", message, "", ""});
                } catch (...) {
                    auto failure = engine::translate(std::current_exception());
                    std::string hint = failure.details().value("hint", "");
                    if (hint.empty()) {
                        switch (profile->api_key.source) {
                            case SecretRef::Source::env: hint = std::format("export {} before running forti", profile->api_key.env); break;
                            case SecretRef::Source::command: hint = "run the command yourself and check it prints the key"; break;
                            default: hint = std::format("store the key with `forti configure --profile {}`", profile->name);
                        }
                    }
                    checks.push_back({"secrets", "fail", failure.what(), hint, std::string(engine::to_string(failure.code()))});
                }
                checks.push_back(check_files(*profile));
            } else skip({"secrets", "tls_files"}, "needs a profile");

            json capabilities;
            if (profile && !failed()) {
                try {
                    capabilities = engine.discover({{"what", "capabilities"}, {"profile", profile->name}}).value("data", json::object());
                    checks.push_back({"connection", "pass",
                                      std::format("{}:{} reachable, TLS certificate verified", profile->host, profile->port), "", ""});
                    const json& device = capabilities["device"];
                    std::string who = device.value("hostname", "");
                    for (const char* key: {"model_name", "serial"})
                        if (device.contains(key) && device[key].is_string()) who += (who.empty() ? "" : ", ") + device[key].get<std::string>();
                    checks.push_back({"auth", "pass", who.empty() ? "API key accepted" : "API key accepted by " + who, "", ""});
                } catch (...) {
                    auto failure = with_advice(engine::translate(std::current_exception()), *profile, true);
                    std::string code(engine::to_string(failure.code()));
                    std::string hint = failure.details().value("hint", "");
                    if (failure.code() == Code::connection) {
                        checks.push_back({"connection", "fail",
                                          std::format("{} ({})", failure.what(), failure.details().value("stage", "network")), hint, code});
                        skip({"auth"}, "needs a connection");
                    } else {
                        checks.push_back({"connection", "pass", std::format("{}:{} reachable, TLS certificate verified",
                                                                            profile->host, profile->port), "", ""});
                        checks.push_back({"auth", "fail", failure.what(), hint, code});
                    }
                }
            } else skip({"connection", "auth"}, "fix the failures above first");

            if (capabilities.is_object() && capabilities.contains("device")) {
                std::string version = capabilities["device"].value("version", "");
                if (capabilities.value("schema_matches_device", false))
                    checks.push_back({"version", "pass", std::format("FortiOS {} matches the SDK schema", version), "", ""});
                else
                    checks.push_back({"version", "warn",
                                      std::format("device runs {}; forti's models are generated from FortiOS {}",
                                                  version.empty() ? "an unknown version" : version, engine::sdk_schema_version),
                                      "reads work as the device answers; attributes added or removed between versions may "
                                      "be missing or rejected in plans", ""});
            } else skip({"version"}, "needs a connection");

            if (profile) {
                checks.push_back({"mode", "pass", std::string(mode_meaning(profile->mode)), "", ""});
                if (profile->mode == Mode::autonomous && capabilities.is_object() && capabilities.contains("device"))
                    checks.push_back(check_privileges(engine, *profile));
            } else skip({"mode"}, "needs a profile");

            if (auto mcp = find_on_path("forti-mcp")) checks.push_back({"mcp", "info", "forti-mcp found at " + mcp->string(), "", ""});
            else checks.push_back({"mcp", "info", "forti-mcp is not on PATH (needed only for AI clients)", "", ""});

            json list = json::array();
            json summary = {{"pass", 0}, {"warn", 0}, {"fail", 0}, {"skip", 0}, {"info", 0}};
            std::string first_code;
            for (const auto& check: checks) {
                list.push_back(check.to_json());
                summary[check.status] = summary[check.status].get<int>() + 1;
                if (check.status == "fail" && first_code.empty()) first_code = check.code.empty() ? "internal" : check.code;
            }
            json data = {{"checks", list}, {"summary", summary}};
            if (profile) data["profile"] = profile->name;

            if (first_code.empty()) return emit(context.output, engine::ok(data, profile ? json{{"profile", profile->name}} : json::object()), render_checks);
            json failure = {{"ok", false},
                            {"error", {{"code", first_code},
                                       {"message", std::format("{} check{} failed", summary["fail"].get<int>(),
                                                               summary["fail"].get<int>() == 1 ? "" : "s")},
                                       {"details", data}}}};
            if (context.output.format == Format::json) return emit(context.output, failure);
            emit(context.output, engine::ok(data), render_checks);
            *context.output.err << std::format("forti: doctor: {}\n", printable(failure["error"]["message"].get<std::string>()));
            return exit_status(first_code);
        }

    }  // namespace

    std::vector<Command> setup_commands() {
        std::vector<Command> commands = {
            {"configure", "Create or update a device profile and verify it",
             "usage: forti configure                              prompt on the terminal\n"
             "       forti configure --profile NAME --host HOST [options] <credential>\n"
             "\n"
             "Creates or updates a profile in config.json and checks it against the device (one read of\n"
             "monitor/system/status). Nothing is saved unless the check passes; an authentication failure is\n"
             "never retried, because FortiOS locks out an API user after repeated failures.\n"
             "\n"
             "On an existing profile, the prompts start from its current values (Enter keeps each one),\n"
             "and with options only the options given change: forti configure --profile fw01 --port 8443.\n"
             "`forti profile set` changes settings without contacting the device.\n"
             "\n"
             "The prompts also offer a client certificate (PKI authentication of the API user): reuse one\n"
             "of forti's certificates (`forti cert list`), or make one, issued by the forti CA, and get the\n"
             "FortiGate commands to paste before the check.\n"
             "\n"
             "connection:\n"
             "  --host HOST              FortiGate host name or address (no scheme, no port)\n"
             "  --port N                 admin HTTPS port (default 443)\n"
             "  --vdom NAME              default VDOM for this profile\n"
             "  --ca-bundle PATH         PEM CA bundle that verifies the device certificate\n"
             "  --resolve-ip IP          connect to IP while verifying the certificate for HOST\n"
             "  --cert NAME              one of forti's client certificates (forti cert list)\n"
             "  --client-cert PATH       a PKCS#12 client certificate of your own\n"
             "\n"
             "credential (the API key is never accepted as an argument):\n"
             "  --api-key-stdin          read the key from standard input and keep it in the secret store\n"
             "  --api-key-env VAR        read the key from $VAR each time (the name is stored, not the value)\n"
             "  --api-key-command CMD    run CMD (split like a shell, run without one); its first line is the key\n"
             "  --cert-password-stdin | --cert-password-env VAR | --cert-password-command CMD\n"
             "                           the client certificate's password, from the same kinds of source\n"
             "  --cert-password-file PATH  or from a file only you can read (0600). Not needed with --cert\n"
             "\n"
             "policy:\n"
             "  --mode MODE              read-only (default), guarded or autonomous\n"
             "  --default                make this the default profile\n"
             "  --skip-check             save without contacting the device\n"
             "\n"
             "examples:\n"
             "  forti configure\n"
             "  op read op://ops/fw01/api-key | forti configure --profile fw01 --host fw01.example.net \\\n"
             "      --ca-bundle ~/fw01-ca.pem --api-key-stdin --default\n"
             "  forti configure --profile lab --host 192.0.2.10 --api-key-env FORTI_LAB_KEY --mode guarded\n",
             {{"host", "port", "ca-bundle", "client-cert", "cert", "resolve-ip", "api-key-env", "api-key-command",
               "cert-password-env", "cert-password-command", "cert-password-file", "mode"},
              {"api-key-stdin", "cert-password-stdin", "default", "skip-check"},
              {}},
             run_configure},
            {"profile", "List, show, change, rename, copy or remove device profiles",
             "usage: forti profile [list]                     list profiles (same as `forti devices`)\n"
             "       forti profile show [NAME]                one profile and where its secrets come from\n"
             "       forti profile set NAME key=value...      change settings (no device check)\n"
             "       forti profile rename OLD NEW             rename, with its secrets and certificates\n"
             "       forti profile copy SOURCE NEW            a new profile with the same settings, no secrets\n"
             "       forti profile default NAME               make NAME the default profile\n"
             "       forti profile mode [NAME] MODE           read-only, guarded or autonomous\n"
             "       forti profile remove NAME                delete the profile and its stored secrets\n"
             "\n"
             "set keys: host, port, vdom, ca_bundle, client_cert, resolve_ip, connect_timeout_ms,\n"
             "  timeout_ms, backup_before_critical (true|false), mode. An empty value (vdom=) restores\n"
             "  the default. Values are checked as config.json is; a changed host or port re-binds the\n"
             "  profile's stored secrets to the new address. Secrets go through `forti configure`.\n"
             "rename moves the stored secrets (Keychain or file store), <home>/certs/OLD, paths that\n"
             "  point into it, and the default. copy leaves out the API key and the client certificate:\n"
             "  run `forti configure --profile NEW` next.\n"
             "\n"
             "examples:\n"
             "  forti profile copy fw01 fw02 && forti profile set fw02 host=fw02.example.net\n"
             "  forti configure --profile fw02 --api-key-stdin < fw02.key\n"
             "  forti profile set lab port=8443 vdom=root timeout_ms=60000\n"
             "\n"
             "modes:\n"
             "  read-only    reads only; plans can be previewed, every apply is refused (default)\n"
             "  guarded      apply needs a human approval of the plan: `forti plan approve <id>`\n"
             "  autonomous   apply runs without interactive approval; validation, drift checks,\n"
             "               verification, audit and rollback plans still apply. The FortiOS account's\n"
             "               admin profile is the real limit on what an agent can change.\n",
             {}, run_profile},
            {"doctor", "Check configuration, credentials, connectivity and the device",
             "usage: forti doctor [--profile NAME]\n"
             "\n"
             "Runs ordered checks and reports each as ok, warn, fail, skip or info:\n"
             "  home        the forti home (warns on a pre-0.2 setup: forti home migrate)\n"
             "  config      configuration directory and file permissions\n"
             "  profile     the selected profile is valid\n"
             "  secrets     the API key (and certificate password) resolve; values are never shown\n"
             "  tls_files   the CA bundle and client certificate exist and are readable\n"
             "  connection  DNS, TCP and TLS to the device (one read of monitor/system/status)\n"
             "  auth        the device accepts the API key (never retried)\n"
             "  version     the device's FortiOS version against the SDK schema version\n"
             "  mode        the profile's operating mode (autonomous: also the account's privileges)\n"
             "  mcp         whether forti-mcp is on PATH\n"
             "\n"
             "Exits 0 when nothing failed, otherwise with the exit status of the first failure.\n",
             {}, run_doctor},
        };
        for (auto&& more: {home_commands(), cert_commands()}) commands.insert(commands.end(), more.begin(), more.end());
        return commands;
    }

}  // namespace forti::cli
