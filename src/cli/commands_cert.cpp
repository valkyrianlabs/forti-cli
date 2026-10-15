//
// `forti cert create|show|remove`: a private CA and a client certificate per profile, for FortiOS PKI
// (peer) authentication of the REST API user, in <home>/certs/<profile>/:
//
//   ca.crt        the CA certificate: imported on the FortiGate as a CA certificate
//   ca/ca.key     the CA key (0600, directory 0700): never leaves this machine
//   client.crt    the client certificate, CN forti-<profile>
//   client.p12    the client certificate, its key and the CA (the profile's client_cert)
//   client.pass   the .p12 password (0600, random hex; the profile's cert_password, source "file")
//
// The work is done by the openssl command (an argv vector, never a shell), with the choices of
// forti-api's tools/gen-certs.sh: RSA 3072, SHA-256, and a PKCS#12 with PBE-SHA1-3DES and a SHA-1 MAC,
// which OpenSSL 3 without the legacy provider, LibreSSL (macOS /usr/bin/openssl, and libcurl there)
// and FortiOS all read. No password ever reaches argv: openssl reads it from client.pass.
//
// Everything is generated in a private staging directory and renamed into place at the end, so a
// failure leaves the previous certificate (or nothing) behind, never half a set.
//

#include "commands.hpp"
#include "setup_support.hpp"
#include "tty.hpp"

#include <process.hpp>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <filesystem>
#include <format>
#include <fstream>
#include <ostream>

#include <sys/stat.h>
#include <unistd.h>

namespace forti::cli {

    using engine::Code;
    using engine::Failure;
    using engine::Profile;
    using engine::ProfileSet;
    using engine::ProfileStore;
    using engine::SecretRef;
    using json = nlohmann::json;
    namespace fs = std::filesystem;

    namespace {

        constexpr unsigned default_days = 1095;
        constexpr unsigned ca_days = 3650;

        struct CertFiles {
            fs::path dir, ca_cert, ca_dir, ca_key, client_cert, client_p12, client_pass;

            explicit CertFiles(fs::path base)
                : dir(std::move(base)), ca_cert(dir / "ca.crt"), ca_dir(dir / "ca"), ca_key(ca_dir / "ca.key"),
                  client_cert(dir / "client.crt"), client_p12(dir / "client.p12"), client_pass(dir / "client.pass") {}
        };

        // FortiGate object names for the steps we print. user/peer and user/peergrp names hold at most
        // 35 characters, vpn.certificate/ca names 79 (FortiOS 7.4.8 schema).
        struct DeviceNames {
            std::string cn, ca, peer, group;
        };

        DeviceNames device_names(const std::string& profile) {
            std::string base = "forti-" + profile;
            return {base, base + "-ca", base.substr(0, 35), base.substr(0, 29) + "-peers"};
        }

        bool present(const fs::path& path) {
            std::error_code error;
            return fs::exists(fs::symlink_status(path, error));
        }

        fs::path openssl_program() {
            if (auto program = find_on_path("openssl")) return *program;
            throw Failure(Code::config, "the openssl command is not installed; forti cert uses it to make certificates",
                          {{"hint", "install openssl (Debian and Ubuntu: apt install openssl; macOS ships /usr/bin/openssl)"}});
        }

        // Runs openssl in `cwd` with relative file names. Its output never contains a secret: passwords
        // are passed as file: references.
        std::string openssl(const fs::path& program, std::vector<std::string> args, const fs::path& cwd) {
            std::string step = args.empty() ? "" : args.front();
            args.insert(args.begin(), program.string());
            auto result = install::run_process(args, {.cwd = cwd, .timeout = std::chrono::seconds(120)});
            if (!result.ok()) {
                std::string detail = result.err;
                if (detail.size() > 2000) detail = detail.substr(detail.size() - 2000);
                throw Failure(Code::config, std::format("openssl {} failed{}", step, result.timed_out ? " (timed out)" : ""),
                              {{"program", program.string()}, {"status", result.status}, {"stderr", detail}});
            }
            return result.out;
        }

        std::string random_hex(std::size_t bytes) {
            std::ifstream random("/dev/urandom", std::ios::binary);
            std::string raw(bytes, '\0');
            if (!random.read(raw.data(), static_cast<std::streamsize>(bytes)))
                throw Failure(Code::internal, "cannot read /dev/urandom");
            std::string hex;
            for (unsigned char c: raw) hex += std::format("{:02x}", c);
            return hex;
        }

        void restrict(const fs::path& path, unsigned mode) {
            if (::chmod(path.c_str(), static_cast<mode_t>(mode)) != 0)
                throw Failure(Code::config, std::format("cannot set the mode of {}", path.string()));
        }

        // subject, expiry and SHA-256 fingerprint of a PEM certificate. OpenSSL 3 prints
        // "subject=O=forti, CN=x" and "sha256 Fingerprint=…", LibreSSL "subject= /O=forti/CN=x" and
        // "SHA256 Fingerprint=…"; both print "notAfter=Oct 14 19:48:33 2029 GMT".
        json certificate_info(const fs::path& program, const fs::path& file) {
            std::string text = openssl(program, {"x509", "-in", file.filename().string(), "-noout", "-subject", "-enddate",
                                                 "-fingerprint", "-sha256"}, file.parent_path());
            json info = json::object();
            std::size_t start = 0;
            while (start < text.size()) {
                std::size_t end = text.find('\n', start);
                std::string line = text.substr(start, end == std::string::npos ? std::string::npos : end - start);
                start = end == std::string::npos ? text.size() : end + 1;
                auto equals = line.find('=');
                if (equals == std::string::npos) continue;
                std::string key = line.substr(0, equals), value = trim(line.substr(equals + 1));
                if (key == "subject") info["subject"] = value;
                else if (key == "notAfter") {
                    info["not_after"] = value;
                    std::tm tm{};
                    if (::strptime(value.c_str(), "%b %d %H:%M:%S %Y", &tm)) {
                        std::time_t when = ::timegm(&tm);
                        char iso[32];
                        std::strftime(iso, sizeof iso, "%Y-%m-%dT%H:%M:%SZ", &tm);
                        info["expires"] = iso;
                        std::time_t now = std::time(nullptr);
                        info["expired"] = when <= now;
                        info["days_left"] = when > now ? static_cast<long long>((when - now) / 86400) : 0LL;
                    }
                } else if (key.ends_with("Fingerprint")) info["fingerprint_sha256"] = value;
            }
            return info;
        }

        // The profile named by --profile, or the default one.
        std::string selected_profile(const Args& args, const ProfileSet& set, bool must_exist) {
            if (auto name = args.value("profile")) {
                engine::validate_profile_name(*name);
                if (must_exist && !set.profiles.contains(*name))
                    throw Failure(Code::config, std::format("no profile named \"{}\"", *name),
                                  {{"hint", std::format("create it first: forti configure --profile {}", *name)}});
                return *name;
            }
            return set.select("").name;
        }

        // How to read the password, as a command to copy (the password itself is never printed).
        std::string password_command(const Profile& profile, const engine::Paths& paths, std::string_view store_kind) {
            switch (profile.cert_password.source) {
                case SecretRef::Source::file: return "cat " + shell_path(profile.cert_password.path);
                case SecretRef::Source::store:
                    if (store_kind == "keychain")
                        return shell_join({"security", "find-generic-password", "-s", "forti", "-a", profile.cert_password_account(), "-w"});
                    if (store_kind == "file") {
                        std::string account = profile.cert_password_account();
                        std::ranges::replace(account, '/', '.');
                        return "sed -n 2p " + shell_path(paths.config / "credentials" / account);
                    }
                    return "";
                default: return "";
            }
        }

        // One line per element: text output passes strings through printable(), which escapes newlines.
        json fortigate_steps(const DeviceNames& names, const CertFiles& files) {
            std::string text = std::format(
                    "  1. Import ca.crt as a CA certificate (paste the PEM between the quotes):\n"
                    "       config vpn certificate ca\n"
                    "           edit \"{0}\"\n"
                    "               set ca \"<paste the output of: cat {4}>\"\n"
                    "           next\n"
                    "       end\n"
                    "     (Imported in the GUI instead, it gets a name such as CA_Cert_1: use that name in step 2.)\n"
                    "\n"
                    "  2. Create a PKI user for this certificate and a peer group with it:\n"
                    "       config user peer\n"
                    "           edit \"{1}\"\n"
                    "               set ca \"{0}\"\n"
                    "               set cn \"{3}\"\n"
                    "           next\n"
                    "       end\n"
                    "       config user peergrp\n"
                    "           edit \"{2}\"\n"
                    "               set member \"{1}\"\n"
                    "           next\n"
                    "       end\n"
                    "\n"
                    "  3. Require the certificate for the REST API user (put your API user's name):\n"
                    "       config system api-user\n"
                    "           edit \"<api-user>\"\n"
                    "               set peer-auth enable\n"
                    "               set peer-group \"{2}\"\n"
                    "           next\n"
                    "       end\n",
                    names.ca, names.peer, names.group, names.cn, shell_path(files.ca_cert));
            json lines = json::array();
            for (std::size_t start = 0; start < text.size();) {
                std::size_t end = text.find('\n', start);
                lines.push_back(text.substr(start, end - start));
                start = end + 1;
            }
            return lines;
        }

        // ---- create ----

        int run_create(Context& context, const Args& args) {
            const auto& paths = context.engine.options().paths;
            ProfileStore profiles(paths);
            ProfileSet set = profiles.load();
            std::string name = selected_profile(args, set, true);
            Profile& profile = set.profiles.at(name);

            unsigned days = default_days;
            if (auto text = args.value("days")) {
                std::size_t value = to_count("days", *text);
                if (value == 0 || value > 36500) throw Failure(Code::usage, "--days must be between 1 and 36500");
                days = static_cast<unsigned>(value);
            }
            CertFiles files(paths.certs() / name);
            bool replacing = present(files.ca_key);
            if (replacing && !args.flag("force"))
                throw Failure(Code::config, std::format("profile {} already has a CA ({}); nothing was changed", name,
                                                        display_path(files.ca_key)),
                              {{"hint", "a FortiGate may trust it: pass --force to replace it, then import the new ca.crt there"}});
            fs::path program = openssl_program();
            auto names = device_names(name);

            engine::ensure_private_dir(paths.certs());
            std::string pattern = (paths.certs() / std::format(".{}.new.XXXXXX", name)).string();
            if (!::mkdtemp(pattern.data())) throw Failure(Code::config, std::format("cannot create a directory in {}", paths.certs().string()));
            fs::path staging = pattern;
            CertFiles work(staging);
            std::string password = random_hex(24);
            json info;
            try {
                restrict(staging, 0700);
                engine::ensure_private_dir(work.ca_dir);
                engine::write_private_file(work.client_pass, password + "\n");
                engine::write_private_file(staging / "client.ext",
                                           "basicConstraints=critical,CA:FALSE\n"
                                           "keyUsage=critical,digitalSignature,keyEncipherment\n"
                                           "subjectKeyIdentifier=hash\n"
                                           "authorityKeyIdentifier=keyid\n"
                                           "extendedKeyUsage=clientAuth\n");
                std::string ca_validity = std::to_string(std::max(days, ca_days));
                openssl(program, {"req", "-x509", "-new", "-newkey", "rsa:3072", "-sha256", "-days", ca_validity, "-nodes",
                                  "-subj", std::format("/O=forti/CN={} CA", names.cn),
                                  "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
                                  "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                                  "-addext", "subjectKeyIdentifier=hash",
                                  "-keyout", "ca/ca.key", "-out", "ca.crt"}, staging);
                openssl(program, {"req", "-new", "-newkey", "rsa:3072", "-sha256", "-nodes", "-subj",
                                  std::format("/O=forti/CN={}", names.cn), "-keyout", "client.key", "-out", "client.csr"}, staging);
                openssl(program, {"x509", "-req", "-sha256", "-days", std::to_string(days), "-in", "client.csr", "-CA", "ca.crt",
                                  "-CAkey", "ca/ca.key", "-set_serial", "0x" + random_hex(16), "-extfile", "client.ext",
                                  "-out", "client.crt"}, staging);
                openssl(program, {"pkcs12", "-export", "-certpbe", "PBE-SHA1-3DES", "-keypbe", "PBE-SHA1-3DES", "-macalg", "sha1",
                                  "-name", names.cn, "-inkey", "client.key", "-in", "client.crt", "-certfile", "ca.crt",
                                  "-passout", "file:client.pass", "-out", "client.p12"}, staging);
                openssl(program, {"verify", "-CAfile", "ca.crt", "client.crt"}, staging);
                for (const char* scratch: {"client.key", "client.csr", "client.ext"}) fs::remove(staging / scratch);
                // openssl leaves modes to the umask (LibreSSL writes keys 0644); the directory was private throughout.
                restrict(work.ca_dir, 0700);
                restrict(work.ca_key, 0600);
                restrict(work.client_p12, 0600);
                restrict(work.client_pass, 0600);
                restrict(work.ca_cert, 0644);
                restrict(work.client_cert, 0644);
                info = certificate_info(program, work.client_cert);

                // --keychain: the password goes to the secret store, before anything is replaced.
                if (args.flag("keychain")) {
                    context.engine.secrets().put(profile.cert_password_account(), password, profile.secret_binding());
                    fs::remove(work.client_pass);
                }
            } catch (...) {
                std::error_code error;
                fs::remove_all(staging, error);
                throw;
            }

            // Into place: the old set (with --force) is moved aside first, and deleted only afterwards.
            fs::path old;
            if (present(files.dir)) {
                old = paths.certs() / std::format(".{}.old.{}", name, ::getpid());
                std::error_code error;
                fs::remove_all(old, error);
                if (::rename(files.dir.c_str(), old.c_str()) != 0) {
                    fs::remove_all(staging, error);
                    throw Failure(Code::config, std::format("cannot move {} aside", files.dir.string()));
                }
            }
            if (::rename(staging.c_str(), files.dir.c_str()) != 0) {
                std::error_code error;
                if (!old.empty()) ::rename(old.c_str(), files.dir.c_str());
                fs::remove_all(staging, error);
                throw Failure(Code::config, std::format("cannot create {}", files.dir.string()));
            }
            if (!old.empty()) {
                std::error_code error;
                fs::remove_all(old, error);
            }

            auto& store = context.engine.secrets();
            SecretRef before = profile.cert_password;
            profile.client_cert = files.client_p12.string();
            if (args.flag("keychain")) profile.cert_password = {SecretRef::Source::store, {}, {}, {}};
            else {
                profile.cert_password = {SecretRef::Source::file, {}, {}, files.client_pass.string()};
                if (before.source == SecretRef::Source::store) {
                    try {
                        store.erase(profile.cert_password_account());
                    } catch (const Failure&) {
                        // A stale store entry is harmless: the profile no longer refers to it.
                    }
                }
            }
            profiles.save(set);

            json file_list = {{"ca_cert", files.ca_cert.string()}, {"ca_key", files.ca_key.string()},
                              {"client_cert", files.client_cert.string()}, {"client_p12", files.client_p12.string()}};
            if (!args.flag("keychain")) file_list["client_pass"] = files.client_pass.string();
            json data = {{"profile", name}, {"dir", files.dir.string()}, {"files", file_list}, {"days", days},
                         {"replaced", replacing}, {"cn", names.cn}, {"certificate", info},
                         {"password_source", describe_source(profile.cert_password, store.kind())},
                         {"password_command", password_command(profile, paths, store.kind())},
                         {"fortigate", {{"ca_name", names.ca}, {"peer", names.peer}, {"peer_group", names.group},
                                        {"steps", fortigate_steps(names, files)}}}};
            return emit(context.output, engine::ok(std::move(data), {{"profile", name}}), [](std::ostream& out, const json& data, const json&) {
                const json& cert = data["certificate"];
                out << styled(std::format("{} a client certificate for profile \"{}\"", data.value("replaced", false) ? "Replaced" : "Created",
                                          data.value("profile", "")), Style::bold)
                    << std::format(" (CN {}, valid {} days{})\n\n", data.value("cn", ""), data.value("days", 0),
                                   cert.contains("expires") ? ", until " + cert["expires"].get<std::string>().substr(0, 10) : "");
                const json& files = data["files"];
                auto line = [&](std::string_view label, const std::string& key, std::string_view note) {
                    if (!files.contains(key)) return;
                    std::string path = display_path(files[key].get<std::string>());
                    if (note.empty()) out << std::format("  {:<15} {}\n", label, path);
                    else out << std::format("  {:<15} {:<44} ", label, path) << styled(note, Style::dim) << "\n";
                };
                line("CA certificate", "ca_cert", "import this on the FortiGate");
                line("CA key", "ca_key", "private: never copy it to the FortiGate");
                line("client cert", "client_cert", "");
                line("client bundle", "client_p12", "the profile's client_cert");
                line("password", "client_pass", "the profile's certificate password");
                if (cert.contains("fingerprint_sha256"))
                    out << std::format("  {:<15} {}\n", "SHA-256", cert["fingerprint_sha256"].get<std::string>());
                out << "\nThe password is never printed. ";
                std::string command = data.value("password_command", "");
                if (!command.empty()) out << "To read it:\n  " << command << "\n";
                else out << "It is in the " << data.value("password_source", "") << ".\n";
                out << "\n" << styled("On the FortiGate (FortiOS CLI):", Style::bold) << "\n\n";
                for (const auto& step: data["fortigate"]["steps"]) out << step.get<std::string>() << "\n";
                out << std::format("\nThen check the connection: forti doctor --profile {}\n", data.value("profile", ""));
            });
        }

        // ---- show ----

        int run_show(Context& context, const Args& args) {
            const auto& paths = context.engine.options().paths;
            ProfileSet set = ProfileStore(paths).load();
            std::string name = selected_profile(args, set, false);
            CertFiles files(paths.certs() / name);
            if (!present(files.dir))
                throw Failure(Code::config, std::format("profile {} has no certificate in {}", name, display_path(files.dir)),
                              {{"hint", std::format("forti cert create --profile {}", name)}});
            fs::path program = openssl_program();
            json file_list = json::object();
            for (auto [key, path]: {std::pair{"ca_cert", files.ca_cert}, std::pair{"ca_key", files.ca_key},
                                    std::pair{"client_cert", files.client_cert}, std::pair{"client_p12", files.client_p12},
                                    std::pair{"client_pass", files.client_pass}})
                if (present(path)) file_list[key] = {{"path", path.string()}, {"mode", std::format("{:04o}", file_mode(path))}};
            json data = {{"profile", name}, {"dir", files.dir.string()}, {"files", file_list}};
            if (present(files.client_cert)) data["client"] = certificate_info(program, files.client_cert);
            if (present(files.ca_cert)) data["ca"] = certificate_info(program, files.ca_cert);
            if (auto it = set.profiles.find(name); it != set.profiles.end()) {
                const Profile& profile = it->second;
                data["profile_client_cert"] = profile.client_cert;
                data["in_use"] = !profile.client_cert.empty() && path_within(profile.client_cert, files.dir);
                data["password_source"] = describe_source(profile.cert_password, context.engine.secrets().kind());
                std::string command = password_command(profile, paths, context.engine.secrets().kind());
                if (!command.empty()) data["password_command"] = command;
            }
            return emit(context.output, engine::ok(std::move(data), {{"profile", name}}), [](std::ostream& out, const json& data, const json&) {
                out << styled(std::format("Certificate of profile \"{}\"", data.value("profile", "")), Style::bold) << "  "
                    << display_path(data.value("dir", "")) << "\n";
                for (const char* which: {"client", "ca"}) {
                    if (!data.contains(which)) continue;
                    const json& cert = data[which];
                    out << std::format("\n  {}\n", std::string_view(which) == "client" ? "client certificate" : "CA certificate");
                    out << std::format("    {:<12} {}\n", "subject", cert.value("subject", ""));
                    std::string expiry = cert.value("expires", cert.value("not_after", ""));
                    if (cert.value("expired", false)) out << std::format("    {:<12} {} ", "expires", expiry) << styled("EXPIRED", Style::red) << "\n";
                    else out << std::format("    {:<12} {} ({} days left)\n", "expires", expiry, cert.value("days_left", 0LL));
                    out << std::format("    {:<12} {}\n", "SHA-256", cert.value("fingerprint_sha256", ""));
                }
                out << "\n  files\n";
                for (auto it = data["files"].begin(); it != data["files"].end(); ++it)
                    out << std::format("    {:<12} {}  {}\n", it.key(), it.value().value("mode", ""), display_path(it.value().value("path", "")));
                if (data.contains("in_use")) {
                    out << "\n  " << (data.value("in_use", false) ? "used by the profile; password from the " + data.value("password_source", "")
                                                                  : std::string("not used by the profile (client_cert points elsewhere)"))
                        << "\n";
                    if (data.contains("password_command") && data.value("in_use", false))
                        out << "  read the password: " << data["password_command"].get<std::string>() << "\n";
                }
            });
        }

        // ---- remove ----

        int run_remove(Context& context, const Args& args) {
            const auto& paths = context.engine.options().paths;
            ProfileStore profiles(paths);
            ProfileSet set = profiles.load();
            std::string name = selected_profile(args, set, false);
            CertFiles files(paths.certs() / name);
            if (!present(files.dir))
                throw Failure(Code::config, std::format("profile {} has no certificate in {}", name, display_path(files.dir)));
            bool updated = false;
            // The profile first, so it never points at files that are gone.
            if (auto it = set.profiles.find(name); it != set.profiles.end() && path_within(it->second.client_cert, files.dir)) {
                Profile& profile = it->second;
                if (profile.cert_password.source == SecretRef::Source::store) context.engine.secrets().erase(profile.cert_password_account());
                profile.client_cert.clear();
                profile.cert_password = {};
                profiles.save(set);
                updated = true;
            }
            std::error_code error;
            fs::remove_all(files.dir, error);
            if (error) throw Failure(Code::config, std::format("cannot remove {}: {}", files.dir.string(), error.message()));
            json data = {{"profile", name}, {"removed", files.dir.string()}, {"profile_updated", updated}};
            return emit(context.output, engine::ok(std::move(data), {{"profile", name}}), [](std::ostream& out, const json& data, const json&) {
                out << std::format("Removed {}.\n", display_path(data.value("removed", "")));
                if (data.value("profile_updated", false))
                    out << std::format("Profile {} no longer uses a client certificate. If its FortiGate API user requires one\n"
                                       "(peer-auth), the profile cannot connect until you run `forti cert create --profile {}`\n"
                                       "or disable peer-auth for that API user.\n",
                                       data.value("profile", ""), data.value("profile", ""));
            });
        }

        int run_cert(Context& context, const Args& args) {
            std::string action = args.positional.empty() ? "" : args.positional[0];
            if (args.positional.size() != 1) throw Failure(Code::usage, "usage: forti cert create|show|remove [--profile NAME]");
            if (action != "create" && (args.value("days") || args.flag("force") || args.flag("keychain")))
                throw Failure(Code::usage, "--days, --force and --keychain apply to forti cert create only");
            if (action == "create") return run_create(context, args);
            if (action == "show") return run_show(context, args);
            if (action == "remove") return run_remove(context, args);
            throw Failure(Code::usage, std::format("unknown cert action \"{}\"", action), {{"hint", "forti cert create | show | remove"}});
        }

    }  // namespace

    std::vector<Command> cert_commands() {
        return {
            {"cert", "Create, show or remove a profile's client certificate",
             "usage: forti cert create [--profile NAME] [--days N] [--force] [--keychain]\n"
             "       forti cert show [--profile NAME]\n"
             "       forti cert remove [--profile NAME]\n"
             "\n"
             "create makes a private CA and a client certificate (CN forti-<profile>) for FortiOS PKI\n"
             "authentication of the REST API user, in <home>/certs/<profile>/:\n"
             "  ca.crt        import on the FortiGate as a CA certificate\n"
             "  ca/ca.key     the CA key (0600); it never leaves this machine\n"
             "  client.crt    the client certificate\n"
             "  client.p12    certificate, key and CA; becomes the profile's client_cert\n"
             "  client.pass   the .p12 password (0600); the profile reads it from this file\n"
             "It then prints the FortiGate commands: import the CA, create a PKI user (user peer) and a\n"
             "peer group, and enable peer-auth for the API user. The password is never printed; the\n"
             "output shows the command that reads it. Needs the openssl command.\n"
             "\n"
             "options (create):\n"
             "  --days N      client certificate validity (default 1095; the CA gets at least 3650)\n"
             "  --force       replace an existing CA (the FortiGate must then import the new ca.crt)\n"
             "  --keychain    keep the password in the secret store (the macOS Keychain, or the 0600 file\n"
             "                store) instead of client.pass\n"
             "\n"
             "show prints the subject, expiry and SHA-256 fingerprint of the certificates. remove deletes\n"
             "the directory and clears the profile's client_cert when it pointed there.\n",
             {{"days"}, {"force", "keychain"}, {}},
             run_cert},
        };
    }

}  // namespace forti::cli
