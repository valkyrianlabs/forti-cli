//
// Certificate sets and the forti CA (see certs.hpp). The work is done by the openssl command (an argv
// vector, never a shell), with the choices of forti-api's tools/gen-certs.sh: RSA 3072, SHA-256, and a
// PKCS#12 with PBE-SHA1-3DES and a SHA-1 MAC, which OpenSSL 3 without the legacy provider, LibreSSL
// (macOS /usr/bin/openssl, and libcurl there) and FortiOS all read. No password ever reaches argv:
// openssl reads it from client.pass.
//

#include "certs.hpp"
#include "setup_support.hpp"
#include "tty.hpp"

#include <forti/engine/error.hpp>
#include <process.hpp>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <ctime>
#include <format>
#include <fstream>
#include <sstream>

#include <sys/stat.h>
#include <unistd.h>

namespace forti::cli::certs {

    using engine::Code;
    using engine::Failure;
    using engine::SecretRef;
    using json = nlohmann::json;
    namespace fs = std::filesystem;

    namespace {

        constexpr unsigned own_ca_days = 3650;
        constexpr unsigned forti_ca_days = 7300;

        bool present(const fs::path& path) {
            std::error_code error;
            return fs::exists(fs::symlink_status(path, error));
        }

        std::string read_text(const fs::path& path) {
            std::ifstream in(path, std::ios::binary);
            std::ostringstream text;
            text << in.rdbuf();
            return text.str();
        }

        std::optional<fs::path> find_openssl() { return find_on_path("openssl"); }

        fs::path openssl_program() {
            if (auto program = find_openssl()) return *program;
            throw Failure(Code::config, "the openssl command is not installed; forti uses it to make certificates",
                          {{"hint", "install openssl (Debian and Ubuntu: apt install openssl; macOS ships /usr/bin/openssl)"}});
        }

        // Runs openssl in `cwd`. Its output never contains a secret: passwords are passed as file: references.
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

        // A private directory below `parent` named .<stem>.new.XXXXXX.
        fs::path staging_dir(const fs::path& parent, std::string_view stem) {
            std::string pattern = (parent / std::format(".{}.new.XXXXXX", stem)).string();
            if (!::mkdtemp(pattern.data())) throw Failure(Code::config, std::format("cannot create a directory in {}", parent.string()));
            return pattern;
        }

        // The CN of a subject as openssl prints it: "O=forti, CN=x" (OpenSSL 3 with -nameopt
        // compat), "O = forti, CN = x" (OpenSSL 3's default) or "/O=forti/CN=x" (LibreSSL).
        std::optional<std::string> common_name(std::string_view subject) {
            for (std::size_t at = subject.find("CN"); at != std::string_view::npos; at = subject.find("CN", at + 2)) {
                if (at > 0 && subject[at - 1] != '/' && subject[at - 1] != ' ' && subject[at - 1] != ',') continue;
                std::size_t equals = subject.find_first_not_of(' ', at + 2);
                if (equals == std::string_view::npos || subject[equals] != '=') continue;
                std::string_view rest = subject.substr(equals + 1);
                return trim(std::string(rest.substr(0, rest.find_first_of(",/"))));
            }
            return std::nullopt;
        }

        // subject, cn, expiry and SHA-256 fingerprint of a PEM certificate. OpenSSL 3 prints
        // "subject=O=forti, CN=x" and "sha256 Fingerprint=…", LibreSSL "subject= /O=forti/CN=x" and
        // "SHA256 Fingerprint=…"; both print "notAfter=Oct 14 19:48:33 2029 GMT".
        json certificate_info(const fs::path& program, const fs::path& file) {
            std::string text = openssl(program, {"x509", "-in", file.filename().string(), "-noout", "-subject", "-issuer", "-enddate",
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
                if (key == "issuer") info["issuer"] = value;
                else if (key == "subject") {
                    info["subject"] = value;
                    if (auto cn = common_name(value)) info["cn"] = *cn;
                } else if (key == "notAfter") {
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

        fs::path forti_ca_cert(const engine::Paths& paths) { return forti_ca_dir(paths) / "ca.crt"; }
        fs::path forti_ca_key(const engine::Paths& paths) { return forti_ca_dir(paths) / "ca.key"; }

        // The forti CA's certificate subject is "forti CA <id>", with a random id: CAs of different
        // machines must not share a subject on one FortiGate, which finds a certificate's CA by it.
        std::string forti_ca_id(const json& info) {
            std::string cn = info.value("cn", "");
            if (cn.starts_with("forti CA ")) return cn.substr(9);
            std::string fingerprint = info.value("fingerprint_sha256", "");
            std::erase(fingerprint, ':');
            std::ranges::transform(fingerprint, fingerprint.begin(), [](unsigned char c) { return std::tolower(c); });
            return fingerprint.substr(0, 8);
        }

        // Makes the forti CA when it does not exist yet; true when it was made now.
        bool ensure_forti_ca(const engine::Paths& paths, const fs::path& program) {
            fs::path dir = forti_ca_dir(paths);
            if (present(forti_ca_key(paths)) && present(forti_ca_cert(paths))) return false;
            if (present(dir))
                throw Failure(Code::config, std::format("{} is incomplete (it needs ca.crt and ca.key)", display_path(dir)),
                              {{"hint", "move it aside; forti then makes a new forti CA (FortiGates must import the new one)"}});
            engine::ensure_private_dir(dir.parent_path());
            fs::path staging = staging_dir(dir.parent_path(), "ca");
            try {
                restrict(staging, 0700);
                openssl(program, {"req", "-x509", "-new", "-newkey", "rsa:3072", "-sha256", "-days", std::to_string(forti_ca_days),
                                  "-nodes", "-subj", std::format("/O=forti/CN=forti CA {}", random_hex(4)),
                                  "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
                                  "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                                  "-addext", "subjectKeyIdentifier=hash",
                                  "-keyout", "ca.key", "-out", "ca.crt"}, staging);
                restrict(staging / "ca.key", 0600);
                restrict(staging / "ca.crt", 0644);
                if (::rename(staging.c_str(), dir.c_str()) != 0) throw Failure(Code::config, std::format("cannot create {}", dir.string()));
            } catch (...) {
                std::error_code error;
                fs::remove_all(staging, error);
                throw;
            }
            return true;
        }

        std::string issuer_of(const engine::Paths& paths, const Set& files) {
            if (present(files.ca_key)) return "own CA";
            if (present(files.ca_cert) && present(forti_ca_cert(paths)) && read_text(files.ca_cert) == read_text(forti_ca_cert(paths)))
                return "forti CA";
            return "other";
        }

        std::vector<std::string> lines_of(const std::string& text) {
            std::vector<std::string> lines;
            for (std::size_t start = 0; start < text.size();) {
                std::size_t end = text.find('\n', start);
                if (end == std::string::npos) end = text.size();
                lines.push_back(text.substr(start, end - start));
                start = end + 1;
            }
            return lines;
        }

    }  // namespace

    fs::path forti_ca_dir(const engine::Paths& paths) { return paths.certs().parent_path() / "ca"; }

    Set::Set(const engine::Paths& paths, std::string set_name) : Set(set_name, paths.certs() / set_name) {}

    Set::Set(std::string set_name, fs::path base)
        : name(std::move(set_name)), dir(std::move(base)), ca_cert(dir / "ca.crt"), ca_dir(dir / "ca"), ca_key(ca_dir / "ca.key"),
          client_cert(dir / "client.crt"), client_p12(dir / "client.p12"), client_pass(dir / "client.pass") {}

    bool Set::exists() const { return present(dir); }

    void validate_name(std::string_view name) {
        bool valid = !name.empty() && name.size() <= 64;
        for (char c: name) valid = valid && (std::isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_');
        if (!valid) throw Failure(Code::usage, std::format("invalid certificate name \"{}\" (letters, digits, - and _)", name));
    }

    std::optional<std::string> used_by(const engine::Paths& paths, const engine::Profile& profile) {
        if (profile.client_cert.empty() || !path_within(profile.client_cert, paths.certs())) return std::nullopt;
        fs::path relative = fs::path(profile.client_cert).lexically_normal().lexically_relative(paths.certs().lexically_normal());
        if (relative.empty() || relative.begin() == relative.end()) return std::nullopt;
        std::string name = relative.begin()->string();
        if (name.empty() || name == "." || name == ".." || name.starts_with('.')) return std::nullopt;
        return name;
    }

    json describe(const engine::Paths& paths, const engine::ProfileSet& set, const std::string& name) {
        Set files(paths, name);
        json out = {{"name", name}, {"dir", files.dir.string()}, {"issuer", issuer_of(paths, files)},
                    {"password_file", present(files.client_pass)}};
        if (auto program = find_openssl(); program && present(files.client_cert)) {
            try {
                json info = certificate_info(*program, files.client_cert);
                for (const char* key: {"cn", "subject", "expires", "expired", "days_left", "fingerprint_sha256"})
                    if (info.contains(key)) out[key] = info[key];
            } catch (const Failure&) {
                out["unreadable"] = true;
            }
        }
        json users = json::array();
        for (const auto& [profile_name, profile]: set.profiles)
            if (!profile.client_cert.empty() && path_within(profile.client_cert, files.dir)) users.push_back(profile_name);
        out["used_by"] = users;
        return out;
    }

    json list(const engine::Paths& paths, const engine::ProfileSet& set) {
        std::vector<std::string> names;
        std::error_code error;
        if (fs::is_directory(paths.certs(), error))
            for (const auto& entry: fs::directory_iterator(paths.certs(), error)) {
                std::string name = entry.path().filename().string();
                if (name.starts_with('.') || !entry.is_directory(error)) continue;
                if (present(entry.path() / "client.p12")) names.push_back(name);
            }
        std::ranges::sort(names);
        json out = json::array();
        for (const auto& name: names) out.push_back(describe(paths, set, name));
        return out;
    }

    json forti_ca(const engine::Paths& paths) {
        json out = {{"path", forti_ca_cert(paths).string()}, {"exists", present(forti_ca_cert(paths))}};
        if (!out["exists"].get<bool>()) return out;
        if (auto program = find_openssl()) {
            try {
                json info = certificate_info(*program, forti_ca_cert(paths));
                for (const char* key: {"subject", "expires", "days_left", "fingerprint_sha256"})
                    if (info.contains(key)) out[key] = info[key];
                out["fortigate_name"] = "forti-ca-" + forti_ca_id(info);
            } catch (const Failure&) {
                out["unreadable"] = true;
            }
        }
        return out;
    }

    json create(const engine::Paths& paths, const engine::ProfileSet& set, const std::string& name, const CreateOptions& options) {
        validate_name(name);
        Set files(paths, name);
        bool replacing = files.exists();
        if (replacing && !options.replace)
            throw Failure(Code::config, std::format("a certificate named \"{}\" already exists; nothing was changed", name),
                          {{"hint", std::format("use it as it is (forti cert use {0}), or replace it: forti cert create {0} --force", name)}});
        std::string before = replacing ? issuer_of(paths, files) : "";
        fs::path program = openssl_program();
        std::string cn = "forti-" + name;

        bool ca_created = false;
        if (!options.own_ca) {
            ca_created = ensure_forti_ca(paths, program);
            json ca = certificate_info(program, forti_ca_cert(paths));
            long long left = ca.value("days_left", 0LL);
            if (static_cast<long long>(options.days) > left)
                throw Failure(Code::usage, std::format("the forti CA is valid for {} more days: a certificate it issues cannot outlive it", left),
                              {{"hint", std::format("pass --days {} or less, or --own-ca", left)}});
        }

        engine::ensure_private_dir(paths.certs());
        fs::path staging = staging_dir(paths.certs(), name);
        Set work(name, staging);
        std::string password = random_hex(24);
        try {
            restrict(staging, 0700);
            engine::write_private_file(work.client_pass, password + "\n");
            engine::write_private_file(staging / "client.ext",
                                       "basicConstraints=critical,CA:FALSE\n"
                                       "keyUsage=critical,digitalSignature,keyEncipherment\n"
                                       "subjectKeyIdentifier=hash\n"
                                       "authorityKeyIdentifier=keyid\n"
                                       "extendedKeyUsage=clientAuth\n");
            std::string ca_key;
            if (options.own_ca) {
                engine::ensure_private_dir(work.ca_dir);
                openssl(program, {"req", "-x509", "-new", "-newkey", "rsa:3072", "-sha256", "-days",
                                  std::to_string(std::max(options.days, own_ca_days)), "-nodes",
                                  "-subj", std::format("/O=forti/CN={} CA", cn),
                                  "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
                                  "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                                  "-addext", "subjectKeyIdentifier=hash",
                                  "-keyout", "ca/ca.key", "-out", "ca.crt"}, staging);
                ca_key = "ca/ca.key";
            } else {
                fs::copy_file(forti_ca_cert(paths), work.ca_cert);
                ca_key = forti_ca_key(paths).string();
            }
            openssl(program, {"req", "-new", "-newkey", "rsa:3072", "-sha256", "-nodes", "-subj",
                              std::format("/O=forti/CN={}", cn), "-keyout", "client.key", "-out", "client.csr"}, staging);
            openssl(program, {"x509", "-req", "-sha256", "-days", std::to_string(options.days), "-in", "client.csr", "-CA", "ca.crt",
                              "-CAkey", ca_key, "-set_serial", "0x" + random_hex(16), "-extfile", "client.ext",
                              "-out", "client.crt"}, staging);
            openssl(program, {"pkcs12", "-export", "-certpbe", "PBE-SHA1-3DES", "-keypbe", "PBE-SHA1-3DES", "-macalg", "sha1",
                              "-name", cn, "-inkey", "client.key", "-in", "client.crt", "-certfile", "ca.crt",
                              "-passout", "file:client.pass", "-out", "client.p12"}, staging);
            openssl(program, {"verify", "-CAfile", "ca.crt", "client.crt"}, staging);
            for (const char* scratch: {"client.key", "client.csr", "client.ext"}) fs::remove(staging / scratch);
            // openssl leaves modes to the umask (LibreSSL writes keys 0644); the directory was private throughout.
            if (options.own_ca) {
                restrict(work.ca_dir, 0700);
                restrict(work.ca_key, 0600);
            }
            restrict(work.client_p12, 0600);
            restrict(work.client_pass, 0600);
            restrict(work.ca_cert, 0644);
            restrict(work.client_cert, 0644);
            if (options.keep_password) {
                options.keep_password(password);
                fs::remove(work.client_pass);
            }
        } catch (...) {
            std::error_code error;
            fs::remove_all(staging, error);
            throw;
        }

        // Into place: the old set (with replace) is moved aside first, and deleted only afterwards.
        fs::path old;
        if (replacing) {
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

        json out = describe(paths, set, name);
        json file_list = {{"ca_cert", files.ca_cert.string()}, {"client_cert", files.client_cert.string()},
                          {"client_p12", files.client_p12.string()}};
        if (options.own_ca) file_list["ca_key"] = files.ca_key.string();
        else file_list["forti_ca_key"] = forti_ca_key(paths).string();
        if (!options.keep_password) file_list["client_pass"] = files.client_pass.string();
        out["files"] = file_list;
        out["days"] = options.days;
        out["replaced"] = replacing;
        out["forti_ca_created"] = ca_created;
        out["fortigate_unchanged"] = replacing && before == "forti CA" && !options.own_ca;
        return out;
    }

    std::optional<std::string> attach(engine::Profile& profile, const engine::Paths& paths, const engine::ProfileSet& set,
                                      engine::SecretStore& store, const std::string& name) {
        validate_name(name);
        Set files(paths, name);
        if (!present(files.client_p12))
            throw Failure(Code::config, std::format("no certificate named \"{}\" in {}", name, display_path(paths.certs())),
                          {{"hint", std::format("forti cert list shows them; forti cert create {} makes one", name)}});
        profile.client_cert = files.client_p12.string();
        if (present(files.client_pass)) {
            profile.cert_password = {SecretRef::Source::file, {}, {}, files.client_pass.string()};
            return std::nullopt;
        }
        // Made with --keychain: the password is wherever a profile using the set gets it from.
        profile.cert_password = {};
        for (const auto& [other_name, other]: set.profiles) {
            if (other_name == profile.name || other.client_cert.empty() || !path_within(other.client_cert, files.dir)) continue;
            if (other.cert_password.source == SecretRef::Source::store) {
                if (auto stored = store.get(other.cert_password_account())) {
                    profile.cert_password = {SecretRef::Source::store, {}, {}, {}};
                    return stored->secret;
                }
            } else if (other.cert_password.source != SecretRef::Source::none) {
                profile.cert_password = other.cert_password;
                return std::nullopt;
            }
        }
        throw Failure(Code::config, std::format("certificate \"{}\" has no client.pass, and no profile holds its password", name),
                      {{"hint", std::format("give the password with forti configure --profile {} --cert {} --cert-password-stdin",
                                            profile.name, name)}});
    }

    json inspect_pem(const std::string& pem) {
        fs::path program = openssl_program();
        std::string pattern = (fs::temp_directory_path() / "forti-peer.XXXXXX").string();
        if (!::mkdtemp(pattern.data())) throw Failure(Code::internal, "cannot create a temporary directory");
        fs::path dir = pattern;
        json info;
        try {
            std::ofstream(dir / "peer.pem") << pem;
            info = certificate_info(program, dir / "peer.pem");
            // Subject Alternative Names, from the text form (the -ext option is newer than LibreSSL's).
            std::string text = openssl(program, {"x509", "-in", "peer.pem", "-noout", "-text"}, dir);
            json names = json::array();
            if (auto at = text.find("X509v3 Subject Alternative Name:"); at != std::string::npos) {
                auto start = text.find('\n', at);
                auto end = start == std::string::npos ? std::string::npos : text.find('\n', start + 1);
                if (start != std::string::npos) {
                    std::string line = trim(text.substr(start + 1, end == std::string::npos ? std::string::npos : end - start - 1));
                    std::size_t from = 0;
                    while (from < line.size()) {
                        auto comma = line.find(',', from);
                        std::string name = trim(line.substr(from, comma == std::string::npos ? std::string::npos : comma - from));
                        if (name.starts_with("IP Address:")) name = "IP:" + name.substr(11);
                        if (name.starts_with("DNS:") || name.starts_with("IP:")) names.push_back(name);
                        from = comma == std::string::npos ? line.size() : comma + 1;
                    }
                }
            }
            info["names"] = names;
            info["self_signed"] = info.value("subject", "") == info.value("issuer", "-");
        } catch (...) {
            std::error_code error;
            fs::remove_all(dir, error);
            throw;
        }
        std::error_code error;
        fs::remove_all(dir, error);
        return info;
    }

    bool covers(const json& inspected, std::string_view host) {
        std::string want(host);
        if (want.starts_with('[') && want.ends_with(']')) want = want.substr(1, want.size() - 2);
        auto lower = [](std::string text) {
            std::ranges::transform(text, text.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            return text;
        };
        want = lower(want);
        const json& names = inspected.contains("names") ? inspected["names"] : json::array();
        auto matches = [&](std::string name) {
            name = lower(std::move(name));
            if (name == want) return true;
            // *.example.net covers exactly one label.
            if (name.starts_with("*.")) {
                auto dot = want.find('.');
                return dot != std::string::npos && dot > 0 && want.substr(dot) == name.substr(1);
            }
            return false;
        };
        for (const auto& entry: names) {
            std::string name = entry.get<std::string>();
            if (name.starts_with("DNS:") && matches(name.substr(4))) return true;
            if (name.starts_with("IP:") && lower(name.substr(3)) == want) return true;
        }
        // Without names the common name counts (as libcurl's verification does).
        return names.empty() && inspected.contains("cn") && matches(inspected["cn"].get<std::string>());
    }

    fs::path pin(const engine::Paths& paths, std::string_view host, unsigned port, const std::string& pem) {
        std::string stem;
        for (char c: host) stem += std::isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '-' ? c : '_';
        fs::path dir = paths.certs().parent_path() / "tls";
        engine::ensure_private_dir(dir);
        fs::path file = dir / std::format("{}-{}.pem", stem, port);
        engine::write_private_file(file, pem);
        restrict(file, 0644);   // a certificate: public
        return file;
    }

    json fortigate(const engine::Paths& paths, const std::string& name) {
        Set files(paths, name);
        std::string issuer = issuer_of(paths, files);
        std::string cn = "forti-" + name;
        std::string ca_name = cn + "-ca";
        if (issuer == "forti CA") {
            json ca = forti_ca(paths);
            ca_name = ca.value("fortigate_name", std::string("forti-ca"));
        }
        if (ca_name.size() > 79) ca_name.resize(79);   // vpn.certificate/ca names: 79 characters (FortiOS 7.4.8 schema)
        // user/peer and user/peergrp names: at most 35 characters.
        std::string peer = cn.substr(0, 35), group = cn.substr(0, 29) + "-peers";

        std::string pem = trim(read_text(files.ca_cert));
        std::vector<std::string> steps;
        auto add = [&](std::string text) {
            for (auto& line: lines_of(text)) steps.push_back(std::move(line));
        };
        add(issuer == "forti CA" ? "  1. Import the forti CA (once per FortiGate: skip this step if it is already there):"
                                 : "  1. Import the certificate's CA:");
        add(std::format("       config vpn certificate ca\n"
                        "           edit \"{}\"\n"
                        "               set ca \"{}\"\n"
                        "           next\n"
                        "       end\n"
                        "     (Imported in the GUI instead, it gets a name such as CA_Cert_1: use that name in step 2.)\n"
                        "\n"
                        "  2. Create a PKI user for this certificate and a peer group with it:\n"
                        "       config user peer\n"
                        "           edit \"{}\"\n"
                        "               set ca \"{}\"\n"
                        "               set cn \"{}\"\n"
                        "           next\n"
                        "       end\n"
                        "       config user peergrp\n"
                        "           edit \"{}\"\n"
                        "               set member \"{}\"\n"
                        "           next\n"
                        "       end\n"
                        "\n"
                        "  3. Require the certificate for the REST API user (put your API user's name):\n"
                        "       config system api-user\n"
                        "           edit \"<api-user>\"\n"
                        "               set peer-auth enable\n"
                        "               set peer-group \"{}\"\n"
                        "           next\n"
                        "       end",
                        ca_name, pem, peer, ca_name, cn, group, peer, group));
        return {{"certificate", name}, {"issuer", issuer}, {"ca_name", ca_name}, {"peer", peer}, {"peer_group", group},
                {"cn", cn}, {"steps", steps}};
    }

    std::string steps_text(const json& fortigate) {
        std::string text;
        for (const auto& line: fortigate.value("steps", json::array())) text += line.get<std::string>() + "\n";
        return text;
    }

}  // namespace forti::cli::certs
