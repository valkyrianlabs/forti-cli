#include <forti/engine/error.hpp>
#include <forti/engine/profile.hpp>

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <format>
#include <fstream>
#include <sstream>
#include <system_error>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace forti::engine {

    namespace fs = std::filesystem;

    namespace {

        std::string env(const char* name) {
            const char* value = std::getenv(name);
            return value ? value : "";
        }

        fs::path home() {
            std::string dir = env("HOME");
            if (dir.empty()) throw Failure(Code::config, "HOME is not set");
            return dir;
        }

        // $<override> | $<xdg>/forti | ~/<fallback>/forti
        fs::path locate(const char* override_var, const char* xdg_var, const char* fallback) {
            if (auto value = env(override_var); !value.empty()) {
                // A relative override would make the profiles, credentials and modes depend on the
                // working directory (a project directory an agent or a repository controls).
                if (!fs::path(value).is_absolute())
                    throw Failure(Code::config, std::format("{} must be an absolute path, not \"{}\"", override_var, value));
                return value;
            }
            if (auto value = env(xdg_var); !value.empty() && fs::path(value).is_absolute()) return fs::path(value) / "forti";
            return home() / fallback / "forti";
        }

        template<typename T>
        T get_or(const nlohmann::json& json, const char* key, T fallback) {
            auto it = json.find(key);
            return it != json.end() && !it->is_null() ? it->get<T>() : fallback;
        }

    }  // namespace

    Paths Paths::from_env() {
        return {locate("FORTI_CONFIG_DIR", "XDG_CONFIG_HOME", ".config"),
                locate("FORTI_STATE_DIR", "XDG_STATE_HOME", ".local/state"),
                locate("FORTI_CACHE_DIR", "XDG_CACHE_HOME", ".cache")};
    }

    nlohmann::json SecretRef::to_json() const {
        switch (source) {
            case Source::none: return nullptr;
            case Source::store: return {{"source", "store"}};
            case Source::env: return {{"source", "env"}, {"env", env}};
            case Source::command: return {{"source", "command"}, {"command", command}};
        }
        return nullptr;
    }

    SecretRef SecretRef::from_json(const nlohmann::json& json) {
        SecretRef ref;
        if (json.is_null()) return ref;
        if (!json.is_object()) throw Failure(Code::config, "a credential reference must be an object");
        auto source = get_or<std::string>(json, "source", "store");
        if (source == "store") ref.source = Source::store;
        else if (source == "env") {
            ref.source = Source::env;
            ref.env = get_or<std::string>(json, "env", "");
            if (ref.env.empty()) throw Failure(Code::config, "credential source \"env\" needs an \"env\" variable name");
        } else if (source == "command") {
            ref.source = Source::command;
            ref.command = get_or<std::vector<std::string>>(json, "command", {});
            if (ref.command.empty()) throw Failure(Code::config, "credential source \"command\" needs a \"command\" argv");
        } else throw Failure(Code::config, std::format("unknown credential source: {}", source));
        return ref;
    }

    std::string_view to_string(Mode mode) {
        switch (mode) {
            case Mode::read_only: return "read-only";
            case Mode::guarded: return "guarded";
            case Mode::autonomous: return "autonomous";
        }
        return "read-only";
    }

    Mode parse_mode(std::string_view text) {
        if (text == "read-only") return Mode::read_only;
        if (text == "guarded") return Mode::guarded;
        if (text == "autonomous") return Mode::autonomous;
        throw Failure(Code::config, std::format("unknown mode \"{}\" (read-only, guarded, autonomous)", text));
    }

    void validate_profile_name(std::string_view name) {
        bool valid = !name.empty() && name.size() <= 64;
        for (char c: name) valid = valid && (std::isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_');
        if (!valid) throw Failure(Code::usage, std::format("invalid profile name \"{}\" (letters, digits, - and _)", name));
    }

    nlohmann::json Profile::to_json() const {
        nlohmann::json out = {{"host", host}, {"port", port}, {"mode", to_string(mode)}, {"api_key", api_key.to_json()}};
        if (!vdom.empty()) out["vdom"] = vdom;
        if (!ca_bundle.empty()) out["ca_bundle"] = ca_bundle;
        if (!client_cert.empty()) out["client_cert"] = client_cert;
        if (cert_password.source != SecretRef::Source::none) out["cert_password"] = cert_password.to_json();
        if (!resolve_ip.empty()) out["resolve_ip"] = resolve_ip;
        if (connect_timeout_ms != 5000) out["connect_timeout_ms"] = connect_timeout_ms;
        if (timeout_ms != 30000) out["timeout_ms"] = timeout_ms;
        if (!backup_before_critical) out["backup_before_critical"] = false;
        return out;
    }

    nlohmann::json Profile::describe() const {
        nlohmann::json out = to_json();
        out["name"] = name;
        out["api_key"] = api_key.source == SecretRef::Source::env ? "env:" + api_key.env
                         : api_key.source == SecretRef::Source::command ? std::string("command")
                         : api_key.source == SecretRef::Source::store ? std::string("secret store")
                         : std::string("none");
        out.erase("cert_password");
        if (cert_password.source != SecretRef::Source::none) out["client_cert_password"] = "configured";
        return out;
    }

    Profile Profile::from_json(std::string name, const nlohmann::json& json) {
        validate_profile_name(name);
        if (!json.is_object()) throw Failure(Code::config, std::format("profile {}: expected an object", name));
        try {
            Profile profile;
            profile.name = std::move(name);
            profile.host = get_or<std::string>(json, "host", "");
            if (profile.host.empty()) throw Failure(Code::config, std::format("profile {}: \"host\" is required", profile.name));
            profile.port = get_or<unsigned>(json, "port", 443);
            if (profile.port == 0 || profile.port > 65535)
                throw Failure(Code::config, std::format("profile {}: port out of range", profile.name));
            profile.vdom = get_or<std::string>(json, "vdom", "");
            profile.ca_bundle = get_or<std::string>(json, "ca_bundle", "");
            profile.client_cert = get_or<std::string>(json, "client_cert", "");
            profile.resolve_ip = get_or<std::string>(json, "resolve_ip", "");
            profile.mode = parse_mode(get_or<std::string>(json, "mode", "read-only"));
            profile.connect_timeout_ms = get_or<unsigned>(json, "connect_timeout_ms", 5000);
            profile.timeout_ms = get_or<unsigned>(json, "timeout_ms", 30000);
            profile.backup_before_critical = get_or<bool>(json, "backup_before_critical", true);
            profile.api_key = json.contains("api_key") ? SecretRef::from_json(json["api_key"])
                                                       : SecretRef{SecretRef::Source::store, {}, {}};
            if (json.contains("cert_password")) profile.cert_password = SecretRef::from_json(json["cert_password"]);
            if (json.contains("api_key_value") || json.contains("token") || json.contains("password"))
                throw Failure(Code::config, std::format("profile {}: secrets must not be stored in config.json "
                                                        "(use `forti configure`)", profile.name));
            return profile;
        } catch (const nlohmann::json::exception& error) {
            throw Failure(Code::config, std::format("profile {}: {}", name, error.what()));
        }
    }

    nlohmann::json ProfileSet::to_json() const {
        nlohmann::json list = nlohmann::json::object();
        for (const auto& [name, profile]: profiles) list[name] = profile.to_json();
        nlohmann::json out = {{"version", 1}, {"profiles", std::move(list)}};
        if (!default_profile.empty()) out["default_profile"] = default_profile;
        return out;
    }

    ProfileSet ProfileSet::from_json(const nlohmann::json& json) {
        if (!json.is_object()) throw Failure(Code::config, "config.json: expected an object");
        if (get_or<int>(json, "version", 1) != 1) throw Failure(Code::config, "config.json: unsupported version");
        ProfileSet set;
        set.default_profile = get_or<std::string>(json, "default_profile", "");
        if (auto it = json.find("profiles"); it != json.end() && it->is_object())
            for (auto entry = it->begin(); entry != it->end(); ++entry)
                set.profiles.emplace(entry.key(), Profile::from_json(entry.key(), entry.value()));
        return set;
    }

    const Profile& ProfileSet::select(std::string_view name) const {
        if (name.empty()) {
            if (!default_profile.empty()) name = default_profile;
            else if (profiles.size() == 1) return profiles.begin()->second;
            else if (profiles.empty())
                throw Failure(Code::config, "no device profile is configured (run `forti configure`)");
            else throw Failure(Code::config, "several profiles exist and none is the default: pass --profile");
        }
        auto it = profiles.find(std::string(name));
        if (it == profiles.end()) throw Failure(Code::config, std::format("no profile named \"{}\"", name));
        return it->second;
    }

    bool ProfileStore::exists() const { return fs::exists(paths_.config_file()); }

    ProfileSet ProfileStore::load() const {
        auto file = paths_.config_file();
        // config.json decides each profile's mode and may name a credential command that forti runs:
        // refuse one that another user owns or can write (like OpenSSH's StrictModes), checked on the
        // descriptor that is then read.
        int fd = ::open(file.c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK);
        if (fd < 0) {
            if (errno == ENOENT || errno == ENOTDIR) return {};
            throw Failure(Code::config, std::format("cannot read {}: {}", file.string(), std::strerror(errno)));
        }
        struct Closer {
            int fd;
            ~Closer() { ::close(fd); }
        } closer{fd};
        struct stat info{};
        if (::fstat(fd, &info) != 0 || !S_ISREG(info.st_mode))
            throw Failure(Code::config, std::format("{} is not a regular file", file.string()));
        if (info.st_uid != ::geteuid())
            throw Failure(Code::config, std::format("{} is owned by another user", file.string()));
        if (info.st_mode & (S_IWGRP | S_IWOTH))
            throw Failure(Code::config, std::format("{} is writable by other users; run chmod 600 on it", file.string()));
        struct stat dir{};
        if (::stat(paths_.config.c_str(), &dir) == 0 && (dir.st_mode & (S_IWGRP | S_IWOTH)) && !(dir.st_mode & S_ISVTX))
            throw Failure(Code::config, std::format("{} is writable by other users; run chmod 700 on it",
                                                    paths_.config.string()));
        std::string text;
        char buffer[8192];
        for (ssize_t n; (n = ::read(fd, buffer, sizeof buffer)) != 0;) {
            if (n < 0) {
                if (errno == EINTR) continue;
                throw Failure(Code::config, std::format("cannot read {}", file.string()));
            }
            text.append(buffer, static_cast<std::size_t>(n));
            if (text.size() > (16u << 20)) throw Failure(Code::config, std::format("{} is too large", file.string()));
        }
        auto json = nlohmann::json::parse(text, nullptr, false);
        if (json.is_discarded()) throw Failure(Code::config, std::format("{}: not valid JSON", file.string()));
        return ProfileSet::from_json(json);
    }

    void ProfileStore::save(const ProfileSet& set) const {
        ensure_private_dir(paths_.config);
        write_private_file(paths_.config_file(), set.to_json().dump(2) + "\n");
    }

    void ensure_private_dir(const fs::path& dir) {
        std::error_code error;
        fs::create_directories(dir, error);
        if (error) throw Failure(Code::config, std::format("cannot create {}: {}", dir.string(), error.message()));
        if (::chmod(dir.c_str(), 0700) != 0)
            throw Failure(Code::config, std::format("cannot restrict {} to its owner", dir.string()));
    }

    void write_private_file(const fs::path& file, std::string_view content) {
        fs::path temp = file;
        temp += std::format(".tmp.{}", ::getpid());
        int fd = ::open(temp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (fd < 0) throw Failure(Code::config, std::format("cannot write {}", file.string()));
        ::fchmod(fd, 0600);
        std::size_t written = 0;
        while (written < content.size()) {
            ssize_t n = ::write(fd, content.data() + written, content.size() - written);
            if (n <= 0) {
                ::close(fd);
                ::unlink(temp.c_str());
                throw Failure(Code::config, std::format("cannot write {}", file.string()));
            }
            written += static_cast<std::size_t>(n);
        }
        bool synced = ::fsync(fd) == 0;
        ::close(fd);
        if (!synced || ::rename(temp.c_str(), file.c_str()) != 0) {
            ::unlink(temp.c_str());
            throw Failure(Code::config, std::format("cannot replace {}", file.string()));
        }
    }

}  // namespace forti::engine
