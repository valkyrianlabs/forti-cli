#include "setup_support.hpp"

#include <forti/engine/error.hpp>

#include <cctype>
#include <cstdlib>
#include <format>

#include <sys/stat.h>
#include <unistd.h>

namespace forti::cli {

    namespace fs = std::filesystem;
    using engine::Code;
    using engine::Failure;
    using engine::SecretRef;

    std::optional<fs::path> find_on_path(std::string_view program) {
        const char* path = std::getenv("PATH");
        std::string_view rest = path ? path : "";
        while (!rest.empty()) {
            auto colon = rest.find(':');
            std::string dir(rest.substr(0, colon));
            rest = colon == std::string_view::npos ? std::string_view() : rest.substr(colon + 1);
            // A relative entry (or the empty one, meaning ".") would make the result depend on the
            // working directory, which a repository controls.
            if (dir.empty() || !fs::path(dir).is_absolute()) continue;
            fs::path candidate = fs::path(dir) / program;
            std::error_code error;
            if (fs::is_regular_file(candidate, error) && ::access(candidate.c_str(), X_OK) == 0) return candidate;
        }
        return std::nullopt;
    }

    unsigned file_mode(const fs::path& path) {
        struct stat info{};
        return ::stat(path.c_str(), &info) == 0 ? info.st_mode & 07777 : 0;
    }

    std::string shell_quote(std::string_view text) {
        bool safe = !text.empty();
        for (char c: text)
            safe = safe && (std::isalnum(static_cast<unsigned char>(c)) || std::string_view("@%_+=:,./-").find(c) != std::string_view::npos);
        if (safe) return std::string(text);
        std::string out = "'";
        for (char c: text) out += c == '\'' ? std::string("'\\''") : std::string(1, c);
        return out + "'";
    }

    std::string shell_join(const std::vector<std::string>& argv) {
        std::string out;
        for (const auto& arg: argv) out += (out.empty() ? "" : " ") + shell_quote(arg);
        return out;
    }

    namespace {

        // The part of `path` below $HOME, or nullopt.
        std::optional<std::string> below_home(const fs::path& path) {
            const char* home = std::getenv("HOME");
            if (!home || !*home || !fs::path(home).is_absolute()) return std::nullopt;
            fs::path base = fs::path(home).lexically_normal();
            fs::path relative = path.lexically_normal().lexically_relative(base);
            if (relative.empty() || *relative.begin() == "..") return std::nullopt;
            if (relative == ".") return std::string();
            return relative.string();
        }

    }  // namespace

    std::string display_path(const fs::path& path) {
        auto rest = below_home(path);
        if (!rest) return path.string();
        return rest->empty() ? "~" : "~/" + *rest;
    }

    std::string shell_path(const fs::path& path) {
        auto rest = below_home(path);
        if (!rest) return shell_quote(path.string());
        return rest->empty() ? "~" : "~/" + shell_quote(*rest);
    }

    bool path_within(const fs::path& path, const fs::path& dir) {
        if (path.empty() || dir.empty()) return false;
        fs::path relative = path.lexically_normal().lexically_relative(dir.lexically_normal());
        return !relative.empty() && *relative.begin() != "..";
    }

    std::string describe_source(const SecretRef& ref, std::string_view store_kind) {
        switch (ref.source) {
            case SecretRef::Source::none: return "none";
            case SecretRef::Source::store:
                return store_kind == "keychain" ? "macOS Keychain" : std::format("{} store", store_kind);
            case SecretRef::Source::env: return std::format("environment variable {}", ref.env);
            case SecretRef::Source::command: return std::format("command `{}`", ref.command.empty() ? "" : ref.command[0]);
            case SecretRef::Source::file: return std::format("file {}", display_path(ref.path));
        }
        return "none";
    }

    LegacyDirs legacy_dirs() {
        const char* home = std::getenv("HOME");
        if (!home || !*home) throw Failure(Code::config, "HOME is not set");
        auto locate = [&](const char* xdg, const char* fallback) {
            const char* value = std::getenv(xdg);
            if (value && *value && fs::path(value).is_absolute()) return fs::path(value) / "forti";
            return fs::path(home) / fallback / "forti";
        };
        return {locate("XDG_CONFIG_HOME", ".config"), locate("XDG_STATE_HOME", ".local/state"), locate("XDG_CACHE_HOME", ".cache")};
    }

}  // namespace forti::cli
