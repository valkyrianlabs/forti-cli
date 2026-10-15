//
// Helpers shared by the setup commands (configure, profile, doctor, home, cert): file and path
// display, shell quoting for commands printed for the user to copy, and the pre-0.2 locations.
//

#ifndef FORTI_CLI_SETUP_SUPPORT_HPP
#define FORTI_CLI_SETUP_SUPPORT_HPP

#include <forti/engine/profile.hpp>

#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace forti::cli {

    // The first executable `program` on $PATH (absolute entries only), or nullopt.
    std::optional<std::filesystem::path> find_on_path(std::string_view program);

    // Permission bits (07777) of `path`, 0 when it cannot be stat'ed. Follows symlinks.
    unsigned file_mode(const std::filesystem::path& path);

    // `text` as one POSIX shell word: unchanged when it is safe, else single-quoted.
    std::string shell_quote(std::string_view text);
    std::string shell_join(const std::vector<std::string>& argv);

    // `path` with $HOME shown as ~ (for reading), and the same as a shell word (for copying: the ~
    // stays outside the quotes so the shell still expands it).
    std::string display_path(const std::filesystem::path& path);
    std::string shell_path(const std::filesystem::path& path);

    // True when `path` is `dir` or lies below it (lexically, after normalization).
    bool path_within(const std::filesystem::path& path, const std::filesystem::path& dir);

    // "macOS Keychain", "file store", "environment variable X", "command `x`", "file PATH".
    std::string describe_source(const engine::SecretRef& ref, std::string_view store_kind);

    // The pre-0.2 locations ($XDG_*_HOME/forti, else ~/.config/forti, ~/.local/state/forti,
    // ~/.cache/forti), whether or not they exist. Throws Failure(config) when HOME is not set.
    struct LegacyDirs {
        std::filesystem::path config, state, cache;
    };
    LegacyDirs legacy_dirs();

}  // namespace forti::cli

#endif  // FORTI_CLI_SETUP_SUPPORT_HPP
