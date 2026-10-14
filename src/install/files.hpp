//
// File-system helpers for the installer: atomic writes that keep the file mode, PATH lookup that
// keeps symlinks (a Homebrew bin link survives upgrades; the Cellar path behind it does not), and
// the running executable's own path.
//

#ifndef FORTI_INSTALL_FILES_HPP
#define FORTI_INSTALL_FILES_HPP

#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <sys/types.h>

namespace forti::install {

    namespace fs = std::filesystem;

    // nullopt when the file does not exist; throws Failure(config) on any other read error.
    std::optional<std::string> read_file(const fs::path& path);

    // Writes through a temporary file in the same directory and rename(2), so readers see the old or
    // the new content, never a mix. Keeps the mode of an existing file (else `mode`), writes through
    // a symlink to its target, and creates missing parent directories (0755).
    void write_file_atomic(const fs::path& path, std::string_view content, mode_t mode = 0644);

    // Removes a file (no error when it is already gone), then `parent` directories up to `stop` that
    // became empty. Never removes `stop` itself or anything non-empty.
    void remove_file(const fs::path& path, const fs::path& stop = {});

    // The first executable `name` on $PATH, absolute but with symlinks kept.
    std::optional<fs::path> find_executable(std::string_view name);

    bool is_executable(const fs::path& path);

    // The running executable as it was invoked (macOS: _NSGetExecutablePath, which keeps the
    // symlink a Homebrew bin entry is; Linux: /proc/self/exe).
    std::optional<fs::path> self_executable();

    // $NAME when set and non-empty.
    std::optional<std::string> env(const char* name);

    // Absolute and canonical when it exists (macOS /tmp → /private/tmp), else absolute and normalized.
    fs::path canonical_or_absolute(const fs::path& path);

}  // namespace forti::install

#endif  // FORTI_INSTALL_FILES_HPP
