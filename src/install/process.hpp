//
// Running AI client CLIs (`claude`, `codex`) and `forti-mcp --version`: posix_spawnp with an argv
// vector, never a shell, so no argument is ever re-parsed. stdin is /dev/null, stdout and stderr are
// captured, and a deadline kills the whole process group. Callers must never put a secret in argv
// (it is visible in `ps`); nothing in the installer needs one.
//

#ifndef FORTI_INSTALL_PROCESS_HPP
#define FORTI_INSTALL_PROCESS_HPP

#include <chrono>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace forti::install {

    struct RunOptions {
        std::optional<std::filesystem::path> cwd;           // run the child in this directory
        std::chrono::milliseconds timeout{30'000};
    };

    struct RunResult {
        int status = -1;          // exit status; 128 + signal when killed by one
        bool timed_out = false;
        std::string out;
        std::string err;

        [[nodiscard]] bool ok() const { return !timed_out && status == 0; }
    };

    // Throws forti::engine::Failure(internal) when the program cannot be started at all.
    RunResult run_process(const std::vector<std::string>& argv, const RunOptions& options = {});

    // "claude mcp add -s user forti -- /opt/homebrew/bin/forti-mcp", quoting arguments that need it.
    // For display only: the argv itself is never joined into a shell command.
    std::string display_command(const std::vector<std::string>& argv);

}  // namespace forti::install

#endif  // FORTI_INSTALL_PROCESS_HPP
