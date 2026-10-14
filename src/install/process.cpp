#include "process.hpp"

#include <forti/engine/error.hpp>

#include <algorithm>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <fcntl.h>
#include <format>
#include <poll.h>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>

extern char** environ;

namespace forti::install {

    using engine::Code;
    using engine::Failure;

    namespace {

        // Owns the posix_spawn attribute objects so every exit path releases them.
        struct SpawnSetup {
            posix_spawn_file_actions_t actions{};
            posix_spawnattr_t attributes{};
            SpawnSetup() {
                posix_spawn_file_actions_init(&actions);
                posix_spawnattr_init(&attributes);
            }
            ~SpawnSetup() {
                posix_spawn_file_actions_destroy(&actions);
                posix_spawnattr_destroy(&attributes);
            }
            SpawnSetup(const SpawnSetup&) = delete;
            SpawnSetup& operator=(const SpawnSetup&) = delete;
        };

        void close_fd(int& fd) {
            if (fd >= 0) ::close(fd);
            fd = -1;
        }

        void make_pipe(int fds[2]) {
            if (::pipe(fds) != 0) throw Failure(Code::internal, std::format("pipe: {}", std::strerror(errno)));
            for (int i = 0; i < 2; ++i) ::fcntl(fds[i], F_SETFD, FD_CLOEXEC);
        }

        int decode_status(int status) {
            if (WIFEXITED(status)) return WEXITSTATUS(status);
            if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
            return -1;
        }

    }  // namespace

    RunResult run_process(const std::vector<std::string>& argv, const RunOptions& options) {
        if (argv.empty()) throw Failure(Code::internal, "run_process: empty argv");

        int out_pipe[2] = {-1, -1};
        int err_pipe[2] = {-1, -1};
        make_pipe(out_pipe);
        try {
            make_pipe(err_pipe);
        } catch (...) {
            close_fd(out_pipe[0]);
            close_fd(out_pipe[1]);
            throw;
        }

        SpawnSetup setup;
        posix_spawn_file_actions_addopen(&setup.actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0);
        posix_spawn_file_actions_adddup2(&setup.actions, out_pipe[1], STDOUT_FILENO);
        posix_spawn_file_actions_adddup2(&setup.actions, err_pipe[1], STDERR_FILENO);
        // _np: the portable spelling (glibc 2.29+, macOS 10.15+). macOS 26 renamed it; the old name still works.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
        if (options.cwd) posix_spawn_file_actions_addchdir_np(&setup.actions, options.cwd->c_str());
#pragma GCC diagnostic pop
        // A process group of its own, so a timeout can stop helpers the client started (node, etc.).
        short flags = POSIX_SPAWN_SETPGROUP;
#ifdef POSIX_SPAWN_CLOEXEC_DEFAULT
        flags |= POSIX_SPAWN_CLOEXEC_DEFAULT;   // macOS: inherit only the three descriptors set up above
#endif
        posix_spawnattr_setflags(&setup.attributes, flags);
        posix_spawnattr_setpgroup(&setup.attributes, 0);

        std::vector<char*> raw;
        raw.reserve(argv.size() + 1);
        for (const auto& arg: argv) raw.push_back(const_cast<char*>(arg.c_str()));
        raw.push_back(nullptr);

        pid_t pid = -1;
        int spawned = posix_spawnp(&pid, raw[0], &setup.actions, &setup.attributes, raw.data(), environ);
        close_fd(out_pipe[1]);
        close_fd(err_pipe[1]);
        if (spawned != 0) {
            close_fd(out_pipe[0]);
            close_fd(err_pipe[0]);
            throw Failure(Code::internal, std::format("cannot run {}: {}", argv[0], std::strerror(spawned)));
        }

        RunResult result;
        auto deadline = std::chrono::steady_clock::now() + options.timeout;
        pollfd fds[2] = {{out_pipe[0], POLLIN, 0}, {err_pipe[0], POLLIN, 0}};
        std::string* sinks[2] = {&result.out, &result.err};
        int open_count = 2;
        char buffer[4096];
        while (open_count > 0) {
            auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now());
            if (remaining.count() <= 0) {
                result.timed_out = true;
                ::kill(-pid, SIGKILL);
                break;
            }
            int ready = ::poll(fds, 2, static_cast<int>(std::min<long long>(remaining.count(), 1000)));
            if (ready < 0) {
                if (errno == EINTR) continue;
                ::kill(-pid, SIGKILL);
                break;
            }
            for (int i = 0; i < 2; ++i) {
                if (fds[i].fd < 0 || !(fds[i].revents & (POLLIN | POLLHUP | POLLERR))) continue;
                ssize_t n = ::read(fds[i].fd, buffer, sizeof buffer);
                if (n > 0) sinks[i]->append(buffer, static_cast<std::size_t>(n));
                else if (n == 0 || errno != EINTR) {
                    close_fd(fds[i].fd);
                    fds[i].fd = -1;
                    --open_count;
                }
            }
        }
        for (auto& fd: fds) close_fd(fd.fd);

        int status = 0;
        while (::waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
        result.status = decode_status(status);
        return result;
    }

    std::string display_command(const std::vector<std::string>& argv) {
        std::string line;
        for (const auto& arg: argv) {
            if (!line.empty()) line += ' ';
            bool plain = !arg.empty() && arg.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
                                                                "0123456789-_./=:@%+,") == std::string::npos;
            if (plain) {
                line += arg;
                continue;
            }
            line += '\'';
            for (char c: arg) line += c == '\'' ? std::string("'\\''") : std::string(1, c);
            line += '\'';
        }
        return line;
    }

}  // namespace forti::install
