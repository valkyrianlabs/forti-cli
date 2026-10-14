#include <forti/engine/error.hpp>
#include <forti/engine/profile.hpp>

#include <cerrno>
#include <cstdlib>
#include <format>
#include <fstream>
#include <map>
#include <sstream>

#include <fcntl.h>
#include <spawn.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

extern char** environ;

namespace forti::engine {

    namespace fs = std::filesystem;

    namespace {

        std::string trim_line(std::string text) {
            if (auto end = text.find_first_of("\r\n"); end != std::string::npos) text.resize(end);
            return text;
        }

        class FileSecretStore final : public SecretStore {
            fs::path dir_;

            fs::path file(std::string_view account) const {
                std::string name(account);
                for (char& c: name) if (c == '/') c = '.';
                return dir_ / name;
            }

        public:
            explicit FileSecretStore(fs::path dir) : dir_(std::move(dir)) {}

            std::string_view kind() const override { return "file"; }

            std::optional<std::string> get(std::string_view account) override {
                auto path = file(account);
                struct stat info{};
                if (::lstat(path.c_str(), &info) != 0) return std::nullopt;
                if (!S_ISREG(info.st_mode))
                    throw Failure(Code::config, std::format("{} is not a regular file", path.string()));
                if (info.st_mode & (S_IRWXG | S_IRWXO))
                    throw Failure(Code::config, std::format("{} is readable by other users; run chmod 600 on it",
                                                            path.string()));
                std::ifstream in(path);
                std::stringstream text;
                text << in.rdbuf();
                return trim_line(text.str());
            }

            void put(std::string_view account, std::string_view secret) override {
                ensure_private_dir(dir_);
                write_private_file(file(account), std::string(secret) + "\n");
            }

            bool erase(std::string_view account) override {
                std::error_code error;
                return fs::remove(file(account), error);
            }
        };

        class MemorySecretStore final : public SecretStore {
            std::map<std::string, std::string, std::less<>> secrets_;

        public:
            std::string_view kind() const override { return "memory"; }

            std::optional<std::string> get(std::string_view account) override {
                auto it = secrets_.find(account);
                return it == secrets_.end() ? std::nullopt : std::optional(it->second);
            }

            void put(std::string_view account, std::string_view secret) override {
                secrets_.insert_or_assign(std::string(account), std::string(secret));
            }

            bool erase(std::string_view account) override {
                auto it = secrets_.find(account);
                if (it == secrets_.end()) return false;
                secrets_.erase(it);
                return true;
            }
        };

        // Runs argv (no shell) and returns the first line of stdout. stderr is inherited so helper
        // prompts (e.g. a password manager unlock) reach the user.
        std::string run_command(const std::vector<std::string>& argv, std::string_view account) {
            int pipe_fds[2];
            if (::pipe(pipe_fds) != 0) throw Failure(Code::config, "cannot create a pipe for the credential command");
            posix_spawn_file_actions_t actions;
            posix_spawn_file_actions_init(&actions);
            posix_spawn_file_actions_adddup2(&actions, pipe_fds[1], STDOUT_FILENO);
            posix_spawn_file_actions_addclose(&actions, pipe_fds[0]);
            posix_spawn_file_actions_addclose(&actions, pipe_fds[1]);
            std::vector<char*> args;
            for (const auto& arg: argv) args.push_back(const_cast<char*>(arg.c_str()));
            args.push_back(nullptr);
            pid_t pid = 0;
            int spawned = ::posix_spawnp(&pid, args[0], &actions, nullptr, args.data(), environ);
            posix_spawn_file_actions_destroy(&actions);
            ::close(pipe_fds[1]);
            if (spawned != 0) {
                ::close(pipe_fds[0]);
                throw Failure(Code::config, std::format("credential command for {} could not start: {}", account, argv[0]));
            }
            std::string output;
            char buffer[4096];
            for (ssize_t n; (n = ::read(pipe_fds[0], buffer, sizeof buffer)) != 0;) {
                if (n < 0 && errno == EINTR) continue;
                if (n < 0 || output.size() > 65536) break;
                output.append(buffer, static_cast<std::size_t>(n));
            }
            ::close(pipe_fds[0]);
            int status = 0;
            while (::waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
            if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
                throw Failure(Code::config, std::format("credential command for {} failed", account));
            return trim_line(std::move(output));
        }

    }  // namespace

    std::shared_ptr<SecretStore> file_secret_store(const Paths& paths) {
        return std::make_shared<FileSecretStore>(paths.config / "credentials");
    }

    std::shared_ptr<SecretStore> memory_secret_store() { return std::make_shared<MemorySecretStore>(); }

#ifndef __APPLE__
    std::shared_ptr<SecretStore> keychain_secret_store(std::string) {
        throw Failure(Code::config, "the macOS Keychain is not available on this platform",
                      {{"hint", "unset FORTI_SECRET_STORE (the 0600 file store is the default here)"}});
    }
#endif

    // FORTI_SECRET_STORE=file|keychain overrides the platform default, e.g. on a Mac reached over SSH
    // where the login keychain is locked. Linux uses the file store; libsecret (Secret Service) is a
    // possible later backend, deferred because it adds a runtime dependency and needs a session bus.
    std::shared_ptr<SecretStore> default_secret_store(const Paths& paths) {
        const char* choice = std::getenv("FORTI_SECRET_STORE");
        std::string_view name = choice ? choice : "";
        if (name == "file") return file_secret_store(paths);
        if (name == "keychain") return keychain_secret_store();
        if (!name.empty())
            throw Failure(Code::config, std::format("FORTI_SECRET_STORE must be \"file\" or \"keychain\", not \"{}\"", name));
#ifdef __APPLE__
        return keychain_secret_store();
#else
        return file_secret_store(paths);
#endif
    }

    std::string resolve_secret(const SecretRef& ref, std::string_view account, SecretStore& store) {
        std::string secret;
        switch (ref.source) {
            case SecretRef::Source::none:
                throw Failure(Code::config, std::format("no credential is configured for {}", account));
            case SecretRef::Source::store:
                if (auto stored = store.get(account)) secret = std::move(*stored);
                else throw Failure(Code::config, std::format("no secret stored for {} in the {} store (run `forti configure`)",
                                                             account, store.kind()));
                break;
            case SecretRef::Source::env:
                if (const char* value = std::getenv(ref.env.c_str())) secret = value;
                if (secret.empty())
                    throw Failure(Code::config, std::format("environment variable {} (credential for {}) is not set",
                                                            ref.env, account));
                break;
            case SecretRef::Source::command:
                secret = run_command(ref.command, account);
                break;
        }
        if (secret.empty()) throw Failure(Code::config, std::format("the credential for {} is empty", account));
        return secret;
    }

}  // namespace forti::engine
