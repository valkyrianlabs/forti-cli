#include "files.hpp"

#include <forti/engine/error.hpp>

#include <cerrno>
#include <climits>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <format>
#include <fstream>
#include <sstream>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif

namespace forti::install {

    using engine::Code;
    using engine::Failure;

    std::optional<std::string> read_file(const fs::path& path) {
        // O_NONBLOCK: opening a FIFO for reading would otherwise wait for a writer forever.
        int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK);
        if (fd < 0) {
            if (errno == ENOENT || errno == ENOTDIR) return std::nullopt;
            throw Failure(Code::config, std::format("cannot read {}: {}", path.string(), std::strerror(errno)));
        }
        struct Closer {
            int fd;
            ~Closer() { ::close(fd); }
        } closer{fd};
        struct stat info{};
        if (::fstat(fd, &info) != 0 || !S_ISREG(info.st_mode))
            throw Failure(Code::config, std::format("{} is not a regular file; forti will not read or replace it", path.string()));
        constexpr std::size_t limit = 64u << 20;
        if (static_cast<std::size_t>(info.st_size) > limit)
            throw Failure(Code::config, std::format("{} is larger than 64 MiB; forti will not edit it", path.string()));
        std::string content;
        char buffer[65536];
        for (ssize_t n; (n = ::read(fd, buffer, sizeof buffer)) != 0;) {
            if (n < 0) {
                if (errno == EINTR) continue;
                throw Failure(Code::config, std::format("cannot read {}: {}", path.string(), std::strerror(errno)));
            }
            content.append(buffer, static_cast<std::size_t>(n));
            if (content.size() > limit)
                throw Failure(Code::config, std::format("{} is larger than 64 MiB; forti will not edit it", path.string()));
        }
        return content;
    }

    void require_inside(const fs::path& path, const fs::path& root) {
        auto relative = path.lexically_normal().lexically_relative(root.lexically_normal());
        if (relative.empty() || *relative.begin() == ".." || relative.is_absolute())
            throw Failure(Code::config, std::format("{} is outside {}", path.string(), root.string()));
        fs::path at = root;
        std::size_t parts = static_cast<std::size_t>(std::distance(relative.begin(), relative.end()));
        std::size_t index = 0;
        for (const auto& part: relative) {
            at /= part;
            bool last = ++index == parts;
            struct stat info{};
            if (::lstat(at.c_str(), &info) != 0) {
                if (errno == ENOENT) return;   // the rest is created by forti, inside root
                throw Failure(Code::config, std::format("cannot check {}: {}", at.string(), std::strerror(errno)));
            }
            if (S_ISLNK(info.st_mode))
                throw Failure(Code::config, std::format("{} is a symbolic link; forti does not follow links out of the "
                                                        "project for a project-scope change (remove it, or edit by hand)",
                                                        at.string()));
            if (last ? !S_ISREG(info.st_mode) : !S_ISDIR(info.st_mode))
                throw Failure(Code::config, std::format("{} is not a regular {}", at.string(), last ? "file" : "directory"));
        }
    }

    void write_file_atomic(const fs::path& requested, std::string_view content, mode_t mode) {
        std::error_code ec;
        fs::path path = requested;
        if (fs::symlink_status(path, ec).type() == fs::file_type::symlink) {
            path = fs::canonical(path, ec);
            if (ec) throw Failure(Code::config, std::format("cannot resolve {}: {}", requested.string(), ec.message()));
        }
        ec.clear();

        fs::create_directories(path.parent_path(), ec);
        if (ec) throw Failure(Code::config, std::format("cannot create {}: {}", path.parent_path().string(), ec.message()));

        struct stat existing{};
        if (::stat(path.c_str(), &existing) == 0) mode = existing.st_mode & 07777;

        std::string pattern = (path.parent_path() / ("." + path.filename().string() + ".forti-XXXXXX")).string();
        std::vector<char> name(pattern.begin(), pattern.end());
        name.push_back('\0');
        int fd = ::mkstemp(name.data());
        if (fd < 0) throw Failure(Code::config, std::format("cannot write {}: {}", path.string(), std::strerror(errno)));
        auto fail = [&](const char* what) {
            int saved = errno;
            ::close(fd);
            ::unlink(name.data());
            throw Failure(Code::config, std::format("cannot write {} ({}): {}", path.string(), what, std::strerror(saved)));
        };
        std::size_t written = 0;
        while (written < content.size()) {
            ssize_t n = ::write(fd, content.data() + written, content.size() - written);
            if (n < 0) {
                if (errno == EINTR) continue;
                fail("write");
            }
            written += static_cast<std::size_t>(n);
        }
        if (::fchmod(fd, mode) != 0) fail("chmod");
        if (::fsync(fd) != 0) fail("fsync");
        if (::close(fd) != 0) {
            int saved = errno;
            ::unlink(name.data());
            throw Failure(Code::config, std::format("cannot write {}: {}", path.string(), std::strerror(saved)));
        }
        if (::rename(name.data(), path.c_str()) != 0) {
            int saved = errno;
            ::unlink(name.data());
            throw Failure(Code::config, std::format("cannot replace {}: {}", path.string(), std::strerror(saved)));
        }
    }

    void remove_file(const fs::path& path, const fs::path& stop) {
        std::error_code ec;
        fs::remove(path, ec);
        if (ec) throw Failure(Code::config, std::format("cannot remove {}: {}", path.string(), ec.message()));
        if (stop.empty()) return;
        auto limit = stop.lexically_normal();
        for (auto dir = path.parent_path().lexically_normal(); dir != limit && dir.has_relative_path();
             dir = dir.parent_path()) {
            auto relative = dir.lexically_relative(limit);
            if (relative.empty() || *relative.begin() == "..") break;   // never climb above `stop`
            if (!fs::is_directory(dir, ec) || !fs::is_empty(dir, ec)) break;
            fs::remove(dir, ec);
            if (ec) break;
        }
    }

    bool is_executable(const fs::path& path) {
        std::error_code ec;
        return fs::is_regular_file(path, ec) && ::access(path.c_str(), X_OK) == 0;
    }

    std::optional<fs::path> find_executable(std::string_view name) {
        if (name.find('/') != std::string_view::npos) {
            fs::path path(name);
            return is_executable(path) ? std::optional(fs::absolute(path).lexically_normal()) : std::nullopt;
        }
        std::string_view search = std::getenv("PATH") ? std::getenv("PATH") : "/usr/bin:/bin";
        while (true) {
            auto colon = search.find(':');
            std::string_view dir = search.substr(0, colon);
            // Empty and relative entries mean the working directory: a project directory could then
            // supply its own `forti-mcp`, `claude` or `codex`. Only absolute entries are searched.
            fs::path candidate = fs::path(std::string(dir)) / std::string(name);
            if (fs::path(std::string(dir)).is_absolute() && is_executable(candidate)) return candidate.lexically_normal();
            if (colon == std::string_view::npos) break;
            search.remove_prefix(colon + 1);
        }
        return std::nullopt;
    }

    std::optional<fs::path> self_executable() {
#ifdef __APPLE__
        std::uint32_t size = 0;
        _NSGetExecutablePath(nullptr, &size);
        std::vector<char> buffer(size + 1, '\0');
        if (_NSGetExecutablePath(buffer.data(), &size) != 0) return std::nullopt;
        return fs::absolute(fs::path(buffer.data())).lexically_normal();
#else
        std::error_code ec;
        auto path = fs::read_symlink("/proc/self/exe", ec);
        if (ec) return std::nullopt;
        return path;
#endif
    }

    std::optional<std::string> env(const char* name) {
        const char* value = std::getenv(name);
        if (!value || !*value) return std::nullopt;
        return std::string(value);
    }

    fs::path canonical_or_absolute(const fs::path& path) {
        std::error_code ec;
        auto canonical = fs::canonical(path, ec);
        if (!ec) return canonical;
        return fs::absolute(path).lexically_normal();
    }

}  // namespace forti::install
