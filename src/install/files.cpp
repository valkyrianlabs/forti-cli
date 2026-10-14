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
        std::error_code ec;
        if (!fs::exists(path, ec)) return std::nullopt;
        std::ifstream in(path, std::ios::binary);
        if (!in) throw Failure(Code::config, std::format("cannot read {}", path.string()));
        std::ostringstream content;
        content << in.rdbuf();
        if (in.bad()) throw Failure(Code::config, std::format("cannot read {}", path.string()));
        return std::move(content).str();
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
            fs::path candidate = fs::path(dir.empty() ? "." : std::string(dir)) / std::string(name);
            if (is_executable(candidate)) return fs::absolute(candidate).lexically_normal();
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
