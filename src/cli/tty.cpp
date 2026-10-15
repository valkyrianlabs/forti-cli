#include "tty.hpp"

#include <forti/engine/error.hpp>

#include <cerrno>
#include <charconv>
#include <csignal>
#include <format>

#include <fcntl.h>
#include <signal.h>
#include <termios.h>
#include <unistd.h>

namespace forti::cli {

    using engine::Code;
    using engine::Failure;

    namespace {

        termios saved_termios{};
        volatile std::sig_atomic_t echo_disabled_fd = -1;

        // Restores echo if the user interrupts a hidden prompt, then dies of the same signal.
        extern "C" void restore_echo(int signal) {
            if (echo_disabled_fd >= 0) ::tcsetattr(echo_disabled_fd, TCSANOW, &saved_termios);
            std::signal(signal, SIG_DFL);
            std::raise(signal);
        }

    }  // namespace

    // Reads one line from `fd`, with echo off when `hidden`. nullopt at end of input.
    std::optional<std::string> read_line(int fd, bool hidden) {
        bool restore = false;
        struct sigaction old_int{}, old_term{}, old_hup{};
        if (hidden && ::isatty(fd) && ::tcgetattr(fd, &saved_termios) == 0) {
            struct sigaction action{};
            action.sa_handler = restore_echo;
            ::sigaction(SIGINT, &action, &old_int);
            ::sigaction(SIGTERM, &action, &old_term);
            ::sigaction(SIGHUP, &action, &old_hup);
            termios quiet = saved_termios;
            quiet.c_lflag &= ~static_cast<tcflag_t>(ECHO);
            quiet.c_lflag |= ECHONL;
            echo_disabled_fd = fd;
            restore = ::tcsetattr(fd, TCSAFLUSH, &quiet) == 0;
        }
        std::string line;
        bool got = false;
        for (char c; ;) {
            ssize_t n = ::read(fd, &c, 1);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) break;
            got = true;
            if (c == '\n') break;
            if (line.size() < 65536) line += c;
        }
        if (restore) {
            ::tcsetattr(fd, TCSAFLUSH, &saved_termios);
            echo_disabled_fd = -1;
            ::sigaction(SIGINT, &old_int, nullptr);
            ::sigaction(SIGTERM, &old_term, nullptr);
            ::sigaction(SIGHUP, &old_hup, nullptr);
        }
        if (!got) return std::nullopt;
        if (!line.empty() && line.back() == '\r') line.pop_back();
        return line;
    }

    std::string trim(std::string text) {
        auto first = text.find_first_not_of(" \t\r\n");
        if (first == std::string::npos) return "";
        auto last = text.find_last_not_of(" \t\r\n");
        return text.substr(first, last - first + 1);
    }


    Tty::Tty() : fd_(::open("/dev/tty", O_RDWR | O_CLOEXEC | O_NOCTTY)) {}

    Tty::~Tty() {
        if (fd_ >= 0) ::close(fd_);
    }

    void Tty::say(std::string_view text) const {
        while (!text.empty()) {
            ssize_t n = ::write(fd_, text.data(), text.size());
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) return;
            text.remove_prefix(static_cast<std::size_t>(n));
        }
    }

    std::string Tty::ask(std::string_view label, std::string_view fallback, bool hidden) const {
        say(fallback.empty() ? std::format("{}: ", label) : std::format("{} [{}]: ", label, fallback));
        auto line = read_line(fd_, hidden);
        if (!line) throw Failure(Code::usage, "input ended: cancelled");
        std::string answer = trim(*line);
        return answer.empty() ? std::string(fallback) : answer;
    }

    bool Tty::confirm(std::string_view label, bool fallback) const {
        for (;;) {
            std::string answer = ask(std::format("{} ({})", label, fallback ? "Y/n" : "y/N"));
            if (answer.empty()) return fallback;
            if (answer == "y" || answer == "Y" || answer == "yes") return true;
            if (answer == "n" || answer == "N" || answer == "no") return false;
        }
    }

    std::size_t Tty::choose(std::string_view question, const std::vector<std::string>& options, std::size_t fallback) const {
        say(std::format("{}\n", question));
        for (std::size_t k = 0; k < options.size(); ++k) say(std::format("  {}) {}\n", k + 1, options[k]));
        for (;;) {
            std::string answer = ask("choice", std::to_string(fallback + 1));
            std::size_t value = 0;
            auto [end, ec] = std::from_chars(answer.data(), answer.data() + answer.size(), value);
            if (ec == std::errc() && end == answer.data() + answer.size() && value >= 1 && value <= options.size())
                return value - 1;
        }
    }

}  // namespace forti::cli
