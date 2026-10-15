//
// Interactive prompts on the controlling terminal (/dev/tty), never on stdin/stdout: commands keep
// working with redirected streams, and a secret typed at a prompt never lands in a pipe.
//

#ifndef FORTI_CLI_TTY_HPP
#define FORTI_CLI_TTY_HPP

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace forti::cli {

    // Reads one line from `fd`, with echo off when `hidden` (restored even if the user interrupts).
    // nullopt at end of input.
    std::optional<std::string> read_line(int fd, bool hidden);

    std::string trim(std::string text);

    class Tty {
        int fd_ = -1;

    public:
        Tty();
        ~Tty();
        Tty(const Tty&) = delete;
        Tty& operator=(const Tty&) = delete;

        // False without a controlling terminal (CI, a service, an agent's shell tool).
        [[nodiscard]] bool available() const { return fd_ >= 0; }

        void say(std::string_view text) const;
        // "label [fallback]: "; an empty answer returns `fallback`. Throws Failure(usage) at end of input.
        std::string ask(std::string_view label, std::string_view fallback = {}, bool hidden = false) const;
        bool confirm(std::string_view label, bool fallback) const;
        // Numbered options; returns the chosen index (`fallback` on an empty answer).
        std::size_t choose(std::string_view question, const std::vector<std::string>& options, std::size_t fallback) const;
    };

}  // namespace forti::cli

#endif  // FORTI_CLI_TTY_HPP
