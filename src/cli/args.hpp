//
// Command-line parsing: positionals, `--name value` / `--name=value` options (repeatable) and boolean
// flags. Each command declares the options it accepts, so an unknown option is a usage error.
//

#ifndef FORTI_CLI_ARGS_HPP
#define FORTI_CLI_ARGS_HPP

#include <map>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace forti::cli {

    struct OptionSpec {
        std::set<std::string, std::less<>> valued;    // take a value: --profile home
        std::set<std::string, std::less<>> flags;     // booleans: --json
        std::map<char, std::string> short_names;      // -p → profile
    };

    class Args {
    public:
        std::vector<std::string> positional;
        std::map<std::string, std::vector<std::string>, std::less<>> values;
        std::set<std::string, std::less<>> flags;

        [[nodiscard]] bool flag(std::string_view name) const { return flags.contains(name); }
        [[nodiscard]] std::optional<std::string> value(std::string_view name) const;   // last occurrence
        [[nodiscard]] std::vector<std::string> all(std::string_view name) const;
    };

    // Throws forti::engine::Failure(usage) for unknown options or missing values. "--" ends options.
    Args parse(std::span<const std::string> argv, const OptionSpec& spec);

    // Splits "a,b,c" (empty items dropped).
    std::vector<std::string> split_list(std::string_view text);

}  // namespace forti::cli

#endif  // FORTI_CLI_ARGS_HPP
