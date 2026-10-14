//
// The command table. Each command declares its options (merged with the global ones) and a run
// function that turns arguments into an engine request and emits the result.
//

#ifndef FORTI_CLI_COMMANDS_HPP
#define FORTI_CLI_COMMANDS_HPP

#include "args.hpp"
#include "output.hpp"

#include <forti/engine/engine.hpp>

#include <string_view>
#include <vector>

namespace forti::cli {

    struct Context {
        engine::Engine& engine;
        Output output;
    };

    struct Command {
        std::string_view name;
        std::string_view summary;
        std::string_view help;   // usage and options, shown by `forti <name> --help`
        OptionSpec options;
        int (*run)(Context&, const Args&);
    };

    // Options every command accepts.
    OptionSpec global_options();

    const std::vector<Command>& commands();

    // Integer option value; throws Failure(usage).
    std::size_t to_count(std::string_view name, const std::string& text);

}  // namespace forti::cli

#endif  // FORTI_CLI_COMMANDS_HPP
