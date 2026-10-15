//
// The command table. Each command declares its options (merged with the global ones) and a run
// function that turns arguments into an engine request and emits the result.
//

#ifndef FORTI_CLI_COMMANDS_HPP
#define FORTI_CLI_COMMANDS_HPP

#include "args.hpp"
#include "output.hpp"

#include <forti/engine/engine.hpp>

#include <functional>
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

    // Commands under a heading in `forti --help`.
    struct CommandGroup {
        std::string_view title;
        std::vector<Command> commands;
    };

    // Every command, grouped and in help order. Assembled from one function per workstream so each
    // command group lives in its own file.
    const std::vector<CommandGroup>& command_groups();
    const std::vector<Command>& commands();   // the groups, flattened

    std::vector<Command> setup_commands();     // commands_setup.cpp: configure, doctor, profiles (+ home, cert)
    std::vector<Command> home_commands();      // commands_home.cpp: home, home migrate
    std::vector<Command> cert_commands();      // commands_cert.cpp: cert create|show|remove
    std::vector<Command> read_commands();      // commands_read.cpp: devices, discover, get
    std::vector<Command> plan_commands();      // commands_plan.cpp: plan, apply
    std::vector<Command> install_commands();   // commands_install.cpp: install, mcp

    // Runs an engine operation and emits its envelope (text or --json); returns the exit status.
    int run_engine(Context& context, const std::function<nlohmann::json()>& operation, const Renderer& render = {});

    // Integer option value; throws Failure(usage).
    std::size_t to_count(std::string_view name, const std::string& text);

}  // namespace forti::cli

#endif  // FORTI_CLI_COMMANDS_HPP
