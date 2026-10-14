//
// forti: the FortiOS command-line interface (forti-cli). Commands live in commands.cpp; FortiOS
// operations go through forti::engine and forti-api, never anything else.
//

#include "commands.hpp"

#include <forti/engine/engine.hpp>

#include <cstdlib>
#include <format>
#include <iostream>

#ifndef FORTI_VERSION
#define FORTI_VERSION "0.0.0"
#endif

namespace {

    using namespace forti;

    void usage(std::ostream& out) {
        out << "forti " FORTI_VERSION ": FortiOS from the command line\n\n"
               "usage: forti [--profile NAME] [--vdom NAME] [--json] <command> [args]\n\ncommands:\n";
        for (const auto& command: cli::commands()) out << std::format("  {:<12} {}\n", command.name, command.summary);
        out << "\nRun `forti <command> --help` for details. Output is text; --json prints the result envelope.\n";
    }

    cli::OptionSpec merged(const cli::OptionSpec& own) {
        auto spec = cli::global_options();
        spec.valued.insert(own.valued.begin(), own.valued.end());
        spec.flags.insert(own.flags.begin(), own.flags.end());
        spec.short_names.insert(own.short_names.begin(), own.short_names.end());
        return spec;
    }

}  // namespace

int main(int argc, char** argv) {
    std::vector<std::string> arguments(argv + 1, argv + argc);
    cli::Output output{std::getenv("FORTI_OUTPUT") && std::string_view(std::getenv("FORTI_OUTPUT")) == "json"
                               ? cli::Format::json : cli::Format::text,
                       &std::cout, &std::cerr};

    // The command is the first positional argument; global options may come before or after it.
    std::size_t command_at = 0;
    auto globals = cli::global_options();
    while (command_at < arguments.size() && arguments[command_at].starts_with('-')) {
        const auto& arg = arguments[command_at];
        if (arg == "--version") {
            std::cout << "forti " FORTI_VERSION << " (forti-api schema " << engine::sdk_schema_version << ")\n";
            return 0;
        }
        std::string name = arg.starts_with("--") ? arg.substr(2, arg.find('=') - 2) : "";
        if (arg == "-p") name = "profile";
        bool takes_value = globals.valued.contains(name) && arg.find('=') == std::string::npos;
        command_at += takes_value ? 2 : 1;
    }
    if (command_at >= arguments.size()) {
        bool help = std::ranges::find(arguments, "--help") != arguments.end() || std::ranges::find(arguments, "-h") != arguments.end();
        usage(help ? std::cout : std::cerr);
        return help ? 0 : 2;
    }
    std::string name = arguments[command_at];
    if (name == "help") {
        usage(std::cout);
        return 0;
    }
    const auto& table = cli::commands();
    auto command = std::ranges::find(table, name, &cli::Command::name);
    if (command == table.end()) {
        std::cerr << "forti: unknown command \"" << name << "\" (run `forti --help`)\n";
        return 2;
    }

    std::vector<std::string> rest(arguments.begin(), arguments.begin() + static_cast<std::ptrdiff_t>(command_at));
    rest.insert(rest.end(), arguments.begin() + static_cast<std::ptrdiff_t>(command_at) + 1, arguments.end());
    try {
        auto args = cli::parse(rest, merged(command->options));
        if (args.flag("help")) {
            std::cout << command->help << "\n";
            return 0;
        }
        if (args.flag("json")) output.format = cli::Format::json;
        engine::Engine engine;
        cli::Context context{engine, output};
        return command->run(context, args);
    } catch (...) {
        auto failure = engine::translate(std::current_exception());
        return cli::emit(output, {{"ok", false}, {"error", failure.to_json()}});
    }
}
