//
// forti: the FortiOS command-line interface (forti-cli). Dispatch is in app.cpp, commands in the
// commands_*.cpp files; FortiOS operations go through forti::engine and forti-api, never anything else.
//

#include "app.hpp"

#include <forti/engine/error.hpp>

#include <iostream>

int main(int argc, char** argv) {
    using namespace forti;
    std::vector<std::string> arguments(argv + 1, argv + argc);
    cli::Output output = cli::terminal_output();
    try {
        return cli::run(arguments, output, engine::Options{});
    } catch (...) {   // Options{} resolves directories from the environment (HOME unset, …)
        auto failure = engine::translate(std::current_exception());
        return cli::emit(output, {{"ok", false}, {"error", failure.to_json()}});
    }
}
