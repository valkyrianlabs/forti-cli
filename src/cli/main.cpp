//
// forti: the FortiOS command-line interface (forti-cli). Dispatch is in app.cpp, commands in the
// commands_*.cpp files; FortiOS operations go through forti::engine and forti-api, never anything else.
//

#include "app.hpp"

#include <forti/engine/error.hpp>

#include <cstdlib>
#include <iostream>

#include <sys/resource.h>

int main(int argc, char** argv) {
    using namespace forti;
    // No core dumps: the process holds API keys and device secrets in memory.
    struct rlimit no_core{0, 0};
    ::setrlimit(RLIMIT_CORE, &no_core);
    std::vector<std::string> arguments(argv + 1, argv + argc);
    cli::Output output = cli::terminal_output();
    try {
        engine::Options options;
        const char* user = std::getenv("USER");
        options.actor = std::string("cli:") + (user && *user ? user : "unknown");   // recorded in the audit log
        return cli::run(arguments, output, std::move(options));
    } catch (...) {   // Options{} resolves directories from the environment (HOME unset, …)
        auto failure = engine::translate(std::current_exception());
        return cli::emit(output, {{"ok", false}, {"error", failure.to_json()}});
    }
}
