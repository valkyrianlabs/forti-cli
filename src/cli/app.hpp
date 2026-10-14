//
// The `forti` front door: global options, `--help` / `--version`, command lookup and dispatch. Kept
// out of main.cpp so tests can drive the whole CLI with their own streams and engine options.
//

#ifndef FORTI_CLI_APP_HPP
#define FORTI_CLI_APP_HPP

#include "output.hpp"

#include <forti/engine/engine.hpp>

#include <string>
#include <vector>

namespace forti::cli {

    // Runs `forti <arguments…>` and returns the exit status. `options` configures the Engine the
    // command runs against (tests inject paths, a memory secret store and a fake transport).
    int run(const std::vector<std::string>& arguments, Output output, engine::Options options = {});

    // `forti --help`.
    std::string usage_text();

}  // namespace forti::cli

#endif  // FORTI_CLI_APP_HPP
