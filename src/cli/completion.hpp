//
// Shell completion. `forti completion bash|zsh|fish` prints a script (completions/ in the source
// tree, embedded at build time); the scripts ask the hidden `forti __complete` for candidates.
//

#ifndef FORTI_CLI_COMPLETION_HPP
#define FORTI_CLI_COMPLETION_HPP

#include "output.hpp"

#include <forti/engine/engine.hpp>

#include <span>
#include <string>

namespace forti::cli {

    // `forti __complete WHAT [ARG] [PREFIX]`: candidates on `output.out`, one per line, those starting
    // with PREFIX. WHAT is commands | subcommands CMD | options CMD | valued CMD (the options that take
    // a value, short forms included) | profiles | modes | plans | resources. Runs on every Tab, so it
    // is fast and quiet: it never contacts a device, resolves a secret or loads the full configuration
    // (profile names only), and on any problem prints nothing and returns 0. Not a command-table entry,
    // so it is in neither `forti --help` nor the command suggestions.
    int complete(std::span<const std::string> arguments, const Output& output, const engine::Options& options);

}  // namespace forti::cli

#endif  // FORTI_CLI_COMPLETION_HPP
