//
// Rendering engine envelopes: `--json` prints the envelope as is (stable, script-friendly); text mode
// renders data for people and errors to stderr. The exit status always follows the error code.
//

#ifndef FORTI_CLI_OUTPUT_HPP
#define FORTI_CLI_OUTPUT_HPP

#include <nlohmann/json.hpp>

#include <functional>
#include <iosfwd>

namespace forti::cli {

    enum class Format { text, json };

    struct Output {
        Format format = Format::text;
        std::ostream* out;
        std::ostream* err;
    };

    using Renderer = std::function<void(std::ostream&, const nlohmann::json& data, const nlohmann::json& meta)>;

    // Prints the envelope and returns the process exit status.
    int emit(const Output& output, const nlohmann::json& envelope, const Renderer& render = {});

    // Default text rendering: tables for arrays of objects, aligned key/value pairs for objects.
    void render_auto(std::ostream& out, const nlohmann::json& data, const nlohmann::json& meta);

}  // namespace forti::cli

#endif  // FORTI_CLI_OUTPUT_HPP
