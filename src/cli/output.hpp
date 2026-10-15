//
// Rendering engine envelopes: `--json` prints the envelope as is (stable, script-friendly); text mode
// renders data for people on stdout and errors (with hints) on stderr. The exit status always follows
// the error code (architecture.md, "Error codes and CLI exit codes").
//

#ifndef FORTI_CLI_OUTPUT_HPP
#define FORTI_CLI_OUTPUT_HPP

#include <nlohmann/json.hpp>

#include <cstddef>
#include <functional>
#include <iosfwd>
#include <string>
#include <string_view>
#include <vector>

namespace forti::cli {

    enum class Format { text, json };

    struct Output {
        Format format = Format::text;
        std::ostream* out;
        std::ostream* err;
        std::istream* in = nullptr;   // --api-key-stdin; null: std::cin
        bool color = false;           // ANSI styles on `out` (a TTY, NO_COLOR unset)
        bool err_color = false;       // ANSI styles on `err`
        std::size_t width = 0;        // terminal columns for tables; 0: no limit (not a TTY)
        bool tty = false;             // stdout is a terminal (`forti get --reveal` needs one, or --json)
    };

    // Decides format, color and width from the environment (FORTI_OUTPUT, NO_COLOR, isatty, COLUMNS).
    Output terminal_output();

    using Renderer = std::function<void(std::ostream&, const nlohmann::json& data, const nlohmann::json& meta)>;

    // Prints the envelope and returns the process exit status.
    int emit(const Output& output, const nlohmann::json& envelope, const Renderer& render = {});

    // Exit status for an error code string ("not_found" → 5); unknown codes map to internal (1).
    int exit_status(std::string_view code);

    // Default text rendering: tables for arrays of objects, aligned key/value pairs for objects.
    void render_auto(std::ostream& out, const nlohmann::json& data, const nlohmann::json& meta);

    // render_auto with columns in this order after the identifying one (`forti get --fields a,b`).
    Renderer table_renderer(std::vector<std::string> columns);

    // Profile list (`forti devices`, `forti profile list`): name first, the default marked.
    void render_profiles(std::ostream& out, const nlohmann::json& data, const nlohmann::json& meta);

    // Text styles for renderers. They apply only while emit() renders to a color-capable stream, so
    // a renderer can call them unconditionally.
    enum class Style { bold, dim, red, green, yellow, cyan };
    std::string styled(std::string_view text, Style style);

    // Rows → aligned columns. `columns` in display order; cells clipped so the table fits the
    // terminal width (when known). Used by render_auto; available to other renderers.
    void print_table(std::ostream& out, const std::vector<std::string>& columns,
                     const std::vector<std::vector<std::string>>& rows);

    // Display width of UTF-8 text (code points; good enough for names and addresses).
    std::size_t display_width(std::string_view text);

    // Text safe to print on a terminal. Device data (names, comments) and plan values (chosen by
    // whoever made the plan, possibly an agent) must not be able to move the cursor, erase or recolor
    // lines, retitle the window, or reorder text: C0 and C1 controls, DEL, line separators and Unicode
    // bidirectional controls become visible escapes (\n, \x1b, \u202e). `keep_newlines` keeps '\n'
    // (forti's own multi-line hints).
    std::string printable(std::string_view text, bool keep_newlines = false);
    // A copy with every string and object key passed through printable().
    nlohmann::json printable_json(const nlohmann::json& value);

}  // namespace forti::cli

#endif  // FORTI_CLI_OUTPUT_HPP
