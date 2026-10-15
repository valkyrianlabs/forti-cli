//
// Format-preserving edits of one TOML table, for Codex's config.toml: `[mcp_servers.forti]` in a
// project's `.codex/config.toml`. Not a TOML library (decision 8: no TOML dependency). A scanner
// follows just enough syntax (strings of all four kinds, multi-line arrays, inline tables, comments)
// to find table headers and key/value lines reliably; everything outside the one table block is
// copied byte for byte. A table forti cannot treat as a block (defined through dotted keys, an
// inline table, or split across the file) is refused, never rewritten.
//

#ifndef FORTI_INSTALL_TOML_TABLE_HPP
#define FORTI_INSTALL_TOML_TABLE_HPP

#include "client.hpp"

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace forti::install::toml {

    using Path = std::vector<std::string>;

    struct Header {
        Path path;
        bool array = false;    // [[array.of.tables]]
        std::size_t begin = 0; // the header line, [begin, end) including its newline
        std::size_t end = 0;
    };

    struct KeyValue {
        Path table;            // the table the line sits in ({} at the top)
        Path key;              // the (possibly dotted) key
        std::size_t begin = 0; // start of the line
        std::string_view value;
    };

    struct Document {
        std::vector<Header> headers;
        std::vector<KeyValue> values;
        std::vector<std::size_t> trivia;   // starts of blank and comment-only lines
    };

    // Throws Failure(config) with a line number on syntax it cannot follow.
    Document scan(std::string_view text);

    // The byte range of table `path` and its sub-tables, without the blank and comment lines that
    // precede the next table (those belong to it). nullopt when absent.
    struct Block {
        std::size_t begin = 0;
        std::size_t end = 0;
    };
    std::optional<Block> find_table(std::string_view text, const Path& path);

    // Replaces the table block with `block` (which ends in a newline), or appends it after a blank line.
    std::string set_table(std::string_view text, const Path& path, std::string_view block);

    // Removes the table block and the blank line forti added before it; unchanged when absent.
    std::string remove_table(std::string_view text, const Path& path);

    // A top-level `key = value` line (before any table header): [begin, end) including its newline,
    // and the raw value. nullopt when absent; a dotted key that starts with `key` is refused.
    struct Line {
        std::size_t begin = 0;
        std::size_t end = 0;
        std::string_view value;
    };
    std::optional<Line> find_top_level(std::string_view text, std::string_view key);

    // Inserts `line` (ending in a newline) after the last top-level key, else at the very start (with
    // a blank line before what follows).
    std::string insert_top_level(std::string_view text, std::string_view line);

    // Removes the line and the blank line insert_top_level added; unchanged when absent.
    std::string remove_top_level(std::string_view text, std::string_view key);

    // ---- Codex specifics ----

    // [mcp_servers.<name>] as an Entry (command, args; anything else sets `extra`).
    std::optional<Entry> read_server(std::string_view text, std::string_view name);

    // "[mcp_servers.<name>]\ncommand = \"...\"\nargs = [...]\n" (args omitted when empty, like `codex mcp add`).
    std::string render_server(std::string_view name, const Entry& entry);

    // `[projects."<dir>"] trust_level = "trusted"` in the global config.
    bool project_trusted(std::string_view global_config, const std::string& project_dir);

    // Single-line basic or literal string; nullopt for anything else.
    std::optional<std::string> parse_string(std::string_view value);
    std::optional<std::vector<std::string>> parse_string_array(std::string_view value);
    std::string quote(std::string_view text);

}  // namespace forti::install::toml

#endif  // FORTI_INSTALL_TOML_TABLE_HPP
