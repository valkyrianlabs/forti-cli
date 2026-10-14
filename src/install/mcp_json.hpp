//
// Claude Code's project-scope `.mcp.json` ({"mcpServers": {"<name>": {...}}}), edited directly
// because the claude CLI rewrites the whole file and drops keys it does not know (`$schema`).
// nlohmann::ordered_json keeps every other server and every key in its original order.
//

#ifndef FORTI_INSTALL_MCP_JSON_HPP
#define FORTI_INSTALL_MCP_JSON_HPP

#include "client.hpp"

#include <nlohmann/json.hpp>

#include <optional>
#include <string>
#include <string_view>

namespace forti::install::mcp_json {

    using Document = nlohmann::ordered_json;

    // Empty text is an empty document. Throws Failure(config) for invalid JSON, a non-object top
    // level, or an `mcpServers` that is not an object: forti never overwrites a file it cannot read.
    Document parse(std::string_view text, std::string_view origin);

    // The entry stored under `name` in an mcpServers object (also used for ~/.claude.json).
    std::optional<Entry> find(const nlohmann::ordered_json& servers, std::string_view name);
    std::optional<Entry> find_server(const Document& document, std::string_view name);

    // Adds or replaces mcpServers[name] (keeping its position) with {"type":"stdio", command, args}.
    void upsert(Document& document, std::string_view name, const Entry& entry);

    // Removes mcpServers[name]; false when it was not there.
    bool remove(Document& document, std::string_view name);

    // Nothing left but an empty mcpServers (the file can be deleted).
    bool is_empty(const Document& document);

    // The indent of the original file (2 when unknown, like the claude CLI) and a trailing newline.
    std::string dump(const Document& document, std::string_view original);

}  // namespace forti::install::mcp_json

#endif  // FORTI_INSTALL_MCP_JSON_HPP
