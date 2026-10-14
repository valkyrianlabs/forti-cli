#include "mcp_json.hpp"

#include <forti/engine/error.hpp>

#include <format>

namespace forti::install::mcp_json {

    using engine::Code;
    using engine::Failure;

    Document parse(std::string_view text, std::string_view origin) {
        if (text.find_first_not_of(" \t\r\n") == std::string_view::npos) return Document::object();
        Document document = Document::parse(text, nullptr, false);
        if (document.is_discarded())
            throw Failure(Code::config, std::format("{} is not valid JSON; fix it by hand, forti will not overwrite it", origin));
        if (!document.is_object()) throw Failure(Code::config, std::format("{}: expected a JSON object", origin));
        if (document.contains("mcpServers") && !document["mcpServers"].is_object())
            throw Failure(Code::config, std::format("{}: \"mcpServers\" is not an object", origin));
        return document;
    }

    std::optional<Entry> find(const nlohmann::ordered_json& servers, std::string_view name) {
        if (!servers.is_object()) return std::nullopt;
        auto it = servers.find(name);
        if (it == servers.end()) return std::nullopt;
        Entry entry;
        const auto& value = *it;
        if (!value.is_object()) {
            entry.extra = true;
            return entry;
        }
        for (auto field = value.begin(); field != value.end(); ++field) {
            const auto& key = field.key();
            if (key == "command" && field->is_string()) entry.command = field->get<std::string>();
            else if (key == "args" && field->is_array()) {
                for (const auto& arg: *field) {
                    if (arg.is_string()) entry.args.push_back(arg.get<std::string>());
                    else entry.extra = true;
                }
            } else if (key == "type" && field->is_string() && field->get<std::string>() == "stdio") {
            } else if (key == "env" && field->is_object() && field->empty()) {
                // `claude mcp add` writes "env": {}; it means nothing.
            } else entry.extra = true;
        }
        return entry;
    }

    std::optional<Entry> find_server(const Document& document, std::string_view name) {
        auto it = document.find("mcpServers");
        if (it == document.end()) return std::nullopt;
        return find(*it, name);
    }

    void upsert(Document& document, std::string_view name, const Entry& entry) {
        if (!document.contains("mcpServers")) document["mcpServers"] = Document::object();
        // forti-mcp needs no env: it reads its own profiles and secret store.
        Document value = {{"type", "stdio"}, {"command", entry.command}, {"args", entry.args}};
        document["mcpServers"][std::string(name)] = std::move(value);
    }

    bool remove(Document& document, std::string_view name) {
        auto it = document.find("mcpServers");
        if (it == document.end() || !it->is_object()) return false;
        return it->erase(std::string(name)) > 0;
    }

    bool is_empty(const Document& document) {
        for (auto it = document.begin(); it != document.end(); ++it)
            if (it.key() != "mcpServers" || !it->empty()) return false;
        return true;
    }

    std::string dump(const Document& document, std::string_view original) {
        int indent = 2;
        // The first indented line tells the file's style ("{\n    \"mcpServers\"" → 4).
        if (auto newline = original.find('\n'); newline != std::string_view::npos) {
            auto line = original.substr(newline + 1);
            auto spaces = line.find_first_not_of(' ');
            if (spaces != std::string_view::npos && spaces > 0 && spaces <= 8 && line[spaces] != '\n') indent = static_cast<int>(spaces);
        }
        return document.dump(indent, ' ', false) + "\n";
    }

}  // namespace forti::install::mcp_json
