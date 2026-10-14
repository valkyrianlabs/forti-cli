#include "output.hpp"

#include <forti/engine/error.hpp>

#include <algorithm>
#include <format>
#include <map>
#include <ostream>

namespace forti::cli {

    namespace {

        std::string scalar(const nlohmann::json& value) {
            if (value.is_string()) return value.get<std::string>();
            if (value.is_null()) return "";
            if (value.is_array()) {
                // Member tables ([{"name": "a"}, {"name": "b"}]) read best as "a b".
                std::string joined;
                for (const auto& item: value) {
                    std::string text = item.is_object() && item.contains("name") ? scalar(item["name"]) : scalar(item);
                    joined += (joined.empty() ? "" : " ") + text;
                }
                return joined;
            }
            return value.dump();
        }

        std::string clip(std::string text, std::size_t width) {
            if (text.size() <= width) return text;
            return text.substr(0, width - 1) + "…";
        }

        void table(std::ostream& out, const nlohmann::json& rows) {
            // Columns: keys in first-seen order, scalar-ish only, at most 8.
            std::vector<std::string> columns;
            for (const auto& row: rows) {
                if (!row.is_object()) continue;
                for (auto it = row.begin(); it != row.end(); ++it) {
                    if (it.value().is_object()) continue;
                    if (std::ranges::find(columns, it.key()) == columns.end() && columns.size() < 8) columns.push_back(it.key());
                }
            }
            if (columns.empty()) {
                out << rows.dump(2) << "\n";
                return;
            }
            std::vector<std::size_t> widths;
            for (const auto& column: columns) {
                std::size_t width = column.size();
                for (const auto& row: rows)
                    if (row.is_object() && row.contains(column)) width = std::max(width, std::min<std::size_t>(scalar(row[column]).size(), 40));
                widths.push_back(width);
            }
            for (std::size_t c = 0; c < columns.size(); ++c) out << std::format("{:<{}}  ", columns[c], widths[c]);
            out << "\n";
            for (const auto& row: rows) {
                for (std::size_t c = 0; c < columns.size(); ++c) {
                    std::string cell = row.is_object() && row.contains(columns[c]) ? scalar(row[columns[c]]) : "";
                    out << std::format("{:<{}}  ", clip(cell, 40), widths[c]);
                }
                out << "\n";
            }
        }

    }  // namespace

    void render_auto(std::ostream& out, const nlohmann::json& data, const nlohmann::json& meta) {
        if (data.is_array()) {
            if (data.empty()) out << "(no results)\n";
            else table(out, data);
            if (meta.contains("next_start"))
                out << std::format("… more results: --start {}\n", meta["next_start"].get<std::size_t>());
        } else if (data.is_object()) {
            std::size_t width = 0;
            for (auto it = data.begin(); it != data.end(); ++it) width = std::max(width, it.key().size());
            for (auto it = data.begin(); it != data.end(); ++it) {
                const auto& value = it.value();
                bool nested = value.is_object() || (value.is_array() && !value.empty() && value.front().is_object() &&
                                                    !(value.front().size() <= 2 && value.front().contains("name")));
                out << std::format("{:<{}}  {}\n", it.key(), width, nested ? value.dump() : scalar(value));
            }
        } else out << scalar(data) << "\n";
    }

    int emit(const Output& output, const nlohmann::json& envelope, const Renderer& render) {
        bool ok = envelope.value("ok", false);
        if (output.format == Format::json) {
            *output.out << envelope.dump(2) << "\n";
        } else if (ok) {
            const auto& data = envelope.contains("data") ? envelope["data"] : nlohmann::json();
            const auto& meta = envelope.contains("meta") ? envelope["meta"] : nlohmann::json::object();
            (render ? render : render_auto)(*output.out, data, meta);
        } else {
            const auto& error = envelope["error"];
            *output.err << "forti: " << error.value("message", "error") << "\n";
            if (error.contains("details")) {
                const auto& details = error["details"];
                if (details.contains("suggestions") && !details["suggestions"].empty())
                    *output.err << "  did you mean: " << scalar(details["suggestions"]) << "\n";
                if (details.contains("hint")) *output.err << "  hint: " << scalar(details["hint"]) << "\n";
            }
        }
        if (ok) return 0;
        static const std::map<std::string, engine::Code, std::less<>> codes = [] {
            std::map<std::string, engine::Code, std::less<>> map;
            for (int c = 0; c <= static_cast<int>(engine::Code::outcome_unknown); ++c)
                map.emplace(engine::to_string(static_cast<engine::Code>(c)), static_cast<engine::Code>(c));
            return map;
        }();
        auto it = codes.find(envelope["error"].value("code", "internal"));
        return engine::exit_code(it == codes.end() ? engine::Code::internal : it->second);
    }

}  // namespace forti::cli
