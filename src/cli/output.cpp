#include "output.hpp"

#include <forti/engine/catalog.hpp>
#include <forti/engine/error.hpp>

#include <algorithm>
#include <charconv>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <format>
#include <iostream>
#include <map>
#include <ostream>
#include <utility>

#include <sys/ioctl.h>
#include <unistd.h>

namespace forti::cli {

    namespace {

        using json = nlohmann::json;

        // What the renderer currently writing may use. Set by emit() around each render; the
        // Renderer signature stays (data, meta) so renderers in other command files keep working.
        struct Active {
            bool color = false;
            std::size_t width = 0;
        };
        Active active;

        struct Scope {
            Active saved = active;
            Scope(bool color, std::size_t width) { active = {color, width}; }
            ~Scope() { active = saved; }
            Scope(const Scope&) = delete;
            Scope& operator=(const Scope&) = delete;
        };

        constexpr std::size_t max_cell = 40;   // a cell wider than this is clipped even without a TTY
        constexpr std::size_t min_cell = 12;   // shrinking to fit the terminal stops here

        std::string scalar(const json& value) {
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

        // Cuts at a code point boundary so the result is at most `width` columns, "…" included.
        std::string clip(const std::string& text, std::size_t width) {
            if (display_width(text) <= width) return text;
            if (width == 0) return "";
            std::string out;
            std::size_t columns = 0;
            for (std::size_t i = 0; i < text.size();) {
                std::size_t length = 1;
                auto lead = static_cast<unsigned char>(text[i]);
                if (lead >= 0xF0) length = 4;
                else if (lead >= 0xE0) length = 3;
                else if (lead >= 0xC0) length = 2;
                if (columns + 1 >= width) break;
                out.append(text, i, length);
                ++columns;
                i += length;
            }
            return out + "…";
        }

        std::string pad(const std::string& text, std::size_t width) {
            std::size_t shown = display_width(text);
            return shown >= width ? text : text + std::string(width - shown, ' ');
        }

        // The column that names a row: the resource's catalog key when the meta says which resource
        // this is, else the first familiar identifier.
        std::string identity_column(const std::vector<std::string>& columns, const json& meta) {
            if (meta.is_object() && meta.contains("resource") && meta["resource"].is_string())
                if (const auto* resource = engine::Catalog::instance().find(meta["resource"].get<std::string>()))
                    if (!resource->key.empty() && std::ranges::find(columns, resource->key) != columns.end())
                        return resource->key;
            for (const char* name: {"name", "resource", "policyid", "key", "id", "seq-num", "mkey"})
                if (std::ranges::find(columns, name) != columns.end()) return name;
            return {};
        }

        // Display order: the identifying column, then `preferred` (--fields as given), then the rest
        // (alphabetical: that is how the JSON object stores them).
        void order(std::vector<std::string>& columns, const json& meta, const std::vector<std::string>& preferred) {
            std::vector<std::string> ordered;
            auto take = [&](const std::string& name) {
                if (std::ranges::find(columns, name) != columns.end() && std::ranges::find(ordered, name) == ordered.end())
                    ordered.push_back(name);
            };
            if (auto id = identity_column(columns, meta); !id.empty()) take(id);
            for (const auto& name: preferred) take(name);
            for (const auto& name: columns) take(name);
            columns = std::move(ordered);
        }

        // FortiOS bookkeeping attributes: hidden in text output, kept in --json.
        bool bookkeeping(std::string_view key) { return key == "q_origin_key"; }

        std::vector<std::string> preferred_columns;   // set by table_renderer around render_auto

        void table(std::ostream& out, const json& rows, const json& meta) {
            // Columns: keys in first-seen order, scalar-ish only, the identifying one first.
            // q_origin_key is FortiOS' internal copy of the key and only adds width.
            std::vector<std::string> columns;
            for (const auto& row: rows) {
                if (!row.is_object()) continue;
                for (auto it = row.begin(); it != row.end(); ++it) {
                    if (it.value().is_object() || bookkeeping(it.key())) continue;
                    if (std::ranges::find(columns, it.key()) == columns.end()) columns.push_back(it.key());
                }
            }
            if (columns.empty()) {
                out << rows.dump(2) << "\n";
                return;
            }
            order(columns, meta, preferred_columns);
            std::vector<std::vector<std::string>> cells;
            for (const auto& row: rows) {
                std::vector<std::string> line;
                for (const auto& column: columns)
                    line.push_back(row.is_object() && row.contains(column) ? scalar(row[column]) : "");
                cells.push_back(std::move(line));
            }
            print_table(out, columns, cells);
        }

        std::string join(const json& list) {
            std::string out;
            for (const auto& item: list) out += (out.empty() ? "" : ", ") + scalar(item);
            return out;
        }

        // A hint for errors that carry none: the next command to run, from the error's details.
        std::string generic_hint(std::string_view code, std::string_view message, const json& details) {
            std::string profile = details.value("profile", std::string("NAME"));
            if (code == "config") {
                if (details.contains("profiles") && details["profiles"].is_array()) {
                    if (details["profiles"].empty()) return "create one: forti configure";
                    return std::format("profiles: {}. Choose one with -p NAME, or make one the default: forti profile default NAME",
                                       join(details["profiles"]));
                }
                if (details.value("missing", "") == "client_cert") {
                    std::filesystem::path path = details.value("path", "");
                    if (path.filename() == "client.p12" && path.parent_path().parent_path().filename() == "certs")
                        return std::format("recreate it: forti cert create {} --force (same CA and CN, so the FortiGate needs no change)",
                                           path.parent_path().filename().string());
                    return std::format("choose a certificate: forti cert use NAME -p {}, or set the file: forti profile set {} client_cert=PATH",
                                       profile, profile);
                }
                if (details.value("missing", "") == "ca_bundle")
                    return std::format("set the file: forti profile set {} ca_bundle=PATH", profile);
                return message.find("forti configure") != std::string_view::npos ? "" : "run `forti doctor` to check the configuration";
            }
            if (code == "connection")
                return "run `forti doctor` for details; `forti configure -p NAME` changes the address or how the certificate is "
                       "trusted (verification is never turned off)";
            if (code == "auth")
                return "the FortiGate rejected the API key. forti did not retry (FortiOS locks the API user out after a few "
                       "failures). Check the key, that the API user's trusted hosts include this machine, and its admin profile";
            if (code == "unknown_resource") return "`forti discover <search>` lists resources";
            if (code == "usage") return message.starts_with("usage:") ? "" : "see `forti --help` or `forti <command> --help`";
            if (code == "policy_denied" && message.find("read-only") != std::string_view::npos)
                return std::format("profiles are read-only by default. Allow changes with `{}` (you approve each plan) or "
                                   "`autonomous`", details.value("mode_command", std::format("forti profile mode {} guarded", profile)));
            return "";
        }

    }  // namespace

    std::string printable(std::string_view text, bool keep_newlines) {
        std::string out;
        out.reserve(text.size());
        for (std::size_t i = 0; i < text.size(); ++i) {
            auto c = static_cast<unsigned char>(text[i]);
            if (c < 0x20 || c == 0x7F) {
                if (c == '\n' && keep_newlines) out += '\n';
                else if (c == '\n') out += "\\n";
                else if (c == '\t') out += "\\t";
                else if (c == '\r') out += "\\r";
                else out += std::format("\\x{:02x}", c);
                continue;
            }
            // Multi-byte sequences: U+0080-U+009F (C1, e.g. 8-bit CSI), U+061C, U+200E-U+200F,
            // U+2028-U+202E, U+2066-U+2069. Input is valid UTF-8 (it came through a JSON parser);
            // anything else passes through byte by byte.
            std::uint32_t cp = 0;
            std::size_t length = 0;
            if (c >= 0xC2 && c <= 0xDF && i + 1 < text.size()) {
                cp = ((c & 0x1Fu) << 6) | (static_cast<unsigned char>(text[i + 1]) & 0x3Fu);
                length = 2;
            } else if (c >= 0xE0 && c <= 0xEF && i + 2 < text.size()) {
                cp = ((c & 0x0Fu) << 12) | ((static_cast<unsigned char>(text[i + 1]) & 0x3Fu) << 6) |
                     (static_cast<unsigned char>(text[i + 2]) & 0x3Fu);
                length = 3;
            }
            bool control = length != 0 && ((cp >= 0x80 && cp <= 0x9F) || cp == 0x061C || cp == 0x200E || cp == 0x200F ||
                                           (cp >= 0x2028 && cp <= 0x202E) || (cp >= 0x2066 && cp <= 0x2069));
            if (control) {
                out += std::format("\\u{:04x}", cp);
                i += length - 1;
                continue;
            }
            out += static_cast<char>(c);
        }
        return out;
    }

    json printable_json(const json& value) {
        if (value.is_string()) {
            const auto& text = value.get_ref<const std::string&>();
            std::string safe = printable(text);
            return safe == text ? value : json(std::move(safe));
        }
        if (value.is_array()) {
            json out = json::array();
            for (const auto& item: value) out.push_back(printable_json(item));
            return out;
        }
        if (value.is_object()) {
            json out = json::object();
            for (auto it = value.begin(); it != value.end(); ++it) out[printable(it.key())] = printable_json(it.value());
            return out;
        }
        return value;
    }

    std::size_t display_width(std::string_view text) {
        std::size_t width = 0;
        for (char c: text)
            if ((static_cast<unsigned char>(c) & 0xC0) != 0x80) ++width;
        return width;
    }

    std::string styled(std::string_view text, Style style) {
        if (!active.color) return std::string(text);
        const char* code = "";
        switch (style) {
            case Style::bold: code = "1"; break;
            case Style::dim: code = "2"; break;
            case Style::red: code = "31"; break;
            case Style::green: code = "32"; break;
            case Style::yellow: code = "33"; break;
            case Style::cyan: code = "36"; break;
        }
        return std::format("\x1b[{}m{}\x1b[0m", code, text);
    }

    void print_table(std::ostream& out, const std::vector<std::string>& columns,
                     const std::vector<std::vector<std::string>>& rows) {
        std::vector<std::size_t> widths;
        for (std::size_t c = 0; c < columns.size(); ++c) {
            std::size_t width = display_width(columns[c]);
            for (const auto& row: rows)
                if (c < row.size()) width = std::max(width, std::min(display_width(row[c]), max_cell));
            widths.push_back(width);
        }
        // Fit the terminal: shrink the widest columns down to min_cell, then drop trailing columns.
        std::size_t shown = columns.size();
        if (active.width > 0) {
            auto total = [&] {
                std::size_t sum = 0;
                for (std::size_t c = 0; c < shown; ++c) sum += widths[c] + 2;
                return sum;
            };
            while (total() > active.width) {
                auto widest = std::max_element(widths.begin(), widths.begin() + static_cast<std::ptrdiff_t>(shown));
                if (*widest > min_cell) {
                    std::size_t excess = total() - active.width;
                    *widest = *widest > min_cell + excess ? *widest - excess : min_cell;
                    continue;
                }
                if (shown == 1) break;
                --shown;
            }
        }
        std::string header;
        for (std::size_t c = 0; c < shown; ++c)
            header += (c ? "  " : "") + (c + 1 < shown ? pad(columns[c], widths[c]) : columns[c]);
        out << styled(header, Style::bold) << "\n";
        for (const auto& row: rows) {
            std::string line;
            for (std::size_t c = 0; c < shown; ++c) {
                std::string cell = clip(c < row.size() ? row[c] : "", widths[c]);
                line += (c ? "  " : "") + (c + 1 < shown ? pad(cell, widths[c]) : cell);
            }
            out << line << "\n";
        }
        if (shown < columns.size())
            out << styled(std::format("(+{} column{}: --fields or --json)", columns.size() - shown,
                                      columns.size() - shown == 1 ? "" : "s"),
                          Style::dim)
                << "\n";
    }

    void render_auto(std::ostream& out, const json& data, const json& meta) {
        if (data.is_array()) {
            if (data.empty()) out << "(no results)\n";
            else if (std::ranges::all_of(data, [](const json& row) { return row.is_object(); })) table(out, data, meta);
            else for (const auto& item: data) out << scalar(item) << "\n";
            if (meta.is_object() && meta.contains("next_start"))
                out << styled(std::format("… more results: --start {}", meta["next_start"].get<std::size_t>()), Style::dim)
                    << "\n";
            if (meta.is_object() && meta.value("truncated", false))
                out << styled(std::format("… showing {} of {} (use --count)", data.size(), meta.value("total", data.size())),
                              Style::dim)
                    << "\n";
        } else if (data.is_object()) {
            std::vector<std::string> keys;
            for (auto it = data.begin(); it != data.end(); ++it)
                if (!bookkeeping(it.key())) keys.push_back(it.key());
            order(keys, meta, preferred_columns);
            std::size_t width = 0;
            for (const auto& key: keys) width = std::max(width, display_width(key));
            for (const auto& key: keys) {
                const auto& value = data[key];
                bool nested = value.is_object() || (value.is_array() && !value.empty() && value.front().is_object() &&
                                                    !(value.front().size() <= 2 && value.front().contains("name")));
                out << styled(pad(key, width), Style::bold) << "  " << (nested ? value.dump() : scalar(value)) << "\n";
            }
        } else out << scalar(data) << "\n";
        if (meta.is_object() && meta.contains("redacted") && meta["redacted"].is_array())
            out << styled(std::format("({} secret attribute{} redacted: {}; forti get --reveal shows them)",
                                      meta["redacted"].size(), meta["redacted"].size() == 1 ? "" : "s",
                                      scalar(meta["redacted"])),
                          Style::dim)
                << "\n";
    }

    Renderer table_renderer(std::vector<std::string> columns) {
        return [columns = std::move(columns)](std::ostream& out, const json& data, const json& meta) {
            auto saved = std::exchange(preferred_columns, columns);
            try {
                render_auto(out, data, meta);
            } catch (...) {
                preferred_columns = std::move(saved);
                throw;
            }
            preferred_columns = std::move(saved);
        };
    }

    void render_profiles(std::ostream& out, const json& data, const json& meta) {
        if (!data.is_array() || data.empty()) {
            out << "no device profiles (run `forti configure`)\n";
            return;
        }
        std::string fallback = meta.is_object() ? meta.value("default_profile", "") : "";
        if (fallback.empty() && data.size() == 1) fallback = data.front().value("name", "");
        std::vector<std::vector<std::string>> rows;
        for (const auto& profile: data) {
            std::string name = profile.value("name", "");
            std::string port = profile.contains("port") ? scalar(profile["port"]) : "";
            rows.push_back({name == fallback ? name + " *" : name,
                            profile.value("host", "") + (port.empty() || port == "443" ? "" : ":" + port),
                            profile.value("vdom", ""),
                            profile.value("mode", "read-only"),
                            profile.contains("api_key") ? scalar(profile["api_key"]) : ""});
        }
        print_table(out, {"profile", "host", "vdom", "mode", "api key"}, rows);
        if (!fallback.empty()) out << styled("* default profile", Style::dim) << "\n";
    }

    int exit_status(std::string_view code) {
        return engine::exit_code(engine::parse_code(code).value_or(engine::Code::internal));
    }

    int emit(const Output& output, const json& raw, const Renderer& render) {
        bool ok = raw.value("ok", false);
        if (output.format == Format::json) {
            *output.out << raw.dump(2) << "\n";   // JSON escapes control characters itself
            return ok ? 0 : exit_status(raw.contains("error") ? raw["error"].value("code", "internal") : "internal");
        }
        // Text for a terminal: nothing from the device or a plan reaches it unescaped.
        json envelope = printable_json(raw);
        if (ok) {
            Scope scope(output.color, output.width);
            const auto& data = envelope.contains("data") ? envelope["data"] : json();
            const auto& meta = envelope.contains("meta") ? envelope["meta"] : json::object();
            (render ? render : render_auto)(*output.out, data, meta);
        } else {
            Scope scope(output.err_color, 0);
            const auto& error = envelope.contains("error") && envelope["error"].is_object() ? envelope["error"] : json::object();
            std::string code = error.value("code", "internal");
            std::string message = error.value("message", "error");
            *output.err << styled("forti: error:", Style::red) << " " << message << "\n";
            const json details = error.contains("details") && error["details"].is_object() ? error["details"] : json::object();
            if (details.contains("suggestions") && !details["suggestions"].empty())
                *output.err << "  did you mean: " << scalar(details["suggestions"]) << "\n";
            if (details.contains("cli_error") && !details["cli_error"].empty())
                *output.err << "  FortiOS: " << scalar(details["cli_error"]) << "\n";
            // forti's own hints may span lines: only their newlines survive.
            static const json none;
            const json& raw_error = raw.contains("error") && raw["error"].is_object() ? raw["error"] : none;
            const json& raw_details = raw_error.contains("details") ? raw_error["details"] : none;
            std::string hint = details.contains("hint")
                               ? (raw_details.is_object() && raw_details.contains("hint") && raw_details["hint"].is_string()
                                  ? printable(raw_details["hint"].get<std::string>(), true) : scalar(details["hint"]))
                               : generic_hint(code, message, details);
            if (!hint.empty()) *output.err << styled("  hint:", Style::cyan) << " " << hint << "\n";
        }
        return ok ? 0 : exit_status(envelope.contains("error") ? envelope["error"].value("code", "internal") : "internal");
    }

    Output terminal_output() {
        Output output{.out = &std::cout, .err = &std::cerr};
        if (const char* format = std::getenv("FORTI_OUTPUT"); format && std::string_view(format) == "json")
            output.format = Format::json;
        // https://no-color.org: any non-empty NO_COLOR disables color; TERM=dumb cannot show it.
        const char* no_color = std::getenv("NO_COLOR");
        const char* term = std::getenv("TERM");
        bool may_color = !(no_color && *no_color) && !(term && std::string_view(term) == "dumb");
        output.color = may_color && ::isatty(STDOUT_FILENO);
        output.err_color = may_color && ::isatty(STDERR_FILENO);
        output.tty = ::isatty(STDOUT_FILENO) == 1;
        if (output.tty) {
            winsize size{};
            if (::ioctl(STDOUT_FILENO, TIOCGWINSZ, &size) == 0 && size.ws_col > 0) output.width = size.ws_col;
            else if (const char* columns = std::getenv("COLUMNS")) {
                std::string_view text(columns);
                std::from_chars(text.data(), text.data() + text.size(), output.width);
            }
            if (output.width == 0) output.width = 80;
        }
        return output;
    }

}  // namespace forti::cli
