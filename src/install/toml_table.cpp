#include "toml_table.hpp"

#include <forti/engine/error.hpp>

#include <algorithm>
#include <cstdint>
#include <format>

namespace forti::install::toml {

    using engine::Code;
    using engine::Failure;

    namespace {

        bool starts_with(const Path& path, const Path& prefix) {
            return path.size() >= prefix.size() && std::equal(prefix.begin(), prefix.end(), path.begin());
        }

        bool bare_char(char c) {
            return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-';
        }

        void append_utf8(std::string& out, std::uint32_t cp) {
            if (cp < 0x80) out += static_cast<char>(cp);
            else if (cp < 0x800) {
                out += static_cast<char>(0xC0 | (cp >> 6));
                out += static_cast<char>(0x80 | (cp & 0x3F));
            } else if (cp < 0x10000) {
                out += static_cast<char>(0xE0 | (cp >> 12));
                out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
                out += static_cast<char>(0x80 | (cp & 0x3F));
            } else {
                out += static_cast<char>(0xF0 | (cp >> 18));
                out += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
                out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
                out += static_cast<char>(0x80 | (cp & 0x3F));
            }
        }

        // Decodes a single-line string starting at s[i] (a quote); advances i past it.
        std::optional<std::string> read_simple_string(std::string_view s, std::size_t& i) {
            char quote = s[i];
            if (s.substr(i, 3) == std::string(3, quote)) return std::nullopt;   // multi-line: not handled here
            std::string out;
            ++i;
            while (i < s.size() && s[i] != quote) {
                char c = s[i];
                if (c == '\n') return std::nullopt;
                if (quote == '"' && c == '\\') {
                    if (++i >= s.size()) return std::nullopt;
                    char e = s[i];
                    switch (e) {
                        case 'b': out += '\b'; break;
                        case 't': out += '\t'; break;
                        case 'n': out += '\n'; break;
                        case 'f': out += '\f'; break;
                        case 'r': out += '\r'; break;
                        case 'e': out += '\x1b'; break;
                        case '"': out += '"'; break;
                        case '\\': out += '\\'; break;
                        case 'u':
                        case 'U': {
                            std::size_t digits = e == 'u' ? 4 : 8;
                            if (i + digits >= s.size()) return std::nullopt;
                            std::uint32_t cp = 0;
                            for (std::size_t d = 1; d <= digits; ++d) {
                                char h = s[i + d];
                                cp <<= 4;
                                if (h >= '0' && h <= '9') cp |= static_cast<std::uint32_t>(h - '0');
                                else if (h >= 'a' && h <= 'f') cp |= static_cast<std::uint32_t>(h - 'a' + 10);
                                else if (h >= 'A' && h <= 'F') cp |= static_cast<std::uint32_t>(h - 'A' + 10);
                                else return std::nullopt;
                            }
                            append_utf8(out, cp);
                            i += digits;
                            break;
                        }
                        default: return std::nullopt;
                    }
                    ++i;
                    continue;
                }
                out += c;
                ++i;
            }
            if (i >= s.size()) return std::nullopt;
            ++i;   // closing quote
            return out;
        }

        class Scanner {
            std::string_view s_;
            std::size_t i_ = 0;
            Document doc_;
            Path table_;

            [[noreturn]] void fail(const std::string& what) const {
                auto line = 1 + std::count(s_.begin(), s_.begin() + static_cast<std::ptrdiff_t>(std::min(i_, s_.size())), '\n');
                throw Failure(Code::config, std::format("TOML line {}: {}", line, what));
            }
            [[nodiscard]] bool more() const { return i_ < s_.size(); }
            void skip_blanks() {
                while (more() && (s_[i_] == ' ' || s_[i_] == '\t')) ++i_;
            }
            void end_line() {
                skip_blanks();
                if (more() && s_[i_] == '#')
                    while (more() && s_[i_] != '\n') ++i_;
                if (more() && s_[i_] == '\r') ++i_;
                if (!more()) return;
                if (s_[i_] != '\n') fail("expected the end of the line");
                ++i_;
            }

            std::string key_part() {
                if (!more()) fail("expected a key");
                if (s_[i_] == '"' || s_[i_] == '\'') {
                    auto part = read_simple_string(s_, i_);
                    if (!part) fail("bad quoted key");
                    return *part;
                }
                std::size_t start = i_;
                while (more() && bare_char(s_[i_])) ++i_;
                if (start == i_) fail("expected a key");
                return std::string(s_.substr(start, i_ - start));
            }

            Path key_path() {
                Path path;
                while (true) {
                    skip_blanks();
                    path.push_back(key_part());
                    skip_blanks();
                    if (more() && s_[i_] == '.') {
                        ++i_;
                        continue;
                    }
                    return path;
                }
            }

            // At a quote: skips a string of any of the four kinds.
            void skip_string() {
                char quote = s_[i_];
                bool multi = s_.substr(i_, 3) == std::string(3, quote);
                if (!multi) {
                    if (!read_simple_string(s_, i_)) fail("unterminated string");
                    return;
                }
                i_ += 3;
                std::string closing(3, quote);
                while (true) {
                    if (!more()) fail("unterminated multi-line string");
                    if (quote == '"' && s_[i_] == '\\') {
                        i_ += 2;
                        continue;
                    }
                    if (s_.substr(i_, 3) == closing) {
                        i_ += 3;
                        // Up to two quotes may sit right before the closing delimiter.
                        for (int extra = 0; extra < 2 && more() && s_[i_] == quote; ++extra) ++i_;
                        return;
                    }
                    ++i_;
                }
            }

            // Skips a value; returns the end of its last significant character.
            std::size_t skip_value() {
                int depth = 0;
                std::size_t last = i_;
                while (more()) {
                    char c = s_[i_];
                    if (c == '"' || c == '\'') {
                        skip_string();
                        last = i_;
                        continue;
                    }
                    if (c == '#') {
                        if (depth == 0) break;
                        while (more() && s_[i_] != '\n') ++i_;
                        continue;
                    }
                    if (c == '\n') {
                        if (depth == 0) break;
                        ++i_;
                        continue;
                    }
                    if (c == '[' || c == '{') ++depth;
                    else if ((c == ']' || c == '}') && --depth < 0) fail("unbalanced bracket");
                    ++i_;
                    if (c != ' ' && c != '\t' && c != '\r') last = i_;
                }
                if (depth != 0) fail("unterminated array or inline table");
                return last;
            }

        public:
            explicit Scanner(std::string_view text) : s_(text) {}

            Document run() {
                while (more()) {
                    std::size_t line = i_;
                    skip_blanks();
                    if (!more() || s_[i_] == '\n' || s_[i_] == '\r' || s_[i_] == '#') {
                        doc_.trivia.push_back(line);
                        end_line();
                        continue;
                    }
                    if (s_[i_] == '[') {
                        bool array = i_ + 1 < s_.size() && s_[i_ + 1] == '[';
                        i_ += array ? 2 : 1;
                        Path path = key_path();
                        if (!more() || s_[i_] != ']') fail("expected ']'");
                        ++i_;
                        if (array) {
                            if (!more() || s_[i_] != ']') fail("expected ']]'");
                            ++i_;
                        }
                        end_line();
                        doc_.headers.push_back({path, array, line, i_});
                        table_ = std::move(path);
                        continue;
                    }
                    Path key = key_path();
                    if (!more() || s_[i_] != '=') fail("expected '='");
                    ++i_;
                    skip_blanks();
                    std::size_t start = i_;
                    std::size_t end = skip_value();
                    if (end <= start) fail("missing value");
                    doc_.values.push_back({table_, std::move(key), line, s_.substr(start, end - start)});
                    end_line();
                }
                return std::move(doc_);
            }
        };

        Path server_path(std::string_view name) { return {"mcp_servers", std::string(name)}; }

    }  // namespace

    Document scan(std::string_view text) { return Scanner(text).run(); }

    std::optional<Block> find_table(std::string_view text, const Path& path) {
        auto doc = scan(text);
        std::string where = "[";
        for (std::size_t k = 0; k < path.size(); ++k) where += (k ? "." : "") + path[k];
        where += "]";

        for (const auto& kv: doc.values) {
            Path full = kv.table;
            full.insert(full.end(), kv.key.begin(), kv.key.end());
            bool inside = starts_with(kv.table, path);
            bool defines = starts_with(full, path) && !inside;
            bool inline_parent = !inside && starts_with(path, full) && full.size() < path.size() &&
                                 kv.value.starts_with('{') && kv.value.find(path.back()) != std::string_view::npos;
            if (defines || inline_parent)
                throw Failure(Code::config, std::format("{} is defined with dotted keys or an inline table; forti only edits "
                                                        "it as a table block, so change it by hand", where));
        }

        std::optional<std::size_t> found;
        for (std::size_t h = 0; h < doc.headers.size(); ++h) {
            if (doc.headers[h].path != path) continue;
            if (doc.headers[h].array) throw Failure(Code::config, std::format("{} is an array of tables; edit it by hand", where));
            if (found) throw Failure(Code::config, std::format("{} appears twice; fix the file by hand", where));
            found = h;
        }
        if (!found) {
            for (const auto& header: doc.headers)
                if (starts_with(header.path, path))
                    throw Failure(Code::config, std::format("{} has sub-tables but no table header; edit it by hand", where));
            return std::nullopt;
        }

        const auto& header = doc.headers[*found];
        Block block{header.begin, text.size()};
        std::size_t h = *found + 1;
        for (; h < doc.headers.size(); ++h) {
            if (!starts_with(doc.headers[h].path, path)) {
                block.end = doc.headers[h].begin;
                break;
            }
        }
        for (; h < doc.headers.size(); ++h)
            if (starts_with(doc.headers[h].path, path))
                throw Failure(Code::config, std::format("{} is split across the file; edit it by hand", where));

        // Blank and comment lines right before the next table belong to that table.
        while (block.end > header.end) {
            auto previous = block.end >= 2 ? text.rfind('\n', block.end - 2) : std::string_view::npos;
            std::size_t line = previous == std::string_view::npos ? 0 : previous + 1;
            if (line < header.end || !std::ranges::contains(doc.trivia, line)) break;
            block.end = line;
        }
        return block;
    }

    std::string set_table(std::string_view text, const Path& path, std::string_view block) {
        if (auto found = find_table(text, path)) {
            std::string out(text.substr(0, found->begin));
            out += block;
            out += text.substr(found->end);
            return out;
        }
        std::string out(text);
        if (!out.empty() && out.back() != '\n') out += '\n';
        if (!out.empty()) out += '\n';
        out += block;
        return out;
    }

    std::string remove_table(std::string_view text, const Path& path) {
        auto found = find_table(text, path);
        if (!found) return std::string(text);
        std::string before(text.substr(0, found->begin));
        std::string_view after = text.substr(found->end);
        if (before.ends_with("\n\n") || before == "\n") {
            // Drop one blank line so remove(set(x)) == x and blank lines do not pile up.
            if (after.empty()) before.pop_back();
            else if (after.starts_with('\n')) after.remove_prefix(1);
        }
        return before + std::string(after);
    }

    std::optional<Entry> read_server(std::string_view text, std::string_view name) {
        Path path = server_path(name);
        if (!find_table(text, path)) return std::nullopt;
        Entry entry;
        bool has_command = false;
        for (const auto& kv: scan(text).values) {
            if (!starts_with(kv.table, path)) continue;
            if (kv.table.size() > path.size()) {
                entry.extra = true;   // [mcp_servers.forti.env] and the like
                continue;
            }
            if (kv.key == Path{"command"}) {
                auto command = parse_string(kv.value);
                if (command) {
                    entry.command = *command;
                    has_command = true;
                } else entry.extra = true;
            } else if (kv.key == Path{"args"}) {
                auto args = parse_string_array(kv.value);
                if (args) entry.args = *args;
                else entry.extra = true;
            } else entry.extra = true;
        }
        if (!has_command) entry.extra = true;
        return entry;
    }

    std::string quote(std::string_view text) {
        std::string out = "\"";
        for (unsigned char c: text) {
            switch (c) {
                case '"': out += "\\\""; break;
                case '\\': out += "\\\\"; break;
                case '\n': out += "\\n"; break;
                case '\t': out += "\\t"; break;
                case '\r': out += "\\r"; break;
                default:
                    if (c < 0x20 || c == 0x7F) out += std::format("\\u{:04X}", static_cast<unsigned>(c));
                    else out += static_cast<char>(c);
            }
        }
        return out + "\"";
    }

    std::string render_server(std::string_view name, const Entry& entry) {
        bool bare = !name.empty() && std::ranges::all_of(name, bare_char);
        std::string out = std::format("[mcp_servers.{}]\ncommand = {}\n", bare ? std::string(name) : quote(name), quote(entry.command));
        if (!entry.args.empty()) {
            out += "args = [";
            for (std::size_t k = 0; k < entry.args.size(); ++k) out += (k ? ", " : "") + quote(entry.args[k]);
            out += "]\n";
        }
        return out;
    }

    bool project_trusted(std::string_view global_config, const std::string& project_dir) {
        Path want{"projects", project_dir, "trust_level"};
        for (const auto& kv: scan(global_config).values) {
            Path full = kv.table;
            full.insert(full.end(), kv.key.begin(), kv.key.end());
            if (full == want) return parse_string(kv.value) == std::optional<std::string>("trusted");
        }
        return false;
    }

    std::optional<std::string> parse_string(std::string_view value) {
        if (value.empty() || (value[0] != '"' && value[0] != '\'')) return std::nullopt;
        std::size_t i = 0;
        auto out = read_simple_string(value, i);
        if (!out || i != value.size()) return std::nullopt;
        return out;
    }

    std::optional<std::vector<std::string>> parse_string_array(std::string_view value) {
        if (!value.starts_with('[') || !value.ends_with(']')) return std::nullopt;
        std::vector<std::string> out;
        std::size_t i = 1;
        auto skip = [&] {
            while (i < value.size()) {
                char c = value[i];
                if (c == ' ' || c == '\t' || c == '\r' || c == '\n') ++i;
                else if (c == '#')
                    while (i < value.size() && value[i] != '\n') ++i;
                else break;
            }
        };
        bool expect_item = true;
        while (true) {
            skip();
            if (i >= value.size()) return std::nullopt;
            if (value[i] == ']') return i + 1 == value.size() ? std::optional(out) : std::nullopt;
            if (!expect_item) {
                if (value[i] != ',') return std::nullopt;
                ++i;
                expect_item = true;
                continue;
            }
            if (value[i] != '"' && value[i] != '\'') return std::nullopt;
            auto item = read_simple_string(value, i);
            if (!item) return std::nullopt;
            out.push_back(std::move(*item));
            expect_item = false;
        }
    }

}  // namespace forti::install::toml
