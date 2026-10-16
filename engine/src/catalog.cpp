#include "ops.hpp"

#include <forti/engine/catalog.hpp>
#include <forti/engine/error.hpp>

#include <forti_api/monitor.hpp>

#include <algorithm>
#include <cctype>
#include <format>
#include <utility>

#ifndef FORTI_SHARDS
#error "FORTI_SHARDS must be defined"
#endif

namespace forti::engine {

    std::string_view to_string(Kind kind) {
        switch (kind) {
            case Kind::table: return "table";
            case Kind::singleton: return "singleton";
            case Kind::monitor: return "monitor";
        }
        return "table";
    }

    nlohmann::json FieldInfo::to_json(bool recursive) const {
        nlohmann::json out = {{"name", name}, {"type", type}};
        if (!reset.empty() && reset != "null") out["default"] = nlohmann::json::parse(reset, nullptr, false);
        if (read_only) out["read_only"] = true;
        if (!children.empty()) {
            if (recursive) {
                nlohmann::json list = nlohmann::json::array();
                for (const auto& child: children) list.push_back(child.to_json(true));
                out["children"] = std::move(list);
            } else out["children"] = children.size();
        }
        return out;
    }

    std::string_view Resource::name() const {
        std::string_view view = path;
        if (view.starts_with("cmdb/")) view.remove_prefix(5);
        return view;
    }

    std::vector<FieldInfo> Resource::fields() const { return ops ? ops->fields() : std::vector<FieldInfo>{}; }

    const FieldInfo* Resource::field(std::string_view field_name, const std::vector<FieldInfo>& list) const {
        auto it = std::ranges::find(list, field_name, &FieldInfo::name);
        return it == list.end() ? nullptr : &*it;
    }

    nlohmann::json Resource::summary() const {
        nlohmann::json out = {{"resource", name()}, {"kind", to_string(kind)}};
        if (!key.empty()) out["key"] = key;
        if (!typed()) out["typed"] = false;
        return out;
    }

    namespace {

        template<unsigned... I>
        void collect_all(std::vector<Resource>& out, std::integer_sequence<unsigned, I...>) {
            (detail::collect<I>(out), ...);
        }

        std::string lower(std::string_view text) {
            std::string out(text);
            for (char& c: out) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            return out;
        }

        // Monitor paths go into the URL as given (the SDK does not encode api paths), so only plain
        // path characters are accepted: no query, fragment, percent-escapes or dot segments.
        void validate_monitor_path(std::string_view path) {
            std::string_view rest = path.substr(8);   // after "monitor/"
            bool valid = !rest.empty() && rest.size() <= 200 && !rest.ends_with('/');
            for (char c: rest)
                valid = valid && (std::isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_' || c == '/' || c == '.');
            valid = valid && rest.find("..") == std::string_view::npos && rest.find("//") == std::string_view::npos &&
                    !rest.starts_with('/') && !rest.starts_with('.');
            if (!valid) throw Failure(Code::usage, std::format("malformed monitor path: {}", path));
        }

        std::string normalize(std::string_view name) {
            while (name.starts_with('/')) name.remove_prefix(1);
            if (name.starts_with("api/v2/")) name.remove_prefix(7);
            while (name.ends_with('/')) name.remove_suffix(1);
            if (name == "monitor") return "monitor/";   // rejected by validate_monitor_path
            if (name.starts_with("cmdb/") || name.starts_with("monitor/")) return std::string(name);
            return "cmdb/" + std::string(name);
        }

        std::size_t edit_distance(std::string_view a, std::string_view b) {
            std::vector<std::size_t> row(b.size() + 1);
            for (std::size_t j = 0; j <= b.size(); ++j) row[j] = j;
            for (std::size_t i = 1; i <= a.size(); ++i) {
                std::size_t diagonal = row[0];
                row[0] = i;
                for (std::size_t j = 1; j <= b.size(); ++j) {
                    std::size_t above = row[j];
                    row[j] = std::min({row[j] + 1, row[j - 1] + 1, diagonal + (a[i - 1] == b[j - 1] ? 0 : 1)});
                    diagonal = above;
                }
            }
            return row[b.size()];
        }

        std::string_view leaf_of(std::string_view path) {
            if (auto slash = path.rfind('/'); slash != std::string_view::npos) path.remove_prefix(slash + 1);
            return path;
        }

        // A path as FortiOS CLI words: "cmdb/firewall.service/custom" → firewall service custom,
        // "monitor/system/status" → monitor system status.
        std::vector<std::string> words_of(std::string_view path) {
            if (path.starts_with("cmdb/")) path.remove_prefix(5);
            std::vector<std::string> words;
            std::string word;
            for (char c: path) {
                if (c == '.' || c == '/') {
                    if (!word.empty()) words.push_back(std::move(word));
                    word.clear();
                } else word += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            }
            if (!word.empty()) words.push_back(std::move(word));
            return words;
        }

        // CLI words as a path: all but the last joined by '.', then '/' and the last
        // ("firewall service custom" → firewall.service/custom); monitor words all by '/'.
        std::string path_of(const std::vector<std::string>& words) {
            if (words.empty()) return "";
            std::string path;
            if (words.front() == "monitor") {
                for (const auto& word: words) path += (path.empty() ? "" : "/") + word;
                return path;
            }
            for (std::size_t i = 0; i + 1 < words.size(); ++i) path += (i ? "." : "") + words[i];
            return words.size() == 1 ? words.front() : path + "/" + words.back();
        }

        std::vector<std::string> split_words(std::string_view text) {
            std::vector<std::string> words;
            std::string word;
            for (char c: text) {
                if (std::isspace(static_cast<unsigned char>(c))) {
                    if (!word.empty()) words.push_back(std::move(word));
                    word.clear();
                } else word += c;
            }
            if (!word.empty()) words.push_back(std::move(word));
            return words;
        }

    }  // namespace

    Catalog::Catalog() {
        resources_.reserve(600);
        collect_all(resources_, std::make_integer_sequence<unsigned, FORTI_SHARDS>{});
        std::ranges::sort(resources_, {}, &Resource::path);
    }

    const Catalog& Catalog::instance() {
        static const Catalog catalog;
        return catalog;
    }

    const Resource* Catalog::find(std::string_view name) const {
        std::string path = normalize(name);
        auto it = std::ranges::lower_bound(resources_, path, {}, &Resource::path);
        return it != resources_.end() && it->path == path ? &*it : nullptr;
    }

    Resource Catalog::resolve(std::string_view name) const {
        if (name.empty()) throw Failure(Code::usage, "a resource name is required");
        if (const Resource* known = find(name)) return *known;
        std::string path = normalize(name);
        if (path.starts_with("monitor/")) {
            validate_monitor_path(path);
            Resource untyped;
            untyped.path = std::move(path);
            untyped.kind = Kind::monitor;
            return untyped;
        }
        auto suggestions = suggest(name);
        std::string message = std::format("unknown resource: {}", name);
        if (!suggestions.empty()) message += std::format(" (did you mean {}?)", suggestions.front());
        throw Failure(Code::unknown_resource, message, {{"resource", name}, {"suggestions", suggestions}});
    }

    Catalog::Match Catalog::match(const std::vector<std::string>& words) const {
        Match out;
        if (words.empty()) return out;
        if (words.size() == 1) {
            if (const Resource* known = find(words.front())) {
                out.resource = *known;
                return out;
            }
            if (normalize(words.front()).starts_with("monitor/")) {
                out.resource = resolve(words.front());   // untyped monitor path, or usage when malformed
                return out;
            }
        }
        // CLI words and tails of them. A word with '/' is a path or a key, never part of CLI words.
        std::vector<std::string> wanted;
        for (const auto& word: words) {
            if (word.empty() || word.find('/') != std::string::npos) return out;
            wanted.push_back(lower(word));
        }
        if (words.size() > 1)
            if (const Resource* known = find(path_of(wanted))) {
                out.resource = *known;
                return out;
            }
        std::vector<const Resource*> config, monitors;
        for (const auto& resource: resources_) {
            auto have = words_of(resource.path);
            if (have.size() < wanted.size() || !std::equal(wanted.rbegin(), wanted.rend(), have.rbegin())) continue;
            (resource.kind == Kind::monitor ? monitors : config).push_back(&resource);
        }
        const auto& found = config.empty() ? monitors : config;
        if (found.size() == 1) out.resource = *found.front();
        else
            for (const Resource* resource: found) out.candidates.emplace_back(resource->name());
        return out;
    }

    Resource Catalog::lookup(std::string_view name) const {
        auto words = split_words(name);
        if (words.empty()) throw Failure(Code::usage, "a resource name is required");
        auto found = match(words);
        if (found.resource) return *found.resource;
        if (!found.candidates.empty()) {
            std::string list;
            for (std::size_t i = 0; i < found.candidates.size() && i < 8; ++i) list += (i ? ", " : "") + found.candidates[i];
            if (found.candidates.size() > 8) list += std::format(" and {} more", found.candidates.size() - 8);
            throw Failure(Code::unknown_resource, std::format("\"{}\" could be any of {} resources: {}", name, found.candidates.size(), list),
                          {{"resource", name}, {"candidates", found.candidates}, {"hint", "name it in full, e.g. " + found.candidates.front()}});
        }
        return resolve(words.size() == 1 ? words.front() : path_of(words));
    }

    std::optional<Catalog::Keyed> Catalog::keyed(std::string_view name) const {
        if (find(name)) return std::nullopt;
        std::string path = normalize(name);
        if (!path.starts_with("cmdb/")) return std::nullopt;
        for (std::size_t slash = path.find('/', 5); slash != std::string::npos; slash = path.find('/', slash + 1)) {
            const Resource* table = find(std::string_view(path).substr(0, slash));
            if (!table) continue;
            if (table->kind != Kind::table || slash + 1 >= path.size()) return std::nullopt;
            return Keyed{table, path.substr(slash + 1)};
        }
        return std::nullopt;
    }

    std::vector<const Resource*> Catalog::search(std::string_view query, std::optional<Kind> kind) const {
        std::string needle = lower(query);
        std::vector<const Resource*> out;
        for (const auto& resource: resources_) {
            if (kind && resource.kind != *kind) continue;
            if (needle.empty() || lower(resource.path).find(needle) != std::string::npos) out.push_back(&resource);
        }
        return out;
    }

    namespace detail {

        std::string closest_name(std::string_view name, const std::set<std::string, std::less<>>& candidates) {
            std::size_t limit = name.size() <= 4 ? 1 : 2, best = limit + 1;
            std::string found;
            for (const auto& candidate: candidates) {
                std::size_t distance = edit_distance(name, candidate);
                if (distance < best) {
                    best = distance;
                    found = candidate;
                }
            }
            return best <= limit ? found : std::string();
        }

    }  // namespace detail

    std::vector<std::string> Catalog::suggest(std::string_view name, std::size_t limit) const {
        std::string wanted = lower(normalize(name));
        std::string_view leaf = leaf_of(wanted);
        std::vector<std::pair<int, const Resource*>> scored;
        for (const auto& resource: resources_) {
            std::string candidate = lower(resource.path);
            int score = 0;
            if (!leaf.empty() && candidate.find(leaf) != std::string::npos) score += 4;
            else if (leaf.size() > 3 && edit_distance(leaf, leaf_of(candidate)) <= 2) score += 4;
            if (candidate.find(wanted) != std::string::npos || wanted.find(candidate) != std::string::npos) score += 3;
            std::string_view group = wanted;
            if (auto slash = group.find('/', 5); slash != std::string_view::npos) group = group.substr(0, slash);
            if (candidate.starts_with(group)) score += 1;
            if (score > 1) scored.emplace_back(score, &resource);
        }
        std::ranges::stable_sort(scored, std::greater<>{}, &std::pair<int, const Resource*>::first);
        std::vector<std::string> out;
        for (const auto& [score, resource]: scored) {
            if (out.size() == limit) break;
            out.emplace_back(resource->name());
        }
        return out;
    }

    std::vector<std::string> closest_names(std::string_view wanted, const std::vector<std::string>& candidates, std::size_t limit) {
        std::string needle = lower(wanted);
        std::vector<std::pair<std::size_t, std::string>> scored;
        for (const auto& candidate: candidates) {
            std::string name = lower(candidate);
            std::size_t distance = edit_distance(needle, name);
            bool contained = needle.size() >= 3 && (name.find(needle) != std::string::npos || needle.find(name) != std::string::npos);
            if (distance <= std::max<std::size_t>(1, needle.size() / 3) || contained) scored.emplace_back(contained ? std::min<std::size_t>(distance, 2) : distance, candidate);
        }
        std::ranges::stable_sort(scored, {}, &std::pair<std::size_t, std::string>::first);
        std::vector<std::string> out;
        for (auto& [distance, name]: scored) {
            if (out.size() == limit) break;
            out.push_back(std::move(name));
        }
        return out;
    }

}  // namespace forti::engine
