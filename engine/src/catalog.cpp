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

    std::vector<const Resource*> Catalog::search(std::string_view query, std::optional<Kind> kind) const {
        std::string needle = lower(query);
        std::vector<const Resource*> out;
        for (const auto& resource: resources_) {
            if (kind && resource.kind != *kind) continue;
            if (needle.empty() || lower(resource.path).find(needle) != std::string::npos) out.push_back(&resource);
        }
        return out;
    }

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

}  // namespace forti::engine
