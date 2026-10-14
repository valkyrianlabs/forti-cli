//
// The resource catalog: every endpoint forti-api generates, reflected at compile time from
// fortiapi::gen::for_each_endpoint / for_each_monitor. The engine keeps no list of its own; a
// resource added to the SDK appears here on the next build.
//
// Names: cmdb resources drop the "cmdb/" prefix ("firewall/address", "firewall.service/custom");
// monitor resources keep theirs ("monitor/system/status"). Monitor paths the SDK has no typed spec for
// are still readable (untyped) through Catalog::resolve.
//

#ifndef FORTI_ENGINE_CATALOG_HPP
#define FORTI_ENGINE_CATALOG_HPP

#include <nlohmann/json.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace forti::engine {

    // The FortiOS version forti-api's models were generated from (forti-api gap G8: not exported).
    inline constexpr std::string_view sdk_schema_version = "7.4.8";

    enum class Kind : std::uint8_t { table, singleton, monitor };

    std::string_view to_string(Kind kind);

    // One attribute, as the SDK's generated visit() describes it.
    struct FieldInfo {
        std::string name;    // FortiOS key ("srcintf")
        std::string type;    // string | integer | number | boolean | object | table | list | map
        std::string reset;   // JSON the attribute resets to (clear())
        bool read_only = false;
        std::vector<FieldInfo> children;   // object / table entries

        [[nodiscard]] nlohmann::json to_json(bool recursive = true) const;
    };

    namespace detail {
        struct Ops;   // typed operations (engine-internal, engine/src/ops.hpp)
    }

    struct Resource {
        std::string path;    // SDK API path: "cmdb/firewall/address", "monitor/system/status"
        Kind kind = Kind::table;
        std::string key;     // tables: the key attribute ("name", "policyid")
        bool numeric_key = false;
        bool list = false;   // monitor: `results` is an array
        const detail::Ops* ops = nullptr;   // null: untyped monitor path

        // User-facing name: path without "cmdb/".
        [[nodiscard]] std::string_view name() const;
        [[nodiscard]] bool typed() const { return ops != nullptr; }
        [[nodiscard]] bool writable() const { return kind != Kind::monitor; }

        // Top-level attributes (empty for untyped monitors).
        [[nodiscard]] std::vector<FieldInfo> fields() const;
        [[nodiscard]] const FieldInfo* field(std::string_view name, const std::vector<FieldInfo>& fields) const;

        // Compact descriptor: {"resource", "kind", "key"?, "typed"}.
        [[nodiscard]] nlohmann::json summary() const;
    };

    class Catalog {
        std::vector<Resource> resources_;   // sorted by name()

        Catalog();

    public:
        static const Catalog& instance();

        [[nodiscard]] const std::vector<Resource>& resources() const { return resources_; }
        [[nodiscard]] std::size_t size() const { return resources_.size(); }

        // Exact lookup of a catalog entry by user-facing name or API path; nullptr when unknown.
        [[nodiscard]] const Resource* find(std::string_view name) const;

        // Lookup that also accepts untyped monitor paths ("monitor/router/ipv4"). Throws Failure
        // (unknown_resource with suggestions, or usage for a malformed path).
        [[nodiscard]] Resource resolve(std::string_view name) const;

        // Case-insensitive substring search over names, optionally restricted to one kind.
        [[nodiscard]] std::vector<const Resource*> search(std::string_view query, std::optional<Kind> kind = {}) const;

        // Up to `limit` names close to an unknown one (shared path segments, substrings).
        [[nodiscard]] std::vector<std::string> suggest(std::string_view name, std::size_t limit = 5) const;
    };

}  // namespace forti::engine

#endif  // FORTI_ENGINE_CATALOG_HPP
