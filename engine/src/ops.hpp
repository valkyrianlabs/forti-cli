//
// Engine-internal: the typed operations behind a catalog Resource. One Ops table per generated SDK
// endpoint, instantiated in catalog_shard.cpp; everything here forwards to forti-api (from_json,
// Field<T>, Table/Singleton, to_json). Nothing builds requests or knows FortiOS semantics itself.
//

#ifndef FORTI_ENGINE_OPS_HPP
#define FORTI_ENGINE_OPS_HPP

#include <forti/engine/catalog.hpp>

#include <forti_api/client.hpp>
#include <forti_api/endpoint.hpp>

#include <optional>
#include <string>
#include <vector>

namespace forti::engine::detail {

    // set/clear for an update: attributes to assign (FortiOS keys → JSON values) and to reset.
    struct Changes {
        nlohmann::json set = nlohmann::json::object();
        std::vector<std::string> clear;
    };

    struct Ops {
        std::vector<FieldInfo> (*fields)();

        // Tables and singletons only (null for monitors).
        nlohmann::json (*schema)(fortiapi::Client&);

        // Validation + the exact body the SDK will send. Throw Failure(validation) for unknown or
        // read-only attributes and values that do not decode as the SDK type.
        nlohmann::json (*create_body)(const nlohmann::json& object);                         // POST
        nlohmann::json (*update_body)(const nlohmann::json& current, const Changes& changes); // PUT

        // Execution through the SDK. Writes are never retried by the SDK once sent.
        fortiapi::Reply (*create)(fortiapi::Client&, const nlohmann::json& object, const fortiapi::Query&);
        std::optional<fortiapi::Reply> (*update)(fortiapi::Client&, const nlohmann::json& current,
                                                 const Changes& changes, const fortiapi::Query&);
        fortiapi::Reply (*remove)(fortiapi::Client&, const std::string& key, const fortiapi::Query&);
    };

    // Collected by each shard: catalog entries for the endpoints whose path hashes to that shard.
    template<unsigned Shard>
    void collect(std::vector<Resource>& out);

    constexpr unsigned fnv1a(std::string_view text) {
        unsigned hash = 2166136261u;
        for (char c: text) {
            hash ^= static_cast<unsigned char>(c);
            hash *= 16777619u;
        }
        return hash;
    }

}  // namespace forti::engine::detail

#endif  // FORTI_ENGINE_OPS_HPP
