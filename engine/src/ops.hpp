//
// Engine-internal: the operations behind a catalog Resource, driven by forti-api's runtime schema
// (fortiapi::schema: every generated endpoint as data). Validation, request bodies and paths all come
// from forti-api; nothing here builds requests or knows FortiOS semantics itself. Compiled once, with
// no generated model instantiated (forti-api gap G3, resolved by the schema tables).
//

#ifndef FORTI_ENGINE_OPS_HPP
#define FORTI_ENGINE_OPS_HPP

#include <forti/engine/catalog.hpp>

#include <forti_api/client.hpp>
#include <forti_api/endpoint.hpp>

#include <optional>
#include <set>
#include <string>
#include <vector>

namespace forti::engine::detail {

    // set/clear for an update: attributes to assign (FortiOS keys → JSON values) and to reset.
    struct Changes {
        nlohmann::json set = nlohmann::json::object();
        std::vector<std::string> clear;
    };

    // Every catalog entry: the generated endpoints, sorted by path.
    std::vector<Resource> collect();

    // The attributes of a typed resource (empty for a monitor whose results stay JSON).
    std::vector<FieldInfo> fields(const Resource& resource);

    // Tables and singletons only.
    nlohmann::json live_schema(const Resource& resource, fortiapi::Client& client);

    // Validation + the exact body the SDK sends. Throw Failure(validation) for unknown or read-only
    // attributes and values that do not decode as the SDK type.
    nlohmann::json create_body(const Resource& resource, const nlohmann::json& object);                          // POST
    nlohmann::json update_body(const Resource& resource, const nlohmann::json& current, const Changes& changes);  // PUT

    // Execution through the SDK client. Writes are never retried by the SDK once sent.
    fortiapi::Reply create(const Resource& resource, fortiapi::Client& client, const nlohmann::json& object,
                           const fortiapi::Query& query);
    std::optional<fortiapi::Reply> update(const Resource& resource, fortiapi::Client& client, const nlohmann::json& current,
                                          const Changes& changes, const fortiapi::Query& query);
    fortiapi::Reply remove(const Resource& resource, fortiapi::Client& client, const std::string& key,
                           const fortiapi::Query& query);

    // The candidate closest to a misspelt name (edit distance 1 for names up to 4 characters, else up
    // to 2), for "did you mean" hints; empty when none is that close. Defined in catalog.cpp.
    std::string closest_name(std::string_view name, const std::set<std::string, std::less<>>& candidates);

}  // namespace forti::engine::detail

#endif  // FORTI_ENGINE_OPS_HPP
