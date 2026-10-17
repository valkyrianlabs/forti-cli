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
#include <forti_api/schema_types.hpp>

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

    // ---- Child tables ----
    //
    // One table attribute of a table resource's objects, entry by entry: FortiOS's child paths
    //
    //   cmdb/<path>/<parent key>/<attribute>               GET (list), POST (one new entry)
    //   cmdb/<path>/<parent key>/<attribute>/<entry key>   GET, PUT, DELETE
    //
    // as fortiapi::ChildTable<Spec, &Type::attribute> addresses them, through the runtime schema's
    // child_table / child_path / created_entry_key (the entry type and its key are the attribute's
    // item Type). A write changes one entry and leaves the others alone. What a reply's `mkey` names
    // depends on the method (fortiapi::Reply): the new entry on POST, the parent on PUT and GET.
    struct Child {
        std::string attribute;                                // "reserved-address"
        std::string key;                                      // the entry key attribute ("id", "name")
        bool numeric_key = false;
        const fortiapi::schema::Field* field = nullptr;       // the attribute (schema::child_table)
        const fortiapi::schema::Type* type = nullptr;         // the entry type
    };

    // The child table `attribute` of a table resource. Throws Failure(usage) when the resource is not
    // a typed table, Failure(validation) when `attribute` is not one of its table attributes with keyed
    // entries (details: the table attributes it has).
    Child child_of(const Resource& resource, std::string_view attribute);
    std::vector<FieldInfo> fields(const Child& child);
    // "cmdb/system.dhcp/server reserved-address": how messages name a child table.
    std::string child_label(const Resource& resource, const Child& child);
    // The child table's path for `parent` (the list), or one entry's. Both keys are one encoded path
    // segment each (fortiapi::path, so "." / ".." are escaped, G13); numeric keys must be numbers
    // (Failure(validation) otherwise).
    std::string child_path(const Resource& resource, const Child& child, const std::string& parent,
                           const std::string& key = {});

    // As create_body / update_body / create / update / remove, for one entry.
    nlohmann::json create_body(const Resource& resource, const Child& child, const nlohmann::json& object);
    nlohmann::json update_body(const Resource& resource, const Child& child, const nlohmann::json& current,
                               const Changes& changes);
    fortiapi::Reply create(const Resource& resource, const Child& child, fortiapi::Client& client, const std::string& parent,
                           const nlohmann::json& object, const fortiapi::Query& query);
    std::optional<fortiapi::Reply> update(const Resource& resource, const Child& child, fortiapi::Client& client,
                                          const std::string& parent, const std::string& key, const nlohmann::json& current,
                                          const Changes& changes, const fortiapi::Query& query);
    fortiapi::Reply remove(const Resource& resource, const Child& child, fortiapi::Client& client, const std::string& parent,
                           const std::string& key, const fortiapi::Query& query);

    // The key of the entry a child POST created, as its reply reports it, as text ("" when it does
    // not): fortiapi::schema::created_entry_key, the rule ChildTable::add uses.
    std::string created_entry_key(const Child& child, const fortiapi::Reply& reply);

    // The candidate closest to a misspelt name (edit distance 1 for names up to 4 characters, else up
    // to 2), for "did you mean" hints; empty when none is that close. Defined in catalog.cpp.
    std::string closest_name(std::string_view name, const std::set<std::string, std::less<>>& candidates);

}  // namespace forti::engine::detail

#endif  // FORTI_ENGINE_OPS_HPP
