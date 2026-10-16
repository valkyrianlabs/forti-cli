//
// The catalog's operations from forti-api's runtime schema (ops.hpp). fortiapi::schema reproduces
// the typed models exactly (forti-api checks every endpoint against them): the same decoding, the same
// bodies, the same paths. This file keeps the engine's own error wording on top of it.
//

#include "ops.hpp"

#include <forti/engine/error.hpp>

#include <forti_api/schema.hpp>

#include <algorithm>
#include <charconv>
#include <format>

namespace forti::engine::detail {

    namespace fs = fortiapi::schema;
    using json = nlohmann::json;

    namespace {

        std::vector<FieldInfo> fields_of(const fs::Type& type);

        // The same type names the typed reflection gave (describe<V>).
        void describe(const fs::Field& field, FieldInfo& info) {
            switch (field.kind) {
                case fs::Kind::boolean: info.type = "boolean"; break;
                case fs::Kind::uint32:
                case fs::Kind::int64: info.type = "integer"; break;
                case fs::Kind::number: info.type = "number"; break;
                case fs::Kind::string: info.type = "string"; break;
                case fs::Kind::json: info.type = "json"; break;
                case fs::Kind::object:
                    info.type = "object";
                    if (field.type) info.children = fields_of(*field.type);
                    break;
                case fs::Kind::array:
                    if (field.item && field.item->kind == fs::Kind::object && field.item->type) {
                        info.type = "table";
                        info.children = fields_of(*field.item->type);
                    } else info.type = "list";
                    break;
                case fs::Kind::map: info.type = "map"; break;
            }
        }

        std::vector<FieldInfo> fields_of(const fs::Type& type) {
            std::vector<FieldInfo> out;
            for (const fs::Field& field: type.fields) {
                FieldInfo info;
                info.name = field.name;
                info.reset = field.reset;
                info.read_only = field.read_only;
                describe(field, info);
                out.push_back(std::move(info));
            }
            return out;
        }

        const fs::Endpoint& endpoint(const Resource& resource) {
            if (!resource.schema || !resource.schema->type)
                throw Failure(Code::validation, std::format("{}: not a configuration resource", resource.path));
            return *resource.schema;
        }

        std::string join(const std::vector<std::string>& names) {
            std::string list;
            for (const auto& name: names) list += (list.empty() ? "" : ", ") + name;
            return list;
        }

        // forti-api's ValidationError, in the engine's words (the same messages and details the typed
        // operations produced). `input` is the object (create) or `set` (update).
        [[noreturn]] void rethrow(const fs::ValidationError& error, const fs::Endpoint& ep, const json& input, bool update) {
            std::string path(ep.path);
            using Reason = fs::ValidationError::Reason;
            switch (error.reason()) {
                case Reason::not_object:
                    throw Failure(Code::validation, update ? path + ": `set` must be an object" : path + ": the object must be a JSON object");
                case Reason::invalid_value: {
                    json value = input.is_object() && input.contains(error.attribute()) ? input.at(error.attribute()) : json();
                    throw Failure(Code::validation, std::format("attribute {}: {}", error.attribute(), error.detail()),
                                  {{"attribute", error.attribute()}, {"value", value}});
                }
                case Reason::unknown: {
                    std::set<std::string, std::less<>> known;
                    for (const fs::Field& field: ep.type->fields) known.emplace(field.name);
                    std::vector<std::string> suggestions;
                    for (const auto& name: error.attributes())
                        if (auto close = closest_name(name, known); !close.empty()) suggestions.push_back(close);
                    std::string message = std::format("{}: unknown attribute(s): {}", path, join(error.attributes()));
                    if (!suggestions.empty()) message += std::format(" (did you mean {}?)", suggestions.front());
                    json details = {{"unknown", error.attributes()}, {"resource", path}};
                    if (!suggestions.empty()) details["suggestions"] = suggestions;
                    throw Failure(Code::validation, message, details);
                }
                case Reason::read_only:
                    throw Failure(Code::validation, path + ": read-only attribute(s) cannot be written",
                                  {{"read_only", error.attributes()}, {"resource", path}});
                case Reason::set_and_cleared:
                    throw Failure(Code::usage, std::format("{}: attribute {} is both set and cleared", path, error.attribute()));
            }
            throw Failure(Code::validation, std::format("{}: {}", path, error.what()));
        }

        // The current object as the typed model reads it; the SDK refuses to update what it cannot read.
        json decode_current(const fs::Endpoint& ep, const json& current) {
            try {
                return fs::decode(*ep.type, current);
            } catch (const std::exception& error) {
                throw Failure(Code::api, std::format("{}: the current object does not decode: {}", ep.path, error.what()));
            }
        }

        void check_key(const fs::Endpoint& ep, const std::string& text) {
            if (ep.key_kind == fs::Kind::string) return;
            bool valid = !text.empty();
            if (ep.key_kind == fs::Kind::uint32) {
                std::uint32_t value{};
                auto [end, ec] = std::from_chars(text.data(), text.data() + text.size(), value);
                valid = valid && ec == std::errc() && end == text.data() + text.size();
            } else {
                std::int64_t value{};
                auto [end, ec] = std::from_chars(text.data(), text.data() + text.size(), value);
                valid = valid && ec == std::errc() && end == text.data() + text.size();
            }
            if (!valid) throw Failure(Code::validation, std::format("{}: key \"{}\" is not a number", ep.path, text));
        }

    }  // namespace

    std::vector<Resource> collect() {
        std::vector<Resource> out;
        for (const fs::Endpoint& ep: fs::endpoints()) {
            Resource resource;
            resource.path = ep.path;
            resource.schema = &ep;
            switch (ep.kind) {
                case fs::EndpointKind::table:
                    resource.kind = Kind::table;
                    resource.key = ep.key;
                    resource.numeric_key = ep.key_kind != fs::Kind::string;
                    break;
                case fs::EndpointKind::singleton: resource.kind = Kind::singleton; break;
                case fs::EndpointKind::monitor:
                    resource.kind = Kind::monitor;
                    resource.list = ep.value && ep.value->kind == fs::Kind::array;
                    break;
            }
            out.push_back(std::move(resource));
        }
        return out;
    }

    std::vector<FieldInfo> fields(const Resource& resource) {
        return resource.schema && resource.schema->type ? fields_of(*resource.schema->type) : std::vector<FieldInfo>{};
    }

    json live_schema(const Resource& resource, fortiapi::Client& client) {
        const fs::Endpoint& ep = endpoint(resource);
        return fortiapi::detail::results(client.get(ep.path, fortiapi::Query().action("schema")), ep.path);
    }

    json create_body(const Resource& resource, const json& object) {
        const fs::Endpoint& ep = endpoint(resource);
        try {
            return fs::create_body(*ep.type, object);
        } catch (const fs::ValidationError& error) {
            rethrow(error, ep, object, false);
        }
    }

    json update_body(const Resource& resource, const json& current, const Changes& changes) {
        const fs::Endpoint& ep = endpoint(resource);
        if (!changes.set.is_object()) throw Failure(Code::validation, std::string(ep.path) + ": `set` must be an object");
        (void) decode_current(ep, current);
        try {
            return fs::update_body(*ep.type, changes.set, changes.clear);
        } catch (const fs::ValidationError& error) {
            rethrow(error, ep, changes.set, true);
        }
    }

    fortiapi::Reply create(const Resource& resource, fortiapi::Client& client, const json& object, const fortiapi::Query& query) {
        const fs::Endpoint& ep = endpoint(resource);
        if (ep.kind != fs::EndpointKind::table) throw Failure(Code::validation, std::string(ep.path) + ": a singleton cannot be created");
        return fortiapi::Reply::from(client.post(ep.path, create_body(resource, object), query));
    }

    std::optional<fortiapi::Reply> update(const Resource& resource, fortiapi::Client& client, const json& current,
                                          const Changes& changes, const fortiapi::Query& query) {
        const fs::Endpoint& ep = endpoint(resource);
        json body = update_body(resource, current, changes);
        // A table object is addressed by the key it has now, checked before "nothing to send", as
        // Table::update does; a singleton is its path.
        std::optional<json> key;
        if (ep.kind == fs::EndpointKind::table) {
            // Table::update addresses the object by its key member after the changes are assigned.
            json object = decode_current(ep, current);
            if (auto it = changes.set.find(std::string(ep.key)); it != changes.set.end()) object[std::string(ep.key)] = *it;
            key = fs::key_of(ep, object);
            if (!key) throw fortiapi::Error(std::string(ep.path) + ": update needs the key attribute");
        }
        if (body.empty()) return std::nullopt;
        return fortiapi::Reply::from(client.put(key ? fs::object_path(ep, *key) : std::string(ep.path), body, query));
    }

    fortiapi::Reply remove(const Resource& resource, fortiapi::Client& client, const std::string& key, const fortiapi::Query& query) {
        const fs::Endpoint& ep = endpoint(resource);
        if (ep.kind != fs::EndpointKind::table) throw Failure(Code::validation, std::string(ep.path) + ": a singleton cannot be deleted");
        check_key(ep, key);
        return fortiapi::Reply::from(client.del(fs::object_path(ep, json(key)), query));
    }

}  // namespace forti::engine::detail
