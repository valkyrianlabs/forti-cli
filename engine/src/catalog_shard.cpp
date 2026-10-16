//
// Compiled FORTI_SHARDS times with -DFORTI_SHARD=k: instantiates the typed operations for the SDK
// endpoints whose path hashes to shard k (forti-api gap G3). The registry is the only list.
//

#include "ops.hpp"

#include <forti/engine/error.hpp>

#include <forti_api/gen/registry.hpp>

#include <algorithm>
#include <charconv>
#include <format>
#include <set>
#include <type_traits>

#ifndef FORTI_SHARD
#error "FORTI_SHARD must be defined"
#endif

namespace forti::engine::detail {
    namespace {

        template<typename T>
        concept Visitable = requires(T& object) {
            T::visit(object, [](std::string_view, auto&, std::string_view, unsigned) {});
        };

        template<typename T> struct is_vector : std::false_type {};
        template<typename T> struct is_vector<std::vector<T>> : std::true_type {};
        template<typename T> struct is_map : std::false_type {};
        template<typename T> struct is_map<std::map<std::string, T>> : std::true_type {};

        template<typename T> struct is_table : std::false_type {};
        template<typename S> struct is_table<fortiapi::Table<S>> : std::true_type {};
        template<typename T> struct is_singleton : std::false_type {};
        template<typename S> struct is_singleton<fortiapi::Singleton<S>> : std::true_type {};

        template<typename V>
        void describe(FieldInfo& info);

        template<typename T>
        std::vector<FieldInfo> fields_of() {
            std::vector<FieldInfo> out;
            if constexpr (!Visitable<T>) return out;   // monitors whose results are free-form JSON
            else {
            T object;
            T::visit(object, [&](std::string_view key, auto& field, std::string_view reset, unsigned flags) {
                using V = typename std::decay_t<decltype(field)>::value_type;
                FieldInfo info;
                info.name = key;
                info.reset = reset;
                info.read_only = (flags & fortiapi::read_only) != 0;
                describe<V>(info);
                out.push_back(std::move(info));
            });
            return out;
            }
        }

        template<typename V>
        void describe(FieldInfo& info) {
            if constexpr (std::is_same_v<V, bool>) info.type = "boolean";
            else if constexpr (std::is_integral_v<V>) info.type = "integer";
            else if constexpr (std::is_floating_point_v<V>) info.type = "number";
            else if constexpr (std::is_same_v<V, std::string>) info.type = "string";
            else if constexpr (Visitable<V>) {
                info.type = "object";
                info.children = fields_of<V>();
            } else if constexpr (is_vector<V>::value) {
                using Item = typename V::value_type;
                if constexpr (Visitable<Item>) {
                    info.type = "table";
                    info.children = fields_of<Item>();
                } else info.type = "list";
            } else if constexpr (is_map<V>::value) info.type = "map";
            else info.type = "json";
        }

        // Nested objects decoded by from_json are "populated"; an update would skip them. Mark every
        // attribute that has a value as modified so the SDK writes the assigned object as given.
        template<typename T>
        void touch(T& object) {
            T::visit(object, [](std::string_view, auto& field, std::string_view, unsigned) {
                using V = typename std::decay_t<decltype(field)>::value_type;
                if (V* value = field.storage()) {
                    if constexpr (Visitable<V>) touch(*value);
                    V copy = *value;
                    field = std::move(copy);
                }
            });
        }

        template<typename V>
        V decode_value(const nlohmann::json& value, std::string_view key) {
            try {
                return fortiapi::from_json<V>(value);
            } catch (const std::exception& error) {
                throw Failure(Code::validation, std::format("attribute {}: {}", key, error.what()),
                              {{"attribute", key}, {"value", value}});
            }
        }

        // `known`: every attribute of the resource, for "did you mean" suggestions.
        [[noreturn]] void unknown_attributes(const std::vector<std::string>& unknown, std::string_view path,
                                             const std::set<std::string, std::less<>>& known) {
            std::string list;
            std::vector<std::string> suggestions;
            for (const auto& name: unknown) {
                list += (list.empty() ? "" : ", ") + name;
                if (auto close = closest_name(name, known); !close.empty()) suggestions.push_back(close);
            }
            std::string message = std::format("{}: unknown attribute(s): {}", path, list);
            if (!suggestions.empty()) message += std::format(" (did you mean {}?)", suggestions.front());
            nlohmann::json details = {{"unknown", unknown}, {"resource", path}};
            if (!suggestions.empty()) details["suggestions"] = suggestions;
            throw Failure(Code::validation, message, details);
        }

        template<typename T>
        T build_create(const nlohmann::json& object, std::string_view path) {
            if (!object.is_object())
                throw Failure(Code::validation, std::string(path) + ": the object must be a JSON object");
            T built;
            std::set<std::string, std::less<>> known;
            std::vector<std::string> read_only;
            T::visit(built, [&](std::string_view key, auto& field, std::string_view, unsigned flags) {
                using V = typename std::decay_t<decltype(field)>::value_type;
                known.emplace(key);
                auto it = object.find(key);
                if (it == object.end()) return;
                if (flags & fortiapi::read_only) {
                    read_only.emplace_back(key);
                    return;
                }
                field = decode_value<V>(*it, key);
                if constexpr (Visitable<V>) touch(*field.storage());
            });
            std::vector<std::string> unknown;
            for (auto it = object.begin(); it != object.end(); ++it)
                if (!known.contains(it.key())) unknown.push_back(it.key());
            if (!unknown.empty()) unknown_attributes(unknown, path, known);
            if (!read_only.empty())
                throw Failure(Code::validation, std::string(path) + ": read-only attribute(s) cannot be written",
                              {{"read_only", read_only}, {"resource", path}});
            return built;
        }

        template<typename T>
        T build_update(const nlohmann::json& current, const Changes& changes, std::string_view path) {
            if (!changes.set.is_object()) throw Failure(Code::validation, std::string(path) + ": `set` must be an object");
            T object;
            try {
                object = fortiapi::from_json<T>(current);
            } catch (const std::exception& error) {
                throw Failure(Code::api, std::format("{}: the current object does not decode: {}", path, error.what()));
            }
            std::set<std::string, std::less<>> seen, known;
            std::vector<std::string> read_only;
            T::visit(object, [&](std::string_view key, auto& field, std::string_view, unsigned flags) {
                using V = typename std::decay_t<decltype(field)>::value_type;
                known.emplace(key);
                auto it = changes.set.find(key);
                bool clear = std::ranges::find(changes.clear, key) != changes.clear.end();
                if (it == changes.set.end() && !clear) return;
                seen.emplace(key);
                if (flags & fortiapi::read_only) {
                    read_only.emplace_back(key);
                    return;
                }
                if (it != changes.set.end() && clear)
                    throw Failure(Code::usage, std::format("{}: attribute {} is both set and cleared", path, key));
                if (clear) field.clear();
                else {
                    field = decode_value<V>(*it, key);
                    if constexpr (Visitable<V>) touch(*field.storage());
                }
            });
            std::vector<std::string> unknown;
            for (auto it = changes.set.begin(); it != changes.set.end(); ++it)
                if (!seen.contains(it.key())) unknown.push_back(it.key());
            for (const auto& name: changes.clear)
                if (!seen.contains(name)) unknown.push_back(name);
            if (!unknown.empty()) unknown_attributes(unknown, path, known);
            if (!read_only.empty())
                throw Failure(Code::validation, std::string(path) + ": read-only attribute(s) cannot be written",
                              {{"read_only", read_only}, {"resource", path}});
            return object;
        }

        template<typename K>
        K parse_key(const std::string& text, std::string_view path) {
            if constexpr (std::is_arithmetic_v<K>) {
                K value{};
                auto [end, ec] = std::from_chars(text.data(), text.data() + text.size(), value);
                if (ec != std::errc() || end != text.data() + text.size())
                    throw Failure(Code::validation, std::format("{}: key \"{}\" is not a number", path, text));
                return value;
            } else return K(text);
        }

        template<typename E>
        struct TableOps {
            using T = typename E::type;

            static nlohmann::json schema(fortiapi::Client& client) { return E::schema(client); }

            static nlohmann::json create_body(const nlohmann::json& object) {
                return fortiapi::to_json(build_create<T>(object, E::path), fortiapi::Write::create);
            }

            static nlohmann::json update_body(const nlohmann::json& current, const Changes& changes) {
                return fortiapi::to_json(build_update<T>(current, changes, E::path), fortiapi::Write::update);
            }

            static fortiapi::Reply create(fortiapi::Client& client, const nlohmann::json& object, const fortiapi::Query& query) {
                if constexpr (is_table<E>::value) {
                    T built = build_create<T>(object, E::path);
                    return E::add(built, query, client);
                } else throw Failure(Code::validation, std::string(E::path) + ": a singleton cannot be created");
            }

            static std::optional<fortiapi::Reply> update(fortiapi::Client& client, const nlohmann::json& current,
                                                         const Changes& changes, const fortiapi::Query& query) {
                T built = build_update<T>(current, changes, E::path);
                return E::update(built, query, client);
            }

            static fortiapi::Reply remove(fortiapi::Client& client, const std::string& key, const fortiapi::Query& query) {
                if constexpr (is_table<E>::value) return E::del(parse_key<typename E::key_type>(key, E::path), query, client);
                else throw Failure(Code::validation, std::string(E::path) + ": a singleton cannot be deleted");
            }

            static constexpr Ops ops{&fields_of<T>, &schema, &create_body, &update_body, &create, &update, &remove};
        };

        template<typename M>
        struct MonitorOps {
            static constexpr Ops ops{&fields_of<typename M::type>, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr};
        };

        // The JSON key of a table's key member (forti-api gap G5).
        template<typename E>
        std::string key_name() {
            typename E::type object;
            const void* key = &(object.*E::key);
            std::string name;
            E::type::visit(object, [&](std::string_view field_key, auto& field, std::string_view, unsigned) {
                if (static_cast<const void*>(&field) == key) name = field_key;
            });
            return name;
        }

        constexpr bool in_shard(std::string_view path) { return fnv1a(path) % FORTI_SHARDS == FORTI_SHARD; }

    }  // namespace

    template<>
    void collect<FORTI_SHARD>(std::vector<Resource>& out) {
        fortiapi::gen::for_each_endpoint([&]<typename E>() {
            if constexpr (in_shard(E::path)) {
                Resource resource;
                resource.path = E::path;
                resource.ops = &TableOps<E>::ops;
                if constexpr (is_table<E>::value) {
                    resource.kind = Kind::table;
                    resource.key = key_name<E>();
                    resource.numeric_key = std::is_arithmetic_v<typename E::key_type>;
                } else resource.kind = Kind::singleton;
                out.push_back(std::move(resource));
            }
        });
        fortiapi::gen::for_each_monitor([&]<typename M>() {
            if constexpr (in_shard(M::path)) {
                Resource resource;
                resource.path = fortiapi::Monitor::path(M::path);
                resource.kind = Kind::monitor;
                resource.list = std::is_same_v<typename M::result_type, std::vector<typename M::type>>;
                resource.ops = &MonitorOps<M>::ops;
                out.push_back(std::move(resource));
            }
        });
    }

}  // namespace forti::engine::detail
