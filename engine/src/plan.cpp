//
// Engine::plan and Engine::apply (architecture.md, "Operating modes and mutation safety").
//
// plan reads, validates through the SDK's runtime schema (ops.hpp), and stores a digest-bound plan;
// it never mutates the device. apply executes a stored plan exactly once, in order, with no retries
// after send, re-reading each object to verify it. Around that it writes a rollback plan, probes
// management connectivity after critical-risk operations, and appends a redacted audit record.
//
// Recovery aids are not guaranteed recovery: the rollback plan and the pre-change config backup of
// critical plans both need a working management path. Recovering from a management lockout needs an
// independent path the operator provides (console, out-of-band interface, device-side auto-revert).
//

#include "ops.hpp"
#include "plan_store.hpp"
#include "policy.hpp"
#include "request.hpp"
#include "session.hpp"
#include "sha256.hpp"

#include <forti/engine/engine.hpp>

#include <forti_api/client.hpp>
#include <forti_api/monitor.hpp>

#include <algorithm>
#include <format>
#include <map>
#include <set>

#include <cerrno>
#include <fcntl.h>
#include <unistd.h>

namespace forti::engine {

    namespace {

        using json = nlohmann::json;
        using detail::Risk;

        constexpr std::size_t max_operations = 200;

        // ---- request parsing ----

        using detail::allow_keys;
        using detail::text;
        using detail::validate_vdom;

        // One requested operation, validated for shape (attribute validation is the SDK's, in ops.hpp).
        struct OpRequest {
            std::string op, resource_name, key;
            // A child table operation: the parent object's key and the table attribute; `key` is then
            // the entry's key. Both empty otherwise.
            std::string parent, child;
            json set = json::object(), object = json::object(), body = json::object();
            std::vector<std::string> clear;
        };

        OpRequest parse_operation(const json& item, std::size_t index) {
            std::string where = std::format("operations[{}]", index);
            if (!item.is_object()) throw Failure(Code::usage, where + ": expected an object");
            OpRequest request;
            request.op = text(item, "op", where);
            if (request.op == "create") allow_keys(item, {"op", "resource", "object", "parent", "child"}, where);
            else if (request.op == "update") allow_keys(item, {"op", "resource", "key", "set", "clear", "parent", "child"}, where);
            else if (request.op == "delete") allow_keys(item, {"op", "resource", "key", "parent", "child"}, where);
            else if (request.op == "action") allow_keys(item, {"op", "resource", "body"}, where);
            else throw Failure(Code::usage, std::format("{}: \"op\" must be create, update, delete or action", where));
            request.resource_name = text(item, "resource", where);
            if (request.resource_name.empty()) throw Failure(Code::usage, where + ": \"resource\" is required");
            request.key = text(item, "key", where);
            if (!request.key.empty()) detail::validate_key(request.key, where);
            request.parent = text(item, "parent", where);
            request.child = text(item, "child", where);
            if (request.parent.empty() != request.child.empty())
                throw Failure(Code::usage, std::format("{}: a child table operation needs both \"parent\" (the object's key) and "
                                                       "\"child\" (its table attribute)", where));
            if (!request.parent.empty()) detail::validate_key(request.parent, where);
            if (auto it = item.find("set"); it != item.end() && !it->is_null()) {
                if (!it->is_object()) throw Failure(Code::usage, where + ": \"set\" must be an object");
                request.set = *it;
            }
            if (auto it = item.find("clear"); it != item.end() && !it->is_null()) {
                if (it->is_string()) request.clear.push_back(it->get<std::string>());
                else if (it->is_array()) {
                    for (const auto& name: *it) {
                        if (!name.is_string()) throw Failure(Code::usage, where + ": \"clear\" must list attribute names");
                        request.clear.push_back(name.get<std::string>());
                    }
                } else throw Failure(Code::usage, where + ": \"clear\" must be an array of attribute names");
            }
            if (auto it = item.find("object"); it != item.end()) {
                if (!it->is_object()) throw Failure(Code::usage, where + ": \"object\" must be an object");
                request.object = *it;
            } else if (request.op == "create") throw Failure(Code::usage, where + ": create needs \"object\"");
            if (auto it = item.find("body"); it != item.end() && !it->is_null()) {
                if (!it->is_object()) throw Failure(Code::usage, where + ": \"body\" must be an object");
                request.body = *it;
            }
            // Reads redact secrets; an agent that copies a read object into a plan would otherwise set a
            // password or PSK to the literal placeholder.
            for (const json* values: {&request.set, &request.object, &request.body}) {
                std::vector<const json*> stack{values};
                while (!stack.empty()) {
                    const json* node = stack.back();
                    stack.pop_back();
                    if (node->is_string() && node->get_ref<const std::string&>() == detail::redacted)
                        throw Failure(Code::validation,
                                      std::format("{}: \"{}\" is the placeholder reads show for a secret, not a value; "
                                                  "leave the attribute out to keep the current secret", where,
                                                  detail::redacted),
                                      {{"reason", "redacted_placeholder"}});
                    if (node->is_structured())
                        for (const auto& child: *node) stack.push_back(&child);
                }
            }
            return request;
        }

        // ---- device access ----

        // What a reply envelope says about the device (serial, version, vdom).
        struct Identity {
            std::string serial, version;

            void take(const json& body) {
                if (!body.is_object()) return;
                if (auto it = body.find("serial"); it != body.end() && it->is_string() && serial.empty()) serial = *it;
                if (auto it = body.find("version"); it != body.end() && it->is_string() && version.empty()) version = *it;
            }
        };

        fortiapi::Query query_for(const std::string& vdom) {
            fortiapi::Query query;
            if (!vdom.empty()) query.vdom(vdom);
            return query;
        }

        std::string object_path(const Resource& resource, const std::string& key) {
            return key.empty() ? resource.path : fortiapi::path(resource.path, key);
        }

        // The child table an operation addresses (nullopt for an ordinary one). `child` is checked
        // against the resource's schema: a table attribute with keyed entries.
        std::optional<detail::Child> child_for(const Resource& resource, const std::string& child) {
            if (child.empty()) return std::nullopt;
            return detail::child_of(resource, child);
        }

        // What an operation reads and writes: the object (or singleton), or one child table entry
        // (the child table itself when `key` is empty).
        std::string target_path(const Resource& resource, const std::optional<detail::Child>& child, const std::string& parent,
                                const std::string& key) {
            return child ? detail::child_path(resource, *child, parent, key) : object_path(resource, key);
        }

        // "system.dhcp/server 1 reserved-address 7" / "firewall/address web", for messages.
        std::string target_name(const Resource& resource, const std::optional<detail::Child>& child, const std::string& parent,
                                const std::string& key) {
            if (!child) return std::format("{} {}", resource.name(), key);
            return std::format("{} {} {} {}", resource.name(), parent, child->attribute, key);
        }

        // The current object at `path`, or nullopt when it does not exist (404 or no results).
        std::optional<json> read_current(fortiapi::Client& client, const std::string& path, const fortiapi::Query& query,
                                         Identity& identity) {
            fortiapi::Result result = client.exchange(fortiapi::Method::Get, path, query);
            detail::check_reply_depth(result.body, path);
            identity.take(result.body);
            if (result.http_status == 404) return std::nullopt;
            if (!result.ok()) throw fortiapi::ApiError(fortiapi::Method::Get, path, result.http_status, std::move(result.body));
            auto it = result.body.find("results");
            if (it == result.body.end()) throw Failure(Code::api, std::format("{}: the reply has no results", path));
            if (it->is_array()) {
                if (it->empty()) return std::nullopt;
                return it->front();
            }
            return *it;
        }

        // ---- values ----

        json reset_value(const FieldInfo& field) {
            if (field.reset.empty()) return nullptr;
            json value = json::parse(field.reset, nullptr, false);
            return value.is_discarded() ? json(field.reset) : value;
        }

        std::optional<std::string> scalar_text(const json& value) {
            if (value.is_string()) return value.get<std::string>();
            if (value.is_number() || value.is_boolean()) return value.dump();
            return std::nullopt;
        }

        // Does the device value `have` satisfy the requested `want`? Objects: every requested
        // attribute matches (the device adds q_origin_key and defaults). Arrays: same size, each
        // requested entry matches a distinct device entry. Scalars: equal, or equal as text (FortiOS
        // reports some numbers as strings and the reverse).
        bool matches(const json& want, const json& have) {
            if (want.is_object()) {
                if (!have.is_object()) return false;
                for (auto it = want.begin(); it != want.end(); ++it)
                    if (!have.contains(it.key()) || !matches(it.value(), have[it.key()])) return false;
                return true;
            }
            if (want.is_array()) {
                if (!have.is_array() || have.size() != want.size()) return false;
                std::vector<bool> used(have.size(), false);
                for (const auto& item: want) {
                    bool found = false;
                    for (std::size_t i = 0; i < have.size() && !found; ++i)
                        if (!used[i] && matches(item, have[i])) used[i] = found = true;
                    if (!found) return false;
                }
                return true;
            }
            if (want == have) return true;
            auto a = scalar_text(want), b = scalar_text(have);
            return a && b && *a == *b;
        }

        // Identity of a table entry for the diff: its name, id, or the entry itself.
        std::string entry_id(const json& entry) {
            if (entry.is_object()) {
                for (const char* key: {"name", "id", "seq-num", "seq_num"})
                    if (auto it = entry.find(key); it != entry.end() && !it->is_null())
                        return it->is_string() ? it->get<std::string>() : it->dump();
                json copy = entry;
                copy.erase("q_origin_key");
                return copy.dump();
            }
            return entry.is_string() ? entry.get<std::string>() : entry.dump();
        }

        // FortiOS replaces table attributes wholesale: say what the replacement adds and removes.
        json table_change(const json& before, const json& after) {
            std::vector<std::string> old_ids, new_ids;
            if (before.is_array()) for (const auto& entry: before) old_ids.push_back(entry_id(entry));
            if (after.is_array()) for (const auto& entry: after) new_ids.push_back(entry_id(entry));
            json added = json::array(), removed = json::array();
            for (const auto& id: new_ids) if (std::ranges::find(old_ids, id) == old_ids.end()) added.push_back(id);
            for (const auto& id: old_ids) if (std::ranges::find(new_ids, id) == new_ids.end()) removed.push_back(id);
            return {{"replaced", true}, {"added", added}, {"removed", removed}, {"result", new_ids}};
        }

        bool is_table_type(const FieldInfo* field) { return field && (field->type == "table" || field->type == "list"); }

        // ---- building operation records ----

        // `child`: the entry's key attribute instead of the resource's.
        std::string key_of_object(const Resource& resource, const json& object, const detail::Child* child = nullptr) {
            const std::string& key = child ? child->key : resource.key;
            if (resource.kind != Kind::table || key.empty()) return {};
            auto it = object.find(key);
            if (it == object.end() || it->is_null()) return {};
            if (it->is_string()) return it->get<std::string>();
            if (it->is_number_integer() && it->get<long long>() != 0) return it->dump();   // 0: device assigns
            return {};
        }

        // The record stored in the plan for one operation. `current` is the object as read (nullopt:
        // absent); `known` is false when the state could not be read (no before-digest check then).
        json build_record(std::size_t index, const OpRequest& request, const Resource& resource,
                          const std::optional<json>& current, bool known) {
            json record = {{"index", index}, {"op", request.op}, {"resource", resource.name()},
                           {"path", resource.path}, {"kind", to_string(resource.kind)},
                           {"risk", detail::to_string(detail::risk_of(resource))}};
            if (!request.key.empty()) record["key"] = request.key;
            // A child table entry: the parent's tier (risk_of(resource)), the entry's attributes, paths
            // and before-state. Ordinary records carry neither field, so they stay as they were.
            auto child = child_for(resource, request.child);
            if (child) {
                record["parent"] = request.parent;
                record["child"] = child->attribute;
            }
            auto fields = child ? detail::fields(*child) : resource.fields();
            const std::string& key_name = child ? child->key : resource.key;
            std::string name = target_name(resource, child, request.parent, request.key);
            json details = {{"resource", resource.name()}, {"key", request.key}};
            if (child) {
                details["parent"] = request.parent;
                details["child"] = child->attribute;
            }
            json diff = json::array();

            if (request.op == "create") {
                if (current) throw Failure(Code::validation, std::format("{} already exists (use update)", name), details);
                json body = child ? detail::create_body(resource, *child, request.object) : detail::create_body(resource, request.object);
                record["object"] = request.object;
                record["before"] = nullptr;
                record["before_digest"] = known ? json(detail::digest_of(nullptr)) : json(nullptr);
                record["after"] = body;
                for (auto it = body.begin(); it != body.end(); ++it) {
                    json entry = {{"attribute", it.key()}, {"change", "add"}, {"before", nullptr}, {"after", it.value()}};
                    if (is_table_type(resource.field(it.key(), fields))) entry["table"] = table_change(json::array(), it.value());
                    diff.push_back(std::move(entry));
                }
                record["wire"] = {{"method", "POST"}, {"path", target_path(resource, child, request.parent, "")},
                                  {"body", std::move(body)}};
            } else if (request.op == "update") {
                if (!current) throw Failure(Code::not_found, std::format("{} not found", name), details);
                if (request.set.empty() && request.clear.empty())
                    throw Failure(Code::usage, std::format("{}: an update needs \"set\" or \"clear\"", resource.name()));
                // The SDK addresses the PUT by the object's key member, so renaming through set would
                // write to the new name's path: refuse it instead.
                if (!key_name.empty() &&
                    (request.set.contains(key_name) || std::ranges::find(request.clear, key_name) != request.clear.end()))
                    throw Failure(Code::validation, std::format("{}: the key attribute {} cannot be changed by an update",
                                                                child ? detail::child_label(resource, *child)
                                                                      : std::string(resource.name()), key_name));
                detail::Changes changes{request.set, request.clear};
                json body = child ? detail::update_body(resource, *child, *current, changes)
                                  : detail::update_body(resource, *current, changes);
                json after = *current;
                for (auto it = request.set.begin(); it != request.set.end(); ++it) {
                    json before = current->contains(it.key()) ? (*current)[it.key()] : json(nullptr);
                    json entry = {{"attribute", it.key()}, {"change", "set"}, {"before", before}, {"after", it.value()}};
                    if (matches(it.value(), before)) entry["unchanged"] = true;
                    if (is_table_type(resource.field(it.key(), fields))) entry["table"] = table_change(before, it.value());
                    after[it.key()] = it.value();
                    diff.push_back(std::move(entry));
                }
                for (const auto& cleared: request.clear) {
                    const FieldInfo* field = resource.field(cleared, fields);
                    json reset = field ? reset_value(*field) : json(nullptr);
                    json before = current->contains(cleared) ? (*current)[cleared] : json(nullptr);
                    json entry = {{"attribute", cleared}, {"change", "clear"}, {"before", before}, {"after", reset}};
                    if (is_table_type(field)) entry["table"] = table_change(before, reset);
                    after[cleared] = reset;
                    diff.push_back(std::move(entry));
                }
                record["set"] = request.set;
                record["clear"] = request.clear;
                record["before"] = *current;
                record["before_digest"] = detail::digest_of(*current);
                record["after"] = std::move(after);
                record["wire"] = {{"method", "PUT"}, {"path", target_path(resource, child, request.parent, request.key)},
                                  {"body", std::move(body)}};
            } else if (request.op == "delete") {
                if (!current) throw Failure(Code::not_found, std::format("{} not found", name), details);
                record["before"] = *current;
                record["before_digest"] = detail::digest_of(*current);
                record["after"] = nullptr;
                record["note"] = child ? std::format("deletes this {} entry; the object's other entries are left alone", child->attribute)
                                       : "deletes the object";
                record["wire"] = {{"method", "DELETE"}, {"path", target_path(resource, child, request.parent, request.key)},
                                  {"body", nullptr}};
            } else {   // action
                record["body"] = request.body;
                record["before"] = nullptr;
                record["before_digest"] = nullptr;
                record["after"] = nullptr;
                record["note"] = "monitor action: its side effects are not catalogued (forti-api gap G6); it cannot "
                                 "be verified by re-reading or rolled back";
                record["wire"] = {{"method", "POST"}, {"path", resource.path}, {"body", request.body}};
            }
            record["diff"] = std::move(diff);
            return record;
        }

        // Resolves and checks that the operation fits the resource.
        Resource resolve_for(const OpRequest& request, std::size_t index) {
            std::string where = std::format("operations[{}]", index);
            Resource resource = Catalog::instance().resolve(request.resource_name);
            if (request.op == "action") {
                if (resource.kind != Kind::monitor)
                    throw Failure(Code::usage, std::format("{}: action needs a monitor path (monitor/...)", where));
                return resource;
            }
            if (resource.kind == Kind::monitor || !resource.typed())
                throw Failure(Code::usage, std::format("{}: {} is a monitor endpoint: only \"action\" applies", where,
                                                       resource.name()));
            if (!request.child.empty() && resource.kind != Kind::table)
                throw Failure(Code::usage, std::format("{}: {} is a {}: only a table's objects have child tables", where,
                                                       resource.name(), to_string(resource.kind)));
            if (resource.kind == Kind::singleton && request.op != "update")
                throw Failure(Code::usage, std::format("{}: {} is a singleton: only update applies", where, resource.name()));
            if (!request.child.empty()) {
                detail::Child child = detail::child_of(resource, request.child);
                if (request.op != "create" && request.key.empty())
                    throw Failure(Code::usage, std::format("{}: {} needs \"key\": the {} entry's {}", where, request.op,
                                                           child.attribute, child.key));
                return resource;
            }
            if (resource.kind == Kind::table && request.op != "create" && request.key.empty())
                throw Failure(Code::usage, std::format("{}: {} needs \"key\" ({})", where, request.op, resource.key));
            if (resource.kind == Kind::singleton && !request.key.empty())
                throw Failure(Code::usage, std::format("{}: {} is a singleton and has no key", where, resource.name()));
            return resource;
        }

        json make_plan(json device, json operations, detail::Clock::time_point time, std::string kind,
                       std::string rollback_of = {}, std::string id = {}) {
            json plan = {{"format", detail::plan_format},
                         {"id", id.empty() ? detail::new_plan_id(time) : std::move(id)},
                         {"kind", std::move(kind)},
                         {"created_at", detail::iso8601(time)},
                         // Orders plans made within one second (`latest`); outside the digest.
                         {"created_ns", std::chrono::duration_cast<std::chrono::nanoseconds>(time.time_since_epoch()).count()},
                         {"device", std::move(device)},
                         {"operations", std::move(operations)}};
            if (!rollback_of.empty()) plan["rollback_of"] = rollback_of;
            Risk risk = detail::plan_risk(plan);
            plan["risk"] = detail::to_string(risk);
            plan["summary"] = detail::summarize(plan);
            plan["digest"] = detail::plan_digest(plan);
            return plan;
        }

        // Error details and messages may echo a value; never let a sensitive one out.
        Failure redacted_failure(const Failure& failure) {
            json details = detail::redact(failure.details());
            // Top-level "key" in engine details is the object's name (a table key), not an attribute.
            if (auto it = failure.details().find("key"); it != failure.details().end()) details["key"] = *it;
            // So is each operation's "key" in an apply's execution record: the record must still say which
            // objects a stopped apply touched.
            if (auto ops = failure.details().find("operations"); ops != failure.details().end() && ops->is_array())
                for (std::size_t i = 0; i < ops->size() && i < details["operations"].size(); ++i)
                    if (auto key = (*ops)[i].find("key"); (*ops)[i].is_object() && key != (*ops)[i].end())
                        details["operations"][i]["key"] = *key;
            std::string message = failure.what();
            if (auto it = failure.details().find("attribute"); it != failure.details().end() && it->is_string() &&
                                                                 detail::sensitive_name(it->get<std::string>()))
                message = std::format("attribute {}: invalid value (redacted)", it->get<std::string>());
            return {failure.code(), message, std::move(details)};
        }

        json mode_notes(const Profile& profile, const std::string& id) {
            json notes = json::array();
            switch (profile.mode) {
                case Mode::read_only:
                    notes.push_back(std::format("profile {0} is read-only: apply will be refused. To allow changes, a human runs "
                                                "`forti profile mode {0} guarded` (each plan approved) or `autonomous`",
                                                profile.name));
                    break;
                case Mode::guarded:
                    notes.push_back(std::format("guarded mode: a human must run `forti approve {}` before apply", id));
                    break;
                case Mode::autonomous:
                    notes.push_back("autonomous mode: apply executes this plan without a human approval");
                    break;
            }
            return notes;
        }

        constexpr std::string_view recovery_limitation =
                "Rollback plans and config backups need a working management path to the device; they are not "
                "independent recovery. Recovering from a management lockout needs the operator's independent path "
                "(console, out-of-band interface, or a device-side auto-revert).";

    }  // namespace

    // ---- plan ----

    json Engine::plan(const json& request) {
        try {
            allow_keys(request, {"profile", "vdom", "operations"}, "plan");
            const Profile& profile = this->profile(text(request, "profile", "plan"));
            std::string vdom = text(request, "vdom", "plan");
            if (vdom.empty()) vdom = profile.vdom;
            validate_vdom(vdom);
            auto operations_it = request.find("operations");
            if (operations_it == request.end() || !operations_it->is_array() || operations_it->empty())
                throw Failure(Code::usage, "plan: \"operations\" must be a non-empty array");
            if (operations_it->size() > max_operations)
                throw Failure(Code::usage, std::format("plan: at most {} operations per plan", max_operations));

            // Shape and catalog checks for every operation before the first device read.
            std::vector<std::pair<OpRequest, Resource>> parsed;
            std::set<std::string> targets;
            for (std::size_t i = 0; i < operations_it->size(); ++i) {
                OpRequest op = parse_operation((*operations_it)[i], i);
                Resource resource = resolve_for(op, i);
                auto child = child_for(resource, op.child);
                if (op.op == "create") {
                    // A new entry is checked before its parent is read (an ordinary create's check
                    // needs no read at all).
                    if (child) (void) detail::create_body(resource, *child, op.object);
                    op.key = key_of_object(resource, op.object, child ? &*child : nullptr);
                    // The key is used for the existence check now and for a rollback delete later.
                    if (!op.key.empty()) detail::validate_key(op.key, std::format("operations[{}]", i));
                }
                // One operation per object: each before-state is read once, before anything runs.
                if (op.op != "action" && !(op.op == "create" && op.key.empty()) &&
                    !targets.insert(target_path(resource, child, op.parent, op.key)).second)
                    throw Failure(Code::usage, std::format("operations[{}]: {} appears more than once in the plan",
                                                           i, target_name(resource, child, op.parent, op.key)));
                parsed.emplace_back(std::move(op), std::move(resource));
            }

            fortiapi::Client& client = this->client(profile);
            fortiapi::Query query = query_for(vdom);
            Identity identity;
            json records = json::array();
            for (std::size_t i = 0; i < parsed.size(); ++i) {
                const auto& [op, resource] = parsed[i];
                std::optional<json> current;
                bool known = false;
                bool needs_read = op.op == "update" || op.op == "delete" || (op.op == "create" && !op.key.empty());
                auto child = child_for(resource, op.child);
                if (needs_read) {
                    std::string path = child ? detail::child_path(resource, *child, op.parent, op.key)
                                             : object_path(resource, resource.kind == Kind::table ? op.key : "");
                    current = read_current(client, path, query, identity);
                    known = true;
                } else if (child && op.op == "create") {
                    // A new entry with a device-assigned key has no before-state of its own, but its
                    // parent must exist. Read once here, never digested: other entries may change.
                    std::string path = detail::child_path(resource, *child, op.parent);
                    fortiapi::Result result = client.exchange(fortiapi::Method::Get, path, query);
                    detail::check_reply_depth(result.body, path);
                    identity.take(result.body);
                    if (result.http_status == 404)
                        throw Failure(Code::not_found, std::format("{} {} not found", resource.name(), op.parent),
                                      {{"resource", resource.name()}, {"key", op.parent}, {"child", child->attribute}});
                    if (!result.ok())
                        throw fortiapi::ApiError(fortiapi::Method::Get, path, result.http_status, std::move(result.body));
                }
                records.push_back(build_record(i, op, resource, current, known));
            }
            if (identity.serial.empty()) identity.take(client.get(fortiapi::Monitor::path("system/status"), query));
            if (identity.serial.empty())
                throw Failure(Code::api, "the device did not report its serial number; cannot bind the plan to it");

            json device = {{"profile", profile.name}, {"host", profile.host}, {"port", profile.port},
                           {"vdom", vdom}, {"serial", identity.serial}, {"version", identity.version}};
            json plan = make_plan(std::move(device), std::move(records), detail::Clock::now(), "plan");
            detail::save_plan(options_.paths, plan);

            json data = detail::plan_view(plan);
            std::string id = plan["id"];
            data["mode"] = to_string(profile.mode);
            data["notes"] = mode_notes(profile, id);
            if (detail::plan_risk(plan) == Risk::critical)
                data["notes"].push_back(std::format("critical risk: apply first saves a configuration backup "
                                                    "(state/backups/{}.conf, owner-only) and probes management "
                                                    "connectivity after each critical operation. {}", id,
                                                    recovery_limitation));
            // Writing a child table through its parent replaces the whole list. The plan's drift check
            // covers the whole object until apply re-reads it, but a list written from an old copy
            // reverts other writers' entry changes: say how to change one entry instead.
            for (std::size_t i = 0; i < parsed.size(); ++i) {
                const auto& [op, resource] = parsed[i];
                if (op.op != "update" || !op.child.empty() || resource.kind != Kind::table) continue;
                std::vector<std::string> touched;
                for (auto it = op.set.begin(); it != op.set.end(); ++it) touched.push_back(it.key());
                touched.insert(touched.end(), op.clear.begin(), op.clear.end());
                for (const auto& attribute: touched) {
                    try {
                        (void) detail::child_of(resource, attribute);
                    } catch (const Failure&) {
                        continue;
                    }
                    data["notes"].push_back(std::format(
                            "operations[{0}] replaces the whole {1} table of {2} {3}: entries changed by others after "
                            "apply re-reads it are reverted. To change one entry, use a child table operation "
                            "(\"parent\": \"{3}\", \"child\": \"{1}\"; forti set {2} <entry> --parent {3} --child {1})",
                            i, attribute, resource.name(), op.key));
                }
            }
            data["apply"] = std::format("forti apply {}", id);
            if (profile.mode == Mode::guarded) data["approve"] = std::format("forti approve {}", id);
            return ok(std::move(data), {{"profile", profile.name}, {"vdom", vdom}});
        } catch (...) {
            throw redacted_failure(translate(std::current_exception()));
        }
    }

    // ---- apply ----

    namespace {

        constexpr std::string_view audit_failure_note =
                "the audit record of this apply could not be appended to audit.jsonl (disk full, permissions?)";

        // Backups hold the device's reversible secrets: keep only the most recent ones (by mtime), always
        // including the one just written. Best effort: a backup that cannot be pruned is left in place.
        constexpr std::size_t kept_backups = 20;

        void prune_backups(const std::filesystem::path& dir, const std::filesystem::path& keep) {
            namespace fs = std::filesystem;
            std::vector<std::pair<fs::file_time_type, fs::path>> backups;
            std::error_code error;
            for (const auto& entry: fs::directory_iterator(dir, error)) {
                std::error_code ignored;
                if (entry.path().extension() != ".conf" || !entry.is_regular_file(ignored) || entry.is_symlink(ignored)) continue;
                if (entry.path() == keep) continue;
                backups.emplace_back(entry.last_write_time(ignored), entry.path());
            }
            if (backups.size() < kept_backups) return;
            std::ranges::sort(backups, std::greater<>{}, &std::pair<fs::file_time_type, fs::path>::first);
            for (std::size_t i = kept_backups - 1; i < backups.size(); ++i) {
                std::error_code ignored;
                fs::remove(backups[i].second, ignored);
            }
        }

        // The device's full configuration, taken before a critical-risk plan runs. Streamed through the
        // SDK's bounded download straight into <state>/backups/<plan id>.conf (0600, directory 0700): never
        // buffered whole, logged, or echoed. A recovery *aid*: restoring it needs a working management
        // path, exactly like the rollback plan (architecture.md, "Recovery aids, not guaranteed recovery").
        //
        // Throws Failure(policy_denied) when the backup cannot be taken: a critical plan does not run
        // without it unless the profile opts out (backup_before_critical: false).
        json pre_change_backup(fortiapi::Client& client, const Paths& paths, const Profile& profile, const std::string& id) {
            if (!profile.backup_before_critical)
                return {{"status", "skipped"}, {"reason", "backup_before_critical is false in the profile"}};
            constexpr std::size_t max_bytes = 256u << 20;
            auto dir = paths.state / "backups";
            ensure_private_dir(paths.state);
            ensure_private_dir(dir);
            auto file = dir / (id + ".conf");
            // Per process: two concurrent applies of one plan (only one passes mark_applied later) must not
            // unlink or rename each other's half-written file.
            auto partial = dir / std::format("{}.conf.partial.{}", id, ::getpid());
            ::unlink(partial.c_str());   // a leftover from a crashed attempt that had this pid
            int fd = ::open(partial.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
            if (fd < 0) throw Failure(Code::config, std::format("cannot create {}", partial.string()));

            detail::Sha256 hash;
            std::string head;   // the first line, to recognize a FortiOS configuration
            auto fail = [&](const std::string& why) -> Failure {
                ::close(fd);
                ::unlink(partial.c_str());
                return Failure(Code::policy_denied,
                               std::format("pre-change configuration backup failed: {}. A critical plan does not run "
                                           "without one; fix the cause (the API account needs read access to the "
                                           "configuration backup) or set \"backup_before_critical\": false in profile {}",
                                           why, profile.name),
                               {{"plan_id", id}, {"reason", "backup_failed"}});
            };
            try {
                fortiapi::DownloadOptions options;
                options.max_bytes = max_bytes;
                options.sink = [&](std::string_view chunk) {
                    if (head.size() < 64) head.append(chunk.substr(0, 64 - head.size()));
                    hash.update(chunk);
                    for (std::size_t written = 0; written < chunk.size();) {
                        ssize_t n = ::write(fd, chunk.data() + written, chunk.size() - written);
                        if (n < 0 && errno == EINTR) continue;
                        if (n <= 0) throw std::runtime_error("cannot write the backup file");
                        written += static_cast<std::size_t>(n);
                    }
                };
                auto download = fortiapi::Monitor::download("system/config/backup", fortiapi::Query().set("scope", "global"),
                                                             options, client);
                if (!head.starts_with("#config-version=")) throw fail("the device did not return a configuration file");
                if (::fsync(fd) != 0) throw fail("cannot flush the backup file");
                ::close(fd);
                if (::rename(partial.c_str(), file.c_str()) != 0) {
                    ::unlink(partial.c_str());
                    throw Failure(Code::config, std::format("cannot store {}", file.string()));
                }
                prune_backups(dir, file);
                return {{"status", "saved"}, {"path", file.string()}, {"bytes", download.bytes},
                        {"sha256", detail::hex(hash.finish())}};
            } catch (const Failure&) {
                throw;
            } catch (...) {
                throw fail(translate(std::current_exception()).what());
            }
        }

        struct Executed {
            std::string status;          // verified | applied_unverified | failed | outcome_unknown | not_attempted
            bool sent = false;           // the request may have reached the device
            bool changed = false;        // the device may differ from the before-state (rollback needed)
            std::string key;             // the object's key after the operation (device-assigned for creates)
            std::optional<json> post;    // the object as re-read afterwards (nullopt: absent)
            bool post_known = false;
            json record = json::object();
        };

        // The inverse of one executed operation. nullopt when nothing needs undoing; throws Failure when
        // no inverse exists.
        std::optional<OpRequest> inverse(const json& op, const Resource& resource, const Executed& done) {
            std::string kind = op["op"];
            if (kind == "action") throw Failure(Code::validation, "monitor actions cannot be rolled back");
            const json& before = op["before"];
            OpRequest undo;
            undo.resource_name = std::string(resource.name());
            // A child table operation is undone on the same entry of the same parent.
            undo.parent = op.value("parent", "");
            undo.child = op.value("child", "");
            auto child = child_for(resource, undo.child);
            if (kind == "create") {
                if (done.post_known && !done.post) return std::nullopt;   // nothing was created
                if (done.key.empty()) throw Failure(Code::validation, "the created object's key is unknown");
                undo.op = "delete";
                undo.key = done.key;
            } else if (kind == "update") {
                undo.op = "update";
                undo.key = op.value("key", "");
                for (auto it = op["set"].begin(); it != op["set"].end(); ++it) {
                    if (before.contains(it.key())) undo.set[it.key()] = before[it.key()];
                    else undo.clear.push_back(it.key());
                }
                for (const auto& name: op["clear"]) {
                    std::string attribute = name;
                    if (before.contains(attribute)) undo.set[attribute] = before[attribute];
                }
                if (undo.set.empty() && undo.clear.empty()) return std::nullopt;
            } else {   // delete: re-create from the writable attributes of the before-state
                if (done.post_known && done.post) return std::nullopt;   // still there
                undo.op = "create";
                undo.key = op.value("key", "");
                for (const auto& field: child ? detail::fields(*child) : resource.fields())
                    if (!field.read_only && before.contains(field.name) && !before[field.name].is_null())
                        undo.object[field.name] = before[field.name];
            }
            return undo;
        }

        // Writes the rollback plan for the operations that may have changed the device (reverse order).
        // `id` set: rewrite that (provisional) rollback plan in place, or remove it when nothing needs
        // undoing.
        json write_rollback(const Paths& paths, const json& plan, const std::vector<Executed>& executed,
                            const std::string& id = {}, bool provisional = false) {
            json operations = json::array();
            json skipped = json::array();
            const json& ops = plan["operations"];
            for (std::size_t n = executed.size(); n-- > 0;) {
                const Executed& done = executed[n];
                if (!done.changed) continue;
                const json& op = ops[n];
                try {
                    Resource resource = Catalog::instance().resolve(op["resource"].get<std::string>());
                    auto undo = inverse(op, resource, done);
                    if (!undo) continue;
                    // The rollback starts from the re-read post-state. When that is unknown (outcome
                    // unknown, failed re-read) the planned after-state stands in and its before-digest
                    // is not checked: apply of the rollback still re-reads before writing.
                    std::optional<json> state = done.post;
                    if (!done.post_known && undo->op != "create") state = op["after"];
                    if (!done.post_known && undo->op == "create") state = std::nullopt;
                    json record = build_record(operations.size(), *undo, resource, state, done.post_known);
                    if (!done.post_known) record["before_digest"] = nullptr;
                    operations.push_back(std::move(record));
                } catch (...) {
                    Failure failure = redacted_failure(translate(std::current_exception()));
                    skipped.push_back({{"index", n}, {"op", op["op"]}, {"resource", op["resource"]},
                                       {"reason", failure.what()}});
                }
            }
            json out = {{"skipped", std::move(skipped)}};
            if (operations.empty()) {
                if (!id.empty()) {
                    std::error_code ignored;
                    std::filesystem::remove(detail::plan_file(paths, id), ignored);
                }
                out["plan_id"] = nullptr;
                return out;
            }
            json rollback = make_plan(plan["device"], std::move(operations), detail::Clock::now(), "rollback",
                                      plan["id"].get<std::string>(), id);
            if (provisional) {
                rollback["provisional"] = true;   // informational, outside the digest
                out["provisional"] = true;
            }
            detail::save_plan(paths, rollback);
            out["plan_id"] = rollback["id"];
            out["apply"] = std::format("forti apply {}", rollback["id"].get<std::string>());
            out["limitation"] = recovery_limitation;
            return out;
        }

        // A fresh client (new connection) reads monitor/system/status: is the management path alive
        // and still the same device?
        json probe(const Options& options, SecretStore& secrets, const Profile& profile, const std::string& serial,
                   const std::string& vdom) {
            try {
                auto fresh = detail::make_client(options, secrets, profile, 1u);
                Identity identity;
                identity.take(fresh->get(fortiapi::Monitor::path("system/status"), query_for(vdom)));
                if (!identity.serial.empty() && identity.serial != serial)
                    return {{"ok", false}, {"error", "the management address now answers with another serial number"}};
                return {{"ok", true}};
            } catch (...) {
                return {{"ok", false}, {"error", redacted_failure(translate(std::current_exception())).what()}};
            }
        }

        json attribute_names(const json& op) {
            json names = json::array();
            for (const char* key: {"set", "object", "body"})
                if (auto it = op.find(key); it != op.end() && it->is_object())
                    for (auto field = it->begin(); field != it->end(); ++field) names.push_back(field.key());
            if (auto it = op.find("clear"); it != op.end()) for (const auto& name: *it) names.push_back(name);
            return names;
        }

    }  // namespace

    json Engine::apply(const json& request) {
        const Paths& paths = options_.paths;
        json event = {{"event", "apply"}};
        try {
            allow_keys(request, {"plan_id"}, "apply");
            std::string id = text(request, "plan_id", "apply");
            if (id.empty()) throw Failure(Code::usage, "apply: \"plan_id\" is required");
            detail::validate_plan_id(id);
            event["plan_id"] = id;
            if (!options_.actor.empty()) event["actor"] = options_.actor;

            json plan = detail::load_plan(paths, id);
            event["summary"] = detail::summarize(plan);
            const json& device = plan["device"];
            Risk risk = detail::plan_risk(plan);
            event["digest"] = plan["digest"];
            event["profile"] = device.value("profile", "");
            event["host"] = device.value("host", "");
            event["serial"] = device.value("serial", "");
            event["risk"] = detail::to_string(risk);
            if (plan.value("kind", "plan") == "rollback") event["rollback_of"] = plan.value("rollback_of", "");

            if (detail::plan_applied(paths, id))
                throw Failure(Code::policy_denied, std::format("plan {} was already applied; a plan runs at most once", id),
                              {{"plan_id", id}, {"reason", "already_applied"}});
            const Profile& profile = this->profile(device.value("profile", ""));
            event["mode"] = to_string(profile.mode);
            if (profile.mode == Mode::read_only)
                throw Failure(Code::policy_denied,
                              std::format("profile {0} is read-only: apply is refused. To allow changes, a human runs "
                                          "`forti profile mode {0} guarded` (each plan approved) or `autonomous`",
                                          profile.name),
                              {{"plan_id", id}, {"reason", "read_only"}, {"profile", profile.name}, {"mode", "read-only"},
                               {"mode_command", std::format("forti profile mode {} guarded", profile.name)}});
            auto now = detail::Clock::now();
            if (profile.mode == Mode::guarded) {
                detail::verify_approval(paths, plan, now);
                if (auto approval = detail::load_approval(paths, id); approval && approval->is_object()) {
                    event["approved_by"] = approval->value("approved_by", "");
                    event["approved_at"] = approval->value("approved_at", "");
                }
            }
            if (profile.host != device.value("host", "") || profile.port != device.value("port", 0u))
                throw Failure(Code::stale_plan,
                              std::format("profile {} now points at {}:{}, not the planned {}:{}", profile.name, profile.host,
                                          profile.port, device.value("host", ""), device.value("port", 0u)),
                              {{"plan_id", id}, {"reason", "device_identity"}});

            std::string vdom = device.value("vdom", "");
            fortiapi::Query query = query_for(vdom);
            fortiapi::Client& client = this->client(profile);
            Identity identity;

            // Re-read every before-state; anything that moved makes the plan stale.
            const json& ops = plan["operations"];
            std::vector<Resource> resources;
            std::vector<std::optional<json>> currents(ops.size());
            for (std::size_t i = 0; i < ops.size(); ++i) {
                const json& op = ops[i];
                resources.push_back(Catalog::instance().resolve(op["resource"].get<std::string>()));
                const Resource& resource = resources.back();
                std::string kind = op["op"];
                std::string key = op.value("key", "");
                std::string parent = op.value("parent", "");
                auto child = child_for(resource, op.value("child", ""));
                bool read = kind == "update" || kind == "delete" || (kind == "create" && op["before_digest"].is_string());
                if (!read) continue;
                // A child table operation re-reads only its entry: changes to the parent's other
                // entries do not make it stale.
                currents[i] = read_current(client,
                                           child ? detail::child_path(resource, *child, parent, key)
                                                 : object_path(resource, resource.kind == Kind::table ? key : ""),
                                           query, identity);
                auto stale = [&](std::string_view reason, std::string_view what) {
                    json details = {{"plan_id", id}, {"reason", reason}, {"index", i}, {"resource", resource.name()},
                                    {"key", key}};
                    if (child) {
                        details["parent"] = parent;
                        details["child"] = child->attribute;
                    }
                    throw Failure(Code::stale_plan,
                                  std::format("{} {} since plan {} was made; plan again", target_name(resource, child, parent, key),
                                              what, id),
                                  std::move(details));
                };
                if ((kind == "update" || kind == "delete") && !currents[i]) stale("before_changed", "no longer exists");
                if (op["before_digest"].is_string() && detail::digest_of(currents[i] ? *currents[i] : json(nullptr)) !=
                                                       op["before_digest"].get<std::string>())
                    stale("before_changed", "changed");
                if (kind == "update") {
                    detail::Changes changes{op["set"], op["clear"].get<std::vector<std::string>>()};
                    json body = child ? detail::update_body(resource, *child, *currents[i], changes)
                                      : detail::update_body(resource, *currents[i], changes);
                    if (body != op["wire"]["body"]) stale("wire_changed", "would now be written differently");
                } else if (kind == "create" && (child ? detail::create_body(resource, *child, op["object"])
                                                      : detail::create_body(resource, op["object"])) != op["wire"]["body"]) {
                    stale("wire_changed", "would now be written differently");
                }
            }
            if (identity.serial.empty()) identity.take(client.get(fortiapi::Monitor::path("system/status"), query));
            if (identity.serial != device.value("serial", ""))
                throw Failure(Code::stale_plan,
                              std::format("the device at {} reports serial {}, not the planned {}; plan again",
                                          profile.host, identity.serial.empty() ? "(none)" : identity.serial,
                                          device.value("serial", "")),
                              {{"plan_id", id}, {"reason", "device_serial"}});

            // The audit record is written after execution; make sure it can be before anything changes.
            if (!detail::audit_writable(paths))
                throw Failure(Code::config,
                              std::format("cannot open the audit log {} for appending; apply refused before any change",
                                          (paths.state / "audit.jsonl").string()),
                              {{"plan_id", id}, {"reason", "audit_unwritable"}});

            json backup = nullptr;
            if (risk == Risk::critical) backup = pre_change_backup(client, paths, profile, id);

            // Committed: the plan can never run again (an atomic marker: of two concurrent applies only
            // one gets past this line), and a guarded approval is used up.
            detail::mark_applied(paths, id, now);
            if (profile.mode == Mode::guarded) detail::consume_approval(paths, id, now);

            // A provisional rollback plan exists before the first mutation, so a crash mid-apply still
            // leaves one: every operation counts as possibly applied, with its post-state unknown (no
            // before-digest checks). It is rewritten in place once the outcome is known.
            std::vector<Executed> assumed(ops.size());
            for (std::size_t i = 0; i < ops.size(); ++i) {
                assumed[i].sent = assumed[i].changed = true;
                assumed[i].key = ops[i].value("key", "");
            }
            json provisional = write_rollback(paths, plan, assumed, {}, true);
            std::string rollback_id = provisional["plan_id"].is_string() ? provisional["plan_id"].get<std::string>() : "";
            event["rollback_plan"] = provisional["plan_id"];

            std::vector<Executed> executed(ops.size());
            std::optional<std::size_t> lost_at;
            json probe_error = nullptr;
            bool stop = false;
            for (std::size_t i = 0; i < ops.size(); ++i) {
                Executed& done = executed[i];
                const json& op = ops[i];
                const Resource& resource = resources[i];
                std::string kind = op["op"];
                done.key = op.value("key", "");
                std::string parent = op.value("parent", "");
                auto child = child_for(resource, op.value("child", ""));
                done.record = {{"index", i}, {"op", kind}, {"resource", resource.name()}};
                if (!done.key.empty()) done.record["key"] = done.key;
                if (child) {
                    done.record["parent"] = parent;
                    done.record["child"] = child->attribute;
                }
                if (stop) {
                    done.status = "not_attempted";
                    done.record["status"] = done.status;
                    continue;
                }
                std::string object_key = resource.kind == Kind::table ? done.key : "";
                try {
                    if (kind == "create") {
                        done.sent = true;
                        fortiapi::Reply reply = child ? detail::create(resource, *child, client, parent, op["object"], query)
                                                      : detail::create(resource, client, op["object"], query);
                        // A child POST reports the new entry's key by its own rule (created_entry_key):
                        // recorded, so verification and the rollback delete address exactly that entry.
                        if (done.key.empty() && child) done.key = detail::created_entry_key(*child, reply);
                        else if (done.key.empty() && !reply.mkey.is_null())
                            done.key = reply.mkey.is_string() ? reply.mkey.get<std::string>() : reply.mkey.dump();
                        // A device-reported key is used for verification and the rollback delete.
                        if (!detail::addressable_key(done.key)) done.key.clear();
                        object_key = done.key;
                    } else if (kind == "update") {
                        detail::Changes changes{op["set"], op["clear"].get<std::vector<std::string>>()};
                        done.sent = true;
                        if (child) detail::update(resource, *child, client, parent, done.key, *currents[i], changes, query);
                        else detail::update(resource, client, *currents[i], changes, query);
                    } else if (kind == "delete") {
                        done.sent = true;
                        if (child) detail::remove(resource, *child, client, parent, done.key, query);
                        else detail::remove(resource, client, done.key, query);
                    } else {
                        done.sent = true;
                        fortiapi::Monitor::post(std::string_view(resource.path).substr(8), op["body"], query, client);
                    }
                    done.status = "verified";
                    done.changed = true;
                } catch (const fortiapi::TransportError& error) {
                    done.sent = !error.before_send();
                    done.changed = done.sent;
                    done.status = error.before_send() ? "failed" : "outcome_unknown";
                    done.record["sent"] = done.sent;
                    done.record["error"] = redacted_failure(translate(std::current_exception())).to_json();
                    if (!error.before_send())
                        done.record["note"] = "the request may have reached the device; its effect is unknown";
                    stop = true;
                } catch (const fortiapi::DecodeError&) {
                    // The device answered 2xx, so the request was accepted, but the reply could not be
                    // read: the effect is unknown, not "failed".
                    done.changed = true;
                    done.status = "outcome_unknown";
                    done.record["sent"] = true;
                    done.record["error"] = redacted_failure(translate(std::current_exception())).to_json();
                    done.record["note"] = "the device accepted the request (HTTP 2xx) but its reply could not be "
                                          "decoded; its effect is unknown";
                    stop = true;
                } catch (...) {
                    done.status = "failed";
                    done.changed = done.sent;   // until the re-read below says otherwise
                    done.record["error"] = redacted_failure(translate(std::current_exception())).to_json();
                    stop = true;
                }
                if (!done.key.empty()) done.record["key"] = done.key;

                // Re-read: verify a success; after a FortiOS error, see what was left behind (creates
                // are not transactional).
                if (done.status == "verified" || (done.status == "failed" && done.sent && kind != "action")) {
                    if (kind == "action") {
                        done.status = "applied_unverified";
                        done.record["verification"] = "monitor actions cannot be verified by re-reading";
                    } else if (resource.kind == Kind::table && object_key.empty()) {
                        if (done.status == "verified") done.status = "applied_unverified";
                        done.record["verification"] = child ? "the created entry's key was not reported (child_mkey)"
                                                            : "the created object's key was not reported";
                    } else {
                        try {
                            Identity ignored;
                            done.post = read_current(client,
                                                     child ? detail::child_path(resource, *child, parent, object_key)
                                                           : object_path(resource, object_key),
                                                     query, ignored);
                            done.post_known = true;
                        } catch (...) {
                            done.record["verification"] = std::string("re-read failed: ") +
                                                          redacted_failure(translate(std::current_exception())).what();
                        }
                    }
                    if (done.status == "failed") {
                        if (done.post_known) {
                            if (kind == "create" && done.post) {
                                done.record["exists_after_failure"] = true;
                                done.record["note"] = "FortiOS creates are not transactional: the object exists "
                                                      "although the create failed";
                            } else if (kind != "create" &&
                                       json(detail::digest_of(done.post ? *done.post : json(nullptr))) != op["before_digest"]) {
                                done.record["changed_after_failure"] = true;
                            }
                            done.changed = done.record.contains("exists_after_failure") ||
                                           done.record.contains("changed_after_failure");
                        }
                    } else if (done.status == "verified" && !done.post_known) {
                        done.status = "applied_unverified";
                    } else if (done.status == "verified") {
                        json mismatches = json::array();
                        auto expect = [&](const std::string& attribute, const json& want) {
                            json have = done.post && done.post->contains(attribute) ? (*done.post)[attribute] : json(nullptr);
                            if (!matches(want, have))
                                mismatches.push_back({{"attribute", attribute}, {"expected", want}, {"actual", have}});
                        };
                        if (kind == "create") {
                            if (!done.post) done.record["verification"] = "the object was not found after the create";
                            else
                                for (auto it = op["object"].begin(); it != op["object"].end(); ++it) {
                                    // A device-assigned entry key (0 or absent in the request) is the reported one.
                                    if (child && it.key() == child->key && !op.contains("key")) continue;
                                    expect(it.key(), it.value());
                                }
                        } else if (kind == "update") {
                            if (!done.post) done.record["verification"] = "the object was not found after the update";
                            else {
                                for (auto it = op["set"].begin(); it != op["set"].end(); ++it) expect(it.key(), it.value());
                                auto fields = child ? detail::fields(*child) : resource.fields();
                                for (const auto& name: op["clear"]) {
                                    const FieldInfo* field = resource.field(name.get<std::string>(), fields);
                                    expect(name, field ? reset_value(*field) : json(nullptr));
                                }
                            }
                        } else if (kind == "delete" && done.post) {
                            done.record["verification"] = "the object still exists after the delete";
                        }
                        if (!mismatches.empty()) {
                            done.record["mismatches"] = detail::redact(mismatches);
                            done.record["verification"] = "the device reports values other than those written (FortiOS "
                                                          "normalizes some values, e.g. 192.0.2.0/24 → 192.0.2.0 255.255.255.0)";
                        }
                        if (done.record.contains("verification")) done.status = "applied_unverified";
                    }
                }
                done.record["status"] = done.status;

                // Management connectivity after a critical change that may have reached the device.
                // Monitor actions included: a critical one (reboot, restore, upgrade) is exactly when the
                // management path is most likely gone.
                if (done.sent && detail::risk_of(resource) == Risk::critical) {
                    json result = probe(options_, *secrets_, profile, device.value("serial", ""), vdom);
                    done.record["management_probe"] = result;
                    if (!result.value("ok", false)) {
                        lost_at = i;
                        probe_error = result["error"];
                        stop = true;
                    }
                }
            }

            json rollback = rollback_id.empty() ? write_rollback(paths, plan, executed)
                                                : write_rollback(paths, plan, executed, rollback_id);
            json records = json::array();
            json audit_ops = json::array();
            std::size_t verified = 0, unverified = 0;
            bool failed = false, unknown = false;
            for (std::size_t i = 0; i < executed.size(); ++i) {
                records.push_back(executed[i].record);
                json entry = {{"index", i}, {"op", ops[i]["op"]}, {"resource", ops[i]["resource"]},
                              {"status", executed[i].status}, {"attributes", attribute_names(ops[i])}};
                if (!executed[i].key.empty()) entry["key"] = executed[i].key;
                for (const char* field: {"parent", "child"})
                    if (auto it = ops[i].find(field); it != ops[i].end()) entry[field] = *it;
                audit_ops.push_back(std::move(entry));
                verified += executed[i].status == "verified";
                unverified += executed[i].status == "applied_unverified";
                failed = failed || executed[i].status == "failed";
                unknown = unknown || executed[i].status == "outcome_unknown";
            }
            event["operations"] = audit_ops;
            event["rollback_plan"] = rollback["plan_id"];
            if (!backup.is_null()) event["backup"] = backup.value("status", "");

            json record = {{"plan_id", id}, {"digest", plan["digest"]}, {"operations", records},
                           {"verified", verified}, {"applied_unverified", unverified}, {"rollback", rollback}};
            if (!backup.is_null()) record["backup"] = backup;

            if (lost_at) {
                const json& op = ops[*lost_at];
                record["before"] = detail::redact(op["before"]);
                record["probe_error"] = probe_error;
                record["recovery"] = recovery_limitation;
                throw Failure(Code::management_connectivity_lost,
                              std::format("management connectivity to {} was lost after operation {} ({} {}); the "
                                          "remaining operations were not attempted. {} Rollback plan: {}",
                                          profile.host, *lost_at, op["op"].get<std::string>(), op["resource"].get<std::string>(),
                                          recovery_limitation,
                                          rollback["plan_id"].is_string() ? rollback["plan_id"].get<std::string>() : "none"),
                              std::move(record));
            }
            if (unknown)
                throw Failure(Code::outcome_unknown,
                              std::format("plan {}: a request may have reached the device but no reply arrived; "
                                          "execution stopped. Re-read the device before planning again", id),
                              std::move(record));
            if (failed)
                throw Failure(Code::partial_failure,
                              std::format("plan {}: execution stopped at a failed operation; see the record for what was "
                                          "applied", id),
                              std::move(record));
            event["outcome"] = "ok";
            record["status"] = "applied";
            // The changes are made; a failed audit write does not undo them, but it is never silent.
            if (!detail::audit(paths, event)) record["audit_error"] = audit_failure_note;
            return ok(std::move(record), {{"profile", profile.name}, {"vdom", vdom}});
        } catch (...) {
            Failure failure = redacted_failure(translate(std::current_exception()));
            event["outcome"] = to_string(failure.code());
            event["error"] = {{"code", to_string(failure.code())}, {"message", failure.what()}};
            if (auto it = failure.details().find("reason"); it != failure.details().end()) event["error"]["reason"] = *it;
            if (!detail::audit(paths, event) && failure.details().contains("operations")) {
                json details = failure.details();
                details["audit_error"] = audit_failure_note;
                throw Failure(failure.code(), failure.what(), std::move(details));
            }
            throw failure;
        }
    }

}  // namespace forti::engine
