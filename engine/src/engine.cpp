#include "ops.hpp"
#include "policy.hpp"
#include "session.hpp"

#include <forti/engine/engine.hpp>

#include <forti_api/client.hpp>
#include <forti_api/monitor.hpp>

#include <algorithm>
#include <format>
#include <fstream>
#include <set>
#include <sstream>

namespace forti::engine {

    namespace {

        using json = nlohmann::json;

        // Requests are strict: an unknown key is an error, so a misspelled option never silently
        // changes what a read returns or what a plan does.
        void allow_keys(const json& request, std::initializer_list<std::string_view> allowed, std::string_view op) {
            if (!request.is_object()) throw Failure(Code::usage, std::format("{}: the request must be a JSON object", op));
            std::vector<std::string> unknown;
            for (auto it = request.begin(); it != request.end(); ++it)
                if (std::ranges::find(allowed, std::string_view(it.key())) == allowed.end()) unknown.push_back(it.key());
            if (!unknown.empty()) {
                std::string list;
                for (const auto& key: unknown) list += (list.empty() ? "" : ", ") + key;
                throw Failure(Code::usage, std::format("{}: unknown request field(s): {}", op, list),
                              {{"unknown", unknown}, {"allowed", allowed}});
            }
        }

        std::string text(const json& request, const char* key, std::string fallback = {}) {
            auto it = request.find(key);
            if (it == request.end() || it->is_null()) return fallback;
            if (it->is_string()) return it->get<std::string>();
            if (it->is_number_integer()) return it->dump();
            throw Failure(Code::usage, std::format("\"{}\" must be a string", key));
        }

        std::size_t number(const json& request, const char* key, std::size_t fallback) {
            auto it = request.find(key);
            if (it == request.end() || it->is_null()) return fallback;
            if (!it->is_number_unsigned() && !(it->is_number_integer() && it->get<long long>() >= 0))
                throw Failure(Code::usage, std::format("\"{}\" must be a non-negative integer", key));
            return it->get<std::size_t>();
        }

        std::vector<std::string> strings(const json& request, const char* key) {
            auto it = request.find(key);
            if (it == request.end() || it->is_null()) return {};
            if (it->is_string()) return {it->get<std::string>()};
            if (!it->is_array()) throw Failure(Code::usage, std::format("\"{}\" must be a string or an array of strings", key));
            std::vector<std::string> out;
            for (const auto& item: *it) {
                if (!item.is_string()) throw Failure(Code::usage, std::format("\"{}\" must contain only strings", key));
                out.push_back(item.get<std::string>());
            }
            return out;
        }

        bool flag(const json& request, const char* key) {
            auto it = request.find(key);
            if (it == request.end() || it->is_null()) return false;
            if (!it->is_boolean()) throw Failure(Code::usage, std::format("\"{}\" must be true or false", key));
            return it->get<bool>();
        }

        void validate_vdom(std::string_view vdom) {
            bool valid = vdom.size() <= 31;
            for (char c: vdom) valid = valid && (std::isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_' || c == '.');
            if (!valid) throw Failure(Code::usage, std::format("invalid VDOM name: {}", vdom));
        }

        // The attribute a FortiOS filter clause tests: "name==x", "type!=fqdn", "comment=@test".
        std::string filter_attribute(std::string_view clause) {
            static constexpr std::array operators = {"==", "!=", "=@", "!@", "<=", ">=", "<", ">"};
            std::size_t at = std::string_view::npos;
            for (std::string_view op: operators) at = std::min(at, clause.find(op));
            if (at == std::string_view::npos || at == 0)
                throw Failure(Code::usage, std::format("filter clause \"{}\" has no operator (==, !=, =@, !@, <, <=, >, >=)", clause));
            return std::string(clause.substr(0, at));
        }

        void check_attributes(const Resource& resource, const std::vector<std::string>& names, std::string_view what) {
            if (!resource.typed() || resource.kind == Kind::monitor || names.empty()) return;
            auto fields = resource.fields();
            std::vector<std::string> unknown;
            for (const auto& name: names)
                if (!resource.field(name, fields)) unknown.push_back(name);
            if (unknown.empty()) return;
            std::string list;
            for (const auto& name: unknown) list += (list.empty() ? "" : ", ") + name;
            throw Failure(Code::validation, std::format("{}: unknown attribute(s) in {}: {}", resource.name(), what, list),
                          {{"unknown", unknown}, {"resource", resource.name()},
                           {"hint", "forti discover <resource> lists the attributes"}});
        }

        // Query parameters a caller may add. Engine-managed ones and anything that could carry a
        // credential (access_token) are refused.
        void add_params(fortiapi::Query& query, const json& request) {
            auto it = request.find("params");
            if (it == request.end() || it->is_null()) return;
            if (!it->is_object()) throw Failure(Code::usage, "\"params\" must be an object of query parameters");
            static constexpr std::array reserved = {"vdom", "filter", "format", "start", "count", "action",
                                                    "access_token", "skip", "with_meta"};
            for (auto param = it->begin(); param != it->end(); ++param) {
                if (std::ranges::find(reserved, std::string_view(param.key())) != reserved.end())
                    throw Failure(Code::usage, std::format("query parameter \"{}\" cannot be set through params", param.key()));
                const auto& value = param.value();
                if (value.is_string()) query.set(param.key(), value.get<std::string>());
                else if (value.is_number() || value.is_boolean()) query.set(param.key(), value.dump());
                else throw Failure(Code::usage, std::format("query parameter \"{}\" must be a scalar", param.key()));
            }
        }

        json device_meta(const json& body) {
            json device = json::object();
            for (const char* key: {"serial", "version", "build"})
                if (auto it = body.find(key); it != body.end()) device[key] = *it;
            return device;
        }

    }  // namespace

    json ok(json data, json meta) {
        json out = {{"ok", true}, {"data", std::move(data)}};
        if (!meta.empty()) out["meta"] = std::move(meta);
        return out;
    }

    json Engine::envelope(const std::function<json()>& operation) {
        try {
            return operation();
        } catch (...) {
            return {{"ok", false}, {"error", translate(std::current_exception()).to_json()}};
        }
    }

    Engine::Engine(Options options) : options_(std::move(options)) {
        secrets_ = options_.secrets ? options_.secrets : default_secret_store(options_.paths);
        if (options_.profiles) profiles_ = options_.profiles;
    }

    const ProfileSet& Engine::profiles() {
        if (!profiles_) profiles_ = ProfileStore(options_.paths).load();
        return *profiles_;
    }

    const Profile& Engine::profile(std::string_view name) { return profiles().select(name); }

    namespace detail {

        std::shared_ptr<fortiapi::Client> make_client(const Options& options, SecretStore& secrets,
                                                      const Profile& profile, std::optional<unsigned> retries) {
            fortiapi::Config config;
            config.host = profile.host;
            config.port = profile.port;
            config.vdom = profile.vdom;
            config.ca_bundle = profile.ca_bundle;
            config.client_cert = profile.client_cert;
            config.resolve_ip = profile.resolve_ip;
            config.connect_timeout = std::chrono::milliseconds(profile.connect_timeout_ms);
            config.timeout = std::chrono::milliseconds(profile.timeout_ms);
            if (retries) config.retries = *retries;
            config.api_key = resolve_secret(profile.api_key, profile.api_key_account(), secrets);
            if (profile.cert_password.source != SecretRef::Source::none)
                config.client_cert_password = resolve_secret(profile.cert_password, profile.cert_password_account(), secrets);
            return options.transport ? std::make_shared<fortiapi::Client>(config, options.transport(config))
                                     : std::make_shared<fortiapi::Client>(config);
        }

    }  // namespace detail

    fortiapi::Client& Engine::client(const Profile& profile) {
        if (auto it = clients_.find(profile.name); it != clients_.end()) return *it->second;
        auto client = detail::make_client(options_, *secrets_, profile);
        return *clients_.emplace(profile.name, std::move(client)).first->second;
    }

    // ---- discover ----

    json Engine::discover(const json& request) {
        allow_keys(request, {"what", "query", "kind", "start", "count", "resource", "fields", "live", "profile"}, "discover");
        std::string what = text(request, "what", request.contains("resource") ? "resource" : "resources");

        if (what == "devices") {
            json list = json::array();
            for (const auto& [name, profile]: profiles().profiles) list.push_back(profile.describe());
            return ok(list, {{"default_profile", profiles().default_profile}});
        }

        if (what == "resources") {
            std::optional<Kind> kind;
            if (auto name = text(request, "kind"); !name.empty()) {
                if (name == "table") kind = Kind::table;
                else if (name == "singleton") kind = Kind::singleton;
                else if (name == "monitor") kind = Kind::monitor;
                else throw Failure(Code::usage, "\"kind\" must be table, singleton or monitor");
            }
            auto matches = Catalog::instance().search(text(request, "query"), kind);
            std::size_t start = number(request, "start", 0);
            std::size_t count = std::min(number(request, "count", default_page), max_page);
            json items = json::array();
            for (std::size_t i = start; i < matches.size() && items.size() < count; ++i) items.push_back(matches[i]->summary());
            json meta = {{"total", matches.size()}, {"start", start}, {"returned", items.size()}};
            if (start + items.size() < matches.size()) meta["next_start"] = start + items.size();
            meta["note"] = "monitor paths not listed here are still readable untyped (forti_read \"monitor/<path>\")";
            return ok(std::move(items), std::move(meta));
        }

        if (what == "resource") {
            Resource resource = Catalog::instance().resolve(text(request, "resource"));
            auto selected = strings(request, "fields");
            auto fields = resource.fields();
            json data = resource.summary();
            data["operations"] = {{"read", true}, {"write", detail::write_operations(resource)}};
            data["risk"] = detail::to_string(detail::risk_of(resource));
            if (!resource.typed())
                data["note"] = "no typed SDK spec: results are returned as the device sends them";

            json live = nullptr;
            if (flag(request, "live")) {
                if (!resource.ops || !resource.ops->schema)
                    throw Failure(Code::usage, std::format("{}: no live schema (monitor endpoints have none)", resource.name()));
                const Profile& profile = this->profile(text(request, "profile"));
                live = resource.ops->schema(client(profile));
            }
            auto live_child = [&](std::string_view name) -> json {
                if (!live.is_object()) return nullptr;
                auto children = live.find("children");
                if (children == live.end() || !children->contains(name)) return nullptr;
                const json& field = (*children)[std::string(name)];
                json out = json::object();
                for (const char* key: {"help", "type", "size", "min-value", "max-value", "required", "datasource",
                                       "multiple_values", "category"})
                    if (auto it = field.find(key); it != field.end()) out[key == std::string_view("type") ? "fortios_type" : key] = *it;
                if (auto it = field.find("options"); it != field.end() && it->is_array()) {
                    json names = json::array();
                    for (const auto& option: *it) if (option.contains("name")) names.push_back(option["name"]);
                    out["options"] = std::move(names);
                }
                return out;
            };

            json list = json::array();
            if (selected.empty()) {
                for (const auto& field: fields) {
                    json entry = field.to_json(false);
                    if (json extra = live_child(field.name); extra.is_object() && extra.contains("help")) entry["help"] = extra["help"];
                    list.push_back(std::move(entry));
                }
            } else {
                check_attributes(resource, selected, "fields");
                for (const auto& name: selected) {
                    json entry = resource.field(name, fields)->to_json(true);
                    if (json extra = live_child(name); extra.is_object()) entry.update(extra);
                    list.push_back(std::move(entry));
                }
            }
            data["fields"] = std::move(list);
            if (live.is_object())
                for (const char* key: {"help", "mkey", "mkey_type", "category", "max_table_size_vdom"})
                    if (auto it = live.find(key); it != live.end()) data[std::string("live_") + key] = *it;
            return ok(std::move(data), {{"schema_version", sdk_schema_version}, {"live", live.is_object()}});
        }

        if (what == "capabilities") {
            const Profile& profile = this->profile(text(request, "profile"));
            json body = client(profile).get(fortiapi::Monitor::path("system/status"));
            json device = device_meta(body);
            if (auto results = body.find("results"); results != body.end() && results->is_object())
                for (const char* key: {"hostname", "model", "model_name", "model_number"})
                    if (auto it = results->find(key); it != results->end()) device[key] = *it;
            std::string version = body.value("version", "");
            bool matches = version == std::string("v") + std::string(sdk_schema_version);
            return ok({{"profile", profile.name},
                       {"device", device},
                       {"sdk_schema_version", sdk_schema_version},
                       {"schema_matches_device", matches},
                       {"mode", to_string(profile.mode)},
                       {"resources", Catalog::instance().size()}});
        }

        throw Failure(Code::usage, std::format("discover: unknown \"what\": {} (devices, resources, resource, capabilities)", what));
    }

    // ---- read ----

    json Engine::read(const json& request) {
        allow_keys(request, {"resource", "key", "filter", "fields", "start", "count", "vdom", "profile", "params"}, "read");
        Resource resource = Catalog::instance().resolve(text(request, "resource"));
        const Profile& profile = this->profile(text(request, "profile"));

        fortiapi::Query query;
        std::string vdom = text(request, "vdom");
        if (!vdom.empty()) {
            validate_vdom(vdom);
            query.vdom(vdom);
        }

        std::string key = text(request, "key");
        if (!key.empty() && resource.kind != Kind::table)
            throw Failure(Code::usage, std::format("{} is a {}: it has no keyed objects", resource.name(), to_string(resource.kind)));

        auto fields = strings(request, "fields");
        check_attributes(resource, fields, "fields");
        if (!fields.empty()) {
            std::string joined;
            for (const auto& field: fields) joined += (joined.empty() ? "" : "|") + field;
            query.set("format", joined);
        }

        for (const auto& expression: strings(request, "filter")) {
            std::vector<std::string> attributes;
            std::string_view rest = expression;
            while (!rest.empty()) {
                auto comma = rest.find(',');
                attributes.push_back(filter_attribute(rest.substr(0, comma)));
                rest = comma == std::string_view::npos ? std::string_view() : rest.substr(comma + 1);
            }
            check_attributes(resource, attributes, "filter");
            query.filter(expression);
        }

        bool listing = key.empty() && resource.kind != Kind::singleton;
        std::size_t start = number(request, "start", 0);
        std::size_t count = std::min(number(request, "count", default_page), max_page);
        if (count == 0) throw Failure(Code::usage, "\"count\" must be at least 1");
        bool server_paging = listing && resource.kind == Kind::table;
        if (server_paging || (listing && (request.contains("start") || request.contains("count")))) {
            query.start(start);
            query.count(count);
        }
        add_params(query, request);

        std::string api_path = key.empty() ? resource.path : fortiapi::path(resource.path, key);
        json body = client(profile).get(api_path, query);
        json results = body.contains("results") ? std::move(body["results"]) : json();

        json meta = {{"resource", resource.name()}, {"profile", profile.name}, {"device", device_meta(body)}};
        if (auto it = body.find("vdom"); it != body.end()) meta["vdom"] = *it;
        if (!key.empty() && results.is_array()) {
            if (results.empty()) throw Failure(Code::not_found, std::format("{} {} not found", resource.name(), key));
            results = std::move(results.front());
        } else if (listing && results.is_array()) {
            bool truncated = false;
            if (!server_paging && results.size() > count) {   // a monitor that ignores count
                meta["total"] = results.size();
                results.erase(results.begin() + static_cast<std::ptrdiff_t>(count), results.end());
                truncated = true;
            }
            meta["start"] = start;
            meta["returned"] = results.size();
            if (server_paging && results.size() == count) meta["next_start"] = start + count;
            if (truncated) meta["truncated"] = true;
        }
        return ok(std::move(results), std::move(meta));
    }

}  // namespace forti::engine
