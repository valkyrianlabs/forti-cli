//
// Reading: `forti get`, `forti discover` and `forti devices`.
//
// Resources are named as people name them: the API path (firewall/address), FortiOS CLI words
// (forti get firewall address), an unambiguous tail of them (forti get address), and a table object
// by its path (forti get firewall/address/web). The engine resolves them (Catalog::lookup), so the
// MCP tools accept the same spellings.
//

#include "commands.hpp"

#include <algorithm>
#include <format>
#include <ostream>

namespace forti::cli {

    using engine::Code;
    using engine::Failure;
    using json = nlohmann::json;

    namespace {

        void common(json& request, const Args& args) {
            if (auto profile = args.value("profile")) request["profile"] = *profile;
        }

        // ---- get ----

        std::string joined(const std::vector<std::string>& words) {
            std::string out;
            for (const auto& word: words) out += (out.empty() ? "" : " ") + word;
            return out;
        }

        // The resource and key in `forti get WORD...`: the longest leading run of words that names a
        // resource (CLI words: "firewall service custom"), then at most one key. Otherwise the plain
        // form, <resource> [key], so the engine reports what is wrong.
        void resource_and_key(const std::vector<std::string>& words, json& request) {
            const auto& catalog = engine::Catalog::instance();
            for (std::size_t take = words.size(); words.size() > 1 && take >= 1 && words.size() - take <= 1; --take) {
                auto found = catalog.match(std::vector<std::string>(words.begin(), words.begin() + static_cast<std::ptrdiff_t>(take)));
                if (found.resource) {
                    request["resource"] = std::string(found.resource->name());
                    if (take < words.size()) request["key"] = words[take];
                    return;
                }
                if (!found.candidates.empty()) break;   // ambiguous: the engine names the candidates
            }
            if (words.size() > 2)
                throw Failure(Code::usage, std::format("no resource is named \"{}\"", joined(words)),
                              {{"hint", "forti get <resource> [key], e.g. forti get firewall address web; "
                                        "`forti discover <search>` lists resources"}});
            request["resource"] = words[0];
            if (words.size() == 2) request["key"] = words[1];
        }

        // Pager hints go to standard error, so a pipeline never mistakes them for data, and a
        // pipeline that got one page is told so.
        void paging_hints(const Context& context, const json& meta) {
            if (!meta.is_object()) return;
            if (meta.contains("next_start"))
                *context.output.err << std::format("forti: more results: --start {}, or --all to read every page\n",
                                                   meta["next_start"].get<std::size_t>());
            else if (meta.value("truncated", false))
                *context.output.err << std::format("forti: showing {} of {}: --count, or --all\n", meta.value("returned", 0),
                                                   meta.value("total", 0));
        }

        // Every page of a listing: start, then next_start until the device has no more.
        json read_all(Context& context, json request, engine::Engine::Secrets secrets) {
            if (!request.contains("count")) request["count"] = engine::max_page;
            json pages = engine::Engine::envelope([&] { return context.engine.read(request, secrets); });
            if (!pages.value("ok", false) || !pages["data"].is_array()) return pages;
            json& meta = pages["meta"];
            while (meta.contains("next_start")) {
                std::size_t next = meta["next_start"].get<std::size_t>();
                if (next <= request.value("start", std::size_t{0})) break;   // a device that does not advance
                request["start"] = next;
                json page = engine::Engine::envelope([&] { return context.engine.read(request, secrets); });
                if (!page.value("ok", false)) return page;
                for (auto& item: page["data"]) pages["data"].push_back(std::move(item));
                meta.erase("next_start");
                if (page["meta"].contains("next_start")) meta["next_start"] = page["meta"]["next_start"];
                if (page["meta"].contains("redacted")) {
                    if (!meta.contains("redacted")) meta["redacted"] = json::array();
                    for (const auto& path: page["meta"]["redacted"])
                        if (std::find(meta["redacted"].begin(), meta["redacted"].end(), path) == meta["redacted"].end())
                            meta["redacted"].push_back(path);
                }
            }
            meta.erase("truncated");
            meta.erase("total");
            meta["start"] = 0;
            meta["returned"] = pages["data"].size();
            meta["all"] = true;
            return pages;
        }

        int run_get(Context& context, const Args& args) {
            if (args.positional.empty())
                throw Failure(Code::usage, "usage: forti get <resource> [key] (see forti get --help)");
            json request = json::object();
            resource_and_key(args.positional, request);
            common(request, args);
            if (auto vdom = args.value("vdom")) request["vdom"] = *vdom;
            if (auto filters = args.all("filter"); !filters.empty()) request["filter"] = filters;
            std::vector<std::string> fields;
            for (const auto& list: args.all("fields"))
                for (auto& field: split_list(list)) fields.push_back(std::move(field));
            if (!fields.empty()) request["fields"] = fields;
            if (auto start = args.value("start")) request["start"] = to_count("start", *start);
            if (auto count = args.value("count")) request["count"] = to_count("count", *count);
            if (auto params = args.all("param"); !params.empty()) {
                json object = json::object();
                for (const auto& param: params) {
                    auto eq = param.find('=');
                    if (eq == std::string::npos || eq == 0) throw Failure(Code::usage, "--param expects name=value");
                    object[param.substr(0, eq)] = param.substr(eq + 1);
                }
                request["params"] = std::move(object);
            }
            // Device secrets (ENC values, passwords, keys) are redacted unless a person asks for them.
            // --reveal prints them only to a terminal, or as --json where the caller chose the format
            // deliberately; never into a pipe or file by accident.
            auto secrets = engine::Engine::Secrets::redact;
            if (args.flag("reveal")) {
                if (!context.output.tty && context.output.format != Format::json)
                    throw Failure(Code::usage, "--reveal prints device secrets: it needs a terminal, or --json",
                                  {{"hint", "run it in a terminal, or add --json if you mean to capture the secrets"}});
                *context.output.err << "forti: --reveal: the output contains device secrets (ENC values, keys, "
                                       "passwords); do not paste or share it\n";
                secrets = engine::Engine::Secrets::reveal;
            }
            if (args.flag("all") && (request.contains("key") || args.value("start")))
                throw Failure(Code::usage, "--all reads every item of a listing: it takes no key and no --start");
            json result = args.flag("all") ? read_all(context, request, secrets)
                                           : engine::Engine::envelope([&] { return context.engine.read(request, secrets); });
            // The renderer leaves the pager hints out; they go to standard error below.
            auto table = table_renderer(fields);
            int status = emit(context.output, result, [&](std::ostream& out, const json& data, const json& meta) {
                json shown = meta;
                if (shown.is_object()) {
                    shown.erase("next_start");
                    shown.erase("truncated");
                }
                table(out, data, shown);
            });
            if (result.value("ok", false) && result.contains("meta")) paging_hints(context, result["meta"]);
            return status;
        }

        // ---- discover ----

        void render_resource(std::ostream& out, const json& data, const json&) {
            out << data.value("resource", "") << "  (" << data.value("kind", "");
            if (data.contains("key")) out << ", key " << data["key"].get<std::string>();
            out << ", risk " << data.value("risk", "") << ")\n";
            if (data.contains("live_help")) out << data["live_help"].get<std::string>() << "\n";
            out << "\n";
            for (const auto& field: data.value("fields", json::array())) {
                std::string type = field.value("type", "");
                if (field.contains("children")) type += field["children"].is_number()
                                                        ? std::format("[{}]", field["children"].get<int>()) : "[…]";
                if (field.value("read_only", false)) type += " ro";
                out << std::format("  {:<32} {:<14} {}\n", field.value("name", ""), type,
                                   field.contains("help") ? field["help"].get<std::string>() : "");
            }
        }

        int run_discover(Context& context, const Args& args) {
            json request = json::object();
            common(request, args);
            std::string target = joined(args.positional);
            // Several words are CLI words for one resource (forti discover firewall address); one word
            // is a search unless it names a resource exactly.
            bool exact = !target.empty() && (args.positional.size() > 1 || engine::Catalog::instance().find(target) ||
                                             target.starts_with("monitor/"));
            if (exact || args.value("fields") || args.flag("live")) {
                if (target.empty()) throw Failure(Code::usage, "--fields and --live need a resource");
                request["what"] = "resource";
                request["resource"] = target;
                if (auto fields = args.value("fields")) request["fields"] = split_list(*fields);
                if (args.flag("live")) request["live"] = true;
                return emit(context.output, engine::Engine::envelope([&] { return context.engine.discover(request); }),
                            render_resource);
            }
            request["what"] = "resources";
            request["query"] = target;
            if (auto kind = args.value("kind")) request["kind"] = *kind;
            if (auto start = args.value("start")) request["start"] = to_count("start", *start);
            request["count"] = args.value("count") ? to_count("count", *args.value("count")) : engine::max_page;
            return emit(context.output, engine::Engine::envelope([&] { return context.engine.discover(request); }));
        }

        int run_devices(Context& context, const Args&) {
            return emit(context.output, engine::Engine::envelope([&] { return context.engine.discover({{"what", "devices"}}); }),
                        render_profiles);
        }

    }  // namespace

    std::vector<Command> read_commands() {
        return {
            {"devices", "List configured device profiles (short for `forti profile list`)",
             "usage: forti devices\n\nLists the configured profiles; the default is marked with *.\n", {}, run_devices},
            {"discover", "Find resources and show their attributes",
             "usage: forti discover [search]            list resources matching a search\n"
             "       forti discover <resource>          show a resource's attributes\n"
             "\n"
             "A resource is its path (firewall/address) or its FortiOS CLI words (firewall address).\n"
             "\n"
             "  --kind table|singleton|monitor   restrict a search\n"
             "  --fields a,b                     full detail for these attributes\n"
             "  --live                           merge the device's schema (help, options, ranges)\n"
             "  --start N --count N              page through a search\n",
             {{"kind", "fields", "start", "count"}, {"live"}, {}}, run_discover},
            {"get", "Read configuration or monitor data",
             "usage: forti get <resource> [key]\n"
             "\n"
             "The resource is its path (firewall/address), its FortiOS CLI words (firewall address,\n"
             "firewall service custom) or, when only one resource has it, its last word (address). A\n"
             "table object can also be read by its path: forti get firewall/address/web.\n"
             "\n"
             "  --filter EXPR      FortiOS filter, repeatable (AND); ',' inside one is OR (name==a,name==b)\n"
             "  --fields a,b       return only these attributes\n"
             "  --all              read every page of a listing\n"
             "  --start N          first item (default 0)\n"
             "  --count N          items per page (default 50, max 1000)\n"
             "  --param name=val   extra query parameter (monitor endpoints)\n"
             "  --reveal           show device secrets (ENC values, keys, passwords) instead of <redacted>;\n"
             "                     needs a terminal or --json, and warns on stderr\n"
             "\n"
             "A listing returns one page. When there are more, forti says so on standard error (never in the\n"
             "data): add --all, or --start N for the next page.\n"
             "Device secrets are redacted by default (meta.redacted lists where). The MCP server cannot reveal them.\n"
             "\n"
             "examples:\n"
             "  forti get firewall/policy --fields policyid,name,action --all\n"
             "  forti get firewall address \"LAN 10.0.0.0/24\"\n"
             "  forti get system interface port1\n"
             "  forti get monitor/system/status\n",
             {{"filter", "fields", "start", "count", "param"}, {"reveal", "all"}, {}}, run_get},
        };
    }

}  // namespace forti::cli
