#include "commands.hpp"

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

        int run_get(Context& context, const Args& args) {
            if (args.positional.empty() || args.positional.size() > 2)
                throw Failure(Code::usage, "usage: forti get <resource> [key] (see forti get --help)");
            json request = {{"resource", args.positional[0]}};
            if (args.positional.size() == 2) request["key"] = args.positional[1];
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
            return emit(context.output, engine::Engine::envelope([&] { return context.engine.read(request); }));
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
            if (args.positional.size() > 1) throw Failure(Code::usage, "usage: forti discover [resource|search]");
            json request = json::object();
            common(request, args);
            std::string target = args.positional.empty() ? "" : args.positional[0];
            bool exact = !target.empty() && (engine::Catalog::instance().find(target) || target.starts_with("monitor/"));
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
            return emit(context.output, engine::Engine::envelope([&] { return context.engine.discover({{"what", "devices"}}); }));
        }

    }  // namespace

    std::vector<Command> read_commands() {
        return {
            {"devices", "List configured device profiles", "usage: forti devices", {}, run_devices},
            {"discover", "Find resources and show their attributes",
             "usage: forti discover [search]            list resources matching a search\n"
             "       forti discover <resource>          show a resource's attributes\n"
             "\n"
             "  --kind table|singleton|monitor   restrict a search\n"
             "  --fields a,b                     full detail for these attributes\n"
             "  --live                           merge the device's schema (help, options, ranges)\n"
             "  --start N --count N              page through a search\n",
             {{"kind", "fields", "start", "count"}, {"live"}, {}}, run_discover},
            {"get", "Read configuration or monitor data",
             "usage: forti get <resource> [key]\n"
             "\n"
             "  --filter EXPR      FortiOS filter, repeatable (AND); ',' inside one is OR (name==a,name==b)\n"
             "  --fields a,b       return only these attributes\n"
             "  --start N          first item (default 0)\n"
             "  --count N          items per page (default 50, max 1000)\n"
             "  --param name=val   extra query parameter (monitor endpoints)\n"
             "\n"
             "examples:\n"
             "  forti get firewall/policy --fields policyid,name,action\n"
             "  forti get firewall/address \"LAN 10.0.0.0/24\"\n"
             "  forti get monitor/system/status\n",
             {{"filter", "fields", "start", "count", "param"}, {}, {}}, run_get},
        };
    }

}  // namespace forti::cli
