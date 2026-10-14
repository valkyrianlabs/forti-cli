#include "args.hpp"

#include <forti/engine/error.hpp>

#include <format>

namespace forti::cli {

    using engine::Code;
    using engine::Failure;

    std::optional<std::string> Args::value(std::string_view name) const {
        auto it = values.find(name);
        if (it == values.end() || it->second.empty()) return std::nullopt;
        return it->second.back();
    }

    std::vector<std::string> Args::all(std::string_view name) const {
        auto it = values.find(name);
        return it == values.end() ? std::vector<std::string>{} : it->second;
    }

    Args parse(std::span<const std::string> argv, const OptionSpec& spec) {
        Args args;
        bool options_done = false;
        for (std::size_t i = 0; i < argv.size(); ++i) {
            std::string_view arg = argv[i];
            if (options_done || arg == "-" || !arg.starts_with('-')) {
                args.positional.emplace_back(arg);
                continue;
            }
            if (arg == "--") {
                options_done = true;
                continue;
            }
            std::string name;
            std::optional<std::string> inline_value;
            if (arg.starts_with("--")) {
                arg.remove_prefix(2);
                if (auto eq = arg.find('='); eq != std::string_view::npos) {
                    inline_value = std::string(arg.substr(eq + 1));
                    arg = arg.substr(0, eq);
                }
                name = arg;
            } else if (arg.size() == 2) {
                auto it = spec.short_names.find(arg[1]);
                if (it == spec.short_names.end()) throw Failure(Code::usage, std::format("unknown option {}", arg));
                name = it->second;
            } else throw Failure(Code::usage, std::format("unknown option {}", arg));

            if (spec.flags.contains(name)) {
                if (inline_value) throw Failure(Code::usage, std::format("--{} takes no value", name));
                args.flags.insert(name);
            } else if (spec.valued.contains(name)) {
                if (!inline_value) {
                    if (i + 1 >= argv.size()) throw Failure(Code::usage, std::format("--{} needs a value", name));
                    inline_value = argv[++i];
                }
                args.values[name].push_back(std::move(*inline_value));
            } else throw Failure(Code::usage, std::format("unknown option --{}", name));
        }
        return args;
    }

    std::vector<std::string> split_list(std::string_view text) {
        std::vector<std::string> out;
        while (!text.empty()) {
            auto comma = text.find(',');
            auto item = text.substr(0, comma);
            if (!item.empty()) out.emplace_back(item);
            text = comma == std::string_view::npos ? std::string_view() : text.substr(comma + 1);
        }
        return out;
    }

}  // namespace forti::cli
