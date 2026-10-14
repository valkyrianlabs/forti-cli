#include "app.hpp"

#include "commands.hpp"

#include <algorithm>
#include <format>
#include <ostream>

#ifndef FORTI_VERSION
#define FORTI_VERSION "0.0.0"
#endif

namespace forti::cli {

    namespace {

        using engine::Code;
        using engine::Failure;

        constexpr std::string_view global_help =
                "global options:\n"
                "  -p, --profile NAME   device profile (default: the default profile, or the only one)\n"
                "      --vdom NAME      VDOM for this request (default: the profile's, else the device's)\n"
                "      --json           print the JSON result envelope (also FORTI_OUTPUT=json)\n"
                "      --no-color       plain text (also NO_COLOR=1; color is used only on a terminal)\n"
                "  -h, --help           show help\n";

        OptionSpec merged(const OptionSpec& own) {
            auto spec = global_options();
            spec.valued.insert(own.valued.begin(), own.valued.end());
            spec.flags.insert(own.flags.begin(), own.flags.end());
            spec.short_names.insert(own.short_names.begin(), own.short_names.end());
            return spec;
        }

        std::size_t distance(std::string_view a, std::string_view b) {
            std::vector<std::size_t> row(b.size() + 1);
            for (std::size_t j = 0; j <= b.size(); ++j) row[j] = j;
            for (std::size_t i = 1; i <= a.size(); ++i) {
                std::size_t diagonal = row[0];
                row[0] = i;
                for (std::size_t j = 1; j <= b.size(); ++j) {
                    std::size_t above = row[j];
                    row[j] = std::min({row[j] + 1, row[j - 1] + 1, diagonal + (a[i - 1] == b[j - 1] ? 0 : 1)});
                    diagonal = above;
                }
            }
            return row[b.size()];
        }

        Failure unknown_command(std::string_view name) {
            std::vector<std::string> close;
            for (const auto& command: commands())
                if (distance(name, command.name) <= 2 || (name.size() >= 3 && command.name.starts_with(name)))
                    close.emplace_back(command.name);
            nlohmann::json details = {{"hint", "run `forti --help` for the list of commands"}};
            if (!close.empty()) details["suggestions"] = close;
            return {Code::usage, std::format("unknown command \"{}\"", name), details};
        }

        std::string command_help(const Command& command) {
            std::string text(command.help);
            while (!text.empty() && text.back() == '\n') text.pop_back();
            return std::format("{}\n\n{}", text, global_help);
        }

    }  // namespace

    std::string usage_text() {
        std::string text = "forti " FORTI_VERSION ": FortiOS from the command line\n\n"
                           "usage: forti [global options] <command> [arguments]\n";
        for (const auto& group: command_groups()) {
            if (group.commands.empty()) continue;
            text += std::format("\n{}:\n", group.title);
            for (const auto& command: group.commands) text += std::format("  {:<11} {}\n", command.name, command.summary);
        }
        text += "\n";
        text += global_help;
        text += "      --version        print the version and the FortiOS schema version\n"
                "\n"
                "environment:\n"
                "  FORTI_CONFIG_DIR, FORTI_STATE_DIR, FORTI_CACHE_DIR   override the XDG locations\n"
                "  FORTI_SECRET_STORE=file|keychain                      choose the secret store\n"
                "  FORTI_OUTPUT=json, NO_COLOR                           output format and color\n"
                "\n"
                "exit status: 0 ok, 1 internal error, 2 usage, 3 configuration, 4 connection or authentication,\n"
                "             5 not found, 6 validation or FortiOS error, 7 refused (mode, approval, stale plan),\n"
                "             8 partial or unknown outcome\n"
                "\n"
                "Start with `forti configure`, then `forti doctor`. `forti help <command>` shows a command's\n"
                "options; `man forti` has the full reference.\n";
        return text;
    }

    int run(const std::vector<std::string>& arguments, Output output, engine::Options options) {
        // Global flags that change how even a usage error is reported.
        for (const auto& arg: arguments) {
            if (arg == "--") break;
            if (arg == "--json") output.format = Format::json;
            if (arg == "--no-color") output.color = output.err_color = false;
        }
        auto fail = [&](const Failure& failure) { return emit(output, {{"ok", false}, {"error", failure.to_json()}}); };

        // The command is the first positional argument; global options may come before or after it.
        std::size_t command_at = 0;
        auto globals = global_options();
        bool help = false;
        while (command_at < arguments.size() && arguments[command_at].starts_with('-')) {
            const auto& arg = arguments[command_at];
            if (arg == "--version") {
                *output.out << "forti " FORTI_VERSION << " (FortiOS schema " << engine::sdk_schema_version << ")\n";
                return 0;
            }
            if (arg == "--help" || arg == "-h") help = true;
            std::string name = arg.starts_with("--") ? arg.substr(2, arg.find('=') - 2) : "";
            if (arg == "-p") name = "profile";
            bool takes_value = globals.valued.contains(name) && arg.find('=') == std::string::npos;
            command_at += takes_value ? 2 : 1;
        }
        if (command_at >= arguments.size()) {
            if (help) {
                *output.out << usage_text();
                return 0;
            }
            *output.err << usage_text();
            return engine::exit_code(Code::usage);
        }

        std::string name = arguments[command_at];
        const auto& table = commands();
        if (name == "help") {
            if (command_at + 1 >= arguments.size()) {
                *output.out << usage_text();
                return 0;
            }
            auto topic = std::ranges::find(table, arguments[command_at + 1], &Command::name);
            if (topic == table.end()) return fail(unknown_command(arguments[command_at + 1]));
            *output.out << command_help(*topic);
            return 0;
        }
        auto command = std::ranges::find(table, name, &Command::name);
        if (command == table.end()) return fail(unknown_command(name));

        std::vector<std::string> rest(arguments.begin(), arguments.begin() + static_cast<std::ptrdiff_t>(command_at));
        rest.insert(rest.end(), arguments.begin() + static_cast<std::ptrdiff_t>(command_at) + 1, arguments.end());
        try {
            Args args;
            try {
                args = parse(rest, merged(command->options));
            } catch (const Failure& failure) {
                auto details = failure.details();
                details["hint"] = std::format("run `forti {} --help`", command->name);
                throw Failure(failure.code(), failure.what(), details);
            }
            if (args.flag("help") || help) {
                *output.out << command_help(*command);
                return 0;
            }
            engine::Engine engine(std::move(options));
            Context context{engine, output};
            return command->run(context, args);
        } catch (...) {
            return fail(engine::translate(std::current_exception()));
        }
    }

}  // namespace forti::cli
