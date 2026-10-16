#include "completion.hpp"

#include "commands.hpp"

#include <completion_scripts.hpp>

#include <algorithm>
#include <filesystem>
#include <format>
#include <fstream>
#include <functional>
#include <ostream>
#include <set>

namespace forti::cli {

    using engine::Code;
    using engine::Failure;
    using json = nlohmann::json;
    namespace fs = std::filesystem;

    namespace {

        // Second words. Kept beside the commands' help texts, which a unit test checks them against
        // (CompletionTest.SubcommandsAreInTheHelp).
        const std::vector<std::pair<std::string_view, std::vector<std::string_view>>>& subcommand_table() {
            static const std::vector<std::pair<std::string_view, std::vector<std::string_view>>> table = {
                {"plan", {"set", "create", "delete", "action", "show", "list", "approve"}},
                {"profile", {"list", "show", "set", "rename", "copy", "default", "mode", "remove"}},
                {"cert", {"create", "list", "show", "use", "remove"}},
                {"mcp", {"install", "status", "repair", "uninstall"}},
                {"install", {"mcp"}},
                {"home", {"migrate"}},
                {"completion", {"bash", "zsh", "fish"}},
            };
            return table;
        }

        const Command* find_command(std::string_view name) {
            const auto& table = commands();
            auto it = std::ranges::find(table, name, &Command::name);
            return it == table.end() ? nullptr : &*it;
        }

        std::vector<std::string> command_names() {
            std::vector<std::string> names;
            for (const auto& command: commands()) names.emplace_back(command.name);
            names.emplace_back("help");
            return names;
        }

        std::vector<std::string> subcommands(std::string_view command) {
            std::vector<std::string> names;
            for (const auto& [name, words]: subcommand_table())
                if (name == command) names.assign(words.begin(), words.end());
            return names;
        }

        // The command's options and the global ones. Unknown or no command: the global options.
        std::vector<std::string> options_of(std::string_view command, bool valued_only) {
            OptionSpec spec = global_options();
            if (const Command* found = find_command(command)) {
                spec.valued.insert(found->options.valued.begin(), found->options.valued.end());
                spec.flags.insert(found->options.flags.begin(), found->options.flags.end());
                spec.short_names.insert(found->options.short_names.begin(), found->options.short_names.end());
            }
            std::vector<std::string> names;
            for (const auto& name: spec.valued) names.push_back("--" + name);
            if (!valued_only) {
                for (const auto& name: spec.flags) names.push_back("--" + name);
                if (command.empty()) names.emplace_back("--version");
                std::ranges::sort(names);
            } else {
                for (const auto& [letter, name]: spec.short_names)
                    if (spec.valued.contains(name)) names.push_back(std::string("-") + letter);
            }
            return names;
        }

        // Profile names only: config.json is not validated here (that is the commands' job), and an
        // unreadable or broken file just completes nothing.
        std::vector<std::string> profile_names(const engine::Options& options) {
            std::vector<std::string> names;
            if (options.profiles) {
                for (const auto& [name, profile]: options.profiles->profiles) names.push_back(name);
                return names;
            }
            std::ifstream in(options.paths.config_file());
            if (!in) return names;
            json config = json::parse(in, nullptr, false);
            if (!config.is_object() || !config.contains("profiles") || !config["profiles"].is_object()) return names;
            for (auto it = config["profiles"].begin(); it != config["profiles"].end(); ++it) names.push_back(it.key());
            return names;
        }

        // Plans not yet applied, newest first (ids start with their UTC time). A directory listing:
        // plan files are not loaded or verified (show and apply do that).
        std::vector<std::string> pending_plans(const engine::Paths& paths) {
            std::vector<std::string> ids;
            fs::path dir = paths.state / "plans";
            std::error_code error;
            for (const auto& entry: fs::directory_iterator(dir, error)) {
                if (entry.path().extension() != ".json") continue;
                std::string id = entry.path().stem().string();
                if (!engine::valid_plan_id(id) || fs::exists(dir / (id + ".applied"), error)) continue;
                ids.push_back(std::move(id));
            }
            std::ranges::sort(ids, std::greater<>());
            return ids;
        }

        // Resource paths one segment at a time: "" gives "firewall/", "system/", "monitor/", ...;
        // "firewall/" gives "firewall/address", "firewall/policy", ...; so no shell is handed the whole
        // catalog on an empty word, and a Tab after a directory lists what is in it.
        std::vector<std::string> resource_candidates(std::string_view prefix) {
            std::set<std::string, std::less<>> found;
            for (const auto& resource: engine::Catalog::instance().resources()) {
                std::string_view name = resource.name();
                if (!name.starts_with(prefix)) continue;
                auto slash = name.find('/', prefix.size());
                found.emplace(slash == std::string_view::npos ? name : name.substr(0, slash + 1));
            }
            return {found.begin(), found.end()};
        }

        int run_completion(Context& context, const Args& args) {
            if (args.positional.size() != 1)
                throw Failure(Code::usage, "usage: forti completion bash|zsh|fish (see forti completion --help)");
            const std::string& shell = args.positional[0];
            std::string_view script = shell == "bash" ? completion_scripts::bash
                                      : shell == "zsh" ? completion_scripts::zsh
                                      : shell == "fish" ? completion_scripts::fish : std::string_view();
            if (script.empty())
                throw Failure(Code::usage, std::format("no completion for \"{}\": forti completion bash|zsh|fish", printable(shell)));
            // The script itself, also under --json or FORTI_OUTPUT=json: it is meant for `source <(...)`.
            *context.output.out << script;
            return 0;
        }

    }  // namespace

    int complete(std::span<const std::string> arguments, const Output& output, const engine::Options& options) {
        try {
            if (arguments.empty()) return 0;
            const std::string& what = arguments[0];
            auto arg = [&](std::size_t i) { return i < arguments.size() ? arguments[i] : std::string(); };
            // WHAT takes a command name first; the prefix comes after it.
            bool per_command = what == "subcommands" || what == "options" || what == "valued";
            std::string command = per_command ? arg(1) : std::string();
            std::string prefix = arg(per_command ? 2 : 1);
            std::vector<std::string> candidates;
            if (what == "commands") candidates = command_names();
            else if (what == "subcommands") candidates = subcommands(command);
            else if (what == "options") candidates = options_of(command, false);
            else if (what == "valued") candidates = options_of(command, true);
            else if (what == "profiles") candidates = profile_names(options);
            else if (what == "modes") candidates = {"read-only", "guarded", "autonomous"};
            else if (what == "plans") candidates = pending_plans(options.paths);
            else if (what == "resources") candidates = resource_candidates(prefix);
            std::string text;
            for (const auto& candidate: candidates)
                if (candidate.starts_with(prefix) && candidate.find('\n') == std::string::npos) text += candidate + "\n";
            *output.out << text << std::flush;
        } catch (...) {
            // Completion never prints an error into someone's command line.
        }
        return 0;
    }

    std::vector<Command> completion_commands() {
        return {
            {"completion", "Print the shell completion script for bash, zsh or fish",
             "usage: forti completion bash|zsh|fish\n"
             "\n"
             "Prints a completion script: commands, subcommands, options, profile names (-p), resource paths\n"
             "(get, discover, plan set/create/delete/action), modes and the ids of plans waiting to be applied\n"
             "(apply, rollback, plan show/approve). The Homebrew formula and the .deb package install it\n"
             "already. Otherwise:\n"
             "\n"
             "  bash   add to ~/.bashrc:   source <(forti completion bash)\n"
             "  zsh    add to ~/.zshrc, after compinit:   source <(forti completion zsh)\n"
             "         (or save it as _forti in a directory on $fpath)\n"
             "  fish   forti completion fish > ~/.config/fish/completions/forti.fish\n"
             "\n"
             "On each Tab the script runs forti, which reads only the profile names in config.json and the\n"
             "plans directory: never a device, never a secret.\n",
             {}, run_completion},
        };
    }

}  // namespace forti::cli
