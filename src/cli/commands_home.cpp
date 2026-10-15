//
// `forti home`: where forti keeps everything (engine Paths: $FORTI_HOME, else ~/.forti), and
// `forti home migrate`, which moves a pre-0.2 setup (~/.config/forti, ~/.local/state/forti,
// ~/.cache/forti, or the XDG equivalents) into the home.
//
// Migration renames (atomic on one file system; copy, then rename into place, then delete across
// file systems), so modes and contents are kept. config.json moves last: until it is in the home the
// engine keeps using the old locations, so an interrupted migration leaves a working setup and running
// the command again finishes it. Keychain items are untouched (their account names do not change).
//

#include "commands.hpp"
#include "setup_support.hpp"

#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <format>
#include <cstdio>
#include <ostream>
#include <vector>

#include <sys/stat.h>
#include <unistd.h>

namespace forti::cli {

    using engine::Code;
    using engine::Failure;
    using json = nlohmann::json;
    namespace fs = std::filesystem;

    namespace {

        constexpr const char* overrides[] = {"FORTI_HOME", "FORTI_CONFIG_DIR", "FORTI_STATE_DIR", "FORTI_CACHE_DIR"};

        json overrides_in_effect() {
            json out = json::object();
            for (const char* name: overrides)
                if (const char* value = std::getenv(name); value && *value) out[name] = value;
            return out;
        }

        bool present(const fs::path& path) {
            std::error_code error;
            return fs::exists(fs::symlink_status(path, error));
        }

        json describe_home(const Context& context) {
            const auto& paths = context.engine.options().paths;
            json data = {{"home", paths.home.empty() ? paths.config.string() : paths.home.string()},
                         {"config_dir", paths.config.string()},
                         {"config_file", paths.config_file().string()},
                         {"config_exists", present(paths.config_file())},
                         {"credentials", (paths.config / "credentials").string()},
                         {"state", paths.state.string()},
                         {"cache", paths.cache.string()},
                         {"certs", paths.certs().string()},
                         {"legacy", paths.legacy},
                         {"overrides", overrides_in_effect()}};
            try {
                data["secret_store"] = std::string(context.engine.secrets().kind());
            } catch (const Failure& failure) {
                data["secret_store"] = std::string("unavailable: ") + failure.what();
            }
            if (paths.legacy)
                data["hint"] = std::format("this is a pre-0.2 setup; `forti home migrate` moves it into {}",
                                           display_path(paths.home));
            return data;
        }

        void render_home(std::ostream& out, const json& data, const json&) {
            out << styled("forti home: ", Style::bold) << display_path(data.value("home", "")) << "\n";
            auto line = [&](std::string_view label, const std::string& value, std::string_view note = {}) {
                out << std::format("  {:<12} {}", label, display_path(value));
                if (!note.empty()) out << "  " << styled(note, Style::dim);
                out << "\n";
            };
            line("config", data.value("config_file", ""), data.value("config_exists", false) ? "" : "(not configured yet)");
            line("credentials", data.value("credentials", "") + "/", "file store");
            line("state", data.value("state", "") + "/", "plans, approvals, audit log, backups");
            line("cache", data.value("cache", "") + "/");
            line("certs", data.value("certs", "") + "/", "forti cert create");
            std::string store = data.value("secret_store", "");
            out << std::format("  {:<12} {}\n", "secrets", store == "keychain" ? "macOS Keychain (service \"forti\")"
                                                         : store == "file" ? "file store (credentials/, 0600)" : store);
            for (auto it = data["overrides"].begin(); it != data["overrides"].end(); ++it)
                out << std::format("  {:<12} {}={}\n", "override", it.key(), it.value().get<std::string>());
            if (data.value("legacy", false))
                out << "\n" << styled("legacy: ", Style::yellow) << data.value("hint", "") << "\n";
        }

        // ---- migrate ----

        struct Move {
            fs::path from, to;
            std::string what;
        };

        // An empty directory at the destination is no conflict (something created the layout).
        bool empty_dir(const fs::path& path) {
            std::error_code error;
            return fs::is_directory(fs::symlink_status(path, error)) && fs::is_empty(path, error) && !error;
        }

        bool same_file(const fs::path& a, const fs::path& b) {
            std::error_code error;
            return fs::equivalent(a, b, error) && !error;
        }

        // rename(2), or across file systems a copy next to the destination, renamed into place, then the
        // source removed. Either way the destination appears whole or not at all.
        void move_item(const Move& move) {
            if (empty_dir(move.to)) fs::remove(move.to);
            if (::rename(move.from.c_str(), move.to.c_str()) == 0) return;
            if (errno != EXDEV)
                throw Failure(Code::config, std::format("cannot move {} to {}: {}", move.from.string(), move.to.string(),
                                                        std::strerror(errno)));
            fs::path staging = move.to;
            staging += std::format(".migrating.{}", ::getpid());
            std::error_code error;
            fs::remove_all(staging, error);
            fs::copy(move.from, staging, fs::copy_options::recursive | fs::copy_options::copy_symlinks, error);
            if (!error) {
                // copy() creates directories with default permissions; keep the source's.
                fs::permissions(staging, fs::status(move.from).permissions(), error);
                if (fs::is_directory(move.from))
                    for (const auto& entry: fs::recursive_directory_iterator(move.from, error)) {
                        if (entry.is_symlink()) continue;
                        auto target = staging / entry.path().lexically_relative(move.from);
                        std::error_code ignored;
                        fs::permissions(target, entry.status().permissions(), ignored);
                    }
            }
            if (error || ::rename(staging.c_str(), move.to.c_str()) != 0) {
                fs::remove_all(staging, error);
                throw Failure(Code::config, std::format("cannot copy {} to {}", move.from.string(), move.to.string()));
            }
            fs::remove_all(move.from, error);
        }

        json run_migrate(const Context& context) {
            const auto& paths = context.engine.options().paths;
            if (paths.home.empty()) throw Failure(Code::config, "this forti has no home directory configured");
            for (const char* name: {"FORTI_CONFIG_DIR", "FORTI_STATE_DIR", "FORTI_CACHE_DIR"})
                if (const char* value = std::getenv(name); value && *value)
                    throw Failure(Code::config, std::format("{} is set, so forti uses {} and not the home; nothing was moved",
                                                            name, value),
                                  {{"hint", std::format("unset {} (and move that directory yourself if you want it in {})",
                                                        name, display_path(paths.home))}});
            LegacyDirs legacy = legacy_dirs();
            const fs::path& home = paths.home;
            // config.json last: the engine switches to the home only once it is there.
            std::vector<Move> moves = {
                {legacy.config / "credentials", home / "credentials", "file-stored secrets"},
                {legacy.state, home / "state", "plans, approvals, audit log, backups"},
                {legacy.cache, home / "cache", "cache"},
                {legacy.config / "config.json", home / "config.json", "profiles"},
            };

            std::vector<Move> pending;
            json conflicts = json::array();
            for (const auto& move: moves) {
                if (!present(move.from) || same_file(move.from, move.to)) continue;
                if (present(move.to) && !empty_dir(move.to)) conflicts.push_back(move.to.string());
                else pending.push_back(move);
            }
            if (!conflicts.empty()) {
                bool config = std::ranges::any_of(conflicts, [&](const json& path) { return path == (home / "config.json").string(); });
                throw Failure(Code::config,
                              config ? std::format("{} already exists; forti home migrate never overwrites it, and nothing was moved",
                                                   display_path(home / "config.json"))
                                     : std::format("{} already exist{} in the home; nothing was moved", conflicts.size() == 1
                                                   ? display_path(conflicts[0].get<std::string>()) : "several items",
                                                   conflicts.size() == 1 ? "s" : ""),
                              {{"conflicts", conflicts},
                               {"hint", std::format("move the old setup ({}) or the conflicting files aside, then run "
                                                    "`forti home migrate` again", display_path(legacy.config))}});
            }

            json moved = json::array();
            if (!pending.empty()) {
                engine::ensure_private_dir(home);
                for (const auto& move: pending) {
                    move_item(move);
                    moved.push_back({{"from", move.from.string()}, {"to", move.to.string()}, {"what", move.what}});
                }
            }
            // The old configuration directory goes when nothing else is left in it.
            json left = json::array();
            std::error_code error;
            if (fs::is_directory(legacy.config, error) && !same_file(legacy.config, home)) {
                for (const auto& entry: fs::directory_iterator(legacy.config, error)) left.push_back(entry.path().string());
                if (left.empty()) fs::remove(legacy.config, error);
            }
            json data = {{"home", home.string()}, {"moved", moved}, {"left_in_place", left},
                         {"config_file", (home / "config.json").string()}};
            if (moved.empty()) data["message"] = present(home / "config.json") ? "already migrated: nothing to move"
                                                                              : "no pre-0.2 setup found: nothing to move";
            return data;
        }

        void render_migrate(std::ostream& out, const json& data, const json&) {
            if (data.contains("message")) {
                out << data["message"].get<std::string>() << " (forti home: " << display_path(data.value("home", "")) << ")\n";
                return;
            }
            out << styled(std::format("Moved into {}:", display_path(data.value("home", ""))), Style::bold) << "\n";
            for (const auto& move: data["moved"])
                out << std::format("  {} → {}  ", display_path(move.value("from", "")), display_path(move.value("to", "")))
                    << styled(move.value("what", ""), Style::dim) << "\n";
            if (!data["left_in_place"].empty()) {
                out << "\nLeft in place (not forti's; profiles may reference them):\n";
                for (const auto& path: data["left_in_place"]) out << "  " << display_path(path.get<std::string>()) << "\n";
            }
            out << "\nKeychain items are unchanged. Next: `forti home`, then `forti doctor`.\n";
        }

        int run_home(Context& context, const Args& args) {
            std::string action = args.positional.empty() ? "show" : args.positional[0];
            if (args.positional.size() > 1) throw Failure(Code::usage, "usage: forti home [migrate]");
            if (action == "show")
                return emit(context.output, engine::ok(describe_home(context)), render_home);
            if (action == "migrate")
                return emit(context.output, engine::ok(run_migrate(context)), render_migrate);
            throw Failure(Code::usage, std::format("unknown home action \"{}\"", action), {{"hint", "forti home | forti home migrate"}});
        }

    }  // namespace

    std::vector<Command> home_commands() {
        return {
            {"home", "Show where forti keeps its files, or migrate a pre-0.2 setup",
             "usage: forti home                 the forti home and every location in it\n"
             "       forti home migrate         move a pre-0.2 setup into the home\n"
             "\n"
             "The forti home is $FORTI_HOME, else ~/.forti. It holds config.json and credentials/\n"
             "(profiles and file-stored secrets), state/ (plans, approvals, audit log, backups), cache/\n"
             "and certs/<profile>/ (forti cert create). FORTI_CONFIG_DIR, FORTI_STATE_DIR and\n"
             "FORTI_CACHE_DIR still override single locations.\n"
             "\n"
             "Releases before 0.2 used ~/.config/forti, ~/.local/state/forti and ~/.cache/forti (or\n"
             "$XDG_CONFIG_HOME, $XDG_STATE_HOME, $XDG_CACHE_HOME). That setup keeps working until it is\n"
             "migrated. `forti home migrate` moves config.json, credentials/, the state and the cache,\n"
             "keeping their modes. It never overwrites an existing config.json in the home, and running\n"
             "it again is harmless. Keychain items need no change.\n",
             {}, run_home},
        };
    }

}  // namespace forti::cli
