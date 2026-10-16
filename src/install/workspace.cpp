#include "workspace.hpp"
#include "mcp_json.hpp"
#include "toml_table.hpp"

#include <forti/engine/error.hpp>

#include <algorithm>
#include <cstdint>
#include <format>

namespace forti::install::workspace {

    using engine::Code;
    using engine::Failure;
    using ojson = nlohmann::ordered_json;

    namespace {

        // ---- What forti wrote: <home>/.forti-workspace.json ----
        //
        // {"generated_by": "forti mcp install", "files": {"AGENTS.md": "<hash>", ...},
        //  "claude_deny_rules": [...], "codex_permissions": "<hash>", "codex_trust": "<home>"}
        //
        // The hashes tell a file forti wrote and nobody touched since (ours to update or remove) from one
        // the person edited (left alone). FNV-1a: change detection, not security.

        std::string digest(std::string_view text) {
            std::uint64_t hash = 0xcbf29ce484222325ull;
            for (unsigned char c: text) {
                hash ^= c;
                hash *= 0x100000001b3ull;
            }
            return std::format("fnv1a64:{:016x}", hash);
        }

        fs::path marker_path(const fs::path& home) { return home / marker_file; }

        ojson read_marker(const fs::path& home) {
            try {
                auto text = read_file(marker_path(home));
                if (!text) return ojson::object();
                auto marker = ojson::parse(*text, nullptr, false);
                // Unreadable: forti claims nothing, so it removes nothing (the safe direction).
                return marker.is_object() ? marker : ojson::object();
            } catch (const Failure&) {
                return ojson::object();
            }
        }

        // Read, change, write back; the file goes away once it records nothing.
        void update_marker(const fs::path& home, const std::function<void(ojson&)>& change) {
            auto path = marker_path(home);
            require_inside(path, home);
            auto marker = read_marker(home);
            change(marker);
            for (const char* key: {"files", "claude_deny_rules"})
                if (marker.contains(key) && marker[key].empty()) marker.erase(key);
            marker.erase("generated_by");
            if (marker.empty()) {
                remove_file(path);
                return;
            }
            ojson out = {{"generated_by", "forti mcp install"}};
            out.update(marker);
            write_file_atomic(path, out.dump(2) + "\n", 0644);
        }

        std::optional<std::string> recorded(const ojson& marker, std::string_view section, std::string_view key) {
            auto it = marker.find(section);
            if (it == marker.end()) return std::nullopt;
            if (key.empty()) return it->is_string() ? std::optional(it->get<std::string>()) : std::nullopt;
            if (!it->is_object()) return std::nullopt;
            auto entry = it->find(key);
            if (entry == it->end() || !entry->is_string()) return std::nullopt;
            return entry->get<std::string>();
        }

        std::string tilde(const fs::path& path, const Context& context) {
            auto text = path.string();
            auto home = context.home.string();
            if (!home.empty() && text.starts_with(home + "/")) return "~" + text.substr(home.size());
            return text;
        }

        // ---- Generated files: AGENTS.md, CLAUDE.md ----

        enum class Own { absent, current, ours, theirs };

        Own ownership(const std::optional<std::string>& content, std::string_view desired, const std::optional<std::string>& hash) {
            if (!content) return Own::absent;
            if (*content == desired) return Own::current;
            if (hash && *hash == digest(*content)) return Own::ours;   // an older forti's version, unedited
            return Own::theirs;
        }

        Item install_file(std::string_view name, std::string desired, const Context& context, const ojson& marker) {
            const auto& home = context.forti_home;
            Item item{std::string(name), home / name, "", "", {}};
            try {
                auto own = ownership(read_file(item.path), desired, recorded(marker, "files", name));
                if (own == Own::current) {
                    item.state = "ok";
                    return item;
                }
                if (own == Own::theirs) {
                    item.state = "conflict";
                    item.message = std::format("{} differs from what forti wrote (edited, or not forti's); left alone. "
                                               "Delete it and run this again for the generated one", tilde(item.path, context));
                    return item;
                }
                item.state = own == Own::absent ? "create" : "update";
                auto path = item.path;
                std::string key(name);
                item.actions.push_back({"write", std::format("{} {}", own == Own::absent ? "create" : "update", path.string()),
                                        [path, home, key, desired] {
                                            require_inside(path, home);
                                            write_file_atomic(path, desired, 0644);
                                            update_marker(home, [&](ojson& m) { m["files"][key] = digest(desired); });
                                        }});
            } catch (const Failure& failure) {
                item.state = "conflict";
                item.message = failure.what();
            }
            return item;
        }

        std::optional<Item> uninstall_file(std::string_view name, std::string_view desired, const Context& context, const ojson& marker) {
            const auto& home = context.forti_home;
            Item item{std::string(name), home / name, "", "", {}};
            try {
                auto own = ownership(read_file(item.path), desired, recorded(marker, "files", name));
                if (own == Own::absent) return std::nullopt;
                if (own == Own::theirs) {
                    item.state = "kept";
                    item.message = "edited since forti wrote it (or not forti's); left alone";
                    return item;
                }
                item.state = "remove";
                auto path = item.path;
                std::string key(name);
                item.actions.push_back({"remove", std::format("remove {}", path.string()), [path, home, key] {
                                            require_inside(path, home);
                                            remove_file(path, home);
                                            update_marker(home, [&](ojson& m) {
                                                if (m.contains("files") && m["files"].is_object()) m["files"].erase(key);
                                            });
                                        }});
            } catch (const Failure& failure) {
                item.state = "kept";
                item.message = failure.what();
            }
            return item;
        }

        // ---- Claude Code: .claude/settings.json permissions.deny ----

        fs::path claude_settings(const Context& context) { return context.forti_home / ".claude" / "settings.json"; }

        // The deny array, or a reason the file cannot be merged into.
        struct Settings {
            ojson document = ojson::object();
            std::vector<std::string> deny;
            std::optional<std::string> problem;
        };

        Settings parse_settings(const std::string& text, const fs::path& path) {
            Settings settings;
            settings.document = ojson::parse(text, nullptr, false);
            auto bad = [&](std::string why) {
                settings.problem = std::format("{} {}; forti leaves it alone", path.string(), why);
                return settings;
            };
            if (settings.document.is_discarded() || !settings.document.is_object()) return bad("is not a JSON object");
            auto permissions = settings.document.find("permissions");
            if (permissions == settings.document.end()) return settings;
            if (!permissions->is_object()) return bad("has a `permissions` that is not an object");
            auto deny = permissions->find("deny");
            if (deny == permissions->end()) return settings;
            if (!deny->is_array()) return bad("has a `permissions.deny` that is not an array");
            for (const auto& rule: *deny)
                if (rule.is_string()) settings.deny.push_back(rule.get<std::string>());
            return settings;
        }

        std::vector<std::string> missing_rules(const std::vector<std::string>& deny) {
            std::vector<std::string> missing;
            for (const auto& rule: claude_deny_rules())
                if (!std::ranges::contains(deny, rule)) missing.push_back(rule);
            return missing;
        }

        Item install_claude_settings(const Context& context) {
            auto path = claude_settings(context);
            auto home = context.forti_home;
            Item item{"Claude Code deny rules", path, "", "", {}};
            try {
                auto text = read_file(path);
                auto missing = claude_deny_rules();
                if (text) {
                    auto settings = parse_settings(*text, path);
                    if (settings.problem) {
                        item.state = "conflict";
                        item.message = *settings.problem;
                        return item;
                    }
                    missing = missing_rules(settings.deny);
                }
                if (missing.empty()) {
                    item.state = "ok";
                    return item;
                }
                item.state = text ? "update" : "create";
                std::string rules;
                for (const auto& rule: missing) rules += (rules.empty() ? "" : ", ") + rule;
                item.actions.push_back({"write", std::format("{} {} (permissions.deny += {})", text ? "edit" : "create", path.string(), rules),
                                        [path, home] {
                                            require_inside(path, home);
                                            // Re-read at execution time and add only what is still missing.
                                            auto current = read_file(path).value_or("");
                                            auto settings = current.empty() ? Settings{} : parse_settings(current, path);
                                            if (settings.problem) throw Failure(Code::config, *settings.problem);
                                            auto add = missing_rules(settings.deny);
                                            if (add.empty()) return;
                                            auto& deny = settings.document["permissions"]["deny"];
                                            if (deny.is_null()) deny = ojson::array();
                                            for (const auto& rule: add) deny.push_back(rule);
                                            write_file_atomic(path, mcp_json::dump(settings.document, current), 0644);
                                            update_marker(home, [&](ojson& m) {
                                                auto& list = m["claude_deny_rules"];
                                                if (!list.is_array()) list = ojson::array();
                                                for (const auto& rule: add)
                                                    if (std::ranges::find(list, ojson(rule)) == list.end()) list.push_back(rule);
                                            });
                                        }});
            } catch (const Failure& failure) {
                item.state = "conflict";
                item.message = failure.what();
            }
            return item;
        }

        std::optional<Item> uninstall_claude_settings(const Context& context, const ojson& marker) {
            auto path = claude_settings(context);
            auto home = context.forti_home;
            Item item{"Claude Code deny rules", path, "", "", {}};
            try {
                auto text = read_file(path);
                if (!text) return std::nullopt;
                auto settings = parse_settings(*text, path);
                std::vector<std::string> ours;
                if (auto list = marker.find("claude_deny_rules"); list != marker.end() && list->is_array())
                    for (const auto& rule: *list)
                        if (rule.is_string()) ours.push_back(rule.get<std::string>());
                std::erase_if(ours, [&](const auto& rule) { return !std::ranges::contains(settings.deny, rule); });
                if (settings.problem) {
                    item.state = "kept";
                    item.message = *settings.problem;
                    return item;
                }
                if (ours.empty()) {
                    if (missing_rules(settings.deny).size() == claude_deny_rules().size()) return std::nullopt;
                    item.state = "kept";
                    item.message = "forti has no record of adding these rules; left alone";
                    return item;
                }
                item.state = "remove";
                item.actions.push_back({"write", std::format("edit {} (remove forti's permissions.deny rules)", path.string()),
                                        [path, home, ours] {
                                            require_inside(path, home);
                                            auto current = read_file(path).value_or("");
                                            auto settings = parse_settings(current, path);
                                            if (settings.problem) throw Failure(Code::config, *settings.problem);
                                            auto& document = settings.document;
                                            if (document.contains("permissions") && document["permissions"].contains("deny")) {
                                                auto& deny = document["permissions"]["deny"];
                                                ojson kept = ojson::array();
                                                for (const auto& rule: deny)
                                                    if (!rule.is_string() || !std::ranges::contains(ours, rule.get<std::string>()))
                                                        kept.push_back(rule);
                                                deny = std::move(kept);
                                                if (deny.empty()) document["permissions"].erase("deny");
                                                if (document["permissions"].empty()) document.erase("permissions");
                                            }
                                            if (document.empty()) remove_file(path, home);
                                            else write_file_atomic(path, mcp_json::dump(document, current), 0644);
                                            update_marker(home, [](ojson& m) { m.erase("claude_deny_rules"); });
                                        }});
            } catch (const Failure& failure) {
                item.state = "kept";
                item.message = failure.what();
            }
            return item;
        }

        // ---- Codex: a permission profile in .codex/config.toml ----
        //
        // Codex 0.162.1 permission profiles (learn.chatgpt.com/docs/permissions): `deny` blocks reads and
        // writes of a path, deny globs are deny-read rules, `read` makes a path read-only. They govern
        // the sandboxed commands Codex runs; MCP servers (forti-mcp itself) are outside the sandbox.

        fs::path codex_project_config(const Context& context) { return context.forti_home / ".codex" / "config.toml"; }

        const toml::Path& profile_path() {
            static const toml::Path path{"permissions", std::string(codex_profile)};
            return path;
        }

        std::string profile_line() { return std::format("default_permissions = {}\n", toml::quote(codex_profile)); }

        std::string profile_block() {
            return std::format("[permissions.{0}]\n"
                               "description = \"forti workspace: no reading credentials or certificate keys, config.json read-only\"\n"
                               "extends = \":workspace\"\n"
                               "\n"
                               "[permissions.{0}.filesystem.\":workspace_roots\"]\n"
                               "\"credentials\" = \"deny\"\n"
                               "\"certs/**/*.pass\" = \"deny\"\n"
                               "\"certs/**/*.p12\" = \"deny\"\n"
                               "\"certs/**/ca/**\" = \"deny\"\n"
                               "\"ca\" = \"deny\"\n"
                               "\"config.json\" = \"read\"\n",
                               codex_profile);
        }

        struct CodexProfile {
            std::optional<std::string> line;    // default_permissions value (raw)
            std::optional<std::string> block;   // the [permissions.forti-workspace] block text
        };

        CodexProfile read_codex_profile(std::string_view text) {
            CodexProfile found;
            if (auto line = toml::find_top_level(text, "default_permissions")) found.line = std::string(line->value);
            if (auto block = toml::find_table(text, profile_path())) found.block = std::string(text.substr(block->begin, block->end - block->begin));
            return found;
        }

        bool selects_ours(const CodexProfile& profile) {
            return profile.line && toml::parse_string(*profile.line) == std::optional<std::string>(std::string(codex_profile));
        }

        Item install_codex_profile(const Context& context, const ojson& marker) {
            auto path = codex_project_config(context);
            auto home = context.forti_home;
            Item item{"Codex permission profile", path, "", "", {}};
            try {
                auto text = read_file(path).value_or("");
                auto found = read_codex_profile(text);
                if (found.line && !selects_ours(found)) {
                    item.state = "conflict";
                    item.message = std::format("{} sets default_permissions = {}; forti does not override it, so Codex's "
                                               "deny rules for credentials/ and certs/ are not active", tilde(path, context), *found.line);
                    return item;
                }
                bool block_ok = found.block && *found.block == profile_block();
                if (found.block && !block_ok && recorded(marker, "codex_permissions", "") != digest(*found.block)) {
                    item.state = "conflict";
                    item.message = std::format("[permissions.{}] in {} was changed by hand; left alone", codex_profile, tilde(path, context));
                    return item;
                }
                if (found.line && block_ok) {
                    item.state = "ok";
                    return item;
                }
                item.state = found.block ? "update" : (text.empty() ? "create" : "update");
                item.actions.push_back({"write", std::format("edit {} (default_permissions = \"{}\", [permissions.{}])", path.string(),
                                                             codex_profile, codex_profile),
                                        [path, home] {
                                            require_inside(path, home);
                                            auto current = read_file(path).value_or("");
                                            auto updated = toml::find_top_level(current, "default_permissions")
                                                                   ? current : toml::insert_top_level(current, profile_line());
                                            updated = toml::set_table(updated, profile_path(), profile_block());
                                            write_file_atomic(path, updated, 0644);
                                            update_marker(home, [](ojson& m) { m["codex_permissions"] = digest(profile_block()); });
                                        }});
            } catch (const Failure& failure) {
                item.state = "conflict";
                item.message = failure.what();
            }
            return item;
        }

        std::optional<Item> uninstall_codex_profile(const Context& context, const ojson& marker) {
            auto path = codex_project_config(context);
            auto home = context.forti_home;
            Item item{"Codex permission profile", path, "", "", {}};
            try {
                auto text = read_file(path);
                if (!text) return std::nullopt;
                auto found = read_codex_profile(*text);
                bool block_ours = found.block && (*found.block == profile_block() ||
                                                  recorded(marker, "codex_permissions", "") == digest(*found.block));
                bool line_ours = selects_ours(found) && (block_ours || !found.block);
                if (!block_ours && !line_ours) {
                    if (!found.block) return std::nullopt;
                    item.state = "kept";
                    item.message = std::format("[permissions.{}] was changed by hand; left alone", codex_profile);
                    return item;
                }
                item.state = "remove";
                item.actions.push_back({"write", std::format("edit {} (remove default_permissions and [permissions.{}])", path.string(), codex_profile),
                                        [path, home, block_ours, line_ours] {
                                            require_inside(path, home);
                                            auto current = read_file(path).value_or("");
                                            auto updated = current;
                                            if (block_ours) updated = toml::remove_table(updated, profile_path());
                                            if (line_ours) updated = toml::remove_top_level(updated, "default_permissions");
                                            if (updated.find_first_not_of(" \t\r\n") == std::string::npos) remove_file(path, home);
                                            else if (updated != current) write_file_atomic(path, updated);
                                            update_marker(home, [](ojson& m) { m.erase("codex_permissions"); });
                                        }});
            } catch (const Failure& failure) {
                item.state = "kept";
                item.message = failure.what();
            }
            return item;
        }

        // ---- Codex: trust for the forti home in the global config ----

        fs::path codex_global_config(const Context& context) {
            return (context.codex_home ? *context.codex_home : context.home / ".codex") / "config.toml";
        }

        toml::Path trust_path(const Context& context) { return {"projects", context.forti_home.string()}; }

        std::string trust_block(const Context& context) {
            return std::format("[projects.{}]\ntrust_level = \"trusted\"\n", toml::quote(context.forti_home.string()));
        }

        std::string how_to_trust(const Context& context) {
            return std::format("Codex loads {} only for trusted projects. To trust {}: start `codex` there and accept "
                               "its trust prompt, or run `forti mcp install --client codex --scope workspace "
                               "--trust-codex-workspace`",
                               tilde(codex_project_config(context), context), tilde(context.forti_home, context));
        }

        Item install_codex_trust(bool consent, const Context& context) {
            auto path = codex_global_config(context);
            auto home = context.forti_home;
            Item item{"Codex trust", path, "", "", {}};
            try {
                auto text = read_file(path).value_or("");
                if (toml::project_trusted(text, home.string())) {
                    item.state = "ok";
                    return item;
                }
                if (toml::find_table(text, trust_path(context))) {
                    item.state = "conflict";
                    item.message = std::format("{} has its own entry for {} that does not trust it; forti leaves that "
                                               "decision alone, so Codex ignores the workspace's .codex/config.toml",
                                               tilde(path, context), tilde(home, context));
                    return item;
                }
                if (!consent) {
                    item.state = "untrusted";
                    item.message = how_to_trust(context);
                    return item;
                }
                item.state = "trust";
                auto block = trust_block(context);
                auto table = trust_path(context);
                item.actions.push_back({"write", std::format("edit {} (add [projects.{}] trust_level = \"trusted\")", path.string(),
                                                             toml::quote(home.string())),
                                        [path, home, block, table] {
                                            auto current = read_file(path).value_or("");
                                            if (toml::find_table(current, table)) return;   // appeared meanwhile: theirs
                                            // Only this one table is added; every other byte is kept.
                                            write_file_atomic(path, toml::set_table(current, table, block), 0600);
                                            update_marker(home, [&](ojson& m) { m["codex_trust"] = home.string(); });
                                        }});
            } catch (const Failure& failure) {
                item.state = "conflict";
                item.message = failure.what();
            }
            return item;
        }

        std::optional<Item> uninstall_codex_trust(const Context& context, const ojson& marker) {
            auto home = context.forti_home;
            // Only an entry forti added (recorded at the time) is ever removed.
            if (recorded(marker, "codex_trust", "") != home.string()) return std::nullopt;
            auto path = codex_global_config(context);
            Item item{"Codex trust", path, "remove", "", {}};
            auto block = trust_block(context);
            auto table = trust_path(context);
            try {
                auto text = read_file(path).value_or("");
                auto found = toml::find_table(text, table);
                if (found && text.substr(found->begin, found->end - found->begin) != block) {
                    item.state = "kept";
                    item.message = "the trust entry forti added was changed since; left alone";
                    item.actions.push_back({"write", std::format("forget {} trust entry", path.string()), [home] {
                                                update_marker(home, [](ojson& m) { m.erase("codex_trust"); });
                                            }});
                    return item;
                }
                auto summary = found ? std::format("edit {} (remove [projects.{}], which forti added)", path.string(), toml::quote(home.string()))
                                     : std::format("forget the trust entry for {} (already gone from {})", home.string(), path.string());
                item.actions.push_back({"write", summary,
                                        [path, home, block, table] {
                                            auto current = read_file(path).value_or("");
                                            auto found = toml::find_table(current, table);
                                            if (found && current.substr(found->begin, found->end - found->begin) == block)
                                                write_file_atomic(path, toml::remove_table(current, table), 0600);
                                            update_marker(home, [](ojson& m) { m.erase("codex_trust"); });
                                        }});
            } catch (const Failure& failure) {
                item.state = "kept";
                item.message = failure.what();
            }
            return item;
        }

        std::string file_health(const fs::path& path, std::string_view desired, const std::optional<std::string>& hash) {
            try {
                switch (ownership(read_file(path), desired, hash)) {
                    case Own::absent: return "missing";
                    case Own::current: return "ok";
                    case Own::ours: return "outdated";
                    case Own::theirs: return "modified";
                }
            } catch (const Failure&) {
            }
            return "unreadable";
        }

    }  // namespace

    const std::vector<std::string>& claude_deny_rules() {
        static const std::vector<std::string> rules = {
                "Read(/credentials/**)", "Read(/certs/**/*.pass)", "Read(/certs/**/*.p12)", "Read(/certs/**/ca/**)",
                "Read(/ca/**)", "Edit(/config.json)",
                // Guarded mode means a person approves: an agent's shell must not approve its own plans
                // or raise the profile's mode. (A prefix match: it stops accidents, not a determined process.)
                "Bash(forti approve:*)", "Bash(forti plan approve:*)", "Bash(forti profile mode:*)",
        };
        return rules;
    }

    std::string agents_md(const Context& context) {
        auto home = tilde(context.forti_home, context);
        return std::format(
                "<!-- Generated by `forti mcp install`. forti updates it while it is unchanged and leaves it alone once edited. -->\n"
                "# forti workspace\n"
                "\n"
                "This directory is the forti home: forti's FortiGate profiles, credentials, certificates and plans live\n"
                "here, and it is the one place where AI agents get the forti MCP tools (`forti_discover`, `forti_read`,\n"
                "`forti_plan`, `forti_apply`). Agents started anywhere else do not.\n"
                "\n"
                "    cd {0} && claude      # or: cd {0} && codex\n"
                "\n"
                "## For agents\n"
                "\n"
                "- Use the forti MCP tools and the `forti` skill (`.claude/skills/forti`, `.agents/skills/forti`).\n"
                "- Never read, print or edit `credentials/`, `certs/`, `ca/`, `config.json` or `state/`. They hold API keys,\n"
                "  private keys and the profiles; never ask for credentials either.\n"
                "- Never run `forti approve`, `forti configure`, `forti profile` or `forti cert`: approvals and\n"
                "  profile changes are the human's.\n"
                "- Claude Code: `.claude/settings.json` denies reading those secrets and editing `config.json`.\n"
                "  Codex: `.codex/config.toml` selects the `{1}` permission profile, which denies the same\n"
                "  paths to sandboxed commands (once Codex trusts this directory). Both stop accidents, not a\n"
                "  determined process: follow the rules above regardless.\n"
                "\n"
                "## For the human\n"
                "\n"
                "- `forti doctor`: profiles, credentials and connectivity.\n"
                "- `forti profile list`: the configured FortiGates.\n"
                "- `forti mcp status`: where forti-mcp is registered and whether this workspace is healthy.\n"
                "- Docs: `man forti`, and docs/guides/ai-agent-integration.md in github.com/valkyrianlabs/forti-cli.\n",
                home, codex_profile);
    }

    std::string claude_md() {
        return "<!-- Generated by `forti mcp install`. -->\n@AGENTS.md\n";
    }

    std::optional<Action> create_home(const Context& context) {
        std::error_code ec;
        if (context.forti_home.empty() || fs::exists(context.forti_home, ec)) return std::nullopt;
        auto home = context.forti_home;
        return Action{"write", std::format("create {} (mode 0700)", home.string()), [home] {
                          std::error_code error;
                          fs::create_directories(home, error);
                          if (!error) fs::permissions(home, fs::perms::owner_all, fs::perm_options::replace, error);
                          if (error) throw Failure(Code::config, std::format("cannot create {}: {}", home.string(), error.message()));
                      }};
    }

    std::vector<Item> plan_install(const ClientAdapter& client, bool shared, bool trust_codex, const Context& context) {
        auto marker = read_marker(context.forti_home);
        std::vector<Item> items;
        if (shared) items.push_back(install_file("AGENTS.md", agents_md(context), context, marker));
        if (client.id() == "claude") {
            items.push_back(install_file("CLAUDE.md", claude_md(), context, marker));
            items.push_back(install_claude_settings(context));
        } else if (client.id() == "codex") {
            items.push_back(install_codex_profile(context, marker));
            items.push_back(install_codex_trust(trust_codex, context));
        }
        return items;
    }

    std::vector<Item> plan_uninstall(const ClientAdapter& client, bool shared, const Context& context) {
        auto marker = read_marker(context.forti_home);
        std::vector<std::optional<Item>> found;
        if (client.id() == "claude") {
            found.push_back(uninstall_file("CLAUDE.md", claude_md(), context, marker));
            found.push_back(uninstall_claude_settings(context, marker));
        } else if (client.id() == "codex") {
            found.push_back(uninstall_codex_profile(context, marker));
            found.push_back(uninstall_codex_trust(context, marker));
        }
        if (shared) found.push_back(uninstall_file("AGENTS.md", agents_md(context), context, marker));
        std::vector<Item> items;
        for (auto& item: found)
            if (item) items.push_back(std::move(*item));
        return items;
    }

    bool codex_trusted(const Context& context) {
        try {
            auto text = read_file(codex_global_config(context));
            return text && toml::project_trusted(*text, context.forti_home.string());
        } catch (const Failure&) {
            return false;
        }
    }

    bool codex_trust_needed(const Context& context) {
        try {
            auto text = read_file(codex_global_config(context)).value_or("");
            return !toml::project_trusted(text, context.forti_home.string()) && !toml::find_table(text, trust_path(context));
        } catch (const Failure&) {
            return false;   // a file forti cannot follow: the install reports it, asking would not help
        }
    }

    nlohmann::json status(const Context& context) {
        using json = nlohmann::json;
        const auto& home = context.forti_home;
        auto marker = read_marker(home);
        std::error_code ec;
        json files = json::array();
        auto add = [&](std::string_view name, const fs::path& path, std::string_view client, std::string state) {
            files.push_back({{"name", name}, {"path", path.string()}, {"client", client}, {"state", std::move(state)}});
        };
        add("AGENTS.md", home / "AGENTS.md", "all", file_health(home / "AGENTS.md", agents_md(context), recorded(marker, "files", "AGENTS.md")));
        add("CLAUDE.md", home / "CLAUDE.md", "claude", file_health(home / "CLAUDE.md", claude_md(), recorded(marker, "files", "CLAUDE.md")));

        std::string settings_state = "unreadable";
        try {
            auto path = claude_settings(context);
            if (auto text = read_file(path)) {
                auto settings = parse_settings(*text, path);
                if (!settings.problem) settings_state = missing_rules(settings.deny).empty() ? "ok" : "incomplete";
            } else settings_state = "missing";
        } catch (const Failure&) {
        }
        add("Claude Code deny rules", claude_settings(context), "claude", settings_state);

        std::string profile_state = "unreadable";
        try {
            auto text = read_file(codex_project_config(context)).value_or("");
            auto found = read_codex_profile(text);
            if (found.line && !selects_ours(found)) profile_state = "overridden";
            else if (!found.block && !found.line) profile_state = "missing";
            else if (!found.block || !found.line) profile_state = "incomplete";
            else if (*found.block == profile_block()) profile_state = "ok";
            else profile_state = recorded(marker, "codex_permissions", "") == digest(*found.block) ? "outdated" : "modified";
        } catch (const Failure&) {
        }
        add("Codex permission profile", codex_project_config(context), "codex", profile_state);
        add("Codex trust", codex_global_config(context), "codex", codex_trusted(context) ? "ok" : "untrusted");

        return {{"path", home.string()},
                {"exists", fs::is_directory(home, ec)},
                {"files", std::move(files)},
                {"codex_trust_added_by_forti", recorded(marker, "codex_trust", "") == home.string()}};
    }

    std::optional<std::string> home_directory_warning(Scope scope, const Context& context) {
        if (scope != Scope::project && scope != Scope::local) return std::nullopt;
        auto dir = canonical_or_absolute(context.project_dir);
        if (context.home.empty() || dir != canonical_or_absolute(context.home)) return std::nullopt;
        if (!context.forti_home.empty() && dir == canonical_or_absolute(context.forti_home)) return std::nullopt;
        return std::format("{} is your home directory. With {} scope there, an agent started anywhere under your home "
                           "directory would get the firewall tools. The forti workspace keeps them in {} "
                           "(--scope workspace), which is recommended",
                           dir.string(), to_string(scope), tilde(context.forti_home, context));
    }

    bool allow_home_directory(Scope scope, const Context& context, bool interactive, bool force,
                              const std::function<void(std::string_view)>& say,
                              const std::function<bool(std::string_view, bool)>& confirm) {
        auto warning = home_directory_warning(scope, context);
        if (!warning) return true;
        if (interactive) {
            say(std::format("\nwarning: {}.\n", *warning));
            return confirm("Are you sure?", false);
        }
        if (force) return true;
        throw Failure(Code::policy_denied, std::format("{}. Refused: use --scope workspace, or pass --force to install there anyway", *warning),
                      {{"hint", "forti mcp install --scope workspace"}});
    }

}  // namespace forti::install::workspace
