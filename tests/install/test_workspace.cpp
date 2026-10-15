// The forti MCP workspace (--scope workspace): project scope in the forti home plus the scaffold
// (AGENTS.md, CLAUDE.md, skills, Claude deny rules, the Codex permission profile, Codex trust only with
// consent), the home-directory guard, and uninstall. Fake `claude` and `codex` on PATH log every call:
// a workspace install writes files only, so they must never be asked to change anything. Everything
// lives in a temporary HOME; the real home directory is never touched.

#include <installer.hpp>
#include <toml_table.hpp>

#include <forti/engine/error.hpp>

#include <gtest/gtest.h>

#include <cstdlib>
#include <fstream>
#include <sstream>
#include <sys/stat.h>
#include <unistd.h>

using namespace forti::install;
using json = nlohmann::json;

namespace {

    // --version answers; anything else is logged and fails, so an unexpected client call shows up.
    const char* fake_client = R"SH(#!/bin/sh
{ printf '%s' "$(basename "$0")"; for a in "$@"; do printf ' %s' "$a"; done; printf '\n'; } >> "$FAKE_LOG"
[ "$1" = --version ] && { echo "fake 1.0"; exit 0; }
echo "unexpected call" >&2; exit 1
)SH";

    void write(const fs::path& path, std::string_view text, mode_t mode = 0644) {
        fs::create_directories(path.parent_path());
        std::ofstream(path) << text;
        ::chmod(path.c_str(), mode);
    }

    std::string slurp(const fs::path& path) {
        std::ifstream in(path);
        std::stringstream content;
        content << in.rdbuf();
        return content.str();
    }

    class Workspace : public ::testing::Test {
    protected:
        fs::path root, bin, home, forti, codex_home, log, forti_mcp;
        std::string saved_path;
        Context context;

        void SetUp() override {
            std::string pattern = (fs::temp_directory_path() / "forti-workspace-XXXXXX").string();
            ASSERT_NE(::mkdtemp(pattern.data()), nullptr);
            root = fs::canonical(pattern);
            bin = root / "bin";
            home = root / "home";
            forti = home / ".forti";
            codex_home = home / ".codex";
            for (const auto& dir: {bin, home, codex_home}) fs::create_directories(dir);
            log = root / "argv.log";
            write(bin / "claude", fake_client, 0755);
            write(bin / "codex", fake_client, 0755);
            forti_mcp = bin / "forti-mcp";
            write(forti_mcp, "#!/bin/sh\necho forti-mcp 0.2.0-test\n", 0755);
            saved_path = std::getenv("PATH") ? std::getenv("PATH") : "";
            ::setenv("PATH", (bin.string() + ":/usr/bin:/bin").c_str(), 1);
            ::setenv("FAKE_LOG", log.c_str(), 1);

            context.home = home;
            context.project_dir = root;   // the cwd: somewhere else entirely
            context.forti_home = forti;
            context.claude_config_dir = home / ".claude";
            context.codex_home = codex_home;
            context.timeout = std::chrono::seconds(20);
        }

        void TearDown() override {
            ::setenv("PATH", saved_path.c_str(), 1);
            ::unsetenv("FAKE_LOG");
            std::error_code ec;
            fs::remove_all(root, ec);
        }

        [[nodiscard]] Entry entry() const { return {forti_mcp.string(), {}, false}; }

        std::vector<Target> targets(std::initializer_list<const char*> clients) const {
            std::vector<Target> list;
            for (const auto* id: clients) list.push_back({find_adapter(id), Scope::workspace});
            return list;
        }

        std::vector<TargetPlan> install(std::initializer_list<const char*> clients, bool trust = false) {
            InstallRequest request{.targets = targets(clients), .desired = entry(), .skill = true, .force = false,
                                   .trust_codex_workspace = trust};
            auto plans = plan_install(request, context);
            execute(plans, context);
            return plans;
        }

        std::vector<TargetPlan> uninstall(std::initializer_list<const char*> clients) {
            auto plans = plan_uninstall(targets(clients), false, false, context);
            execute(plans, context);
            return plans;
        }

        static const workspace::Item* item(const TargetPlan& plan, std::string_view name) {
            for (const auto& it: plan.workspace)
                if (it.name == name) return &it;
            return nullptr;
        }

        // Only reads (--version, `codex mcp get` for status) may ever reach a client: the workspace is
        // files, never a client CLI change.
        void expect_no_client_changes() const {
            std::istringstream in(slurp(log));
            for (std::string line; std::getline(in, line);)
                EXPECT_TRUE(line.ends_with("--version") || line.starts_with("codex mcp get ")) << line;
        }
    };

}  // namespace

TEST_F(Workspace, InstallWritesTheRegistrationAndScaffoldInTheFortiHome) {
    auto plans = install({"claude", "codex"}, true);
    ASSERT_EQ(plans.size(), 2u);
    for (const auto& plan: plans) {
        EXPECT_EQ(plan.state, "installed") << to_json(plan).dump(2);
        EXPECT_EQ(plan.skill_state, "installed");
        EXPECT_FALSE(plan.blocked());
        for (const auto& it: plan.workspace) EXPECT_TRUE(it.state == "created" || it.state == "updated" || it.state == "trusted")
                                                      << it.name << ": " << it.state << " " << it.message;
    }
    expect_no_client_changes();

    struct stat info{};
    ASSERT_EQ(::stat(forti.c_str(), &info), 0);
    EXPECT_EQ(info.st_mode & 0777, static_cast<mode_t>(0700));   // created private, like the engine's own dirs

    // Registrations: project-scope files in the home, nothing user-wide.
    auto mcp = json::parse(slurp(forti / ".mcp.json"));
    EXPECT_EQ(mcp["mcpServers"]["forti"]["command"], forti_mcp.string());
    EXPECT_FALSE(fs::exists(home / ".claude" / ".claude.json"));
    EXPECT_FALSE(fs::exists(root / ".mcp.json"));   // not the cwd
    auto codex = slurp(forti / ".codex" / "config.toml");
    EXPECT_TRUE(toml::read_server(codex, "forti")->same_target(entry()));

    // Scaffold.
    EXPECT_EQ(slurp(forti / ".claude" / "skills" / "forti" / "SKILL.md"), skill_text());
    EXPECT_EQ(slurp(forti / ".agents" / "skills" / "forti" / "SKILL.md"), skill_text());
    auto agents = slurp(forti / "AGENTS.md");
    EXPECT_TRUE(agents.starts_with("<!-- Generated by `forti install mcp`"));
    EXPECT_NE(agents.find("cd ~/.forti && claude"), std::string::npos);
    for (const char* pointer: {"forti doctor", "forti profile list", "Docs:"}) EXPECT_NE(agents.find(pointer), std::string::npos) << pointer;
    EXPECT_NE(slurp(forti / "CLAUDE.md").find("\n@AGENTS.md\n"), std::string::npos);

    auto settings = json::parse(slurp(forti / ".claude" / "settings.json"));
    EXPECT_EQ(settings["permissions"]["deny"], json(workspace::claude_deny_rules()));
    for (const char* rule: {"Read(/credentials/**)", "Read(/certs/**/*.pass)", "Read(/certs/**/*.p12)", "Read(/certs/**/ca/**)",
                            "Edit(/config.json)"})
        EXPECT_NE(std::ranges::find(settings["permissions"]["deny"], json(rule)), settings["permissions"]["deny"].end()) << rule;

    auto line = toml::find_top_level(codex, "default_permissions");
    ASSERT_TRUE(line);
    EXPECT_EQ(toml::parse_string(line->value), "forti-workspace");
    EXPECT_NE(codex.find("[permissions.forti-workspace.filesystem.\":workspace_roots\"]\n\"credentials\" = \"deny\"\n"), std::string::npos);
    EXPECT_NE(codex.find("\"config.json\" = \"read\"\n"), std::string::npos);

    // Trust, with consent: exactly the one table.
    EXPECT_EQ(slurp(codex_home / "config.toml"), std::format("[projects.\"{}\"]\ntrust_level = \"trusted\"\n", forti.string()));
    EXPECT_TRUE(workspace::codex_trusted(context));
    auto marker = json::parse(slurp(forti / workspace::marker_file));
    EXPECT_EQ(marker["codex_trust"], forti.string());
    EXPECT_EQ(marker["claude_deny_rules"].size(), workspace::claude_deny_rules().size());
    EXPECT_FALSE(fs::exists(forti / "config.json"));   // never created by the installer
}

TEST_F(Workspace, InstallIsIdempotent) {
    install({"claude", "codex"}, true);
    std::map<fs::path, std::string> before;
    for (const auto& file: fs::recursive_directory_iterator(forti))
        if (file.is_regular_file()) before[file.path()] = slurp(file.path());
    auto global = slurp(codex_home / "config.toml");

    auto again = install({"claude", "codex"}, true);
    for (const auto& plan: again) {
        EXPECT_EQ(plan.state, "already_registered");
        EXPECT_EQ(plan.skill_state, "already_installed");
        EXPECT_FALSE(plan.has_actions()) << to_json(plan).dump(2);
        for (const auto& it: plan.workspace) EXPECT_EQ(it.state, "ok") << it.name;
    }
    for (const auto& [path, text]: before) EXPECT_EQ(slurp(path), text) << path;
    EXPECT_EQ(slurp(codex_home / "config.toml"), global);
}

TEST_F(Workspace, ScaffoldMergesIntoExistingFilesWithoutClobbering) {
    // The person's own AGENTS.md, settings.json and .codex/config.toml are already there.
    write(forti / "AGENTS.md", "# my notes\n");
    std::string settings = "{\n    \"model\": \"opus\",\n    \"permissions\": {\n        \"allow\": [\"Bash(ls)\"],\n"
                           "        \"deny\": [\"Read(/secret.txt)\", \"Read(/credentials/**)\"]\n    },\n    \"env\": {\"A\": \"1\"}\n}\n";
    write(forti / ".claude" / "settings.json", settings);
    std::string codex = "# mine\nmodel = \"o3\"\n\n[mcp_servers.other]\ncommand = \"x\"\n";
    write(forti / ".codex" / "config.toml", codex);

    auto plans = install({"claude", "codex"});
    for (const auto& plan: plans) EXPECT_FALSE(plan.blocked()) << to_json(plan).dump(2);   // conflicts are reported, not fatal
    ASSERT_TRUE(item(plans[0], "AGENTS.md"));
    EXPECT_EQ(item(plans[0], "AGENTS.md")->state, "conflict");
    EXPECT_EQ(slurp(forti / "AGENTS.md"), "# my notes\n");

    auto merged = nlohmann::ordered_json::parse(slurp(forti / ".claude" / "settings.json"));
    EXPECT_EQ(merged["model"], "opus");
    EXPECT_EQ(merged["env"]["A"], "1");
    EXPECT_EQ(merged["permissions"]["allow"], json::array({"Bash(ls)"}));
    auto deny = merged["permissions"]["deny"];
    EXPECT_EQ(deny[0], "Read(/secret.txt)");                         // theirs first, in order
    EXPECT_EQ(deny.size(), 2 + workspace::claude_deny_rules().size() - 1);   // Read(/credentials/**) not duplicated
    EXPECT_TRUE(slurp(forti / ".claude" / "settings.json").starts_with("{\n    \"model\""));   // their indent kept

    auto config = slurp(forti / ".codex" / "config.toml");
    EXPECT_TRUE(config.find("# mine\nmodel = \"o3\"\ndefault_permissions = \"forti-workspace\"\n\n[mcp_servers.other]\ncommand = \"x\"\n") == 0)
            << config;

    // Uninstall takes out only what forti added.
    uninstall({"claude", "codex"});
    EXPECT_EQ(slurp(forti / "AGENTS.md"), "# my notes\n");
    auto after = nlohmann::ordered_json::parse(slurp(forti / ".claude" / "settings.json"));
    EXPECT_EQ(after["permissions"]["deny"], json::array({"Read(/secret.txt)", "Read(/credentials/**)"}));
    EXPECT_EQ(slurp(forti / ".codex" / "config.toml"), codex);
}

TEST_F(Workspace, EditedGeneratedFilesAreLeftAloneAndUnchangedOnesAreUpdated) {
    install({"claude"});
    // Edited after forti wrote it: never overwritten, never removed.
    write(forti / "AGENTS.md", slurp(forti / "AGENTS.md") + "\nMy own rule.\n");
    auto again = install({"claude"});
    EXPECT_EQ(item(again[0], "AGENTS.md")->state, "conflict");
    EXPECT_NE(slurp(forti / "AGENTS.md").find("My own rule."), std::string::npos);

    // Written by an older forti and untouched (its hash is on record): updated to the current text.
    std::string old = "<!-- Generated by `forti install mcp`. -->\n@AGENTS.md (old)\n";
    write(forti / "CLAUDE.md", old);
    auto marker = json::parse(slurp(forti / workspace::marker_file));
    std::uint64_t hash = 0xcbf29ce484222325ull;
    for (unsigned char c: old) hash = (hash ^ c) * 0x100000001b3ull;
    marker["files"]["CLAUDE.md"] = std::format("fnv1a64:{:016x}", hash);
    write(forti / workspace::marker_file, marker.dump());
    auto updated = install({"claude"});
    EXPECT_EQ(item(updated[0], "CLAUDE.md")->state, "updated");
    EXPECT_EQ(slurp(forti / "CLAUDE.md"), workspace::claude_md());

    auto removed = uninstall({"claude"});
    EXPECT_EQ(item(removed[0], "AGENTS.md")->state, "kept");
    EXPECT_TRUE(fs::exists(forti / "AGENTS.md"));
    EXPECT_FALSE(fs::exists(forti / "CLAUDE.md"));
}

TEST_F(Workspace, CodexTrustNeedsConsent) {
    std::string global = "model = \"gpt-5\"\n\n[projects.\"/elsewhere\"]\ntrust_level = \"trusted\"\n";
    write(codex_home / "config.toml", global, 0600);
    EXPECT_TRUE(workspace::codex_trust_needed(context));

    // Without consent: nothing global changes, and the person is told how to trust it.
    auto plans = install({"codex"}, false);
    EXPECT_EQ(plans[0].state, "installed");
    const auto* trust = item(plans[0], "Codex trust");
    ASSERT_TRUE(trust);
    EXPECT_EQ(trust->state, "untrusted");
    EXPECT_NE(trust->message.find("--trust-codex-workspace"), std::string::npos);
    EXPECT_NE(trust->message.find("trust prompt"), std::string::npos);
    EXPECT_EQ(slurp(codex_home / "config.toml"), global);
    EXPECT_FALSE(json::parse(slurp(forti / workspace::marker_file)).contains("codex_trust"));
    // Status says Codex ignores the workspace config.
    auto status = find_adapter("codex")->status(Scope::workspace, context);
    EXPECT_TRUE(status.registered);
    ASSERT_FALSE(status.notes.empty());
    EXPECT_NE(status.notes[0].find("trusted"), std::string::npos);

    // With consent: exactly one table appended, every other byte and the file mode kept.
    auto consented = install({"codex"}, true);
    EXPECT_EQ(item(consented[0], "Codex trust")->state, "trusted");
    EXPECT_EQ(slurp(codex_home / "config.toml"),
              global + std::format("\n[projects.\"{}\"]\ntrust_level = \"trusted\"\n", forti.string()));
    struct stat info{};
    ::stat((codex_home / "config.toml").c_str(), &info);
    EXPECT_EQ(info.st_mode & 0777, static_cast<mode_t>(0600));
    EXPECT_TRUE(workspace::codex_trusted(context));
    EXPECT_FALSE(workspace::codex_trust_needed(context));

    // Uninstall removes the entry forti added, and nothing else.
    uninstall({"codex"});
    EXPECT_EQ(slurp(codex_home / "config.toml"), global);
}

TEST_F(Workspace, CodexTrustTheUserDecidedIsNeverChangedOrRemoved) {
    // An explicit "untrusted" entry is the person's decision: no question, no change.
    std::string untrusted = std::format("[projects.\"{}\"]\ntrust_level = \"untrusted\"\n", forti.string());
    write(codex_home / "config.toml", untrusted);
    EXPECT_FALSE(workspace::codex_trust_needed(context));
    auto plans = install({"codex"}, true);
    EXPECT_EQ(item(plans[0], "Codex trust")->state, "conflict");
    EXPECT_EQ(slurp(codex_home / "config.toml"), untrusted);
    uninstall({"codex"});

    // Trust the person added themselves stays after uninstall.
    std::string trusted = std::format("[projects.\"{}\"]\ntrust_level = \"trusted\"\n", forti.string());
    write(codex_home / "config.toml", trusted);
    auto again = install({"codex"}, true);
    EXPECT_EQ(item(again[0], "Codex trust")->state, "ok");
    auto removed = uninstall({"codex"});
    EXPECT_EQ(item(removed[0], "Codex trust"), nullptr);
    EXPECT_EQ(slurp(codex_home / "config.toml"), trusted);
}

TEST_F(Workspace, AConflictingDefaultPermissionsIsReportedNotOverridden) {
    std::string codex = "default_permissions = \":workspace\"\n";
    write(forti / ".codex" / "config.toml", codex);
    auto plans = install({"codex"});
    EXPECT_FALSE(plans[0].blocked());
    EXPECT_EQ(item(plans[0], "Codex permission profile")->state, "conflict");
    EXPECT_TRUE(slurp(forti / ".codex" / "config.toml").starts_with(codex));
    EXPECT_EQ(slurp(forti / ".codex" / "config.toml").find("[permissions."), std::string::npos);
}

TEST_F(Workspace, UninstallRemovesTheScaffoldAndLeavesSecretsAndConfig) {
    // What the forti home holds besides the workspace: never the installer's to touch.
    std::map<fs::path, std::string> secrets = {
            {forti / "config.json", "{\"profiles\":{}}\n"},
            {forti / "credentials" / "lab" / "api-key", "sekrit\n"},
            {forti / "certs" / "lab" / "client.p12", "p12"},
            {forti / "certs" / "lab" / "client.pass", "pw"},
            {forti / "certs" / "lab" / "ca" / "ca.key", "key"},
            {forti / "state" / "audit.jsonl", "{}\n"},
            {forti / "cache" / "x", "x"},
    };
    for (const auto& [path, text]: secrets) write(path, text, 0600);
    ::chmod(forti.c_str(), 0700);
    std::string global = "# codex\n";
    write(codex_home / "config.toml", global);

    install({"claude", "codex"}, true);
    // Status reports the workspace and its health.
    auto report = status_report(forti_mcp, context);
    ASSERT_TRUE(report.contains("workspace"));
    EXPECT_EQ(report["workspace"]["path"], forti.string());
    for (const auto& file: report["workspace"]["files"]) EXPECT_EQ(file["state"], "ok") << file.dump();
    EXPECT_TRUE(report["workspace"]["codex_trust_added_by_forti"]);
    bool listed = false;
    for (const auto& client: report["clients"])
        for (const auto& row: client["scopes"])
            if (row["scope"] == "workspace") {
                listed = true;
                EXPECT_TRUE(row["registered"]) << row.dump();
                EXPECT_TRUE(row["skill"]["installed"]);
            }
    EXPECT_TRUE(listed);

    // Claude alone: AGENTS.md stays, Codex still uses it.
    auto first = uninstall({"claude"});
    EXPECT_EQ(first[0].state, "removed") << to_json(first[0]).dump(2);
    EXPECT_TRUE(fs::exists(forti / "AGENTS.md"));
    EXPECT_FALSE(fs::exists(forti / "CLAUDE.md"));
    EXPECT_FALSE(fs::exists(forti / ".claude"));
    EXPECT_FALSE(fs::exists(forti / ".mcp.json"));

    auto second = uninstall({"codex"});
    EXPECT_EQ(second[0].state, "removed") << to_json(second[0]).dump(2);
    EXPECT_FALSE(second[0].blocked());
    for (const char* gone: {"AGENTS.md", ".codex", ".agents", ".forti-workspace.json"}) EXPECT_FALSE(fs::exists(forti / gone)) << gone;
    EXPECT_EQ(slurp(codex_home / "config.toml"), global);   // the trust entry forti added is gone
    for (const auto& [path, text]: secrets) EXPECT_EQ(slurp(path), text) << path;
    struct stat info{};
    ::stat(forti.c_str(), &info);
    EXPECT_EQ(info.st_mode & 0777, static_cast<mode_t>(0700));
    expect_no_client_changes();

    // Nothing left: a second uninstall plans nothing.
    auto again = plan_uninstall(targets({"claude", "codex"}), false, false, context);
    for (const auto& plan: again) EXPECT_FALSE(plan.has_actions()) << to_json(plan).dump(2);
}

TEST_F(Workspace, HomeDirectoryGuard) {
    auto at = [&](fs::path dir) {
        Context c = context;
        c.project_dir = std::move(dir);
        return c;
    };
    for (auto scope: {Scope::project, Scope::local}) {
        auto warning = workspace::home_directory_warning(scope, at(home));
        ASSERT_TRUE(warning);
        EXPECT_NE(warning->find("anywhere under your home"), std::string::npos);
        EXPECT_NE(warning->find("--scope workspace"), std::string::npos);
    }
    EXPECT_FALSE(workspace::home_directory_warning(Scope::project, at(root)));           // any other directory
    EXPECT_FALSE(workspace::home_directory_warning(Scope::project, at(home / "src")));   // even under the home
    EXPECT_FALSE(workspace::home_directory_warning(Scope::user, at(home)));
    EXPECT_FALSE(workspace::home_directory_warning(Scope::workspace, at(home)));
    Context same = at(home);
    same.forti_home = home;   // FORTI_HOME=$HOME: the forti home is never warned about
    EXPECT_FALSE(workspace::home_directory_warning(Scope::project, same));

    std::string said;
    std::vector<std::pair<std::string, bool>> asked;
    auto say = [&](std::string_view text) { said += text; };
    auto press_enter = [&](std::string_view question, bool fallback) {
        asked.emplace_back(question, fallback);
        return fallback;
    };
    // Interactive: warns, asks "Are you sure?", and Enter means no.
    EXPECT_FALSE(workspace::allow_home_directory(Scope::project, at(home), true, false, say, press_enter));
    ASSERT_EQ(asked.size(), 1u);
    EXPECT_EQ(asked[0].first, "Are you sure?");
    EXPECT_FALSE(asked[0].second);
    EXPECT_NE(said.find("warning:"), std::string::npos);
    EXPECT_TRUE(workspace::allow_home_directory(Scope::project, at(home), true, false, say, [](auto, bool) { return true; }));

    // Without a terminal: refused unless --force.
    try {
        workspace::allow_home_directory(Scope::local, at(home), false, false, say, press_enter);
        ADD_FAILURE() << "expected a refusal";
    } catch (const forti::engine::Failure& failure) {
        EXPECT_EQ(failure.code(), forti::engine::Code::policy_denied);
        EXPECT_NE(std::string(failure.what()).find("--force"), std::string::npos);
    }
    EXPECT_TRUE(workspace::allow_home_directory(Scope::local, at(home), false, true, say, press_enter));
    EXPECT_TRUE(workspace::allow_home_directory(Scope::project, at(root), false, false, say, press_enter));
    EXPECT_EQ(asked.size(), 1u);   // only the interactive home case ever asked
}

TEST_F(Workspace, ScopeParsesAndMapsOntoTheFortiHome) {
    EXPECT_EQ(parse_scope("workspace"), Scope::workspace);
    EXPECT_EQ(to_string(Scope::workspace), "workspace");
    EXPECT_TRUE(find_adapter("claude")->supports(Scope::workspace));
    EXPECT_TRUE(find_adapter("codex")->supports(Scope::workspace));
    EXPECT_FALSE(find_adapter("codex")->supports(Scope::local));
    EXPECT_EQ(find_adapter("claude")->status(Scope::workspace, context).location, (forti / ".mcp.json").string());
    EXPECT_EQ(find_adapter("codex")->skill_file(Scope::workspace, context), forti / ".agents" / "skills" / "forti" / "SKILL.md");
    EXPECT_EQ(context.for_scope(Scope::project).project_dir, root);
}

TEST(TomlTopLevel, InsertFindRemoveRoundTrip) {
    for (std::string text: {std::string(), std::string("model = \"o3\"\n\n[a]\nx = 1\n"), std::string("# c\n[a]\nx = 1\n"),
                            std::string("model = \"o3\"   # trailing\nother = [\n  1,\n]\n[a]\n")}) {
        auto inserted = toml::insert_top_level(text, "default_permissions = \"p\"\n");
        auto line = toml::find_top_level(inserted, "default_permissions");
        ASSERT_TRUE(line) << inserted;
        EXPECT_EQ(line->value, "\"p\"");
        EXPECT_EQ(toml::scan(inserted).values.front().table, toml::Path{});   // stays a top-level key
        EXPECT_FALSE(toml::find_top_level(inserted, "x"));                       // table keys are not top-level
        EXPECT_EQ(toml::remove_top_level(inserted, "default_permissions"), text) << inserted;
    }
    EXPECT_THROW(toml::find_top_level("default_permissions.x = 1\n", "default_permissions"), forti::engine::Failure);
}
