// Adapters and the installer against fake `claude` and `codex` executables (sh scripts first on
// PATH) that log their argv and emulate the documented behavior of Claude Code 2.1.300 and Codex
// 0.162.1: claude add fails on an existing name, remove fails on a missing one, local scope keys on
// the cwd; codex add replaces silently, remove of a missing name succeeds, get exits 1 when missing.
// Nothing here starts a real client or touches the real home directory.

#include <installer.hpp>
#include <process.hpp>

#include <forti/engine/error.hpp>

#include <gtest/gtest.h>

#include <cstdlib>
#include <fstream>
#include <sstream>
#include <sys/stat.h>
#include <unistd.h>

using namespace forti::install;

namespace {

    const char* fake_claude = R"SH(#!/bin/sh
{ printf 'claude'; for a in "$@"; do printf ' %s' "$a"; done; printf ' [cwd=%s]\n' "$(pwd -P)"; } >> "$FAKE_LOG"
[ "$1" = --version ] && { echo "2.1.300 (Claude Code)"; exit 0; }
[ "$1" = mcp ] || exit 2
sub=$2; shift 2
[ "$1" = -s ] || { echo "missing -s" >&2; exit 2; }
scope=$2; name=$3; shift 3
if [ "$scope" = local ]; then key="local_$(pwd -P | tr / _)"; else key=$scope; fi
file="$FAKE_STATE/$key"
case $sub in
  add)
    [ -e "$file" ] && { echo "MCP server $name already exists in $scope config" >&2; exit 1; }
    shift
    [ "$1" = "$FAKE_FAIL_CMD" ] && { echo "simulated failure" >&2; exit 1; }
    cmd=$1; shift; args=""
    for a in "$@"; do args="$args${args:+,}\"$a\""; done
    printf '{"type":"stdio","command":"%s","args":[%s],"env":{}}' "$cmd" "$args" > "$file"
    [ "$scope" = local ] && pwd -P > "$file.dir" ;;
  remove)
    [ -e "$file" ] || { echo "No MCP server named \"$name\" in $scope scope" >&2; exit 1; }
    rm -f "$file" "$file.dir" ;;
  *) exit 2 ;;
esac
{
  printf '{"numStartups":3'
  [ -e "$FAKE_STATE/user" ] && printf ',"mcpServers":{"forti":%s}' "$(cat "$FAKE_STATE/user")"
  printf ',"projects":{'; sep=""
  for f in "$FAKE_STATE"/local_*; do
    case $f in *.dir) continue ;; esac
    [ -e "$f" ] || continue
    printf '%s"%s":{"mcpServers":{"forti":%s}}' "$sep" "$(cat "$f.dir")" "$(cat "$f")"; sep=","
  done
  printf '}}'
} > "$CLAUDE_CONFIG_DIR/.claude.json"
)SH";

    const char* fake_codex = R"SH(#!/bin/sh
{ printf 'codex'; for a in "$@"; do printf ' %s' "$a"; done; printf ' [cwd=%s]\n' "$(pwd -P)"; } >> "$FAKE_LOG"
[ "$1" = --version ] && { echo "codex-cli 0.162.1"; exit 0; }
[ "$1" = mcp ] || exit 2
sub=$2; name=$3
file="$FAKE_STATE/codex_$name"
case $sub in
  add)
    shift 4; cmd=$1; shift; args=""
    for a in "$@"; do args="$args${args:+,}\"$a\""; done
    printf '{"type":"stdio","command":"%s","args":[%s],"env":null,"env_vars":[],"cwd":null}' "$cmd" "$args" > "$file"
    echo "Added global MCP server '$name'." ;;
  remove) rm -f "$file"; echo "Removed global MCP server '$name'." ;;
  get)
    [ -e "$file" ] || { echo "Error: No MCP server named '$name' found." >&2; exit 1; }
    printf '{"name":"%s","enabled":true,"transport":%s}\n' "$name" "$(cat "$file")" ;;
  *) exit 2 ;;
esac
)SH";

    void write_script(const fs::path& path, std::string_view text) {
        std::ofstream(path) << text;
        ::chmod(path.c_str(), 0755);
    }

    std::string slurp(const fs::path& path) {
        std::ifstream in(path);
        std::stringstream content;
        content << in.rdbuf();
        return content.str();
    }

    class Adapters : public ::testing::Test {
    protected:
        fs::path root, bin, state, log, home, project, claude_dir, codex_home, forti_mcp;
        std::string saved_path;
        Context context;

        void SetUp() override {
            std::string pattern = (fs::temp_directory_path() / "forti-install-XXXXXX").string();
            ASSERT_NE(::mkdtemp(pattern.data()), nullptr);
            root = fs::canonical(pattern);
            bin = root / "bin";
            state = root / "state";
            home = root / "home";
            project = root / "project";
            claude_dir = home / ".claude";
            codex_home = home / ".codex";
            for (const auto& dir: {bin, state, home, project, claude_dir, codex_home}) fs::create_directories(dir);
            log = root / "argv.log";
            write_script(bin / "claude", fake_claude);
            write_script(bin / "codex", fake_codex);
            forti_mcp = bin / "forti-mcp";
            write_script(forti_mcp, "#!/bin/sh\necho forti-mcp 0.1.0-test\n");

            saved_path = std::getenv("PATH") ? std::getenv("PATH") : "";
            ::setenv("PATH", (bin.string() + ":/usr/bin:/bin").c_str(), 1);
            ::setenv("FAKE_LOG", log.c_str(), 1);
            ::setenv("FAKE_STATE", state.c_str(), 1);
            ::setenv("CLAUDE_CONFIG_DIR", claude_dir.c_str(), 1);
            ::unsetenv("FAKE_FAIL_CMD");

            context.home = home;
            context.project_dir = project;
            context.claude_config_dir = claude_dir;
            context.codex_home = codex_home;
            context.timeout = std::chrono::seconds(20);
        }

        void TearDown() override {
            ::setenv("PATH", saved_path.c_str(), 1);
            ::unsetenv("FAKE_LOG");
            ::unsetenv("FAKE_STATE");
            ::unsetenv("CLAUDE_CONFIG_DIR");
            ::unsetenv("FAKE_FAIL_CMD");
            std::error_code ec;
            fs::remove_all(root, ec);
        }

        [[nodiscard]] std::vector<std::string> calls() const {
            std::vector<std::string> lines;
            std::istringstream in(slurp(log));
            for (std::string line; std::getline(in, line);) lines.push_back(line);
            return lines;
        }

        [[nodiscard]] Entry entry(std::vector<std::string> args = {}) const { return {forti_mcp.string(), std::move(args), false}; }

        std::vector<TargetPlan> install(const char* client, Scope scope, Entry desired, bool skill = false, bool force = false) {
            InstallRequest request{{{find_adapter(client), scope}}, std::move(desired), skill, force};
            auto plans = plan_install(request, context);
            execute(plans, context);
            return plans;
        }
    };

}  // namespace

TEST_F(Adapters, Detect) {
    auto claude = find_adapter("claude")->detect(context);
    EXPECT_TRUE(claude.found);
    EXPECT_EQ(claude.version, "2.1.300 (Claude Code)");
    EXPECT_EQ(find_adapter("codex")->detect(context).version, "codex-cli 0.162.1");
    ::setenv("PATH", "/usr/bin:/bin", 1);
    EXPECT_FALSE(find_adapter("claude")->detect(context).found);
}

TEST_F(Adapters, ClaudeUserInstallIsIdempotent) {
    auto plans = install("claude", Scope::user, entry());
    ASSERT_EQ(plans.size(), 1u);
    EXPECT_EQ(plans[0].state, "installed") << plans[0].message;
    auto expected = std::format("claude mcp add -s user forti -- {}", forti_mcp.string());
    ASSERT_EQ(calls().size(), 1u);
    EXPECT_TRUE(calls()[0].starts_with(expected)) << calls()[0];

    auto again = install("claude", Scope::user, entry());
    EXPECT_EQ(again[0].state, "already_registered");
    EXPECT_TRUE(again[0].actions.empty());
    EXPECT_EQ(calls().size(), 1u);   // status reads the file; nothing ran
}

TEST_F(Adapters, ClaudeConflictNeedsForceThenRemovesAndAdds) {
    install("claude", Scope::user, {"/elsewhere/forti-mcp", {}, false});
    auto refused = install("claude", Scope::user, entry({"--profile", "lab"}));
    EXPECT_EQ(refused[0].state, "conflict");
    EXPECT_EQ(calls().size(), 1u);

    auto forced = install("claude", Scope::user, entry({"--profile", "lab"}), false, true);
    EXPECT_EQ(forced[0].state, "replaced") << forced[0].message;
    auto lines = calls();
    ASSERT_EQ(lines.size(), 3u);
    EXPECT_TRUE(lines[1].starts_with("claude mcp remove -s user forti"));
    EXPECT_TRUE(lines[2].starts_with(std::format("claude mcp add -s user forti -- {} --profile lab", forti_mcp.string())));
    auto status = find_adapter("claude")->status(Scope::user, context);
    EXPECT_TRUE(status.entry->same_target(entry({"--profile", "lab"})));
}

TEST_F(Adapters, ClaudeFailedReplaceRestoresTheOldEntry) {
    install("claude", Scope::user, {"/elsewhere/forti-mcp", {}, false});
    ::setenv("FAKE_FAIL_CMD", forti_mcp.c_str(), 1);
    auto plans = install("claude", Scope::user, entry(), false, true);
    EXPECT_EQ(plans[0].state, "failed");
    EXPECT_NE(plans[0].message.find("simulated failure"), std::string::npos);
    auto status = find_adapter("claude")->status(Scope::user, context);
    ASSERT_TRUE(status.registered);
    EXPECT_EQ(status.entry->command, "/elsewhere/forti-mcp");
}

TEST_F(Adapters, ClaudeLocalScopeRunsInTheProject) {
    auto plans = install("claude", Scope::local, entry());
    EXPECT_EQ(plans[0].state, "installed") << plans[0].message;
    EXPECT_NE(calls()[0].find(std::format("[cwd={}]", project.string())), std::string::npos) << calls()[0];
    EXPECT_FALSE(find_adapter("claude")->status(Scope::user, context).registered);

    auto removed = plan_uninstall({{find_adapter("claude"), Scope::local}}, false, false, context);
    execute(removed, context);
    EXPECT_EQ(removed[0].state, "removed");
    EXPECT_TRUE(calls().back().starts_with("claude mcp remove -s local forti"));
}

TEST_F(Adapters, ClaudeProjectScopeWritesOnlyTheProjectFile) {
    std::string original = "{\n  \"mcpServers\": {\n    \"other\": {\n      \"command\": \"o\"\n    }\n  }\n}\n";
    std::ofstream(project / ".mcp.json") << original;
    ::chmod((project / ".mcp.json").c_str(), 0600);

    auto plans = install("claude", Scope::project, entry());
    EXPECT_EQ(plans[0].state, "installed");
    EXPECT_TRUE(calls().empty());                              // no CLI call at all
    EXPECT_FALSE(fs::exists(claude_dir / ".claude.json"));     // never escalates to user config
    struct stat info{};
    ::stat((project / ".mcp.json").c_str(), &info);
    EXPECT_EQ(info.st_mode & 0777, static_cast<mode_t>(0600));                     // mode kept
    auto doc = nlohmann::ordered_json::parse(slurp(project / ".mcp.json"));
    EXPECT_EQ(doc["mcpServers"].begin().key(), "other");

    auto removed = plan_uninstall({{find_adapter("claude"), Scope::project}}, false, false, context);
    execute(removed, context);
    EXPECT_EQ(slurp(project / ".mcp.json"), original);
}

TEST_F(Adapters, CodexUserScope) {
    auto plans = install("codex", Scope::user, entry({"--profile", "lab"}));
    EXPECT_EQ(plans[0].state, "installed") << plans[0].message;
    auto lines = calls();
    // get (status), add, get (validation)
    ASSERT_EQ(lines.size(), 3u);
    EXPECT_TRUE(lines[0].starts_with("codex mcp get forti --json"));
    EXPECT_TRUE(lines[1].starts_with(std::format("codex mcp add forti -- {} --profile lab", forti_mcp.string())));
    EXPECT_NE(lines[1].find(std::format("[cwd={}]", codex_home.string())), std::string::npos);   // never a project cwd

    auto again = install("codex", Scope::user, entry({"--profile", "lab"}));
    EXPECT_EQ(again[0].state, "already_registered");

    auto removed = plan_uninstall({{find_adapter("codex"), Scope::user}}, false, false, context);
    execute(removed, context);
    EXPECT_EQ(removed[0].state, "removed");
    EXPECT_FALSE(find_adapter("codex")->status(Scope::user, context).registered);
}

TEST_F(Adapters, CodexMissingHomeIsAnError) {
    context.codex_home = root / "missing";
    auto plans = plan_install({{{find_adapter("codex"), Scope::user}}, entry(), false, false}, context);
    EXPECT_EQ(plans[0].state, "error");
    EXPECT_TRUE(plans[0].blocked());
}

TEST_F(Adapters, CodexProjectScopeNeverTouchesGlobalConfig) {
    fs::create_directories(project / ".codex");
    std::string original = "# mine\nmodel = \"o3\"\n\n[mcp_servers.other]\ncommand = \"x\"\n";
    std::ofstream(project / ".codex" / "config.toml") << original;

    auto plans = install("codex", Scope::project, entry());
    EXPECT_EQ(plans[0].state, "installed") << plans[0].message;
    EXPECT_FALSE(plans[0].warnings.empty());                       // untrusted project warning
    EXPECT_TRUE(calls().empty());
    EXPECT_FALSE(fs::exists(codex_home / "config.toml"));          // no trust entry, no global edit
    EXPECT_TRUE(slurp(project / ".codex" / "config.toml").starts_with(original));

    auto removed = plan_uninstall({{find_adapter("codex"), Scope::project}}, false, false, context);
    execute(removed, context);
    EXPECT_EQ(slurp(project / ".codex" / "config.toml"), original);

    // A file that only held our table is deleted, with .codex/ if empty.
    fs::remove_all(project / ".codex");
    install("codex", Scope::project, entry());
    auto again = plan_uninstall({{find_adapter("codex"), Scope::project}}, false, false, context);
    execute(again, context);
    EXPECT_FALSE(fs::exists(project / ".codex"));
}

TEST_F(Adapters, UninstallLeavesForeignEntries) {
    install("claude", Scope::user, {"/usr/local/bin/some-other-server", {}, false});
    auto plans = plan_uninstall({{find_adapter("claude"), Scope::user}}, false, false, context);
    EXPECT_EQ(plans[0].state, "foreign");
    EXPECT_TRUE(plans[0].actions.empty());
    auto forced = plan_uninstall({{find_adapter("claude"), Scope::user}}, false, true, context);
    EXPECT_EQ(forced[0].state, "remove");
}

TEST_F(Adapters, SkillsGoWhereEachClientLoadsThem) {
    install("claude", Scope::user, entry(), true);
    install("codex", Scope::user, entry(), true);
    install("claude", Scope::project, entry(), true);
    install("codex", Scope::project, entry(), true);
    EXPECT_EQ(slurp(claude_dir / "skills" / "forti" / "SKILL.md"), skill_text());
    EXPECT_EQ(slurp(home / ".agents" / "skills" / "forti" / "SKILL.md"), skill_text());
    EXPECT_EQ(slurp(project / ".claude" / "skills" / "forti" / "SKILL.md"), skill_text());
    EXPECT_EQ(slurp(project / ".agents" / "skills" / "forti" / "SKILL.md"), skill_text());

    auto again = install("claude", Scope::user, entry(), true);
    EXPECT_EQ(again[0].skill_state, "already_installed");

    auto removed = plan_uninstall({{find_adapter("codex"), Scope::project}}, false, false, context);
    execute(removed, context);
    EXPECT_EQ(removed[0].skill_state, "removed");
    EXPECT_FALSE(fs::exists(project / ".agents"));   // created by forti, removed when empty

    auto kept = plan_uninstall({{find_adapter("claude"), Scope::user}}, true, false, context);
    execute(kept, context);
    EXPECT_TRUE(fs::exists(claude_dir / "skills" / "forti" / "SKILL.md"));
}

TEST_F(Adapters, SomeoneElsesSkillIsNotOverwrittenOrRemoved) {
    auto path = project / ".claude" / "skills" / "forti" / "SKILL.md";
    fs::create_directories(path.parent_path());
    std::ofstream(path) << "---\nname: other\ndescription: not ours\n---\n";
    auto plans = install("claude", Scope::project, entry(), true);
    EXPECT_EQ(plans[0].skill_state, "conflict");
    EXPECT_TRUE(plans[0].blocked());
    auto removed = plan_uninstall({{find_adapter("claude"), Scope::project}}, false, false, context);
    EXPECT_TRUE(removed[0].skill_actions.empty());
}

TEST_F(Adapters, RepairPointsBrokenEntriesAtTheInstalledServer) {
    install("claude", Scope::user, {"/gone/forti-mcp", {"--profile", "lab"}, false});
    install("codex", Scope::user, {"/opt/homebrew/Cellar/forti-mcp/0.1.0/bin/forti-mcp", {}, false});
    std::vector<Target> targets{{find_adapter("claude"), Scope::user}, {find_adapter("codex"), Scope::user}};
    auto plans = plan_repair(targets, forti_mcp, context);
    EXPECT_EQ(plans[0].state, "repair");
    EXPECT_EQ(plans[1].state, "repair");   // versioned Cellar path
    execute(plans, context);
    EXPECT_EQ(plans[0].state, "repaired") << plans[0].message;
    EXPECT_EQ(plans[1].state, "repaired") << plans[1].message;
    EXPECT_TRUE(find_adapter("claude")->status(Scope::user, context).entry->same_target(entry({"--profile", "lab"})));
    EXPECT_EQ(plan_repair(targets, forti_mcp, context)[0].state, "ok");
}

TEST_F(Adapters, LocateFortiMcp) {
    // Next to forti.
    EXPECT_EQ(locate_forti_mcp(bin / "forti"), forti_mcp);
    // A Homebrew Cellar forti maps to <prefix>/bin/forti-mcp (kept as the link, not resolved).
    auto prefix = root / "brew";
    fs::create_directories(prefix / "bin");
    fs::create_directories(prefix / "Cellar" / "forti-mcp" / "1.0" / "bin");
    write_script(prefix / "Cellar" / "forti-mcp" / "1.0" / "bin" / "forti-mcp", "#!/bin/sh\n");
    fs::create_symlink(prefix / "Cellar" / "forti-mcp" / "1.0" / "bin" / "forti-mcp", prefix / "bin" / "forti-mcp");
    EXPECT_EQ(locate_forti_mcp(prefix / "Cellar" / "forti-cli" / "1.0" / "bin" / "forti"), prefix / "bin" / "forti-mcp");
    // Otherwise PATH, symlinks kept.
    ::setenv("PATH", ((prefix / "bin").string() + ":/usr/bin:/bin").c_str(), 1);
    EXPECT_EQ(locate_forti_mcp(root / "elsewhere" / "forti"), prefix / "bin" / "forti-mcp");
    ::setenv("PATH", "/usr/bin:/bin", 1);
    EXPECT_FALSE(locate_forti_mcp(root / "elsewhere" / "forti"));
}

TEST_F(Adapters, ProfileNamesAreValidated) {
    EXPECT_NO_THROW(validate_profile_name("lab-1.home_2"));
    EXPECT_THROW(validate_profile_name("--version"), forti::engine::Failure);
    EXPECT_THROW(validate_profile_name("a b"), forti::engine::Failure);
    EXPECT_THROW(validate_profile_name(""), forti::engine::Failure);
}

TEST(Process, CapturesOutputStatusAndCwd) {
    auto result = run_process({"/bin/sh", "-c", "echo out; echo err >&2; pwd -P; exit 3"}, {.cwd = fs::path("/"), .timeout = std::chrono::seconds(10)});
    EXPECT_EQ(result.status, 3);
    EXPECT_EQ(result.out, "out\n/\n");
    EXPECT_EQ(result.err, "err\n");
    EXPECT_FALSE(result.ok());
}

TEST(Process, ArgumentsAreNeverShellParsed) {
    auto result = run_process({"/bin/echo", "$(touch /nonexistent)", "a;b", "*"});
    EXPECT_EQ(result.out, "$(touch /nonexistent) a;b *\n");
}

TEST(Process, TimeoutKillsTheProcessGroup) {
    auto start = std::chrono::steady_clock::now();
    auto result = run_process({"/bin/sh", "-c", "sleep 30 & sleep 30"}, {.cwd = std::nullopt, .timeout = std::chrono::milliseconds(300)});
    EXPECT_TRUE(result.timed_out);
    EXPECT_LT(std::chrono::steady_clock::now() - start, std::chrono::seconds(5));
}

TEST(Process, MissingProgramThrows) {
    EXPECT_THROW(run_process({"/nonexistent/forti-test-program"}), forti::engine::Failure);
}

TEST(Skill, EmbeddedSkillIsValid) {
    auto text = skill_text();
    EXPECT_TRUE(is_forti_skill(text));
    auto end = text.find("\n---\n", 4);
    ASSERT_NE(end, std::string_view::npos);
    auto description = text.find("\ndescription: ");
    ASSERT_LT(description, end);
    auto line_end = text.find('\n', description + 1);
    EXPECT_LT(line_end - description - 14, 1024u);
    EXPECT_NE(text.find("forti plan approve"), std::string_view::npos);
    EXPECT_NE(text.find("untrusted"), std::string_view::npos);
}
