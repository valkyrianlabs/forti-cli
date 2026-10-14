// S-02, S-12 (security-audit.md): `forti install mcp --scope project` in a hostile project directory.
// Links, FIFOs and relative PATH entries a repository controls must not turn a project install into a
// change to user or global client configuration, hang forti, or register the project's own binary.

#include <installer.hpp>

#include <forti/engine/error.hpp>

#include <gtest/gtest.h>

#include <chrono>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <sys/stat.h>
#include <unistd.h>

using namespace forti::install;

namespace {

    std::string slurp(const fs::path& file) {
        std::ifstream in(file);
        std::stringstream text;
        text << in.rdbuf();
        return text.str();
    }

    struct Hostile : ::testing::Test {
        fs::path root, home, project;
        Context context;
        std::string saved_path;
        fs::path saved_cwd = fs::current_path();

        void SetUp() override {
            std::string pattern = (fs::temp_directory_path() / "forti-hostile-XXXXXX").string();
            ASSERT_NE(::mkdtemp(pattern.data()), nullptr);
            root = fs::canonical(pattern);
            home = root / "home";
            project = root / "project";
            fs::create_directories(home / ".codex");
            fs::create_directories(project);
            context.home = home;
            context.project_dir = project;
            context.claude_config_dir = home;
            context.codex_home = home / ".codex";
            context.timeout = std::chrono::seconds(5);
            saved_path = std::getenv("PATH") ? std::getenv("PATH") : "";
            ::setenv("PATH", "/usr/bin:/bin", 1);   // no claude/codex: project scope needs neither
        }

        void TearDown() override {
            ::setenv("PATH", saved_path.c_str(), 1);
            fs::current_path(saved_cwd);
            std::error_code ec;
            fs::remove_all(root, ec);
        }

        std::vector<TargetPlan> install(std::string_view client) {
            InstallRequest request{.targets = {{find_adapter(client), Scope::project}},
                                   .desired = {"/opt/forti/bin/forti-mcp", {}, false},
                                   .skill = true};
            auto plans = plan_install(request, context);
            execute(plans, context);
            return plans;
        }
    };

}  // namespace

TEST_F(Hostile, McpJsonLinkedToTheUserConfigIsNotFollowed) {
    // .mcp.json -> ~/.claude.json would add a user-scope server (and edit a file only the claude CLI may edit).
    std::string user_config = R"({"numStartups": 3, "projects": {}})";
    std::ofstream(home / ".claude.json") << user_config;
    fs::create_symlink(home / ".claude.json", project / ".mcp.json");
    auto plans = install("claude");
    ASSERT_EQ(plans.size(), 1u);
    EXPECT_TRUE(plans[0].blocked()) << to_json(plans[0]).dump();
    EXPECT_EQ(slurp(home / ".claude.json"), user_config);
}

TEST_F(Hostile, CodexDirectoryLinkedToCodexHomeIsNotFollowed) {
    std::string global = "model = \"x\"\n";
    std::ofstream(home / ".codex" / "config.toml") << global;
    fs::create_directory_symlink(home / ".codex", project / ".codex");
    auto plans = install("codex");
    EXPECT_TRUE(plans[0].blocked()) << to_json(plans[0]).dump();
    EXPECT_EQ(slurp(home / ".codex" / "config.toml"), global);
}

TEST_F(Hostile, SkillDirectoryLinkedOutOfTheProjectIsNotWritten) {
    fs::create_directories(home / ".claude");
    fs::create_directory_symlink(home / ".claude", project / ".claude");
    install("claude");
    EXPECT_FALSE(fs::exists(home / ".claude" / "skills" / "forti" / "SKILL.md"));
}

TEST_F(Hostile, FifoInPlaceOfMcpJsonDoesNotHang) {
    ASSERT_EQ(::mkfifo((project / ".mcp.json").c_str(), 0644), 0);
    auto started = std::chrono::steady_clock::now();
    EXPECT_THROW((void) read_file(project / ".mcp.json"), forti::engine::Failure);
    auto plans = install("claude");
    EXPECT_TRUE(plans[0].blocked());
    EXPECT_LT(std::chrono::steady_clock::now() - started, std::chrono::seconds(3));
}

TEST_F(Hostile, RequireInsideAcceptsRealFilesAndAbsentOnes) {
    EXPECT_NO_THROW(require_inside(project / ".mcp.json", project));
    std::ofstream(project / ".mcp.json") << "{}";
    EXPECT_NO_THROW(require_inside(project / ".mcp.json", project));
    EXPECT_NO_THROW(require_inside(project / ".claude" / "skills" / "forti" / "SKILL.md", project));
    EXPECT_THROW(require_inside(home / "x", project), forti::engine::Failure);
    EXPECT_THROW(require_inside(project / ".." / "home" / "x", project), forti::engine::Failure);
}

TEST_F(Hostile, ProjectInstallStillWorksAndKeepsTheEntryClean) {
    // A path with spaces and quotes round-trips; no env or secrets are registered.
    InstallRequest request{.targets = {{find_adapter("claude"), Scope::project}, {find_adapter("codex"), Scope::project}},
                           .desired = {"/opt/my \"forti\" dir/forti-mcp", {"--profile", "lab"}, false}};
    auto plans = plan_install(request, context);
    execute(plans, context);
    for (const auto& plan: plans) EXPECT_EQ(plan.state, "installed") << to_json(plan).dump();
    auto mcp = nlohmann::json::parse(slurp(project / ".mcp.json"));
    EXPECT_EQ(mcp["mcpServers"]["forti"]["command"], "/opt/my \"forti\" dir/forti-mcp");
    EXPECT_FALSE(mcp["mcpServers"]["forti"].contains("env"));
    auto codex = find_adapter("codex")->status(Scope::project, context);
    ASSERT_TRUE(codex.registered);
    EXPECT_EQ(codex.entry->command, "/opt/my \"forti\" dir/forti-mcp");
    EXPECT_FALSE(codex.entry->extra);
}

TEST_F(Hostile, RelativePathEntriesAreNotSearched) {
    // A repository that ships ./forti-mcp (or ./claude) must not be found through "." or an empty PATH entry.
    std::ofstream(project / "forti-mcp-hostile") << "#!/bin/sh\n";
    ::chmod((project / "forti-mcp-hostile").c_str(), 0755);
    fs::current_path(project);
    for (const char* path: {".:/usr/bin", ":/usr/bin", "/usr/bin::", "bin:."}) {
        ::setenv("PATH", path, 1);
        EXPECT_EQ(find_executable("forti-mcp-hostile"), std::nullopt) << path;
    }
    ::setenv("PATH", (project.string() + ":/usr/bin").c_str(), 1);
    EXPECT_EQ(find_executable("forti-mcp-hostile"), project / "forti-mcp-hostile");
}
