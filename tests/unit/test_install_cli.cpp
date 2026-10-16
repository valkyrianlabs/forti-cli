// `forti mcp install|status` and the `forti install mcp` alias, through the CLI, against fake `claude`
// and `codex` executables that log every call: each client is probed once per run, output shows
// paths under the home directory as ~, and the option rules hold. HOME, FORTI_HOME, CLAUDE_CONFIG_DIR,
// CODEX_HOME and PATH point into a temporary directory; nothing real is touched.

#include <cli_harness.hpp>

#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <optional>

#include <sys/stat.h>

using namespace forti;
namespace fs = std::filesystem;

namespace {

    struct ScopedEnv {
        std::string name;
        std::optional<std::string> saved;
        ScopedEnv(std::string variable, const std::string& value) : name(std::move(variable)) {
            if (const char* old = std::getenv(name.c_str())) saved = old;
            ::setenv(name.c_str(), value.c_str(), 1);
        }
        ~ScopedEnv() {
            if (saved) ::setenv(name.c_str(), saved->c_str(), 1);
            else ::unsetenv(name.c_str());
        }
        ScopedEnv(const ScopedEnv&) = delete;
        ScopedEnv& operator=(const ScopedEnv&) = delete;
    };

    // Logs its argv; answers --version, and `codex mcp get` as "not registered". Anything else fails, so
    // an unexpected call shows up (a workspace install writes files and never asks a client to change).
    const char* fake_client = R"SH(#!/bin/sh
{ printf '%s' "$(basename "$0")"; for a in "$@"; do printf ' %s' "$a"; done; printf '\n'; } >> "$FAKE_LOG"
[ "$1" = --version ] && { echo "fake 1.0"; exit 0; }
[ "$1" = mcp ] && [ "$2" = get ] && { echo "Error: No MCP server named 'forti' found." >&2; exit 1; }
echo "unexpected call" >&2; exit 1
)SH";

    void write(const fs::path& path, std::string_view text, mode_t mode) {
        fs::create_directories(path.parent_path());
        std::ofstream(path) << text;
        ::chmod(path.c_str(), mode);
    }

    std::vector<std::string> lines(const fs::path& path) {
        std::vector<std::string> out;
        std::ifstream in(path);
        for (std::string line; std::getline(in, line);) out.push_back(line);
        return out;
    }

    struct McpCli : fake::Cli {
        fs::path root = fs::canonical(dir.path);
        fs::path home = root / "home", bin = root / "bin", log = root / "argv.log";
        std::optional<ScopedEnv> env_home, env_forti, env_claude, env_codex, env_path, env_log;

        void SetUp() override {
            fs::create_directories(home / ".codex");
            write(bin / "claude", fake_client, 0755);
            write(bin / "codex", fake_client, 0755);
            write(bin / "forti-mcp", "#!/bin/sh\necho forti-mcp 0.3.0-test\n", 0755);
            env_home.emplace("HOME", home.string());
            env_forti.emplace("FORTI_HOME", (home / ".forti").string());
            env_claude.emplace("CLAUDE_CONFIG_DIR", (home / ".claude").string());
            env_codex.emplace("CODEX_HOME", (home / ".codex").string());
            env_path.emplace("PATH", bin.string() + ":/usr/bin:/bin");
            env_log.emplace("FAKE_LOG", log.string());
        }

        std::size_t calls(std::string_view line) const { return std::ranges::count(lines(log), std::string(line)); }
    };

}  // namespace

TEST_F(McpCli, InstallProbesEachClientOnceAndShowsHomePathsAsTilde) {
    ASSERT_EQ(run({"mcp", "install", "--client", "all", "--scope", "workspace", "--trust-codex-workspace", "--yes"}), 0)
            << out.str() << err.str();
    EXPECT_EQ(calls("claude --version"), 1u);
    EXPECT_EQ(calls("codex --version"), 1u);
    std::string text = out.str();
    EXPECT_NE(text.find("~/.forti"), std::string::npos) << text;
    EXPECT_EQ(text.find(home.string()), std::string::npos) << text;   // never the absolute home
    EXPECT_NE(text.find("cd ~/.forti && claude (or codex)"), std::string::npos) << text;
    EXPECT_TRUE(fs::exists(home / ".forti" / "AGENTS.md"));

    fs::remove(log);
    ASSERT_EQ(run({"mcp", "status"}), 0) << err.str();
    EXPECT_EQ(calls("claude --version"), 1u);
    EXPECT_EQ(calls("codex --version"), 1u);
    EXPECT_EQ(out.str().find(home.string()), std::string::npos) << out.str();
    EXPECT_NE(out.str().find("workspace  ~/.forti"), std::string::npos) << out.str();
}

TEST_F(McpCli, InstallMcpIsTheSameCommand) {
    ASSERT_EQ(run({"install", "mcp", "--client", "claude", "--scope", "workspace", "--yes", "--dry-run"}), 0) << err.str();
    EXPECT_NE(out.str().find("dry run"), std::string::npos);
    EXPECT_EQ(run({"install", "other"}), 2);
    EXPECT_NE(err.str().find("forti mcp install"), std::string::npos) << err.str();
}

TEST_F(McpCli, OptionsBelongToTheirSubcommand) {
    EXPECT_EQ(run({"mcp", "status", "--skill"}), 2);
    EXPECT_EQ(run({"mcp", "repair", "--trust-codex-workspace"}), 2);
    EXPECT_EQ(run({"mcp", "install", "--keep-skill", "--client", "claude", "--scope", "workspace", "--yes"}), 2);
    EXPECT_EQ(run({"mcp", "install", "--client", "claude", "--yes"}), 2);   // --scope is required without a terminal
    EXPECT_NE(err.str().find("forti mcp install --client"), std::string::npos) << err.str();
    EXPECT_EQ(run({"mcp", "frobnicate"}), 2);
    EXPECT_TRUE(lines(log).empty());   // refused before anything ran
    ASSERT_EQ(run({"mcp", "--help"}), 0);
    EXPECT_TRUE(out.str().starts_with("usage: forti mcp install")) << out.str();
}

TEST_F(McpCli, MissingFortiMcpSaysHowToInstallIt) {
    fs::remove(bin / "forti-mcp");
    EXPECT_EQ(run({"--json", "mcp", "install", "--client", "claude", "--scope", "workspace", "--yes"}), 5);
    auto error = json_out()["error"];
    EXPECT_NE(error["message"].get<std::string>().find("forti-mcp"), std::string::npos);
    EXPECT_EQ(error["details"]["install"]["homebrew"], "brew install valkyrianlabs/tap/forti-mcp");
    EXPECT_EQ(error["details"]["install"]["apt"], "sudo apt install forti-mcp");
    EXPECT_NE(error["details"]["hint"].get<std::string>().find("forti mcp install again"), std::string::npos);
}
