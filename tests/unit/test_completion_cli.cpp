// forti completion and the hidden forti __complete the scripts call on every Tab.

#include <cli_harness.hpp>

#include <app.hpp>
#include <commands.hpp>

#include <algorithm>
#include <format>
#include <fstream>
#include <sstream>

using namespace forti;
using json = nlohmann::json;
namespace fs = std::filesystem;

namespace {

    struct CompletionCli : fake::Cli {
        std::vector<std::string> complete(std::vector<std::string> words) {
            words.insert(words.begin(), "__complete");
            EXPECT_EQ(run(words), 0);
            EXPECT_EQ(err.str(), "");
            std::vector<std::string> lines;
            std::istringstream in(out.str());
            for (std::string line; std::getline(in, line);) lines.push_back(line);
            return lines;
        }

        static bool has(const std::vector<std::string>& lines, const std::string& line) {
            return std::ranges::find(lines, line) != lines.end();
        }

        void touch(const fs::path& path, const std::string& text = "{}") {
            fs::create_directories(path.parent_path());
            std::ofstream(path) << text;
        }
    };

}  // namespace

TEST_F(CompletionCli, CommandsAndHelp) {
    auto all = complete({"commands"});
    EXPECT_TRUE(has(all, "get"));
    EXPECT_TRUE(has(all, "history"));
    EXPECT_TRUE(has(all, "completion"));
    EXPECT_TRUE(has(all, "help"));
    EXPECT_FALSE(has(all, "__complete"));
    EXPECT_EQ(complete({"commands", "ge"}), std::vector<std::string>{"get"});
    // Hidden: not in forti --help.
    ASSERT_EQ(run({"--help"}), 0);
    EXPECT_EQ(out.str().find("__complete"), std::string::npos);
    EXPECT_NE(out.str().find("history"), std::string::npos);
    EXPECT_NE(out.str().find("completion"), std::string::npos);
}

TEST_F(CompletionCli, OptionsAndValuedOptions) {
    auto get = complete({"options", "get"});
    EXPECT_TRUE(has(get, "--fields"));
    EXPECT_TRUE(has(get, "--profile"));   // global
    EXPECT_TRUE(has(get, "--json"));
    EXPECT_EQ(complete({"options", "get", "--fi"}), (std::vector<std::string>{"--fields", "--filter"}));
    auto valued = complete({"valued", "history"});
    EXPECT_TRUE(has(valued, "--limit"));
    EXPECT_TRUE(has(valued, "-n"));
    EXPECT_TRUE(has(valued, "-p"));
    EXPECT_FALSE(has(valued, "--verbose"));
    // No or an unknown command: the global options.
    EXPECT_TRUE(has(complete({"options"}), "--version"));
    EXPECT_TRUE(has(complete({"options", "nosuch"}), "--profile"));
}

TEST_F(CompletionCli, SubcommandsAreInTheHelp) {
    for (const auto& command: cli::commands()) {
        std::string help(command.help);
        for (const auto& sub: complete({"subcommands", std::string(command.name)}))
            EXPECT_TRUE(help.find(std::format("forti {} {}", command.name, sub)) != std::string::npos ||
                        help.find(std::format("forti {} [{}]", command.name, sub)) != std::string::npos)
                    << command.name << " " << sub;
    }
    EXPECT_EQ(complete({"subcommands", "completion"}), (std::vector<std::string>{"bash", "zsh", "fish"}));
    EXPECT_TRUE(has(complete({"subcommands", "plan"}), "approve"));
    EXPECT_TRUE(complete({"subcommands", "get"}).empty());
}

TEST_F(CompletionCli, ProfilesFromConfigNamesOnly) {
    EXPECT_TRUE(complete({"profiles"}).empty());   // no config.json
    touch(paths.config_file(), R"({"version": 1, "profiles": {"fw01": {"host": "a"}, "lab": {}, "fw02": {"bogus": 1}}})");
    EXPECT_EQ(complete({"profiles"}), (std::vector<std::string>{"fw01", "fw02", "lab"}));
    EXPECT_EQ(complete({"profiles", "fw"}), (std::vector<std::string>{"fw01", "fw02"}));
    touch(paths.config_file(), "{ broken");
    EXPECT_TRUE(complete({"profiles"}).empty());
}

TEST_F(CompletionCli, ResourcesOneSegmentAtATime) {
    auto top = complete({"resources"});
    EXPECT_TRUE(has(top, "firewall/"));
    EXPECT_TRUE(has(top, "monitor/"));
    EXPECT_FALSE(has(top, "firewall/address"));
    EXPECT_LT(top.size(), 200u);   // never the whole catalog on an empty word
    for (const auto& line: top) EXPECT_TRUE(line.ends_with("/")) << line;

    auto firewall = complete({"resources", "firewall/"});
    EXPECT_TRUE(has(firewall, "firewall/address"));
    EXPECT_TRUE(has(firewall, "firewall/policy"));
    auto addr = complete({"resources", "firewall/addr"});
    EXPECT_TRUE(has(addr, "firewall/address"));
    EXPECT_TRUE(has(addr, "firewall/addrgrp"));
    for (const auto& line: addr) EXPECT_TRUE(line.starts_with("firewall/addr")) << line;
    EXPECT_TRUE(has(complete({"resources", "monitor/sys"}), "monitor/system/"));
    EXPECT_TRUE(has(complete({"resources", "monitor/system/available-c"}), "monitor/system/available-certificates"));
    EXPECT_TRUE(complete({"resources", "zzz"}).empty());
}

TEST_F(CompletionCli, PendingPlansNewestFirst) {
    EXPECT_TRUE(complete({"plans"}).empty());   // no state directory
    fs::path plans = paths.state / "plans";
    touch(plans / "20261016-120000-aaaaaa.json");
    touch(plans / "20261016-130000-bbbbbb.json");
    touch(plans / "20261016-110000-cccccc.json");
    touch(plans / "20261016-110000-cccccc.applied");   // applied: not offered
    touch(plans / "Not-A-Plan.json");
    touch(plans / "notes.txt");
    EXPECT_EQ(complete({"plans"}), (std::vector<std::string>{"20261016-130000-bbbbbb", "20261016-120000-aaaaaa"}));
    EXPECT_EQ(complete({"plans", "20261016-12"}), std::vector<std::string>{"20261016-120000-aaaaaa"});
}

TEST_F(CompletionCli, ModesAndQuietFailures) {
    EXPECT_EQ(complete({"modes"}), (std::vector<std::string>{"read-only", "guarded", "autonomous"}));
    EXPECT_EQ(complete({"modes", "g"}), std::vector<std::string>{"guarded"});
    // Unknown, empty or option-looking arguments: nothing, exit 0, no error.
    EXPECT_TRUE(complete({"nonsense"}).empty());
    EXPECT_TRUE(complete({}).empty());
    EXPECT_TRUE(complete({"--json"}).empty());
    EXPECT_TRUE(has(complete({"options", "get", "--"}), "--fields"));
    // --json elsewhere on the line does not turn candidates into an envelope.
    EXPECT_EQ(run({"--json", "__complete", "modes", "a"}), 0);
    EXPECT_EQ(out.str(), "autonomous\n");
}

TEST_F(CompletionCli, CompletionPrintsEachScript) {
    for (const char* shell: {"bash", "zsh", "fish"}) {
        ASSERT_EQ(run({"completion", shell}), 0) << err.str();
        EXPECT_NE(out.str().find("__complete"), std::string::npos) << shell;
    }
    ASSERT_EQ(run({"completion", "bash"}), 0);
    EXPECT_NE(out.str().find("complete -F _forti forti"), std::string::npos);
    ASSERT_EQ(run({"completion", "zsh"}), 0);
    EXPECT_TRUE(out.str().starts_with("#compdef forti"));
    ASSERT_EQ(run({"completion", "fish"}), 0);
    EXPECT_NE(out.str().find("complete -c forti"), std::string::npos);
    // The script, not a JSON envelope, even with --json.
    ASSERT_EQ(run({"--json", "completion", "bash"}), 0);
    EXPECT_TRUE(out.str().starts_with("# bash completion"));

    EXPECT_EQ(run({"completion"}), engine::exit_code(engine::Code::usage));
    EXPECT_EQ(run({"completion", "tcsh"}), engine::exit_code(engine::Code::usage));
    EXPECT_NE(err.str().find("bash|zsh|fish"), std::string::npos) << err.str();
}
