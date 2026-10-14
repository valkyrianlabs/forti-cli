// Argument parsing, help, dispatch, rendering and exit codes of the `forti` CLI.

#include <cli_harness.hpp>

#include <args.hpp>
#include <commands.hpp>
#include <output.hpp>

using namespace forti;
using json = nlohmann::json;

namespace {

    using CliTest = fake::Cli;

    std::vector<std::string> lines(const std::string& text) {
        std::vector<std::string> out;
        std::istringstream in(text);
        for (std::string line; std::getline(in, line);) out.push_back(line);
        return out;
    }

    // A Cli whose engine uses the fake transport's built-in "lab" profile (no config file needed).
    struct ReadCli : fake::Cli {
        int read(std::vector<std::string> arguments) {
            out.str("");
            err.str("");
            cli::Output output{.out = &out, .err = &err, .color = color, .err_color = color, .width = width};
            return cli::run(arguments, output, fake::options(transport));
        }
    };

}  // namespace

TEST(Args, ParsesOptionsFlagsShortNamesAndDoubleDash) {
    cli::OptionSpec spec{{"profile", "count"}, {"json"}, {{'p', "profile"}}};
    std::vector<std::string> argv = {"get", "-p", "home", "--count=5", "--json", "--", "--literal"};
    auto args = cli::parse(argv, spec);
    EXPECT_EQ(args.positional, (std::vector<std::string>{"get", "--literal"}));
    EXPECT_EQ(args.value("profile"), "home");
    EXPECT_EQ(args.value("count"), "5");
    EXPECT_TRUE(args.flag("json"));

    std::vector<std::string> unknown = {"--api-key", "secret"};
    EXPECT_THROW(cli::parse(unknown, spec), engine::Failure);
    std::vector<std::string> missing = {"--count"};
    EXPECT_THROW(cli::parse(missing, spec), engine::Failure);
    std::vector<std::string> flag_value = {"--json=1"};
    EXPECT_THROW(cli::parse(flag_value, spec), engine::Failure);
}

TEST(Args, SplitsCommandLinesLikeAShellWithoutOne) {
    EXPECT_EQ(cli::split_command(R"(op read "op://ops/fw 01/key" --no-newline)"),
              (std::vector<std::string>{"op", "read", "op://ops/fw 01/key", "--no-newline"}));
    EXPECT_EQ(cli::split_command(R"(sh -c 'echo $KEY; true' a\ b "q\"x")"),
              (std::vector<std::string>{"sh", "-c", "echo $KEY; true", "a b", "q\"x"}));
    EXPECT_EQ(cli::split_command("  "), std::vector<std::string>{});
    EXPECT_THROW(cli::split_command("pass 'unterminated"), engine::Failure);
}

TEST_F(CliTest, HelpListsGroupsAndEveryCommandHasConsistentHelp) {
    EXPECT_EQ(run({"--help"}), 0);
    std::string help = out.str();
    for (const char* text: {"setup:", "read:", "configure", "doctor", "profile", "get", "global options:", "exit status:"})
        EXPECT_NE(help.find(text), std::string::npos) << text;

    for (const auto& command: cli::commands()) {
        EXPECT_EQ(run({std::string(command.name), "--help"}), 0) << command.name;
        EXPECT_TRUE(out.str().starts_with("usage: forti " + std::string(command.name))) << out.str();
        EXPECT_NE(out.str().find("global options:"), std::string::npos) << command.name;
        EXPECT_FALSE(command.summary.empty());
    }
    EXPECT_EQ(run({"help", "configure"}), 0);
    EXPECT_NE(out.str().find("--api-key-stdin"), std::string::npos);
    EXPECT_EQ(run({"--version"}), 0);
    EXPECT_NE(out.str().find("7.4.8"), std::string::npos);
}

TEST_F(CliTest, UsageErrorsExitTwoWithSuggestionsAndJsonEnvelopes) {
    EXPECT_EQ(run({}), 2);
    EXPECT_NE(err.str().find("usage:"), std::string::npos);

    EXPECT_EQ(run({"confgure"}), 2);
    EXPECT_NE(err.str().find("unknown command \"confgure\""), std::string::npos);
    EXPECT_NE(err.str().find("did you mean: configure"), std::string::npos);
    EXPECT_TRUE(out.str().empty());

    EXPECT_EQ(run({"--json", "confgure"}), 2);
    json envelope = json_out();
    EXPECT_FALSE(envelope["ok"]);
    EXPECT_EQ(envelope["error"]["code"], "usage");
    EXPECT_TRUE(err.str().empty());

    EXPECT_EQ(run({"doctor", "--bogus"}), 2);
    EXPECT_NE(err.str().find("forti doctor --help"), std::string::npos);
}

TEST_F(CliTest, MissingProfileIsAConfigurationError) {
    EXPECT_EQ(run({"get", "firewall/address"}), 3);
    EXPECT_NE(err.str().find("forti configure"), std::string::npos);
    EXPECT_TRUE(transport->requests.empty());
}

TEST_F(ReadCli, TablesPutTheKeyFirstThenRequestedFieldsAndHideBookkeeping) {
    transport->reply(200, fake::envelope(json::array({
            {{"policyid", 1}, {"name", "lan-out"}, {"action", "accept"}, {"status", "enable"}, {"q_origin_key", 1}},
            {{"policyid", 22}, {"name", "block"}, {"action", "deny"}, {"status", "disable"}, {"q_origin_key", 22}}})));
    ASSERT_EQ(read({"get", "firewall/policy", "--fields", "name,action,status,policyid"}), 0) << err.str();
    auto text = lines(out.str());
    ASSERT_GE(text.size(), 3u);
    EXPECT_EQ(text[0], "policyid  name     action  status");
    EXPECT_EQ(text[1], "1         lan-out  accept  enable");
    EXPECT_EQ(out.str().find("q_origin_key"), std::string::npos);
    EXPECT_EQ(out.str().find("\x1b["), std::string::npos);   // no color off a terminal

    transport->reply(200, fake::envelope(json::array({{{"policyid", 1}, {"q_origin_key", 1}}})));
    ASSERT_EQ(read({"--json", "get", "firewall/policy"}), 0);
    EXPECT_EQ(json_out()["data"][0]["q_origin_key"], 1);   // --json keeps everything
}

TEST_F(ReadCli, ColorOnlyWhenEnabledAndTablesFitTheTerminal) {
    color = true;
    width = 40;
    json rows = json::array();
    for (int i = 0; i < 3; ++i)
        rows.push_back({{"name", std::format("address-with-a-rather-long-name-{}", i)},
                        {"comment", std::string(60, 'c')}, {"subnet", "192.0.2.0 255.255.255.0"}, {"type", "ipmask"}});
    transport->reply(200, fake::envelope(rows));
    ASSERT_EQ(read({"get", "firewall/address"}), 0);
    EXPECT_NE(out.str().find("\x1b[1m"), std::string::npos);
    auto text = lines(out.str());
    for (std::size_t i = 1; i < text.size(); ++i)   // the header and the note carry escape codes
        if (!text[i].starts_with("\x1b")) EXPECT_LE(cli::display_width(text[i]), 40u) << text[i];
    EXPECT_NE(out.str().find("--fields or --json"), std::string::npos);
    EXPECT_TRUE(text[1].starts_with("address-"));
}

TEST_F(ReadCli, ExitCodesFollowTheErrorTable) {
    transport->reply(404, json{{"status", "error"}, {"http_status", 404}});
    EXPECT_EQ(read({"get", "firewall/address", "forti-cli-does-not-exist"}), 5);
    EXPECT_NE(err.str().find("forti: error: firewall/address \"forti-cli-does-not-exist\" not found"), std::string::npos)
            << err.str();
    EXPECT_EQ(err.str().find("HTTP 404"), std::string::npos);

    transport->reply(404, json{{"status", "error"}, {"http_status", 404}});
    EXPECT_EQ(read({"--json", "get", "firewall/address", "gone"}), 5);
    EXPECT_EQ(json_out()["error"]["details"]["http_status"], 404);

    transport->reply(401, json{{"status", "error"}, {"http_status", 401}});
    EXPECT_EQ(read({"get", "firewall/address"}), 4);
    EXPECT_NE(err.str().find("does not retry"), std::string::npos);

    EXPECT_EQ(read({"get", "firewall/adress"}), 5);    // unknown_resource
    EXPECT_EQ(read({"get", "firewall/address", "--fields", "subnett"}), 6);   // validation
    EXPECT_EQ(read({"get", "firewall/address", "--count", "x"}), 2);          // usage
    EXPECT_EQ(transport->requests.size(), 3u);
}

TEST_F(ReadCli, DevicesListsProfilesWithTheDefaultMarked) {
    ASSERT_EQ(read({"devices"}), 0);
    auto text = lines(out.str());
    ASSERT_GE(text.size(), 2u);
    EXPECT_TRUE(text[0].starts_with("profile"));
    EXPECT_TRUE(text[1].starts_with("lab *")) << text[1];
    EXPECT_NE(text[1].find("fortigate.test:8443"), std::string::npos);
    EXPECT_NE(text[1].find("read-only"), std::string::npos);
}

TEST(Output, ExitStatusMapsEveryCode) {
    EXPECT_EQ(cli::exit_status("internal"), 1);
    EXPECT_EQ(cli::exit_status("usage"), 2);
    EXPECT_EQ(cli::exit_status("config"), 3);
    EXPECT_EQ(cli::exit_status("connection"), 4);
    EXPECT_EQ(cli::exit_status("auth"), 4);
    EXPECT_EQ(cli::exit_status("not_found"), 5);
    EXPECT_EQ(cli::exit_status("unknown_resource"), 5);
    EXPECT_EQ(cli::exit_status("validation"), 6);
    EXPECT_EQ(cli::exit_status("api"), 6);
    EXPECT_EQ(cli::exit_status("stale_plan"), 7);
    EXPECT_EQ(cli::exit_status("approval_required"), 7);
    EXPECT_EQ(cli::exit_status("policy_denied"), 7);
    EXPECT_EQ(cli::exit_status("partial_failure"), 8);
    EXPECT_EQ(cli::exit_status("outcome_unknown"), 8);
    EXPECT_EQ(cli::exit_status("something-new"), 1);
}

TEST(Output, ErrorsGoToStderrWithHintsAndJsonToStdout) {
    std::ostringstream out, err;
    cli::Output text{.out = &out, .err = &err};
    json failure = {{"ok", false}, {"error", {{"code", "connection"}, {"message", "cannot reach fw"}}}};
    EXPECT_EQ(cli::emit(text, failure), 4);
    EXPECT_TRUE(out.str().empty());
    EXPECT_NE(err.str().find("forti: error: cannot reach fw"), std::string::npos);
    EXPECT_NE(err.str().find("hint:"), std::string::npos);
    EXPECT_NE(err.str().find("--ca-bundle"), std::string::npos);

    std::ostringstream jout, jerr;
    cli::Output machine{.format = cli::Format::json, .out = &jout, .err = &jerr};
    EXPECT_EQ(cli::emit(machine, failure), 4);
    EXPECT_EQ(json::parse(jout.str()), failure);
    EXPECT_TRUE(jerr.str().empty());
}
