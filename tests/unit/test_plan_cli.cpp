// forti plan / apply / rollback from the command line, without a terminal (as scripts and agents
// run them): naming plans, --apply, rollback, attribute suggestions and the text output. The
// interactive shortcuts (inline approval, "Apply now?") are tested on a pseudo-terminal in
// tests/integration/test_cli.py.

#include <cli_harness.hpp>

#include <output.hpp>

#include <filesystem>
#include <fstream>

using namespace forti;
using json = nlohmann::json;
namespace fs = std::filesystem;

namespace {

    const std::string serial = "FGT60FTK00000000";

    json address(const std::string& name, json extra = json::object()) {
        json object = {{"name", name}, {"q_origin_key", name}, {"uuid", "8f0c-" + name}, {"subnet", "192.0.2.0 255.255.255.0"},
                       {"type", "ipmask"}, {"comment", ""}, {"color", 0}};
        object.update(extra);
        return object;
    }

    json written(const std::string& mkey) {
        return {{"status", "success"}, {"http_status", 200}, {"serial", serial}, {"version", "v7.4.8"}, {"vdom", "root"},
                {"mkey", mkey}};
    }

    struct PlanCli : fake::Cli {
        engine::Mode mode = engine::Mode::autonomous;

        int forti(std::vector<std::string> arguments) {
            out.str("");
            err.str("");
            cli::Output output{.out = &out, .err = &err};
            auto options = fake::options(transport, mode);
            options.paths = paths;
            return cli::run(arguments, output, options);
        }

        // Plans "comment" on address LAN (currently "old"); returns the plan id.
        std::string plan_comment(const std::string& comment, const std::string& old = "old") {
            transport->reply(200, fake::envelope(json::array({address("LAN", {{"comment", old}})})));
            EXPECT_EQ(forti({"--json", "plan", "set", "firewall/address", "LAN", "comment=" + comment}), 0) << err.str() << out.str();
            return json_out()["data"]["id"];
        }

        // Replies for applying a comment change from `from` to `to`: re-read, PUT, verify.
        void script_apply(const std::string& from, const std::string& to) {
            transport->reply(200, fake::envelope(json::array({address("LAN", {{"comment", from}})})));
            transport->reply(200, written("LAN"));
            transport->reply(200, fake::envelope(json::array({address("LAN", {{"comment", to}})})));
        }

        std::size_t writes() const {
            std::size_t n = 0;
            for (const auto& request: transport->requests) n += request.method != fortiapi::Method::Get;
            return n;
        }
    };

}  // namespace

TEST_F(PlanCli, ReadOnlyRefusalNamesTheModeCommand) {
    mode = engine::Mode::read_only;
    std::string id = plan_comment("new");
    ASSERT_EQ(forti({"plan", "show", id}), 0) << err.str();
    EXPECT_NE(out.str().find("forti profile mode lab guarded"), std::string::npos) << out.str();
    EXPECT_EQ(out.str().find("forti apply"), std::string::npos) << out.str();   // read-only: no apply hint
    EXPECT_NE(forti({"--json", "apply", id}), 0);
    json error = json_out()["error"];
    EXPECT_EQ(error["code"], "policy_denied");
    EXPECT_NE(error["message"].get<std::string>().find("forti profile mode lab guarded"), std::string::npos);
    EXPECT_EQ(error["message"].get<std::string>().find("forti configure"), std::string::npos);
    EXPECT_EQ(error["details"]["mode_command"], "forti profile mode lab guarded");
    EXPECT_EQ(writes(), 0u);
}

TEST_F(PlanCli, PlansAreNamedByPrefixTailOrLatest) {
    std::string first = plan_comment("one");
    std::string second;
    do second = plan_comment("two");   // ids are random: make the two tails differ in their first character
    while (second.substr(16, 1) == first.substr(16, 1));

    ASSERT_EQ(forti({"--json", "plan", "show", "latest"}), 0) << err.str();
    EXPECT_EQ(json_out()["data"]["id"], second);
    ASSERT_EQ(forti({"--json", "plan", "show", second.substr(16)}), 0) << err.str();   // the random part
    EXPECT_EQ(json_out()["data"]["id"], second);
    ASSERT_EQ(forti({"--json", "plan", "show", first.substr(16)}), 0) << err.str();
    EXPECT_EQ(json_out()["data"]["id"], first);

    // A prefix of both is ambiguous and lists them; an unknown one is not_found.
    EXPECT_EQ(forti({"--json", "plan", "show", first.substr(0, 8)}), 2);
    json candidates = json_out()["error"]["details"]["candidates"];
    EXPECT_EQ(candidates.size(), 2u);
    EXPECT_EQ(forti({"--json", "plan", "show", "zzzz"}), 5);

    // Without a terminal, a plan must be named.
    EXPECT_EQ(forti({"apply"}), 2);
    EXPECT_NE(err.str().find("latest"), std::string::npos) << err.str();
    EXPECT_EQ(forti({"plan", "approve"}), 2);
    EXPECT_EQ(forti({"plan", "show"}), 2);
    EXPECT_EQ(writes(), 0u);

    // apply by prefix tells which plan it took.
    script_apply("old", "two");
    ASSERT_EQ(forti({"apply", second.substr(16)}), 0) << err.str();
    EXPECT_NE(err.str().find(second), std::string::npos) << err.str();
    EXPECT_NE(out.str().find("1 change applied and verified."), std::string::npos) << out.str();
    EXPECT_EQ(out.str().find("applied but unverified"), std::string::npos);
    EXPECT_NE(out.str().find("forti rollback " + second), std::string::npos) << out.str();
}

TEST_F(PlanCli, LatestSkipsRollbackPlansAndProfilesFilter) {
    std::string id = plan_comment("new");
    script_apply("old", "new");
    ASSERT_EQ(forti({"--json", "apply", id}), 0) << err.str();
    std::string rollback = json_out()["data"]["rollback"]["plan_id"];
    ASSERT_EQ(forti({"--json", "plan", "show", "latest"}), 0) << err.str();
    EXPECT_EQ(json_out()["data"]["id"], id);   // the rollback plan is newer, but not "latest"
    ASSERT_EQ(forti({"--json", "plan", "show", rollback}), 0);   // named in full it is fine
}

TEST_F(PlanCli, DigestOnlyWithVerbose) {
    std::string id = plan_comment("new");
    ASSERT_EQ(forti({"plan", "show", id}), 0) << err.str();
    EXPECT_EQ(out.str().find("digest "), std::string::npos) << out.str();
    ASSERT_EQ(forti({"plan", "show", id, "--verbose"}), 0) << err.str();
    EXPECT_NE(out.str().find("digest "), std::string::npos) << out.str();
    ASSERT_EQ(forti({"--json", "plan", "show", id}), 0);
    EXPECT_EQ(json_out()["data"]["digest"].get<std::string>().size(), 64u);
}

TEST_F(PlanCli, ApplyFlagPlansAndAppliesInOneCommand) {
    transport->reply(200, fake::envelope(json::array({address("LAN", {{"comment", "old"}})})));
    script_apply("old", "new");
    ASSERT_EQ(forti({"plan", "set", "firewall/address", "LAN", "comment=new", "--apply"}), 0) << err.str() << out.str();
    EXPECT_NE(out.str().find("Plan "), std::string::npos);
    EXPECT_NE(out.str().find("1 change applied and verified."), std::string::npos) << out.str();
    EXPECT_EQ(writes(), 1u);

    // --json: one envelope with the apply result and the plan.
    transport->reply(200, fake::envelope(json::array({address("LAN", {{"comment", "new"}})})));
    script_apply("new", "newer");
    ASSERT_EQ(forti({"--json", "plan", "set", "firewall/address", "LAN", "comment=newer", "--apply"}), 0) << err.str();
    json data = json_out()["data"];
    EXPECT_EQ(data["verified"], 1);
    EXPECT_EQ(data["plan"]["id"], data["plan_id"]);
}

TEST_F(PlanCli, ApplyFlagStopsAtTheApprovalWithoutATerminal) {
    mode = engine::Mode::guarded;
    transport->reply(200, fake::envelope(json::array({address("LAN", {{"comment", "old"}})})));
    EXPECT_EQ(forti({"plan", "set", "firewall/address", "LAN", "comment=new", "--apply"}), engine::exit_code(engine::Code::approval_required));
    EXPECT_NE(err.str().find("forti plan approve"), std::string::npos) << err.str();
    // The approval command is printed once, not twice.
    std::string text = err.str();
    EXPECT_EQ(text.find("forti plan approve"), text.rfind("forti plan approve")) << text;
    EXPECT_EQ(writes(), 0u);
}

TEST_F(PlanCli, RollbackUndoesTheLastApply) {
    EXPECT_EQ(forti({"rollback"}), 5);   // nothing applied yet
    std::string id = plan_comment("new");
    script_apply("old", "new");
    ASSERT_EQ(forti({"apply", id}), 0) << err.str();

    // The rollback re-reads LAN (before-state "new"), writes "old" back and verifies.
    script_apply("new", "old");
    ASSERT_EQ(forti({"rollback"}), 0) << err.str() << out.str();
    EXPECT_NE(out.str().find("Rolling back plan " + id), std::string::npos) << out.str();
    EXPECT_NE(out.str().find("1 change applied and verified."), std::string::npos) << out.str();
    ASSERT_EQ(forti({"--json", "plan", "list"}), 0);
    std::size_t applied_rollbacks = 0;
    for (const auto& plan: json_out()["data"])
        applied_rollbacks += plan["kind"] == "rollback" && plan["state"] == "applied";
    EXPECT_EQ(applied_rollbacks, 1u);

    // Rolling back the same plan again is refused: its rollback was applied.
    EXPECT_EQ(forti({"--json", "rollback", id}), engine::exit_code(engine::Code::policy_denied));
    EXPECT_NE(json_out()["error"]["message"].get<std::string>().find("already applied"), std::string::npos);
    // A plan that was never applied has no rollback.
    std::string other = plan_comment("x");
    EXPECT_EQ(forti({"rollback", other}), 5);
}

TEST_F(PlanCli, RollbackInGuardedModeNeedsTheApproval) {
    std::string id = plan_comment("new");
    script_apply("old", "new");
    ASSERT_EQ(forti({"apply", id}), 0) << err.str();
    mode = engine::Mode::guarded;
    transport->requests.clear();
    EXPECT_EQ(forti({"rollback"}), engine::exit_code(engine::Code::approval_required));
    EXPECT_NE(err.str().find("forti plan approve"), std::string::npos) << err.str();
    EXPECT_EQ(writes(), 0u);
}

TEST_F(PlanCli, CreateTakesAttributePairs) {
    transport->reply(404, {{"status", "error"}, {"http_status", 404}, {"serial", serial}, {"version", "v7.4.8"}});
    ASSERT_EQ(forti({"--json", "plan", "create", "firewall/address", "name=web", "subnet=192.0.2.10 255.255.255.255", "color=3"}), 0)
            << err.str() << out.str();
    json op = json_out()["data"]["operations"][0];
    EXPECT_EQ(op["op"], "create");
    EXPECT_EQ(op["key"], "web");
    EXPECT_EQ(op["wire"]["body"]["subnet"], "192.0.2.10 255.255.255.255");
    EXPECT_EQ(op["wire"]["body"]["color"], 3);
    EXPECT_EQ(forti({"plan", "create", "firewall/address"}), 2);
}

TEST_F(PlanCli, UnknownAttributesGetASuggestion) {
    transport->reply(200, fake::envelope(json::array({address("LAN")})));
    EXPECT_EQ(forti({"--json", "plan", "set", "firewall/address", "LAN", "colour=3"}), engine::exit_code(engine::Code::validation));
    json error = json_out()["error"];
    EXPECT_EQ(error["code"], "validation");
    EXPECT_NE(error["message"].get<std::string>().find("did you mean color?"), std::string::npos) << error.dump();
    EXPECT_EQ(error["details"]["suggestions"], json::array({"color"}));

    transport->reply(404, {{"status", "error"}, {"http_status", 404}, {"serial", serial}, {"version", "v7.4.8"}});
    EXPECT_EQ(forti({"--json", "plan", "create", "firewall/address", "name=web", "sbnet=192.0.2.1/32"}), engine::exit_code(engine::Code::validation));
    EXPECT_NE(json_out()["error"]["message"].get<std::string>().find("did you mean subnet?"), std::string::npos);
    // Nothing close: no suggestion.
    transport->reply(200, fake::envelope(json::array({address("LAN")})));
    EXPECT_EQ(forti({"--json", "plan", "set", "firewall/address", "LAN", "zzzzzzzz=1"}), engine::exit_code(engine::Code::validation));
    EXPECT_FALSE(json_out()["error"]["details"].contains("suggestions"));
}
