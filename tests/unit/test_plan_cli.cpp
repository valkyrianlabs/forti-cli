// forti plan / apply / rollback from the command line, without a terminal (as scripts and agents
// run them): naming plans, --apply, rollback, attribute suggestions and the text output. The
// interactive shortcuts (inline approval, "Apply now?") are tested on a pseudo-terminal in
// tests/integration/test_cli.py.

#include <cli_harness.hpp>

#include <output.hpp>

#include <algorithm>
#include <filesystem>
#include <format>
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
    // Every plan made above shares the date prefix (the loop may have made more than two).
    json candidates = json_out()["error"]["details"]["candidates"];
    EXPECT_GE(candidates.size(), 2u);
    for (const auto& id: {first, second})
        EXPECT_NE(std::ranges::find(candidates, json(id)), candidates.end()) << id;
    EXPECT_EQ(forti({"--json", "plan", "show", "zzzz"}), 5);

    // Without a terminal, a plan must be named, and nothing is approved without --yes.
    EXPECT_EQ(forti({"apply"}), 2);
    EXPECT_NE(err.str().find("latest"), std::string::npos) << err.str();
    EXPECT_EQ(forti({"plan", "approve", second}), engine::exit_code(engine::Code::approval_required));
    EXPECT_NE(err.str().find("needs a person"), std::string::npos) << err.str();
    EXPECT_EQ(forti({"approve", "--yes"}), 2);
    EXPECT_EQ(forti({"plan", "show"}), 2);
    // Two plans are waiting: latest is not a guess when acting on one.
    EXPECT_EQ(forti({"--json", "apply", "latest"}), 2);
    EXPECT_GE(json_out()["error"]["details"]["candidates"].size(), 2u);
    EXPECT_EQ(writes(), 0u);

    // apply by prefix shows which plan it took.
    script_apply("old", "two");
    ASSERT_EQ(forti({"apply", second.substr(16)}), 0) << err.str();
    EXPECT_NE(out.str().find("plan " + second), std::string::npos) << out.str();
    EXPECT_NE(out.str().find("1 change applied and verified."), std::string::npos) << out.str();
    EXPECT_EQ(out.str().find("applied but unverified"), std::string::npos);
    EXPECT_NE(out.str().find("forti rollback " + second), std::string::npos) << out.str();
}

TEST_F(PlanCli, LatestSkipsRollbackPlansAndProfilesFilter) {
    std::string id = plan_comment("new");
    script_apply("old", "new");
    ASSERT_EQ(forti({"--json", "apply", id}), 0) << err.str();
    std::string rollback = json_out()["data"]["rollback"]["plan_id"];
    std::string waiting = plan_comment("newer");
    ASSERT_EQ(forti({"--json", "plan", "show", "latest"}), 0) << err.str();
    EXPECT_EQ(json_out()["data"]["id"], waiting);   // the rollback plan is newer, but not "latest"
    ASSERT_EQ(forti({"--json", "plan", "show", rollback}), 0);   // named in full it is fine
}

TEST_F(PlanCli, AnAppliedPlanIsDeletedAndARepeatIsRefusedAsApplied) {
    std::string id = plan_comment("new");
    script_apply("old", "new");
    ASSERT_EQ(forti({"--json", "apply", id}), 0) << err.str();
    std::string rollback = json_out()["data"]["rollback"]["plan_id"];
    EXPECT_FALSE(fs::exists(paths.state / "plans" / (id + ".json")));
    EXPECT_TRUE(fs::exists(paths.state / "plans" / (id + ".applied")));

    // Named in full or by its tail, at a terminal or not: already applied, not "no such plan".
    std::size_t sent = transport->requests.size();
    for (const auto& name: {id, id.substr(16)}) {
        EXPECT_EQ(forti({"apply", name}), engine::exit_code(engine::Code::policy_denied)) << name;
        EXPECT_NE(err.str().find("already applied"), std::string::npos) << err.str();
        EXPECT_EQ(forti({"--json", "apply", name}), engine::exit_code(engine::Code::policy_denied));
        EXPECT_EQ(json_out()["error"]["details"]["reason"], "already_applied");
    }
    EXPECT_EQ(transport->requests.size(), sent);   // nothing was read or sent
    EXPECT_EQ(forti({"--json", "plan", "show", id}), 5);
    EXPECT_EQ(json_out()["error"]["details"]["reason"], "already_applied");
    EXPECT_EQ(forti({"--json", "approve", id, "--yes"}), engine::exit_code(engine::Code::policy_denied));

    // Listed from its marker; nothing else is stored but the rollback plan.
    ASSERT_EQ(forti({"--json", "plan", "list"}), 0);
    json listed = json_out()["data"];
    ASSERT_EQ(listed.size(), 2u);
    for (const auto& item: listed) {
        if (item["id"] == id) {
            EXPECT_EQ(item["state"], "applied");
            EXPECT_FALSE(item["stored"].get<bool>());
            EXPECT_EQ(item["outcome"], "ok");
            EXPECT_EQ(item["rollback_plan"], rollback);
            EXPECT_EQ(item["profile"], "lab");
            EXPECT_NE(item["summary"].get<std::string>().find("1 update"), std::string::npos) << item.dump();
        } else {
            EXPECT_EQ(item["id"], rollback);
            EXPECT_EQ(item["state"], "pending");
        }
    }
    EXPECT_EQ(forti({"--json", "plan", "show", "latest"}), 5);   // no stored plan but the rollback

    // forti rollback still finds the applied plan's rollback.
    script_apply("new", "old");
    ASSERT_EQ(forti({"--json", "rollback", id}), 0) << err.str();
    EXPECT_FALSE(fs::exists(paths.state / "plans" / (rollback + ".json")));
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
    EXPECT_NE(out.str().find("1 operation on lab"), std::string::npos) << out.str();
    EXPECT_NE(out.str().find("\"old\" → \"new\""), std::string::npos) << out.str();
    EXPECT_EQ(out.str().find("PUT "), std::string::npos) << out.str();   // request lines only with --verbose
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
    EXPECT_NE(err.str().find("forti approve "), std::string::npos) << err.str();
    // The approval command is printed once, not twice.
    std::string text = err.str();
    EXPECT_EQ(text.find("forti approve "), text.rfind("forti approve ")) << text;
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
    EXPECT_NE(out.str().find("Undoes plan " + id), std::string::npos) << out.str();
    EXPECT_NE(out.str().find("1 change applied and verified."), std::string::npos) << out.str();
    ASSERT_EQ(forti({"--json", "plan", "list"}), 0);
    std::size_t applied_rollbacks = 0;
    json plans = json_out()["data"];   // json_out() returns a temporary: keep it alive for the loop
    for (const auto& plan: plans)
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
    EXPECT_NE(err.str().find("forti approve "), std::string::npos) << err.str();
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

// ---- forti set / create / delete: one command, at most one question ----

TEST_F(PlanCli, SetAppliesInOneCommandWhateverTheSpelling) {
    for (std::vector<std::string> spelling: {std::vector<std::string>{"firewall/address/LAN"}, {"firewall/address", "LAN"},
                                             {"firewall", "address", "LAN"}, {"address", "LAN"}}) {
        transport->requests.clear();
        transport->reply(200, fake::envelope(json::array({address("LAN", {{"comment", "old"}})})));
        script_apply("old", "new");
        std::vector<std::string> command = {"set"};
        command.insert(command.end(), spelling.begin(), spelling.end());
        command.push_back("comment=new");
        ASSERT_EQ(forti(command), 0) << spelling.front() << ": " << err.str() << out.str();
        EXPECT_NE(out.str().find("update firewall/address \"LAN\""), std::string::npos) << out.str();
        EXPECT_NE(out.str().find("1 change applied and verified."), std::string::npos) << out.str();
        EXPECT_EQ(out.str().find("Apply these changes?"), std::string::npos);   // autonomous: no question
        EXPECT_EQ(writes(), 1u);
    }
}

TEST_F(PlanCli, SetNeedsSomethingToChange) {
    EXPECT_EQ(forti({"set", "firewall/address/LAN"}), 2);
    EXPECT_NE(err.str().find("nothing to change"), std::string::npos) << err.str();
    EXPECT_EQ(forti({"set"}), 2);
    EXPECT_EQ(forti({"delete", "firewall/address"}), 2);   // no key
    EXPECT_EQ(forti({"create", "firewall/address/web", "subnet=192.0.2.1/32"}), 2);   // a key, not attributes
    EXPECT_EQ(writes(), 0u);
}

TEST_F(PlanCli, ReadOnlySetShowsTheChangeAndHowToAllowIt) {
    mode = engine::Mode::read_only;
    transport->reply(200, fake::envelope(json::array({address("LAN", {{"comment", "old"}})})));
    EXPECT_EQ(forti({"set", "firewall/address/LAN", "comment=new"}), engine::exit_code(engine::Code::policy_denied));
    EXPECT_NE(out.str().find("\"old\" → \"new\""), std::string::npos) << out.str();
    EXPECT_NE(err.str().find("read-only: nothing was changed"), std::string::npos) << err.str();
    EXPECT_NE(err.str().find("forti profile mode lab guarded"), std::string::npos) << err.str();
    EXPECT_EQ(err.str().find("--writes"), std::string::npos);
    EXPECT_EQ(writes(), 0u);
}

TEST_F(PlanCli, GuardedSetWithoutATerminalIsNeverApproved) {
    mode = engine::Mode::guarded;
    transport->reply(200, fake::envelope(json::array({address("LAN", {{"comment", "old"}})})));
    EXPECT_EQ(forti({"set", "firewall/address/LAN", "comment=new"}), engine::exit_code(engine::Code::approval_required));
    EXPECT_NE(err.str().find("needs your approval"), std::string::npos) << err.str();
    EXPECT_NE(err.str().find("forti approve "), std::string::npos) << err.str();
    EXPECT_EQ(writes(), 0u);
    // --json: the envelope says the same, with the plan.
    transport->reply(200, fake::envelope(json::array({address("LAN", {{"comment", "old"}})})));
    EXPECT_EQ(forti({"--json", "set", "firewall/address/LAN", "comment=new"}), engine::exit_code(engine::Code::approval_required));
    json error = json_out()["error"];
    std::string id = error["details"]["plan"]["id"];
    EXPECT_EQ(error["details"]["approve_command"], "forti approve " + id);
    // The person approves (here as a script would, explicitly), and the plan's maker applies it.
    ASSERT_EQ(forti({"approve", id, "--yes"}), 0) << err.str();
    EXPECT_NE(out.str().find("The agent can apply it now"), std::string::npos) << out.str();
    script_apply("old", "new");
    ASSERT_EQ(forti({"apply", id}), 0) << err.str();
    EXPECT_EQ(writes(), 1u);
}

TEST_F(PlanCli, DeleteAndCreateInOneCommand) {
    transport->reply(200, fake::envelope(json::array({address("web")})));   // plan: the object exists
    transport->reply(200, fake::envelope(json::array({address("web")})));   // apply: re-read
    transport->reply(200, written("web"));                                  // DELETE
    transport->reply(404, {{"status", "error"}, {"http_status", 404}, {"serial", serial}, {"version", "v7.4.8"}});   // verify: gone
    ASSERT_EQ(forti({"delete", "firewall/address/web"}), 0) << err.str() << out.str();
    EXPECT_NE(out.str().find("delete firewall/address \"web\""), std::string::npos) << out.str();
    EXPECT_EQ(transport->requests[2].method, fortiapi::Method::Delete);

    transport->requests.clear();
    transport->reply(404, {{"status", "error"}, {"http_status", 404}, {"serial", serial}, {"version", "v7.4.8"}});
    ASSERT_EQ(forti({"create", "address", "name=web", "subnet=192.0.2.10 255.255.255.255", "--dry-run"}), 0) << err.str();
    EXPECT_NE(out.str().find("create firewall/address"), std::string::npos) << out.str();
    EXPECT_EQ(writes(), 0u);   // --dry-run: planned only
}

TEST_F(PlanCli, AuditRecordsTheChangeAndItsApproval) {
    mode = engine::Mode::guarded;
    std::string id = plan_comment("new");
    ASSERT_EQ(forti({"approve", id, "--yes"}), 0) << err.str();
    script_apply("old", "new");
    ASSERT_EQ(forti({"apply", id}), 0) << err.str();
    std::ifstream in(paths.state / "audit.jsonl");
    std::string line;
    json apply;
    while (std::getline(in, line)) {
        json event = json::parse(line);
        if (event["event"] == "apply") apply = event;
    }
    ASSERT_TRUE(apply.is_object());
    EXPECT_EQ(apply["outcome"], "ok");
    EXPECT_TRUE(apply["approved_by"].get<std::string>().starts_with("cli:")) << apply.dump();
    EXPECT_NE(apply["summary"].get<std::string>().find("1 update"), std::string::npos) << apply.dump();
}

// ---- child tables: --parent / --child, forti get --child ----

namespace {

    json reservation(unsigned id, const std::string& ip, const std::string& description = "") {
        return {{"id", id}, {"q_origin_key", id}, {"type", "mac"}, {"ip", ip}, {"mac", "00:00:5e:00:53:07"},
                {"action", "reserved"}, {"description", description}};
    }

    // FortiOS 7.4.8 child write replies: POST mkey = the new entry's key (no child_mkey); PUT mkey = the
    // parent's key, child_mkey = the entry's as text.
    json child_written(const std::string& method, unsigned entry) {
        json body = {{"http_method", method}, {"status", "success"}, {"http_status", 200}, {"serial", serial},
                     {"version", "v7.4.8"}, {"vdom", "root"}, {"child_path", "reserved-address"}};
        if (method == "POST") body["mkey"] = entry;
        else {
            body["mkey"] = 1;
            body["child_mkey"] = std::to_string(entry);
        }
        return body;
    }

    const std::string reservations = "https://fortigate.test:8443/api/v2/cmdb/system.dhcp/server/1/reserved-address";

}  // namespace

TEST_F(PlanCli, GetReadsAChildTable) {
    transport->reply(200, fake::envelope(json::array({reservation(7, "192.0.2.7", "nas"), reservation(21, "192.0.2.21")})));
    ASSERT_EQ(forti({"--json", "get", "system.dhcp/server", "1", "--child", "reserved-address", "--fields", "id,ip"}), 0) << err.str();
    EXPECT_EQ(transport->requests.back().url, reservations + "?format=id%7Cip");
    EXPECT_EQ(json_out()["data"].size(), 2u);
    EXPECT_EQ(json_out()["meta"]["child"], "reserved-address");

    transport->reply(200, fake::envelope(json::array({reservation(21, "192.0.2.21")})));
    ASSERT_EQ(forti({"--json", "get", "system.dhcp/server/1", "--child", "reserved-address", "--child-key", "21"}), 0) << err.str();
    EXPECT_EQ(transport->requests.back().url, reservations + "/21");
    EXPECT_EQ(json_out()["data"]["ip"], "192.0.2.21");

    // --all pages a child listing; it is the entry key (--child-key) that makes a read single.
    transport->reply(200, fake::envelope(json::array({reservation(7, "192.0.2.7")})));
    ASSERT_EQ(forti({"--json", "get", "system.dhcp/server", "1", "--child", "reserved-address", "--all"}), 0) << err.str();
    EXPECT_EQ(forti({"get", "system.dhcp/server", "1", "--child", "reserved-address", "--child-key", "7", "--all"}), 2);
    EXPECT_EQ(forti({"get", "system.dhcp/server", "1", "--child-key", "7"}), 2);
}

TEST_F(PlanCli, SetCreateAndDeleteTakeParentAndChild) {
    // set: the key is the entry's.
    transport->reply(200, fake::envelope(json::array({reservation(7, "192.0.2.7", "old")})));   // plan
    transport->reply(200, fake::envelope(json::array({reservation(7, "192.0.2.7", "old")})));   // apply: re-read
    transport->reply(200, child_written("PUT", 7));
    transport->reply(200, fake::envelope(json::array({reservation(7, "192.0.2.7", "nas")})));   // verify
    ASSERT_EQ(forti({"set", "system.dhcp/server", "7", "--parent", "1", "--child", "reserved-address", "description=nas"}), 0)
            << err.str() << out.str();
    EXPECT_NE(out.str().find("update system.dhcp/server \"1\" reserved-address \"7\""), std::string::npos) << out.str();
    EXPECT_EQ(transport->requests[2].method, fortiapi::Method::Put);
    EXPECT_EQ(transport->requests[2].url, reservations + "/7");
    EXPECT_EQ(transport->requests[2].body, R"({"description":"nas"})");

    // create: the device assigns the id; the record names it.
    transport->requests.clear();
    transport->reply(200, fake::envelope(json::array()));                                        // plan: the parent exists
    transport->reply(200, fake::envelope({{"hostname", "fw"}}));                                 // apply: serial
    transport->reply(200, child_written("POST", 21));
    transport->reply(200, fake::envelope(json::array({reservation(21, "192.0.2.50", "printer")})));
    ASSERT_EQ(forti({"--json", "create", "system.dhcp/server", "--parent", "1", "--child", "reserved-address", "ip=192.0.2.50",
                     "mac=00:00:5e:00:53:07", "description=printer"}), 0) << err.str() << out.str();
    EXPECT_EQ(json_out()["data"]["operations"][0]["key"], "21");
    EXPECT_EQ(json_out()["data"]["plan"]["operations"][0]["wire"]["path"], "cmdb/system.dhcp/server/1/reserved-address");
    EXPECT_EQ(transport->requests[2].method, fortiapi::Method::Post);
    EXPECT_EQ(transport->requests[2].url, reservations);

    // delete, as a plan for later.
    transport->requests.clear();
    transport->reply(200, fake::envelope(json::array({reservation(21, "192.0.2.50", "printer")})));
    ASSERT_EQ(forti({"--json", "plan", "delete", "system.dhcp/server", "21", "--parent", "1", "--child", "reserved-address"}), 0)
            << err.str();
    EXPECT_EQ(json_out()["data"]["operations"][0]["wire"]["path"], "cmdb/system.dhcp/server/1/reserved-address/21");
    EXPECT_EQ(writes(), 0u);

    // Both options or neither.
    EXPECT_EQ(forti({"delete", "system.dhcp/server", "21", "--parent", "1"}), 2);
    EXPECT_EQ(forti({"delete", "system.dhcp/server", "21", "--child", "reserved-address"}), 2);
    EXPECT_EQ(forti({"plan", "action", "monitor/system/dhcp/revoke", "--parent", "1", "--child", "reserved-address"}), 2);
}

TEST_F(PlanCli, LargeActionBodiesAreShownByReferenceAndRepliesArePrinted) {
    json entries = json::array();
    for (int i = 0; i < 6000; ++i) entries.push_back(std::format("host-{}.blocked.example", i));
    json body = {{"commands", json::array({{{"name", "dns-block"}, {"command", "snapshot"}, {"entries", entries}}})}};
    fs::path file = paths.state.parent_path() / "push.json";
    std::ofstream(file) << body.dump();
    transport->reply(200, fake::envelope({{"hostname", "fw01"}}));
    ASSERT_EQ(forti({"plan", "action", "monitor/system/external-resource/dynamic", "--body", "@" + file.string()}), 0)
            << err.str();
    EXPECT_EQ(out.str().find("blocked.example"), std::string::npos);
    EXPECT_NE(out.str().find("POST monitor/system/external-resource/dynamic (body of "), std::string::npos) << out.str();
    EXPECT_NE(out.str().find("bytes, stored as state/blobs/"), std::string::npos) << out.str();

    transport->reply(200, fake::envelope({{"hostname", "fw01"}}));
    transport->reply(200, fake::envelope(json::array({{{"name", "dns-block"}, {"status", "error"}, {"message", "Connect pending"}}})));
    EXPECT_EQ(forti({"apply", "latest"}), 8) << err.str() << out.str();
    std::string text = out.str() + err.str();
    EXPECT_NE(text.find("1 of 1 command failed: Connect pending"), std::string::npos) << text;
    EXPECT_NE(text.find("reply [{\"message\":\"Connect pending\""), std::string::npos) << text;
    EXPECT_EQ(writes(), 1u);
}
