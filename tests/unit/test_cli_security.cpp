// S-01 (security-audit.md): terminal control sequences in device data or plan values must not reach
// the terminal of the person reading `forti get`, `forti plan show` or the guarded-mode approval.

#include <cli_harness.hpp>

#include <output.hpp>

using namespace forti;
using json = nlohmann::json;

namespace {

    // "\x1b[1A\x1b[2K" moves up a line and erases it: enough to hide an operation from the approver.
    const std::string erase_line = "\x1b[1A\x1b[2K";
    const std::string rtl_override = "\xe2\x80\xae";   // U+202E RIGHT-TO-LEFT OVERRIDE
    const std::string c1_csi = "\xc2\x9b";             // U+009B, CSI on 8-bit terminals

    bool has_control(const std::string& text) {
        for (std::size_t i = 0; i < text.size(); ++i) {
            auto c = static_cast<unsigned char>(text[i]);
            if ((c < 0x20 && c != '\n') || c == 0x7F) return true;
        }
        return text.find(rtl_override) != std::string::npos || text.find(c1_csi) != std::string::npos;
    }

    struct SecurityCli : fake::Cli {
        int as_guarded(std::vector<std::string> arguments) {
            out.str("");
            err.str("");
            cli::Output output{.out = &out, .err = &err};
            auto options = fake::options(transport, engine::Mode::guarded);
            options.paths = paths;
            return cli::run(arguments, output, options);
        }
    };

}  // namespace

TEST(Printable, EscapesControlsAndBidiButKeepsText) {
    EXPECT_EQ(cli::printable("office LAN"), "office LAN");
    EXPECT_EQ(cli::printable("caf\xc3\xa9 \xe6\x9d\xb1\xe4\xba\xac"), "caf\xc3\xa9 \xe6\x9d\xb1\xe4\xba\xac");   // UTF-8 text
    EXPECT_EQ(cli::printable("a\x1b[2Kb"), "a\\x1b[2Kb");
    EXPECT_EQ(cli::printable("a\nb\tc\rd"), "a\\nb\\tc\\rd");
    EXPECT_EQ(cli::printable("a\nb", true), "a\nb");
    EXPECT_EQ(cli::printable("x" + rtl_override + "y"), "x\\u202ey");
    EXPECT_EQ(cli::printable("x" + c1_csi + "y"), "x\\u009by");
    EXPECT_EQ(cli::printable(std::string("\x7f")), "\\x7f");

    json value = {{"comm\x1b" "ent", {"a\x07", 1}}};
    EXPECT_EQ(cli::printable_json(value).dump(), R"({"comm\\x1bent":["a\\x07",1]})");
}

TEST_F(SecurityCli, DeviceDataCannotDriveTheTerminal) {
    transport->reply(200, fake::envelope(json::array({{{"name", "LAN"}, {"comment", "ok" + erase_line + "PWNED"}},
                                                       {{"name", "x" + rtl_override + "gpj.exe"}, {"comment", c1_csi + "31m"}}})));
    ASSERT_EQ(as_guarded({"get", "firewall/address"}), 0) << err.str();
    EXPECT_FALSE(has_control(out.str())) << out.str();
    EXPECT_NE(out.str().find("\\x1b[1A"), std::string::npos);

    // --json is for programs: JSON escaping applies, values are not altered.
    transport->reply(200, fake::envelope(json::array({{{"name", "LAN"}, {"comment", "ok" + erase_line}}})));
    ASSERT_EQ(as_guarded({"--json", "get", "firewall/address"}), 0);
    EXPECT_EQ(json_out()["data"][0]["comment"], "ok" + erase_line);
}

TEST_F(SecurityCli, PlanValuesCannotHideOperationsFromTheApprover) {
    // An agent plans a comment change whose value erases the lines above it when printed.
    transport->reply(200, fake::envelope(json::array({{{"name", "LAN"}, {"q_origin_key", "LAN"}, {"comment", "old"},
                                                       {"subnet", "192.0.2.0 255.255.255.0"}, {"type", "ipmask"}}})));
    ASSERT_EQ(as_guarded({"--json", "plan", "set", "firewall/address", "LAN", "comment=" + erase_line + erase_line + "harmless"}), 0)
            << err.str() << out.str();
    std::string id = json_out()["data"]["id"];

    ASSERT_EQ(as_guarded({"plan", "show", id}), 0) << err.str();
    EXPECT_FALSE(has_control(out.str())) << out.str();
    EXPECT_NE(out.str().find("\\x1b[1A\\x1b[2K"), std::string::npos);

    // forti apply in guarded mode prints the refusal (and its approve command) on stderr.
    ASSERT_NE(as_guarded({"apply", id}), 0);
    EXPECT_FALSE(has_control(err.str())) << err.str();
}

TEST_F(SecurityCli, ErrorMessagesFromTheDeviceAreEscaped) {
    transport->reply(500, {{"status", "error"}, {"http_status", 500}, {"error", -5},
                           {"cli_error", "bad" + erase_line + "value"}});
    EXPECT_NE(as_guarded({"get", "firewall/address"}), 0);
    EXPECT_FALSE(has_control(err.str())) << err.str();
}
