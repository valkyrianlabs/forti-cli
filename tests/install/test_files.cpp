// .mcp.json merge/remove and the Codex TOML table edit: pure text transformations, no processes.

#include <mcp_json.hpp>
#include <toml_table.hpp>

#include <forti/engine/error.hpp>

#include <gtest/gtest.h>

using namespace forti::install;

namespace {

    Entry forti_entry(std::vector<std::string> args = {}) { return {"/opt/homebrew/bin/forti-mcp", std::move(args), false}; }

}  // namespace

// ---- .mcp.json ----

TEST(McpJson, AddsToEmptyFile) {
    auto doc = mcp_json::parse("", ".mcp.json");
    mcp_json::upsert(doc, "forti", forti_entry());
    EXPECT_EQ(mcp_json::dump(doc, ""),
              "{\n  \"mcpServers\": {\n    \"forti\": {\n      \"type\": \"stdio\",\n"
              "      \"command\": \"/opt/homebrew/bin/forti-mcp\",\n      \"args\": []\n    }\n  }\n}\n");
}

TEST(McpJson, PreservesOtherServersKeysAndOrder) {
    std::string text = R"({
    "$schema": "https://example.invalid/s.json",
    "mcpServers": {
        "zeta": {"command": "z", "env": {"TOKEN": "${TOKEN}"}},
        "alpha": {"command": "a", "args": ["--x"]}
    },
    "extra": [1, 2]
}
)";
    auto doc = mcp_json::parse(text, ".mcp.json");
    mcp_json::upsert(doc, "forti", forti_entry({"--profile", "lab"}));
    auto out = mcp_json::dump(doc, text);
    auto reparsed = nlohmann::ordered_json::parse(out);
    std::vector<std::string> top, servers;
    for (auto it = reparsed.begin(); it != reparsed.end(); ++it) top.push_back(it.key());
    for (auto it = reparsed["mcpServers"].begin(); it != reparsed["mcpServers"].end(); ++it) servers.push_back(it.key());
    EXPECT_EQ(top, (std::vector<std::string>{"$schema", "mcpServers", "extra"}));
    EXPECT_EQ(servers, (std::vector<std::string>{"zeta", "alpha", "forti"}));
    EXPECT_EQ(reparsed["mcpServers"]["zeta"]["env"]["TOKEN"], "${TOKEN}");
    EXPECT_FALSE(reparsed["mcpServers"]["forti"].contains("env"));   // no env, no secrets
    EXPECT_TRUE(out.starts_with("{\n    \""));                           // the file's 4-space indent is kept
}

TEST(McpJson, UpsertIsIdempotentAndKeepsPosition) {
    std::string text = R"({"mcpServers": {"a": {"command": "a"}, "forti": {"command": "/old/forti-mcp"}, "b": {"command": "b"}}})";
    auto doc = mcp_json::parse(text, ".mcp.json");
    mcp_json::upsert(doc, "forti", forti_entry());
    auto once = mcp_json::dump(doc, text);
    auto again = mcp_json::parse(once, ".mcp.json");
    mcp_json::upsert(again, "forti", forti_entry());
    EXPECT_EQ(mcp_json::dump(again, once), once);
    std::vector<std::string> servers;
    for (auto it = again["mcpServers"].begin(); it != again["mcpServers"].end(); ++it) servers.push_back(it.key());
    EXPECT_EQ(servers, (std::vector<std::string>{"a", "forti", "b"}));
}

TEST(McpJson, FindDetectsConflictsAndExtras) {
    auto doc = mcp_json::parse(R"({"mcpServers": {"forti": {"type": "stdio", "command": "/elsewhere/forti-mcp", "args": [], "env": {}}}})", "x");
    auto entry = mcp_json::find_server(doc, "forti");
    ASSERT_TRUE(entry);
    EXPECT_FALSE(entry->extra);   // "env": {} is what `claude mcp add` writes
    EXPECT_FALSE(entry->same_target(forti_entry()));
    EXPECT_TRUE(entry->is_forti_mcp());

    auto custom = mcp_json::parse(R"({"mcpServers": {"forti": {"command": "/x/forti-mcp", "env": {"A": "1"}}}})", "x");
    EXPECT_TRUE(mcp_json::find_server(custom, "forti")->extra);
    EXPECT_FALSE(mcp_json::find_server(custom, "other"));
}

TEST(McpJson, RemoveLeavesOthersAndReportsEmpty) {
    std::string text = R"({"mcpServers": {"other": {"command": "o"}, "forti": {"command": "f"}}})";
    auto doc = mcp_json::parse(text, "x");
    EXPECT_TRUE(mcp_json::remove(doc, "forti"));
    EXPECT_FALSE(mcp_json::remove(doc, "forti"));
    EXPECT_TRUE(doc["mcpServers"].contains("other"));
    EXPECT_FALSE(mcp_json::is_empty(doc));

    auto only = mcp_json::parse(R"({"mcpServers": {"forti": {"command": "f"}}})", "x");
    mcp_json::remove(only, "forti");
    EXPECT_TRUE(mcp_json::is_empty(only));
}

TEST(McpJson, RefusesFilesItCannotRead) {
    EXPECT_THROW(mcp_json::parse("{\"mcpServers\": ", "x"), forti::engine::Failure);
    EXPECT_THROW(mcp_json::parse("[1]", "x"), forti::engine::Failure);
    EXPECT_THROW(mcp_json::parse(R"({"mcpServers": []})", "x"), forti::engine::Failure);
}

// ---- Codex config.toml ----

namespace {

    const toml::Path forti_table{"mcp_servers", "forti"};

    // A config with everything the scanner must step over without mistaking it for a header.
    const std::string tricky = R"(# Codex config: keep me
model = "gpt-5"   # trailing comment
notes = """
[mcp_servers.forti]
not a table, a string
"""
literal = '''
[[also.not]]'''
matrix = [
  [1, 2],
  [3, 4]
]
inline = { a = "[x]", b = 'y' }

[mcp_servers.other]
command = "other-mcp"
args = ["--flag"] # comment

[projects."/Users/me/src/net"]
trust_level = "trusted"
)";

    std::string block(std::vector<std::string> args = {}) { return toml::render_server("forti", forti_entry(std::move(args))); }

}  // namespace

TEST(TomlTable, AppendsWithoutTouchingAnythingElse) {
    auto out = toml::set_table(tricky, forti_table, block());
    EXPECT_EQ(out, tricky + "\n[mcp_servers.forti]\ncommand = \"/opt/homebrew/bin/forti-mcp\"\n");
    auto entry = toml::read_server(out, "forti");
    ASSERT_TRUE(entry);
    EXPECT_TRUE(entry->same_target(forti_entry()));
    EXPECT_FALSE(entry->extra);
}

TEST(TomlTable, RemoveRestoresTheOriginalBytes) {
    auto added = toml::set_table(tricky, forti_table, block({"--profile", "lab"}));
    EXPECT_EQ(toml::remove_table(added, forti_table), tricky);
    EXPECT_EQ(toml::remove_table(tricky, forti_table), tricky);   // absent: unchanged
    EXPECT_EQ(toml::remove_table(block(), forti_table), "");      // file held only our table
}

TEST(TomlTable, ReplacesOnlyItsOwnBlockInTheMiddle) {
    std::string before = "# head\n[a]\nx = 1\n\n";
    std::string ours = "[mcp_servers.forti]\ncommand = \"/old/forti-mcp\"\nenv_vars = [\"X\"]\n\n[mcp_servers.forti.env]\nK = \"v\"\n";
    std::string after = "\n# belongs to b\n[b]\ny = \"[mcp_servers.forti]\"\n";
    std::string text = before + ours + after;

    auto existing = toml::read_server(text, "forti");
    ASSERT_TRUE(existing);
    EXPECT_EQ(existing->command, "/old/forti-mcp");
    EXPECT_TRUE(existing->extra);   // env_vars and the env sub-table

    auto replaced = toml::set_table(text, forti_table, block());
    EXPECT_EQ(replaced, before + block() + after);
    auto removed = toml::remove_table(text, forti_table);
    EXPECT_EQ(removed, "# head\n[a]\nx = 1\n\n# belongs to b\n[b]\ny = \"[mcp_servers.forti]\"\n");
}

TEST(TomlTable, IdempotentSet) {
    auto once = toml::set_table(tricky, forti_table, block());
    EXPECT_EQ(toml::set_table(once, forti_table, block()), once);
}

TEST(TomlTable, QuotedHeaderAndSpacingAreRecognised) {
    std::string text = "[ mcp_servers . \"forti\" ]  # ours\ncommand = '/x/forti-mcp'\nargs = [\n  \"--profile\", # p\n  \"lab\",\n]\n";
    auto entry = toml::read_server(text, "forti");
    ASSERT_TRUE(entry);
    EXPECT_EQ(entry->command, "/x/forti-mcp");
    EXPECT_EQ(entry->args, (std::vector<std::string>{"--profile", "lab"}));
    EXPECT_EQ(toml::set_table(text, forti_table, block()), block());
}

TEST(TomlTable, RefusesFormsItCannotEditAsABlock) {
    using forti::engine::Failure;
    EXPECT_THROW(toml::set_table("[mcp_servers]\nforti = { command = \"x\" }\n", forti_table, block()), Failure);
    EXPECT_THROW(toml::set_table("[mcp_servers]\nforti.command = \"x\"\n", forti_table, block()), Failure);
    EXPECT_THROW(toml::set_table("mcp_servers.forti.command = \"x\"\n", forti_table, block()), Failure);
    EXPECT_THROW(toml::set_table("mcp_servers = { forti = { command = \"x\" } }\n", forti_table, block()), Failure);
    EXPECT_THROW(toml::set_table(block() + "[x]\n" + block(), forti_table, block()), Failure);   // duplicate
    EXPECT_THROW(toml::set_table("[mcp_servers.forti]\ncommand = \"a\"\n[x]\n[mcp_servers.forti.env]\n", forti_table, block()),
                 Failure);   // split
    EXPECT_THROW(toml::set_table("x = \"unterminated\n", forti_table, block()), Failure);
}

TEST(TomlTable, StringsRoundTrip) {
    Entry odd{"/path with \"quotes\"/and\\back/forti-mcp", {"--profile", "a'b"}, false};
    auto text = toml::render_server("forti", odd);
    auto entry = toml::read_server(text, "forti");
    ASSERT_TRUE(entry);
    EXPECT_TRUE(entry->same_target(odd));
    EXPECT_EQ(toml::parse_string(R"("café\t")"), std::optional<std::string>("caf\xc3\xa9\t"));
    EXPECT_FALSE(toml::parse_string(R"("a" trailing)"));
}

TEST(TomlTable, ProjectTrust) {
    EXPECT_TRUE(toml::project_trusted(tricky, "/Users/me/src/net"));
    EXPECT_FALSE(toml::project_trusted(tricky, "/Users/me/src/other"));
    EXPECT_TRUE(toml::project_trusted("projects.\"/p\".trust_level = \"trusted\"\n", "/p"));
    EXPECT_FALSE(toml::project_trusted("[projects.\"/p\"]\ntrust_level = \"untrusted\"\n", "/p"));
}
