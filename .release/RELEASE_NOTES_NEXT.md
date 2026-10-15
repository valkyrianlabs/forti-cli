<!--
vl-release staged release notes: the user-facing story of the NEXT release.
Maintained continuously while working; `vlr prepare` promotes it into the release notes
history (and the GitHub release) and resets this file to this template.

Format: the first line is "# <release title>" WITHOUT a version number (vlr adds it).
Everything after the title is the Markdown release body. Describe the resulting behavior
for users and operators; keep it representative of what actually ships.
-->
# One home for forti: ~/.forti, certificates and the MCP workspace

## The MCP workspace

`forti install mcp` now recommends one place for the FortiGate tools: the forti home, `~/.forti`.
Pick "~/.forti workspace (recommended)" (or pass `--scope workspace`), then start your agent there:

```sh
forti install mcp --client all --scope workspace --trust-codex-workspace --yes
cd ~/.forti && claude      # or: codex
```

An agent started in `~/.forti` gets `forti_discover`, `forti_read`, `forti_plan` and `forti_apply`;
an agent started in any other project does not. The workspace comes with a short `AGENTS.md` (and a
`CLAUDE.md` pointing at it) and the forti skill for both clients.

The same directory holds your profiles, credentials and certificates, so the workspace keeps them
out of the agent's context: Claude Code gets deny rules in `.claude/settings.json` for
`credentials/`, certificate passwords, PKCS#12 files and CA keys, and for editing `config.json`;
Codex gets a `forti-workspace` permission profile that denies the same paths to the commands it
runs. Your own settings in those files are kept.

Codex only reads a project's `.codex/config.toml` once the project is trusted. forti asks before it
marks `~/.forti` as trusted in your global Codex config (or takes `--trust-codex-workspace`), adds
exactly that one entry, and removes it again on uninstall only if it added it.

`forti install mcp` also warns when the project directory is your home directory itself: an agent
started anywhere under it would get the firewall tools. It asks "Are you sure?" (default no), and
refuses without a terminal unless you pass `--force`.

`forti mcp status` shows the workspace and the health of its files; `forti mcp uninstall --scope
workspace` removes the registration and the files forti wrote, and never touches `config.json`,
credentials, certificates or state.

