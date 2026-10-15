<!--
vl-release staged release notes: the user-facing story of the NEXT release.
Maintained continuously while working; `vlr prepare` promotes it into the release notes
history (and the GitHub release) and resets this file to this template.

Format: the first line is "# <release title>" WITHOUT a version number (vlr adds it).
Everything after the title is the Markdown release body. Describe the resulting behavior
for users and operators; keep it representative of what actually ships.
-->
# One home for forti: ~/.forti, certificates and the MCP workspace

## Everything in ~/.forti

forti now keeps everything in one directory, the forti home: `~/.forti`, or `$FORTI_HOME`. Profiles
and file-stored secrets, plans, approvals, the audit log, backups and client certificates all live
there. `forti home` shows every location.

Coming from 0.1? Nothing breaks: an existing `~/.config/forti` setup keeps working, and `forti home`
and `forti doctor` point it out. Move it with one command:

```sh
forti home migrate
```

It moves the configuration, stored credentials, state and cache, keeps their permissions, never
overwrites an existing `~/.forti/config.json`, and is safe to run again. Keychain entries need no change.

## Client certificates in one command

FortiOS can require a client certificate from the REST API user on top of the API key. forti now
makes everything that needs:

```sh
forti cert create --profile fw01
```

This creates a private CA and a client certificate in `~/.forti/certs/fw01/`, points the profile at
them, and prints the exact FortiGate commands: import the CA, create the PKI user and peer group, and
enable `peer-auth` for the API user. The certificate's password stays in a private file (or, with
`--keychain`, in the macOS Keychain). forti never prints it; it shows the command that reads it.
`forti cert show` reports expiry and fingerprints, and `forti cert remove` cleans up. It uses the system
`openssl` command (macOS's built-in one works).

## Several FortiGates, less typing

- `forti profile copy fw01 fw02` starts a new profile from an existing one's settings (never its key).
- `forti profile set fw02 host=fw02.example.net port=8443` changes settings without prompts.
- `forti profile rename lab fw01` takes the stored key, the certificates and the default along.
- `forti configure --profile fw02` edits an existing profile with every prompt prefilled.

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

