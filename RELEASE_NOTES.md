# forti-cli release notes

<!-- vl-release:entry version=0.2.0 -->
## 0.2.0 — One home for forti: ~/.forti, certificates and the MCP workspace

_Released 2026-10-16_

### Everything in ~/.forti

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

### Client certificates in one command

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

### Several FortiGates, less typing

- `forti profile copy fw01 fw02` starts a new profile from an existing one's settings (never its key).
- `forti profile set fw02 host=fw02.example.net port=8443` changes settings without prompts.
- `forti profile rename lab fw01` takes the stored key, the certificates and the default along.
- `forti configure --profile fw02` edits an existing profile with every prompt prefilled.

### The MCP workspace

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


### Documentation

The quick start now goes from install to an agent working in `~/.forti` in five commands, and a new
Client certificates guide walks through `forti cert create` and the FortiGate side.

<!-- vl-release:entry version=0.1.1 -->
## 0.1.1 — Documentation in Payload Markdown

_Released 2026-10-15_

The forti documentation is now authored with Payload Markdown directives, so the docs site renders
it as structured pages instead of plain Markdown. The content is the same, checked against the
code; new tables summarize it. The `forti` binary and the packages are unchanged.

- **Installation** puts APT, Homebrew and the source build side by side in tabs.
- **Quick start** is a numbered sequence of steps, from creating the API administrator to
  connecting an AI client.
- **Warnings are callouts**: authentication lockout, operating modes, wholesale replacement of
  table attributes, configuration backups, and the limits of rollback plans and backups when a
  change cuts off management access.
- **The overview** links every section through cards, with release, CI and license badges.
- **New summary tables**: every command at a glance (and whether it contacts the device), exit
  statuses grouped by meaning, the `forti plan list` states, how each operation is rolled back,
  and the `--filter` operators. The exit-code page gains a section on what to do after exit 8, and
  the security notes compare the three operating modes side by side and show the Claude Code
  permission rules as a copyable JSON block.

<!-- vl-release:entry version=0.1.0 -->
## 0.1.0 — forti: FortiOS from the command line

_Released 2026-10-15_

The first release of `forti`, a native FortiOS command-line interface built on
[forti-api](https://github.com/valkyrianlabs/forti-api). It reaches every endpoint the SDK
generates (487 configuration tables and singletons from FortiOS 7.4.8, plus monitor data) without a
hand-written command per resource, and it registers the companion MCP server with AI clients in one
command.

- **Discover and read anything.** `forti discover` searches resources and shows their attributes,
  merging the device's own schema (help, options, ranges) with `--live`. `forti get` reads
  configuration and monitor data with FortiOS filters, field projection and paging. Text output for
  people, a stable JSON envelope with `--json`, and consistent exit codes for scripts.
- **Profiles and credentials.** `forti configure` (interactive or flag-driven) stores device
  profiles, with the API key in the macOS Keychain or an owner-only file, or read from an environment
  variable or a command. A key is never accepted as an argument, and a stored key only goes to the
  host it was saved for. TLS is always verified; `--ca-bundle` and `--resolve-ip` cover self-signed
  and internal names. `forti doctor` checks the whole path, from file modes to authentication.
- **Planned, verified changes.** `forti plan` validates changes against the SDK's types and the live
  objects and records the exact diff, request bodies and risk tier. `forti apply` executes a plan once,
  in order, never retries a write, verifies every change by reading it back, writes a rollback plan
  and an audit record, and reports partial failures and unknown outcomes truthfully. Critical changes
  (management access, routing, interfaces, admins) take a configuration backup first and are followed
  by a management connectivity check.
- **Operating modes.** Each profile is `read-only` (the default), `guarded` (a person runs
  `forti plan approve <id>`) or `autonomous`. The FortiOS API account's permissions remain the real
  boundary. Rollback plans and backups need a working management path, so they are not a substitute
  for console or out-of-band access.
- **AI clients in one command.** `forti install mcp` registers the native `forti-mcp` server with
  Claude Code and Codex (user or project scope), preserves existing configuration, never writes a
  secret into it, optionally installs the forti agent skill, and is idempotent; `forti mcp status`,
  `repair` and `uninstall` manage it afterwards.
- Device secrets in read results are redacted unless you ask for them (`forti get --reveal`).

### Install

- Debian/Ubuntu (amd64), from the ValkyrianLabs APT repository: `sudo apt install forti-cli`.
- macOS (Homebrew): `brew install valkyrianlabs/tap/forti-cli` (builds from source).
- From source: Meson and a C++23 compiler (GCC 13+ or Apple clang); see the README.

Then `forti configure`, `forti doctor`, `forti get firewall/policy`, and `forti install mcp`.
