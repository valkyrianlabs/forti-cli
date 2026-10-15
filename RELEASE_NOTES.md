# forti-cli release notes

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
