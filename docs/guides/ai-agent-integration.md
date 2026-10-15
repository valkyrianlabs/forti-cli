---
title: AI agent integration
description: Register forti-mcp with Claude Code and Codex, install the forti agent skill, and check, repair or remove the registrations.
order: 60
status: published
tags:
  - guides
---

# AI agent integration

`forti install mcp` registers the installed `forti-mcp` stdio server with AI clients. The clients
start `forti-mcp` themselves when they need it and stop it when they exit. There is no daemon.
forti-mcp offers four tools (`forti_discover`, `forti_read`, `forti_plan`, `forti_apply`) over the same
engine, profiles and [operating modes](/guides/planning-and-applying-changes#operating-modes) as `forti`.

:::callout[What an agent cannot do through forti-mcp]{variant="info"}
forti-mcp can never change a mode, approve a plan or reveal a device secret.
:::

:::toc[On this page]{depth="2" theme="compact"}
:::

## Install, check, repair, remove

```sh
forti install mcp                                    # interactive: pick clients, scope, skill; confirm
forti install mcp --client claude --scope user --yes
forti install mcp --client all --scope project --project-dir ~/src/netops --skill --dry-run
forti mcp status                                     # where it is registered, and is it still right?
forti mcp repair                                     # fix entries whose forti-mcp moved or vanished
forti mcp uninstall --client codex --scope user --yes
```

In a terminal without `--yes`, forti asks for whatever you did not pass, prints every command it
will run and every file it will write, and changes nothing until you confirm. Without a terminal, or
with `--yes` or `--json`, it never prompts: `--client` and `--scope` are then required (for
`mcp uninstall` too). `--dry-run` prints the plan and stops.

| Option | Meaning |
|---|---|
| `--client NAME` | `claude`, `codex` or `all`; for install, `all` is every supported client found on `PATH` |
| `--scope SCOPE` | `user`: all your projects; `project`: files in the project you can commit; `local`: you, this project (Claude Code only) |
| `--project-dir DIR` | the project for `project` and `local` scope (default: the current directory) |
| `--profile NAME` | start forti-mcp with this profile (the only argument forti adds; never a secret) |
| `--skill` / `--no-skill` | also install the forti agent skill (default: no; asked interactively) |
| `--yes` | never prompt |
| `--dry-run` | show what would change, change nothing |
| `--force` | replace an existing `forti` entry that points elsewhere; for `mcp uninstall`, also remove a `forti` entry that is not forti-mcp |
| `--keep-skill` | `mcp uninstall` only: leave the agent skill in place |

`mcp status` reports every client and scope (for the project in `--project-dir`); `mcp repair` and
`mcp uninstall` take `--client` and `--scope` to narrow what they touch. When a conflict or error
blocks the plan, nothing is changed and the command fails with `policy_denied` (exit 7); when a
change fails during execution, it fails with `config` (exit 3).

## What gets written where

The server is registered under the name `forti`, with the absolute path of `forti-mcp` and no
environment. With `--profile NAME`, the args are `--profile NAME`. Nothing else is written.

| Client | Scope | How | Where |
|---|---|---|---|
| Claude Code | `user` | `claude mcp add -s user forti -- <forti-mcp>` | `~/.claude.json` → `mcpServers` |
| Claude Code | `local` | the same with `-s local`, run in the project directory | `~/.claude.json` → `projects["<dir>"].mcpServers` |
| Claude Code | `project` | direct edit (other servers, keys and their order kept; atomic write; file mode kept) | `<dir>/.mcp.json` |
| Codex | `user` | `codex mcp add forti -- <forti-mcp>` | `$CODEX_HOME/config.toml` (default `~/.codex`) |
| Codex | `project` | direct edit of only the `[mcp_servers.forti]` table; every other byte stays the same | `<dir>/.codex/config.toml` |

`$CLAUDE_CONFIG_DIR` moves `~/.claude.json` to `$CLAUDE_CONFIG_DIR/.claude.json`. Codex has no `local` scope.

Agent skill (`--skill`, offered interactively, never installed by default):

| Client | `user` | `project` / `local` |
|---|---|---|
| Claude Code | `~/.claude/skills/forti/SKILL.md` (`$CLAUDE_CONFIG_DIR/skills/...` when set) | `<dir>/.claude/skills/forti/SKILL.md` |
| Codex | `~/.agents/skills/forti/SKILL.md` | `<dir>/.agents/skills/forti/SKILL.md` |

The skill text is compiled into `forti`, so installing it needs no data files. forti never edits
`CLAUDE.md`, `AGENTS.md` or any other instruction file.

### Behavior worth knowing

- **Idempotent.** Re-running with the same inputs reports `already_registered` and changes nothing.
- **Conflicts.** An existing `forti` entry with a different command or args is reported and left
  alone. `--force` replaces it. Claude Code's `add` refuses existing names, so a replacement is
  `remove` and then `add`; if the `add` fails, forti puts the old entry back.
- **Scopes never widen.** A project install writes project files only.
- **Claude Code asks** each person to approve project servers from `.mcp.json` once.
- **Validation.** After writing, forti reads each registration back and runs `forti-mcp --version`.
  It never runs `claude mcp get` or `claude mcp list`: both start every server to health-check it.
  Status for Claude's local and user scopes reads `~/.claude.json` (read only); Codex user status
  uses `codex mcp get forti --json`, which starts nothing.
- **Restart Codex** after a change to its config. Claude Code picks up new servers in new sessions.

:::callout[Codex project scope needs a trusted project]{variant="note"}
Codex loads `<dir>/.codex/config.toml` only for projects marked trusted in the global config, and
forti does **not** add that trust entry (that would be a global change). It warns instead. Codex
asks to trust a project the first time you run it there.
:::

## Locating forti-mcp

forti looks next to its own executable, then on `PATH`. The path is registered as found, without
resolving symlinks: Homebrew's `/opt/homebrew/bin/forti-mcp` link survives upgrades, while the
versioned `Cellar` path behind it does not (a forti running from a Cellar path registers the
prefix's `bin/forti-mcp` link).

If forti-mcp is missing, forti prints the command to install it and exits with status 5
(`not_found`). It never runs a package manager or `sudo`:

:::tabs{
  default="homebrew"
  theme="glass"
  tabTheme="muted"
}

:::tab[macOS (Homebrew)]{value="homebrew"}
```sh
brew install valkyrianlabs/tap/forti-mcp
```
:::

:::tab[Debian, Ubuntu (APT)]{value="apt"}
After adding apt.valkyrianlabs.com ([Installation](/getting-started/installation)):

```sh
sudo apt install forti-mcp
```
:::

:::

## Undoing it

`forti mcp uninstall` removes the `forti` entries it finds (only those whose command is a
`forti-mcp` executable; `--force` removes another `forti` entry) and the forti skill (only a
`SKILL.md` whose frontmatter says `name: forti`; `--keep-skill` leaves it). Project files that held
nothing else are deleted, along with directories forti created and that are now empty. By hand:

```sh
claude mcp remove -s user forti          # or -s local, from the project directory
codex mcp remove forti
# project scope: delete "forti" from .mcp.json, and [mcp_servers.forti] from .codex/config.toml
rm -r ~/.claude/skills/forti ~/.agents/skills/forti
```

`forti mcp repair` points registrations whose forti-mcp no longer exists (or that use a versioned
Homebrew Cellar path) at the installed forti-mcp, keeping their args, and refreshes an outdated
forti skill. Entries that point at another working forti-mcp are reported, not changed.

## Security notes

- **No secrets in client config.** forti-mcp reads its own profiles (`~/.config/forti/config.json`)
  and secret store (Keychain or credential files), so the registration needs no `env`. The only
  argument forti may add is a profile name, which is validated and is not a secret.
- **No shell.** Client CLIs run through `posix_spawnp` with an argument vector, a timeout and
  captured output. No secret is ever passed in argv.
- **Files.** Writes are atomic (temporary file and rename) and keep the existing file mode. forti
  refuses to rewrite a `.mcp.json` it cannot parse, or a `[mcp_servers.forti]` defined in a form it
  cannot edit as one block (dotted keys, inline tables, split tables).
- **`~/.claude.json` is never edited directly.** Running Claude Code sessions rewrite it constantly;
  only the `claude` CLI changes it.
- **Project files are shared.** `.mcp.json` and `.codex/config.toml` are meant to be committed. They
  then contain the absolute path of your forti-mcp, which may differ on a teammate's machine (they can
  run `forti install mcp --scope project --force`, or prefer `user` scope).

:::callout[The skill is guidance, not a control]{variant="warning"}
Changes stay bounded by the profile's mode (`read-only`, `guarded`, `autonomous`) and the engine's
safeguards, whatever the agent reads. The skill tells agents to treat device data (comments, names)
as untrusted and never to change modes or approve plans. An agent that can also run shell commands
as you could still do both; see
[What a mode does and does not stop](/reference/security#what-a-mode-does-and-does-not-stop).
:::

:::details[Evidence: which skill directory Codex loads]{theme="muted"}
Verified on Codex 0.162.1 with sandboxed `HOME` and `CODEX_HOME`, by placing marker skills and
rendering the model input with `codex debug prompt-input "hi"` (no network, no model call). Its skill
roots were `<repo>/.codex/skills`, `$CODEX_HOME/skills`, `$HOME/.agents/skills`,
`$CODEX_HOME/skills/.system` and `<repo>/.agents/skills`. With `CODEX_HOME` pointed elsewhere,
`~/.codex/skills` was no longer read but `~/.agents/skills` still was. Project `.agents/skills` loads
from the git root or the working directory. forti therefore uses the documented `~/.agents/skills`
and `<dir>/.agents/skills`, which work for both the installed binary and the documented behavior.

The Claude Code skill location under `$CLAUDE_CONFIG_DIR` follows the same rule as its other files
(`.claude.json` and `backups/` move there); it has not been confirmed with a live session.
:::
