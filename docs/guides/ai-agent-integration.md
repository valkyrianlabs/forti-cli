---
title: AI agent integration
description: Give Claude Code and Codex the FortiGate tools in the ~/.forti workspace, keep credentials out of the agent's context, and check, repair or remove the registrations.
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

The recommended setup is the **forti workspace**: the tools are registered in the forti home,
`~/.forti`, and an agent gets them only when you start it there.

```sh
forti install mcp               # pick "~/.forti workspace (recommended)"
cd ~/.forti && claude           # or: codex
```

:::callout[What an agent cannot do through forti-mcp]{variant="info"}
forti-mcp can never change a mode, approve a plan or reveal a device secret.
:::

:::toc[On this page]{depth="2" theme="compact"}
:::

## The forti workspace

The workspace is project scope in the forti home (`~/.forti`, or `$FORTI_HOME`). An agent started in
`~/.forti` gets the FortiGate tools; an agent started in any other project does not. That keeps
firewall access out of your everyday coding sessions, and gives the agent a directory that explains
itself.

### Set it up

In a terminal, `forti install mcp` asks which clients to set up, then "Where should agents get the
forti tools?". The workspace is the first choice and preselected. It then shows every file it will
write and changes nothing until you confirm.

Without prompts (scripts, `--yes`, `--json`), name the clients and the scope:

```sh
forti install mcp --client all --scope workspace --trust-codex-workspace --yes
```

Then start your agent in the workspace:

```sh
cd ~/.forti && claude           # or: cd ~/.forti && codex
```

- forti creates the home (mode 0700) if it does not exist yet.
- The [forti agent skill](#the-agent-skill) is part of the workspace and installed by default
  (`--no-skill` leaves it out).
- `--project-dir` does not apply: the workspace is always the forti home.
- `--profile NAME` starts forti-mcp with that profile, as for any scope.

### What the workspace contains

| File | For | What |
|---|---|---|
| `.mcp.json` | Claude Code | the `forti` server registration (project scope) |
| `.claude/settings.json` | Claude Code | `permissions.deny` rules that keep secrets out of reach ([below](#keeping-secrets-out-of-the-agents-context)) |
| `.claude/skills/forti/SKILL.md` | Claude Code | the forti agent skill |
| `CLAUDE.md` | Claude Code | one line, `@AGENTS.md` |
| `.codex/config.toml` | Codex | `[mcp_servers.forti]`, and `default_permissions = "forti-workspace"` with the `[permissions.forti-workspace]` profile |
| `.agents/skills/forti/SKILL.md` | Codex | the forti agent skill |
| `AGENTS.md` | both | what the directory is, the rules for agents, and the commands for you |
| `.forti-workspace.json` | forti | what forti wrote (file hashes, rules, the Codex trust entry), so updates and uninstall touch only that |

The same directory holds `config.json`, `credentials/`, `certs/` and `state/`
([the forti home](/reference/configuration-files#the-forti-home)). A workspace install never touches them.

The generated files are created and updated idempotently. A file you edited is never overwritten:
forti reports it as a conflict and leaves it alone (delete it and run `forti install mcp` again to get
the generated one). Your own entries in `.claude/settings.json` and `.codex/config.toml` are kept;
forti adds only what is missing.

### Keeping secrets out of the agent's context

Claude Code gets these deny rules in `~/.forti/.claude/settings.json`, merged into any rules you have.
A leading `/` anchors a rule to the directory of the settings file, the forti home:

```json
{
  "permissions": {
    "deny": [
      "Read(/credentials/**)",
      "Read(/certs/**/*.pass)",
      "Read(/certs/**/*.p12)",
      "Read(/certs/**/ca/**)",
      "Read(/ca/**)",
      "Edit(/config.json)"
    ]
  }
}
```

Codex gets a permission profile in `~/.forti/.codex/config.toml`, selected with
`default_permissions = "forti-workspace"`:

```toml
[permissions.forti-workspace]
description = "forti workspace: no reading credentials or certificate keys, config.json read-only"
extends = ":workspace"

[permissions.forti-workspace.filesystem.":workspace_roots"]
"credentials" = "deny"
"certs/**/*.pass" = "deny"
"certs/**/*.p12" = "deny"
"certs/**/ca/**" = "deny"
"ca" = "deny"
"config.json" = "read"
```

What they cover:

- **Claude Code**: its file tools cannot read the file secret store (`credentials/`), certificate
  passwords (`*.pass`), PKCS#12 bundles (`*.p12`) or CA keys (`ca/`, `certs/<name>/ca/`), and cannot edit
  `config.json`.
- **Codex**: commands it runs in its sandbox cannot read or write the same paths, and see
  `config.json` read-only. Codex applies the profile only once it trusts `~/.forti`
  ([Codex trust](#codex-trust)).
- forti-mcp itself is not restricted: it runs outside both, and reads the profiles and credentials
  to reach the FortiGate. Secrets in the macOS Keychain are not files in the workspace at all.

:::callout[Guard rails, not a boundary]{variant="warning"}
The rules stop accidents, not a determined process. A script or program the agent runs that opens a
file itself is not checked against Claude Code's deny rules, and commands Codex runs outside its
sandbox (an escalation you approve, or full access) are not bound by the permission profile. Nor do
the rules stop an agent with a shell from running `forti plan approve` or `forti configure`. The
generated `AGENTS.md` tells agents to stay away from these files and commands; the FortiOS account's
privileges remain the boundary that holds in every case. See
[What a mode does and does not stop](/reference/security#what-a-mode-does-and-does-not-stop).
:::

### Claude Code's approval prompt

Claude Code asks each person to approve the servers in a project's `.mcp.json` the first time they
open the project. The first time you run `cd ~/.forti && claude`, approve the `forti` server; until
you do, the session has no FortiGate tools.

### Codex trust

Codex loads a project's `.codex/config.toml` (the `forti` server and the permission profile) only for
projects marked trusted in its global configuration. Trusting the forti home is a change to that
global file, so forti asks first:

- **Interactively**, when Codex has no entry for the home at all, forti shows the exact entry and asks
  "Trust ~/.forti in Codex?" (default no).
- **`--trust-codex-workspace`** gives that consent without a prompt.

With consent, forti adds exactly this to `$CODEX_HOME/config.toml` (default `~/.codex/config.toml`),
keeping every other byte of the file:

```toml
[projects."/Users/me/.forti"]
trust_level = "trusted"
```

forti records that it added the entry, and `forti mcp uninstall --scope workspace` removes it again
only if forti added it and it is unchanged. An entry you wrote yourself (for example
`trust_level = "untrusted"`) is your decision: forti leaves it alone and reports that Codex ignores
the workspace configuration. Without consent, the install reports the workspace as `untrusted`; start
`codex` in `~/.forti` and accept its trust prompt, or run the install again with
`--trust-codex-workspace`.

### The home directory guard

Project or local scope with your home directory itself as the project would give the firewall tools
to an agent started anywhere under your home directory. forti warns and asks "Are you sure?"
(default no); declining changes nothing. Without a terminal, it refuses (`policy_denied`, exit 7)
unless you pass `--force`. The forti workspace is the recommended alternative.

## Scopes and options

| Scope | Who gets the tools | Where it is written |
|---|---|---|
| `workspace` | agents started in the forti home (recommended) | `~/.forti` |
| `project` | agents started in `--project-dir`; files you can commit | `<dir>/.mcp.json`, `<dir>/.codex/config.toml` |
| `user` | every project, for you | the clients' user configuration |
| `local` | you, in `--project-dir` (Claude Code only) | `~/.claude.json` |

```sh
forti install mcp                                    # interactive: clients, scope; confirm
forti install mcp --client all --scope workspace --trust-codex-workspace --yes
forti install mcp --client claude --scope user --skill --yes
forti install mcp --client all --scope project --project-dir ~/src/netops --dry-run
forti mcp status                                     # where it is registered, and is it still right?
forti mcp repair                                     # fix entries whose forti-mcp moved or vanished
forti mcp uninstall --client codex --scope user --yes
```

In a terminal without `--yes`, forti asks for whatever you did not pass, prints every command it will
run and every file it will write, and changes nothing until you confirm. Without a terminal, or with
`--yes` or `--json`, it never prompts: `--client` and `--scope` are then required (for
`mcp uninstall` too). `--dry-run` prints the plan and stops.

| Option | Meaning |
|---|---|
| `--client NAME` | `claude`, `codex` or `all`; for install, `all` is every supported client found on `PATH` |
| `--scope SCOPE` | `workspace`, `project`, `user` or `local` (see above) |
| `--project-dir DIR` | the project for `project` and `local` scope (default: the current directory) |
| `--profile NAME` | start forti-mcp with this profile (the only argument forti adds; never a secret) |
| `--skill` / `--no-skill` | also install the forti agent skill (workspace: yes; other scopes: no, asked interactively) |
| `--trust-codex-workspace` | workspace with Codex: mark the forti home trusted in the global Codex config |
| `--yes` | never prompt |
| `--dry-run` | show what would change, change nothing |
| `--force` | replace an existing `forti` entry that points elsewhere; allow project or local scope in your home directory without a terminal. For `mcp uninstall`, also remove a `forti` entry that is not forti-mcp |
| `--keep-skill` | `mcp uninstall` only: leave the agent skill in place |

`mcp status` reports every client and scope (for the project in `--project-dir`) and the workspace;
`mcp repair` and `mcp uninstall` take `--client` and `--scope` to narrow what they touch. When a
conflict or error blocks the plan, nothing is changed and the command fails with `policy_denied`
(exit 7); when a change fails during execution, it fails with `config` (exit 3).

## What gets written where

The server is registered under the name `forti`, with the absolute path of `forti-mcp` and no
environment. With `--profile NAME`, the args are `--profile NAME`.

| Client | Scope | How | Where |
|---|---|---|---|
| Claude Code | `workspace` | direct edit, as for `project` | `~/.forti/.mcp.json` |
| Claude Code | `user` | `claude mcp add -s user forti -- <forti-mcp>` | `~/.claude.json` → `mcpServers` |
| Claude Code | `local` | the same with `-s local`, run in the project directory | `~/.claude.json` → `projects["<dir>"].mcpServers` |
| Claude Code | `project` | direct edit (other servers, keys and their order kept; atomic write; file mode kept) | `<dir>/.mcp.json` |
| Codex | `workspace` | direct edit, as for `project` | `~/.forti/.codex/config.toml` |
| Codex | `user` | `codex mcp add forti -- <forti-mcp>` | `$CODEX_HOME/config.toml` (default `~/.codex`) |
| Codex | `project` | direct edit of only the `[mcp_servers.forti]` table; every other byte stays the same | `<dir>/.codex/config.toml` |

`$CLAUDE_CONFIG_DIR` moves `~/.claude.json` to `$CLAUDE_CONFIG_DIR/.claude.json`. Codex has no `local` scope.

### The agent skill

The skill tells agents how to use the four tools, to treat device data as untrusted, and never to
change modes or approve plans. Its text is compiled into `forti`, so installing it needs no data files.

| Client | `workspace` | `user` | `project` / `local` |
|---|---|---|---|
| Claude Code | `~/.forti/.claude/skills/forti/SKILL.md` | `~/.claude/skills/forti/SKILL.md` (`$CLAUDE_CONFIG_DIR/skills/...` when set) | `<dir>/.claude/skills/forti/SKILL.md` |
| Codex | `~/.forti/.agents/skills/forti/SKILL.md` | `~/.agents/skills/forti/SKILL.md` | `<dir>/.agents/skills/forti/SKILL.md` |

Outside the workspace, forti never edits `CLAUDE.md`, `AGENTS.md` or any other instruction file. In
the workspace it writes its own `AGENTS.md` and `CLAUDE.md`, and leaves them alone once you edit them.

### Behavior worth knowing

- **Idempotent.** Re-running with the same inputs reports `already_registered` and changes nothing.
- **Conflicts.** An existing `forti` entry with a different command or args is reported and left
  alone. `--force` replaces it. Claude Code's `add` refuses existing names, so a replacement is
  `remove` and then `add`; if the `add` fails, forti puts the old entry back.
- **Scopes never widen.** A project or workspace install writes files in that directory only, apart
  from the Codex trust entry you agreed to.
- **Validation.** After writing, forti reads each registration back and runs `forti-mcp --version`.
  It never runs `claude mcp get` or `claude mcp list`: both start every server to health-check it.
  Status for Claude's local and user scopes reads `~/.claude.json` (read only); Codex user status
  uses `codex mcp get forti --json`, which starts nothing.
- **Restart Codex** after a change to its config. Claude Code picks up new servers in new sessions.

:::callout[Codex project scope needs a trusted project]{variant="note"}
For `project` scope, forti does **not** add a trust entry to the global Codex config; it warns
instead, and Codex asks to trust the project the first time you run it there. Only the workspace
offers to add the entry, with your consent ([Codex trust](#codex-trust)).
:::

## Checking the registrations

```sh
forti mcp status
```

`status` shows the forti-mcp it would register, every client and scope with its state, and the
workspace with the health of each of its files:

```text
workspace  /Users/me/.forti
  AGENTS.md                  ok
  CLAUDE.md                  ok
  Claude Code deny rules     ok
  Codex permission profile   ok
  Codex trust                ok (added by forti install mcp)
```

| State | Meaning |
|---|---|
| `ok` | as forti writes it |
| `missing` | not there; run `forti install mcp --scope workspace` |
| `outdated` | written by an older forti and unedited; the next install updates it |
| `modified` | edited since forti wrote it; left alone |
| `incomplete` | some of forti's deny rules, or half of the Codex profile, are missing |
| `overridden` | `.codex/config.toml` selects another `default_permissions`, so the forti profile is not active |
| `untrusted` | Codex does not trust the forti home, so it ignores the workspace's `.codex/config.toml` |

Files of a client that is not registered in the workspace are marked as such. With `--json`, the
same report is in `data.workspace`.

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

```sh
forti mcp uninstall --client all --scope workspace --yes
```

For the workspace, uninstall removes the registrations, the skill, `CLAUDE.md`, the deny rules forti
added, the Codex permission profile, the Codex trust entry if forti added it, and `AGENTS.md` once no
client is registered in the workspace any more. Files you edited are kept and reported. It never
touches `config.json`, `credentials/`, `certs/` or `state/`.

For other scopes, `forti mcp uninstall` removes the `forti` entries it finds (only those whose
command is a `forti-mcp` executable; `--force` removes another `forti` entry) and the forti skill
(only a `SKILL.md` whose frontmatter says `name: forti`; `--keep-skill` leaves it). Project files that
held nothing else are deleted, along with directories forti created and that are now empty. By hand:

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

- **No secrets in client config.** forti-mcp reads its own profiles (`~/.forti/config.json`) and
  secret store (Keychain or credential files), so the registration needs no `env`. The only argument
  forti may add is a profile name, which is validated and is not a secret.
- **No shell.** Client CLIs run through `posix_spawnp` with an argument vector, a timeout and
  captured output. No secret is ever passed in argv.
- **Files.** Writes are atomic (temporary file and rename) and keep the existing file mode. forti
  refuses to rewrite a `.mcp.json` or `.claude/settings.json` it cannot parse, or a
  `[mcp_servers.forti]` defined in a form it cannot edit as one block (dotted keys, inline tables,
  split tables).
- **`~/.claude.json` is never edited directly.** Running Claude Code sessions rewrite it constantly;
  only the `claude` CLI changes it.
- **Project files are shared.** `.mcp.json` and `.codex/config.toml` in a project are meant to be
  committed. They then contain the absolute path of your forti-mcp, which may differ on a teammate's
  machine (they can run `forti install mcp --scope project --force`, or prefer `user` scope). The
  workspace is yours alone: the forti home is private (0700) and is not a repository to commit.

:::callout[The skill is guidance, not a control]{variant="warning"}
Changes stay bounded by the profile's mode (`read-only`, `guarded`, `autonomous`) and the engine's
safeguards, whatever the agent reads. The skill and the workspace `AGENTS.md` tell agents to treat
device data (comments, names) as untrusted and never to change modes or approve plans. An agent that
can also run shell commands as you could still do both; see
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
