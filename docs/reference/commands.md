---
title: Command reference
description: Every forti command and option, the output formats and the JSON envelope.
order: 80
status: published
tags:
  - reference
---

# Command reference

```text
forti [global options] <command> [arguments]
```

`forti --help` lists the commands; `forti <command> --help` or `forti help <command>` shows a
command's options, and `man forti` has a summary. A mistyped command gets suggestions.

:::toc[On this page]{depth="3" theme="compact"}
:::

## Commands at a glance

| Command | Group | What it does | Contacts the device |
|---|---|---|---|
| [`configure`](#configure) | Setup | create or update a profile | one verification read, unless `--skip-check` |
| [`profile`](#profile) | Setup | list, show, change, rename, copy, set the default or mode, remove | never |
| [`doctor`](#doctor) | Setup | check the home, configuration, credentials, TLS, auth, version, mode | yes |
| [`home`](#home) | Setup | show where forti keeps its files, or migrate a pre-0.2 setup | never |
| [`cert`](#cert) | Setup | create, list, show, use or remove client certificates | never |
| [`devices`](#devices) | Read | list the configured profiles | never |
| [`discover`](#discover) | Read | search the catalog, or show a resource's attributes | only with `--live` |
| [`get`](#get) | Read | read configuration or monitor data | yes |
| [`set`, `create`, `delete`](#set-create-delete) | Change | make a change in one command, as the profile's mode allows | yes |
| [`rollback`](#rollback) | Change | undo the last change (or a named one) | yes |
| [`approve`](#approve) | Change | approve a plan an agent made (guarded mode), one at a time or `--watch` | never |
| [`plan`](#plan) | Change | preview, save, show and list plans | when writing a plan (reads only) |
| [`apply`](#apply) | Change | apply a saved plan | yes |
| [`history`](#history) | Change | what was applied: when, on which profile, approved by whom, what changed | never |
| [`mcp`](#mcp) | Integrations | register forti-mcp with AI clients (recommended: the `~/.forti` workspace); status, repair or uninstall the registrations | never |
| [`completion`](#completion) | Integrations | print the bash, zsh or fish completion script | never |

## Global options

Global options may come before or after the command.

| Option | Meaning |
|---|---|
| `-p, --profile NAME` | device profile (default: the default profile, or the only one) |
| `--vdom NAME` | VDOM for this request (default: the profile's, else the device's) |
| `--json` | print the JSON result envelope (also `FORTI_OUTPUT=json`) |
| `--no-color` | plain text (also `NO_COLOR`; color is only used on a terminal) |
| `-h, --help` | help for forti or for a command |
| `--version` | the forti version and the FortiOS schema version of the models |

## Output

Text output is for people. Tables put the identifying column first (an object's key, such as
`policyid` or `name`), then the `--fields` you asked for in that order, and fit the terminal width.
FortiOS's bookkeeping attribute `q_origin_key` is hidden in text output. Values read from a device
are printed with terminal control characters escaped.

`--json` prints the stable envelope that scripts and forti-mcp share:

```json
{"ok": true, "data": [...], "meta": {"profile": "fw01", "resource": "firewall/policy", "start": 0, "returned": 50, "next_start": 50}}
{"ok": false, "error": {"code": "not_found", "message": "firewall/address \"x\" not found", "details": {"http_status": 404}}}
```

In text mode, errors go to standard error with a hint. In JSON mode, the envelope goes to standard
output. The exit status follows [the error code](/reference/exit-codes) in both modes.

## Setup

### configure

```text
forti configure                                   prompt on the terminal
forti configure --profile NAME [--skip-check]     prompt for NAME's settings (prefilled when it exists)
forti configure --profile NAME --host HOST [options] <credential>
```

Creates or updates a profile and verifies it with one read of `monitor/system/status` before saving.
On an existing profile the prompts start from its current values, and with options only the options
given change. The prompts also offer a client certificate: reuse one, or make one and get the
FortiGate commands before the check. See [Profiles and credentials](/guides/profiles-and-credentials)
and [Client certificates](/guides/client-certificates).

| Options | |
|---|---|
| connection | `--host`, `--port`, `--vdom`, `--ca-bundle`, `--resolve-ip` |
| client certificate (optionally one of) | `--cert NAME` (one of forti's, password included), `--client-cert PATH` (a PKCS#12 file of your own) |
| API key (one of) | `--api-key-stdin`, `--api-key-env VAR`, `--api-key-command CMD` |
| certificate password (optionally one of) | `--cert-password-stdin`, `--cert-password-env VAR`, `--cert-password-command CMD`, `--cert-password-file PATH` |
| other | `--mode`, `--default`, `--skip-check` |

### profile

```text
forti profile [list]
forti profile show [NAME]
forti profile set NAME key=value...
forti profile rename OLD NEW
forti profile copy SOURCE NEW
forti profile default NAME
forti profile mode [NAME] read-only|guarded|autonomous
forti profile remove NAME
```

- `set` changes settings without contacting the device. Keys: `host`, `port`, `vdom`, `ca_bundle`,
  `client_cert`, `resolve_ip`, `connect_timeout_ms`, `timeout_ms`, `backup_before_critical`, `mode`;
  an empty value restores the default. A changed host or port re-binds the profile's stored secrets.
- `rename` moves the stored secrets, a certificate named after the profile (`~/.forti/certs/OLD/`) and
  the paths that point into it, and the default. A certificate keeps its CN, so the FortiGate needs no
  change.
- `copy` copies settings only: never the API key, the client certificate or its password.
- `remove` also deletes the profile's secrets from the secret store.

No profile command contacts the device. See
[Several FortiGates](/guides/profiles-and-credentials#several-fortigates).

### doctor

```text
forti doctor [--profile NAME]
```

Ordered checks (`home`, `config`, `profile`, `secrets`, `tls_files`, `connection`, `auth`, `version`, `mode`,
`privileges` for autonomous profiles, `mcp`), each reported as `ok`, `warn`, `fail`, `skip` or
`info`. Exits 0 when nothing failed, otherwise with the status of the first failure. See
[Checking a profile](/guides/profiles-and-credentials#checking-a-profile).

### home

```text
forti home                 the forti home and every location in it
forti home migrate         move a pre-0.2 setup into the home
```

The forti home is `$FORTI_HOME`, else `~/.forti`. `migrate` moves `credentials/`, the state and the
cache, then `config.json`, from `~/.config/forti`, `~/.local/state/forti` and `~/.cache/forti` (or the
`XDG_*` equivalents). It keeps modes, never overwrites, refuses while a `FORTI_*_DIR` override is set,
and is safe to run again. See [Configuration files](/reference/configuration-files#the-forti-home).

### cert

```text
forti cert create [NAME] [--profile PROFILE] [--own-ca] [--days N] [--force] [--keychain]
forti cert list
forti cert show [NAME]
forti cert use NAME [--profile PROFILE]
forti cert remove [NAME]
```

Certificates are named, live in `~/.forti/certs/<name>/` and need no profile: one can serve several
FortiGates. `create` makes one (CN `forti-<name>`), issued by the forti CA (`~/.forti/ca/`, made on
first use) unless `--own-ca`, and prints the FortiGate commands, ready to paste, and the command that
reads the password (never the password). Without NAME it is named after the default profile, which
then uses it; with no profile at all it is named `default`. Needs the `openssl` command.

| Option | Meaning |
|---|---|
| `--profile PROFILE` | the profile that uses the new certificate |
| `--own-ca` | a CA for this certificate only, instead of the forti CA |
| `--days N` | validity (default 1095); a forti CA certificate cannot outlive the CA |
| `--force` | replace a certificate of that name. From the forti CA, the FortiGate needs no change |
| `--keychain` | keep the password in the secret store of `--profile` instead of `client.pass` |

`list` shows the forti CA and every certificate with its issuer, expiry and the profiles using it.
`show` prints one (NAME, else the certificate of `--profile` or the default profile). `use` points a
profile (`--profile`, else the default) at a certificate. `remove` deletes a certificate and detaches
it from every profile that used it. See [Client certificates](/guides/client-certificates).

## Read

### devices

```text
forti devices
```

Lists the configured profiles; the default is marked with `*`. The same as `forti profile list`.

### discover

```text
forti discover [search]          resources whose path contains `search`
forti discover <resource>        a resource's attributes, operations and risk tier (path or CLI words)
  --kind table|singleton|monitor   restrict a search
  --fields a,b                     full detail for these attributes
  --live                           merge the device's schema (help, options, ranges)
  --start N --count N              page through a search
```

Works offline except with `--live`. See [Discovering and reading](/guides/discovering-and-reading#discover).

### get

```text
forti get <resource> [key]
  --filter EXPR      FortiOS filter, repeatable (AND); ',' inside one is OR (name==a,name==b)
  --fields a,b       return only these attributes
  --all              read every page of a listing
  --start N          first item (default 0)
  --count N          items per page (default 50, max 1000)
  --param name=val   extra query parameter (monitor endpoints), repeatable
  --reveal           show device secrets instead of <redacted>; needs a terminal or --json
```

```sh
forti get firewall/policy --fields policyid,name,action,status --all
forti get firewall address "LAN 10.0.0.0/24"
forti get firewall/address/web
forti get monitor/system/status
```

The resource is its path, its FortiOS CLI words, or a last word only one resource has (`address`); a
table object can be named by its path. When a listing has more pages, forti says so on standard
error; `--all` reads them all. See
[Naming a resource](/guides/discovering-and-reading#naming-a-resource) and
[Discovering and reading](/guides/discovering-and-reading#get).

## Change

### set, create, delete

```text
forti set <resource> [key] attr=value... [--clear attr] [--dry-run] [--verbose]
forti create <resource> attr=value... | --object JSON|@file [--dry-run] [--verbose]
forti delete <resource> <key> [--dry-run] [--verbose]
```

One command per change. The resource is named as for `get` (`firewall/address web`,
`firewall/address/web`, `firewall address web`, `address web`). forti plans the change, shows it,
and then:

| Profile mode | `set`, `create`, `delete` |
|---|---|
| `read-only` | change nothing, and print the command that allows changes (exit 7) |
| `guarded` | at a terminal, ask once: `Apply these changes? [y/N]`; without one, stop at the approval (exit 7) with `forti approve <id>` |
| `autonomous` | apply without asking |

`--dry-run` only plans; `--verbose` adds the request lines and the digest; `--json` prints the apply
result with the plan (and never asks). See [Making changes](/guides/planning-and-applying-changes).

### rollback

```text
forti rollback [plan id]
```

Applies the rollback plan of the profile's last change, or of the named plan (or the named rollback
plan), showing what it undoes. The same mode rules as `set` (guarded: one question). See
[Rollback plans](/guides/planning-and-applying-changes#rollback-plans).

### approve

```text
forti approve [id] [--yes] [--verbose]
forti approve --watch [-p PROFILE]
```

Approves a plan (guarded mode) so the agent or script that made it can apply it. At a terminal it
shows the change and asks; without an id it takes the plan waiting for the profile when only one is.
Without a terminal only `--yes` approves. `--watch` asks about each plan as agents make them (and
those made in the last hour) until Ctrl-C or `q`. `forti plan approve` is the same command. See
[Changes made by an agent](/guides/planning-and-applying-changes#changes-made-by-an-agent).

### plan

```text
forti plan set|create|delete <resource> ... [--apply]
forti plan action <monitor/path> [--body JSON|@file] [--apply]
forti plan --file changes.json|- [--apply]
forti plan show [id]
forti plan list
forti plan approve [id] [--yes]
```

`-f` is short for `--file`, `-y` for `--yes`. Planning reads the device and never changes it; the
plan is saved for `forti apply` (or `forti approve`). `--apply` makes the change in the same command,
exactly as `set` does. `--verbose` adds the plan digest to the text output. A plan id can be
shortened to a unique prefix (of the id or of its last part); `show latest` is the newest plan. See
[Plans](/guides/planning-and-applying-changes#plans).

### apply

```text
forti apply [plan id]
```

Shows a saved plan and applies it once, as the profile's mode allows (guarded: one question at a
terminal, none for a plan already approved). Without an id, at a terminal: the plan waiting for the
profile; when several are, you pick one. Without a terminal the plan must be named. See
[Applying a plan](/guides/planning-and-applying-changes#applying-a-plan).

### history

```text
forti history [-p NAME] [-n N] [--all] [--verbose]
```

Reads the audit log (`~/.forti/state/audit.jsonl`) and shows the applies in it, newest last: the
local time, the profile, the result (`applied`, `partial`, `failed`, `unknown`, `lost management`,
`refused: ...`), the plan (the last part of its id, which `forti plan show` accepts), the approval
(`approved by cli:alice`, or `autonomous` with the agent that applied it) and what changed.
Rollbacks say which plan they undo. It needs no configuration and never contacts a device.

| Option | Meaning |
|---|---|
| `-p, --profile NAME` | only this profile's entries (default: every profile) |
| `-n, --limit N` | the last N entries (default 20; `0`: all) |
| `--all` | also the attempts refused before anything changed: a read-only profile, a missing approval, a stale or already applied plan. They are hidden by default, and standard error says how many |
| `--verbose` | every operation with its result, the approval, the error, the rollback plan and the `forti rollback` command that undoes the change; approve events too |

`--json` prints the audit events as recorded, with `meta.hidden` (refusals left out), `meta.older`
(entries beyond the limit) and `meta.malformed` (lines that could not be read, which are skipped).
Text output escapes terminal control characters in everything taken from the log.

```sh
forti history
forti history -p fw01 --verbose -n 5
```

## Integrations

### mcp

```text
forti mcp install   [--client claude|codex|all] [--scope workspace|project|user|local] [--project-dir DIR]
                    [--profile NAME] [--skill|--no-skill] [--trust-codex-workspace]
                    [--yes] [--dry-run] [--force]
forti mcp status
forti mcp repair    [--client ...] [--scope ...] [--project-dir DIR] [--yes] [--dry-run]
forti mcp uninstall [--client ...] [--scope ...] [--project-dir DIR] [--keep-skill] [--yes] [--dry-run] [--force]
```

`forti install mcp` is the same as `forti mcp install`. In a terminal, `install` asks for what is
missing, shows every change, and applies it on Enter (`repair` too; `uninstall` needs `y`).
`workspace` (the recommended, first interactive choice) registers forti-mcp in the forti home, so only
agents started there (`cd ~/.forti && claude`, or `codex`) get the tools, with the skill, `AGENTS.md`
and deny rules for the credentials kept there. `--trust-codex-workspace` marks the home trusted in the
global Codex config. `--force` also allows project or local scope in your home directory without a
terminal. Without a terminal, or with `--yes`, `--client` and `--scope` are required.

`status` includes the workspace and the health of its files. `uninstall --scope workspace` removes
the registrations and the files forti wrote in the workspace, never `config.json`, credentials,
certificates or state. `-y` is short for `--yes`. See [AI agent integration](/guides/ai-agent-integration).

### completion

```text
forti completion bash|zsh|fish
```

Prints the shell completion script: commands, subcommands, options, profile names after `-p`,
resource paths (one segment at a time: `firewall/` then `firewall/address`), modes after
`profile mode`, and the ids of plans waiting to be applied after `apply`, `rollback` and
`plan show|approve`. On each Tab the script runs `forti`, which reads only the profile names in
`config.json` and the plans directory: never a device or a secret.

The Homebrew formula and the Debian package install the scripts; nothing else is needed (bash needs
the bash-completion package, zsh `compinit`). For a source build or a copy in your home directory:

:::tabs{default="bash"}

:::tab[bash]{value="bash"}
```bash
echo 'source <(forti completion bash)' >> ~/.bashrc
```
:::

:::tab[zsh]{value="zsh"}
```bash
# in ~/.zshrc, after compinit
source <(forti completion zsh)
```
:::

:::tab[fish]{value="fish"}
```bash
forti completion fish > ~/.config/fish/completions/forti.fish
```
:::

:::

`meson install` puts them in `share/bash-completion/completions/forti`,
`share/zsh/site-functions/_forti` and `share/fish/vendor_completions.d/forti.fish` under the prefix
(`-Dcompletions=disabled` leaves them out).

## Environment

| Variable | Effect |
|---|---|
| `FORTI_HOME` | the forti home (default `~/.forti`; `forti home` shows it) |
| `FORTI_CONFIG_DIR`, `FORTI_STATE_DIR`, `FORTI_CACHE_DIR` | override one location inside it |
| `FORTI_SECRET_STORE` | `file` or `keychain` |
| `FORTI_OUTPUT=json` | always print the JSON envelope (same as `--json`) |
| `NO_COLOR` | no ANSI color |

See [Configuration files](/reference/configuration-files#environment).
