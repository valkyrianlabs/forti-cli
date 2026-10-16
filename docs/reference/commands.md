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
| [`cert`](#cert) | Setup | create, show or remove a profile's client certificate | never |
| [`devices`](#devices) | Read | list the configured profiles | never |
| [`discover`](#discover) | Read | search the catalog, or show a resource's attributes | only with `--live` |
| [`get`](#get) | Read | read configuration or monitor data | yes |
| [`plan`](#plan) | Change | write, show, list and approve stored plans | when writing a plan (reads only) |
| [`apply`](#apply) | Change | execute a stored plan once | yes |
| [`install mcp`](#install-mcp) | Integrations | register forti-mcp with AI clients (recommended: the `~/.forti` workspace) | never |
| [`mcp`](#mcp) | Integrations | status, repair or uninstall the registrations | never |

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

### plan

```text
forti plan --file changes.json|-
forti plan set <resource> [key] attr=value... [--clear attr]
forti plan create <resource> --object JSON|@file
forti plan delete <resource> <key>
forti plan action <monitor/path> [--body JSON|@file]
forti plan show <id>
forti plan list
forti plan approve <id> [--yes]
```

`-f` is short for `--file`, `-y` for `--yes`. Planning reads the device and never changes it.
`approve` exists only in the CLI, for guarded profiles. See
[Planning and applying changes](/guides/planning-and-applying-changes).

### apply

```text
forti apply <plan id>
```

Executes a stored plan once, under the profile's mode. See
[Applying a plan](/guides/planning-and-applying-changes#applying-a-plan).

| Profile mode | `forti apply` |
|---|---|
| `read-only` | refused (`policy_denied`) |
| `guarded` | needs `forti plan approve <id>` first |
| `autonomous` | runs without approval |

## Integrations

### install mcp

```text
forti install mcp [--client claude|codex|all] [--scope workspace|project|user|local] [--project-dir DIR]
                  [--profile NAME] [--skill|--no-skill] [--trust-codex-workspace]
                  [--yes] [--dry-run] [--force]
```

`workspace` (the recommended, first interactive choice) registers forti-mcp in the forti home, so only
agents started there (`cd ~/.forti && claude`, or `codex`) get the tools, with the skill, `AGENTS.md`
and deny rules for the credentials kept there. `--trust-codex-workspace` marks the home trusted in the
global Codex config. `--force` also allows project or local scope in your home directory without a
terminal. Without a terminal, or with `--yes`, `--client` and `--scope` are required.

### mcp

```text
forti mcp status
forti mcp repair    [--client ...] [--scope ...] [--project-dir DIR] [--yes] [--dry-run]
forti mcp uninstall [--client ...] [--scope ...] [--project-dir DIR] [--keep-skill] [--yes] [--dry-run] [--force]
```

`status` includes the workspace and the health of its files. `uninstall --scope workspace` removes
the registrations and the files forti wrote in the workspace, never `config.json`, credentials,
certificates or state. `-y` is short for `--yes`. See [AI agent integration](/guides/ai-agent-integration).

## Environment

| Variable | Effect |
|---|---|
| `FORTI_HOME` | the forti home (default `~/.forti`; `forti home` shows it) |
| `FORTI_CONFIG_DIR`, `FORTI_STATE_DIR`, `FORTI_CACHE_DIR` | override one location inside it |
| `FORTI_SECRET_STORE` | `file` or `keychain` |
| `FORTI_OUTPUT=json` | always print the JSON envelope (same as `--json`) |
| `NO_COLOR` | no ANSI color |

See [Configuration files](/reference/configuration-files#environment).
