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
forti configure --profile NAME [--skip-check]     prompt for NAME's settings
forti configure --profile NAME --host HOST [options] <credential>
```

Creates or updates a profile and verifies it with one read of `monitor/system/status` before saving.
Options: `--host`, `--port`, `--vdom`, `--ca-bundle`, `--resolve-ip`, `--client-cert`, one of
`--api-key-stdin`, `--api-key-env VAR`, `--api-key-command CMD`, optionally one of
`--cert-password-stdin`, `--cert-password-env VAR`, `--cert-password-command CMD`, and `--mode`,
`--default`, `--skip-check`. See [Profiles and credentials](/guides/profiles-and-credentials).

### profile

```text
forti profile [list]
forti profile show [NAME]
forti profile default NAME
forti profile mode [NAME] read-only|guarded|autonomous
forti profile remove NAME
```

`remove` also deletes the profile's secrets from the secret store. Removing a profile never contacts
the device.

### doctor

```text
forti doctor [--profile NAME]
```

Ordered checks (`config`, `profile`, `secrets`, `tls_files`, `connection`, `auth`, `version`, `mode`,
`privileges` for autonomous profiles, `mcp`), each reported as `ok`, `warn`, `fail`, `skip` or
`info`. Exits 0 when nothing failed, otherwise with the status of the first failure. See
[Checking a profile](/guides/profiles-and-credentials#checking-a-profile).

## Read

### devices

```text
forti devices
```

Lists the configured profiles; the default is marked with `*`. The same as `forti profile list`.

### discover

```text
forti discover [search]          resources whose path contains `search`
forti discover <resource>        a resource's attributes, operations and risk tier
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
  --start N          first item (default 0)
  --count N          items per page (default 50, max 1000)
  --param name=val   extra query parameter (monitor endpoints), repeatable
  --reveal           show device secrets instead of <redacted>; needs a terminal or --json
```

```sh
forti get firewall/policy --fields policyid,name,action,status
forti get firewall/address "LAN 10.0.0.0/24"
forti get monitor/system/status
```

See [Discovering and reading](/guides/discovering-and-reading#get).

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

Executes a stored plan once, under the profile's mode: read-only profiles refuse, guarded profiles
need `forti plan approve <id>` first, autonomous profiles run without approval. See
[Applying a plan](/guides/planning-and-applying-changes#applying-a-plan).

## Integrations

### install mcp

```text
forti install mcp [--client claude|codex|all] [--scope user|project|local] [--project-dir DIR]
                  [--profile NAME] [--skill|--no-skill] [--yes] [--dry-run] [--force]
```

### mcp

```text
forti mcp status
forti mcp repair    [--client ...] [--scope ...] [--project-dir DIR] [--yes] [--dry-run]
forti mcp uninstall [--client ...] [--scope ...] [--project-dir DIR] [--keep-skill] [--yes] [--dry-run] [--force]
```

`-y` is short for `--yes`. See [AI agent integration](/guides/ai-agent-integration).

## Environment

| Variable | Effect |
|---|---|
| `FORTI_CONFIG_DIR`, `FORTI_STATE_DIR`, `FORTI_CACHE_DIR` | override the configuration, state and cache directories |
| `FORTI_SECRET_STORE` | `file` or `keychain` |
| `FORTI_OUTPUT=json` | always print the JSON envelope (same as `--json`) |
| `NO_COLOR` | no ANSI color |

See [Configuration files](/reference/configuration-files#environment).
