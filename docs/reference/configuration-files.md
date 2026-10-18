---
title: Configuration files
description: The forti home ~/.forti and its layout, overrides, migrating a pre-0.2 setup, file modes, config.json keys and environment variables.
order: 90
status: published
tags:
  - reference
---

# Configuration files

Where forti keeps profiles, secrets, certificates, plans, approvals, backups and the audit log, and
the keys of `config.json`. Everything lives in one directory, the forti home. Nothing depends on the
working directory.

:::toc[On this page]{depth="3" theme="compact"}
:::

## The forti home

The forti home is `$FORTI_HOME`, else `~/.forti` (mode 0700, macOS and Linux alike). forti-mcp uses the
same home, so both see the same profiles.

```text
~/.forti/                        0700   the forti home ($FORTI_HOME)
├── config.json                  0600   profiles and the default profile; no secrets
├── credentials/                 0700   the file secret store
│   └── <profile>.api-key        0600   (and <profile>.cert-password)
├── certs/<name>/                0700   client certificates: ca.crt, client.crt, client.p12, client.pass
├── ca/                          0700   the forti CA that issues them: ca.crt, ca.key
├── state/                       0700   plans, approvals, backups, the audit log
│   ├── plans/  approvals/  backups/  blobs/
│   └── audit.jsonl
└── cache/                              reserved
```

After `forti mcp install --scope workspace`, the home is also the
[MCP workspace](/guides/ai-agent-integration#the-forti-workspace): it then holds `AGENTS.md`,
`CLAUDE.md`, `.mcp.json`, `.claude/`, `.codex/`, `.agents/` and `.forti-workspace.json` as well.

`forti home` shows every location in use, the secret store, and any override:

```text
$ forti home
forti home: ~/.forti
  config       ~/.forti/config.json
  credentials  ~/.forti/credentials/  file store
  state        ~/.forti/state/  plans (kept 30 days), approvals, audit log, backups
  cache        ~/.forti/cache/
  certs        ~/.forti/certs/  client certificates (forti cert list)
  forti CA     ~/.forti/ca/  issues them; its key never leaves this machine
  secrets      macOS Keychain (service "forti")
```

With `--json`, `data` holds the same (`home`, `config_dir`, `config_file`, `credentials`, `state`,
`cache`, `certs`, `secret_store`, `plan_retention_days`, `legacy`, `overrides`).

### Overrides

| Location | Resolved as |
|---|---|
| home | `$FORTI_HOME`, else `~/.forti` |
| configuration (`config.json`, `credentials/`) | `$FORTI_CONFIG_DIR`, else the pre-0.2 location while one is in use, else the home |
| state | `$FORTI_STATE_DIR`, else the pre-0.2 location while one is in use, else `<home>/state` |
| cache | `$FORTI_CACHE_DIR`, else the pre-0.2 location while one is in use, else `<home>/cache` |
| certificates | always `<home>/certs` |

`FORTI_HOME` moves everything at once; the `FORTI_*_DIR` variables move one location each. All of them
must be absolute paths (a relative one is a `config` error).

### Pre-0.2 setups

Releases before 0.2 used the XDG locations: `~/.config/forti` (configuration and credentials),
`~/.local/state/forti` and `~/.cache/forti`, or `$XDG_CONFIG_HOME/forti`, `$XDG_STATE_HOME/forti` and
`$XDG_CACHE_HOME/forti` when those are set to absolute paths. Such a setup keeps working: forti uses it
while all of these hold:

- `FORTI_HOME` and `FORTI_CONFIG_DIR` are not set;
- `~/.forti/config.json` does not exist;
- the old `config.json` does.

`forti home` then adds a `legacy:` line, and the `home` check of `forti doctor` warns. New certificates
go to `~/.forti/certs` either way. Move the setup with one command:

```sh
forti home migrate
```

- It moves `credentials/`, the state directory and the cache into the home, then `config.json` **last**:
  until `config.json` is in the home, forti keeps using the old locations, so an interrupted migration
  leaves a working setup, and running the command again finishes it.
- Items are renamed (or, across file systems, copied, renamed into place and then deleted), so their
  contents and modes are kept.
- It never overwrites anything. When `~/.forti/config.json`, or another destination that is not an
  empty directory, already exists, it moves nothing and lists the conflicts. Move the old setup or the
  conflicting files aside and run it again.
- It refuses while `FORTI_CONFIG_DIR`, `FORTI_STATE_DIR` or `FORTI_CACHE_DIR` is set, because forti then
  uses that directory, not the home. Unset the variable (and move that directory yourself if you want
  it in the home).
- Other files in `~/.config/forti` (a CA bundle a profile refers to, for example) stay where they are
  and are listed; profiles keep pointing at them. The old directory is removed once it is empty.
- Keychain items need no change: their account names stay the same.
- Running it again is harmless: "already migrated: nothing to move".

Then run `forti home` and `forti doctor`.

## Files

| File | Mode | Contents |
|---|---|---|
| `~/.forti/config.json` | 0600, directory 0700 | profiles and the default profile; no secrets |
| `~/.forti/credentials/<profile>.api-key`, `<profile>.cert-password` | 0600, directory 0700 | the file secret store: a `binding host:port` line, then the secret |
| macOS login Keychain, service `forti` | Keychain ACL | the macOS secret store: accounts `<profile>/api-key` and `<profile>/cert-password` |
| `~/.forti/certs/<name>/` | 0700 | a client certificate (`forti configure`, `forti cert`): `ca.crt` and `client.crt` (0644), `client.p12` and `client.pass` (0600), and `ca/ca.key` for one with its own CA. See [Client certificates](/guides/client-certificates#the-files) |
| `~/.forti/ca/` | 0700 | the forti CA: `ca.crt` (0644), `ca.key` (0600) |
| `~/.forti/state/plans/<id>.json` | 0600, directory 0700 | stored plans, including rollback plans, with real values; deleted once an apply has started executing them, or after the retention period |
| `~/.forti/state/plans/<id>.applied` | 0600 | marks a plan as applied (a plan runs at most once) and keeps its summary and outcome; deleted after the retention period |
| `~/.forti/state/plans/.lock` | 0600 | held by every apply, so the retention purge never runs during one |
| `~/.forti/state/blobs/<sha256>.json` | 0600, directory 0700 | monitor action bodies over 64 KiB, stored once and named by their SHA-256; deleted after an apply once no waiting plan refers to them |
| `~/.forti/state/approvals/<id>.json` | 0600, directory 0700 | a guarded-mode approval: plan id, digest, `approved_at`, `expires_at`, `approved_by`; deleted with its plan, or after the retention period |
| `~/.forti/state/approvals/<id>.used` | 0600 | an approval that an apply has consumed (until the apply ends) |
| `~/.forti/state/backups/<plan id>.conf` | 0600, directory 0700 | configuration backups taken before critical plans (the 20 most recent are kept) |
| `~/.forti/state/audit.jsonl` | 0600 | one JSON line per apply attempt and per approval; attribute names, never values |

:::callout[Plan retention]{variant="note"}
A plan is deleted once an apply has started executing it; its `.applied` marker stays so a second apply
is refused as already applied. Plans not applied, rollback plans, markers and approvals are deleted
after `plan_retention_days` (default 30; `forti home retention DAYS`). The audit log is never cleaned
up, and backups keep the 20 most recent. See
[How long plans are kept](/guides/planning-and-applying-changes#how-long-plans-are-kept).
:::

The cache directory is resolved but not written in this release: `forti discover --live` reads the
device's schema each time.

### Permissions forti enforces

- `config.json` is refused when another user owns it, when group or others can write it, or when its
  directory is writable by group or others (without the sticky bit).
- A credential file, and a file named by a `file` credential source, is refused when it is a symbolic
  link, is not a regular file, is owned by another user, or is accessible by group or others. Fix it
  with `chmod 600`.
- `forti doctor` reports loose modes on the configuration directory, `config.json` and
  `credentials/` with the `chmod` that fixes them.

## config.json

```json
{
  "version": 1,
  "default_profile": "fw01",
  "plan_retention_days": 30,
  "profiles": {
    "fw01": {
      "host": "fw01.example.net",
      "port": 443,
      "vdom": "root",
      "ca_bundle": "/Users/me/certs/fw01-ca.pem",
      "mode": "read-only",
      "api_key": {"source": "store"},
      "client_cert": "/Users/me/.forti/certs/fw01/client.p12",
      "cert_password": {"source": "file", "path": "/Users/me/.forti/certs/fw01/client.pass"}
    },
    "lab": {
      "host": "192.0.2.10",
      "port": 8443,
      "mode": "guarded",
      "api_key": {"source": "env", "env": "FORTI_LAB_KEY"}
    }
  }
}
```

`forti configure`, `forti profile` and `forti cert` write this file atomically. You can edit it by
hand; keep it 0600.

:::callout[Unknown keys are dropped]{variant="warning"}
Keys other than those below are dropped the next time forti writes the file. A profile that contains
a secret value (`token`, `password`, `api_key_value`) is rejected.
:::

Top-level keys:

| Key | Default | Meaning |
|---|---|---|
| `version` | `1` | the file format |
| `default_profile` | none | the profile used when none is named (`forti profile default NAME`) |
| `plan_retention_days` | `30` | how long stored plans, applied markers and approvals are kept, in whole days from 1 to 3650 (`forti home retention DAYS`). Anything else (0, a negative or fractional number, a string) makes `config.json` invalid: a `config` error naming the setting |
| `profiles` | none | the profiles, by name; keys below |

Profile keys:

| Key | Default | Meaning |
|---|---|---|
| `host` | required | host name or address, without scheme or port |
| `port` | `443` | admin HTTPS port |
| `vdom` | the device's default | VDOM for every request |
| `ca_bundle` | the system trust store | absolute path of a PEM CA bundle |
| `client_cert` | none | absolute path of a PKCS#12 client certificate |
| `resolve_ip` | none | connect to this address while verifying TLS for `host` |
| `mode` | `read-only` | `read-only`, `guarded` or `autonomous` |
| `api_key` | `{"source": "store"}` | `{"source": "store"}`, `{"source": "env", "env": "VAR"}`, `{"source": "command", "command": ["argv", "..."]}` or `{"source": "file", "path": "/absolute/path"}` |
| `cert_password` | none | the client certificate's password, same forms as `api_key` |
| `backup_before_critical` | `true` | take a configuration backup before a critical-risk plan runs (and refuse the plan if it cannot be taken) |
| `connect_timeout_ms` | `5000` | connection timeout |
| `timeout_ms` | `30000` | whole-request timeout |

`backup_before_critical`, `connect_timeout_ms` and `timeout_ms` have no `forti configure` option;
set them with `forti profile set NAME key=value` or here.

## Environment

| Variable | Effect |
|---|---|
| `FORTI_HOME` | the forti home (default `~/.forti`; an absolute path) |
| `FORTI_CONFIG_DIR`, `FORTI_STATE_DIR`, `FORTI_CACHE_DIR` | override one location inside it ([Overrides](#overrides); absolute paths) |
| `XDG_CONFIG_HOME`, `XDG_STATE_HOME`, `XDG_CACHE_HOME` | used only to find a [pre-0.2 setup](#pre-0-2-setups) |
| `FORTI_SECRET_STORE` | `file` or `keychain`. Default: the Keychain on macOS, the file store elsewhere |
| `FORTI_OUTPUT=json` | always print the JSON envelope (same as `--json`) |
| `NO_COLOR` | no ANSI color (color is used only when the output is a terminal) |
| `HOME` | the base of the default home, `~/.forti` |
| `USER` | recorded as `cli:$USER` in approvals |
