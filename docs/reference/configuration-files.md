---
title: Configuration files
description: Where forti keeps profiles, secrets, plans, approvals, backups and the audit log; config.json keys, file modes and environment variables.
order: 90
status: published
tags:
  - reference
---

# Configuration files

Nothing depends on the working directory.

## Directories

| What | Location |
|---|---|
| configuration | `$FORTI_CONFIG_DIR`, else `$XDG_CONFIG_HOME/forti`, else `~/.config/forti` (macOS included) |
| state | `$FORTI_STATE_DIR`, else `$XDG_STATE_HOME/forti`, else `~/.local/state/forti` |
| cache | `$FORTI_CACHE_DIR`, else `$XDG_CACHE_HOME/forti`, else `~/.cache/forti` |

The `FORTI_*_DIR` overrides must be absolute paths (a relative one is a `config` error). A relative
`XDG_*` value is ignored. forti-mcp uses the same directories, so both see the same profiles.

## Files

| File | Mode | Contents |
|---|---|---|
| `<config>/config.json` | 0600, directory 0700 | profiles and the default profile; no secrets |
| `<config>/credentials/<profile>.api-key`, `<profile>.cert-password` | 0600, directory 0700 | the file secret store: a `binding host:port` line, then the secret |
| macOS login Keychain, service `forti` | Keychain ACL | the macOS secret store: accounts `<profile>/api-key` and `<profile>/cert-password` |
| `<state>/plans/<id>.json` | 0600, directory 0700 | stored plans, including rollback plans, with real values |
| `<state>/plans/<id>.applied` | 0600 | marks a plan as applied: a plan runs at most once |
| `<state>/approvals/<id>.json` | 0600, directory 0700 | a guarded-mode approval: plan id, digest, `approved_at`, `expires_at`, `approved_by` |
| `<state>/approvals/<id>.used` | 0600 | an approval that an apply has consumed |
| `<state>/backups/<plan id>.conf` | 0600, directory 0700 | configuration backups taken before critical plans (the 20 most recent are kept) |
| `<state>/audit.jsonl` | 0600 | one JSON line per apply attempt and per approval; attribute names, never values |

Plans, approvals and backups are never cleaned up automatically, apart from the backup limit.
Deleting old plan files is safe once you no longer need them.

The cache directory is resolved but not written in this release: `forti discover --live` reads the
device's schema each time.

### Permissions forti enforces

- `config.json` is refused when another user owns it, when group or others can write it, or when its
  directory is writable by group or others (without the sticky bit).
- A credential file is refused when it is a symbolic link, is owned by another user, or is
  accessible by group or others. Fix it with `chmod 600`.
- `forti doctor` reports loose modes on the configuration directory, `config.json` and
  `credentials/` with the `chmod` that fixes them.

## config.json

```json
{
  "version": 1,
  "default_profile": "fw01",
  "profiles": {
    "fw01": {
      "host": "fw01.example.net",
      "port": 443,
      "vdom": "root",
      "ca_bundle": "/Users/me/certs/fw01-ca.pem",
      "mode": "read-only",
      "api_key": {"source": "store"}
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

`forti configure` and `forti profile` write this file atomically. You can edit it by hand; keep it
0600. Keys other than those below are dropped the next time forti writes the file.

| Key | Default | Meaning |
|---|---|---|
| `host` | required | host name or address, without scheme or port |
| `port` | `443` | admin HTTPS port |
| `vdom` | the device's default | VDOM for every request |
| `ca_bundle` | the system trust store | absolute path of a PEM CA bundle |
| `client_cert` | none | absolute path of a PKCS#12 client certificate |
| `resolve_ip` | none | connect to this address while verifying TLS for `host` |
| `mode` | `read-only` | `read-only`, `guarded` or `autonomous` |
| `api_key` | `{"source": "store"}` | `{"source": "store"}`, `{"source": "env", "env": "VAR"}` or `{"source": "command", "command": ["argv", "..."]}` |
| `cert_password` | none | the client certificate's password, same forms as `api_key` |
| `backup_before_critical` | `true` | take a configuration backup before a critical-risk plan runs (and refuse the plan if it cannot be taken) |
| `connect_timeout_ms` | `5000` | connection timeout |
| `timeout_ms` | `30000` | whole-request timeout |

`backup_before_critical`, `connect_timeout_ms` and `timeout_ms` have no `forti configure` option;
set them here. A profile that contains a secret value (`token`, `password`, `api_key_value`) is
rejected.

## Environment

| Variable | Effect |
|---|---|
| `FORTI_CONFIG_DIR`, `FORTI_STATE_DIR`, `FORTI_CACHE_DIR` | override the directories above (absolute paths) |
| `FORTI_SECRET_STORE` | `file` or `keychain`. Default: the Keychain on macOS, the file store elsewhere |
| `FORTI_OUTPUT=json` | always print the JSON envelope (same as `--json`) |
| `NO_COLOR` | no ANSI color (color is used only when the output is a terminal) |
| `HOME` | the base of the default directories |
| `USER` | recorded as `cli:$USER` in approvals |
