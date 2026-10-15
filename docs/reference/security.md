---
title: Security notes
description: What is stored where, how secrets are kept out of output, TLS, the limits of operating modes and the risks of autonomous writes.
order: 100
status: published
tags:
  - reference
---

# Security notes

## What is stored where

| Data | Where | Protection |
|---|---|---|
| Profiles (host, port, VDOM, paths, mode, credential *reference*) | `config.json` | 0600 file in a 0700 directory. No secrets: a config file containing one is rejected |
| API keys and certificate passwords (secret-store source) | macOS: login Keychain (service `forti`). Elsewhere: `credentials/` | Keychain ACL; or 0600 files that forti refuses to read when group or others can access them. Bound to the profile's host:port |
| API keys (env / command source) | not stored | only the variable name or the command's argv is saved |
| Plans, approvals, audit log | state directory | 0600 files. Plan files keep real values (apply needs them) |
| Pre-change configuration backups (critical plans) | `<state>/backups/<plan id>.conf` | 0600 file in a 0700 directory, streamed to disk, never logged or printed; the 20 most recent are kept |

Paths: [Configuration files](/reference/configuration-files).

forti's own credentials (API keys, certificate passwords) never appear in arguments, output, logs,
plans, audit records, error messages or the MCP client configuration. `forti profile show` and
`forti doctor` report where a key comes from and whether it resolves, never its value.
`forti configure` refuses a key as an argument value.

Device secrets are redacted too. FortiOS returns stored secrets in its encrypted form (`ENC ...`).
Admin passwords are hashes, but pre-shared keys and RADIUS/LDAP/TACACS+ secrets are reversibly
encrypted, by default with a key built into FortiOS (CVE-2019-6693) unless `private-data-encryption`
is enabled on the device. So:

- **Reads** (`forti get`, forti-mcp's `forti_read`) replace every string value starting with `ENC `,
  and the value of every attribute whose name marks it as secret, with `"<redacted>"`, at any depth.
  `meta.redacted` lists where (JSON pointers, `*` for list items, e.g. `/*/psksecret`). An unset
  secret stays visibly unset (`""` or `null`). This is the default for every caller, and forti-mcp
  cannot turn it off. Only `forti get --reveal` shows the values, for a person who asks: it needs a
  terminal (or `--json`, chosen deliberately) and warns on stderr.
- **Plan diffs, request previews, audit records and error details** redact the same attribute names
  (password, psk, secret, private-key, key-string, api-key, `*-key`, ...; checked against every
  attribute the FortiOS 7.4.8 schema types as a password). Audit records hold attribute names only,
  never values.
- **Plans refuse `"<redacted>"` as a value**, so copying a read object into a plan cannot overwrite a
  secret with the placeholder.
- **Stored plan files** keep the real values, because apply writes them and compares the device's
  current state against them. That is why they are 0600.

Name-based redaction can miss an attribute a later FortiOS adds; `ENC ` values are caught whatever
their name.

### Stored keys are bound to their device

A key in the secret store is saved with the `host:port` of the profile it was configured for (the
Keychain item's generic attribute; the first line of a credential file). forti releases it only to a
profile that still points there. Otherwise it fails with `config` ("the stored key belongs to
host:port; run forti configure") and sends nothing. So another `config.json` that reuses a profile
name (a different `FORTI_CONFIG_DIR`, for example one set by a repository's MCP configuration) cannot
send your key to another host. `forti configure` writes the binding, and re-binds a kept key when you
change the profile's host or port. Keys from `env` and `command` sources are not stored, so they are
not bound.

### Other hardening

- `config.json` decides each profile's mode and may name a credential command that forti runs, so it
  is refused when another user owns it or when group or others can write it (or its directory).
  Credential files are refused when they are symbolic links, owned by another user, or accessible
  by group or others.
- `FORTI_CONFIG_DIR`, `FORTI_STATE_DIR` and `FORTI_CACHE_DIR` must be absolute paths, so profiles,
  credentials and modes never depend on the working directory.
- A credential command runs without a shell, with its standard input from `/dev/null` and only
  descriptors 0 to 2 inherited.
- `forti` and `forti-mcp` disable core dumps at startup, because their memory holds keys and device
  data.
- Text output escapes terminal control characters in everything read from a device or a plan, so a
  crafted object name or comment cannot redraw the terminal (for example while you approve a plan).
- Before its first change, apply checks that `audit.jsonl` can be opened for appending; if it cannot,
  nothing is sent (`config`). If the record cannot be written after the changes, the result says so
  (`audit_error`) instead of dropping it silently.

## TLS is always verified

The SDK always verifies the peer certificate and host name, and no option, environment variable or
config key turns that off. For a self-signed or private-CA device, give the profile the CA with
`--ca-bundle`, or use `--resolve-ip` to connect to an address while verifying the certificate's name.

## Authentication failures are not retried

FortiOS locks an API user out after repeated authentication failures. `forti configure` and
`forti doctor` make one attempt and stop on HTTP 401/403 with advice: check the key, check that
this machine is within the API user's trusted hosts, and check its admin profile.

## Operating modes

The **FortiOS account is the primary authorization boundary.** An API user can do exactly what its
admin profile (accprofile), VDOM assignment and trusted hosts allow, whatever forti's settings are.
A profile's mode (`read-only`, the default; `guarded`; `autonomous`) is the operator's policy on top
of that boundary. It is stored in config.json, and the MCP server cannot change it. The modes, the
safeguards that apply in every mode that writes, and the limits of rollback plans and backups are in
[Planning and applying changes](/guides/planning-and-applying-changes#operating-modes).

**Recovery aids are not guaranteed recovery.** The rollback plan and the configuration backup both
need a working management path to the device. If a change cuts off management access, forti cannot
undo it. You need an independent path: the console port, an out-of-band management interface, or a
device-side automatic revert. Plan for that before letting an agent change critical settings.

A configuration backup holds the device's complete configuration, including FortiOS-encrypted
secrets, most of them reversible (see above). Treat it like a credential: keep the state directory on
an encrypted disk (FileVault or LUKS). forti keeps the **20 most recent** backups (by modification
time) and deletes older ones after each new backup. Copy any backup you want to keep longer somewhere
safe, and delete ones you no longer need (`rm ~/.local/state/forti/backups/<plan id>.conf`).

### Choosing autonomous mode

Autonomous mode suits a capable agent doing real administration where approving every plan would
defeat the purpose. With it, **the agent can do anything the FortiOS API account may do**, including
changes that cut off your own management access. The safeguards make changes visible and verified,
and reversible while the management path works, but they do not limit what may be changed. That
limit is the account:

- Give the API user an admin profile that grants only what the agent manages (for example
  read-write on firewall objects and policy, read-only on system). Avoid `super_admin`.
  `forti doctor` warns when an autonomous profile appears to use a super_admin-class account.
- Restrict the API user's trusted hosts to the machine the agent runs on.
- Use a VDOM-scoped account when the agent should manage only one VDOM.
- Keep an out-of-band path to the device (console or a separate admin account) when the agent may
  touch interfaces, routing or administrative access.

`guarded` is a middle ground: the agent prepares and validates changes and a person approves each
plan. `read-only` is the default and suits monitoring, auditing and planning.

### What a mode does and does not stop

A mode governs what the **forti-mcp tools** can do: nothing an MCP client sends can change a mode,
approve a plan, or apply a plan in a read-only profile. A mode is not a barrier against software
running as your user account. An agent that can also run shell commands as you (Claude Code's Bash
tool, Codex's shell) could run `forti plan approve` or `forti configure --mode autonomous`, or edit
`config.json` and the approval files, exactly as you can. forti uses no passphrase or
terminal-only approval, by design. For guarded mode to mean "a person approved this":

- keep the client's shell permission prompts on for `forti` commands, or deny them outright (Claude
  Code: `"permissions": {"deny": ["Bash(forti plan approve:*)", "Bash(forti configure:*)",
  "Bash(forti profile:*)"]}` in your settings);
- read the plan (`forti plan show <id>`, which `forti plan approve` prints first) before you approve it.

The installed agent skill tells agents never to approve plans or change modes, but that instruction
is not enforcement. The FortiOS account's privileges remain the boundary that holds in every case.
