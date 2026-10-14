# Security notes

## What is stored where

| Data | Where | Protection |
|---|---|---|
| Profiles (host, port, VDOM, paths, mode, credential *reference*) | `config.json` | 0600 file in a 0700 directory. No secrets: a config file containing one is rejected |
| API keys and certificate passwords (secret-store source) | macOS: login Keychain (service `forti`). Elsewhere: `credentials/` | Keychain ACL; or 0600 files that forti refuses to read when group or others can access them |
| API keys (env / command source) | not stored | only the variable name or the command's argv is saved |
| Plans, approvals, audit log | state directory | 0600 |
| Pre-change configuration backups (critical plans) | `state/backups/<plan id>.conf` | 0600 file in a 0700 directory, streamed to disk (never buffered whole), never logged or printed |

Secrets never appear in arguments, output, logs, plans, audit records, error messages or the MCP
client configuration. `forti profile show` and `forti doctor` report where a key comes from and
whether it resolves, never its value. `forti configure` refuses a key as an argument value.

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
A profile's mode is the operator's policy on top of that boundary. You choose it with
`forti configure --mode` or `forti profile mode`. It is stored in config.json, and the MCP server
cannot change it.

| Mode | Plans | Applying changes |
|---|---|---|
| `read-only` (default) | can be created to preview and validate changes | refused |
| `guarded` | yes | only after a person approves that exact plan with `forti plan approve <id>` |
| `autonomous` | yes | without interactive approval |

These safeguards apply in every mode that writes, autonomous included:

- validation against the catalog and SDK types before anything is sent;
- a drift check: apply refuses a plan whose objects changed since it was made;
- execution in order without retries, stopping at the first failure, with each change verified by
  re-reading it;
- a generated rollback plan and an audit record (`audit.jsonl`) for every apply;
- before a critical-risk plan (management access, routing, interfaces, admins, HA, VDOMs, global
  settings), a full configuration backup. If the backup cannot be taken, the plan does not run.
  The profile setting `"backup_before_critical": false` turns this off;
- after each critical-risk change, a fresh connection probe that stops execution if management
  connectivity is lost.

**Recovery aids are not guaranteed recovery.** The rollback plan and the configuration backup both
need a working management path to the device. If a change cuts off management access, forti cannot
undo it. You need an independent path: the console port, an out-of-band management interface, or a
device-side automatic revert. Plan for that before letting an agent change critical settings.

A configuration backup holds the device's complete configuration, including FortiOS-encrypted
secrets. Treat it like a credential: keep the state directory on an encrypted disk (FileVault or
LUKS), and delete backups you no longer need (`rm ~/.local/state/forti/backups/<plan id>.conf`).

### Choosing autonomous mode

Autonomous mode suits a capable agent doing real administration where approving every plan would
defeat the purpose. With it, **the agent can do anything the FortiOS API account may do**, including
changes that cut off your own management access. The safeguards above make changes visible
and verified, and reversible while the management path works, but they do not limit what may be
changed. That limit is the account:

- Give the API user an admin profile that grants only what the agent manages (for example
  read-write on firewall objects and policy, read-only on system). Avoid `super_admin`.
  `forti doctor` warns when an autonomous profile appears to use a super_admin-class account.
- Restrict the API user's trusted hosts to the machine the agent runs on.
- Use a VDOM-scoped account when the agent should manage only one VDOM.
- Keep an out-of-band path to the device (console or a separate admin account) when the agent may
  touch interfaces, routing or administrative access.

`guarded` is a middle ground: the agent prepares and validates changes and a person approves each
plan. `read-only` is the default and suits monitoring, auditing and planning.
