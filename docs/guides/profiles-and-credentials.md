---
title: Profiles and credentials
description: Create and manage device profiles, choose where the API key comes from, and set up TLS.
order: 30
status: published
tags:
  - guides
---

# Profiles and credentials

forti keeps one or more **profiles**, each describing how to reach one FortiGate. A profile holds
connection settings, an operating mode and a *reference* to its API key, never the key itself.
Commands use the profile named by `--profile`/`-p`, else the default profile, else the only one.

:::toc[On this page]{depth="3" theme="compact"}
:::

## Creating a profile

Interactively (prompts on the terminal; the API key is typed with echo off):

```sh
forti configure                      # asks for the profile name too
forti configure --profile fw01       # creates or edits fw01, prompting for the rest
```

Each prompt shows the current value in brackets; Enter keeps it, and `-` clears an optional value.
If the connection check fails at the terminal for a network reason, forti offers to save the profile
anyway, so a typed key is not lost.

Non-interactively (scripts, provisioning), with `--profile` and any option other than `--skip-check`.
Pick where the API key comes from:

:::tabs{
  default="stdin"
  theme="glass"
  tabTheme="muted"
}

:::tab[Secret store]{value="stdin"}
The key comes from standard input and is kept in the secret store.

```sh
op read op://ops/fw01/api-key | forti configure --profile fw01 --host fw01.example.net \
    --ca-bundle ~/certs/fw01-ca.pem --api-key-stdin --default
```
:::

:::tab[Environment variable]{value="env"}
The key stays in an environment variable; only the variable's name is saved.

```sh
forti configure --profile lab --host 192.0.2.10 --port 8443 --api-key-env FORTI_LAB_KEY
```
:::

:::tab[Command]{value="command"}
The key is printed by a command (run without a shell; quotes group words).

```sh
forti configure --profile edge --host edge.example.net --api-key-command "pass show fortigate/edge"
```
:::

:::

Before saving, `forti configure` checks the profile with one read of `monitor/system/status`. If the
check fails, nothing is written. `--skip-check` saves without contacting the device (for example
while it is offline).

:::callout[Authentication failures are never retried]{variant="warning"}
FortiOS locks an API user out after a few failed attempts, so `forti configure` makes one attempt
and stops on a rejected key.
:::

Running `forti configure --profile NAME` with options updates an existing profile: options that are
not given keep their current values. A new profile needs `--host` and an API key source.

| Option | Meaning |
|---|---|
| `--profile NAME` | profile name: 1 to 64 letters, digits, `-` and `_` (required with other options) |
| `--host HOST` | host name or address. No scheme and no port: `fw.example.net`, `192.0.2.1`, `[2001:db8::1]` |
| `--port N` | admin HTTPS port, 1 to 65535 (default 443) |
| `--vdom NAME` | VDOM for every request (default: the device's default VDOM) |
| `--ca-bundle PATH` | PEM file of CA certificates that verify the device's certificate |
| `--resolve-ip IP` | connect to this IPv4 or IPv6 address, while still verifying the certificate for `--host` |
| `--client-cert PATH` | PKCS#12 client certificate, when the device requires one |
| `--api-key-stdin` / `--api-key-env VAR` / `--api-key-command CMD` | where the API key comes from (exactly one) |
| `--cert-password-stdin` / `--cert-password-env VAR` / `--cert-password-command CMD` | the client certificate's password (needs `--client-cert`) |
| `--mode MODE` | `read-only` (default), `guarded` or `autonomous` (see [Operating modes](/guides/planning-and-applying-changes#operating-modes)) |
| `--default` | make this the default profile |
| `--skip-check` | save without the verification read |

Paths are checked for readability and stored as absolute paths, so later commands do not depend on
the working directory. Standard input carries only one secret: with `--api-key-stdin`, take the
certificate password from `--cert-password-env` or `--cert-password-command`. The first profile you
create becomes the default.

:::callout[Autonomous mode]{variant="warning"}
Choosing `autonomous` prints a notice of what that mode allows. Read
[Choosing autonomous mode](/reference/security#choosing-autonomous-mode) first.
:::

## Credential sources

An API key is never accepted as an argument value, because argument lists are visible to other
users and end up in shell history. It comes from one of these sources:

| Source | Stored in config.json | Where the secret lives |
|---|---|---|
| secret store (`--api-key-stdin`, or typed at the prompt) | `{"source": "store"}` | macOS: the login Keychain, service `forti`, account `<profile>/api-key`. Elsewhere: `<config>/credentials/<profile>.api-key`, mode 0600 |
| environment (`--api-key-env VAR`) | `{"source": "env", "env": "VAR"}` | the variable, read on every use |
| command (`--api-key-command CMD`) | `{"source": "command", "command": [argv...]}` | whatever the command reads; the first line of its output is the key |

A client certificate password uses the same sources, under the account `<profile>/cert-password`.

A credential command runs on every use, without a shell (found on `PATH`), with standard input from
`/dev/null`. Its standard error reaches you, so a password manager can ask to be unlocked on the
terminal. It must exit with status 0.

:::callout[Stored keys are bound to their device]{variant="info"}
A stored key is bound to the profile's `host:port`. forti releases it only to a profile that still
points there, so another `config.json` that reuses the profile name cannot send your key to a
different host. `forti configure` writes the binding and re-binds a kept key when you change the
host or port. Keys from the environment or a command are not stored, so they are not bound. See
[Security notes](/reference/security#stored-keys-are-bound-to-their-device).
:::

`FORTI_SECRET_STORE=file` selects the 0600 file store on macOS too, for example on a Mac reached over
SSH where the login keychain is locked. `FORTI_SECRET_STORE=keychain` asks for the Keychain
explicitly. Use the same setting for configuring and for running commands. On Linux the file store is
the default.

### macOS Keychain notes

- The item belongs to the application that created it. Another binary, such as `forti-mcp`, or
  `forti` after an upgrade, triggers a one-time macOS prompt. Choose **Always Allow**.
- Without a GUI session (SSH, launchd jobs) macOS cannot show that prompt, and a locked keychain
  cannot be unlocked interactively. forti reports this as a configuration error with a hint. Unlock
  with `security unlock-keychain`, or use `--api-key-env`, `--api-key-command` or
  `FORTI_SECRET_STORE=file`.
- Inspect or delete items in Keychain Access by searching for `forti`.

## TLS

:::callout[Verification is always on]{variant="info"}
Certificate verification is always on, and no option, environment variable or config key disables
it.
:::

A FortiGate with a self-signed or private-CA certificate needs one of:

- `--ca-bundle PATH`: export the device's CA certificate (or its self-signed certificate) as PEM and
  point the profile at it.
- `--resolve-ip IP`: when the certificate names a host (`fw01.example.net`) that does not resolve
  from where you are, keep that name as `--host` and connect to the address with `--resolve-ip`.
  The certificate is still checked against the name.

`forti configure` and `forti doctor` tell a DNS failure, a refused connection, a timeout, an untrusted
certificate and a failed handshake apart, and suggest the matching fix.

## Managing profiles

```sh
forti profile list                 # also: forti profile, forti devices; the default is marked *
forti profile show [NAME]          # settings and where the key comes from (never the key)
forti profile default NAME
forti profile mode [NAME] guarded  # read-only | guarded | autonomous
forti profile remove NAME          # deletes the profile and its stored secrets
```

- `profile show` reports the key's source and, for the secret store, whether a key is stored and
  bound to this host and port (`api_key_stored`, `api_key_bound`); for an environment source,
  whether the variable is set (`api_key_set`).
- `profile mode` without a name changes the selected profile (`--profile`, else the default).
- `profile remove` deletes the stored secrets first; if the secret store refuses (a locked
  keychain), the profile stays so you can remove it later. When the default profile is removed and
  exactly one profile remains, that one becomes the default. Removing a profile never contacts the
  device.

## Checking a profile

```sh
forti doctor [--profile NAME]
```

Ordered checks, each reported as `ok`, `warn`, `fail`, `skip` or `info`:

| Check | What it verifies |
|---|---|
| `config` | the configuration directory and config.json exist; the files are private (credential files readable by others fail, loose directory or config modes warn) |
| `profile` | the selected profile loads and is valid |
| `secrets` | the API key (and certificate password) resolve. Values are never shown |
| `tls_files` | the CA bundle and client certificate exist and are readable; the bundle contains a PEM certificate |
| `connection` | DNS, TCP and TLS, through one read of `monitor/system/status` |
| `auth` | the device accepts the key (one attempt, never retried) |
| `version` | the device's FortiOS version against the SDK schema version (a mismatch is a warning: reads work, attributes added or removed between versions may be missing or rejected in plans) |
| `mode` | the operating mode |
| `privileges` | autonomous profiles only: whether the account looks super_admin-class (read from `system/api-user`) |
| `mcp` | whether `forti-mcp` is on `PATH` (information only) |

Later checks are skipped when an earlier one they depend on failed. The exit status is 0 when
nothing failed, otherwise that of the first failure (3 for configuration, 4 for connection or
authentication). With `--json`, a failing run returns `ok: false` with the checks in
`error.details.checks`.

Where profiles, secrets, plans and caches are stored: [Configuration files](/reference/configuration-files).
