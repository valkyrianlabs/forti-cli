---
title: Profiles and credentials
description: One profile per FortiGate - create the first, add, edit, rename and copy more, choose where each API key comes from, and check them with forti doctor.
order: 30
status: published
tags:
  - guides
---

# Profiles and credentials

forti keeps one **profile** per FortiGate. A profile holds how to reach the device (host, port, VDOM,
TLS files), its operating mode and a *reference* to its API key, never the key itself. All profiles
live in one file, `~/.forti/config.json` in the [forti home](/reference/configuration-files#the-forti-home),
so managing ten firewalls is the same as managing one.

:::toc[On this page]{depth="3" theme="compact"}
:::

## Your first profile

```sh
forti configure
```

forti asks for:

1. **The address**: `fw.example.net`, `192.0.2.1:8443`, `[2001:db8::1]:8443` or an https URL.
2. **The API key**, typed with echo off and kept in the secret store. Type `env:VARIABLE` or
   `cmd:COMMAND` instead to read it from a variable or a password manager on every use. No key yet?
   Answer **n** to *Do you have a REST API key?* and forti prints the FortiOS commands that create a
   REST API admin and its key.
3. **A [client certificate](/guides/client-certificates)**, optional: it reuses one or makes one, and
   prints the FortiGate commands.
4. **The [operating mode](/guides/planning-and-applying-changes#operating-modes)**.

It then checks the connection with one read of `monitor/system/status`. When the device has several
VDOMs, it asks which one the profile uses. Last, it asks for the profile's name, offering the device's
host name. The first profile becomes the default.

If the check fails, forti says why once, keeps every answer, and offers what fits: type the key again,
change the address, give a CA bundle (a self-signed device), connect to an IP address while checking
the certificate for the name, save without checking, or quit. Nothing is saved until the check passes
or you choose to save. `--advanced` also asks for the VDOM, CA bundle and connect-to address up front.

:::callout[Authentication failures are never retried]{variant="warning"}
FortiOS locks an API user out after a few failed attempts, so `forti configure` makes one attempt and
stops on a rejected key. Check the key, the API user's trusted hosts and its admin profile first.
:::

Non-interactively (scripts, provisioning), pass `--host` and the settings, and `--profile` once a
profile exists (the first one is named `default` without it). Pick where the API key comes from:

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

`--skip-check` saves without contacting the device (for example while it is offline).

## Several FortiGates

Every command works on one profile: the one named by `--profile`/`-p`, else the default profile, else
the only one.

```sh
forti devices                                  # every profile; the default is marked *
forti -p fw02 get monitor/system/status
forti get firewall/policy --profile branch-ber --fields policyid,name,action
forti profile default fw02                     # change which one commands use by default
```

### Add another device

Most FortiGates in a fleet share settings: mode, VDOM, timeouts, a client certificate. Start the new
profile from an existing one: forti then asks only for the address and the key.

```sh
forti configure --like fw01
```

At the terminal, `forti configure` offers the same: *Start from fw01's settings?* (from the default
profile). The client certificate comes along when it is one of forti's; the API key and the device's
address never do. Scripts use `--like` with `--host` and a key option.

To copy settings without contacting any device, use `profile copy`, then give the copy its key:

```sh
forti profile copy fw01 fw02                   # settings only: no API key, no client certificate
forti profile set fw02 host=fw02.example.net
forti configure --profile fw02                 # prompts, prefilled from fw02; type fw02's key
```

`profile copy` never copies the API key or the client certificate and its password: they belong to the
source device. It does copy everything else, including `resolve_ip` and `ca_bundle`, so check that
those fit the new device (`forti profile show fw02`). To give the new device a client certificate,
reuse one with `forti cert use fw01 --profile fw02`, or choose one in `forti configure --profile fw02`
([Client certificates](/guides/client-certificates)).

### Change settings

`forti profile set` changes settings without prompts and without contacting the device:

```sh
forti profile set fw02 host=fw02.example.net port=8443
forti profile set lab vdom=root timeout_ms=60000
forti profile set lab vdom=                    # an empty value restores the default
```

| Key | Value |
|---|---|
| `host` | host name or address, without scheme or port |
| `port` | admin HTTPS port, 1 to 65535 |
| `vdom` | VDOM for every request |
| `ca_bundle` | PEM CA bundle (checked for readability, stored as an absolute path) |
| `client_cert` | PKCS#12 client certificate; clearing it (`client_cert=`) also clears its password |
| `resolve_ip` | connect to this IPv4 or IPv6 address while verifying TLS for `host` |
| `connect_timeout_ms`, `timeout_ms` | 1 to 3600000 |
| `backup_before_critical` | `true` or `false` |
| `mode` | `read-only`, `guarded` or `autonomous` |

Values are checked exactly as `config.json` is when it loads. Secrets are not settings: an API key or a
password goes through `forti configure`. Changing `host` or `port` re-binds the profile's stored
secrets to the new address (only secrets bound to the old address; see
[Stored keys are bound to their device](#stored-keys-are-bound-to-their-device)).

To change settings *and* check them against the device, or to change where the key comes from, run
`forti configure --profile NAME`. On an existing profile, every prompt starts from the current value
(including an API key command), and Enter keeps it. With options instead of prompts, only the
options you give change:

```sh
forti configure --profile fw01 --port 8443     # checks the device, keeps everything else
```

### Rename a profile

```sh
forti profile rename lab fw-lab
```

The rename takes everything along: stored secrets (Keychain or file store) move to the new name and
stay bound to the same device, a certificate named after the profile (`~/.forti/certs/lab/`) moves to
`certs/fw-lab/` with every profile path that pointed into it, and the default follows. The certificate
keeps its CN (`forti-lab`), so the FortiGate needs no change. Plans made before the rename name the old profile:
plan them again.

### Remove a profile

```sh
forti profile remove fw-lab
```

`remove` deletes the profile's stored secrets first; if the secret store refuses (a locked keychain),
the profile stays so you can remove it later. When the default profile is removed and exactly one
profile remains, that one becomes the default. Removing a profile never contacts the device, and it
does not delete its certificate, which other profiles may use (`forti cert remove NAME`).

### Several devices and AI agents

forti-mcp reads the same profiles. An agent lists them with `forti_discover {"what": "devices"}` and
names one in each call, so one registration covers every FortiGate, each under its own mode. To pin
forti-mcp to one profile, register it with `forti mcp install --profile NAME`; see
[AI agent integration](/guides/ai-agent-integration).

## Profile commands

```sh
forti profile list                 # also: forti profile, forti devices
forti profile show [NAME]          # settings and where the key comes from (never the key)
forti profile set NAME key=value...
forti profile rename OLD NEW
forti profile copy SOURCE NEW
forti profile default NAME
forti profile mode [NAME] guarded  # read-only | guarded | autonomous
forti profile remove NAME
```

- `profile show` reports the key's source and, for the secret store, whether a key is stored and
  bound to this host and port (`api_key_stored`, `api_key_bound`); for an environment source, whether
  the variable is set (`api_key_set`).
- `profile mode` without a name changes the selected profile (`--profile`, else the default).
- No profile command contacts the device.

## configure options

| Option | Meaning |
|---|---|
| `--profile NAME` | profile name: 1 to 64 letters, digits, `-` and `_` (scripts: required once a profile exists; the first is `default`) |
| `--host ADDRESS` | host name or address, optionally with the port or as an https URL: `fw.example.net`, `192.0.2.1:8443`, `[2001:db8::1]:8443` |
| `--port N` | admin HTTPS port, 1 to 65535 (default 443) |
| `--like PROFILE` | start a new profile from `PROFILE`'s mode, VDOM, timeouts and client certificate |
| `--advanced` | at the terminal, also ask for the VDOM, CA bundle and connect-to address |
| `--vdom NAME` | VDOM for every request (default: the device's default VDOM) |
| `--ca-bundle PATH` | PEM file of CA certificates that verify the device's certificate |
| `--resolve-ip IP` | connect to this IPv4 or IPv6 address, while still verifying the certificate for `--host` |
| `--cert NAME` | one of forti's [client certificates](/guides/client-certificates) (`forti cert list`), with its password |
| `--client-cert PATH` | a PKCS#12 client certificate of your own, when the device requires one |
| `--api-key-stdin` / `--api-key-env VAR` / `--api-key-command CMD` | where the API key comes from (exactly one) |
| `--cert-password-stdin` / `--cert-password-env VAR` / `--cert-password-command CMD` / `--cert-password-file PATH` | the client certificate's password (needs a client certificate) |
| `--mode MODE` | `read-only` (default), `guarded` or `autonomous` |
| `--default` | make this the default profile |
| `--skip-check` | save without the verification read |

A new profile needs `--host` and an API key source. Paths are checked for readability and stored as
absolute paths, so later commands do not depend on the working directory. Standard input carries only
one secret: with `--api-key-stdin`, take the certificate password from another source.

:::callout[Autonomous mode]{variant="warning"}
Choosing `autonomous` prints a notice of what that mode allows. Read
[Choosing autonomous mode](/reference/security#choosing-autonomous-mode) first.
:::

## Credential sources

An API key is never accepted as an argument value, because argument lists are visible to other
users and end up in shell history. It comes from one of these sources:

| Source | Stored in config.json | Where the secret lives |
|---|---|---|
| secret store (`--api-key-stdin`, or typed at the prompt) | `{"source": "store"}` | macOS: the login Keychain, service `forti`, account `<profile>/api-key`. Elsewhere: `~/.forti/credentials/<profile>.api-key`, mode 0600 |
| environment (`--api-key-env VAR`) | `{"source": "env", "env": "VAR"}` | the variable, read on every use |
| command (`--api-key-command CMD`) | `{"source": "command", "command": [argv...]}` | whatever the command reads; the first line of its output is the key |
| file (`--cert-password-file PATH`) | `{"source": "file", "path": "/abs/path"}` | a file only you can read; its first line is the secret |

A client certificate password uses the same sources, under the account `<profile>/cert-password`. The
`file` source has a `forti configure` option for the certificate password only (forti's own
certificates use it for `client.pass`); in `config.json` it works for the API key as well. A file source must be a regular file,
not a symbolic link, owned by you, with no access for group or others (`chmod 600`).

A credential command runs on every use, without a shell (found on `PATH`), with standard input from
`/dev/null`. Its standard error reaches you, so a password manager can ask to be unlocked on the
terminal. It must exit with status 0.

### Stored keys are bound to their device

A key in the secret store is bound to the profile's `host:port`. forti releases it only to a profile
that still points there, so another `config.json` that reuses the profile name cannot send your key to
a different host. `forti configure` writes the binding, and both `forti configure` and
`forti profile set` re-bind a kept key when you change the host or port. Keys from the environment, a
command or a file are not stored, so they are not bound. See
[Security notes](/reference/security#stored-keys-are-bound-to-their-device).

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

### Trust on first use

Most FortiGates present a self-signed or factory certificate, which no trust store knows. At the
terminal, `forti configure` looks at the certificate right after you give the address, before
anything else is sent. It connects, completes the TLS handshake and stops: no request, no API key.
When the certificate does not verify, forti shows it and asks:

```text
The certificate of 192.0.2.1 is not trusted (SSL certificate problem: self-signed certificate).
  subject   CN = FGT60FTK20000000
  issuer    CN = FGT60FTK20000000 (self-signed)
  names     (none)
  expires   2032-04-01T10:00:00Z
  SHA-256   3B:7E:…:C2
Trust this certificate for this FortiGate? (y/N):
```

Compare the fingerprint with the one the FortiGate shows (System, Certificates) if you can. A yes
saves that exact certificate in `~/.forti/tls/` and makes it the profile's CA bundle: forti then
verifies the FortiGate against it on every request, and refuses any other certificate. When the
certificate names something other than what you typed (a factory certificate names the serial
number), forti offers to connect to the address and verify the certificate for its own name
(`resolve_ip`). After a TLS failure, the recovery menu offers the same choice.

### Other ways

- `--ca-bundle PATH`: export the device's CA certificate (or its self-signed certificate) as PEM and
  point the profile at it.
- `--resolve-ip IP`: when the certificate names a host (`fw01.example.net`) that does not resolve
  from where you are, keep that name as `--host` and connect to the address with `--resolve-ip`.
  The certificate is still checked against the name.

`forti configure` and `forti doctor` tell a DNS failure, a refused connection, a timeout, an untrusted
certificate and a failed handshake apart, and suggest the matching fix.

For a FortiGate that should also require a client certificate from forti, see
[Client certificates](/guides/client-certificates).

## Checking a profile

```sh
forti doctor [--profile NAME]
```

Ordered checks, each reported as `ok`, `warn`, `fail`, `skip` or `info`:

| Check | What it verifies |
|---|---|
| `home` | the forti home; a pre-0.2 setup is a warning, with `forti home migrate` as the fix ([Configuration files](/reference/configuration-files#pre-0-2-setups)) |
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
`error.details.checks`. Run it once per device: `forti doctor -p fw02`.

Where profiles, secrets, certificates and plans are stored: [Configuration files](/reference/configuration-files).
