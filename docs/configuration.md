# Configuration

`forti` keeps one or more **profiles**, each describing how to reach one FortiGate. A profile holds
connection settings and a *reference* to its API key, never the key itself.

## Creating a profile

Interactively (prompts appear on the terminal, the API key is typed with echo off):

```sh
forti configure
```

Non-interactively (scripts, provisioning):

```sh
# The key comes from standard input and is kept in the secret store.
op read op://ops/fw01/api-key | forti configure --profile fw01 --host fw01.example.net \
    --ca-bundle ~/certs/fw01-ca.pem --api-key-stdin --default

# The key stays in an environment variable; only the variable's name is saved.
forti configure --profile lab --host 192.0.2.10 --port 8443 --api-key-env FORTI_LAB_KEY

# The key is printed by a command (run without a shell; quotes group words).
forti configure --profile edge --host edge.example.net --api-key-command "pass show fortigate/edge"
```

`forti configure` checks the profile against the device with one read (`monitor/system/status`)
before it saves anything. If the check fails, nothing is written. An authentication failure is
**never retried**, because FortiOS locks an API user out after a few failed attempts. Pass
`--skip-check` to save without contacting the device (for example while it is offline).

Running `forti configure --profile NAME` with some options updates an existing profile: options that
are not given keep their current values.

| Option | Meaning |
|---|---|
| `--profile NAME` | profile name: letters, digits, `-` and `_` (required with other options) |
| `--host HOST` | host name or address. No scheme and no port: `fw.example.net`, `192.0.2.1`, `[2001:db8::1]` |
| `--port N` | admin HTTPS port (default 443) |
| `--vdom NAME` | VDOM for every request (default: the device's default VDOM) |
| `--ca-bundle PATH` | PEM file of CA certificates that verify the device's certificate |
| `--resolve-ip IP` | connect to this address, while still verifying the certificate for `--host` |
| `--client-cert PATH` | PKCS#12 client certificate, when the device requires one |
| `--api-key-stdin` / `--api-key-env VAR` / `--api-key-command CMD` | where the API key comes from (exactly one) |
| `--cert-password-stdin` / `--cert-password-env VAR` / `--cert-password-command CMD` | the client certificate's password |
| `--mode MODE` | `read-only` (default), `guarded` or `autonomous` (see [Operating modes](security.md#operating-modes)) |
| `--default` | make this the default profile |
| `--skip-check` | save without the verification read |

Paths are stored as absolute paths, so later commands do not depend on the working directory.

## Credential sources

An API key is never accepted as an argument value, because argument lists are visible to other
users and end up in shell history. It comes from one of these sources:

| Source | Stored in config.json | Where the secret lives |
|---|---|---|
| secret store (`--api-key-stdin`, or typed at the prompt) | `{"source": "store"}` | macOS: the login Keychain, service `forti`, account `<profile>/api-key`. Elsewhere: `<config>/credentials/<profile>.api-key`, mode 0600 |
| environment (`--api-key-env VAR`) | `{"source": "env", "env": "VAR"}` | the variable, read on every use |
| command (`--api-key-command CMD`) | `{"source": "command", "command": [argv…]}` | whatever the command reads; its first line of output is the key |

A client certificate password uses the same sources, under the account `<profile>/cert-password`.

`FORTI_SECRET_STORE=file` selects the 0600 file store on macOS too, for example on a Mac reached over
SSH where the login keychain is locked. `FORTI_SECRET_STORE=keychain` asks for the Keychain
explicitly. Use the same setting for configuring and for running commands. On Linux the file store is
the default; a Secret Service (libsecret) backend may come later.

### macOS Keychain notes

- The item belongs to the application that created it. Another binary, such as `forti-mcp`, or
  `forti` after an upgrade, triggers a one-time macOS prompt. Choose **Always Allow**.
- Without a GUI session (SSH, launchd jobs) macOS cannot show that prompt and a locked keychain
  cannot be unlocked interactively. forti reports this as a configuration error with a hint. Unlock
  with `security unlock-keychain`, or use `--api-key-env` / `--api-key-command` or
  `FORTI_SECRET_STORE=file`.
- Inspect or delete items in Keychain Access by searching for `forti`.

## TLS

Certificate verification is always on, and no option disables it. A FortiGate with a self-signed
or private-CA certificate needs one of:

- `--ca-bundle PATH`: export the device's CA certificate (or its self-signed certificate) as PEM and
  point the profile at it.
- `--resolve-ip IP`: when the certificate names a host (`fw01.example.net`) that does not resolve
  from where you are, keep that name as `--host` and connect to the address with `--resolve-ip`.
  The certificate is still checked against the name.

`forti doctor` tells a DNS failure, a refused connection, a timeout and an untrusted certificate
apart, and suggests the matching fix.

## Managing profiles

```sh
forti profile list                 # also: forti devices
forti profile show [NAME]          # settings and where the key comes from (never the key)
forti profile default NAME
forti profile mode [NAME] guarded  # read-only | guarded | autonomous
forti profile remove NAME          # deletes the profile and its stored secrets
```

Commands use the profile named by `--profile`/`-p`, else the default profile, else the only profile.

## File locations

Nothing depends on the working directory.

| What | Location |
|---|---|
| configuration | `$FORTI_CONFIG_DIR`, else `$XDG_CONFIG_HOME/forti`, else `~/.config/forti` (macOS included) |
| `config.json` | `<config>/config.json`, mode 0600, directory 0700 |
| file secret store | `<config>/credentials/`, files 0600, directory 0700 |
| state (plans, approvals, audit log) | `$FORTI_STATE_DIR`, else `$XDG_STATE_HOME/forti`, else `~/.local/state/forti` |
| cache (live schemas) | `$FORTI_CACHE_DIR`, else `$XDG_CACHE_HOME/forti`, else `~/.cache/forti` |

### config.json

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
    }
  }
}
```

Optional per-profile keys: `resolve_ip`, `client_cert`, `cert_password`, `connect_timeout_ms`
(default 5000) and `timeout_ms` (default 30000). A config file that contains a secret value
(`token`, `password`, `api_key_value`) is rejected.

## Environment

| Variable | Effect |
|---|---|
| `FORTI_CONFIG_DIR`, `FORTI_STATE_DIR`, `FORTI_CACHE_DIR` | override the directories above |
| `FORTI_SECRET_STORE` | `file` or `keychain` |
| `FORTI_OUTPUT=json` | always print the JSON envelope (same as `--json`) |
| `NO_COLOR` | no ANSI color (color is used only when the output is a terminal) |
