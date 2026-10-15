# Command reference

```text
forti [global options] <command> [arguments]
```

Global options may come before or after the command.

| Option | Meaning |
|---|---|
| `-p, --profile NAME` | device profile (default: the default profile, or the only one) |
| `--vdom NAME` | VDOM for this request |
| `--json` | print the JSON result envelope (also `FORTI_OUTPUT=json`) |
| `--no-color` | plain text (also `NO_COLOR`; color is only used on a terminal) |
| `-h, --help` | help for forti or for a command (`forti help <command>` too) |
| `--version` | version and the FortiOS schema version of the models |

## Output

Text output is for people. Tables put the identifying column first (an object's key, such as
`policyid` or `name`), then the `--fields` you asked for in that order, and fit the terminal width.
FortiOS bookkeeping attributes such as `q_origin_key` are hidden in text output.

`--json` prints the stable envelope that scripts and forti-mcp share:

```json
{"ok": true, "data": [...], "meta": {"profile": "fw01", "resource": "firewall/policy", "start": 0, "returned": 50, "next_start": 50}}
{"ok": false, "error": {"code": "not_found", "message": "firewall/address \"x\" not found", "details": {"http_status": 404}}}
```

In text mode, errors go to standard error with a hint. In JSON mode, the envelope goes to standard
output. The exit status follows [the error code](exit-codes.md) in both modes.

## Setup

### configure

```text
forti configure
forti configure --profile NAME --host HOST [options] <credential>
```

Creates or updates a profile and verifies it with one read before saving. See
[configuration](configuration.md) for every option.

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
forti doctor [--profile NAME] [--json]
```

Ordered checks, each reported as `ok`, `warn`, `fail`, `skip` or `info`:

| Check | What it verifies |
|---|---|
| `config` | the configuration directory and config.json exist; file modes are private |
| `profile` | the selected profile loads and is valid |
| `secrets` | the API key (and certificate password) resolve. Values are never shown |
| `tls_files` | the CA bundle and client certificate exist and are readable; the bundle contains PEM |
| `connection` | DNS, TCP and TLS, through one read of `monitor/system/status` |
| `auth` | the device accepts the key (one attempt, never retried) |
| `version` | the device's FortiOS version against the SDK schema version (a mismatch is a warning) |
| `mode` | the operating mode. For autonomous profiles, also whether the account looks super_admin-class |
| `mcp` | whether `forti-mcp` is on PATH |

Later checks are skipped when an earlier one they depend on failed. The exit status is 0 when
nothing failed, otherwise the status of the first failure (3 for configuration, 4 for connection or
authentication). With `--json`, a failing run returns `ok: false` with the checks in
`error.details.checks`.

## Read

### devices

Lists profiles; the same as `forti profile list`.

### discover

```text
forti discover [search]          resources whose name contains `search`
forti discover <resource>        a resource's attributes, operations and risk tier
  --kind table|singleton|monitor   --fields a,b   --live   --start N --count N
```

### get

```text
forti get <resource> [key]
  --filter EXPR   --fields a,b   --start N   --count N   --param name=value   --reveal
```

Device secrets (`ENC ...` values, passwords, keys) print as `<redacted>`; `meta.redacted` lists
where. `--reveal` shows them to a person: it needs a terminal, or `--json`, and warns on stderr.

```sh
forti get firewall/policy --fields policyid,name,action,status
forti get firewall/address "LAN 10.0.0.0/24"
forti get monitor/system/status
```

## Changes and integrations

`forti plan`, `forti plan approve`, `forti apply` and `forti install mcp` are described by
`forti <command> --help`. Changes require a profile in `guarded` or `autonomous` mode; see
[security](security.md#operating-modes).
