# Project Forti: ecosystem architecture

Master notes for the `~/dev/forti` workspace. Contracts here bind every repository; changing one is an
architecture decision (the master orchestrator records it in `decisions.md`).

## Repositories

| Repo | Role | Ships |
|---|---|---|
| `forti-api/` (existing, `valkyrianlabs/forti-api`) | The **only** FortiOS implementation: transport, TLS/auth, generated 7.4.8 models, `Table`/`Singleton`/`Monitor`, schema access | `libforti-api-dev` (headers), Homebrew `forti-api` |
| `forti-cli/` (new) | `forti` executable **and** the internal command engine (`engine/`, Meson dependency `forti-engine`) | `forti-cli` package: `/usr/bin/forti` |
| `forti-mcp/` (new) | `forti-mcp` stdio MCP server: a thin adapter over the engine | `forti-mcp` package: `/usr/bin/forti-mcp` |

The parent workspace is not a repository. It holds these notes and cross-repo integration scripts.

## Dependency graph

```text
forti (CLI) ───────┐                      forti-mcp (stdio MCP) ───┐
  src/cli          │                        src/                   │
  src/install      ├── forti-engine (static, in-process) ◄─────────┘  (Meson subproject of forti-cli)
                   │     catalog · profiles · session · discover/read/plan/apply · approvals · audit
                   │
                   └── forti-api (header-only SDK) ── libcurl ── FortiOS REST v2
```

- **One engine, linked statically into both executables.** forti-mcp never spawns `forti`. No daemon
  and no IPC: the AI client launches `forti-mcp` over stdio on demand, and it exits with the client.
- **forti-mcp installs independently.** It depends on the engine *source* at build time, pinned as a
  subproject of forti-cli. It has no package-level runtime dependency on forti-cli. Each executable
  carries its own copy of the engine (about 10 MB). That is the cost of independent installability
  without a third shared-library package.
- `forti install mcp` (forti-cli) owns agent registration. forti-mcp works with a hand-written client
  entry, a source build, or embedding by another application.
- No new public library. `forti-engine` is not installed and has no ABI or API promise outside these
  two repos.

## forti-api owns FortiOS (enforced boundary)

The engine and front-ends never build URLs, set headers, touch TLS or curl, define FortiOS models,
or keep a resource list. They reach FortiOS only through:

| Need | SDK surface used |
|---|---|
| Resource catalog | `fortiapi::gen::for_each_endpoint` (487 cmdb) and `for_each_monitor` (47 typed monitor GETs) |
| Field structure | `T::visit(self, v)` → key, `Field<V>` type, reset value, `read_only` flag |
| Live schema (help, options, required, references) | `Table<Spec>::schema()` / `Singleton<Spec>::schema()` (`?action=schema`) |
| Reads | `fortiapi::Client::get(Spec::path / fortiapi::path(Spec::path, key), Query)`; `fortiapi::Monitor::get(relative, Query)` for any monitor GET |
| Writes | `from_json<T>`, `Field::operator=`/`clear()`, `Table::add/update/del`, `Singleton::update`, `to_json(obj, Write::…)` for the exact wire preview; `fortiapi::Monitor::post` for monitor actions |
| Connection | `fortiapi::Config` (built from a profile), `fortiapi::Client(Config[, Transport])` |
| Errors | `ApiError` (status, FortiOS code, CLI messages), `TransportError::before_send()`, `DecodeError` |

Reads return the device JSON as FortiOS sent it, through the SDK `Client`, instead of decoding and
re-serializing, with **device secrets redacted** (see "Read redaction" below). `to_json` omits read-only
attributes, so a round-trip would lose data (gap G2). Writes always go through the typed SDK objects,
so `Field<T>` semantics decide exactly what is sent.

Every device reply is checked iteratively for nesting depth (limit 256) before the engine copies it:
nlohmann's copy and `dump()` recurse, so a hostile reply could otherwise overflow the stack (gap G14).
Deeper replies fail with `api`.

### Read redaction (contract)

`Engine::read` replaces, at any depth, every string value starting with `ENC ` (FortiOS's reversible
secret form) and every non-empty value of an attribute that `detail::sensitive_name` marks as secret
with `"<redacted>"`. `meta.redacted` lists the locations as JSON pointers relative to `data`, with `*`
for array items (`["/*/psksecret"]`). This is the default for every caller. No request field turns it
off, so MCP cannot. Only the C++ argument `Engine::Secrets::reveal` disables it, and only the CLI's
`forti get --reveal` passes it (a terminal, or explicit `--json`, plus a stderr warning). Plan and apply
read the device separately and keep real values, so before-digests and drift checks use unredacted data.
`plan` refuses `"<redacted>"` as a value to write (`validation`).

### Compile-time sharding (no duplication)

Instantiating typed operations for all 487 endpoints in one TU measured 68–100 s and 4–5 GB RSS (Apple
clang 21). The engine compiles `engine/src/catalog_shard.cpp` N=8 times (`-DFORTI_SHARD=k`). Each copy
instantiates only the endpoints whose `constexpr fnv1a(E::path) % N == k`. Measured: 15 s wall, about
1.2 GB per TU. The registry stays the single source; shards only filter it.

## Engine contract (forti-engine)

Namespace `forti::engine`, headers in `forti-cli/engine/include/forti/engine/`. The public surface is
**JSON request → JSON result**, so the CLI (argv → request) and MCP (tool arguments → request) share
one validated contract. MCP `inputSchema`s mirror the request schemas below.

```cpp
class Engine {
public:
    explicit Engine(Options);                 // dirs, secret store, transport factory (tests), clock
    nlohmann::json discover(const nlohmann::json& request);
    nlohmann::json read(const nlohmann::json& request);
    nlohmann::json plan(const nlohmann::json& request);    // stores the plan, returns id + digest + diff
    nlohmann::json apply(const nlohmann::json& request);   // {plan_id}; requires a human approval record
};
// Errors: forti::engine::Failure (code, message, details JSON). Never contains secrets.
```

### Resource addressing

- `firewall/address` and `cmdb/firewall/address` both name the cmdb table. FortiOS-dotted paths
  (`firewall.service/custom`) are canonical. `monitor/system/status` names a monitor GET: typed when
  the SDK has a spec, untyped through `fortiapi::Monitor::get` otherwise.
- Table objects are addressed by `key` (string; numeric keys are parsed to the SDK key type). `.` and
  `..` are never keys: the SDK leaves '.' unescaped and libcurl removes dot segments, so
  `DELETE …/address/.` would address the whole table (gap G13). The engine rejects them in requests,
  created object names, stored plans and device-reported mkeys.

### Requests

```jsonc
// discover
{"what": "devices"}                                    // profiles, no secrets
{"what": "resources", "query": "addr", "kind": "table|singleton|monitor", "start": 0, "count": 50}
{"what": "resource", "resource": "firewall/address", "fields": ["name","type"], "live": false}
                                                       // live=true merges the device's ?action=schema (fetched per request)
{"what": "capabilities", "profile": "home"}            // device identity, version vs SDK schema version, mode

// read
{"resource": "firewall/address", "key": "LAN", "filter": ["type==ipmask"], "fields": ["name","subnet"],
 "start": 0, "count": 50, "vdom": "root", "profile": "home", "params": {"datasource": "1"}}
 // filter/fields field names are validated against the catalog; count is capped (default 50, max 1000)

// plan
{"profile": "home", "vdom": "root", "operations": [
  {"op": "create", "resource": "firewall/address", "object": {"name": "x", "subnet": "192.0.2.0 255.255.255.0"}},
  {"op": "update", "resource": "firewall/address", "key": "x", "set": {"comment": "c"}, "clear": ["color"]},
  {"op": "delete", "resource": "firewall/address", "key": "x"},
  {"op": "action", "resource": "monitor/system/external-resource/dynamic", "body": {}}]}

// apply
{"plan_id": "…"}            // nothing else is accepted: operations come from the stored plan
```

### Result envelope

```jsonc
{"ok": true, "data": …, "meta": {"profile": "home", "vdom": "root", "resource": "…",
  "start": 0, "count": 50, "returned": 50, "next_start": 50, "truncated": false}}
{"ok": false, "error": {"code": "not_found", "message": "…", "details": {…}}}
```

### Error codes and CLI exit codes

| code | meaning | exit |
|---|---|---|
| — | success | 0 |
| `internal` | bug or unexpected state | 1 |
| `usage` | bad arguments or request shape | 2 |
| `config` | missing or invalid profile, credentials or config file | 3 |
| `connection` | DNS, connect, TLS or timeout (`TransportError`) | 4 |
| `auth` | HTTP 401/403 | 4 |
| `not_found` | unknown object (404) | 5 |
| `unknown_resource` | path not in the catalog | 5 |
| `validation` | schema violation, unknown or read-only field, bad value | 6 |
| `api` | other FortiOS error (status, FortiOS code, cli_error) | 6 |
| `stale_plan` | device state changed since planning | 7 |
| `approval_required` | apply without a valid human approval | 7 |
| `policy_denied` | profile is read-only, or a risk tier needs an extra step | 7 |
| `partial_failure` | apply stopped part-way; the record says what happened | 8 |
| `management_connectivity_lost` | the management probe after a critical change failed; execution stopped | 8 |
| `outcome_unknown` | a mutation may have reached the device (`!before_send`) | 8 |

## Profiles and credentials

- One forti home (`Paths`, profile.hpp): `$FORTI_HOME`, else `~/.forti` (0700). It holds `config.json` and
  `credentials/`, `state/` (plans, approvals, audit log, backups), `cache/` (reserved) and
  `certs/<profile>/` (`forti cert create`). `$FORTI_CONFIG_DIR`, `$FORTI_STATE_DIR`, `$FORTI_CACHE_DIR`
  override single locations. A pre-0.2 setup (`$XDG_*_HOME/forti`, else `~/.config/forti`,
  `~/.local/state/forti`, `~/.cache/forti`) stays in use (`Paths::legacy`) while `~/.forti/config.json`
  does not exist; `forti home migrate` moves it. Never derived from the working directory.
- `config.json` (0600, dir 0700) holds profiles: host, port, vdom, ca_bundle, client_cert path,
  resolve_ip, timeouts, `mode` (default **read-only**), and a credential *reference*, never a secret.
- Secret sources, in order: OS store (macOS Keychain via Security.framework: service `forti`, account
  `<profile>/api-key`); file `credentials/<profile>.api-key` (0600); `env` (variable name stored, not
  the value); `command` (argv, git-credential style, stdin `/dev/null`, only fds 0-2 inherited); `file`
  (absolute path; first line; refused unless a regular file owned by the user with no group/other access,
  the file store's rules). The P12 password uses the same mechanism; `forti cert create` sets it to
  `file` `<home>/certs/<profile>/client.pass`, or with `--keychain` to the store.
- Stored secrets are **bound to the profile's `host:port`**: the Keychain item's `kSecAttrGeneric`, or the
  credential file's first line (`binding host:port`). `resolve_secret` refuses an unbound or
  differently bound secret (`config`, "…belongs to host:port; run forti configure"). This stops another
  config.json that reuses a profile name from sending the key elsewhere. `forti configure` writes the
  binding and re-binds a kept key when the host or port changes (so does `forti profile set`, only for a
  secret bound to the old address). env/command/file sources are unbound.
- config.json is refused when owned by another user or writable by group or others; the `FORTI_*_DIR`
  overrides must be absolute. Both executables set `RLIMIT_CORE` to 0 at startup.
- TLS verification is always on (the SDK hardcodes VERIFYPEER/VERIFYHOST=2). No flag disables it.
  Self-signed devices use `ca_bundle` or `resolve_ip`.
- forti's own credentials never appear in argv, output, logs, plans, audit records, MCP client config,
  or project files. Device secrets are redacted in reads, diffs, audit records and error details (stored
  plan files keep real values, 0600).

## Operating modes and mutation safety

**The FortiOS account's privileges are the primary authorization boundary.** A profile's `mode` is the
operator's policy on top of that boundary. It is chosen in `forti configure`, persists in config.json, and
cannot be changed through MCP:

| mode | plan | apply |
|---|---|---|
| `read-only` (default) | yes (preview and validation are reads) | refused: `policy_denied` |
| `guarded` | yes | only with a human approval of that plan's digest (`forti plan approve <id>`, CLI only) |
| `autonomous` | yes | yes, with no interactive approval; every safeguard below still applies |

There are no passphrases, TTY ceremonies or biometric prompts (maintainer decision). Autonomous mode
is meant for capable agents doing real administration. Its risks are documented plainly: the agent can
do anything the FortiOS API account may do.

Automatic safeguards (every mode that writes):

1. **Plan** validates every operation against the catalog and the SDK types (resource exists,
   operation supported, attributes known and writable, values decode). It reads the current objects
   and computes before/after, a field diff, the exact SDK wire body and the risk tier. The plan is
   stored at `state/plans/<id>.json` (0600). `digest` = SHA-256 over canonical JSON of {device
   identity, operations, before digests}. Planning never mutates the device.
2. **Apply** takes only `{plan_id}`. It recomputes the digest (tamper check) and checks the device
   serial, then re-reads every before-state (`stale_plan` on drift). It executes in order with no
   retries (the SDK never retries after send) and verifies each operation by re-reading. It stops at the
   first failure. Per-operation status: `verified | applied_unverified | failed | outcome_unknown |
   not_attempted`. Results are `partial_failure` / `outcome_unknown` with the full execution record. An
   HTTP failure is never assumed to mean "nothing changed".
3. **Recovery aids, not guaranteed recovery.**
   - Every apply writes a generated **rollback plan** (inverse operations from the recorded
     before-state).
   - Critical plans take a **pre-change config backup** through forti-api's raw download (G9
     upstream). It is stored only under `state/backups/` (0600 file, 0700 dir, never a shared temp
     dir), never logged, and never included in output. Only the 20 most recent `.conf` files (by mtime)
     are kept; older ones are deleted after each successful backup.
   - After each **critical**-risk operation, a fresh `fortiapi::Client` probes management
     connectivity (`monitor/system/status`). On failure, execution stops with
     `management_connectivity_lost`, the rollback plan id, the backup reference and the before-state.

   **Limitation, stated in docs and output:** the rollback plan and the backup both need a working
   management path to the device. They are not independent recovery. Forti never claims it can
   recover from a management lockout. That needs an independently executable mechanism (e.g. a
   device-side auto-revert) or a verified alternate management path (console, out-of-band
   interface), which the operator must provide.
4. **Audit and redaction.** Every apply is appended to `state/audit.jsonl` (0600). Before the first
   mutation, apply checks that the log can be opened for appending, and refuses with `config`
   (nothing sent) when it cannot. A write failure after execution is reported in the result
   (`audit_error`), never dropped. Sensitive attributes (passwords, PSKs, secrets, keys, tokens, `*-key`;
   plus the live schema's `password*` types) are redacted in reads, diffs, audit records and error
   details. Stored plan files keep real values because apply needs them, so they are 0600.
5. **Risk tiers** are reported by `discover` and `plan`:
   - `low`: objects inert unless referenced
   - `elevated`: policies, VIPs, users, VPN, most `system/*`, monitor actions not listed below
   - `critical`: management access, routing, interfaces, admins, HA, VDOMs, global settings; and the
     monitor actions that restart or reconfigure the device or cut a management path: `system/os/*`
     (reboot, shutdown), `system/config/restore|reload|revert`, `system/config-revision/*`,
     `system/firmware/*`, `system/factory-reset`, `system/change-password`,
     `system/admin/change-vdom-mode`, `system/disconnect-admins/*`, `system/ha-*`, `system/interface/*`,
     `system/vmlicense/*`, `system/certificate/*`, `vpn/ike/clear`, `vpn/ssl/delete`,
     `firewall/session/close-all` (list in `engine/src/policy.cpp`)

   Tiers drive the connectivity probe (critical monitor actions included), the pre-change backup and
   the audit emphasis, not interactive gates.

Discovering a capability never authorizes it. Execution policy is the profile mode plus the FortiOS
account.

## MCP surface (forti-mcp)

Four tools, mirroring the engine: `forti_discover`, `forti_read`, `forti_plan`, `forti_apply`.
In guarded mode `forti_apply` returns `approval_required` with the exact `forti plan approve <id>`
command for the human. In autonomous mode it executes. MCP can never change the mode or approve. Responses are bounded (default 50 items and 48 KiB of JSON, with `next_start` continuation).
Field schemas are returned selectively (`fields`). No arbitrary SSH/CLI execution, ever: REST only.
Protocol: JSON-RPC 2.0 over stdio, newline-delimited, dual-era. MCP `2026-07-28` is served
statelessly (per-request `_meta` protocol version and client capabilities; `server/discover`,
`tools/list`, `tools/call`); the `initialize` lifecycle of `2025-11-25` / `2025-06-18` (with `ping`) is
kept for clients that still use it. No JSON-RPC batches. stdout carries protocol only; logs go to
stderr without secrets.
