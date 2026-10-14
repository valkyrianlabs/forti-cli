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
re-serializing. `to_json` omits read-only attributes, so a round-trip would lose data (gap G2). Writes
always go through the typed SDK objects, so `Field<T>` semantics decide exactly what is sent.

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
- Table objects are addressed by `key` (string; numeric keys are parsed to the SDK key type).

### Requests

```jsonc
// discover
{"what": "devices"}                                    // profiles, no secrets
{"what": "resources", "query": "addr", "kind": "table|singleton|monitor", "start": 0, "count": 50}
{"what": "resource", "resource": "firewall/address", "fields": ["name","type"], "live": false}
                                                       // live=true merges device ?action=schema (cached per FortiOS version)
{"what": "capabilities", "profile": "home"}            // device identity, version vs SDK schema version, writes allowed?

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
| `outcome_unknown` | a mutation may have reached the device (`!before_send`) | 8 |

## Profiles and credentials

- Config dir: `$FORTI_CONFIG_DIR`, else `$XDG_CONFIG_HOME/forti`, else `~/.config/forti` (macOS
  included). State: `$XDG_STATE_HOME/forti` or `~/.local/state/forti` (plans, approvals, audit log).
  Cache: `$XDG_CACHE_HOME/forti` (live schemas). Never derived from the working directory.
- `config.json` (0600, dir 0700) holds profiles: host, port, vdom, ca_bundle, client_cert path,
  resolve_ip, timeouts, `writes` (default **false**), and a credential *reference*, never a secret.
- Secret sources, in order: OS store (macOS Keychain via Security.framework: service `forti`, account
  `<profile>/api-key`); file `credentials/<profile>.token` (0600); `env` (variable name stored, not
  the value); `command` (argv, git-credential style). The P12 password uses the same mechanism.
- TLS verification is always on (the SDK hardcodes VERIFYPEER/VERIFYHOST=2). No flag disables it.
  Self-signed devices use `ca_bundle` or `resolve_ip`.
- Secrets never appear in argv, output, logs, plans, audit records, MCP client config, or project files.

## Mutation safety model

1. **plan** validates every operation against the catalog (resource exists, op supported, fields
   known and writable, values decode as the SDK type). It reads the current object(s), computes
   before/after and a field diff, includes the SDK wire body (`to_json(obj, Write::update|create)`),
   classifies risk, and stores the plan in `state/plans/<id>.json`. `digest` = SHA-256 over canonical
   JSON of {device identity (profile, host, serial, vdom), operations, before digests}.
2. **approve** is human only. `forti plan approve <id>` shows the diff and requires an interactive
   terminal (`/dev/tty`, not stdin) where the person types the plan's confirmation code. On macOS,
   critical plans also need LocalAuthentication (Touch ID or password). It writes an approval record
   bound to the digest (HMAC with a key in the secret store), and it expires (default 15 min). The MCP
   server has **no** approve tool and never writes approvals.
3. **apply** takes only a plan id. It refuses when: the approval is missing, expired or for another
   digest; the profile is not write-enabled; the device identity differs; or any re-read before-digest
   differs (`stale_plan`). It runs operations in order with no retries (the SDK never retries
   post-send). It re-reads after each one to verify. It stops at the first failure and records each
   operation as `applied | verified | failed | outcome_unknown | not_attempted`. Every attempt is
   appended to `state/audit.jsonl`.
4. **Risk tiers.** `low` (objects inert unless referenced: addresses, services, schedules, profiles,
   lists); `elevated` (policies, VIPs, NAT pools, user and auth objects, monitor actions); `critical`
   (system interface, admin, api-user, accprofile, global, HA, VDOM, router/*, zones, DNS, NTP,
   certificates, management access). Critical plans need a fresh config backup taken by the engine
   (`monitor/system/config/backup`, stored 0600 under state) before apply. The approval prompt must
   confirm an out-of-band recovery path (console or other admin access).

Discovering a capability never authorizes it: `discover` reports `operations` and `risk` per resource.
Execution policy lives in the profile (`writes`) and the approval record.

## MCP surface (forti-mcp)

Four tools, mirroring the engine: `forti_discover`, `forti_read`, `forti_plan`, `forti_apply`.
`forti_apply` returns `approval_required` with the exact `forti plan approve <id>` command for the
human. Responses are bounded (default 50 items and 48 KiB of JSON, with `next_start` continuation).
Field schemas are returned selectively (`fields`). No arbitrary SSH/CLI execution, ever: REST only.
Protocol: JSON-RPC 2.0 over stdio, newline-delimited; `initialize`, `tools/list`, `tools/call`,
`ping`, and notifications. stdout carries protocol only; logs go to stderr without secrets.
