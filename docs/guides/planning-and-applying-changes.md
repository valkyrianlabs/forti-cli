---
title: Planning and applying changes
description: Stored, digest-bound plans; read-only, guarded and autonomous modes; approving and applying in one step, verification, forti rollback, critical backups and their limits.
order: 50
status: published
tags:
  - guides
---

# Planning and applying changes

Every change goes through two steps. `forti plan` reads the device, validates the change and stores
it as a plan; it never changes the device. `forti apply <id>` executes a stored plan once. Between
the two, you (or a person you trust) read exactly what will be sent. At a terminal the two steps can
be one command (`--apply`), and `forti rollback` undoes the last apply.

:::toc[On this page]{depth="3" theme="compact"}
:::

## Writing a plan

The convenience forms plan one operation:

```text
forti plan set <resource> [key] attr=value... [--clear attr]
forti plan create <resource> attr=value... | --object JSON|@file
forti plan delete <resource> <key>
forti plan action <monitor/path> [--body JSON|@file]
```

```sh
forti plan set firewall/address LAN comment="office LAN" --clear color
forti plan set system/global hostname=fw-lab                   # a singleton takes no key
forti plan create firewall/address name=web subnet="192.0.2.10 255.255.255.255"
forti plan create firewall/address --object '{"name":"web","subnet":"192.0.2.10 255.255.255.255"}'
forti plan delete firewall/address web
forti plan action monitor/system/external-resource/dynamic       # --body defaults to {}
```

`attr=value` is JSON when the value parses as JSON (a number, boolean, array, object, `null` or a
`"quoted"` string), else literal text: `status=disable` and `subnet=192.0.2.0/24` are text,
`color=3` is a number and `name='"123"'` is the string `123`. `--clear attr` (repeatable) resets an
attribute to its default. `@file` reads JSON from a file, `@-` from standard input. `plan create`
takes the new object as `attr=value` pairs, as `--object`, or both (the pairs win). A misspelt
attribute is refused with a suggestion: `unknown attribute(s): colour (did you mean color?)`.

Add `--apply` to any of these (or to `--file`) to apply the plan in the same command, as the profile's
mode allows: autonomous applies it, guarded asks for your approval at a terminal (and without one
stops at the approval, as `forti apply` does), read-only refuses.

### Plan files

Several operations go in one plan with `--file` (`-` reads standard input). The file holds a request
object, or just the array of operations:

```json
{
  "profile": "fw01",
  "vdom": "root",
  "operations": [
    {"op": "create", "resource": "firewall/address", "object": {"name": "web1", "subnet": "192.0.2.10 255.255.255.255"}},
    {"op": "update", "resource": "firewall/policy", "key": "12", "set": {"status": "disable"}, "clear": ["comments"]},
    {"op": "delete", "resource": "firewall/address", "key": "old-web"},
    {"op": "action", "resource": "monitor/system/external-resource/dynamic", "body": {}}
  ]
}
```

```sh
forti plan --file changes.json
forti plan --profile fw01 --file - < changes.json
```

| Field | Meaning |
|---|---|
| `profile`, `vdom` | optional; `--profile` and `--vdom` on the command line take precedence. The VDOM defaults to the profile's |
| `operations` | 1 to 200 operations, executed in order |
| `op` | `create`, `update`, `delete` or `action` |
| `resource` | a resource path, as in `forti discover` |
| `key` | the object's key, for `update` and `delete` on tables (singletons have none) |
| `object` | `create`: the new object's attributes. Without its key (or with a numeric key of `0`), the device assigns one |
| `set`, `clear` | `update`: attributes to set, and attribute names to reset to their defaults (at least one of the two) |
| `body` | `action`: the JSON body of the monitor POST (default `{}`) |

Any other field is a `usage` error. Which operation fits which resource:

| Resource kind | Operations |
|---|---|
| table | `create`, `update`, `delete` |
| singleton | `update` |
| monitor path | `action` |

### What planning checks

Before the first device read, each operation is checked against the catalog: the resource exists,
it supports the operation, and each object appears at most once in the plan. Then forti reads every
object the plan touches and builds each change through the SDK's typed models, so unknown or
read-only attributes and values that do not decode are refused (`validation`) before anything is
stored. It also refuses:

- creating an object that already exists (use an update), and updating or deleting one that does not (`not_found`);
- changing a table's key attribute through an update (that would write to another object);
- the value `"<redacted>"` anywhere in a plan. Reads show secrets that way; leave a secret attribute
  out to keep its current value.

:::callout[Table attributes are replaced wholesale]{variant="warning"}
FortiOS replaces a list attribute such as `srcaddr` or `member` with exactly the entries you send.
List every entry you want to keep; the diff shows which entries the change adds and removes and the
resulting list.
:::

### The plan

```text
Plan 20261015-142233-a1b2c3  risk low
Device fw01  fw01.example.net:443  serial FGT60F...  v7.4.8
1 operation on fw01 (fw01.example.net): 1 update; risk low

1. update firewall/address "LAN"  [low]
     comment  "" → "office LAN"
     color    3 → 0  (cleared to default)
     PUT cmdb/firewall/address/LAN {"color":0,"comment":"office LAN"}

mode   guarded
next   forti apply 20261015-142233-a1b2c3  (shows the plan and asks for your approval)
       without a terminal: forti plan approve 20261015-142233-a1b2c3, then the same apply
```

`--verbose` adds the plan's digest; `--json` always carries it. For a read-only profile, the last line
says how to allow changes instead (`forti profile mode fw01 guarded`).

The plan is stored as `~/.forti/state/plans/<id>.json` (mode 0600). It records the device identity (profile,
host, port, VDOM, serial number, FortiOS version), and for each operation the before-state and its
SHA-256 digest, the after-state, a field diff, the exact request (method, path and body) and the risk
tier. The plan's digest is a SHA-256 over the device identity and the operations. Plan ids look like
`20261015-142233-a1b2c3` (UTC time and six random hex digits).

:::callout[Stored plans hold real values]{variant="note"}
Sensitive values are redacted in everything forti prints (diffs, request bodies, `plan show`). The
stored plan file keeps the real values because apply writes them and compares the device against
them; that is why it is owner-only.
:::

```sh
forti plan list                      # stored plans, newest first, with their state
forti plan show <id>                 # the plan, its before/after, approval and applied state
```

### Naming a plan

Wherever a command takes a plan id, it also takes:

| You type | Plan |
|---|---|
| `20261015-142233-a1b2c3` | that plan |
| `a1b2c3`, `a1b`, `20261015-1422` | the one plan whose id, or whose last part, starts with it. Several matches are listed, and nothing runs |
| `latest` | the newest plan of the profile (rollback plans aside) |
| nothing, at a terminal | the newest plan of the profile waiting to be applied. forti names it and shows it before acting |

Without a terminal (scripts, agents' shell tools), a plan must be named: the id, a prefix or `latest`.

| `plan list` state | Meaning |
|---|---|
| `pending` | not applied, and no approval for its digest |
| `approved` | not applied, with an unexpired approval for its digest |
| `approval_expired` | not applied; its approval has expired (approvals last 24 hours) |
| `applied` | the plan has run (a plan runs at most once) |
| `tampered`, `invalid` | the plan file fails its integrity check |

## Operating modes

:::callout[The FortiOS account is the primary authorization boundary]{variant="warning"}
An API user can do exactly what its admin profile, VDOM assignment and trusted hosts allow, whatever
forti's settings. A profile's mode is the operator's policy on top of that.
:::

A mode is set with `forti configure --mode` or `forti profile mode`, is stored in config.json, and
cannot be changed through forti-mcp.

| Mode | Plan | Apply |
|---|---|---|
| `read-only` (default) | yes: preview and validation are reads | refused: `policy_denied`. Allow changes with `forti profile mode NAME guarded` |
| `guarded` | yes | only after a person approves that exact plan: inline at a terminal, or `forti plan approve <id>` |
| `autonomous` | yes | without interactive approval; every safeguard below still applies |

### Approving a plan (guarded)

At a terminal, `forti apply` does it in one step: it shows the plan and asks
`Approve and apply plan <id>? [y/N]`. A yes records the approval (exactly as `forti plan approve`
does) and applies.

```sh
forti apply                  # the newest plan waiting to be applied: shown, approved, applied
forti plan approve <id>      # approve only; at a terminal it then asks "Apply now? [Y/n]"
```

`approve` prints the plan and asks `[y/N]`; `--yes`, `--json`, or standard output that is not a
terminal skip the question (and the offer to apply). The approval is written to
`~/.forti/state/approvals/<id>.json`: it names the plan's digest, is recorded as `cli:$USER`, expires
after **24 hours**, and is used up by the apply it allows. Approving a plan of a read-only profile, or
one already applied, is refused (`policy_denied`); for an autonomous profile nothing is written and
forti says no approval is needed. Without a terminal, `forti apply` never approves: it stops with
`approval_required` and the `forti plan approve <id>` command.

Approval exists only in the CLI. forti-mcp never writes approvals: in guarded mode its apply tool
answers `approval_required` with the `forti plan approve <id>` command for the person to run.

:::callout[An approval records intent]{variant="warning"}
An approval records operator intent; it is not a cryptographic control. An agent that can run shell
commands as you can approve a plan too. See
[What a mode does and does not stop](/reference/security#what-a-mode-does-and-does-not-stop).
:::

## Applying a plan

```sh
forti apply <id>
```

```text
Applied plan 20261015-142233-a1b2c3: 1 change applied and verified.
1. update firewall/address "LAN"  verified
undo      forti rollback 20261015-142233-a1b2c3  (rollback plan 20261015-142240-d4e5f6)
```

Apply takes only the plan id; the operations come from the stored plan. In order, it:

1. verifies the plan file (its format, its digest, and that every operation's shape, risk tier and
   request match what the catalog says), refusing a tampered plan;
2. refuses a plan that was already applied: a plan runs at most once;
3. checks the mode, and in guarded mode a valid, unexpired approval for this digest;
4. checks that the profile still points at the planned host and port, re-reads every before-state,
   and checks the device's serial number. Anything that moved makes the plan **stale** (`stale_plan`):
   plan again from fresh reads;
5. checks that the audit log can be appended to, and refuses before any change if not (`config`);
6. for a critical-risk plan, saves a configuration backup (below);
7. writes a provisional rollback plan, so even a crash mid-apply leaves one;
8. executes the operations in order, without retries, and stops at the first failure;
9. verifies each operation by re-reading the object, and after each critical-risk operation probes
   management connectivity;
10. rewrites the rollback plan from what actually happened, and appends the record to `audit.jsonl`.

Each operation ends with one status:

| Status | Meaning |
|---|---|
| `verified` | sent, and the re-read object matches what was written |
| `applied_unverified` | sent and accepted, but not confirmed: a monitor action (cannot be re-read), a create whose key the device did not report, a failed re-read, or values that differ (FortiOS normalizes some, e.g. `192.0.2.0/24` to `192.0.2.0 255.255.255.0`; the record lists `mismatches`) |
| `failed` | FortiOS refused it, or the connection failed before the request was sent |
| `outcome_unknown` | the request may have reached the device, but no usable reply came back |
| `not_attempted` | an earlier operation stopped the run |

An apply that stopped returns `partial_failure`, `outcome_unknown` or `management_connectivity_lost`
(exit 8) with the full execution record in `error.details`; in text mode the record is printed
first.

:::callout[A failed request does not mean nothing changed]{variant="warning"}
An HTTP failure is never taken to mean "nothing changed": after a failed operation forti re-reads the
object. FortiOS creates are not transactional, so a create that failed can leave the object behind
(`exists_after_failure`).
:::

### Rollback plans

Every apply that may have changed the device writes a **rollback plan**: the inverse operations, in
reverse order, built from the recorded before-states.

| Operation | Undone by |
|---|---|
| create | a delete |
| update | setting the previous values (or clearing attributes that had none) |
| delete | re-creating the object from its writable attributes |
| action | nothing: monitor actions cannot be rolled back; the record lists them under `rollback.skipped` |

The rollback plan is an ordinary stored plan (`kind: rollback`, `rollback_of: <id>`). `forti rollback`
applies it:

```sh
forti rollback               # undo the profile's last apply
forti rollback <plan id>     # undo that plan (or apply that rollback plan)
```

It first says what it undoes (`Rolling back plan <id>: ...`), then applies under the same mode rules
as `forti apply`: a guarded profile needs the approval (asked inline at a terminal), a read-only one
refuses. The rollback is checked for drift like any plan, and it writes a rollback plan of its own,
so a second `forti rollback` re-does the change. `forti plan show <rollback id>` reviews it first;
`forti apply <rollback id>` works too.

### Configuration backups before critical plans

Before a plan with a **critical**-risk operation runs, forti downloads a full configuration backup to
`~/.forti/state/backups/<plan id>.conf` (0600, in a 0700 directory). It is streamed to disk, never printed or
logged, and the 20 most recent backups are kept (older ones are deleted after each new backup). If the
backup cannot be taken, the plan does not run (`policy_denied`, reason `backup_failed`). Setting
`"backup_before_critical": false` on the profile in config.json turns the backup off.

:::callout[Treat a backup like a credential]{variant="warning"}
A backup holds the complete configuration, including FortiOS-encrypted secrets, most of them
reversible. See [Security notes](/reference/security#what-is-stored-where).
:::

### Management connectivity probe

After each critical-risk operation that may have reached the device (critical monitor actions
included), forti opens a fresh connection and reads `monitor/system/status`, checking the serial
number. If that fails, execution stops with `management_connectivity_lost`, and the result carries
the rollback plan id, the backup reference and the before-state of the operation that lost the path.

### Recovery aids are not guaranteed recovery

:::callout[Keep an independent path to the device]{variant="danger"}
The rollback plan and the configuration backup both need a **working management path** to the device.
If a change cuts off management access (an interface, a route, an admin setting, trusted hosts), forti
cannot undo it, and it never claims to. You need an independent path: the console port, an
out-of-band management interface, or a device-side automatic revert. Have one before you, or an
agent, change critical settings.
:::

## Risk tiers

`discover` and `plan` report a risk tier for every resource and operation; a plan's tier is that of
its riskiest operation.

| Tier | Resources |
|---|---|
| `low` | objects that do nothing unless referenced: addresses, services, schedules, security profiles, ... |
| `elevated` | policies, VIPs, IP pools, users, VPN, logging, most `system/*`, and monitor actions not listed as critical |
| `critical` | management access, routing, interfaces, zones, admins and API users, access profiles, HA, VDOMs, DNS, NTP, SD-WAN, SNMP, certificates, `system/global` and `system/settings`, local-in policies; monitor actions that reboot, restore, upgrade, reset or disconnect (`system/os/*`, `system/config/restore`, `system/firmware/*`, `system/ha-*`, `system/interface/*`, `firewall/session/close-all`, ...) |

:::callout[Tiers are not approval gates]{variant="info"}
Tiers drive the configuration backup, the connectivity probe and the emphasis in output. What may
run is decided by the mode and the FortiOS account.
:::

## Audit log

Every apply attempt, refused or not, and every approval is appended to `~/.forti/state/audit.jsonl` (0600),
one JSON object per line: the event, plan id and digest, profile, host, serial, mode, risk, each
operation's resource, key, status and the *names* of the attributes it changed, the rollback plan, the
backup status and the outcome. Values are not recorded. If the record cannot be written after the
changes were made, the result says so (`audit_error`) rather than dropping it.
