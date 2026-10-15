---
title: Discovering and reading
description: Find resources, inspect their attributes, and read configuration and monitor data with filters, fields and paging.
order: 40
status: published
tags:
  - guides
---

# Discovering and reading

Find the resource you need with `forti discover`, then read it with `forti get`: narrowed by
filters and fields, paged, and with device secrets redacted.

:::toc[On this page]{depth="3" theme="compact"}
:::

## Resources

Every FortiOS object forti can address is a **resource**, named by its REST path:

| Kind | Example | Read | Write |
|---|---|---|---|
| table | `firewall/address` (objects addressed by a key, here `name`) | list, or one object by key | create, update, delete |
| singleton | `system/global` (one object, no key) | the object | update |
| monitor | `monitor/system/status` | the endpoint's result | `action` (a POST) |

`firewall/address` and `cmdb/firewall/address` name the same table. FortiOS's dotted paths are
canonical: `firewall.service/custom`. The catalog compiled into forti holds every configuration
endpoint of the FortiOS 7.4.8 schema and the typed monitor endpoints of the SDK (360 tables, 127
singletons, 47 monitors). Any other `monitor/...` path is still readable, untyped: forti returns
whatever the device sends.

## Discover

`discover` works without a device, except with `--live`.

```text
forti discover [search]          resources whose path contains `search`
forti discover <resource>        a resource's attributes, operations and risk tier
  --kind table|singleton|monitor   restrict a search
  --fields a,b                     full detail for these attributes
  --live                           merge the device's own schema (help text, options, ranges)
  --start N --count N              page through a search
```

```sh
forti discover addr
forti discover --kind monitor system
forti discover firewall/policy
forti discover firewall/policy --fields srcaddr,action --live
```

An exact resource name shows the resource; anything else is a search. A search lists up to 1000
matches unless you pass `--count`.

For a resource, forti prints its kind, key and risk tier (`low`, `elevated` or `critical`; see
[Risk tiers](/guides/planning-and-applying-changes#risk-tiers)), then each attribute with its type
(`table[...]` for a list of child entries, `ro` for read-only). With `--json` the result also lists
the supported operations and each attribute's default value, and `--fields` limits the list to the
attributes you name and expands their child attributes.

`--live` reads the device's schema (`?action=schema`) through the selected profile and adds
FortiOS's help text to every attribute; for the attributes named in `--fields` it also adds the
FortiOS type, size, value range, `required`, option names and the data source of references.
Monitor endpoints have no live schema. The live schema is fetched from the device on every call.

## Get

```text
forti get <resource> [key]
  --filter EXPR      FortiOS filter, repeatable (AND); ',' inside one is OR (name==a,name==b)
  --fields a,b       return only these attributes
  --start N          first item (default 0)
  --count N          items per page (default 50, max 1000)
  --param name=val   extra query parameter (monitor endpoints)
  --reveal           show device secrets instead of <redacted>
```

```sh
forti get firewall/policy --fields policyid,name,action,status
forti get firewall/address "LAN 10.0.0.0/24"
forti get firewall/policy 12
forti get system/global --fields hostname,admin-sport
forti get monitor/system/status
forti --vdom dmz get firewall/address
```

A key reads one object of a table; singletons and monitors take no key. Keys are sent URL-encoded,
and `.` and `..` are refused as keys. A missing object is `not_found` (exit 5).

### Filters

`--filter` takes FortiOS filter expressions: `attribute` `operator` `value`. Several `--filter`
options must all match; a comma inside one expression means OR.

| Operator | Matches |
|---|---|
| `==` | equal |
| `!=` | not equal |
| `=@` | contains |
| `!@` | does not contain |
| `<`, `<=`, `>`, `>=` | less than, at most, greater than, at least |

```sh
forti get firewall/policy --filter status==disable
forti get firewall/address --filter type==fqdn --filter comment=@legacy
forti get firewall/address --filter name==web1,name==web2
```

:::callout[Names are checked before anything is sent]{variant="tip"}
For typed resources, forti checks every attribute named in `--filter` and `--fields` against the
catalog before sending anything; an unknown one fails with `validation` (exit 6) and the list of
unknown names.
:::

### Fields

`--fields` sends FortiOS's `format` parameter, so the device returns only those attributes, which
keeps large tables small. The text table puts the identifying column (the key, such as `policyid` or
`name`) first, then the fields in the order you gave, and fits the terminal width. FortiOS's
bookkeeping attribute `q_origin_key` is hidden in text output and kept in `--json`.

### Paging

Lists are paged: 50 items by default, at most 1000 per request. When more remain, `meta.next_start`
says where to continue (text output ends with `… more results: --start N`):

```sh
forti get firewall/address --count 1000
forti get firewall/address --count 1000 --start 1000
```

Tables page on the device: `next_start` is set whenever a page came back full. Monitor endpoints do
not page consistently, so forti reads the whole result and windows it itself; `meta.total` is the
full count and `meta.truncated` is true when items were left out.

### Monitor endpoints and parameters

Monitor endpoints return runtime state: `monitor/system/status`, `monitor/firewall/session-count-list`
and the like. `--param name=value` adds a query parameter the endpoint understands, and may be
repeated:

```sh
forti get monitor/system/interface --param interface_name=wan1
```

:::callout[Reserved parameters]{variant="note"}
Parameters that forti manages itself or that could carry a credential are refused: `vdom`,
`filter`, `format`, `start`, `count`, `action`, `access_token`, `skip` and `with_meta` (compared
without case). Use the options for these instead.
:::

## Device secrets are redacted

FortiOS returns stored secrets in its encrypted form (`ENC ...`). Pre-shared keys and RADIUS, LDAP
and TACACS+ secrets are reversibly encrypted, by default with a key built into FortiOS. So reads
replace, at any depth:

- every string value starting with `ENC `, and
- the value of every attribute whose name marks it as a secret (`password`, `psk`, `secret`,
  `private-key`, `key-string`, `api-key`, names ending in `-key`, and others)

with `"<redacted>"`. An unset secret stays visibly unset (`""` or `null`). `meta.redacted` lists the
locations as JSON pointers, with `*` for list items (`["/*/psksecret"]`), and text output ends with a
line saying how many were redacted.

:::callout[Revealing secrets]{variant="warning"}
`--reveal` shows the values, for a person who asks: it needs a terminal, or an explicit `--json`
(where you chose to capture the output), prints a warning on standard error, and sets
`meta.revealed`. In a pipe or file without `--json` it fails with `usage`. Nothing else turns
redaction off: forti-mcp has no way to reveal secrets.
:::

```sh
forti get vpn.ipsec/phase1-interface --fields name,psksecret --reveal
```

:::callout[Limits of name-based redaction]{variant="note"}
Name-based redaction can miss an attribute a later FortiOS adds; `ENC ` values are caught whatever
their name. See [Security notes](/reference/security#what-is-stored-where).
:::

## JSON output

`--json` (or `FORTI_OUTPUT=json`) prints the envelope that scripts and forti-mcp share:

```json
{"ok": true, "data": [...], "meta": {"resource": "firewall/policy", "profile": "fw01", "device": {"serial": "FGT60F...", "version": "v7.4.8", "build": ...}, "start": 0, "returned": 50, "next_start": 50}}
```

`data` is the device's `results`, as FortiOS sent it apart from redaction: an array for a list, an
object for a keyed read or a singleton. See [Command reference](/reference/commands#output) and
[Exit codes](/reference/exit-codes).
