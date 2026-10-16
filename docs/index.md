---
title: forti-cli
description: forti, FortiOS from the command line - discover, read, plan and apply FortiGate configuration over the REST API.
order: 0
status: published
tags:
  - overview
---

# forti-cli

:::badges{gap="sm"}
::badge[Latest release]{
  type="github"
  target="release"
  repo="valkyrianlabs/forti-cli"
  href="https://github.com/valkyrianlabs/forti-cli/releases"
  newTab=true
}
::badge[CI]{
  type="github"
  target="workflow"
  repo="valkyrianlabs/forti-cli"
  workflow="ci.yml"
  href="https://github.com/valkyrianlabs/forti-cli/actions/workflows/ci.yml"
  newTab=true
}
::badge[License]{
  type="github"
  target="license"
  repo="valkyrianlabs/forti-cli"
  href="https://github.com/valkyrianlabs/forti-cli/blob/main/LICENSE"
  newTab=true
}
:::

`forti` reads FortiGate configuration and monitor data through the FortiOS REST API, and changes it
through validated, stored plans. It is built on the [forti-api](https://github.com/valkyrianlabs/forti-api)
SDK and shares its command engine with [forti-mcp](https://github.com/valkyrianlabs/forti-mcp), so
AI clients get the same bounded surface as you do at the terminal.

:::buttons{align="left" stack="mobile" gap="md"}
::button[Install forti]{href="/getting-started/installation" variant="primary"}
::button[Quick start]{href="/getting-started/quick-start" variant="secondary"}
::button[GitHub]{href="https://github.com/valkyrianlabs/forti-cli" variant="outline" newTab=true}
:::

```sh
forti configure                       # address, API key (hidden), client certificate, mode; checked
forti get firewall/policy             # or: forti get firewall policy
forti mcp install                     # the FortiGate tools for Claude Code and Codex, in ~/.forti
cd ~/.forti && claude                 # or: codex
```

At the terminal:

```sh
forti get firewall/policy --fields policyid,name,action,status
forti plan set firewall/address LAN comment="office LAN"
forti apply 20261015-142233-a1b2c3    # the plan's id; needs a guarded or autonomous profile
```

## What you get

:::cards{
  columns="2"
  cardTheme="muted"
}

:::card[Every FortiOS 7.4.8 resource]{eyebrow="Catalog"}
360 tables, 127 singletons and 47 typed monitor endpoints, compiled into the binary.
`forti discover` searches them and shows each one's attributes, key, risk tier and supported
operations without a device. Other monitor paths are readable untyped.
:::

:::card[Narrow reads]{eyebrow="Read"}
FortiOS filters, field selection and paging, checked against the catalog before anything is sent.
Device secrets (`ENC ...` values, passwords, keys) are redacted by default.
:::

:::card[Changes as plans]{eyebrow="Change"}
A plan reads the device, validates every operation against the SDK types, and stores the
before-state, a field diff, the exact request body and a risk tier. Planning never changes the
device. `forti apply` runs a plan once, checks it for drift first, verifies every change by
re-reading it, and writes a rollback plan and an audit record.
:::

:::card[Operating modes]{eyebrow="Policy"}
Profiles are `read-only` by default. `guarded` profiles apply a plan only after a person approves
it; `autonomous` profiles apply without approval, with every safeguard still on.
:::

:::card[One home, many FortiGates]{eyebrow="Setup"}
Profiles, credentials, certificates and plans live in `~/.forti`. Copy, rename and edit profiles
for a fleet of devices, and share one client certificate across them.
:::

:::card[Credentials kept out of sight]{eyebrow="Security"}
The API key is never an argument. It lives in the macOS Keychain or a 0600 file bound to its
device, or is referenced as an environment variable or a command. TLS verification is always on.
:::

:::card[Scripts and AI clients]{eyebrow="Integrations"}
Every command takes `--json` for one stable envelope, and the exit status follows the error code.
`forti mcp install` gives Claude Code and Codex the FortiGate tools in the `~/.forti` workspace, with
the agent skill and rules that keep the stored credentials out of the agent's reach.
:::

:::

## Where to go next

### Get started

:::cards{
  columns="2"
  cardTheme="glass"
}

:::card[Installation]{href="/getting-started/installation"}
APT, Homebrew or a source build, and a first check that it works.
:::

:::card[Quick start]{href="/getting-started/quick-start"}
Configure a FortiGate, add a certificate, check it, and start an AI agent in `~/.forti`.
:::

:::

### Guides

:::cards{
  columns="2"
  cardTheme="muted"
}

:::card[Profiles and credentials]{href="/guides/profiles-and-credentials"}
Several FortiGates: add, copy, rename and edit profiles, credential sources, TLS and `forti doctor`.
:::

:::card[Client certificates]{href="/guides/client-certificates"}
Made or reused by `forti configure`, the forti CA, the FortiGate commands, renewal and removal.
:::

:::card[Discovering and reading]{href="/guides/discovering-and-reading"}
Resources, `discover`, `get`, filters, fields, paging and secret redaction.
:::

:::card[Making changes]{href="/guides/planning-and-applying-changes"}
Stored plans, operating modes, approvals, apply, rollback plans, backups and risk tiers.
:::

:::card[AI agent integration]{href="/guides/ai-agent-integration"}
The `~/.forti` workspace for Claude Code and Codex, its deny rules, status, repair and removal.
:::

:::

### Reference

:::cards{
  columns="2"
  cardTheme="muted"
}

:::card[Command reference]{href="/reference/commands"}
Every command and option, the output formats and the JSON envelope.
:::

:::card[Configuration files]{href="/reference/configuration-files"}
The forti home and its layout, migrating from 0.1, file modes, `config.json` keys and environment.
:::

:::card[Exit codes]{href="/reference/exit-codes"}
The stable error codes and the exit status each one maps to.
:::

:::card[Security notes]{href="/reference/security"}
What is stored where, redaction, TLS, and what modes do and do not stop.
:::

:::

### Development

:::cards{
  columns="2"
  cardTheme="muted"
}

:::card[Building]{href="/development/building"}
Build options, the forti-api SDK, the resource catalog and the release profile.
:::

:::card[Testing]{href="/development/testing"}
Unit tests, the mock FortiOS integration suite, and CI.
:::

:::
