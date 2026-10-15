---
title: forti-cli
description: forti, FortiOS from the command line - discover, read, plan and apply FortiGate configuration over the REST API.
order: 0
status: published
tags:
  - overview
---

# forti-cli

`forti` reads FortiGate configuration and monitor data through the FortiOS REST API, and changes it
through validated, stored plans. It is built on the [forti-api](https://github.com/valkyrianlabs/forti-api)
SDK and shares its command engine with [forti-mcp](https://github.com/valkyrianlabs/forti-mcp), so
AI clients get the same bounded surface as you do at the terminal.

```sh
forti configure                                     # host, CA bundle, API key (hidden) and mode
forti doctor                                        # config, credentials, TLS, auth, FortiOS version
forti get firewall/policy --fields policyid,name,action,status
forti plan set firewall/address LAN comment="office LAN"
forti apply 20261015-142233-a1b2c3                  # the plan's id; needs a guarded or autonomous profile
```

## What you get

- **Every FortiOS 7.4.8 resource**: 360 tables, 127 singletons and 47 typed monitor endpoints, compiled
  into the binary. `forti discover` searches them and shows each one's attributes, key, risk tier and
  supported operations without a device. Other monitor paths are readable untyped.
- **Narrow reads**: FortiOS filters, field selection and paging, checked against the catalog before
  anything is sent. Device secrets (`ENC ...` values, passwords, keys) are redacted by default.
- **Changes as plans**: a plan reads the device, validates every operation against the SDK types, and
  stores the before-state, a field diff, the exact request body and a risk tier. Planning never
  changes the device. `forti apply` runs a plan once, checks it for drift first, verifies every
  change by re-reading it, and writes a rollback plan and an audit record.
- **Operating modes**: profiles are `read-only` by default. `guarded` profiles apply a plan only after
  a person approves it; `autonomous` profiles apply without approval, with every safeguard still on.
- **Credentials kept out of sight**: the API key is never an argument. It lives in the macOS Keychain
  or a 0600 file bound to its device, or is referenced as an environment variable or a command.
  TLS verification is always on.
- **Scriptable**: every command takes `--json` for one stable envelope, and the exit status follows
  the error code.
- **AI clients**: `forti install mcp` registers forti-mcp with Claude Code and Codex, and can
  install an agent skill alongside it.

## Where to go next

- [Installation](/getting-started/installation)
- [Quick start](/getting-started/quick-start)
- [Profiles and credentials](/guides/profiles-and-credentials)
- [Discovering and reading](/guides/discovering-and-reading)
- [Planning and applying changes](/guides/planning-and-applying-changes)
- [AI agent integration](/guides/ai-agent-integration)
- [Command reference](/reference/commands)
- [Security notes](/reference/security)
