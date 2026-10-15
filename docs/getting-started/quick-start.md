---
title: Quick start
description: Configure a profile, check it, read the device, make a first change and connect an AI client.
order: 20
status: published
tags:
  - getting-started
---

# Quick start

Go from a fresh install to a checked profile, a first read and a first planned change. Each step
links to the guide that covers it in full.

:::callout[Before you start]{variant="info"}
You need `forti` installed ([Installation](/getting-started/installation)) and administrator access
to the FortiGate, to create a REST API administrator for forti.
:::

:::steps{
  variant="cards"
  layout="stack"
  numbered
  stepTheme="muted"
}

### Create an API administrator

On the FortiGate, create a REST API administrator (System, Administrators, Create New, REST API
Admin). Give it an admin profile with only the permissions you need, restrict its trusted hosts to
the machine that runs `forti`, and copy the generated API key. The FortiOS account is the real
boundary on what forti can do; see [Security notes](/reference/security#choosing-autonomous-mode).

:::callout[TLS is always verified]{variant="note"}
If the device uses a self-signed or private-CA certificate, export its CA (or the self-signed
certificate) as PEM. forti always verifies TLS and has no option to turn that off.
:::

### Configure a profile

```sh
forti configure
```

forti asks for a profile name, the host, the admin HTTPS port, an optional VDOM, CA bundle,
connect-to address and client certificate, where the API key comes from (it is typed with echo off),
and the operating mode. It then reads `monitor/system/status` once to check the profile, and saves
nothing if that fails.

Without prompts, for scripts:

```sh
op read op://ops/fw01/api-key | forti configure --profile fw01 --host fw01.example.net \
    --ca-bundle ~/certs/fw01-ca.pem --api-key-stdin --default
```

Profiles are `read-only` unless you choose otherwise. See
[Profiles and credentials](/guides/profiles-and-credentials) for every option.

:::callout[Authentication failures are never retried]{variant="warning"}
FortiOS locks an API user out after repeated failures, so forti stops after one rejected attempt.
Check the key, the API user's trusted hosts and its admin profile before trying again.
:::

### Check the profile

```sh
forti doctor
```

`doctor` checks the configuration files and their modes, the profile, that the key resolves, the
TLS files, the connection, authentication, the device's FortiOS version against the SDK's, the
operating mode, and whether forti-mcp is on `PATH`. Each failure comes with a hint.

### Discover and read

```sh
forti discover addr                                  # resources whose path contains "addr"
forti discover firewall/address                      # attributes, key, risk tier
forti get firewall/address --fields name,subnet,comment
forti get firewall/address "LAN 10.0.0.0/24"
forti get monitor/system/status
forti get firewall/policy --filter action==accept --fields policyid,name,srcaddr,dstaddr --count 100
```

See [Discovering and reading](/guides/discovering-and-reading).

### Plan and apply a change

A change starts as a plan. Planning reads the device and never changes it:

```sh
forti plan set firewall/address LAN comment="office LAN"
```

The plan shows the before and after of every attribute, the exact request, the risk tier and an id.
What happens next depends on the profile's mode:

```sh
forti profile mode fw01 guarded      # read-only profiles refuse every apply
forti plan approve <id>              # guarded: a person approves the exact plan
forti apply <id>                     # runs once: drift check, execute, verify, rollback plan, audit
```

:::callout[Choose the mode deliberately]{variant="warning"}
`read-only` profiles refuse every apply, `guarded` profiles apply only a plan a person approved,
and `autonomous` profiles apply without approval. forti-mcp cannot change a mode. Read
[Operating modes](/guides/planning-and-applying-changes#operating-modes) before you pick one.
:::

See [Planning and applying changes](/guides/planning-and-applying-changes).

### Connect an AI client (optional)

With [forti-mcp](/getting-started/installation#forti-mcp-optional) installed:

```sh
forti install mcp                    # pick Claude Code or Codex, a scope, and the agent skill
forti mcp status
```

The agent works through the same profiles and modes. See
[AI agent integration](/guides/ai-agent-integration).

:::

## Next steps

:::cards{
  columns="3"
  cardTheme="muted"
}

:::card[Profiles and credentials]{href="/guides/profiles-and-credentials"}
Credential sources, TLS options and every `forti doctor` check.
:::

:::card[Planning and applying changes]{href="/guides/planning-and-applying-changes"}
Plan files, approvals, verification, rollback plans and their limits.
:::

:::card[Security notes]{href="/reference/security"}
What is stored where, and what a mode does and does not stop.
:::

:::
