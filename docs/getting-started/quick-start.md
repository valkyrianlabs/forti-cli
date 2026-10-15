---
title: Quick start
description: From install to an AI agent working on your FortiGate - configure, optionally add a client certificate, check, and start the agent in ~/.forti.
order: 20
status: published
tags:
  - getting-started
---

# Quick start

Five commands take you from a fresh install to an AI agent with bounded access to your FortiGate.
Everything forti keeps (profiles, credentials, certificates, plans) lives in one directory, the forti
home `~/.forti`, and that is also where the agent works.

:::callout[Before you start]{variant="info"}
You need `forti` installed ([Installation](/getting-started/installation)) and, on the FortiGate, a
REST API administrator for forti (System, Administrators, Create New, REST API Admin). Give it an admin
profile with only the permissions you need, restrict its trusted hosts to this machine, and copy its
API key. The FortiOS account is the real boundary on what forti can do; see
[Security notes](/reference/security#choosing-autonomous-mode).
:::

:::steps{
  variant="cards"
  layout="stack"
  numbered
  stepTheme="muted"
}

### Configure the FortiGate

```sh
forti configure
```

forti asks for a profile name, the host, the port, a CA bundle if the device's certificate is
self-signed or from a private CA (TLS is always verified), where the API key comes from (typed with
echo off, it goes to the macOS Keychain or a 0600 file), and the operating mode. It checks the
profile with one read of the device and saves nothing if that fails. Profiles are `read-only` unless
you choose otherwise.

More devices later: `forti profile copy fw01 fw02`, then `forti configure --profile fw02`. See
[Profiles and credentials](/guides/profiles-and-credentials).

### Add a client certificate (optional)

```sh
forti cert create
```

When the FortiGate should require a client certificate as well as the API key, this makes a private
CA and a client certificate in `~/.forti/certs/<profile>/`, points the profile at them, and prints the
FortiGate commands to run. The certificate's password stays in a private file and is never printed.
See [Client certificates](/guides/client-certificates).

### Check everything

```sh
forti doctor
```

`doctor` checks the forti home, file modes, the profile, that the key resolves, the TLS files, the
connection, authentication, the FortiOS version, the operating mode, and whether forti-mcp is
installed. Each failure comes with a hint.

:::callout[Authentication failures are never retried]{variant="warning"}
FortiOS locks an API user out after repeated failures, so forti stops after one rejected attempt.
Check the key, the API user's trusted hosts and its admin profile before trying again.
:::

### Set up the agent workspace

With [forti-mcp](/getting-started/installation#forti-mcp-optional) installed:

```sh
forti install mcp
```

Choose your clients (Claude Code, Codex) and the first scope, "~/.forti workspace (recommended)".
forti registers the FortiGate tools in `~/.forti` only, with the forti agent skill, an `AGENTS.md`, and
rules that keep the agent away from the credentials stored there. For Codex it asks before marking
`~/.forti` as trusted. See [AI agent integration](/guides/ai-agent-integration#the-forti-workspace).

### Start the agent

```sh
cd ~/.forti && claude          # or: codex
```

Claude Code asks once to approve the `forti` server; approve it. The agent can now discover
resources, read configuration and plan changes, within the profile's mode. Agents started anywhere
else do not get the FortiGate tools.

:::

## At the terminal

The same engine works directly from the shell:

```sh
forti discover addr                                  # resources whose path contains "addr"
forti get firewall/address --fields name,subnet,comment
forti get firewall/policy --filter action==accept --fields policyid,name,srcaddr,dstaddr
forti plan set firewall/address LAN comment="office LAN"
```

A change starts as a plan: planning reads the device and never changes it. What happens next depends
on the profile's mode:

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

## Coming from forti 0.1

An existing `~/.config/forti` setup keeps working, and `forti doctor` points it out. Move it into
`~/.forti` with one command:

```sh
forti home migrate
```

See [Pre-0.2 setups](/reference/configuration-files#pre-0-2-setups).

## Next steps

:::cards{
  columns="3"
  cardTheme="muted"
}

:::card[Profiles and credentials]{href="/guides/profiles-and-credentials"}
Several FortiGates, credential sources, TLS and every `forti doctor` check.
:::

:::card[Planning and applying changes]{href="/guides/planning-and-applying-changes"}
Plan files, approvals, verification, rollback plans and their limits.
:::

:::card[Security notes]{href="/reference/security"}
What is stored where, and what a mode does and does not stop.
:::

:::
