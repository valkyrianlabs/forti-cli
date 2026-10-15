---
title: Quick start
description: Configure a profile, check it, read the device, make a first change and connect an AI client.
order: 20
status: published
tags:
  - getting-started
---

# Quick start

## 1. Create an API administrator

On the FortiGate, create a REST API administrator (System, Administrators, Create New, REST API
Admin). Give it an admin profile with only the permissions you need, restrict its trusted hosts to
the machine that runs `forti`, and copy the generated API key. The FortiOS account is the real
boundary on what forti can do; see [Security notes](/reference/security#choosing-autonomous-mode).

If the device uses a self-signed or private-CA certificate, export its CA (or the self-signed
certificate) as PEM. forti always verifies TLS and has no option to turn that off.

## 2. Configure a profile

```sh
forti configure
```

forti asks for a profile name, the host, the admin HTTPS port, an optional VDOM, CA bundle,
connect-to address and client certificate, where the API key comes from (it is typed with echo off),
and the operating mode. It then reads `monitor/system/status` once to check the profile, and saves
nothing if that fails. An authentication failure is never retried, because FortiOS locks an API user
out after repeated failures.

Without prompts, for scripts:

```sh
op read op://ops/fw01/api-key | forti configure --profile fw01 --host fw01.example.net \
    --ca-bundle ~/certs/fw01-ca.pem --api-key-stdin --default
```

Profiles are `read-only` unless you choose otherwise. See
[Profiles and credentials](/guides/profiles-and-credentials) for every option.

## 3. Check it

```sh
forti doctor
```

`doctor` checks the configuration files and their modes, the profile, that the key resolves, the
TLS files, the connection, authentication, the device's FortiOS version against the SDK's, the
operating mode, and whether forti-mcp is on `PATH`. Each failure comes with a hint.

## 4. Discover and read

```sh
forti discover addr                                  # resources whose path contains "addr"
forti discover firewall/address                      # attributes, key, risk tier
forti get firewall/address --fields name,subnet,comment
forti get firewall/address "LAN 10.0.0.0/24"
forti get monitor/system/status
forti get firewall/policy --filter action==accept --fields policyid,name,srcaddr,dstaddr --count 100
```

See [Discovering and reading](/guides/discovering-and-reading).

## 5. Plan and apply a change

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

See [Planning and applying changes](/guides/planning-and-applying-changes).

## 6. Connect an AI client (optional)

With [forti-mcp](/getting-started/installation#forti-mcp-optional) installed:

```sh
forti install mcp                    # pick Claude Code or Codex, a scope, and the agent skill
forti mcp status
```

The agent works through the same profiles and modes. See
[AI agent integration](/guides/ai-agent-integration).
