# forti-cli

`forti`: FortiOS from the command line, built on [forti-api](https://github.com/valkyrianlabs/forti-api).
It reads FortiGate configuration and monitor data through the FortiOS REST API. Changes go through
validated plans. It shares its engine with [forti-mcp](https://github.com/valkyrianlabs/forti-mcp),
so AI clients get the same, bounded surface.

## Quick start

```sh
brew install valkyrianlabs/tap/forti-cli    # or: sudo apt install forti-cli (apt.valkyrianlabs.com)

forti configure                 # prompts for host, CA bundle, API key (hidden) and mode
forti cert create               # optional: a client certificate, and the FortiGate steps to trust it
forti doctor                    # checks the home, credentials, TLS, auth and the FortiOS version
forti install mcp               # pick "~/.forti workspace (recommended)"; needs forti-mcp
cd ~/.forti && claude           # or: codex. The agent gets the FortiGate tools here, nowhere else
```

At the terminal: `forti get firewall/policy --fields policyid,name,action,status`.

Everything lives in one directory, the forti home: `~/.forti` (or `$FORTI_HOME`, see `forti home`).

```text
~/.forti/
├── config.json       profiles, one per FortiGate (no secrets)
├── credentials/      file-stored API keys (0600; macOS uses the Keychain)
├── certs/<profile>/  client certificates from forti cert create
├── state/            plans, approvals, backups, audit log
└── cache/
```

After `forti install mcp`, it is also the agent workspace: `AGENTS.md`, the forti skill, the MCP
registration, and deny rules that keep the agent's file tools away from `credentials/`, certificate
keys and `config.json`. Coming from 0.1? `~/.config/forti` keeps working; `forti home migrate` moves it.

Profiles are **read-only by default**. TLS verification is always on: for a self-signed device, pass
`--ca-bundle` (the device's CA as PEM) or `--resolve-ip`. The API key never goes on the command line.
It is kept in the macOS Keychain or a 0600 file, or referenced as an environment variable or a
command.

Without prompts, for scripts:

```sh
op read op://ops/fw01/api-key | forti configure --profile fw01 --host fw01.example.net \
    --ca-bundle ~/certs/fw01-ca.pem --api-key-stdin --default
```

Every command takes `--json` for a stable envelope (`{"ok": …, "data": …, "meta": …}`), and exit
statuses follow the error code.

## Documentation

- [Docs index](docs/index.md): installation, quick start, guides, reference and development
- [Profiles and credentials](docs/guides/profiles-and-credentials.md): several FortiGates, credential sources, TLS
- [Client certificates](docs/guides/client-certificates.md): `forti cert create` and the FortiGate side
- [AI agent integration](docs/guides/ai-agent-integration.md): the `~/.forti` workspace for Claude Code and Codex
- [Configuration files](docs/reference/configuration-files.md): the forti home, migration from 0.1, `config.json`
- [Commands](docs/reference/commands.md): every command and option
- [Exit codes](docs/reference/exit-codes.md)
- [Security notes](docs/reference/security.md): what is stored where, operating modes and the risks of autonomous writes
- `man forti`

## Building from source

Needs a C++23 compiler (Apple clang 16+ or GCC 13+), Meson ≥ 1.3, Ninja and libcurl. The
header-only forti-api SDK comes from pkg-config or the Meson wrap.

```sh
meson setup build --buildtype=release
ninja -C build                      # each engine shard needs ~1.2 GB of RAM; use -j to limit
meson install -C build              # installs forti and its man page under the prefix
```

Tests are network-free:

```sh
meson setup build/dev -Dtests=enabled --buildtype=debugoptimized
ninja -C build/dev
meson test -C build/dev --suite unit
```

`FORTI_TEST_KEYCHAIN=1` also runs a round-trip test against the login keychain (service
`forti-test`). It is off by default.

See [AGENTS.md](AGENTS.md) for the layout and the contribution rules.
