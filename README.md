# forti-cli

`forti`: FortiOS from the command line, built on [forti-api](https://github.com/valkyrianlabs/forti-api).
It reads FortiGate configuration and monitor data through the FortiOS REST API. Changes go through
validated plans. It shares its engine with [forti-mcp](https://github.com/valkyrianlabs/forti-mcp),
so AI clients get the same, bounded surface.

## Quick start

```sh
brew install valkyrianlabs/tap/forti-cli

forti configure                 # prompts for host, CA bundle, API key (hidden) and mode
forti doctor                    # checks config, credentials, TLS, auth and the FortiOS version
forti get firewall/policy --fields policyid,name,action,status
forti install mcp               # register forti-mcp with your AI client (optional)
```

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

- [Configuration](docs/configuration.md): profiles, credential sources, file locations, TLS
- [Commands](docs/commands.md): every command and option
- [Exit codes](docs/exit-codes.md)
- [Security notes](docs/security.md): what is stored where, operating modes and the risks of autonomous writes
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
