---
title: Building
description: Build forti from source, the build options, the engine shards and the release profile.
order: 110
status: published
tags:
  - development
---

# Building

Build forti from source for development, choose the build options, and see how the packages build
the release profile.

:::toc[On this page]{depth="2" theme="compact"}
:::

## Requirements

| Needed for | What |
|---|---|
| building | a C++23 compiler (Apple clang 16+ or GCC 13+), Meson 1.3 or later, Ninja, libcurl |
| the tests | also GoogleTest, Python 3 and `openssl` |

Builds are warning-free at `warning_level=3` (`-Wall -Wextra -Wpedantic`) on Apple clang and GCC,
and CI builds with `-Dwerror=true`.

## Development build

:::steps

### Configure

```bash
meson setup build/dev -Dtests=enabled --buildtype=plain -Doptimization=0 -Ddebug=false
```

### Compile

```bash
meson compile -C build/dev -j 4
```

Each engine shard needs about 2 GB of RAM to compile with GCC, so size `-j` to the machine's memory
([Engine shards](#engine-shards)).

### Run

```bash
./build/dev/src/cli/forti --version
```

:::

## The forti-api SDK

forti reaches FortiOS only through the header-only forti-api SDK. Meson finds it through pkg-config
(`libforti-api-dev`, or the Homebrew `forti-api` formula) and otherwise falls back to
`subprojects/forti-api.wrap`, which pins a release tag. To develop against a local SDK checkout,
put it (or a symlink to it) at `subprojects/forti-api`:

```bash
ln -sfn "$(cd ../forti-api && pwd)" subprojects/forti-api
```

:::callout[Do not install the SDK from the wrap]{variant="warning"}
When installing a source build, use `meson install --skip-subprojects` so the SDK headers from the
wrap are not installed with forti.
:::

## Layout

| Path | What |
|---|---|
| `engine/` | forti-engine, the command engine shared with forti-mcp: catalog, profiles and secrets, discover/read/plan/apply, approvals, audit. Its contract is `engine/include/forti/engine/engine.hpp` (JSON request in, JSON result out) |
| `src/cli/` | the `forti` executable: argument parsing, the command table, text and `--json` output |
| `src/install/` | the AI client adapters behind `forti mcp` |
| `skill/forti/SKILL.md` | the agent skill, compiled into `forti` |
| `doc/forti.1` | the man page |
| `tests/` | unit tests, the mock FortiOS and the integration tests ([Testing](/development/testing)) |
| `ci/` | the CI container and scripts |

:::callout[forti-engine is internal]{variant="note"}
forti-engine is a static library linked into both `forti` and `forti-mcp`. It is not installed and
has no API promise outside these two repositories.
:::

## Engine shards

Instantiating the typed SDK operations for every endpoint in one translation unit takes minutes and
several GB of memory. The engine therefore compiles `engine/src/catalog_shard.cpp` once per shard,
and each copy instantiates only its share of the endpoints. The registry stays the single source;
shards only filter it.

| Option | Default | Meaning |
|---|---|---|
| `engine_shards` | `10` | translation units the typed endpoint operations are split across (1 to 64): more shards, less memory each and more parallelism |
| `tests` | `auto` | build the unit and integration tests |
| `subproject_cli` | `false` | also build (never install) `forti` when forti-cli is a subproject, for forti-mcp's integration tests |

:::callout[About 2 GB of RAM per shard]{variant="warning"}
Each shard needs about 2 GB of RAM to compile with GCC (less unoptimized, more with `-g` or
sanitizers), so limit `-j` to what memory allows. `ci/build-jobs` prints that number for the current
machine.
:::

## Release profile

The default build type is `release`: -O3, `NDEBUG`, and on Linux `-ffunction-sections
-fdata-sections -Wl,--gc-sections`. Packages build exactly that and test what they built:

| Package | Build | Tested |
|---|---|---|
| Debian (`debian/rules`) | against the system `libforti-api-dev` with `--wrap-mode=nodownload`; dpkg's `-O2 -g` replaced with `-O3`; LTO off | the unit suite runs on the build |
| Homebrew formula | `-Doptimization=3 -Dstrip=true` against the `forti-api` formula | an offline `forti --version` and `forti discover` in its test block |

No LTO, no `-g` and no debug-symbol package: the generated shards make both expensive, and the
stripped binary is what ships. Releases are cut with vl-release; `release.toml` holds the repository
contract.
