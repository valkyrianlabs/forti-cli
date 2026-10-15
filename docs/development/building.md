---
title: Building
description: Build forti from source, the build options, the engine shards and the release profile.
order: 110
status: published
tags:
  - development
---

# Building

```bash
meson setup build/dev -Dtests=enabled --buildtype=plain -Doptimization=0 -Ddebug=false
meson compile -C build/dev -j 4
./build/dev/src/cli/forti --version
```

Needs a C++23 compiler (Apple clang 16+ or GCC 13+), Meson 1.3 or later, Ninja and libcurl; the
tests also need GoogleTest, Python 3 and `openssl`. Builds are warning-free at `warning_level=3`
(`-Wall -Wextra -Wpedantic`) on Apple clang and GCC, and CI builds with `-Dwerror=true`.

## The forti-api SDK

forti reaches FortiOS only through the header-only forti-api SDK. Meson finds it through pkg-config
(`libforti-api-dev`, or the Homebrew `forti-api` formula) and otherwise falls back to
`subprojects/forti-api.wrap`, which pins a release tag. To develop against a local SDK checkout,
put it (or a symlink to it) at `subprojects/forti-api`:

```bash
ln -sfn "$(cd ../forti-api && pwd)" subprojects/forti-api
```

When installing a source build, use `meson install --skip-subprojects` so the SDK headers from the
wrap are not installed with forti.

## Layout

| Path | What |
|---|---|
| `engine/` | forti-engine, the command engine shared with forti-mcp: catalog, profiles and secrets, discover/read/plan/apply, approvals, audit. Its contract is `engine/include/forti/engine/engine.hpp` (JSON request in, JSON result out) |
| `src/cli/` | the `forti` executable: argument parsing, the command table, text and `--json` output |
| `src/install/` | the AI client adapters behind `forti install mcp` and `forti mcp` |
| `skill/forti/SKILL.md` | the agent skill, compiled into `forti` |
| `doc/forti.1` | the man page |
| `tests/` | unit tests, the mock FortiOS and the integration tests ([Testing](/development/testing)) |
| `ci/` | the CI container and scripts |

forti-engine is a static library linked into both `forti` and `forti-mcp`. It is not installed and
has no API promise outside these two repositories.

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

Each shard needs about 2 GB of RAM to compile with GCC (less unoptimized, more with `-g` or
sanitizers), so limit `-j` to what memory allows. `ci/build-jobs` prints that number for the current
machine.

## Release profile

The default build type is `release`: -O3, `NDEBUG`, and on Linux `-ffunction-sections
-fdata-sections -Wl,--gc-sections`. Packages build exactly that and test what they built:

- the Debian package (`debian/rules`) builds against the system `libforti-api-dev` with
  `--wrap-mode=nodownload`, replaces dpkg's `-O2 -g` with `-O3`, turns LTO off, and runs the unit
  suite on the build;
- the Homebrew formula builds with `-Doptimization=3 -Dstrip=true` against the `forti-api` formula
  and runs an offline `forti --version` and `forti discover` in its test block.

No LTO, no `-g` and no debug-symbol package: the generated shards make both expensive, and the
stripped binary is what ships. Releases are cut with vl-release; `release.toml` holds the repository
contract.
