---
title: Testing
description: The network-free unit tests, the mock FortiOS integration suite, and how CI builds and runs them.
order: 120
status: published
tags:
  - development
---

# Testing

forti has two test suites: network-free unit tests, and integration tests that run the real `forti`
against a mock FortiOS over TLS.

```bash
meson setup build/dev -Dtests=enabled --buildtype=plain -Doptimization=0 -Ddebug=false
meson compile -C build/dev -j 4
meson test -C build/dev --suite unit           # network-free
meson test -C build/dev --suite integration    # the real forti against a mock FortiOS over TLS
```

:::callout[No real devices]{variant="warning"}
Nothing in either suite talks to a FortiGate. Development never sends a change to a real device,
and reads against one happen only with the maintainer's go-ahead.
:::

:::toc[On this page]{depth="3" theme="compact"}
:::

## Unit tests

GoogleTest, in three executables of the `unit` suite:

| Test | Covers |
|---|---|
| `unit` | the engine through a scripted `fortiapi::Transport` (`tests/support/fake_transport.hpp`): catalog, reads, filters and paging, profiles and secrets, plans, apply, drift, rollback, approvals, redaction, digests |
| `cli` | the CLI in-process: arguments, `configure`, `profile`, `doctor`, rendering, terminal escaping, exit codes |
| `install` | `.mcp.json` and `config.toml` edits and the client adapters, against fake `claude` and `codex` scripts in a temporary home directory |

:::callout[macOS Keychain round trip]{variant="note"}
`FORTI_TEST_KEYCHAIN=1` also runs a round-trip test against the macOS login keychain (service
`forti-test`, removed afterwards). It is off by default.
:::

## Integration tests

The `integration` suite runs the built `forti` binary end to end:

| Test | Covers |
|---|---|
| `cli-e2e` (`tests/integration/test_cli.py`) | starts the mock FortiOS and drives `forti` through libcurl and verified TLS: configure (a wrong key saves nothing), TLS verification, doctor, offline and live discover, paging, fields and filters, keyed, singleton and monitor reads, read-only refusal, approvals bound to the plan digest, creates, updates and deletes with exact request bodies, normalized values, stale plans, a connection dropped after a write (never sent twice), partial failures, critical-plan backups and the management probe |
| `no-second-http-stack` (`tests/integration/scan_http.py`) | checks that no code outside forti-api builds URLs or talks HTTP, sockets, DNS or TLS |

It needs Python 3 (standard library only) and `openssl`; without Python the suite is not built.

### The mock FortiOS

`tests/mock-fortios/mock_fortios.py` is a small, stateful mock of the FortiOS 7.4 REST API. It
serves HTTPS on 127.0.0.1 with a throwaway CA made by `openssl`, requires the bearer API key, and
implements `firewall/address`, `firewall/policy` (device-assigned keys) and `system/global` with
list, filter, format and paging, create, update, delete and `?action=schema`, plus
`monitor/system/status`, the configuration backup download and an untyped monitor list. Tests can
inject faults (a connection dropped after a write, an error after a create, normalized values) and
inspect every request it received.

It runs in-process from the tests, or standalone:

```bash
python3 tests/mock-fortios/mock_fortios.py --dir /tmp/mock --addresses 200
```

which prints one JSON line with the port and CA path and serves until standard input closes.
forti-mcp's integration tests reuse it through `tests/mock-fortios/harness.py`.

`tests/perf/bench.py` measures startup, memory and request latency of `forti` and `forti-mcp`
against the mock. It prints a report and is not part of any suite.

## CI

Pull requests and pushes to `main` run `.github/workflows/ci.yml`: **one unoptimized build per job**,
which every suite then runs against.

| Job | Build | Runs |
|---|---|---|
| Linux (Ubuntu 24.04, GCC 13) | `-O0`, `-Dwerror=true`, AddressSanitizer and UndefinedBehaviorSanitizer on the hand-written code (the generated shards stay uninstrumented) | `pmdocs validate` of this docs package, the unit and integration suites, `ci/smoke-test.sh` |
| macOS (Apple clang) | `-O0`, `-Dwerror=true` | the unit and integration suites, `ci/smoke-test.sh` |

The mock tests do not need optimization, and an optimized build only slows the engine shards; ccache
keeps the shards between runs. Linux jobs run in a disposable, rootless Podman container
(`ci/run-ci`, `ci/Containerfile`), with as many compile jobs as memory allows (`ci/build-jobs`).

The optimized build is tested where it is made: the release workflow and the manual packaging
rehearsal (`package.yml`) build the Debian package and the Homebrew formula at **-O3, tested as
built**, then install the `.deb` into a clean `ubuntu:24.04` and run the smoke test there.
`ci/smoke-test.sh` runs `forti --version`, an offline `forti discover firewall/address` that must
write no files, and checks the exit status of a usage error.
