# forti-cli

`forti`, the FortiOS command-line interface, and **forti-engine**, the command engine it shares
with forti-mcp. C++23, Meson, built on the header-only forti-api SDK (the only FortiOS
implementation). The ecosystem architecture and contracts are in `../.claude/context/architecture.md`
in the parent workspace. A copy of the engine contract is in `.claude/context/engine.md`.

```sh
ln -sfn "$(cd ../forti-api && pwd)" subprojects/forti-api   # SDK co-development (else the wrap downloads v1.0.1)
meson setup build/dev -Dtests=enabled --buildtype=debugoptimized
meson compile -C build/dev -j "$(ci/build-jobs)"   # every core memory allows (~2 GB per engine shard with GCC)
meson test -C build/dev --suite unit   # network-free; what CI runs
meson test -C build/dev --suite integration   # real `forti` vs a mock FortiOS over TLS (python3 + openssl)
meson install -C build/rel --skip-subprojects   # source installs: never install the SDK from the wrap
```

The default build is `buildtype=release` (-O3), as packaged and tested; CI builds -O0 and tests that.
Packaging and release: `.claude/context/release.md`.

forti keeps everything in the forti home: `$FORTI_HOME`, else `~/.forti` (config.json, credentials/,
certs/, state/, cache/, and the MCP workspace files). `FORTI_CONFIG_DIR`, `FORTI_STATE_DIR` and
`FORTI_CACHE_DIR` override single locations; a pre-0.2 XDG setup (`~/.config/forti`) stays in use until
`forti home migrate`. When running `forti` by hand, set `HOME` and `FORTI_HOME` to a temporary directory
(as `ci/smoke-test.sh` and the test harnesses do): never touch the real `~/.forti`, `~/.claude*` or
`~/.codex`. User docs: `docs/` (payload-markdown; `pmdocs validate --source forti-cli`).

## Layout

| Path | What |
|---|---|
| `engine/include/forti/engine/` | Engine contract: `engine.hpp` (discover/read/plan/apply, JSON in and out), `catalog.hpp`, `profile.hpp`, `error.hpp` |
| `engine/src/` | Implementation. `catalog_shard.cpp` is compiled N times and holds the typed SDK glue (`ops.hpp`); `policy.cpp` holds risk tiers; `plan.cpp` plan/apply (rollback plans, management probe); `plan_store.cpp` plan files, approvals, audit log, redaction; `approval.cpp` the CLI-only approve/show/list API (`approval.hpp`) |
| `src/cli/` | `forti`: argument parsing, the command table (`commands.cpp`), output (text, or `--json` envelope) |
| `src/install/` | AI client adapters for `forti install mcp` |
| `skill/` | The agent skill installed alongside the MCP registration |
| `tests/` | GoogleTest, network-free. `tests/support/fake_transport.hpp` scripts the SDK transport |
| `tests/mock-fortios/` | Stateful mock FortiOS REST server (Python stdlib, HTTPS with a throwaway CA, fault injection, request records) and the harness forti-mcp reuses (`mock_fortios_dir`) |
| `tests/integration/` | The real `forti` end to end against the mock; `scan_http.py` checks that nothing outside forti-api speaks HTTP. `tests/perf/bench.py`: startup, RSS and latency |

## Rules

1. **forti-api owns FortiOS.** Never construct URLs, headers, TLS or curl calls, FortiOS models,
   or a resource list here. Reach FortiOS only through `fortiapi::Client`, `Table`/`Singleton`,
   `Monitor`, `from_json`/`to_json` and the generated registry. If the SDK is missing something, write
   it up in `../.claude/context/forti-api-gaps.md`. Do not work around it, and do not edit forti-api.
2. **No live firewall in tests or development.** Tests use the fake transport. Never send a
   mutation to a real device. Reads against a real device only with the maintainer's go-ahead.
3. **Secrets never leak.** Never put them in argv, output, logs, plans, audit records, error
   messages, or client MCP config.
4. **The engine contract is stable.** The request and result shapes in `engine.hpp` and
   `architecture.md` are shared with forti-mcp. Change them only through the orchestrator.
5. Match the style: 4-space indent, `snake_case`, comments that explain *why*, no framework where a
   function will do. Keep `-Wall -Wextra -Wpedantic` (warning_level=3) clean on Apple clang and GCC 13+.
