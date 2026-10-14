# forti-cli

`forti`, the FortiOS command-line interface, and **forti-engine**, the command engine it shares
with forti-mcp. C++23, Meson, built on the header-only forti-api SDK (the only FortiOS
implementation). The ecosystem architecture and contracts are in `../.claude/context/architecture.md`
in the parent workspace. A copy of the engine contract is in `.claude/context/engine.md`.

```sh
ln -sfn "$(cd ../forti-api && pwd)" subprojects/forti-api   # SDK co-development (else the wrap downloads v1.0.0)
meson setup build/dev -Dtests=enabled --buildtype=debugoptimized
ninja -C build/dev -j6                 # each engine shard TU needs ~1.2 GB of RAM
meson test -C build/dev --suite unit   # network-free; what CI runs
```

## Layout

| Path | What |
|---|---|
| `engine/include/forti/engine/` | Engine contract: `engine.hpp` (discover/read/plan/apply, JSON in and out), `catalog.hpp`, `profile.hpp`, `error.hpp` |
| `engine/src/` | Implementation. `catalog_shard.cpp` is compiled N times and holds the typed SDK glue (`ops.hpp`); `policy.cpp` holds risk tiers; `plan.cpp` plan/apply (rollback plans, management probe); `plan_store.cpp` plan files, approvals, audit log, redaction; `approval.cpp` the CLI-only approve/show/list API (`approval.hpp`) |
| `src/cli/` | `forti`: argument parsing, the command table (`commands.cpp`), output (text, or `--json` envelope) |
| `src/install/` | AI client adapters for `forti install mcp` |
| `skill/` | The agent skill installed alongside the MCP registration |
| `tests/` | GoogleTest, network-free. `tests/support/fake_transport.hpp` scripts the SDK transport |

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
