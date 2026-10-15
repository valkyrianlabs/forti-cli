# Releasing forti-cli

forti-cli releases with vl-release (`vlr`, ValkyrianLabs convention, same as forti-api). The
repository contract is `release.toml`; release CI is `.github/workflows/release.yml` and only calls
`vlr` commands. The generic workflow is in `.claude/skills/vl-release/SKILL.md`, this repository's
specifics in `PROJECT.md` next to it (`vlr install-local-skill` regenerates it).

## What ships

| Channel | Artifact | Built by |
|---|---|---|
| APT (`apt.valkyrianlabs.com`, suite `stable`, `main`) | `forti-cli_<v>-1_amd64.deb`: `/usr/bin/forti`, `forti.1.gz`, copyright | `vlr build-deb` (`debian/`, against `libforti-api-dev >= 1.0.0`) |
| GitHub release | the .deb, `forti-cli-<v>.tar.gz` (prepared tracked tree), `SHA256SUMS` | `vlr source-archive`, `vlr checksums`, `vlr github-release` |
| Homebrew (`valkyrianlabs/tap`) | `Formula/forti-cli.rb`, builds from the source archive | `vlr homebrew formula` / `publish` (`packaging/homebrew/forti-cli.rb`) |

No package ever vendors forti-api: `debian/rules` passes `--wrap-mode=nodownload` with the system
`libforti-api-dev`, and the formula's `std_meson_args` pass `--wrap-mode=nofallback` with the
`forti-api` formula. The source archive therefore carries only `subprojects/forti-api.wrap` (as in
Git); a from-source build without a system forti-api fetches the pinned v1.0.0 through the wrap,
which is what `meson dist --include-subprojects` would have embedded. We deliberately do not ship
that: the tap and APT both provide forti-api.

## Cutting a release

1. Keep `.release/RELEASE_NOTES_NEXT.md` and `.release/CHANGELOG_NEXT.md` current with every
   user-visible change (`vlr help staging`). `vlr status` must say `pending`.
2. On a clean, up-to-date `main`: `vlr check`, then `vlr cut patch|minor|major --push` (or
   `vlr cut 0.1.0 --push` for the first release: the version already in `VERSION`).
3. The tag push runs `release.yml`:
   `build` (gate, prepare, `.deb` against `libforti-api-dev`, source archive, formula, checksums,
   contract validation, clean-install smoke test in stock `ubuntu:24.04`, APT dry-run plan) →
   `homebrew-check` (macOS: formula from a local tap, built from the archive, `brew test`) →
   `publish-apt` (Production; upload, index verification, install from the repository) →
   `github-release` → `homebrew-tap` (Production) → `finalize` (commits the promoted
   `debian/changelog` / `RELEASE_NOTES.md` to `main`).
4. A rehearsal without publishing: Actions → Release → Run workflow, `ref: vX.Y.Z`,
   `publish: dry-run` (runs `build` and `homebrew-check` only).

`debian/changelog` and `RELEASE_NOTES.md` do not exist until the first `vlr prepare`; never create
or edit them by hand (vl-release would treat a hand-written entry as an inconsistent release).

## Secrets, variables and settings

| Name | Kind | Used by |
|---|---|---|
| `NEXUS_USER`, `NEXUS_PASSWORD` | org secrets | `publish-apt` (`vlr publish-deb`) |
| `NEXUS_APT_REPO` | org variable | `publish-apt`: Nexus APT upload URL |
| `HOMEBREW_TAP_TOKEN` | secret (org or repo) | `homebrew-tap`: push to `valkyrianlabs/homebrew-tap` |
| `RELEASE_PUBLISH_MODE` | repo variable, optional | `nexus` (the workflow default) or `disabled` |
| `GITHUB_TOKEN` | automatic | `github-release`, `finalize` (`contents: write`) |

Org secrets and variables must be granted to this repository (organization settings → secrets →
repository access).

## Before the first release (checklist)

- [ ] GitHub repository `valkyrianlabs/forti-cli` exists (it did not on 2026-10-14) and `main` is
      pushed; Actions enabled.
- [ ] Environment `Production` on the repository (`publish-apt`, `homebrew-tap` use it; add
      reviewers if publication should need a click).
- [ ] The org secrets/variables above are available to the repository; `HOMEBREW_TAP_TOKEN` can push
      to `valkyrianlabs/homebrew-tap` (fine-grained token: contents read/write on that repo).
- [ ] The self-hosted VPS runner (labels `self-hosted, Linux, X64, ubuntu-latest-lts`) serves this
      repository (runner group access), with rootless Podman as for forti-api.
- [ ] If `main` is protected, `github-actions[bot]` may push the `finalize` commit.
- [ ] `libforti-api-dev >= 1.0.0` is in the APT index (it is: 1.0.0-1) and `forti-api` 1.0.0 is in
      the tap (it is).
- [ ] The man page `doc/forti.1` and its `install_man` are merged (the package contract requires
      `usr/share/man/man1/forti.1.gz`, and the formula check looks for it).
- [ ] Staged release docs describe the first release; `vlr status` says `pending`.
- [ ] A dry-run of `release.yml` (workflow_dispatch, `publish: dry-run`) is green.

## Build profile

Current (maintainer decision, 2026-10-15): release builds are `buildtype=release` (-O3) and are tested
as built; pull-request CI builds -O0 and tests that; no job builds twice. `engine_shards=10`, no LTO;
on ELF, non-debug builds add `-ffunction-sections -fdata-sections -Wl,--gc-sections`. Packaging:
Debian swaps dpkg's `-O2` for `-O3`, drops Ubuntu's default `-flto=auto -ffat-lto-objects` and `-g`,
sets `b_ndebug=true` and ships no `-dbgsym` package; Homebrew passes `-Doptimization=3 -Dstrip=true`;
parallelism comes from `ci/build-jobs` (memory-aware). GCC 13 per shard (4-core runner, dpkg
hardening flags): -O0 30 s / 1.9 GB, -O1 49 s, -O2 64 s, -O3 76 s / 2.3 GB.

The table below is the 2026-10-14 size study that chose `optimization=s` before that decision; kept
for its numbers (an -O3 stripped `forti` is ~24 MB, -Oz ~12 MB).

Measured 2026-10-14 on the development Mac (Apple clang 21, meson 1.8, `ninja -j4` building only
`forti`, forti-api from the wrap with its tests disabled, a quiet machine except other agents). Peak
RSS is the largest single process (a shard TU, or the linker under LTO); at `-j4` up to four run at
once. Sizes in MiB.

| Configuration | Wall | Peak RSS | Link | Binary | Stripped |
|---|---:|---:|---:|---:|---:|
| debugoptimized (dev baseline) | 97 s | 3.9 GB | <1 s | 32.8 | 22.2 |
| release (-O3) | 70 s | 2.0 GB | <1 s | 31.8 | 23.5 |
| release, -O2 | 71 s | 2.0 GB | <1 s | 30.9 | 22.6 |
| **release, optimization=s (-Oz)** | **44 s** | **1.8 GB** | <1 s | **24.3** | **12.4** |
| minsize (-Oz -g) | 54 s | 2.6 GB | <1 s | 28.7 | 12.3 |
| -O3 + `-Wl,-dead_strip` | 72 s | 2.0 GB | <1 s | 31.6 | 23.4 |
| -Oz + `-Wl,-dead_strip` | 43 s | 1.8 GB | <1 s | 24.1 | 12.3 |
| -O2 + full LTO | 178 s | 5.8 GB | 131 s | 24.9 | 20.9 |
| -Oz + full LTO | 110 s | 5.8 GB | 78 s | 13.4 | 7.3 |
| -Oz + full LTO + dead_strip | 107 s | 5.9 GB | 75 s | 13.4 | 7.3 |
| -O3 + thin LTO | 50 s | 3.4 GB | 17 s | 15.3 | 8.2 |
| -Oz + thin LTO | 50 s | 3.3 GB | 18 s | 15.3 | 8.2 |
| -Oz, engine_shards=4 | 35 s | 2.6 GB | <1 s | 24.0 | 12.2 |
| -Oz, engine_shards=16 | 55 s | 1.4 GB | <1 s | 24.8 | 12.6 |
| -O2, engine_shards=4 | 65 s | 2.7 GB | <1 s | 30.8 | 22.5 |
| -O2, engine_shards=16 | 83 s | 1.4 GB | <1 s | 31.2 | 22.7 |
| source archive, Homebrew flags (`--wrap-mode=nofallback`, `-Oz`, `strip=true`) | 45 s | 1.9 GB | | installed 12.4 | |

Reading it:

- `optimization=s` is the one big lever: the stripped binary halves (23.5 → 12.4 MB), the build is
  ~35% faster and shards need less memory. `forti --json discover` runs in ~10 ms at -O3 and -Oz
  alike: the work is network-bound.
- Stripping matters as much (24.3 → 12.4 MB): the symbol table of the SDK instantiations is half the
  file. Debian strips by default; the formula sets `strip=true`.
- `-dead_strip` is noise on Mach-O. `--gc-sections` on ELF is the standard equivalent and is enabled,
  but unmeasured here (no GCC/ELF toolchain locally): check the first CI build.
- LTO: full LTO reaches 7.3 MB but makes the link the bottleneck (78 s, 5.9 GB single process). Thin
  LTO (8.2 MB, 18 s, 3.3 GB) is attractive for Homebrew but clang-only, so it cannot be a project
  default; GCC LTO is unmeasured. Revisit if size starts to matter (e.g. forti-mcp ships a second
  copy of the engine).
- Shards: 8 balances wall time against memory. 4 is fastest at `-j4` but 2.6 GB per TU; 16 halves
  memory (1.4 GB) for +25% wall. CI's sanitizer build uses 16.
- AGENTS.md's "~1.2 GB per shard" holds only without `-g`: debugoptimized shards peak at 3.9 GB on
  clang. GCC typically needs more; the Linux CI caps `-j` accordingly.

## Multi-architecture (arm64): vl-release gap

Today `forti-cli` ships amd64 only. `debian/control` already says `Architecture: any`, so the
package itself builds anywhere; the limits are in vl-release 0.5.0:

1. **One architecture per package contract.** `[[debian.packages]]` has a single
   `architecture` string, and `validate-artifacts` checks every `.deb` of that package against it.
2. **One `.deb` per package in a release directory.** Collecting `forti-cli_X_amd64.deb` and
   `forti-cli_X_arm64.deb` in `release/` is rejected (duplicate package), so an arm64 build cannot
   join the same release.
3. `build-deb` runs one `build_command` per release. A cross build
   (`dpkg-buildpackage --host-arch arm64`) is possible in principle (`libforti-api-dev` is
   `Architecture: all`, so it needs no cross variant), but it needs a cross toolchain and
   `libcurl4-openssl-dev:arm64` in the image, and still hits limits 1 and 2. A native arm64 runner
   is simpler.

`[publish.apt] architectures` already accepts a list, and `libforti-api-dev` (arch `all`) is
listed in every `binary-*` index, so the APT side needs no change. Proposed vl-release change:
`architecture` accepts a list (`architectures = ["amd64", "arm64"]`), the release directory keys
packages by (name, architecture), `validate-artifacts` checks each against the contract, and
`publish-deb` verifies each architecture's index. The workflow then gains a matrix `build-deb` job
per architecture (an arm64 self-hosted or `ubuntu-24.04-arm` runner) whose `release/` outputs are
merged before `checksums`. Until then, arm64 users build from source (the wrap or
`libforti-api-dev`).

Homebrew has no such limit (source builds on both Apple silicon and Intel); bottles would need
vl-release bottle support, which it does not have.

## GCC 13 / libstdc++ 13 portability (Ubuntu 24.04)

Static scan of `engine/`, `src/`, `tests/` on 2026-10-14 (no GCC or container runtime on the
development Mac, so nothing was compiled with GCC locally; the Linux CI job is the proof):

- No C++23 library feature that libstdc++ 13 lacks: no `std::print`, `std::ranges::contains`/`to`/
  `fold`, `views::enumerate`/`zip`/`chunk`, range or `{:?}` formatting, `flat_map`, `generator`,
  `stacktrace`, or `std::expected` monadic calls. `std::format` (in libstdc++ 13) is only given
  strings, string views and integers. `.contains()` is on `std::set`/`map` (transparent `less<>`) and
  `nlohmann::json`; `std::string::contains` is in libstdc++ 11+.
- No language feature GCC 13 lacks (no deducing `this`, no `static operator()` reliance).
- Headers that libc++ might provide transitively (`<array>`, `<cctype>`, `<map>`, `<vector>`,
  `<algorithm>`, `<ostream>`, `<system_error>`, `<chrono>`) all arrive through explicitly included
  headers on both libraries (nlohmann/json, `<filesystem>`, `<charconv>`, forti_api/client.hpp).
- Residual risk is warnings under `-Werror` that only GCC emits: `-Wdangling-reference` (GCC 13,
  `-Wall`; no reference here binds to a call that takes a temporary), and optimizer-driven
  `-Wmaybe-uninitialized`/`-Warray-bounds`/`-Wrestrict` false positives in libstdc++ at -Os.
  If the first Linux CI run hits one, fix the code or scope a `#pragma GCC diagnostic` to the line.

## Known issue: source builds through the wrap install forti-api too

When forti-api comes from the wrap (no system forti-api), `meson install` also installs the SDK's
headers and `forti-api.pc` into the prefix (verified with `DESTDIR`). Packages are unaffected (they
use the system SDK), but source installs should use `meson install --skip-subprojects`.
