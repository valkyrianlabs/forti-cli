# CI container

forti-cli's Linux CI and release jobs follow forti-api's conventions: every step runs inside a
disposable, rootless Podman container on the self-hosted VPS runner (GitHub-hosted `ubuntu-latest`
for pull requests from forks). The runner needs no host sudo, host packages or Docker. The shared
conventions are described in [payload-markdown's `ci/README.md`](https://github.com/valkyrianlabs/payload-markdown/blob/main/ci/README.md).

- `ci/run-ci` is copied **verbatim** from forti-api / payload-markdown (it is repository-agnostic);
  update it there and copy it back.
- `ci/Containerfile`: Ubuntu 24.04 (pinned by digest, GCC 13) with meson, ninja, g++, libcurl,
  GoogleTest, dpkg-dev, debhelper, gh and vl-release. libforti-api-dev is installed at run time
  by the package jobs only (development builds use the pinned wrap).
- Workflows set `defaults.run.shell: bash ./ci/run-ci bash -euo pipefail {0}` on their Linux jobs.
  Clean-install checks of the `.deb` use a stock image instead:
  `./ci/run-ci --image "$UBUNTU_IMAGE" --root bash -c 'apt-get install -y ./release/…'`.
- The container is capped at 12 GB (`CI_MEMORY`). Each engine shard TU needs about 2 GB at -O2/-O3
  (more with `-g` or sanitizers), so builds run with `-j 4` at most.

Build locally the way CI does (needs Podman):

```sh
./ci/run-ci bash -c 'meson setup build/ci -Dtests=enabled -Dwerror=true && meson compile -C build/ci -j 4 && meson test -C build/ci --suite unit'
```
