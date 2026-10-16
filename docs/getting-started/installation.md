---
title: Installation
description: Install forti from the APT repository or Homebrew, or build it from source.
order: 10
status: published
tags:
  - getting-started
---

# Installation

`forti` is a single executable. Its only runtime library dependency is libcurl; the forti-api SDK is
header-only and compiled in. Client certificates (`forti configure`, `forti cert`) also use the `openssl` command, which macOS ships
(`/usr/bin/openssl`, LibreSSL) and the Debian package depends on. The packages install `forti`, its
man page (`man forti`), shell completions (bash, zsh, fish), and forti-mcp, the MCP server AI agents
use.

:::toc[On this page]{depth="2" theme="compact"}
:::

## Install forti

Pick the method for your platform: the APT package (Debian and Ubuntu, amd64), the Homebrew formula
(macOS and Linux), or a build from source.

:::tabs{
  default="apt"
  theme="glass"
  tabTheme="muted"
}

:::tab[APT (Debian, Ubuntu)]{value="apt"}
The `forti-cli` package (amd64) is published to the ValkyrianLabs APT repository:

```bash
sudo install -d -m 0755 /etc/apt/keyrings
sudo curl -fsSL https://apt.valkyrianlabs.com/pubkey.gpg \
  -o /etc/apt/keyrings/valkyrianlabs.gpg
sudo chmod 0644 /etc/apt/keyrings/valkyrianlabs.gpg

echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/valkyrianlabs.gpg] https://apt.valkyrianlabs.com stable main" | \
  sudo tee /etc/apt/sources.list.d/valkyrianlabs.list > /dev/null

sudo apt update
sudo apt install -y forti-cli
```

The packages recommend `valkyrianlabs-archive-keyring` (APT installs it by default), which puts the repository key at
`/usr/share/keyrings/valkyrianlabs.gpg` and keeps it current through normal upgrades (for example when its
expiry changes). When the key downloaded above is unmodified, the package replaces it with a symlink to the
packaged key, so the source line above keeps working and you never need to download the key again. Removing
the package turns the symlink back into a plain copy. Signing key fingerprint:
`494D 71A1 EEDD F87B D48E  5048 6D64 CB7B DFC3 0EC6`.

The executable is `/usr/bin/forti`. APT also installs the `forti-mcp` package, which `forti-cli`
recommends (unless recommends are turned off). The `.deb` from a GitHub release installs on its own too.
:::

:::tab[Homebrew (macOS, Linux)]{value="homebrew"}
```bash
brew install valkyrianlabs/tap/forti-cli
```

Homebrew pours a prebuilt bottle on macOS 15 or later (Apple silicon and Intel), and installs
forti-mcp with it. Elsewhere it builds from source against the `forti-api` formula, which it needs
only at build time.

:::callout[Trust the tap first]{variant="note"}
Recent Homebrew versions ask you to trust a third-party tap first: `brew trust valkyrianlabs/tap`.
:::
:::

:::tab[From source]{value="source"}
Needs a C++23 compiler (Apple clang 16+ or GCC 13+), Meson 1.3 or later, Ninja and libcurl. The
forti-api SDK comes from pkg-config (`libforti-api-dev` or the Homebrew formula) or, failing that,
from the Meson wrap.

```bash
# Ubuntu: sudo apt install meson ninja-build g++ pkgconf libcurl4-openssl-dev
# macOS:  brew install meson ninja       (libcurl comes with the SDK)
meson setup build
meson compile -C build -j 4
meson install -C build --skip-subprojects
```

The default build type is `release` (-O3). `--skip-subprojects` keeps `meson install` from
installing the SDK headers when they came from the wrap. See [Building](/development/building) for
the details.

:::

:::

## forti-mcp

forti-mcp, the MCP server for AI clients, comes with forti-cli (a Homebrew dependency, an APT
recommendation). It is also a package of its own, with no dependency on forti-cli:
`brew install valkyrianlabs/tap/forti-mcp` or `sudo apt install forti-mcp`. `forti mcp install`
registers it with your AI clients in the `~/.forti` workspace
([AI agent integration](/guides/ai-agent-integration)).

## Check the installation

```bash
forti --version
forti discover firewall/address
forti home
```

`--version` prints the forti version and the FortiOS schema version its models come from
(`forti 0.2.0 (FortiOS schema 7.4.8)`). `discover` works offline: the resource catalog is compiled in.
`forti home` shows where forti keeps its files: the forti home, `~/.forti` (or `$FORTI_HOME`).
Upgrading from 0.1? Your existing setup keeps
working; see [Pre-0.2 setups](/reference/configuration-files#pre-0-2-setups).

## Shell completion

The APT package and the Homebrew formula install Tab completion for bash, zsh and fish: commands,
options, profile names, resource paths and pending plan ids. A source build installs it with
`meson install`; for a copy in your home directory instead, see
[`forti completion`](/reference/commands#completion).

## Next steps

:::cards{
  columns="3"
  cardTheme="muted"
}

:::card[Quick start]{href="/getting-started/quick-start"}
Configure a FortiGate, check it, and start an AI agent in `~/.forti`.
:::

:::card[Profiles and credentials]{href="/guides/profiles-and-credentials"}
Every `forti configure` option, credential sources and TLS.
:::

:::card[Building]{href="/development/building"}
Build options, the resource catalog and the release profile.
:::

:::
