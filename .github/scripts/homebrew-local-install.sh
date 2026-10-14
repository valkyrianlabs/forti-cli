#!/usr/bin/env bash
# Install the release formula from a throwaway local tap, pointing it at the locally built source
# archive (file://), then run `brew test`. Proves the formula builds from source and works before it
# ever reaches valkyrianlabs/homebrew-tap. Expects `vlr` on PATH; run it in a disposable checkout:
# `vlr prepare` rewrites the release documents (bumping the version first when unreleased).
#
# The build dependency forti-api comes from the published tap (valkyrianlabs/tap), exactly as it
# will for users; meson, ninja and pkgconf from homebrew/core.
set -euo pipefail

phase="$(vlr status --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["phase"])')"
if [ "$phase" = unbumped ]; then vlr version bump minor >/dev/null; fi
vlr prepare >/dev/null
vlr source-archive
formula="$(vlr homebrew formula --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["path"])')"
version="$(vlr version show)"
archive="$PWD/release/forti-cli-${version}.tar.gz"

export HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_INSTALL_CLEANUP=1
brew tap valkyrianlabs/tap
# Recent Homebrew refuses formulae from third-party taps until they are trusted; forti-cli depends on
# valkyrianlabs/tap/forti-api, and the throwaway tap below holds the formula under test.
trust() { if brew commands --quiet | grep -qx trust; then brew trust "$1"; fi; }
trust valkyrianlabs/tap

tap="forti-cli-ci/local"
brew untap "$tap" >/dev/null 2>&1 || true
brew tap-new --no-git "$tap"
trust "$tap"
tap_formula="$(brew --repository "$tap")/Formula/forti-cli.rb"
trap 'brew uninstall --formula "$tap/forti-cli" >/dev/null 2>&1 || true; brew untap "$tap" >/dev/null 2>&1 || true' EXIT

# Style-check the exact formula that will be published, as a tap formula.
cp "$formula" "$tap_formula"
brew style "$tap/forti-cli"

# Then install it from the locally built archive and run its test block.
sed -E "s#^  url \".*\"#  url \"file://${archive}\"#" "$formula" > "$tap_formula"
brew install --build-from-source "$tap/forti-cli"
brew test "$tap/forti-cli"
"$(brew --prefix)/bin/forti" --version
test -f "$(brew --prefix)/share/man/man1/forti.1"
