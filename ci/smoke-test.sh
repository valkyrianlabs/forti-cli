#!/usr/bin/env bash
# Smoke test of a built or installed `forti`, offline and without touching the caller's config:
#
#   ci/smoke-test.sh [PATH-TO-FORTI]     (default: forti on PATH)
#
# Runs `forti --version` and an offline `forti discover firewall/address` (the catalog is compiled
# in; no profile, device or network is needed), and checks that discover wrote no files. POSIX tools
# only: it also runs in a stock ubuntu:24.04 with nothing but the .deb installed.
set -euo pipefail

forti="${1:-forti}"
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT
export HOME="$scratch/home" FORTI_HOME="$scratch/forti"
mkdir -p "$HOME"

version="$("$forti" --version)"
echo "$version"
case "$version" in
  "forti "[0-9]*) ;;
  *) echo "smoke-test: unexpected --version output" >&2; exit 1 ;;
esac

"$forti" --json discover firewall/address > "$scratch/discover.json"
grep -Eq '"ok": *true' "$scratch/discover.json" || { cat "$scratch/discover.json" >&2; exit 1; }
grep -q '"subnet"' "$scratch/discover.json" || { echo "smoke-test: firewall/address has no subnet field" >&2; exit 1; }
"$forti" discover firewall/address > /dev/null

# Usage errors exit with the documented code (2), not a crash.
status=0
"$forti" no-such-command > /dev/null 2>&1 || status=$?
[ "$status" -eq 2 ] || { echo "smoke-test: an unknown command exited $status, expected 2" >&2; exit 1; }

if [ -n "$(find "$FORTI_HOME" "$HOME" -type f 2>/dev/null)" ]; then
  echo "smoke-test: an offline discover wrote files" >&2
  exit 1
fi
echo "smoke-test: ok"
