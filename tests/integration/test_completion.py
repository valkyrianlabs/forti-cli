#!/usr/bin/env python3
"""The shell completion scripts against the real `forti`: the bash script is sourced in a fresh bash
(each bash found: the system's and one on PATH) with the built binary first on PATH, and _forti is
called as bash would call it; COMPREPLY is checked. zsh: _forti runs with the completion builtins
stubbed to print what they would be given (zsh's own prefix matching is not part of that). zsh and
fish: syntax (`zsh -n`, `fish -n`), when installed. Every run uses a temporary HOME and FORTI_HOME.

    FORTI_BINARY=build/dev/src/cli/forti python3 tests/integration/test_completion.py
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "completions"
FORTI = os.environ.get("FORTI_BINARY", "")

BASH_DRIVER = r"""
source "$1"
shift
COMP_WORDS=(forti "$@")
COMP_CWORD=$#
_forti
printf '%s\n' "${COMPREPLY[@]}"
"""

ZSH_DRIVER = r"""
compdef() { : }
compadd() {
    while [[ $1 == -* && $1 != -- ]]; do [[ $1 == -[SPJV] ]] && shift; shift; done
    [[ $1 == -- ]] && shift
    print -l -- "$@"
}
_describe() { [[ $1 == -t ]] && shift 2; shift; print -l -- "${(@P)1}" }
_files() { print -- "<files>" }
_message() { : }
compset() { [[ $1 == -P ]] && PREFIX=${PREFIX#*=} }
source "$1"
shift
words=(forti "$@")
CURRENT=$#words
PREFIX=${words[CURRENT]}
_forti
"""


def bashes() -> list[str]:
    found = []
    for candidate in (shutil.which("bash"), "/bin/bash"):
        if candidate and os.access(candidate, os.X_OK) and os.path.realpath(candidate) not in found:
            found.append(os.path.realpath(candidate))
    return found


class Completion(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="forti-completion-")
        self.addCleanup(self.tmp.cleanup)
        home = Path(self.tmp.name)
        self.forti_home = home / ".forti"
        self.forti_home.mkdir(mode=0o700)
        bin_dir = home / "bin"
        bin_dir.mkdir()
        (bin_dir / "forti").symlink_to(Path(FORTI).resolve())
        self.env = {"HOME": str(home), "FORTI_HOME": str(self.forti_home), "PATH": f"{bin_dir}:/usr/bin:/bin",
                    "LC_ALL": "C"}

    def complete(self, bash: str, *words: str) -> list[str]:
        result = subprocess.run([bash, "--norc", "--noprofile", "-c", BASH_DRIVER, "bash", str(SCRIPTS / "forti.bash"), *words],
                                env=self.env, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "", f"{bash}: {' '.join(words)}")
        return [line for line in result.stdout.splitlines() if line]

    def test_bash(self) -> None:
        shells = bashes()
        if not shells:
            self.skipTest("no bash")
        (self.forti_home / "config.json").write_text(json.dumps({"version": 1, "profiles": {"fw01": {}, "lab": {}}}))
        plans = self.forti_home / "state" / "plans"
        plans.mkdir(parents=True)
        (plans / "20261016-120000-a1b2c3.json").write_text("{}")
        for bash in shells:
            with self.subTest(bash=bash):
                self.assertEqual(self.complete(bash, "ge"), ["get"])
                self.assertIn("firewall/address", self.complete(bash, "get", "firewall/addr"))
                self.assertIn("firewall/", self.complete(bash, "get", "fire"))
                self.assertEqual(self.complete(bash, "help", "hist"), ["history"])
                self.assertEqual(self.complete(bash, "-p", ""), ["fw01", "lab"])
                self.assertEqual(self.complete(bash, "get", "--profile", "l"), ["lab"])
                # An option value is skipped when finding the resource argument.
                self.assertIn("firewall/address", self.complete(bash, "get", "--fields", "name", "firewall/addr"))
                self.assertIn("--fields", self.complete(bash, "get", "--fi"))
                self.assertEqual(self.complete(bash, "plan", "sh"), ["show"])
                self.assertEqual(self.complete(bash, "apply", ""), ["20261016-120000-a1b2c3"])
                self.assertEqual(self.complete(bash, "profile", "mode", "lab", "g"), ["guarded"])
                self.assertEqual(self.complete(bash, "completion", "z"), ["zsh"])
                self.assertEqual(self.complete(bash, "history", ""), [])

    def test_zsh(self) -> None:
        zsh = shutil.which("zsh")
        if not zsh:
            self.skipTest("no zsh")
        (self.forti_home / "config.json").write_text(json.dumps({"version": 1, "profiles": {"fw01": {}, "lab": {}}}))

        def complete(*words: str) -> list[str]:
            result = subprocess.run([zsh, "-f", "-c", ZSH_DRIVER, "zsh", str(SCRIPTS / "_forti"), *words],
                                    env=self.env, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stderr, "", " ".join(words))
            return [line for line in result.stdout.splitlines() if line]

        self.assertIn("get", complete("ge"))
        self.assertIn("firewall/address", complete("get", "firewall/addr"))
        self.assertIn("firewall/", complete("get", "fire"))
        self.assertEqual(complete("-p", ""), ["fw01", "lab"])
        self.assertEqual(complete("--profile=l"), ["fw01", "lab"])
        self.assertIn("firewall/address", complete("get", "--fields", "name", "firewall/addr"))
        self.assertIn("--fields", complete("get", "--fi"))
        self.assertEqual(complete("plan", "--file", ""), ["<files>"])
        self.assertEqual(complete("profile", "mode", "lab", ""), ["read-only", "guarded", "autonomous"])

    def test_printed_script_is_the_installed_one(self) -> None:
        for shell, name in (("bash", "forti.bash"), ("zsh", "_forti"), ("fish", "forti.fish")):
            printed = subprocess.run([FORTI, "completion", shell], env=self.env, capture_output=True, text=True, check=True)
            self.assertEqual(printed.stdout, (SCRIPTS / name).read_text(), shell)

    def test_syntax(self) -> None:
        checked = 0
        for shell, name in (("bash", "forti.bash"), ("zsh", "_forti"), ("fish", "forti.fish")):
            program = shutil.which(shell)
            if not program:
                continue
            result = subprocess.run([program, "-n", str(SCRIPTS / name)], capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, f"{shell} -n {name}: {result.stderr}")
            checked += 1
        if not checked:
            self.skipTest("no shell to check")


if __name__ == "__main__":
    if not FORTI:
        sys.exit("FORTI_BINARY is not set")
    unittest.main(verbosity=2)
