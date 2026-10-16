#!/usr/bin/env python3
"""`forti mcp install` at a terminal, the way a person runs it: Enter at every prompt sets up the
~/.forti workspace for every client found (Codex trust included, since the person chose it), probing
each client once. Fake `claude` and `codex` log their calls; HOME and FORTI_HOME are temporary.

    FORTI_BINARY=build/dev/src/cli/forti python3 tests/integration/test_mcp_install.py
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "mock-fortios"))
from harness import binary  # noqa: E402
from test_cli import Terminal  # noqa: E402

FORTI = ""

FAKE_CLIENT = """#!/bin/sh
{ printf '%s' "$(basename "$0")"; for a in "$@"; do printf ' %s' "$a"; done; printf '\\n'; } >> "$FAKE_LOG"
[ "$1" = --version ] && { echo "fake 1.0"; exit 0; }
[ "$1" = mcp ] && [ "$2" = get ] && { echo "Error: No MCP server named 'forti' found." >&2; exit 1; }
echo "unexpected call" >&2; exit 1
"""


class McpInstall(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="forti-mcp-it-")).resolve()
        self.addCleanup(shutil.rmtree, self.root, True)
        self.home = self.root / "home"
        bin_dir = self.root / "bin"
        (self.home / ".codex").mkdir(parents=True)
        bin_dir.mkdir()
        for name, text in (("claude", FAKE_CLIENT), ("codex", FAKE_CLIENT),
                           ("forti-mcp", "#!/bin/sh\necho forti-mcp 0.3.0-test\n")):
            (bin_dir / name).write_text(text)
            (bin_dir / name).chmod(0o755)
        self.log = self.root / "argv.log"
        self.env = {"HOME": str(self.home), "FORTI_HOME": str(self.home / ".forti"),
                    "CLAUDE_CONFIG_DIR": str(self.home / ".claude"), "CODEX_HOME": str(self.home / ".codex"),
                    "PATH": f"{bin_dir}:/usr/bin:/bin", "FAKE_LOG": str(self.log), "NO_COLOR": "1",
                    "FORTI_SECRET_STORE": "file", "TERM": "dumb"}
        for name in ("ASAN_OPTIONS", "UBSAN_OPTIONS"):   # sanitizer builds
            if name in os.environ:
                self.env[name] = os.environ[name]

    def test_enter_at_every_prompt_sets_up_the_workspace(self) -> None:
        term = Terminal([FORTI, "mcp", "install"], self.env)
        term.answer("choice [3]: ", "")                       # all of the above
        term.answer("choice [1]: ", "")                       # the ~/.forti workspace
        explained = term.answer("Trust ~/.forti in Codex? (Y/n): ", "")
        self.assertIn("No: Codex ignores the workspace", explained)
        preview = term.answer("Apply these changes? (Y/n): ", "")
        self.assertIn("create ~/.forti/AGENTS.md", preview)
        self.assertNotIn(str(self.home) + "/.forti/AGENTS.md", preview)
        self.assertEqual(term.finish(), 0, term.text)
        self.assertIn("cd ~/.forti && claude (or codex)", term.text)

        forti = self.home / ".forti"
        for name in ("AGENTS.md", ".mcp.json", ".codex/config.toml", ".claude/settings.json"):
            self.assertTrue((forti / name).exists(), name)
        self.assertIn(f'[projects."{forti}"]', (self.home / ".codex" / "config.toml").read_text())
        calls = self.log.read_text().splitlines()
        self.assertEqual(calls.count("claude --version"), 1, calls)
        self.assertEqual(calls.count("codex --version"), 1, calls)

    def test_no_to_codex_trust_is_explained_once(self) -> None:
        term = Terminal([FORTI, "mcp", "install", "--client", "codex", "--scope", "workspace"], self.env)
        term.answer("Trust ~/.forti in Codex? (Y/n): ", "n")
        preview = term.answer("Apply these changes? (Y/n): ", "")
        self.assertNotIn("only for trusted projects", preview)
        self.assertIn("you answered no", preview)
        self.assertEqual(term.finish(), 0, term.text)
        self.assertFalse((self.home / ".codex" / "config.toml").exists())


def main() -> int:
    global FORTI
    FORTI = binary("FORTI_BINARY")
    program = unittest.main(exit=False, verbosity=2)
    return 0 if program.result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
