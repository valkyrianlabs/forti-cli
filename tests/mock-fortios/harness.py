"""Shared fixtures for the real-binary integration tests of forti-cli and forti-mcp.

`Sandbox` owns a temporary directory with FORTI_CONFIG_DIR / FORTI_STATE_DIR / FORTI_CACHE_DIR, a
throwaway HOME and XDG directories, and a running `MockFortiOS`. The API key reaches the binaries
only through an environment-variable reference (`api_key: {"source": "env", ...}`), so no keychain
or credential file is ever touched. `forti()` runs the CLI; `mcp()` starts a `forti-mcp` session.

Meson runs the suites with exit status 77 (skipped) when openssl is missing; see `require_tools()`.
"""

from __future__ import annotations

import json
import os
import select
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from mock_fortios import MockFortiOS, have_openssl  # noqa: E402

SKIP = 77                                   # Meson's "test skipped" exit status
KEY_VAR = "FORTI_IT_API_KEY"
# Distinctive, so a leak is easy to find in any output, plan, audit record or log.
API_KEY = "it-secret-9f3c1a7e5b2d4c6e8a0b"


def require_tools() -> None:
    if not have_openssl():
        print("SKIP: openssl is not available", file=sys.stderr)
        sys.exit(SKIP)


def binary(variable: str) -> str:
    path = os.environ.get(variable)
    if not path or not os.access(path, os.X_OK):
        print(f"SKIP: {variable} is not set to an executable", file=sys.stderr)
        sys.exit(SKIP)
    return path


@dataclass
class Result:
    code: int
    out: str
    err: str

    def json(self) -> Any:
        return json.loads(self.out)


class Sandbox:
    """Temporary directories, environment and a mock device. Use as a context manager."""

    def __init__(self, forti: str | None = None, forti_mcp: str | None = None) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="forti-it-"))
        self.forti_bin = forti
        self.mcp_bin = forti_mcp
        self.mock = MockFortiOS(self.root / "mock", api_key=API_KEY)
        self.config = self.root / "config"
        self.state = self.root / "state"
        self.cache = self.root / "cache"
        home = self.root / "home"
        home.mkdir()
        self.env = {
            "PATH": "/usr/bin:/bin",
            "HOME": str(home),
            "FORTI_CONFIG_DIR": str(self.config),
            "FORTI_STATE_DIR": str(self.state),
            "FORTI_CACHE_DIR": str(self.cache),
            "XDG_CONFIG_HOME": str(home / ".config"),
            "XDG_STATE_HOME": str(home / ".local/state"),
            "XDG_CACHE_HOME": str(home / ".cache"),
            "FORTI_SECRET_STORE": "file",    # belt and braces: never the login keychain
            "NO_COLOR": "1",
            "USER": "integration",
            KEY_VAR: API_KEY,
        }

    def __enter__(self) -> "Sandbox":
        self.mock.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.mock.stop()
        shutil.rmtree(self.root, ignore_errors=True)

    # ---- forti ----

    def forti(self, *args: str, input: str | None = None, env: dict[str, str] | None = None,
              timeout: float = 60) -> Result:
        assert self.forti_bin, "no forti binary"
        proc = subprocess.run([self.forti_bin, *args], input=input, capture_output=True, text=True,
                              env={**self.env, **(env or {})}, timeout=timeout)
        return Result(proc.returncode, proc.stdout, proc.stderr)

    def configure(self, profile: str = "lab", mode: str = "read-only", *extra: str) -> Result:
        return self.forti("configure", "--profile", profile, "--host", "localhost", "--port", str(self.mock.port),
                          "--ca-bundle", str(self.mock.ca_path), "--api-key-env", KEY_VAR, "--mode", mode, *extra)

    def set_mode(self, mode: str, profile: str = "lab") -> None:
        result = self.forti("profile", "mode", profile, mode)
        assert result.code == 0, result.err

    def plan(self, request: dict[str, Any] | list[Any]) -> Result:
        return self.forti("plan", "--file", "-", "--json", input=json.dumps(request))

    # ---- forti-mcp ----

    def mcp(self, *args: str) -> "McpSession":
        assert self.mcp_bin, "no forti-mcp binary"
        return McpSession([self.mcp_bin, *args], self.env)

    # ---- inspection ----

    def audit(self) -> list[dict[str, Any]]:
        path = self.state / "audit.jsonl"
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]

    def all_files_text(self) -> str:
        """Everything under config, state and cache, for leak checks."""
        chunks = []
        for base in (self.config, self.state, self.cache):
            for path in sorted(base.rglob("*")) if base.exists() else []:
                if path.is_file():
                    chunks.append(path.read_text(errors="replace"))
        return "\n".join(chunks)


class McpSession:
    """A running forti-mcp: one JSON-RPC request line in, one response line out."""

    def __init__(self, argv: list[str], env: dict[str, str]) -> None:
        self.proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     env=env, text=True, bufsize=1)
        self.next_id = 1
        self.stderr = ""

    def __enter__(self) -> "McpSession":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def close(self) -> int:
        if self.proc.stdin and not self.proc.stdin.closed:
            self.proc.stdin.close()
        try:
            code = self.proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            code = self.proc.wait()
        assert self.proc.stdout and self.proc.stderr
        rest = self.proc.stdout.read()
        assert rest == "", f"unexpected output after the last response: {rest[:200]!r}"
        self.stderr += self.proc.stderr.read()
        self.proc.stdout.close()
        self.proc.stderr.close()
        return code

    def send(self, message: dict[str, Any]) -> None:
        assert self.proc.stdin
        self.proc.stdin.write(json.dumps(message) + "\n")
        self.proc.stdin.flush()

    def receive(self, timeout: float = 60) -> dict[str, Any]:
        assert self.proc.stdout
        ready, _, _ = select.select([self.proc.stdout], [], [], timeout)
        if not ready:
            raise TimeoutError("forti-mcp did not answer")
        line = self.proc.stdout.readline()
        if not line:
            raise EOFError(f"forti-mcp closed stdout (exit {self.proc.poll()})")
        message = json.loads(line)
        assert message.get("jsonrpc") == "2.0", line
        return message

    def request(self, method: str, params: dict[str, Any] | None = None, modern: bool = False) -> dict[str, Any]:
        message: dict[str, Any] = {"jsonrpc": "2.0", "id": self.next_id, "method": method}
        self.next_id += 1
        params = dict(params or {})
        if modern:
            params["_meta"] = {"io.modelcontextprotocol/protocolVersion": "2026-07-28",
                               "io.modelcontextprotocol/clientCapabilities": {},
                               "io.modelcontextprotocol/clientInfo": {"name": "forti-it", "version": "1"}}
        if params:
            message["params"] = params
        self.send(message)
        response = self.receive()
        assert response.get("id") == message["id"], response
        return response

    def initialize(self, version: str = "2025-11-25") -> dict[str, Any]:
        response = self.request("initialize", {"protocolVersion": version, "capabilities": {},
                                               "clientInfo": {"name": "forti-it", "version": "1"}})
        self.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        return response

    def call(self, tool: str, arguments: dict[str, Any], modern: bool = False) -> dict[str, Any]:
        """tools/call; returns the result object (isError, structuredContent, content)."""
        response = self.request("tools/call", {"name": tool, "arguments": arguments}, modern=modern)
        assert "result" in response, response
        return response["result"]


def wait_for(predicate, timeout: float = 10.0) -> bool:  # type: ignore[no-untyped-def]
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return False
