#!/usr/bin/env python3
"""Startup, memory and request-latency measurements of `forti` and `forti-mcp` against the mock
FortiOS (tests/mock-fortios). Not a test: it prints a JSON report. Methodology and results live in the
workspace's .claude/context/performance.md.

    python3 tests/perf/bench.py --forti build/rel/src/cli/forti --forti-mcp ../forti-mcp/build/rel/src/forti-mcp

macOS: peak RSS comes from /usr/bin/time -l ("maximum resident set size"); Linux: /usr/bin/time -v.
"Cold" start is the first exec of a fresh copy of the binary (new inode: no dyld launch closure, no
prior exec); dropping the page cache needs root, so the file's pages may still be cached.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "mock-fortios"))
from harness import API_KEY, Sandbox  # noqa: E402

TIME = ["/usr/bin/time", "-l"] if sys.platform == "darwin" else ["/usr/bin/time", "-v"]


def wall(argv: list[str], env: dict[str, str], input: str | None = None) -> float:
    start = time.perf_counter()
    proc = subprocess.run(argv, input=input, capture_output=True, text=True, env=env)
    elapsed = time.perf_counter() - start
    if proc.returncode != 0:
        raise RuntimeError(f"{argv}: exit {proc.returncode}: {proc.stderr[:500]}")
    return elapsed


def median_ms(samples: list[float]) -> dict[str, float]:
    ms = sorted(s * 1000 for s in samples)
    return {"median_ms": round(statistics.median(ms), 2), "min_ms": round(ms[0], 2), "max_ms": round(ms[-1], 2),
            "n": len(ms)}


def peak_rss(argv: list[str], env: dict[str, str], input: str | None = None) -> int:
    proc = subprocess.run(TIME + argv, input=input, capture_output=True, text=True, env=env)
    if proc.returncode != 0:
        raise RuntimeError(f"{argv}: exit {proc.returncode}: {proc.stderr[-800:]}")
    if sys.platform == "darwin":
        match = re.search(r"(\d+)\s+maximum resident set size", proc.stderr)
        return int(match.group(1)) if match else -1
    match = re.search(r"Maximum resident set size \(kbytes\): (\d+)", proc.stderr)
    return int(match.group(1)) * 1024 if match else -1


def startup(binary: str, args: list[str], env: dict[str, str], runs: int, input: str | None = None) -> dict:
    cold = []
    with tempfile.TemporaryDirectory() as tmp:
        for i in range(5):
            copy = Path(tmp) / f"copy{i}" / Path(binary).name
            copy.parent.mkdir()
            shutil.copy2(binary, copy)
            cold.append(wall([str(copy), *args], env, input))
    for _ in range(3):
        wall([binary, *args], env, input)
    warm = [wall([binary, *args], env, input) for _ in range(runs)]
    return {"cold_first_exec": median_ms(cold), "warm": median_ms(warm)}


def mcp_lines(*messages: dict) -> str:
    return "".join(json.dumps(m) + "\n" for m in messages)


INIT = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "bench", "version": "1"}}}
LIST = {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--forti", required=True)
    parser.add_argument("--forti-mcp", required=True)
    parser.add_argument("--runs", type=int, default=30)
    args = parser.parse_args()
    report: dict = {}

    with Sandbox(forti=args.forti, forti_mcp=args.forti_mcp) as sb:
        env = sb.env
        assert sb.configure(mode="autonomous").code == 0
        sb.mock.seed_addresses(1000)
        forti, mcp = args.forti, args.forti_mcp

        report["startup"] = {
            "forti --version": startup(forti, ["--version"], env, args.runs),
            "forti discover firewall/address (offline)": startup(forti, ["discover", "firewall/address"], env, args.runs),
            "forti-mcp initialize + tools/list": startup(mcp, [], env, args.runs, mcp_lines(INIT, LIST)),
        }

        ops = [{"op": "create", "resource": "firewall/address",
                "object": {"name": f"bench-{i:02d}", "subnet": f"198.51.100.{i} 255.255.255.255"}} for i in range(20)]
        plan_input = json.dumps({"operations": ops})
        rss = {
            "forti --version": peak_rss([forti, "--version"], env),
            "forti get firewall/address --count 1000 (1000 objects)": peak_rss(
                [forti, "get", "firewall/address", "--count", "1000", "--json"], env),
            "forti plan (20 creates)": peak_rss([forti, "plan", "--file", "-", "--json"], env, plan_input),
        }
        plan = subprocess.run([forti, "plan", "--file", "-", "--json"], input=plan_input, capture_output=True,
                              text=True, env=env)
        plan_id = json.loads(plan.stdout)["data"]["id"]
        rss["forti apply (20 creates, verified)"] = peak_rss([forti, "apply", plan_id, "--json"], env)
        read_1000 = {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                     "params": {"name": "forti_read", "arguments": {"resource": "firewall/address", "count": 1000}}}
        rss["forti-mcp initialize + tools/list"] = peak_rss([mcp], env, mcp_lines(INIT, LIST))
        rss["forti-mcp read 1000 objects (48 KiB budget)"] = peak_rss([mcp], env, mcp_lines(INIT, read_1000))
        report["peak_rss_mib"] = {k: round(v / 1048576, 1) for k, v in rss.items()}

        # One request, process to process: curl (same libcurl family) vs forti.
        url = f"https://localhost:{sb.mock.port}/api/v2/monitor/system/status"
        curl = ["/usr/bin/curl", "-sS", "-o", "/dev/null", "--cacert", str(sb.mock.ca_path),
                "-H", f"Authorization: Bearer {API_KEY}", url]
        get = [forti, "get", "monitor/system/status", "--json"]
        for argv in (curl, get):
            for _ in range(3):
                wall(argv, env)
        sb.mock.clear_requests()
        curl_t = [wall(curl, env) for _ in range(args.runs)]
        curl_requests = len(sb.mock.requests)
        sb.mock.clear_requests()
        forti_t = [wall(get, env) for _ in range(args.runs)]
        forti_requests = len(sb.mock.requests)
        report["one_request_process"] = {
            "curl": median_ms(curl_t), "forti get": median_ms(forti_t),
            "overhead_ms": round((statistics.median(forti_t) - statistics.median(curl_t)) * 1000, 2),
            "requests_per_run": {"curl": curl_requests / args.runs, "forti": forti_requests / args.runs}}

        # Warm connection: N requests in one curl process (keep-alive) vs N forti_read calls in one
        # forti-mcp session (each also crosses JSON-RPC over pipes and the engine).
        n = 50
        many = [a for a in curl[:-1] if a not in ("-o", "/dev/null")] + ["-w", "%{time_total}\\n"]
        for _ in range(n):
            many += ["-o", "/dev/null", url]
        timing = subprocess.run(many, capture_output=True, text=True)
        per_curl = [float(x) for x in timing.stdout.split()]
        session = sb.mcp()
        session.initialize()
        session.call("forti_read", {"resource": "monitor/system/status"})
        per_mcp = []
        for _ in range(n):
            start = time.perf_counter()
            result = session.call("forti_read", {"resource": "monitor/system/status"})
            per_mcp.append(time.perf_counter() - start)
            assert not result["isError"], result
        session.close()
        report["warm_request"] = {
            "curl keep-alive transfer": median_ms(per_curl[1:]),
            "forti-mcp forti_read round trip": median_ms(per_mcp),
            "overhead_ms": round((statistics.median(per_mcp) - statistics.median(per_curl[1:])) * 1000, 2)}

    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
