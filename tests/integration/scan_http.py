#!/usr/bin/env python3
"""No second HTTP stack: forti-api is the only code that talks to FortiOS.

Scans C/C++ sources outside forti-api (comments stripped, string literals kept) for curl usage, URL
or header building, raw sockets, DNS and TLS libraries, and spawning curl/wget. With --binary, also
checks that the linked executable imports no socket, DNS or TLS symbols of its own: its only network
imports are libcurl's `curl_*`, which the header-only SDK compiles into it.

    scan_http.py --root engine --root src [--binary build/dev/src/cli/forti]

Exit 0 when clean; otherwise every finding is printed as file:line: reason.
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path

SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".mm", ".m"}

# (pattern over comment-free code, reason)
CODE_PATTERNS = [
    (r"#\s*include\s*[<\"]curl/", "includes libcurl"),
    (r"\bcurl_(easy|multi|global|slist|url|share|ws)_\w+", "calls libcurl"),
    (r"\bCURL(OPT|INFO|E|M)_\w+", "uses libcurl options/codes"),
    (r"#\s*include\s*[<\"](sys/socket|netdb|netinet/[\w.]+|openssl/[\w.]+|gnutls/[\w.]+|mbedtls/[\w.]+)", "includes a network/TLS header"),
    (r"(?<![\w.])(::)?(socket|connect|getaddrinfo|gethostbyname|gethostbyname2|sendto|recvfrom)\s*\(", "raw socket or DNS call"),
    (r"\b(SSL_CTX_\w+|SSL_new|SSL_connect|SecTrust\w*|SSLCreateContext|nw_connection_\w+)\b", "TLS API"),
    (r"\b(NSURLSession|NSURLConnection|CFHTTPMessage\w*|CFReadStreamCreateForHTTPRequest|CFStreamCreatePairWithSocket\w*)\b", "Apple networking API"),
    (r"\b(boost::asio|asio::|httplib::|cpr::|Poco::Net|beast::http)\b", "third-party HTTP/network library"),
]
# (pattern over string-literal contents, reason)
STRING_PATTERNS = [
    (r"^\s*https?://|[^\w]https?://", "URL literal"),
    (r"/api/v2", "FortiOS API path literal"),
    (r"^(Authorization|Bearer)\b|Authorization:", "HTTP auth header literal"),
    (r"^(curl|wget)$", "spawns an HTTP client"),
]
# Imported symbols a front-end binary must not have (the SDK's network code is libcurl's).
FORBIDDEN_IMPORTS = re.compile(
    r"^_?(socket|connect|getaddrinfo|gethostbyname2?|getnameinfo|sendto|recvfrom|SSL_\w+|TLS_\w+|"
    r"SecTrust\w+|SSLCreateContext|nw_connection_\w+|CFHTTPMessage\w+|CFStreamCreatePairWithSocket\w*)$")


def lex(text: str) -> tuple[str, list[tuple[int, str]]]:
    """Code with comments blanked (newlines kept), and every string literal with its line number."""
    code: list[str] = []
    strings: list[tuple[int, str]] = []
    i, line, n = 0, 1, len(text)
    while i < n:
        c = text[i]
        if text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
            continue
        if text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            line += text.count("\n", i, j)
            code.append("\n" * text.count("\n", i, j))
            i = j
            continue
        raw = re.match(r'(?:u8|[uUL])?R"([^(\s]{0,16})\(', text[i:i + 24])
        if raw and (i == 0 or not (text[i - 1].isalnum() or text[i - 1] == "_")):
            end = text.find(")" + raw.group(1) + '"', i + raw.end())
            end = n if end < 0 else end
            strings.append((line, text[i + raw.end():end]))
            stop = min(n, end + len(raw.group(1)) + 2)
            line += text.count("\n", i, stop)
            code.append('""' + "\n" * text.count("\n", i, stop))
            i = stop
            continue
        if c in "\"'":
            j = i + 1
            while j < n and text[j] != c and text[j] != "\n":
                j += 2 if text[j] == "\\" else 1
            if c == '"':
                strings.append((line, text[i + 1:j]))
            code.append(c + c)
            i = j + 1
            continue
        if c == "\n":
            line += 1
        code.append(c)
        i += 1
    return "".join(code), strings


def scan_file(path: Path) -> list[str]:
    findings = []
    code, strings = lex(path.read_text(errors="replace"))
    for number, text in enumerate(code.split("\n"), 1):
        for pattern, reason in CODE_PATTERNS:
            if re.search(pattern, text):
                findings.append(f"{path}:{number}: {reason}: {text.strip()[:120]}")
    for number, text in strings:
        for pattern, reason in STRING_PATTERNS:
            if re.search(pattern, text):
                findings.append(f"{path}:{number}: {reason}: \"{text[:120]}\"")
    return findings


def imported_symbols(binary: Path) -> list[str] | None:
    nm = shutil.which("nm")
    if not nm:
        return None
    args = [nm, "-u", str(binary)] if sys.platform == "darwin" else [nm, "-D", "--undefined-only", str(binary)]
    proc = subprocess.run(args, capture_output=True, text=True)
    if proc.returncode != 0:
        return None
    symbols = []
    for line in proc.stdout.splitlines():
        name = line.split()[-1] if line.split() else ""
        symbols.append(name.split("@")[0])
    return symbols


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", action="append", default=[], help="source directory to scan")
    parser.add_argument("--binary", action="append", default=[], help="linked executable to inspect")
    args = parser.parse_args()

    findings: list[str] = []
    files = 0
    for root in map(Path, args.root):
        for path in sorted(root.rglob("*")):
            if path.suffix in SOURCE_SUFFIXES and path.is_file():
                files += 1
                findings += scan_file(path)
    for binary in map(Path, args.binary):
        symbols = imported_symbols(binary)
        if symbols is None:
            print(f"note: cannot list the imports of {binary} (no nm); skipped")
            continue
        bad = sorted({s for s in symbols if FORBIDDEN_IMPORTS.match(s)})
        curl = sorted({s.lstrip("_") for s in symbols if s.lstrip("_").startswith("curl_")})
        findings += [f"{binary}: imports {s}" for s in bad]
        print(f"{binary.name}: {len(symbols)} imported symbols; network imports are libcurl only: {', '.join(curl)}")
    print(f"scanned {files} source files under {', '.join(args.root)}")
    for finding in findings:
        print(finding)
    print("clean: no HTTP, socket, DNS or TLS code outside forti-api" if not findings else f"{len(findings)} finding(s)")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
