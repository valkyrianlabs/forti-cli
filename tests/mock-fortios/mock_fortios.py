#!/usr/bin/env python3
"""A small, stateful mock of the FortiOS 7.4 REST API (v2), for end-to-end tests of the real `forti`
and `forti-mcp` binaries through libcurl and TLS. Python 3 standard library only.

* HTTPS only, on 127.0.0.1 and an ephemeral port. `make_pki()` creates a throwaway CA and a server
  certificate for "localhost" / 127.0.0.1 with `openssl`; clients verify it through a `ca_bundle`.
* `Authorization: Bearer <api key>` is required (401 otherwise).
* cmdb: `firewall/address` (string keys), `firewall/policy` (integer keys assigned on create),
  `system.dhcp/server` (integer keys) and the singleton `system/global`: GET (list with
  start/count/format/filter, keyed, 404), POST, PUT, DELETE, `?action=schema`. The DHCP servers'
  `reserved-address` is also served on FortiOS's child paths (`.../server/<id>/reserved-address[/<id>]`:
  GET, POST with a device-assigned id, PUT, DELETE, 404s) with the reply shapes FortiOS 7.4.8 sends
  (observed live by forti-api): POST `mkey` = the new entry's key and no `child_mkey`; PUT `mkey` = the
  parent's key, `child_mkey` = the entry's key as text; DELETE `mkey` = the entry's key, `child_mkey`
  as text; GET `mkey` = the parent's key; a missing entry is 404 with `child_path`, a missing parent
  404 without it. Writes carry revision, old_revision and revision_changed. Monitor: `system/status`,
  `system/config/backup` (plain text), `system/dhcp` (leases) with the action `system/dhcp/revoke`
  ({"ip": [...]}), the threat-feed push `system/external-resource/dynamic` ({"commands": [{"name", "command":
  snapshot|add|remove, "entries"}]}: HTTP 200 with one results entry per command, {"status": "error",
  "message": "Connect pending"} for a feed in `.pending_feeds`, as FortiOS answers before it has loaded a
  feed), and an untyped list (`firewall/session-count-list`, not in the SDK registry).
* Faults the test controls (`MockFortiOS.drop_after_write()`, `.error_after_create()`,
  `.fail_status_after_write()`, `.normalize`), and a record of every request (`.requests`).

Used in-process by the integration tests (`with MockFortiOS(tmp) as mock: ...`) or standalone
(`python3 mock_fortios.py --dir DIR [--addresses N]`), which prints one JSON line with the port and
CA path and serves until stdin closes or SIGTERM.
"""

from __future__ import annotations

import copy
import ipaddress
import json
import os
import socket
import ssl
import subprocess
import sys
import threading
import uuid as uuidlib
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qsl, unquote, urlsplit

SERIAL = "FGT60FTK20000000"
VERSION = "v7.4.8"
BUILD = 2795
# In every configuration backup the mock serves, so tests can prove backups never reach any output.
BACKUP_MARKER = "mock-backup-content-7d1e"


def have_openssl() -> bool:
    try:
        subprocess.run(["openssl", "version"], check=True, capture_output=True)
        return True
    except (OSError, subprocess.CalledProcessError):
        return False


def make_pki(directory: Path) -> tuple[Path, Path, Path]:
    """A throwaway CA and a server certificate signed by it. Returns (ca.pem, server.pem, server.key)."""
    directory.mkdir(parents=True, exist_ok=True)
    ca_key, ca_pem = directory / "ca.key", directory / "ca.pem"
    key, csr, pem = directory / "server.key", directory / "server.csr", directory / "server.pem"
    ext = directory / "server.ext"

    def run(*args: str) -> None:
        subprocess.run(["openssl", *args], check=True, capture_output=True)

    run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj", "/CN=forti mock test CA",
        "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        "-keyout", str(ca_key), "-out", str(ca_pem))
    run("req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost", "-keyout", str(key), "-out", str(csr))
    ext.write_text("basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
                   "extendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n")
    run("x509", "-req", "-in", str(csr), "-CA", str(ca_pem), "-CAkey", str(ca_key), "-CAcreateserial",
        "-days", "2", "-extfile", str(ext), "-out", str(pem))
    return ca_pem, pem, key


# ---- the device model ----

def _addr_children() -> dict[str, Any]:
    def unitary(name: str, kind: str, help_: str, **extra: Any) -> dict[str, Any]:
        return {"name": name, "category": "unitary", "type": kind, "help": help_, **extra}
    return {
        "name": unitary("name", "string", "Address name.", size=79, required=True),
        "uuid": unitary("uuid", "uuid", "Universally Unique Identifier."),
        "subnet": unitary("subnet", "ipv4-classnet-any", "IP address and subnet mask of address."),
        "type": unitary("type", "option", "Type of address.",
                        options=[{"name": n} for n in ("ipmask", "iprange", "fqdn", "geography", "wildcard")]),
        "fqdn": unitary("fqdn", "string", "Fully Qualified Domain Name address.", size=255),
        "comment": unitary("comment", "var-string", "Comment.", size=255),
        "color": unitary("color", "integer", "Color of icon on the GUI.", **{"min-value": 0, "max-value": 32}),
    }


def _policy_children() -> dict[str, Any]:
    def unitary(name: str, kind: str, help_: str, **extra: Any) -> dict[str, Any]:
        return {"name": name, "category": "unitary", "type": kind, "help": help_, **extra}

    def ref_table(name: str, help_: str) -> dict[str, Any]:
        return {"name": name, "category": "table", "help": help_, "mkey": "name", "mkey_type": "string",
                "children": {"name": unitary("name", "string", "Name.", size=79)}}
    return {
        "policyid": unitary("policyid", "integer", "Policy ID.", **{"min-value": 0, "max-value": 4294967294}),
        "name": unitary("name", "string", "Policy name.", size=35),
        "status": unitary("status", "option", "Enable or disable this policy.",
                          options=[{"name": "enable"}, {"name": "disable"}]),
        "srcintf": ref_table("srcintf", "Incoming (ingress) interface."),
        "dstintf": ref_table("dstintf", "Outgoing (egress) interface."),
        "srcaddr": ref_table("srcaddr", "Source IPv4 address and address group names."),
        "dstaddr": ref_table("dstaddr", "Destination IPv4 address and address group names."),
        "service": ref_table("service", "Service and service group names."),
        "action": unitary("action", "option", "Policy action.",
                          options=[{"name": n} for n in ("accept", "deny", "ipsec")]),
        "schedule": unitary("schedule", "string", "Schedule name.", size=35),
        "comments": unitary("comments", "var-string", "Comment.", size=1023),
    }


def _global_children() -> dict[str, Any]:
    return {
        "hostname": {"name": "hostname", "category": "unitary", "type": "string", "help": "FortiGate unit's hostname.",
                     "size": 35},
        "admintimeout": {"name": "admintimeout", "category": "unitary", "type": "integer",
                         "help": "Number of minutes before an idle administrator session times out.",
                         "min-value": 1, "max-value": 480},
        "admin-sport": {"name": "admin-sport", "category": "unitary", "type": "integer",
                        "help": "Administrative access port for HTTPS.", "min-value": 1, "max-value": 65535},
        "timezone": {"name": "timezone", "category": "unitary", "type": "string", "help": "Timezone database name."},
    }


def _dhcp_children() -> dict[str, Any]:
    def unitary(name: str, kind: str, help_: str, **extra: Any) -> dict[str, Any]:
        return {"name": name, "category": "unitary", "type": kind, "help": help_, **extra}
    return {
        "id": unitary("id", "integer", "ID.", **{"min-value": 0, "max-value": 4294967295}),
        "interface": unitary("interface", "string", "DHCP server can assign IP configurations to clients connected to this interface."),
        "lease-time": unitary("lease-time", "integer", "Lease time in seconds, 0 means unlimited."),
        "reserved-address": {"name": "reserved-address", "category": "table", "mkey": "id", "mkey_type": "integer",
                             "help": "Options for the DHCP server to assign IP settings to specific MAC addresses.",
                             "children": {"id": unitary("id", "integer", "ID."), "ip": unitary("ip", "ipv4-address", "IP address."),
                                          "mac": unitary("mac", "mac-address", "MAC address."),
                                          "description": unitary("description", "var-string", "Description.")}},
    }


def _reservation_defaults() -> dict[str, Any]:
    return {"id": 0, "type": "mac", "ip": "0.0.0.0", "mac": "00:00:00:00:00:00", "action": "reserved",
            "circuit-id-type": "string", "circuit-id": "", "remote-id-type": "string", "remote-id": "", "description": ""}


@dataclass
class ChildSpec:
    """A table attribute FortiOS serves on child paths: cmdb/<path>/<parent key>/<attribute>[/<entry key>]."""
    mkey: str                      # the entry key ("id")
    numeric: bool
    defaults: Callable[[], dict[str, Any]]


@dataclass
class TableSpec:
    path: str                      # "firewall/address"
    mkey: str                      # "name" / "policyid"
    numeric: bool
    help: str
    children: dict[str, Any]
    defaults: Callable[[], dict[str, Any]]
    child_tables: dict[str, ChildSpec] = field(default_factory=dict)


TABLES: dict[str, TableSpec] = {
    "firewall/address": TableSpec(
        "firewall/address", "name", False, "Configure IPv4 addresses.", _addr_children(),
        lambda: {"uuid": str(uuidlib.uuid4()), "subnet": "0.0.0.0 0.0.0.0", "type": "ipmask", "fqdn": "",
                 "comment": "", "color": 0, "associated-interface": "", "allow-routing": "disable"}),
    "firewall/policy": TableSpec(
        "firewall/policy", "policyid", True, "Configure IPv4/IPv6 policies.", _policy_children(),
        lambda: {"uuid": str(uuidlib.uuid4()), "name": "", "status": "enable", "srcintf": [], "dstintf": [],
                 "srcaddr": [], "dstaddr": [], "service": [], "action": "deny", "schedule": "always",
                 "comments": "", "logtraffic": "utm"}),
    "system.dhcp/server": TableSpec(
        "system.dhcp/server", "id", True, "Configure DHCP servers.", _dhcp_children(),
        lambda: {"status": "enable", "lease-time": 604800, "interface": "", "default-gateway": "0.0.0.0",
                 "netmask": "0.0.0.0", "dns-service": "default", "ip-range": [], "reserved-address": []},
        {"reserved-address": ChildSpec("id", True, _reservation_defaults)}),
}
SINGLETONS = {"system/global": ("Configure global attributes.", _global_children())}


def _cidr_to_mask(value: Any) -> Any:
    """FortiOS stores `subnet` as "address netmask": 192.0.2.0/24 reads back as 192.0.2.0 255.255.255.0."""
    if not isinstance(value, str):
        return value
    text = value.strip()
    try:
        if "/" in text:
            net = ipaddress.ip_interface(text)
            return f"{net.ip} {net.network.netmask}"
        if " " not in text:
            return f"{ipaddress.ip_address(text)} 255.255.255.255"
    except ValueError:
        return value
    return value


def _matches(obj: dict[str, Any], clause: str) -> bool:
    for op in ("==", "!=", "=@", "!@"):
        at = clause.find(op)
        if at > 0:
            name, want = clause[:at], clause[at + 2:]
            have = obj.get(name)
            have_text = have if isinstance(have, str) else json.dumps(have)
            if op == "==":
                return have_text == want
            if op == "!=":
                return have_text != want
            if op == "=@":
                return want in have_text
            return want not in have_text
    return False


def _project(obj: dict[str, Any], fields: list[str] | None) -> dict[str, Any]:
    if not fields:
        return obj
    out = {k: v for k, v in obj.items() if k in fields}
    if "q_origin_key" in obj:
        out["q_origin_key"] = obj["q_origin_key"]
    return out


@dataclass
class Request:
    """One request as it arrived. `status` is None when the mock dropped the connection."""
    method: str
    path: str                               # "/api/v2/cmdb/firewall/address/web"
    query: list[tuple[str, str]]
    body: str
    authorized: bool
    connection: int
    status: int | None = None
    client_cn: str | None = None            # CN of the TLS client certificate, when one was presented

    @property
    def api(self) -> str:                   # "cmdb/firewall/address/web"
        return self.path.removeprefix("/api/v2/")

    def param(self, name: str) -> str | None:
        for key, value in self.query:
            if key == name:
                return value
        return None

    def json(self) -> Any:
        return json.loads(self.body) if self.body else None

    def as_dict(self) -> dict[str, Any]:
        return {"method": self.method, "path": self.path, "query": self.query, "body": self.body,
                "authorized": self.authorized, "connection": self.connection, "status": self.status}


@dataclass
class Fault:
    kind: str                               # "drop" | "error" | "drop_status"
    method: str | None = None
    api_prefix: str | None = None
    apply: bool = True                      # perform the mutation before misbehaving
    status: int = 500
    times: int = 1                          # -1: until cleared

    def hits(self, method: str, api: str) -> bool:
        return (self.method is None or self.method == method) and (self.api_prefix is None or api.startswith(self.api_prefix))


class Device:
    """The configuration state, guarded by one lock."""

    def __init__(self) -> None:
        self.tables: dict[str, dict[str, dict[str, Any]]] = {path: {} for path in TABLES}
        self.singletons: dict[str, dict[str, Any]] = {
            "system/global": {"hostname": "fw-mock", "admintimeout": 5, "admin-sport": 443, "timezone": "UTC",
                              "gui-theme": "jade"}}
        self.revision = 1
        self.next_policy_id = 1
        self.leases: list[dict[str, Any]] = []   # monitor/system/dhcp
        self.feeds: dict[str, list[str]] = {}    # pushed threat-feed entries, by feed name
        self.pending_feeds: set[str] = set()     # feeds FortiOS has not loaded yet ("Connect pending")

    def bump(self) -> None:
        self.revision += 1


class MockFortiOS:
    """The mock device and its HTTPS server. Use as a context manager, or start()/stop()."""

    def __init__(self, workdir: Path | str, api_key: str = "mock-api-key", serial: str = SERIAL,
                 version: str = VERSION, build: int = BUILD) -> None:
        self.workdir = Path(workdir)
        self.api_key = api_key
        self.serial, self.version, self.build = serial, version, build
        self.device = Device()
        self.normalize = True
        self.requests: list[Request] = []
        self.faults: list[Fault] = []
        self.lock = threading.RLock()
        self.ca_path: Path | None = None
        self.port = 0
        self._context: ssl.SSLContext | None = None
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._connections = 0
        self.monitors: dict[str, Callable[[], Any]] = {
            # Not in the SDK's typed monitor registry: read untyped.
            "firewall/session-count-list": lambda: [
                {"vdom": "root", "count": 100 + i, "id": i} for i in range(5)],
            "system/dhcp": lambda: copy.deepcopy(self.device.leases),
        }

    # ---- lifecycle ----

    def start(self) -> "MockFortiOS":
        ca, cert, key = make_pki(self.workdir / "pki")
        self.ca_path = ca
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(str(cert), str(key))
        self._context = context
        mock = self

        class Handler(_Handler):
            owner = mock

        server = _Server(("127.0.0.1", 0), Handler)
        server.daemon_threads = True
        # Handshake in the per-connection thread, so one stalled client cannot block accept().
        server.socket = context.wrap_socket(server.socket, server_side=True, do_handshake_on_connect=False)
        self._server = server
        self.port = server.server_address[1]
        self._thread = threading.Thread(target=server.serve_forever, name="mock-fortios", daemon=True)
        self._thread.start()
        return self

    def require_client_certificate(self, ca_file: Path | str) -> None:
        """Like peer-auth for the API user: from now on, every connection needs a TLS client certificate
        issued by `ca_file` (a handshake without one fails)."""
        assert self._context, "start() first"
        self._context.load_verify_locations(str(ca_file))
        self._context.verify_mode = ssl.CERT_REQUIRED

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None

    def __enter__(self) -> "MockFortiOS":
        return self.start()

    def __exit__(self, *exc: Any) -> None:
        self.stop()

    # ---- state the tests set up and inspect ----

    def add_address(self, name: str, subnet: str = "192.0.2.1 255.255.255.255", **attrs: Any) -> dict[str, Any]:
        with self.lock:
            obj = TABLES["firewall/address"].defaults()
            obj.update({"name": name, "q_origin_key": name, "subnet": _cidr_to_mask(subnet), **attrs})
            self.device.tables["firewall/address"][name] = obj
            self.device.bump()
            return obj

    def seed_addresses(self, count: int, prefix: str = "host-") -> None:
        for i in range(count):
            self.add_address(f"{prefix}{i:05d}", f"10.{(i >> 16) & 255}.{(i >> 8) & 255}.{i & 255} 255.255.255.255",
                             comment=f"seeded address {i}")

    def add_policy(self, **attrs: Any) -> dict[str, Any]:
        with self.lock:
            obj = TABLES["firewall/policy"].defaults()
            obj.update(attrs)
            pid = int(obj.get("policyid") or self.device.next_policy_id)
            self.device.next_policy_id = max(self.device.next_policy_id, pid + 1)
            obj["policyid"] = pid
            obj["q_origin_key"] = pid
            self.device.tables["firewall/policy"][str(pid)] = obj
            self.device.bump()
            return obj

    def add_dhcp_server(self, server_id: int, **attrs: Any) -> dict[str, Any]:
        with self.lock:
            obj = TABLES["system.dhcp/server"].defaults()
            obj.update(attrs)
            obj.update({"id": server_id, "q_origin_key": server_id})
            obj["reserved-address"] = [dict(_reservation_defaults(), **entry, **{"q_origin_key": entry["id"]})
                                       for entry in obj["reserved-address"]]
            self.device.tables["system.dhcp/server"][str(server_id)] = obj
            self.device.bump()
            return copy.deepcopy(obj)

    def reservations(self, server_id: int) -> dict[int, dict[str, Any]]:
        """The server's reserved-address entries by id (a copy)."""
        with self.lock:
            server = self.device.tables["system.dhcp/server"][str(server_id)]
            return {entry["id"]: copy.deepcopy(entry) for entry in server["reserved-address"]}

    def set_reservation_attr(self, server_id: int, entry_id: int, attr: str, value: Any) -> None:
        """Change one reservation behind the client's back (drift of a child table entry)."""
        with self.lock:
            server = self.device.tables["system.dhcp/server"][str(server_id)]
            next(e for e in server["reserved-address"] if e["id"] == entry_id)[attr] = value
            self.device.bump()

    def add_lease(self, ip: str, mac: str, server_mkey: int = 1, **attrs: Any) -> None:
        with self.lock:
            self.device.leases.append({"ip": ip, "mac": mac, "hostname": "", "expire_time": 1924992000, "status": "leased",
                                       "reserved": False, "interface": "internal", "type": "ipv4",
                                       "server_mkey": server_mkey, **attrs})

    def table(self, path: str) -> dict[str, dict[str, Any]]:
        with self.lock:
            return copy.deepcopy(self.device.tables[path])

    def singleton(self, path: str) -> dict[str, Any]:
        with self.lock:
            return copy.deepcopy(self.device.singletons[path])

    def set_attr(self, path: str, key: str | None, attr: str, value: Any) -> None:
        """Change the device behind the client's back (drift)."""
        with self.lock:
            target = self.device.singletons[path] if key is None else self.device.tables[path][key]
            target[attr] = value
            self.device.bump()

    def writes(self) -> list[Request]:
        with self.lock:
            return [r for r in self.requests if r.method != "GET"]

    def clear_requests(self) -> None:
        with self.lock:
            self.requests.clear()

    # ---- faults ----

    def drop_after_write(self, method: str | None = None, api_prefix: str | None = None, apply: bool = True,
                         times: int = 1) -> None:
        """Read the whole write request, (optionally) perform it, then close the connection unanswered."""
        with self.lock:
            self.faults.append(Fault("drop", method, api_prefix, apply, times=times))

    def error_after_create(self, api_prefix: str, status: int = 500, times: int = 1) -> None:
        """Create the object, then answer with a FortiOS error (creates are not transactional)."""
        with self.lock:
            self.faults.append(Fault("error", "POST", api_prefix, True, status, times))

    def fail_request(self, method: str | None, api_prefix: str, status: int = 403, times: int = 1) -> None:
        """Answer matching requests with a FortiOS error envelope and do nothing else."""
        with self.lock:
            self.faults.append(Fault("fail", method, api_prefix, False, status, times))

    def fail_status_after_write(self) -> None:
        """Once a write arrives, every later monitor/system/status request is dropped until cleared."""
        with self.lock:
            self.faults.append(Fault("drop_status_armed", times=-1))

    def clear_faults(self) -> None:
        with self.lock:
            self.faults.clear()

    def _take_fault(self, kind: str, method: str, api: str) -> Fault | None:
        with self.lock:
            for fault in self.faults:
                if fault.kind == kind and fault.hits(method, api):
                    if fault.times > 0:
                        fault.times -= 1
                        if fault.times == 0:
                            self.faults.remove(fault)
                    return fault
            return None

    def _arm_status_faults(self) -> None:
        with self.lock:
            for fault in self.faults:
                if fault.kind == "drop_status_armed":
                    fault.kind = "drop"
                    fault.method, fault.api_prefix, fault.apply = "GET", "monitor/system/status", False

    # ---- envelopes ----

    def envelope(self, method: str, api: str, status: int = 200, **extra: Any) -> dict[str, Any]:
        parts = api.split("/")
        out: dict[str, Any] = {"http_method": method}
        out.update(extra)
        out.update({"vdom": "root", "path": parts[1] if len(parts) > 1 else "",
                    "name": parts[2] if len(parts) > 2 else "", "action": "",
                    "status": "success" if status < 400 else "error", "http_status": status,
                    "serial": self.serial, "version": self.version, "build": self.build})
        return out


class _Server(ThreadingHTTPServer):
    def handle_error(self, request: Any, client_address: Any) -> None:
        # A client that rejects the certificate or hangs up is part of the tests, not a mock failure.
        if isinstance(sys.exc_info()[1], (ssl.SSLError, ConnectionError, TimeoutError)):
            return
        super().handle_error(request, client_address)


class _Handler(BaseHTTPRequestHandler):
    owner: MockFortiOS
    protocol_version = "HTTP/1.1"          # keep-alive, like FortiOS: libcurl reuses the connection
    server_version = "xxxxxxxx-xxxxx"      # FortiOS hides its server header
    sys_version = ""

    def setup(self) -> None:
        self.request.settimeout(30)
        self.request.do_handshake()
        self.client_cn = None
        peer = self.request.getpeercert()
        for rdn in (peer or {}).get("subject", ()):
            for key, value in rdn:
                if key == "commonName":
                    self.client_cn = value
        with self.owner.lock:
            self.owner._connections += 1
            self.connection_id = self.owner._connections
        super().setup()

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - quiet: tests read records instead
        pass

    def do_GET(self) -> None:
        self._serve("GET")

    def do_POST(self) -> None:
        self._serve("POST")

    def do_PUT(self) -> None:
        self._serve("PUT")

    def do_DELETE(self) -> None:
        self._serve("DELETE")

    # ---- plumbing ----

    def _reply(self, record: Request, status: int, body: Any, content_type: str = "application/json") -> None:
        data = body.encode() if isinstance(body, str) else json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
        record.status = status

    def _drop(self) -> None:
        """Close the TCP connection without a reply (no TLS close_notify either)."""
        self.close_connection = True
        try:
            self.connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def _serve(self, method: str) -> None:
        mock = self.owner
        split = urlsplit(self.path)
        query = parse_qsl(split.query, keep_blank_values=True)
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode() if length else ""
        authorized = self.headers.get("Authorization") == f"Bearer {mock.api_key}"
        record = Request(method, split.path, query, body, authorized, self.connection_id, client_cn=self.client_cn)
        with mock.lock:
            mock.requests.append(record)

        if not split.path.startswith("/api/v2/"):
            return self._reply(record, 404, mock.envelope(method, "", 404))
        api = split.path.removeprefix("/api/v2/")
        if not authorized:
            return self._reply(record, 401, mock.envelope(method, api, 401))

        if failure := mock._take_fault("fail", method, api):
            return self._reply(record, failure.status, mock.envelope(method, api, failure.status, error=-37))
        if method != "GET":
            mock._arm_status_faults()
        drop = mock._take_fault("drop", method, api)
        if drop and not drop.apply:
            return self._drop()
        error = mock._take_fault("error", method, api) if method == "POST" else None

        try:
            status, reply, content_type = self._dispatch(method, api, query, body)
        except Exception as exc:  # a mock bug must surface as a 500, not a hung client
            status, reply, content_type = 500, mock.envelope(method, api, 500, error=-1, mock_error=repr(exc)), "application/json"
        if drop:
            return self._drop()
        if error and status < 400:
            reply = mock.envelope(method, api, error.status, error=-1, cli_error=["mock: injected failure after create"])
            status = error.status
        self._reply(record, status, reply, content_type)

    # ---- FortiOS semantics ----

    def _dispatch(self, method: str, api: str, query: list[tuple[str, str]], body: str) -> tuple[int, Any, str]:
        mock = self.owner
        params = dict(query)
        if api.startswith("monitor/"):
            return self._monitor(method, api.removeprefix("monitor/"), params, body)
        if not api.startswith("cmdb/"):
            return 404, mock.envelope(method, api, 404), "application/json"
        rest = api.removeprefix("cmdb/")
        for path in SINGLETONS:
            if rest == path:
                return self._singleton(method, path, params, body)
        for path in TABLES:
            if rest == path or rest.startswith(path + "/"):
                # Each key is one encoded segment: a raw '/' separates the parent key, a child table
                # attribute and an entry key (an encoded %2F stays inside its key).
                segments = rest[len(path) + 1:].split("/") if rest != path else []
                spec = TABLES[path]
                if len(segments) in (2, 3) and segments[1] in spec.child_tables:
                    entry = unquote(segments[2]) if len(segments) == 3 else None
                    return self._child(method, spec, unquote(segments[0]), segments[1], entry, query, body)
                if len(segments) > 1:
                    return 404, mock.envelope(method, api, 404, error=-3), "application/json"
                key = unquote(segments[0]) if segments else None
                return self._table(method, spec, key, query, body)
        return 404, mock.envelope(method, api, 404, error=-3), "application/json"

    def _schema(self, method: str, api: str, name: str, help_: str, children: dict[str, Any],
                table: TableSpec | None) -> tuple[int, Any, str]:
        results: dict[str, Any] = {"name": name, "category": "table" if table else "complex", "help": help_,
                                   "children": children}
        if table:
            results.update({"mkey": table.mkey, "mkey_type": "integer" if table.numeric else "string",
                            "max_table_size_vdom": 0})
        return 200, self.owner.envelope(method, api, results=results), "application/json"

    def _singleton(self, method: str, path: str, params: dict[str, str], body: str) -> tuple[int, Any, str]:
        mock = self.owner
        api = "cmdb/" + path
        with mock.lock:
            state = mock.device.singletons[path]
            if method == "GET":
                if params.get("action") == "schema":
                    help_, children = SINGLETONS[path]
                    return self._schema(method, api, path.split("/")[-1], help_, children, None)
                fields = params["format"].split("|") if params.get("format") else None
                return 200, mock.envelope(method, api, revision=str(mock.device.revision),
                                          results=_project(copy.deepcopy(state), fields)), "application/json"
            if method == "PUT":
                change = json.loads(body or "{}")
                if not isinstance(change, dict):
                    return 400, mock.envelope(method, api, 400, error=-651), "application/json"
                state.update(change)
                mock.device.bump()
                return 200, mock.envelope(method, api, revision=str(mock.device.revision), revision_changed=True), "application/json"
        return 405, mock.envelope(method, api, 405, error=-1), "application/json"

    def _table(self, method: str, spec: TableSpec, key: str | None, query: list[tuple[str, str]],
               body: str) -> tuple[int, Any, str]:
        mock = self.owner
        api = "cmdb/" + spec.path
        params = dict(query)
        with mock.lock:
            rows = mock.device.tables[spec.path]
            if method == "GET":
                if params.get("action") == "schema":
                    return self._schema(method, api, spec.path.split("/")[-1], spec.help, spec.children, spec)
                fields = params["format"].split("|") if params.get("format") else None
                if key is not None:
                    obj = rows.get(key)
                    if obj is None:
                        return 404, mock.envelope(method, api, 404, mkey=key), "application/json"
                    return 200, mock.envelope(method, api, revision=str(mock.device.revision), mkey=key,
                                              results=[_project(copy.deepcopy(obj), fields)]), "application/json"
                items = list(rows.values())
                for expression in (v for k, v in query if k == "filter"):
                    clauses = expression.split(",")
                    items = [o for o in items if any(_matches(o, c) for c in clauses)]
                matched = len(items)
                start = int(params.get("start", 0))
                count = int(params["count"]) if "count" in params else matched
                page = items[start:start + count]
                extra: dict[str, Any] = {"revision": str(mock.device.revision), "size": len(page),
                                         "matched_count": matched, "next_idx": start + len(page) - 1,
                                         "limit_reached": start + count < matched}
                return 200, mock.envelope(method, api, **extra,
                                          results=[_project(copy.deepcopy(o), fields) for o in page]), "application/json"

            if method == "POST":
                if key is not None:
                    return 405, mock.envelope(method, api, 405, error=-1), "application/json"
                obj = json.loads(body or "{}")
                if not isinstance(obj, dict):
                    return 400, mock.envelope(method, api, 400, error=-651), "application/json"
                if spec.numeric:
                    pid = int(obj.get(spec.mkey) or 0) or mock.device.next_policy_id
                    if str(pid) in rows:
                        return 500, mock.envelope(method, api, 500, error=-5), "application/json"
                    mock.device.next_policy_id = max(mock.device.next_policy_id, pid + 1)
                    obj[spec.mkey] = pid
                    mkey: Any = pid
                else:
                    mkey = obj.get(spec.mkey)
                    if not mkey:
                        return 500, mock.envelope(method, api, 500, error=-651,
                                                  cli_error=[f"{spec.mkey}: required"]), "application/json"
                    if mkey in rows:
                        return 500, mock.envelope(method, api, 500, error=-5), "application/json"
                stored = spec.defaults()
                stored.update(obj)
                stored["q_origin_key"] = mkey
                if mock.normalize and "subnet" in stored:
                    stored["subnet"] = _cidr_to_mask(stored["subnet"])
                rows[str(mkey)] = stored
                mock.device.bump()
                return 200, mock.envelope(method, api, revision=str(mock.device.revision), revision_changed=True,
                                          old_revision=str(mock.device.revision - 1), mkey=mkey), "application/json"

            if key is None:
                return 405, mock.envelope(method, api, 405, error=-1), "application/json"
            if key not in rows:
                return 404, mock.envelope(method, api, 404, error=-3, mkey=key), "application/json"

            if method == "PUT":
                change = json.loads(body or "{}")
                if not isinstance(change, dict):
                    return 400, mock.envelope(method, api, 400, error=-651), "application/json"
                if spec.mkey in change and str(change[spec.mkey]) != key:
                    return 500, mock.envelope(method, api, 500, error=-1, cli_error=["mock: rename unsupported"]), "application/json"
                rows[key].update(change)
                if mock.normalize and "subnet" in change:
                    rows[key]["subnet"] = _cidr_to_mask(rows[key]["subnet"])
                mock.device.bump()
                return 200, mock.envelope(method, api, revision=str(mock.device.revision), revision_changed=True,
                                          mkey=rows[key][spec.mkey]), "application/json"

            if method == "DELETE":
                mkey = rows[key][spec.mkey]
                del rows[key]
                mock.device.bump()
                return 200, mock.envelope(method, api, revision=str(mock.device.revision), revision_changed=True,
                                          mkey=mkey), "application/json"
        return 405, mock.envelope(method, api, 405, error=-1), "application/json"

    def _child(self, method: str, spec: TableSpec, parent: str, attribute: str, entry_key: str | None,
               query: list[tuple[str, str]], body: str) -> tuple[int, Any, str]:
        """One child table: the entries of `attribute` of object `parent`, kept inside the parent (so a
        read of the parent shows them). Reply shapes as FortiOS 7.4.8 sends them (module docstring)."""
        mock = self.owner
        child = spec.child_tables[attribute]
        api = "cmdb/" + spec.path
        params = dict(query)
        parent_mkey: Any = int(parent) if spec.numeric and parent.isdigit() else parent

        def reply(status: int, **extra: Any) -> tuple[int, Any, str]:
            fields: dict[str, Any] = {"mkey": parent_mkey, "child_path": attribute}
            fields.update(extra)
            return status, mock.envelope(method, api, status, **fields), "application/json"

        def written(**extra: Any) -> tuple[int, Any, str]:
            mock.device.bump()
            return reply(200, revision=str(mock.device.revision), old_revision=str(mock.device.revision - 1),
                         revision_changed=True, **extra)

        with mock.lock:
            owner = mock.device.tables[spec.path].get(parent)
            if owner is None:   # a missing parent: 404 without child_path; nothing is ever created
                return 404, mock.envelope(method, api, 404, mkey=parent_mkey), "application/json"
            entries: list[dict[str, Any]] = owner.setdefault(attribute, [])

            def find(key: str) -> dict[str, Any] | None:
                return next((e for e in entries if str(e.get(child.mkey)) == key), None)

            if method == "GET":
                fields = params["format"].split("|") if params.get("format") else None
                if entry_key is not None:
                    found = find(entry_key)
                    if found is None:
                        return reply(404)
                    return reply(200, revision=str(mock.device.revision), child_mkey=found[child.mkey],
                                 results=[_project(copy.deepcopy(found), fields)])
                items = list(entries)
                for expression in (v for k, v in query if k == "filter"):
                    clauses = expression.split(",")
                    items = [o for o in items if any(_matches(o, c) for c in clauses)]
                return reply(200, revision=str(mock.device.revision), size=len(items),
                             results=[_project(copy.deepcopy(o), fields) for o in items])

            if method == "POST":
                if entry_key is not None:
                    return reply(405, error=-1)
                obj = json.loads(body or "{}")
                if not isinstance(obj, dict):
                    return reply(400, error=-651)
                if child.numeric:
                    wanted = int(obj.get(child.mkey) or 0)
                    key: Any = wanted or max((int(e[child.mkey]) for e in entries), default=0) + 1   # 0: highest + 1
                else:
                    key = obj.get(child.mkey)
                    if not key:
                        return reply(500, error=-651, cli_error=[f"{child.mkey}: required"])
                if find(str(key)) is not None:   # a POST never overwrites
                    return reply(500, revision=str(mock.device.revision), error=-5)
                stored = child.defaults()
                stored.update(obj)
                stored[child.mkey] = key
                stored["q_origin_key"] = key
                entries.append(stored)
                return written(mkey=key)          # the NEW ENTRY's key, and no child_mkey

            if entry_key is None:
                return reply(405, error=-1)
            found = find(entry_key)
            if found is None:                     # never created by a PUT or DELETE
                return reply(404)
            if method == "PUT":
                change = json.loads(body or "{}")
                if not isinstance(change, dict):
                    return reply(400, error=-651)
                if child.mkey in change and str(change[child.mkey]) != entry_key:
                    return reply(500, error=-1, cli_error=["mock: rename unsupported"])
                found.update(change)
                return written(child_mkey=str(found[child.mkey]))
            if method == "DELETE":
                entries.remove(found)
                return written(mkey=found[child.mkey], child_mkey=str(found[child.mkey]))
        return reply(405, error=-1)

    def _monitor(self, method: str, path: str, params: dict[str, str], body: str = "") -> tuple[int, Any, str]:
        mock = self.owner
        api = "monitor/" + path
        if method == "POST" and path == "system/dhcp/revoke":
            # {"ip": ["192.0.2.50", ...]} (fortinet.fortios fortios_monitor, selector revoke.system.dhcp).
            # What FortiOS does without "ip" is not documented: the mock refuses it rather than guess.
            request = json.loads(body or "{}")
            ips = request.get("ip") if isinstance(request, dict) else None
            if not isinstance(ips, list) or not all(isinstance(ip, str) for ip in ips):
                return 400, mock.envelope(method, api, 400, error=-651), "application/json"
            with mock.lock:
                mock.device.leases = [lease for lease in mock.device.leases if lease["ip"] not in ips]
            return 200, mock.envelope(method, api, results={}), "application/json"
        if method == "POST" and path == "system/external-resource/dynamic":
            request = json.loads(body or "{}")
            commands = request.get("commands") if isinstance(request, dict) else None
            if not isinstance(commands, list):
                return 400, mock.envelope(method, api, 400, error=-651), "application/json"
            results = []
            with mock.lock:
                for command in commands:
                    name, verb = command.get("name"), command.get("command")
                    entries = command.get("entries", [])
                    if name in mock.device.pending_feeds:
                        results.append({"name": name, "status": "error", "message": "Connect pending"})
                        continue
                    feed = mock.device.feeds.setdefault(name, [])
                    if verb == "snapshot":
                        feed[:] = list(entries)
                    elif verb == "add":
                        feed.extend(entry for entry in entries if entry not in feed)
                    elif verb == "remove":
                        feed[:] = [entry for entry in feed if entry not in entries]
                    else:
                        results.append({"name": name, "status": "error", "message": "invalid command"})
                        continue
                    results.append({"name": name, "status": "success"})
            return 200, mock.envelope(method, api, results=results), "application/json"
        if method == "GET" and path == "system/status":
            return 200, mock.envelope(method, api, results={
                "model_name": "FortiGate", "model_number": "60F", "model": "FGT60F", "hostname": "fw-mock",
                "log_disk_status": "available"}), "application/json"
        if method == "GET" and path == "system/config/backup":
            text = (f"#config-version=FGT60F-7.4.8-FW-build{mock.build}-250101:opmode=0:vdom=0:user=api\n"
                    "#conf_file_ver=1\n#buildno=2795\n#global_vdom=1\nconfig system global\n"
                    f"    set hostname \"{mock.device.singletons['system/global'].get('hostname', '')}\"\n"
                    f"    set post-login-banner \"{BACKUP_MARKER}\"\nend\n")
            return 200, text, "text/plain"
        if method == "GET" and path in mock.monitors:
            return 200, mock.envelope(method, api, results=mock.monitors[path]()), "application/json"
        return 404, mock.envelope(method, api, 404, error=-3), "application/json"


def main(argv: list[str]) -> int:
    import argparse
    import signal

    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--dir", required=True, help="working directory for the throwaway PKI")
    parser.add_argument("--api-key", default="mock-api-key")
    parser.add_argument("--addresses", type=int, default=0, help="seed this many firewall addresses")
    args = parser.parse_args(argv)
    mock = MockFortiOS(args.dir, api_key=args.api_key)
    mock.seed_addresses(args.addresses)
    mock.start()
    print(json.dumps({"port": mock.port, "ca": str(mock.ca_path), "pid": os.getpid()}), flush=True)
    done = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: done.set())
    threading.Thread(target=lambda: (sys.stdin.read(), done.set()), daemon=True).start()
    done.wait()
    mock.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
