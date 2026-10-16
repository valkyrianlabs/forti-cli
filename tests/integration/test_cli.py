#!/usr/bin/env python3
"""End-to-end tests of the real `forti` binary against the mock FortiOS (tests/mock-fortios), through
libcurl and verified TLS. Every test gets its own mock device and temporary config/state/cache
directories; the API key comes from an environment variable reference.

    FORTI_BINARY=build/dev/src/cli/forti python3 tests/integration/test_cli.py [-k pattern]
"""

from __future__ import annotations

import json
import os
import pty
import select
import stat
import sys
import time
import unittest
import warnings
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "mock-fortios"))
from harness import API_KEY, KEY_VAR, Sandbox, binary, require_tools  # noqa: E402
from mock_fortios import BACKUP_MARKER  # noqa: E402

FORTI = ""

ADDRESS = {"name": "web", "subnet": "192.0.2.10 255.255.255.255", "comment": "web server"}


def create_address(obj=None):  # type: ignore[no-untyped-def]
    return {"op": "create", "resource": "firewall/address", "object": obj or ADDRESS}


class CliTest(unittest.TestCase):
    mode = "read-only"

    def setUp(self) -> None:
        self.sb = Sandbox(forti=FORTI).__enter__()
        self.addCleanup(self.sb.__exit__, None, None, None)
        self.outputs: list[str] = []
        result = self.sb.configure(mode=self.mode)
        self.assertEqual(result.code, 0, result.err)
        self.mock = self.sb.mock

    def tearDown(self) -> None:
        # The API key never appears in any output or any file the binaries wrote; configuration
        # backups never appear in any output or in the audit log.
        for text in self.outputs + [self.sb.all_files_text()]:
            self.assertNotIn(API_KEY, text)
        for text in self.outputs + [json.dumps(self.sb.audit())]:
            self.assertNotIn(BACKUP_MARKER, text)

    def forti(self, *args: str, input: str | None = None, expect: int | None = 0):  # type: ignore[no-untyped-def]
        result = self.sb.forti(*args, input=input)
        self.outputs += [result.out, result.err]
        if expect is not None:
            self.assertEqual(result.code, expect, f"forti {' '.join(args)}\nstdout: {result.out}\nstderr: {result.err}")
        return result

    def json_of(self, *args: str, expect: int = 0, input: str | None = None):  # type: ignore[no-untyped-def]
        return self.forti(*args, "--json", input=input, expect=expect).json()

    def plan(self, *operations, expect: int = 0):  # type: ignore[no-untyped-def]
        envelope = self.json_of("plan", "--file", "-", input=json.dumps({"operations": list(operations)}), expect=expect)
        return envelope

    def writes(self) -> list:  # type: ignore[type-arg]
        return self.mock.writes()


class Setup(CliTest):
    def test_configure_saves_an_env_reference_and_doctor_passes(self) -> None:
        config = json.loads((self.sb.config / "config.json").read_text())
        profile = config["profiles"]["lab"]
        self.assertEqual(profile["api_key"], {"source": "env", "env": KEY_VAR})
        self.assertEqual(profile["mode"], "read-only")
        self.assertEqual(stat.S_IMODE(os.stat(self.sb.config / "config.json").st_mode), 0o600)
        # configure verified the device through the SDK: one authorized GET of monitor/system/status.
        self.assertEqual([(r.method, r.api, r.authorized) for r in self.mock.requests],
                         [("GET", "monitor/system/status", True)])

        doctor = self.json_of("doctor")
        checks = {c["check"]: c["status"] for c in doctor["data"]["checks"]}
        for name in ("config", "profile", "secrets", "tls_files", "connection", "auth", "version"):
            self.assertEqual(checks.get(name), "pass", doctor)

    def test_configure_with_a_wrong_key_saves_nothing(self) -> None:
        result = self.sb.forti("configure", "--profile", "bad", "--host", "localhost", "--port", str(self.mock.port),
                               "--ca-bundle", str(self.mock.ca_path), "--api-key-env", "WRONG_KEY",
                               env={"WRONG_KEY": "not-the-key"})
        self.outputs += [result.out, result.err]
        self.assertEqual(result.code, 4, result.err)
        self.assertNotIn("bad", json.loads((self.sb.config / "config.json").read_text())["profiles"])
        self.assertNotIn("not-the-key", result.out + result.err)
        self.assertEqual(self.mock.requests[-1].status, 401)

    def test_tls_verification_is_on(self) -> None:
        # The same device without the CA bundle (system trust store): the certificate is refused.
        result = self.sb.forti("configure", "--profile", "notrust", "--host", "localhost", "--port",
                               str(self.mock.port), "--api-key-env", KEY_VAR, "--json")
        self.outputs += [result.out, result.err]
        self.assertEqual(result.code, 4, result.out)
        self.assertEqual(result.json()["error"]["code"], "connection")
        # 127.0.0.1 is in the certificate; "127.0.0.2" resolves to the mock but is not: refused as well.
        bad_name = self.sb.forti("configure", "--profile", "badname", "--host", "forti-it.invalid", "--port",
                                 str(self.mock.port), "--resolve-ip", "127.0.0.1", "--ca-bundle",
                                 str(self.mock.ca_path), "--api-key-env", KEY_VAR, "--json")
        self.outputs += [bad_name.out, bad_name.err]
        self.assertEqual(bad_name.code, 4, bad_name.out)
        self.assertTrue(all(r.authorized for r in self.mock.requests))


class Terminal:
    """`forti` on a pseudo-terminal, as an operator at the keyboard sees it: prompts go to /dev/tty."""

    def __init__(self, argv: list[str], env: dict[str, str]) -> None:
        with warnings.catch_warnings():
            # The mock's server thread makes this process multi-threaded; the child only calls execve.
            warnings.simplefilter("ignore", DeprecationWarning)
            self.pid, self.fd = pty.fork()
        if self.pid == 0:  # child
            os.execve(argv[0], argv, env)
        self.text = ""
        self.pos = 0

    def expect(self, needle: str, timeout: float = 60) -> str:
        """Reads until `needle` appears after the previous match; returns the text up to it."""
        deadline = time.monotonic() + timeout
        while needle not in self.text[self.pos:]:
            remaining = deadline - time.monotonic()
            ready = select.select([self.fd], [], [], max(remaining, 0))[0] if remaining > 0 else []
            if not ready:
                raise AssertionError(f"timed out waiting for {needle!r}; the terminal shows:\n{self.text[-3000:]}")
            try:
                data = os.read(self.fd, 4096)
            except OSError:
                data = b""
            if not data:
                raise AssertionError(f"forti exited before {needle!r}; the terminal shows:\n{self.text[-3000:]}")
            self.text += data.decode(errors="replace").replace("\r\n", "\n")
        at = self.text.index(needle, self.pos)
        before = self.text[self.pos:at]
        self.pos = at + len(needle)
        return before

    def answer(self, prompt: str, reply: str) -> str:
        before = self.expect(prompt)
        os.write(self.fd, (reply + "\n").encode())
        return before

    def answer_hidden(self, prompt: str, reply: str) -> str:
        """A hidden prompt switches echo off with TCSAFLUSH, which drops anything typed before it."""
        before = self.expect(prompt)
        time.sleep(0.3)
        os.write(self.fd, (reply + "\n").encode())
        return before

    def finish(self, timeout: float = 60) -> int:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if select.select([self.fd], [], [], 0.2)[0]:
                try:
                    data = os.read(self.fd, 4096)
                except OSError:
                    data = b""
                self.text += data.decode(errors="replace").replace("\r\n", "\n")
            pid, status = os.waitpid(self.pid, os.WNOHANG)
            if pid:
                try:
                    while select.select([self.fd], [], [], 0.1)[0]:
                        data = os.read(self.fd, 4096)
                        if not data:
                            break
                        self.text += data.decode(errors="replace").replace("\r\n", "\n")
                except OSError:
                    pass
                os.close(self.fd)
                return os.waitstatus_to_exitcode(status)
        os.kill(self.pid, 9)
        raise AssertionError(f"forti did not exit; the terminal shows:\n{self.text[-3000:]}")


class InteractiveConfigure(CliTest):
    """forti configure at a terminal: address, key, certificate, mode; check; then the name."""

    def start(self, *args: str) -> Terminal:
        return Terminal([FORTI, "configure", *args], self.sb.env)

    def checks(self) -> list:  # type: ignore[type-arg]
        """The connection checks (configure also lists the VDOMs after one succeeds)."""
        return [r for r in self.mock.requests if r.api == "monitor/system/status"]

    def address(self, term: Terminal, trust: bool = True) -> str:
        """The mock's certificate comes from a private CA: forti shows it and asks (trust on first use)."""
        term.answer("FortiGate address (name or IP, optionally :port): ", f"localhost:{self.mock.port}")
        shown = term.answer("Trust this certificate for this FortiGate? (y/N): ", "y" if trust else "")
        self.assertIn("is not trusted", shown)
        self.assertIn("SHA-256", shown)
        self.assertIn("DNS:localhost", shown)
        return shown

    def address_and_key(self, term: Terminal, have_key: bool = True) -> str:
        self.address(term)
        steps = term.answer("Do you have a REST API key for this FortiGate? (Y/n): ", "" if have_key else "n")
        term.answer_hidden("API key: ", f"env:{KEY_VAR}")
        return steps

    def name_it(self, term: Terminal, name: str) -> None:
        term.answer("Profile name [fw-mock]: ", name)
        term.answer("Make it the default profile? (y/N): ", "n")

    def test_create_then_reuse_a_certificate(self) -> None:
        home = Path(self.sb.env["FORTI_HOME"])
        term = self.start()
        term.answer("Start from lab's settings (mode read-only)? (Y/n): ", "n")
        self.address_and_key(term)
        term.answer("Use a client certificate? (y/N): ", "y")
        term.answer("choice [1]: ", "")                    # New certificate: issued by the forti CA
        term.answer("Certificate name [", "fw01")
        term.expect("done")
        term.answer("Mode [1]: ", "")
        steps = term.expect("Press Enter when the FortiGate is ready")
        for keyword in ("config vpn certificate ca", "-----BEGIN CERTIFICATE-----", 'set cn "forti-fw01"',
                        "set peer-auth enable", "once per FortiGate"):
            self.assertIn(keyword, steps)
        # The operator does the steps: from now on the device requires a certificate from the forti CA.
        self.mock.require_client_certificate(home / "ca" / "ca.crt")
        os.write(term.fd, b"\n")
        self.name_it(term, "fw01")
        self.assertEqual(term.finish(), 0, term.text)
        self.assertIn('Saved profile "fw01"', term.text)
        self.assertIn('client cert  certificate "fw01"', term.text)
        self.assertEqual(self.checks()[-1].client_cn, "forti-fw01")
        self.assertEqual(self.checks()[-1].status, 200)
        profile = json.loads((self.sb.config / "config.json").read_text())["profiles"]["fw01"]
        self.assertEqual(profile["client_cert"], str(home / "certs" / "fw01" / "client.p12"))
        self.assertEqual(profile["cert_password"], {"source": "file", "path": str(home / "certs" / "fw01" / "client.pass")})
        self.assertEqual(profile["api_key"], {"source": "env", "env": KEY_VAR})
        # The trusted certificate is pinned: the device's own certificate is the CA bundle.
        pinned = Path(profile["ca_bundle"])
        self.assertEqual(pinned.parent, home / "tls")
        self.assertIn("BEGIN CERTIFICATE", pinned.read_text())

        # A profile without the certificate no longer gets through; fw01 does.
        self.assertNotEqual(self.forti("doctor", "--profile", "lab", expect=None).code, 0)
        self.json_of("doctor", "--profile", "fw01")

        # A second FortiGate starts from fw01's settings: its certificate comes along.
        self.forti("profile", "default", "fw01")
        term = self.start()
        term.answer("Start from fw01's settings (mode read-only, its client certificate)? (Y/n): ", "")
        self.address_and_key(term)
        term.expect('Client certificate: "fw01" (as fw01)')
        term.expect("Mode: read-only (as fw01")
        term.expect("Press Enter when the FortiGate is ready")
        os.write(term.fd, b"\n")
        term.answer("Profile name [fw-mock]: ", "fw02")
        term.answer("Make it the default profile? (y/N): ", "n")
        self.assertEqual(term.finish(), 0, term.text)
        self.assertEqual(self.checks()[-1].client_cn, "forti-fw01")
        listed = self.json_of("cert", "list")["data"]["certificates"]
        self.assertEqual([(c["name"], c["used_by"]) for c in listed], [("fw01", ["fw01", "fw02"])])

    def test_reuse_from_the_list_and_skip_the_check(self) -> None:
        self.forti("cert", "create", "spare", "--own-ca")
        term = self.start("--advanced")
        term.answer("FortiGate address (name or IP, optionally :port): ", f"localhost:{self.mock.port}")
        term.answer("VDOM", "")
        term.answer("CA bundle, PEM", str(self.mock.ca_path))
        term.answer("Connect to this IP instead", "")
        steps = term.answer("Do you have a REST API key for this FortiGate? (Y/n): ", "n")
        term.answer_hidden("API key: ", f"env:{KEY_VAR}")
        term.answer("Use a client certificate? (y/N): ", "y")
        term.answer("Reuse a certificate you already have? (Y/n): ", "")
        listing = term.answer("Certificate [1]: ", "")
        self.assertIn("1) spare  own CA, until", listing)
        term.answer("Mode [1]: ", "2")
        term.expect("Press Enter when the FortiGate is ready")
        os.write(term.fd, b"s\n")
        term.answer("Profile name [localhost]: ", "fw03")
        term.answer("Make it the default profile? (y/N): ", "")
        self.assertEqual(term.finish(), 0, term.text)
        self.assertIn("not checked", term.text)
        # Without a key, forti printed the FortiOS commands that make one.
        for keyword in ("config system accprofile", "config system api-user", "set accprofile \"forti\"",
                        "config trusthost", "execute api-user generate-key forti"):
            self.assertIn(keyword, term.text)
        shown = self.json_of("cert", "show", "spare")["data"]
        self.assertEqual(shown["used_by"], ["fw03"])
        profile = json.loads((self.sb.config / "config.json").read_text())["profiles"]["fw03"]
        self.assertEqual(profile["mode"], "guarded")
        self.assertEqual(profile["port"], self.mock.port)

    def test_a_rejected_key_is_typed_again_never_retried_alone(self) -> None:
        term = self.start()
        term.answer("Start from lab's settings (mode read-only)? (Y/n): ", "n")
        self.address(term, trust=False)   # declined: the check fails on TLS, and the menu offers fixes
        term.answer("Do you have a REST API key for this FortiGate? (Y/n): ", "")
        term.answer_hidden("API key: ", "wrong-key")
        term.answer("Use a client certificate? (y/N): ", "")
        term.answer("Mode [1]: ", "")
        menu = term.answer("choice [1]: ", "3")
        self.assertIn("is not trusted", menu)
        self.assertIn("3) use a CA bundle", menu)
        term.answer("CA bundle, PEM: ", str(self.mock.ca_path))
        menu = term.expect("choice [1]: ")
        self.assertIn("did not accept the API key", menu)
        statuses = [r.status for r in self.checks()]
        self.assertEqual(statuses[-1], 401)
        self.assertEqual(statuses.count(401), 1)   # never retried on its own
        os.write(term.fd, b"1\n")
        term.answer_hidden("API key: ", f"env:{KEY_VAR}")
        self.name_it(term, "fw04")
        self.assertEqual(term.finish(), 0, term.text)
        self.assertEqual([r.status for r in self.checks()[-2:]], [401, 200])


class Discover(CliTest):
    def test_offline_discovery_makes_no_request(self) -> None:
        self.mock.clear_requests()
        found = self.json_of("discover", "firewall/addr")
        self.assertIn("firewall/address", [r["resource"] for r in found["data"]])
        resource = self.json_of("discover", "firewall/address")
        self.assertEqual(resource["data"]["key"], "name")
        self.assertIn("subnet", [f["name"] for f in resource["data"]["fields"]])
        self.assertEqual(self.mock.requests, [])

    def test_live_discovery_merges_the_device_schema(self) -> None:
        self.mock.clear_requests()
        data = self.json_of("discover", "firewall/address", "--fields", "type,comment", "--live")
        self.assertTrue(data["meta"]["live"])
        self.assertEqual(data["data"]["live_help"], "Configure IPv4 addresses.")
        by_name = {f["name"]: f for f in data["data"]["fields"]}
        self.assertEqual(by_name["type"]["options"], ["ipmask", "iprange", "fqdn", "geography", "wildcard"])
        self.assertEqual(by_name["comment"]["size"], 255)
        self.assertEqual([(r.method, r.api, r.query) for r in self.mock.requests],
                         [("GET", "cmdb/firewall/address", [("action", "schema")])])

    def test_capabilities(self) -> None:
        data = self.json_of("discover", "--live", "system/global")["data"]
        self.assertEqual(data["live_help"], "Configure global attributes.")


class Get(CliTest):
    def setUp(self) -> None:
        super().setUp()
        self.mock.seed_addresses(120)
        self.mock.clear_requests()

    def test_list_pages_on_the_device(self) -> None:
        first = self.json_of("get", "firewall/address", "--count", "50")
        self.assertEqual(len(first["data"]), 50)
        self.assertEqual(first["meta"]["next_start"], 50)
        last = self.json_of("get", "firewall/address", "--start", "100", "--count", "50")
        self.assertEqual([o["name"] for o in last["data"]], [f"host-{i:05d}" for i in range(100, 120)])
        self.assertNotIn("next_start", last["meta"])
        self.assertEqual(self.mock.requests[0].query, [("start", "0"), ("count", "50")])
        self.assertEqual(self.mock.requests[1].query, [("start", "100"), ("count", "50")])

    def test_fields_and_filter(self) -> None:
        data = self.json_of("get", "firewall/address", "--fields", "name,subnet", "--filter", "name==host-00007")
        self.assertEqual(data["data"], [{"name": "host-00007", "q_origin_key": "host-00007",
                                         "subnet": "10.0.0.7 255.255.255.255"}])
        self.assertEqual(self.mock.requests[-1].query,
                         [("format", "name|subnet"), ("filter", "name==host-00007"), ("start", "0"), ("count", "50")])

    def test_unknown_filter_attribute_is_refused_before_any_request(self) -> None:
        data = self.json_of("get", "firewall/address", "--filter", "nosuch==1", expect=6)
        self.assertEqual(data["error"]["code"], "validation")
        self.assertEqual(self.mock.requests, [])

    def test_resources_by_cli_words_tail_and_path(self) -> None:
        # The same object, four ways: path and key, CLI words, the last word alone, the object's path.
        for spelling in (["firewall/address", "host-00003"], ["firewall", "address", "host-00003"],
                         ["address", "host-00003"], ["firewall/address/host-00003"]):
            one = self.json_of("get", *spelling)
            self.assertEqual(one["data"]["name"], "host-00003", spelling)
            self.assertEqual(one["meta"]["resource"], "firewall/address")
            self.assertEqual(one["meta"]["key"], "host-00003")
            self.assertEqual(self.mock.requests[-1].api, "cmdb/firewall/address/host-00003")
        self.assertEqual(self.json_of("get", "system", "global")["data"]["hostname"], "fw-mock")
        self.assertEqual(self.json_of("get", "firewall", "address", "--count", "3")["meta"]["returned"], 3)
        # A key with '/' after the table's path.
        self.json_of("get", "firewall/address/LAN 10.0.0.0/24", expect=5)
        self.assertEqual(self.mock.requests[-1].api, "cmdb/firewall/address/LAN%2010.0.0.0%2F24")

    def test_ambiguous_and_doubled_spellings_are_refused_before_any_request(self) -> None:
        ambiguous = self.forti("get", "policy", expect=5)
        for name in ("firewall/policy", "router/policy"):
            self.assertIn(name, ambiguous.err)
        twice = self.forti("get", "firewall/address/host-00001", "host-00002", expect=2)
        self.assertIn("key is given twice", twice.err)
        self.forti("get", "firewall", "address", "a", "b", expect=2)
        self.assertEqual(self.mock.requests, [])

    def test_unknown_attributes_get_suggestions(self) -> None:
        typo = self.forti("get", "firewall/address", "--fields", "name,colour", expect=6)
        self.assertIn("did you mean color", typo.err)
        data = self.json_of("get", "firewall/address", "--filter", "subnett==x", expect=6)
        self.assertIn("subnet", data["error"]["details"]["suggestions"])
        self.assertEqual(self.mock.requests, [])

    def test_all_reads_every_page(self) -> None:
        every = self.json_of("get", "address", "--all", "--count", "50")
        self.assertEqual([o["name"] for o in every["data"]], [f"host-{i:05d}" for i in range(120)])
        self.assertEqual(every["meta"]["returned"], 120)
        self.assertTrue(every["meta"]["all"])
        self.assertNotIn("next_start", every["meta"])
        self.assertEqual([r.query[-2:] for r in self.mock.requests],
                         [[("start", "0"), ("count", "50")], [("start", "50"), ("count", "50")],
                          [("start", "100"), ("count", "50")]])
        # Without --count, pages of 1000: one request here.
        self.mock.clear_requests()
        self.assertEqual(len(self.json_of("get", "firewall/address", "--all")["data"]), 120)
        self.assertEqual(len(self.mock.requests), 1)
        # Monitors window their results in the engine; --all reads them whole too.
        untyped = self.json_of("get", "monitor/firewall/session-count-list", "--count", "2", "--all")
        self.assertEqual(len(untyped["data"]), 5)
        self.assertNotIn("truncated", untyped["meta"])
        self.forti("get", "firewall/address", "host-00001", "--all", expect=2)
        self.forti("get", "firewall/address", "--all", "--start", "5", expect=2)

    def test_more_results_are_announced_on_stderr_only(self) -> None:
        text = self.forti("get", "firewall/address")
        self.assertEqual(len([line for line in text.out.splitlines() if line.startswith("host-")]), 50)
        self.assertNotIn("more results", text.out)
        self.assertIn("more results: --start 50, or --all", text.err)
        piped = self.forti("get", "firewall/address", "--json")
        self.assertEqual(json.loads(piped.out)["meta"]["next_start"], 50)
        self.assertIn("--all", piped.err)
        last = self.forti("get", "firewall/address", "--start", "100")
        self.assertEqual(last.err, "")
        window = self.forti("get", "monitor/firewall/session-count-list", "--count", "2")
        self.assertNotIn("more results", window.out)
        self.assertIn("more results: --start 2", window.err)
        self.assertEqual(self.forti("get", "address", "--all").err, "")

    def test_discover_takes_cli_words(self) -> None:
        shown = self.json_of("discover", "firewall", "address")
        self.assertEqual(shown["data"]["resource"], "firewall/address")
        self.assertEqual(self.json_of("discover", "firewall", "service", "custom")["data"]["resource"], "firewall.service/custom")

    def test_keyed_singleton_monitor_and_404(self) -> None:
        one = self.json_of("get", "firewall/address", "host-00003")
        self.assertEqual(one["data"]["name"], "host-00003")
        self.assertEqual(self.mock.requests[-1].api, "cmdb/firewall/address/host-00003")
        self.assertEqual(self.json_of("get", "system/global")["data"]["hostname"], "fw-mock")
        status = self.json_of("get", "monitor/system/status")
        self.assertEqual(status["data"]["hostname"], "fw-mock")
        self.assertEqual(status["meta"]["device"], {"serial": "FGT60FTK20000000", "version": "v7.4.8", "build": 2795})
        untyped = self.json_of("get", "monitor/firewall/session-count-list", "--count", "2")
        self.assertEqual(len(untyped["data"]), 2)
        self.assertEqual(untyped["meta"]["total"], 5)
        self.assertEqual(untyped["meta"]["next_start"], 2)
        missing = self.forti("get", "firewall/address", "nope", "--json", expect=5).json()
        self.assertEqual(missing["error"]["code"], "not_found")
        # An object name with a slash is one encoded path segment.
        self.forti("get", "firewall/address", "10.0.0.0/24", expect=5)
        self.assertEqual(self.mock.requests[-1].path, "/api/v2/cmdb/firewall/address/10.0.0.0%2F24")


class ReadOnly(CliTest):
    mode = "read-only"

    def test_apply_is_refused(self) -> None:
        plan = self.plan(create_address())["data"]
        self.assertEqual(plan["mode"], "read-only")
        refused = self.json_of("apply", plan["id"], expect=7)
        self.assertEqual(refused["error"]["code"], "policy_denied")
        self.assertEqual(self.writes(), [])
        self.assertEqual(self.sb.audit()[-1]["outcome"], "policy_denied")


class Guarded(CliTest):
    mode = "guarded"

    def test_refused_then_approved_then_applied(self) -> None:
        plan = self.plan(create_address())["data"]
        self.assertEqual(plan["approve"], f"forti approve {plan['id']}")
        refused = self.json_of("apply", plan["id"], expect=7)
        self.assertEqual(refused["error"]["code"], "approval_required")
        self.assertEqual(refused["error"]["details"]["approve_command"], f"forti approve {plan['id']}")
        self.assertEqual(self.writes(), [])

        shown = self.forti("plan", "show", plan["id"])
        self.assertIn("create firewall/address", shown.out)
        approved = self.json_of("plan", "approve", plan["id"], "--yes")
        self.assertEqual(approved["data"]["plan_id"], plan["id"])
        applied = self.json_of("apply", plan["id"])
        self.assertEqual(applied["data"]["verified"], 1)
        self.assertIn("web", self.mock.table("firewall/address"))
        # A plan runs once; the approval is used up.
        again = self.json_of("apply", plan["id"], expect=7)
        self.assertEqual(again["error"]["details"]["reason"], "already_applied")
        self.assertEqual(len(self.writes()), 1)

    def test_approval_is_bound_to_the_digest(self) -> None:
        plan = self.plan(create_address())["data"]
        self.json_of("plan", "approve", plan["id"], "--yes")
        stored = self.sb.state / "plans" / f"{plan['id']}.json"
        doc = json.loads(stored.read_text())
        doc["operations"][0]["object"]["comment"] = "tampered"
        stored.write_text(json.dumps(doc))
        refused = self.json_of("apply", plan["id"], expect=None)
        self.assertNotEqual(refused.get("ok"), True)
        self.assertEqual(self.writes(), [])


class GuardedAtTerminal(CliTest):
    """A person at a terminal: plans named implicitly, the approval asked inline, rollback."""

    mode = "guarded"

    def terminal(self, *args: str) -> Terminal:
        return Terminal([FORTI, *args], self.sb.env)

    def approvals(self) -> list:  # type: ignore[type-arg]
        return [e for e in self.sb.audit() if e.get("event") == "approve" and e.get("outcome") == "approved"]

    def test_apply_without_an_id_shows_the_plan_and_asks_once(self) -> None:
        plan = self.plan(create_address())["data"]
        term = self.terminal("apply")
        shown = term.answer("Apply these changes? [y/N] ", "y")
        self.assertIn("create firewall/address", shown)
        self.assertIn(f"plan {plan['id']}", shown)
        self.assertEqual(term.finish(), 0, term.text)
        self.assertIn("1 change applied and verified.", term.text)
        self.assertEqual(term.text.count("? ["), 1, term.text)   # one question, no "apply now?"
        self.assertIn("web", self.mock.table("firewall/address"))
        self.assertEqual([e["plan_id"] for e in self.approvals()], [plan["id"]])
        self.assertTrue(self.approvals()[0]["approved_by"].startswith("cli:"))

    def test_declining_applies_nothing(self) -> None:
        plan = self.plan(create_address())["data"]
        term = self.terminal("apply", plan["id"][-6:])
        term.answer("Apply these changes? [y/N] ", "")
        self.assertEqual(term.finish(), 7, term.text)
        self.assertIn("Nothing was changed.", term.text)
        self.assertEqual(self.writes(), [])
        self.assertEqual(self.approvals(), [])

    def test_set_is_one_command_and_one_question(self) -> None:
        self.mock.add_address("web", "192.0.2.10 255.255.255.255", comment="old")
        self.mock.clear_requests()
        term = self.terminal("set", "firewall/address/web", "comment=Web server")
        shown = term.answer("Apply these changes? [y/N] ", "y")
        self.assertIn('comment  "old" → "Web server"', shown)
        self.assertNotIn("PUT ", shown)   # the request line only with --verbose
        self.assertEqual(term.finish(), 0, term.text)
        self.assertIn("1 change applied and verified.", term.text)
        self.assertIn("undo      forti rollback", term.text)
        self.assertEqual(self.mock.table("firewall/address")["web"]["comment"], "Web server")
        apply = [e for e in self.sb.audit() if e.get("event") == "apply"][-1]
        self.assertEqual(apply["outcome"], "ok")
        self.assertTrue(apply["approved_by"].startswith("cli:"))
        self.assertTrue(apply["actor"].startswith("cli:"))

    def test_approve_for_an_agent_then_the_agent_applies(self) -> None:
        plan = self.plan(create_address())["data"]
        term = self.terminal("approve")
        shown = term.answer("Approve these changes? [y/N] ", "y")
        self.assertIn("create firewall/address", shown)
        self.assertEqual(term.finish(), 0, term.text)
        self.assertIn("The agent can apply it now", term.text)
        self.assertEqual(self.writes(), [])   # approving applies nothing
        applied = self.json_of("apply", plan["id"])   # the agent, without a terminal
        self.assertEqual(applied["data"]["verified"], 1)

    def test_approve_watch_asks_about_each_new_plan(self) -> None:
        term = self.terminal("approve", "--watch")
        term.expect("stops.")
        plan = self.plan(create_address())["data"]   # an agent plans meanwhile
        shown = term.answer("Approve these changes? [y/N] ", "y")
        self.assertIn(f"plan {plan['id']}", shown)
        term.expect("the agent can apply it now")
        os.write(term.fd, b"\x04")   # end of input stops the watch
        self.assertEqual(term.finish(), 0, term.text)
        self.assertEqual([e["plan_id"] for e in self.approvals()], [plan["id"]])
        self.assertEqual(self.json_of("apply", plan["id"])["data"]["verified"], 1)

    def test_two_waiting_plans_are_never_guessed(self) -> None:
        first = self.plan(create_address())["data"]
        second = self.plan(create_address({"name": "web2", "subnet": "192.0.2.11 255.255.255.255"}))["data"]
        # Without a terminal: refused, with both listed.
        refused = self.json_of("apply", "latest", expect=2)
        self.assertEqual(set(refused["error"]["details"]["candidates"]), {first["id"], second["id"]})
        # At a terminal: the person picks one, then answers the one question.
        term = self.terminal("apply")
        listing = term.answer("Which one? (Enter: none) ", "1")
        self.assertIn(first["id"], listing)
        self.assertIn(second["id"], listing)
        term.answer("Apply these changes? [y/N] ", "y")
        self.assertEqual(term.finish(), 0, term.text)
        self.assertEqual(len(self.writes()), 1)

    def test_plan_apply_flag_and_rollback(self) -> None:
        term = self.terminal("plan", "create", "firewall/address", "name=web", "subnet=192.0.2.10 255.255.255.255", "--apply")
        term.answer("Apply these changes? [y/N] ", "y")
        self.assertEqual(term.finish(), 0, term.text)
        self.assertIn("web", self.mock.table("firewall/address"))

        # forti rollback says what it undoes, asks once, and deletes the object again.
        term = self.terminal("rollback")
        before = term.answer("Apply these changes? [y/N] ", "y")
        self.assertIn("Undoes plan ", before)
        self.assertIn("delete firewall/address", before)
        self.assertEqual(term.finish(), 0, term.text)
        self.assertNotIn("web", self.mock.table("firewall/address"))


class AutonomousAtTerminal(CliTest):
    mode = "autonomous"

    def test_set_applies_without_a_question(self) -> None:
        self.mock.add_address("web", "192.0.2.10 255.255.255.255", comment="old")
        term = Terminal([FORTI, "set", "address", "web", "comment=new"], self.sb.env)
        self.assertEqual(term.finish(), 0, term.text)
        self.assertNotIn("? [", term.text)
        self.assertIn('"old" → "new"', term.text)
        self.assertEqual(self.mock.table("firewall/address")["web"]["comment"], "new")


class ReadOnlySet(CliTest):
    mode = "read-only"

    def test_set_shows_the_change_and_the_mode_command(self) -> None:
        self.mock.add_address("web", "192.0.2.10 255.255.255.255", comment="old")
        self.mock.clear_requests()
        result = self.forti("set", "firewall/address/web", "comment=new", expect=7)
        self.assertIn('"old" → "new"', result.out)
        self.assertIn("read-only: nothing was changed", result.err)
        self.assertIn("forti profile mode", result.err)
        self.assertEqual(self.writes(), [])


class Autonomous(CliTest):
    mode = "autonomous"

    def test_create_update_delete_with_exact_wire_bodies(self) -> None:
        self.mock.add_address("old", "198.51.100.1 255.255.255.255", comment="old")
        self.mock.add_address("gone", "198.51.100.2 255.255.255.255")
        self.mock.clear_requests()
        policy = {"name": "allow-web", "srcintf": [{"name": "port1"}], "dstintf": [{"name": "port2"}],
                  "srcaddr": [{"name": "all"}], "dstaddr": [{"name": "web"}], "service": [{"name": "HTTPS"}],
                  "action": "accept", "schedule": "always"}
        planned = self.plan(create_address(),
                            {"op": "create", "resource": "firewall/policy", "object": policy},
                            {"op": "update", "resource": "firewall/address", "key": "old", "set": {"comment": "new"},
                             "clear": ["color"]},
                            {"op": "delete", "resource": "firewall/address", "key": "gone"})["data"]
        self.assertEqual(self.writes(), [], "planning never writes")
        self.assertEqual(planned["risk"], "elevated")
        wires = [op["wire"] for op in planned["operations"]]

        self.mock.clear_requests()
        applied = self.json_of("apply", planned["id"])["data"]
        self.assertEqual(applied["verified"], 4, applied)
        statuses = [op["status"] for op in applied["operations"]]
        self.assertEqual(statuses, ["verified"] * 4)
        self.assertEqual(applied["operations"][1]["key"], "1", "the integer key FortiOS assigned")

        writes = self.writes()
        self.assertEqual([(w.method, w.api) for w in writes],
                         [("POST", "cmdb/firewall/address"), ("POST", "cmdb/firewall/policy"),
                          ("PUT", "cmdb/firewall/address/old"), ("DELETE", "cmdb/firewall/address/gone")])
        # The bytes on the wire are exactly the bodies the plan showed.
        for write, wire in zip(writes, wires):
            self.assertEqual(write.method, wire["method"])
            self.assertEqual(write.json(), wire.get("body"))
        self.assertEqual(writes[2].json(), {"comment": "new", "color": 0})

        addresses = self.mock.table("firewall/address")
        self.assertEqual(addresses["old"]["comment"], "new")
        self.assertNotIn("gone", addresses)
        self.assertEqual(self.mock.table("firewall/policy")["1"]["dstaddr"], [{"name": "web"}])

        # Rollback: the generated inverse plan restores the before-state.
        rollback_id = applied["rollback"]["plan_id"]
        shown = self.json_of("plan", "show", rollback_id)["data"]
        self.assertEqual(shown["kind"], "rollback")
        self.assertEqual(shown["rollback_of"], planned["id"])
        self.assertEqual([op["op"] for op in shown["operations"]], ["create", "update", "delete", "delete"])
        rolled = self.json_of("apply", rollback_id)["data"]
        self.assertTrue(all(op["status"] in ("verified", "applied_unverified") for op in rolled["operations"]), rolled)
        addresses = self.mock.table("firewall/address")
        self.assertEqual(sorted(addresses), ["gone", "old"])
        self.assertEqual(addresses["old"]["comment"], "old")
        self.assertEqual(self.mock.table("firewall/policy"), {})

        audit = self.sb.audit()
        self.assertEqual([e["outcome"] for e in audit if e["event"] == "apply"], ["ok", "ok"])
        self.assertEqual(stat.S_IMODE(os.stat(self.sb.state / "audit.jsonl").st_mode), 0o600)
        first = [e for e in audit if e["event"] == "apply"][0]
        self.assertEqual(first["plan_id"], planned["id"])
        self.assertEqual(first["digest"], planned["digest"])
        self.assertEqual(first["serial"], "FGT60FTK20000000")
        self.assertEqual(first["operations"][2]["attributes"], ["comment", "color"])
        self.assertNotIn("new", json.dumps(first), "audit records carry attribute names, not values")

    def test_normalized_value_is_applied_unverified(self) -> None:
        planned = self.plan(create_address({"name": "net", "subnet": "192.0.2.0/24"}))["data"]
        applied = self.json_of("apply", planned["id"])["data"]
        op = applied["operations"][0]
        self.assertEqual(op["status"], "applied_unverified")
        self.assertEqual(op["mismatches"], [{"attribute": "subnet", "expected": "192.0.2.0/24",
                                             "actual": "192.0.2.0 255.255.255.0"}])
        self.assertEqual(applied["applied_unverified"], 1)

    def test_stale_plan(self) -> None:
        self.mock.add_address("old", comment="before")
        planned = self.plan({"op": "update", "resource": "firewall/address", "key": "old", "set": {"comment": "x"}})["data"]
        self.mock.set_attr("firewall/address", "old", "comment", "changed behind our back")
        self.mock.clear_requests()
        stale = self.json_of("apply", planned["id"], expect=7)
        self.assertEqual(stale["error"]["code"], "stale_plan")
        self.assertEqual(stale["error"]["details"]["reason"], "before_changed")
        self.assertEqual(self.writes(), [])

    def test_outcome_unknown_when_the_connection_drops_after_send(self) -> None:
        planned = self.plan(create_address(), create_address({"name": "second"}))["data"]
        # times=2: the SDK's libcurl transport re-sends once on its own (see the next test).
        self.mock.drop_after_write("POST", apply=True, times=2)
        failed = self.json_of("apply", planned["id"], expect=8)
        self.assertEqual(failed["error"]["code"], "outcome_unknown")
        ops = failed["error"]["details"]["operations"]
        self.assertEqual([op["status"] for op in ops], ["outcome_unknown", "not_attempted"])
        self.assertTrue(ops[0]["sent"])
        self.assertIn("web", self.mock.table("firewall/address"), "the drop happened after the device acted")
        self.assertNotIn("second", self.mock.table("firewall/address"))
        self.assertEqual(self.sb.audit()[-1]["outcome"], "outcome_unknown")

    def test_no_write_is_sent_twice(self) -> None:
        # The device performs the create, then the connection drops before the reply. Before forti-api
        # fixed gap G12 (PR #17), libcurl took the empty reply on a reused connection for a stale
        # keep-alive and silently re-sent the POST: FortiOS assigned a second policy id, and the first
        # policy was in no record and no rollback plan. Now the write is sent once and reported as
        # outcome_unknown.
        policy = {"name": "p", "srcintf": [{"name": "port1"}], "dstintf": [{"name": "port2"}],
                  "srcaddr": [{"name": "all"}], "dstaddr": [{"name": "all"}], "service": [{"name": "ALL"}],
                  "action": "accept", "schedule": "always"}
        planned = self.plan({"op": "create", "resource": "firewall/policy", "object": policy})["data"]
        self.mock.drop_after_write("POST", apply=True, times=1)
        self.mock.clear_requests()
        result = self.json_of("apply", planned["id"], expect=None)
        posts = [w for w in self.writes() if w.method == "POST"]
        self.assertEqual(len(posts), 1, f"the device received the create {len(posts)} times "
                                        f"(connections {[w.connection for w in posts]}); "
                                        f"policies now: {sorted(self.mock.table('firewall/policy'))}; "
                                        f"apply said: {result.get('ok')}")
        self.assertEqual(result["error"]["code"], "outcome_unknown")

    def test_partial_failure_when_a_create_fails_but_exists(self) -> None:
        planned = self.plan(create_address(), create_address({"name": "second"}))["data"]
        self.mock.error_after_create("cmdb/firewall/address", status=500)
        self.mock.clear_requests()
        failed = self.json_of("apply", planned["id"], expect=8)
        self.assertEqual(failed["error"]["code"], "partial_failure")
        ops = failed["error"]["details"]["operations"]
        self.assertEqual([op["status"] for op in ops], ["failed", "not_attempted"])
        self.assertTrue(ops[0]["exists_after_failure"])
        self.assertEqual(ops[0]["error"]["details"]["http_status"], 500)
        self.assertEqual([(w.method, w.api) for w in self.writes()], [("POST", "cmdb/firewall/address")])
        # The rollback plan deletes what the failed create left behind.
        rollback = failed["error"]["details"]["rollback"]["plan_id"]
        self.json_of("apply", rollback)
        self.assertEqual(self.mock.table("firewall/address"), {})

    def test_failure_record_names_the_objects(self) -> None:
        planned = self.plan(create_address(), create_address({"name": "second"}))["data"]
        self.mock.error_after_create("cmdb/firewall/address", status=500)
        ops = self.json_of("apply", planned["id"], expect=8)["error"]["details"]["operations"]
        self.assertEqual([op.get("key") for op in ops], ["web", "second"])

    def test_critical_plan_takes_a_private_backup_first(self) -> None:
        planned = self.plan({"op": "update", "resource": "system/global", "set": {"hostname": "fw-new"}})["data"]
        self.assertEqual(planned["risk"], "critical")
        self.mock.clear_requests()
        applied = self.json_of("apply", planned["id"])["data"]
        self.assertEqual(applied["operations"][0]["status"], "verified")
        self.assertTrue(applied["operations"][0]["management_probe"]["ok"])
        self.assertEqual(applied["backup"]["status"], "saved", applied["backup"])
        calls = [(r.method, r.api) for r in self.mock.requests]
        backup_at = calls.index(("GET", "monitor/system/config/backup"))
        self.assertLess(backup_at, calls.index(("PUT", "cmdb/system/global")), "the backup precedes the change")
        self.assertEqual(self.mock.requests[backup_at].query, [("scope", "global")])
        files = list((self.sb.state / "backups").iterdir())
        self.assertEqual([f.name for f in files], [f"{planned['id']}.conf"])
        self.assertEqual(stat.S_IMODE(os.stat(files[0]).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(self.sb.state / "backups").st_mode), 0o700)
        content = files[0].read_text()
        self.assertTrue(content.startswith("#config-version="))
        self.assertIn('set hostname "fw-mock"', content, "the backup holds the before-state")
        self.assertIn(BACKUP_MARKER, content)
        self.assertEqual(self.sb.audit()[-1]["backup"], "saved")

    def test_failed_backup_refuses_a_critical_plan(self) -> None:
        planned = self.plan({"op": "update", "resource": "system/global", "set": {"hostname": "fw-new"}})["data"]
        self.mock.fail_request("GET", "monitor/system/config/backup", status=403)
        self.mock.clear_requests()
        refused = self.json_of("apply", planned["id"], expect=7)
        self.assertEqual(refused["error"]["code"], "policy_denied")
        self.assertEqual(refused["error"]["details"]["reason"], "backup_failed")
        self.assertEqual(self.writes(), [])
        self.assertEqual(self.mock.singleton("system/global")["hostname"], "fw-mock")
        self.assertFalse(any((self.sb.state / "backups").glob("*")) if (self.sb.state / "backups").exists() else False,
                         "no partial backup file is left behind")
        self.assertEqual(self.sb.audit()[-1]["error"]["reason"], "backup_failed")

    def test_management_probe_failure_stops_a_critical_apply(self) -> None:
        planned = self.plan({"op": "update", "resource": "system/global", "set": {"hostname": "fw-new"}},
                            create_address())["data"]
        self.assertEqual(planned["risk"], "critical")
        self.mock.fail_status_after_write()
        failed = self.json_of("apply", planned["id"], expect=8)
        self.assertEqual(failed["error"]["code"], "management_connectivity_lost")
        details = failed["error"]["details"]
        self.assertFalse(details["operations"][0]["management_probe"]["ok"])
        self.assertEqual(details["operations"][1]["status"], "not_attempted")
        self.assertEqual(details["before"]["hostname"], "fw-mock")
        self.assertIn("plan_id", details["rollback"])
        self.assertEqual(self.mock.singleton("system/global")["hostname"], "fw-new")
        self.assertNotIn("web", self.mock.table("firewall/address"))
        self.mock.clear_faults()
        # Once management is back, the rollback plan restores the hostname.
        self.json_of("apply", details["rollback"]["plan_id"])
        self.assertEqual(self.mock.singleton("system/global")["hostname"], "fw-mock")


def main() -> int:
    global FORTI
    require_tools()
    FORTI = binary("FORTI_BINARY")
    program = unittest.main(exit=False, verbosity=2)
    return 0 if program.result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
