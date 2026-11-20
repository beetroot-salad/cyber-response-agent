"""#1504 O2: every catalog adapter's declared non-GET reads are exactly what its tools send. Each roster tool is driven
through the transport capture seam and each captured non-GET request is matched with the proxy's own route check."""
from __future__ import annotations

import contextlib
import http.server
import json
import threading
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from defender.credential_proxy._refusal import Refused
from defender.credential_proxy._scope import READ_METHODS, check_route, locate
from defender.credential_proxy._tokens import READ
from defender.integrations.confinement import CapturedRequest, TransportCapture
from defender.kit.faults import AdapterFault, ConfigFault, ConfinementFault
from defender.kit.proxy_client import REPLY_CONTENT_TYPE, FinalRecord, encode_body, encode_final
from defender.kit.settings import SystemConfig
from defender.system_rules.catalog import Catalog
from defender.systems.verbs import VerbContext
from defender.tenancy import parse_access
from defender.tests.support.tenancy import _systems1366 as R
from defender.tests.systems import _reads1504 as X

DEFENDER = Path(__file__).resolve().parents[2]
TOKEN = "read-pass-token"

#: How each roster tool is driven: `(adapter id, tool) -> keyword arguments`. A roster tool missing here fails the test
#: (the class is enumerated from the roster, never from this table), and so does a row naming no roster tool.
DRIVE: Mapping[tuple[str, str], Mapping[str, Any]] = {
    ("change-mgmt", "health-check"): {},
    ("change-mgmt", "active-changes"): {"host": "web-01", "at": "2026-01-01T00:00:00Z"},
    ("change-mgmt", "get-change"): {"cr_id": "CHG-1"},
    ("change-mgmt", "list-changes"): {"status": "approved", "host": "web-01", "active_at": "2026-01-01T00:00:00Z"},
    ("cmdb", "health-check"): {},
    ("cmdb", "get-host"): {"host": "web-01"},
    ("cmdb", "list-hosts"): {"role": "web", "criticality": "high", "owner": "ops"},
    ("cmdb", "list-roles"): {},
    ("elastic", "health-check"): {},
    ("elastic", "query"): {"native_query": "*"},
    ("elastic", "alerts"): {"native_query": "*"},
    ("elastic", "esql"): {"query": "FROM logs-* | LIMIT 1"},
    ("host-state", "health-check"): {},
    ("host-state", "container-inspect"): {"container_id": "abc123"},
    ("host-state", "proc-tree"): {"host": "web-01"},
    ("host-state", "passwd"): {"host": "web-01"},
    ("host-state", "authorized-keys"): {"host": "web-01", "user": "root"},
    ("host-state", "fim-checksum"): {"host": "web-01", "path": "/etc/passwd"},
    ("host-state", "package-list"): {"host": "web-01"},
    ("identity", "health-check"): {},
    ("identity", "can-access"): {"user": "alice", "host": "web-01"},
    ("identity", "get-user"): {"user": "alice"},
    ("identity", "list-authorized-hosts"): {"user": "alice"},
    ("identity", "list-users"): {"role": "admin", "enabled": True},
    ("identity", "list-roles"): {},
    ("threat-intel", "health-check"): {},
    ("threat-intel", "lookup"): {"value": "198.51.100.7"},
    ("threat-intel", "list-indicators"): {"verdict": "malicious", "type": "ip", "tag": "c2"},
    ("ticket", "health-check"): {},
    ("ticket", "list-tickets"): {"status": "open", "label": "soc", "q": "phish"},
    ("ticket", "get-ticket"): {"key": "ABC-1"},
    ("ticket", "key-pattern"): {},
    ("ticket", "case-opened-at"): {"key": "ABC-1"},
}


class _ProxyStandIn(http.server.ThreadingHTTPServer):
    """The credential proxy's address, answering every request with a whole 200 and an empty JSON object in the proxy's
    reply framing. It decides nothing: the capture seam, before the proxy, is what the test observes."""

    daemon_threads = True

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802 — the http.server hook
            self.rfile.read(int(self.headers.get("content-length") or 0))
            final = FinalRecord(status=200, headers={}, fault=None, detail=None, system_side=False, sent=True,
                                body_whole=True, reader_fault=False, origin=None)
            reply = encode_body(b"{}") + encode_final(final)
            self.send_response(200)
            self.send_header("content-type", REPLY_CONTENT_TYPE)
            self.send_header("content-length", str(len(reply)))
            self.end_headers()
            self.wfile.write(reply)

        def log_message(self, *args: Any) -> None:
            return None

    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), self._Handler)


@contextlib.contextmanager
def _proxy() -> Iterator[str]:
    server = _ProxyStandIn()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(10)


@dataclass(frozen=True)
class _Tenant:
    """The run's record as a verb reads it: one system's settings and its access declaration."""

    systems: Mapping[str, Any]
    access: Mapping[str, Any]
    agent: Path


def _base(adapter: str) -> str:
    return f"https://{adapter}.example"


def _declaration(adapter: str, reads: tuple[tuple[str, str], ...]) -> Any:
    """The access declaration a record of `adapter` would hold, parsed as the store parses it."""
    return parse_access(R.declaration(_base(adapter), reads=reads), system=adapter)


def _sent(catalog: Catalog, adapter: str, tool: str, kwargs: Mapping[str, Any], proxy_url: str,
          tmp_path: Path) -> tuple[list[CapturedRequest], list[str]]:
    """The requests `tool` made through the capture seam, and the findings if the call could not be driven (a settings or
    confinement refusal is the fixture's fault, never read as "sent nothing"; any other fault follows the first request)."""
    entry = catalog.entry(adapter)
    settings = SystemConfig(entry.sample_settings or {})
    tenant = _Tenant(systems={adapter: settings}, access={adapter: _declaration(adapter, ())}, agent=tmp_path)
    capture = TransportCapture()
    ctx = VerbContext(defender_dir=DEFENDER, run_dir=tmp_path / "run", env={}, tenant=tenant, capture=capture,
                      proxy_url=proxy_url, request_token=TOKEN)
    try:
        catalog.module(adapter).VERBS[tool](ctx, **kwargs)
    except (ConfigFault, ConfinementFault) as refused:
        return capture.requests, [f"{adapter} {tool}: its drive fixture was refused before it was sent: {refused}"]
    except AdapterFault:
        pass  # the stand-in answers `{}`: a later shape fault follows the request the seam already holds
    return capture.requests, []


def _findings(catalog: Catalog, adapter: str, declared: tuple[tuple[str, str], ...], drive: Mapping[tuple[str, str], Any],
              proxy_url: str, tmp_path: Path) -> list[str]:
    """What is wrong between `declared` and what `adapter`'s roster tools send. Each captured non-GET request is judged by
    the proxy's route check (`check_route`, read mode) over a declaration built from `declared`; each declared route is
    judged the same way over a declaration of that route alone, against every non-GET request the tools sent."""
    tools = sorted(catalog.entry(adapter).tools)
    found = [f"{adapter} {tool}: no drive fixture" for tool in tools if (adapter, tool) not in drive]
    whole = _declaration(adapter, declared)
    sent: list[tuple[str, str]] = []
    for tool in (t for t in tools if (adapter, t) in drive):
        requests, refused = _sent(catalog, adapter, tool, drive[(adapter, tool)], proxy_url, tmp_path)
        found += refused
        for request in requests:
            if request.method in READ_METHODS:
                continue
            path = locate(whole, request.url).path
            sent.append((request.method, path))
            try:
                check_route(whole, adapter, request.method, path, READ)
            except Refused:
                found.append(f"{adapter} {tool} sent {request.method} {path}, which its declared reads do not list")
    for method, pattern in declared:
        alone = _declaration(adapter, ((method, pattern),))
        if not any(_admits(alone, adapter, m, p) for m, p in sent):
            found.append(f"{adapter} declares {method} {pattern}, which no tool sends")
    return found


def _admits(declaration: Any, adapter: str, method: str, path: str) -> bool:
    try:
        check_route(declaration, adapter, method, path, READ)
    except Refused:
        return False
    return True


def test_1504_o2_each_adapters_declared_reads_are_exactly_the_non_get_requests_its_tools_send(tmp_path):
    """Every roster tool of every catalog adapter, driven through the capture seam: each non-GET request it sends is
    admitted as a read by the proxy's route check over the declared list, each declared route is sent by some tool, and a
    roster tool with no drive fixture fails. (O2)"""
    catalog = Catalog.of_checkout(DEFENDER)
    adapters = catalog.adapter_ids
    assert set(adapters) == {a for a, _ in DRIVE} | {"jira", "servicenow"}, "premise: the roster is the table's adapters"
    roster = {(a, t) for a in adapters for t in catalog.entry(a).tools}
    stale = sorted(set(DRIVE) - roster)
    assert stale == [], f"drive fixtures for tools the roster does not have: {stale}"
    with _proxy() as proxy_url:
        found = [line for a in adapters
                 for line in _findings(catalog, a, X.declared_reads(a), DRIVE, proxy_url, tmp_path)]
    assert found == [], found


# controls: the same machinery over declarations and fixture tables the checkout does not carry


def test_1504_o2_control_a_declaration_matching_what_elastics_tools_send_is_clean(tmp_path):
    """Positive control: Elastic's census reads (`POST /*/_search`, `POST /_query`) leave no finding. (O2)"""
    catalog = Catalog.of_checkout(DEFENDER)
    with _proxy() as proxy_url:
        assert _findings(catalog, "elastic", X.ELASTIC_READS, DRIVE, proxy_url, tmp_path) == []


@pytest.mark.parametrize(("label", "declared", "named"), [
    ("an-unlisted-search", X.ELASTIC_READS[1:], "_search"),
    ("an-unlisted-query", X.ELASTIC_READS[:1], "POST /_query"),
    ("nothing-listed", (), "POST /_query"),
])
def test_1504_o2_control_a_non_get_request_the_declaration_lacks_is_a_finding(tmp_path, label, declared, named):
    """Elastic's tools send both searches: a list missing one is a finding naming the request. (O2)"""
    catalog = Catalog.of_checkout(DEFENDER)
    with _proxy() as proxy_url:
        found = _findings(catalog, "elastic", declared, DRIVE, proxy_url, tmp_path)
    assert [f for f in found if "do not list" in f and named in f], (label, found)


@pytest.mark.parametrize("extra", [("POST", "/_bulk"), ("DELETE", "/*"), ("POST", "/*/_count"), ("POST", "/*/*/_search")])
def test_1504_o2_control_a_declared_route_no_tool_sends_is_a_finding(tmp_path, extra):
    """A listed route beyond what Elastic's tools send (a `_count`, a two-segment index) is a finding naming it. (O2)"""
    catalog = Catalog.of_checkout(DEFENDER)
    with _proxy() as proxy_url:
        found = _findings(catalog, "elastic", (*X.ELASTIC_READS, extra), DRIVE, proxy_url, tmp_path)
    assert [f for f in found if "no tool sends" in f and X.shown(extra) in f], found


def test_1504_o2_control_a_roster_tool_with_no_drive_fixture_is_a_finding(tmp_path):
    """Drop Elastic's `esql` row: the tool is named as having no fixture, and the other rows still drive. (O2)"""
    catalog = Catalog.of_checkout(DEFENDER)
    drive = {k: v for k, v in DRIVE.items() if k != ("elastic", "esql")}
    with _proxy() as proxy_url:
        found = _findings(catalog, "elastic", X.ELASTIC_READS, drive, proxy_url, tmp_path)
    assert [f for f in found if "esql" in f and "no drive fixture" in f], found


def test_1504_o2_control_a_fixture_the_adapter_refuses_is_a_finding_not_a_silent_skip(tmp_path):
    """A lookup value of two path segments is refused before it is sent: reported, so it cannot hide a POST. (O2)"""
    catalog = Catalog.of_checkout(DEFENDER)
    drive = {**DRIVE, ("cmdb", "get-host"): {"host": "a/b"}}
    with _proxy() as proxy_url:
        found = _findings(catalog, "cmdb", (), drive, proxy_url, tmp_path)
    assert [f for f in found if "get-host" in f and "refused" in f], found


def test_1504_o2_the_stand_in_replies_in_the_proxys_framing(tmp_path):
    """Premise of the drive: a tool reaches the capture seam and the stand-in's reply is one the transport accepts (a
    threat-intel lookup records `POST /lookup` once). (O2)"""
    catalog = Catalog.of_checkout(DEFENDER)
    with _proxy() as proxy_url:
        requests, refused = _sent(catalog, "threat-intel", "lookup", DRIVE[("threat-intel", "lookup")], proxy_url, tmp_path)
    assert refused == []
    assert [(r.system, r.method, json.dumps(r.url)) for r in requests] == [
        ("threat-intel", "POST", json.dumps("https://threat-intel.example/lookup"))]
