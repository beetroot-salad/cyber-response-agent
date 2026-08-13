"""The shared stub transport's fault floor (#877 F-5): a dead system is a DOWN system, never
an empty one.

`docker_exec_curl` appends `-w "\\n%{http_code}"`, so curl writes a status line to stdout on
every exit — including the ones where no request completed. That made
`_raise_on_transport_failure`'s old `rc != 0 and not stdout` condition unsatisfiable for a
curl-level fault (stdout is `"\\n000"`, not empty), `_parse_status_code` read the status as `0`,
`_raise_on_http_error` matched neither its 5xx nor its 4xx arm, and `_request` returned `{}` as
a SUCCESS. An outage of any of the five stub systems routed through this transport — `ticket`,
`cmdb`, `identity`, `change-mgmt`, `threat-intel` — therefore reached the lead as "the system
answered, and it holds nothing", and the circuit breaker counted nothing, because the row's exit
code was 0 and `INFRA_EXIT_CODES` is `{2, 124}`: no `PER_SYSTEM_FAIL_LIMIT` trip, no
down-message, and the silent zero repeating for the rest of the run.

`elastic_adapter._http_json` has carried the missing guard verbatim all along
(`curl reported HTTP 000 (no response; rc=…)`); these tests are the contract's holder outside
it, and they drive the REAL verbs of a real stub adapter so the fault has to survive the whole
`health_check` → `http_get_obj` → `_request` path rather than a unit call to the guard.
"""
from __future__ import annotations

import pytest

from defender.runtime.verbs import VerbContext
from defender.scripts.adapters import _stub_transport as transport
from defender.scripts.adapters import ticket_adapter
from defender.scripts.adapters.faults import TransportFault

#: curl's three ways of failing before a response exists, as observed against real curl through
#: a `docker` shim: DNS failure, connection refused, and the `--max-time` timeout. All three
#: write `\n000` to stdout, which is why none of them used to raise.
CURL_FAULTS = [
    (6, "curl: (6) Could not resolve host: ticket-store"),
    (7, "curl: (7) Failed to connect to ticket-store port 8080: Connection refused"),
    (28, "curl: (28) Operation timed out after 10001 milliseconds with 0 bytes received"),
]


@pytest.fixture
def ctx(tmp_path):
    return VerbContext(defender_dir=tmp_path / "defender", run_dir=tmp_path / "run", env={})


@pytest.fixture(autouse=True)
def _stub_config(monkeypatch):
    """The adapter's config, without a config file — the transport underneath is what these
    tests drive, and it is stubbed per test."""
    shaped = {"URL_BASE": "http://ticket-store:8080", "BASTION_HOST": "web-1",
              "TIMEOUT_SEC": "10", "KEY_PATTERN": "^INC-[0-9]+$"}

    def _fake(ctx, system, prefix, required=transport.REQUIRED_CONFIG_KEYS_TEMPLATE):
        return {k: shaped.get(k, f"stub-{k}") for k in required}

    monkeypatch.setattr(transport, "load_config", _fake)  # lint-monkeypatch: ok — the docker-exec-curl transport has no in-process DI seam (tests/test_ticket_adapter.py's established pattern)


def _curl(monkeypatch, rc: int, stdout: str, stderr: str) -> None:
    monkeypatch.setattr(  # lint-monkeypatch: ok — the transport's only seam is the subprocess it forks
        transport, "docker_exec_curl",
        lambda *a, **kw: (rc, stdout, stderr),
    )


@pytest.mark.parametrize(("rc", "stderr"), CURL_FAULTS)
def test_a_curl_level_failure_is_a_transport_fault_not_an_empty_payload(
    monkeypatch, ctx, rc, stderr,
):
    """Every curl exit that never produced a response is a down system. Previously each of these
    returned `{'system': 'ticket', 'connected': True}` from `health_check` and `{}` from
    `list_tickets` — a health check that reports a dead service as connected."""
    _curl(monkeypatch, rc, "\n000", stderr)
    with pytest.raises(TransportFault) as exc:
        ticket_adapter.health_check(ctx)
    assert "000" in str(exc.value) or str(rc) in str(exc.value)

    with pytest.raises(TransportFault):
        ticket_adapter.list_tickets(ctx, status="closed")


def test_http_000_raises_even_when_curl_reports_success(monkeypatch, ctx):
    """The `000` guard in `_parse_status_code` is INDEPENDENT of the rc check, not a second
    spelling of it: a status line that says no response happened is a down system whatever the
    exit code claims, and this is the reading `elastic_adapter._http_json` has always made."""
    _curl(monkeypatch, 0, "\n000", "")
    with pytest.raises(TransportFault) as exc:
        ticket_adapter.health_check(ctx)
    assert "000" in str(exc.value)


def test_a_missing_bastion_still_names_the_container(monkeypatch, ctx):
    """The case the guard was ORIGINALLY written for, unchanged: `docker exec` fails before curl
    runs, stdout is genuinely empty, and the fault keeps its `docker ps` hint."""
    _curl(monkeypatch, 125, "", 'Error: No such container: web-1')
    with pytest.raises(TransportFault) as exc:
        ticket_adapter.health_check(ctx)
    assert "web-1" in str(exc.value)
    assert "docker" in str(exc.value)


def test_a_live_service_still_answers(monkeypatch, ctx):
    """The negative control — the widened guard must not turn a working transport into an
    outage. A clean curl with a 200 returns the payload it always did."""
    _curl(monkeypatch, 0, '{"status": "ok", "tickets": 3}\n200', "")
    assert ticket_adapter.health_check(ctx) == {
        "system": "ticket", "connected": True, "status": "ok", "tickets": 3,
    }


def test_an_http_error_is_still_the_upstreams_own_verdict(monkeypatch, ctx):
    """And a service that DID answer keeps its own status: a 5xx stays a `TransportFault`
    carrying the body, not a `curl reported HTTP 000`."""
    _curl(monkeypatch, 0, '{"detail": "index closed"}\n503', "")
    with pytest.raises(TransportFault) as exc:
        ticket_adapter.health_check(ctx)
    assert "503" in str(exc.value)
    assert "000" not in str(exc.value)
