"""The shared stub transport's fault floor (#877): a curl-level failure (HTTP 000, rc != 0) is a transport fault, never an empty successful payload. Driven through real stub-adapter verbs."""
from __future__ import annotations

import pytest

from defender.systems.verbs import VerbContext
from defender.integrations import _stub_transport as transport
from defender.integrations import ticket_adapter
from defender.kit.faults import TransportFault, UpstreamFault
from defender.tests.support.tenancy import _tenants1106

CURL_FAULTS = [
    (6, "curl: (6) Could not resolve host: ticket-store"),
    (7, "curl: (7) Failed to connect to ticket-store port 8080: Connection refused"),
    (28, "curl: (28) Operation timed out after 10001 milliseconds with 0 bytes received"),
]


@pytest.fixture
def ctx(tmp_path):
    return VerbContext(defender_dir=tmp_path / "defender", run_dir=tmp_path / "run", env={},
                       tenant=_tenants1106.fixture_run_tenant())


@pytest.fixture(autouse=True)
def _stub_config(monkeypatch):
    """The adapter's config, without a config file — the transport underneath is what these
    tests drive, and it is stubbed per test."""
    shaped = {"URL_BASE": "http://ticket-store:8080", "BASTION_HOST": "web-1",
              "TIMEOUT_SEC": "10", "KEY_PATTERN": "^INC-[0-9]+$"}

    def _fake(ctx, system, prefix, required=transport.REQUIRED_CONFIG_KEYS_TEMPLATE):
        return {k: shaped.get(k, f"stub-{k}") for k in required}

    monkeypatch.setattr(transport, "load_config", _fake)  # lint-monkeypatch: ok — the docker-exec-curl transport has no in-process DI seam (tests/integrations/test_ticket_adapter.py's established pattern)


def _curl(monkeypatch, rc: int, stdout: str, stderr: str) -> None:
    monkeypatch.setattr(  # lint-monkeypatch: ok — the transport's only seam is the subprocess it forks
        transport, "docker_exec_curl",
        lambda *a, **kw: (rc, stdout, stderr),
    )


@pytest.mark.parametrize(("rc", "stderr"), CURL_FAULTS)
def test_a_curl_level_failure_is_a_transport_fault_not_an_empty_payload(
    monkeypatch, ctx, rc, stderr,
):
    _curl(monkeypatch, rc, "\n000", stderr)
    with pytest.raises(TransportFault) as exc:
        ticket_adapter.health_check(ctx)
    assert f"rc={rc}" in str(exc.value), str(exc.value)
    assert stderr.split(":")[0] in str(exc.value), str(exc.value)

    with pytest.raises(TransportFault):
        ticket_adapter.list_tickets(ctx, status="closed")


def test_http_000_raises_even_when_curl_reports_success(monkeypatch, ctx):
    _curl(monkeypatch, 0, "\n000", "")
    with pytest.raises(TransportFault) as exc:
        ticket_adapter.health_check(ctx)
    assert "000" in str(exc.value)


def test_a_missing_bastion_still_names_the_container(monkeypatch, ctx):
    """`docker exec` fails before curl runs, so stdout is genuinely empty; the fault keeps its
    `docker ps` hint."""
    _curl(monkeypatch, 125, "", 'Error: No such container: web-1')
    with pytest.raises(TransportFault) as exc:
        ticket_adapter.health_check(ctx)
    assert "web-1" in str(exc.value)
    assert "docker" in str(exc.value)


def test_a_live_service_still_answers(monkeypatch, ctx):
    """Negative control: a clean curl with a 200 still returns its payload."""
    _curl(monkeypatch, 0, '{"status": "ok", "tickets": 3}\n200', "")
    assert ticket_adapter.health_check(ctx) == {
        "system": "ticket", "connected": True, "status": "ok", "tickets": 3,
    }


def test_an_http_error_is_still_the_upstreams_own_verdict(monkeypatch, ctx):
    """A service that answered keeps its own status: the 5xx fault carries the body, not `HTTP 000`."""
    _curl(monkeypatch, 0, '{"detail": "index closed"}\n503', "")
    with pytest.raises(TransportFault) as exc:
        ticket_adapter.health_check(ctx)
    assert "503" in str(exc.value)
    assert "000" not in str(exc.value)


# ---- the host write entry (#1359 D-6): the same fault floor under the comment action ------------

def _comment(ctx, key: str = "SOC-1"):
    """The host's one write on this route: the `ticket` adapter's comment action, through the
    shared transport's host write entry."""
    return ticket_adapter.add_case_comment(ctx, key=key, body="findings")


def _curl_recording(monkeypatch, rc: int, stdout: str, stderr: str) -> list[dict]:
    """`_curl`, also recording the request the transport handed the container's curl."""
    seen: list[dict] = []

    def fake(ctx, container, url, **kw):
        seen.append({"container": container, "url": url, **kw})
        return rc, stdout, stderr

    monkeypatch.setattr(transport, "docker_exec_curl", fake)  # lint-monkeypatch: ok — the transport's only seam is the subprocess it forks
    return seen


@pytest.mark.parametrize(("rc", "stderr"), CURL_FAULTS)
def test_a_curl_level_failure_on_the_host_write_is_a_transport_fault(monkeypatch, ctx, rc, stderr):
    """The write entry has the read entries' fault floor: no empty success. O3."""
    _curl(monkeypatch, rc, "\n000", stderr)
    with pytest.raises(TransportFault) as exc:
        _comment(ctx)
    assert f"rc={rc}" in str(exc.value), str(exc.value)
    assert stderr.split(":")[0] in str(exc.value), str(exc.value)


def test_http_000_on_the_host_write_raises_even_when_curl_reports_success(monkeypatch, ctx):
    _curl(monkeypatch, 0, "\n000", "")
    with pytest.raises(TransportFault) as exc:
        _comment(ctx)
    assert "000" in str(exc.value)


def test_a_missing_bastion_on_the_host_write_still_names_the_container(monkeypatch, ctx):
    _curl(monkeypatch, 125, "", 'Error: No such container: web-1')
    with pytest.raises(TransportFault) as exc:
        _comment(ctx)
    assert "web-1" in str(exc.value)


@pytest.mark.parametrize("status", [400, 403, 404, 409, 422])
def test_a_4xx_on_the_host_write_is_an_upstream_fault_carrying_the_status(monkeypatch, ctx, status):
    """The store's own refusal, with its status as data (D-5), not text to be parsed. O3, r4."""
    _curl(monkeypatch, 0, f'{{"detail": "no"}}\n{status}', "")
    with pytest.raises(UpstreamFault) as exc:
        _comment(ctx)
    assert getattr(exc.value, "status", None) == status, vars(exc.value)


@pytest.mark.parametrize("status", [500, 502, 503])
def test_a_5xx_on_the_host_write_stays_a_transport_fault(monkeypatch, ctx, status):
    _curl(monkeypatch, 0, f'{{"detail": "down"}}\n{status}', "")
    with pytest.raises(TransportFault) as exc:
        _comment(ctx)
    assert str(status) in str(exc.value)
    assert not isinstance(exc.value, UpstreamFault)


@pytest.mark.parametrize("answer", ['{"id": 1}', "", "created", "<html>ok</html>", "[]"])
def test_any_2xx_on_the_host_write_is_success_whatever_its_body(monkeypatch, ctx, answer):
    """A 2xx whose body is not a JSON object is still the store taking the comment. D-8."""
    seen = _curl_recording(monkeypatch, 0, f"{answer}\n201", "")
    assert _comment(ctx) == "http://ticket-store:8080/tickets/SOC-1"
    assert len(seen) == 1, "the comment was not sent exactly once"


def test_the_host_write_hands_curl_its_method_and_json_body(monkeypatch, ctx):
    """Positive control for the faults above: a live store receives one POST of the comment."""
    seen = _curl_recording(monkeypatch, 0, '{"id": 1}\n201', "")
    _comment(ctx, key="SOC-9")
    assert [(c["method"], c["url"], c["body"]["body"]) for c in seen] == [
        ("POST", "http://ticket-store:8080/tickets/SOC-9/comments", "findings")]
