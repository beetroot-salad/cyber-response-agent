"""#1131 — the stub platform API: the route set, the login seam, tenant scoping, and the
data-layer rules behind each write.

WHAT IS DRIVEN. The real app (`api.app.create_app`) through starlette's `TestClient`, over the
in-memory fakes (`api.fakes`) seeded per test here rather than from `api.demo`, so each test
states the records it relies on. The fakes carry the rules the real store will enforce with
constraints (one live investigation per alert, `client_request_id` replay, learning only from a
completed investigation), so these tests are also the conformance suite a real store has to
pass when it replaces them.
"""
from __future__ import annotations

import datetime as _dt
import json
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient  # noqa: E402

from defender.api.app import MAX_PAGE, create_app  # noqa: E402
from defender.api.demo import DEMO_TOKENS, demo_deps  # noqa: E402
from defender.api.fakes import (  # noqa: E402
    InMemoryAudit,
    InMemorySecrets,
    InMemoryStore,
    StubArtifactLinks,
    StubSystemChecker,
    TokenAuthenticator,
)
from defender.api.models import Alert, Investigation, SystemPut  # noqa: E402
from defender.api.ports import ApiDeps, Principal  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]
NOW = _dt.datetime(2026, 9, 28, 12, 0, tzinfo=_dt.UTC)

A, B = "tenant-a", "tenant-b"
TOKENS = {
    "tok-a": Principal(tenant_id=A, user_id="ann@a.example"),
    "tok-b": Principal(tenant_id=B, user_id="bob@b.example"),
}
AUTH_A = {"Authorization": "Bearer tok-a"}
AUTH_B = {"Authorization": "Bearer tok-b"}

#: #1131's "API" section, verbatim as (method, path). The contract this stub exists to pin.
PUBLIC_ROUTES = {
    ("GET", "/alerts"),
    ("GET", "/alerts/{alert_id}"),
    ("POST", "/investigations"),
    ("GET", "/investigations"),
    ("GET", "/investigations/{investigation_id}"),
    ("POST", "/investigations/{investigation_id}/cancel"),
    ("DELETE", "/investigations/{investigation_id}"),
    ("GET", "/investigations/{investigation_id}/artifacts/{key}"),
    ("POST", "/learning-jobs"),
    ("GET", "/learning-jobs"),
    ("GET", "/learning-jobs/{learning_job_id}"),
    ("GET", "/lessons"),
    ("GET", "/systems"),
    ("PUT", "/systems/{system_id}"),
    ("PUT", "/systems/{system_id}/credentials"),
    ("POST", "/systems/{system_id}/check"),
}


class _World:
    def __init__(self) -> None:
        self.secrets = InMemorySecrets()
        self.store = InMemoryStore(lambda: NOW, self.secrets)
        self.audit = InMemoryAudit()
        self.deps = ApiDeps(
            authenticator=TokenAuthenticator(TOKENS),
            alerts=self.store, investigations=self.store, learning_jobs=self.store,
            lessons=self.store, systems=self.store, secrets=self.secrets,
            checker=StubSystemChecker(), artifact_links=StubArtifactLinks(),
            audit=self.audit, clock=lambda: NOW,
        )
        self.client = TestClient(create_app(self.deps))

    def alert(self, tenant: str, alert_id: str, *, hours_ago: int = 1, severity: str = "high") -> Alert:
        fired = NOW - _dt.timedelta(hours=hours_ago)
        return self.store.add_alert(tenant, Alert(
            alert_id=alert_id, vendor="tickets", vendor_ticket_id=f"T-{alert_id}", title=alert_id,
            severity=severity, rule="r", fired_at=fired, changed_at=fired, received_at=fired,
            raw={"id": alert_id},
        ))

    def investigation(self, tenant: str, investigation_id: str, alert_id: str, status: str,
                      artifacts: tuple[str, ...] = ()) -> Investigation:
        return self.store.add_investigation(tenant, Investigation(
            investigation_id=investigation_id, alert_id=alert_id, status=status,
            cost_usd=0.0, created_at=NOW, artifacts=list(artifacts),
        ))

    def actions(self) -> list[str]:
        return [e.action for e in self.audit.events]


@pytest.fixture
def world() -> _World:
    return _World()


def _concrete(path: str) -> str:
    return path.replace("{key:path}", "k").replace("{", "").replace("}", "")


# --- the contract --------------------------------------------------------------------------


def test_the_published_routes_are_exactly_1131s_list(world: _World) -> None:
    doc = world.client.get("/openapi.json").json()
    documented = {(method.upper(), path) for path, ops in doc["paths"].items() for method in ops}
    assert documented == PUBLIC_ROUTES
    assert doc["components"]["securitySchemes"]["HTTPBearer"]["scheme"] == "bearer"


def test_the_api_never_loads_the_runtime_or_the_learning_loop() -> None:
    probe = (
        "import json, sys; import defender.api.app, defender.api.demo, defender.api.serve; "
        "print(json.dumps(sorted(m for m in sys.modules "
        "if m.startswith(('defender.runtime', 'defender.learning')))))"
    )
    out = subprocess.run(
        [sys.executable, "-c", probe], cwd=REPO_ROOT, capture_output=True, text=True,
        encoding="utf-8", check=True,
    )
    assert json.loads(out.stdout) == []


# --- login ---------------------------------------------------------------------------------


@pytest.mark.parametrize(("method", "path"), sorted(PUBLIC_ROUTES))
@pytest.mark.parametrize("headers", [{}, {"Authorization": "Bearer nope"}, {"Authorization": "Basic tok-a"}])
def test_every_route_refuses_a_caller_without_a_known_bearer_token(
    world: _World, method: str, path: str, headers: dict[str, str]
) -> None:
    response = world.client.request(method, _concrete(path), headers=headers, json={})
    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"


def test_a_body_cannot_name_a_tenant(world: _World) -> None:
    world.alert(B, "al-b")
    response = world.client.post(
        "/investigations", headers=AUTH_A,
        json={"alert_id": "al-b", "client_request_id": "r", "tenant_id": B},
    )
    assert response.status_code == 422
    assert world.store.list_investigations(B, alert_id=None, limit=MAX_PAGE) == []


# --- tenant scoping ------------------------------------------------------------------------


def test_another_tenants_records_read_as_missing(world: _World) -> None:
    world.alert(B, "al-b")
    world.investigation(B, "inv-b", "al-b", "completed", artifacts=("report.md",))
    world.store.put_system(B, "sys-b", SystemPut(kind="siem", display_name="B"))
    job, _ = world.store.create_learning_job(B, "inv-b", "r")

    for path in ("/alerts/al-b", "/investigations/inv-b",
                 "/investigations/inv-b/artifacts/report.md", f"/learning-jobs/{job.learning_job_id}"):
        assert world.client.get(path, headers=AUTH_A, follow_redirects=False).status_code == 404, path
    assert world.client.post("/investigations/inv-b/cancel", headers=AUTH_A).status_code == 404
    assert world.client.delete("/investigations/inv-b", headers=AUTH_A).status_code == 404
    assert world.client.post("/systems/sys-b/check", headers=AUTH_A).status_code == 404
    assert world.client.put("/systems/sys-b/credentials", headers=AUTH_A,
                            json={"credentials": {"k": "v"}}).status_code == 404
    for path in ("/alerts", "/investigations", "/learning-jobs", "/lessons", "/systems"):
        assert world.client.get(path, headers=AUTH_A).json() == [], path
    # ...and B still sees its own.
    assert world.client.get("/investigations/inv-b", headers=AUTH_B).status_code == 200


def test_a_body_naming_another_tenants_record_is_an_unknown_reference(world: _World) -> None:
    world.alert(B, "al-b")
    world.investigation(B, "inv-b", "al-b", "completed")
    assert world.client.post("/investigations", headers=AUTH_A,
                             json={"alert_id": "al-b", "client_request_id": "r"}).status_code == 422
    assert world.client.post("/learning-jobs", headers=AUTH_A,
                             json={"investigation_id": "inv-b", "client_request_id": "r"}).status_code == 422


def test_a_put_system_in_one_tenant_leaves_the_same_id_in_another_alone(world: _World) -> None:
    body = {"kind": "siem", "display_name": "A's"}
    assert world.client.put("/systems/siem", headers=AUTH_A, json=body).status_code == 201
    assert world.client.put("/systems/siem", headers=AUTH_B, json=body | {"display_name": "B's"}).status_code == 201
    assert world.client.get("/systems", headers=AUTH_A).json()[0]["display_name"] == "A's"


# --- alerts --------------------------------------------------------------------------------


def test_alerts_list_newest_first_without_the_raw_alert_and_filters(world: _World) -> None:
    world.alert(A, "old", hours_ago=10, severity="low")
    world.alert(A, "mid", hours_ago=5)
    world.alert(A, "new", hours_ago=1)

    listed = world.client.get("/alerts", headers=AUTH_A).json()
    assert [a["alert_id"] for a in listed] == ["new", "mid", "old"]
    assert all("raw" not in a for a in listed)

    after = (NOW - _dt.timedelta(hours=6)).isoformat()
    before = (NOW - _dt.timedelta(hours=2)).isoformat()
    windowed = world.client.get("/alerts", headers=AUTH_A,
                                params={"fired_after": after, "fired_before": before}).json()
    assert [a["alert_id"] for a in windowed] == ["mid"]
    low = world.client.get("/alerts", headers=AUTH_A, params={"severity": "low"}).json()
    assert [a["alert_id"] for a in low] == ["old"]
    assert len(world.client.get("/alerts", headers=AUTH_A, params={"limit": 2}).json()) == 2


@pytest.mark.parametrize("limit", [0, MAX_PAGE + 1])
def test_a_page_size_out_of_range_is_refused(world: _World, limit: int) -> None:
    assert world.client.get("/alerts", headers=AUTH_A, params={"limit": limit}).status_code == 422


def test_one_alert_carries_the_raw_alert(world: _World) -> None:
    world.alert(A, "al")
    assert world.client.get("/alerts/al", headers=AUTH_A).json()["raw"] == {"id": "al"}


# --- investigations ------------------------------------------------------------------------


def test_start_creates_a_queued_investigation_and_audits_it(world: _World) -> None:
    world.alert(A, "al")
    response = world.client.post("/investigations", headers=AUTH_A,
                                 json={"alert_id": "al", "client_request_id": "r1"})
    assert response.status_code == 201
    body = response.json()
    assert response.headers["Location"] == f"/investigations/{body['investigation_id']}"
    assert (body["status"], body["alert_id"], body["disposition"]) == ("queued", "al", None)
    assert world.actions() == ["investigation.start"]
    assert world.audit.events[0].user_id == "ann@a.example"


def test_a_replayed_request_returns_the_same_investigation_without_a_second_start(world: _World) -> None:
    world.alert(A, "al")
    first = world.client.post("/investigations", headers=AUTH_A, json={"alert_id": "al", "client_request_id": "r1"})
    world.client.post(f"/investigations/{first.json()['investigation_id']}/cancel", headers=AUTH_A)
    again = world.client.post("/investigations", headers=AUTH_A, json={"alert_id": "al", "client_request_id": "r1"})
    assert again.status_code == 200
    assert again.json()["investigation_id"] == first.json()["investigation_id"]
    assert world.actions().count("investigation.start") == 1


def test_a_live_investigation_is_returned_instead_of_starting_a_second(world: _World) -> None:
    world.alert(A, "al")
    world.investigation(A, "inv-live", "al", "running")
    response = world.client.post("/investigations", headers=AUTH_A,
                                 json={"alert_id": "al", "client_request_id": "fresh"})
    assert response.status_code == 200
    assert response.json()["investigation_id"] == "inv-live"
    assert world.actions() == []


@pytest.mark.parametrize("prior", ["completed", "unparseable", "failed", "aborted"])
def test_a_terminal_prior_does_not_block_a_rerun(world: _World, prior: str) -> None:
    world.alert(A, "al")
    world.investigation(A, "inv-prior", "al", prior)
    response = world.client.post("/investigations", headers=AUTH_A,
                                 json={"alert_id": "al", "client_request_id": "rerun"})
    assert response.status_code == 201
    assert response.json()["investigation_id"] != "inv-prior"
    listed = world.client.get("/investigations", headers=AUTH_A, params={"alert_id": "al"}).json()
    assert {i["investigation_id"] for i in listed} == {"inv-prior", response.json()["investigation_id"]}


def test_start_refuses_an_unknown_alert_and_a_blank_request_id(world: _World) -> None:
    world.alert(A, "al")
    assert world.client.post("/investigations", headers=AUTH_A,
                             json={"alert_id": "nope", "client_request_id": "r"}).status_code == 422
    assert world.client.post("/investigations", headers=AUTH_A,
                             json={"alert_id": "al", "client_request_id": ""}).status_code == 422
    assert world.actions() == []


@pytest.mark.parametrize("live", ["queued", "running"])
def test_cancel_aborts_a_live_investigation(world: _World, live: str) -> None:
    world.alert(A, "al")
    world.investigation(A, "inv", "al", live)
    response = world.client.post("/investigations/inv/cancel", headers=AUTH_A)
    assert response.status_code == 200
    assert response.json()["status"] == "aborted"
    assert response.json()["finished_at"] is not None
    assert world.actions() == ["investigation.cancel"]


def test_cancel_refuses_an_investigation_that_already_ended(world: _World) -> None:
    world.alert(A, "al")
    world.investigation(A, "inv", "al", "completed")
    assert world.client.post("/investigations/inv/cancel", headers=AUTH_A).status_code == 409
    assert world.actions() == []


def test_delete_hides_an_ended_investigation_from_every_read(world: _World) -> None:
    world.alert(A, "al")
    world.investigation(A, "inv", "al", "completed", artifacts=("report.md",))
    assert world.client.delete("/investigations/inv", headers=AUTH_A).status_code == 204
    assert world.client.get("/investigations/inv", headers=AUTH_A).status_code == 404
    assert world.client.get("/investigations/inv/artifacts/report.md", headers=AUTH_A,
                            follow_redirects=False).status_code == 404
    assert world.client.get("/investigations", headers=AUTH_A).json() == []
    assert world.client.delete("/investigations/inv", headers=AUTH_A).status_code == 404
    assert world.actions() == ["investigation.delete"]


def test_delete_refuses_a_live_investigation(world: _World) -> None:
    world.alert(A, "al")
    world.investigation(A, "inv", "al", "running")
    assert world.client.delete("/investigations/inv", headers=AUTH_A).status_code == 409
    assert world.client.get("/investigations/inv", headers=AUTH_A).status_code == 200


@pytest.mark.parametrize("key", ["runtime.html", "gather_raw/L1/0.json"])
def test_an_artifact_read_redirects_to_a_signed_link_and_is_audited(world: _World, key: str) -> None:
    world.alert(A, "al")
    world.investigation(A, "inv", "al", "completed", artifacts=(key,))
    response = world.client.get(f"/investigations/inv/artifacts/{key}", headers=AUTH_A,
                                follow_redirects=False)
    assert response.status_code == 307
    assert response.headers["Location"] == StubArtifactLinks().signed_url(A, "inv", key)
    assert not response.headers["Location"].startswith(str(world.client.base_url))
    assert response.headers["Cache-Control"] == "no-store"
    assert [(e.action, e.target, e.detail) for e in world.audit.events] == [("artifact.read", "inv", key)]


def test_only_keys_the_investigation_lists_are_answered(world: _World) -> None:
    world.alert(A, "al")
    world.investigation(A, "inv", "al", "completed", artifacts=("report.md",))
    for key in ("runtime.html", "../other/report.md", "report.md/x"):
        response = world.client.get(f"/investigations/inv/artifacts/{key}", headers=AUTH_A,
                                    follow_redirects=False)
        assert response.status_code == 404, key
    assert world.actions() == []


def test_a_disposition_outside_the_vocabulary_cannot_be_served() -> None:
    with pytest.raises(ValueError, match="not a disposition"):
        Investigation(investigation_id="i", alert_id="a", status="completed", disposition="fine",
                      cost_usd=0.0, created_at=NOW)


# --- learning jobs -------------------------------------------------------------------------


def test_a_relearn_of_a_completed_investigation_is_queued_once_per_request(world: _World) -> None:
    world.alert(A, "al")
    world.investigation(A, "inv", "al", "completed")
    first = world.client.post("/learning-jobs", headers=AUTH_A,
                              json={"investigation_id": "inv", "client_request_id": "r1"})
    assert first.status_code == 201
    job = first.json()
    assert (job["status"], job["trigger"], job["alert_id"]) == ("queued", "explicit", "al")
    assert first.headers["Location"] == f"/learning-jobs/{job['learning_job_id']}"

    again = world.client.post("/learning-jobs", headers=AUTH_A,
                              json={"investigation_id": "inv", "client_request_id": "r1"})
    assert (again.status_code, again.json()) == (200, job)
    second = world.client.post("/learning-jobs", headers=AUTH_A,
                               json={"investigation_id": "inv", "client_request_id": "r2"})
    assert second.status_code == 201
    assert world.actions() == ["learning_job.start", "learning_job.start"]

    listed = world.client.get("/learning-jobs", headers=AUTH_A, params={"investigation_id": "inv"}).json()
    assert len(listed) == 2
    assert world.client.get(f"/learning-jobs/{job['learning_job_id']}", headers=AUTH_A).json() == job


@pytest.mark.parametrize("status", ["queued", "running", "unparseable", "failed", "aborted"])
def test_a_relearn_needs_a_completed_investigation(world: _World, status: str) -> None:
    world.alert(A, "al")
    world.investigation(A, "inv", "al", status)
    response = world.client.post("/learning-jobs", headers=AUTH_A,
                                 json={"investigation_id": "inv", "client_request_id": "r"})
    assert response.status_code == 409
    assert world.actions() == []


def test_a_request_id_reused_for_another_investigation_is_a_conflict(world: _World) -> None:
    world.alert(A, "al")
    world.investigation(A, "inv1", "al", "completed")
    world.investigation(A, "inv2", "al", "completed")
    world.client.post("/learning-jobs", headers=AUTH_A, json={"investigation_id": "inv1", "client_request_id": "r"})
    response = world.client.post("/learning-jobs", headers=AUTH_A,
                                 json={"investigation_id": "inv2", "client_request_id": "r"})
    assert response.status_code == 409


# --- systems -------------------------------------------------------------------------------


def test_put_system_creates_then_replaces(world: _World) -> None:
    created = world.client.put("/systems/tix", headers=AUTH_A,
                               json={"kind": "ticketing", "display_name": "Tickets", "settings": {"queue": "sec"}})
    assert created.status_code == 201
    assert created.headers["Location"] == "/systems/tix"
    replaced = world.client.put("/systems/tix", headers=AUTH_A,
                                json={"kind": "ticketing", "display_name": "Queue", "enabled": False})
    assert replaced.status_code == 200
    assert replaced.json() == {"system_id": "tix", "kind": "ticketing", "display_name": "Queue",
                               "enabled": False, "settings": {}, "has_credentials": False}
    assert world.actions() == ["system.update", "system.update"]


def test_credentials_are_write_only(world: _World) -> None:
    secret = "s3cr3t-value-never-echoed"
    world.client.put("/systems/tix", headers=AUTH_A, json={"kind": "ticketing", "display_name": "T"})
    response = world.client.put("/systems/tix/credentials", headers=AUTH_A,
                                json={"credentials": {"api_token": secret}})
    assert response.status_code == 204
    assert response.content == b""

    listed = world.client.get("/systems", headers=AUTH_A)
    checked = world.client.post("/systems/tix/check", headers=AUTH_A)
    assert listed.json()[0]["has_credentials"] is True
    assert checked.json()["ok"] is True
    for text in (listed.text, checked.text, repr(world.audit.events)):
        assert secret not in text
    assert world.audit.events[-1].action == "system.credentials"
    assert world.audit.events[-1].detail == "fields: api_token"


def test_credentials_for_an_unknown_system_are_refused_and_not_stored(world: _World) -> None:
    response = world.client.put("/systems/nope/credentials", headers=AUTH_A,
                                json={"credentials": {"api_token": "x"}})
    assert response.status_code == 404
    assert world.secrets.has_credentials(A, "nope") is False
    assert world.client.put("/systems/nope/credentials", headers=AUTH_A,
                            json={"credentials": {}}).status_code == 422


def test_check_reports_a_system_without_credentials(world: _World) -> None:
    world.client.put("/systems/tix", headers=AUTH_A, json={"kind": "ticketing", "display_name": "T"})
    assert world.client.post("/systems/tix/check", headers=AUTH_A).json() == {
        "ok": False, "detail": "no credentials set",
    }


# --- the demo server's seed ----------------------------------------------------------------


def test_the_demo_seed_serves_each_tenant_its_own_records() -> None:
    client = TestClient(create_app(demo_deps(lambda: NOW)))
    for token, principal in DEMO_TOKENS.items():
        alerts = client.get("/alerts", headers={"Authorization": f"Bearer {token}"}).json()
        assert alerts, token
        for alert in alerts:
            detail = client.get(f"/alerts/{alert['alert_id']}", headers={"Authorization": f"Bearer {token}"})
            assert detail.status_code == 200, (principal.tenant_id, alert["alert_id"])
