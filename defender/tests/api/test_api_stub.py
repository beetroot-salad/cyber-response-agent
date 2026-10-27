"""The platform API HTTP layer over a scripted fake: routes, login seam, port-answer to response mapping."""
from __future__ import annotations

from defender.tests.support.shared._fixture_uuid import fixture_uuid

import base64
import datetime as _dt
import json
from http import HTTPStatus
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient  # noqa: E402

from defender.api.app import MAX_PAGE, create_app  # noqa: E402
from defender.api.demo import DEMO_ROLES, demo_deps, demo_sessions  # noqa: E402
from defender.api.fakes import (  # noqa: E402
    InMemorySecrets,
    InMemoryStore,
    StubArtifactLinks,
    StubSystemChecker,
)
from defender.api.models import (  # noqa: E402
    Alert,
    AlertSummary,
    Investigation,
    LearningJob,
    Lesson,
    System,
    CredentialsPut,
    SystemCheck,
    SystemPut,
    SystemSettings,
)
from defender.tests.tooling.layout_contracts._spec1080 import api_forbidden  # noqa: E402
from defender.api.ports import (  # noqa: E402
    ApiDeps,
    Conflict,
    NotFound,
    Principal,
    UnknownReference,
)
from defender.identity import (  # noqa: E402
    Bootstrap,
    IdentityService,
    InMemoryIdentityRepository,
    register_tenant,
)
from defender.records._tenant_id import TenantId, TenantRefused  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[3]
NOW = _dt.datetime(2026, 9, 28, 12, 0, tzinfo=_dt.UTC)

A = fixture_uuid("tenant:tenant-a")
DEMO_ONE = fixture_uuid("tenant:t-one")
DEMO_TWO = fixture_uuid("tenant:t-two")
B = fixture_uuid("tenant:tenant-b")
USER = "user-ann"
#: O7/O6 (#1306): the tenant is the path's `T`; the caller is a session seeded through the identity
#: repository, sent as the `__Host-defender_session` cookie plus the configured `Origin`.
T = f"/tenants/{A}"
TB = f"/tenants/{B}"
SESSION_COOKIE = "__Host-defender_session"
SESSION_A = "session-value-of-ann"
SESSION_B = "session-value-of-bob"
#: Cy is a member of both A and B (O3): one session for two tenants.
SESSION_AB = "session-value-of-cy"
ORIGIN = "https://app.defender.test"
AUTH = {"Cookie": f"{SESSION_COOKIE}={SESSION_A}", "Origin": ORIGIN}
AUTH_B = {"Cookie": f"{SESSION_COOKIE}={SESSION_B}", "Origin": ORIGIN}
AUTH_AB = {"Cookie": f"{SESSION_COOKIE}={SESSION_AB}", "Origin": ORIGIN}
BASE = "https://testserver"

ALERT = Alert(
    alert_id="al-1", vendor="tickets", vendor_ticket_id="T-1", title="t", severity="high",
    rule="r", fired_at=NOW, changed_at=NOW, received_at=NOW, raw={"id": "al-1"},
)
SUMMARY = AlertSummary.model_validate(ALERT.model_dump(exclude={"raw"}))
INV = Investigation(
    investigation_id="inv-1", alert_id="al-1", status="completed", disposition="benign",
    cost_usd=1.5, created_at=NOW, artifacts=["report.md", "gather_raw/L1/0.json"],
    # #1108 P4 O-WARN: the knowledge revision the run used (`current` = the run record's `fresh`).
    knowledge={"status": "current", "commit": "f4e5c0de0000f4e5c0de0000f4e5c0de0000f4e5",
               "stale_kind": None},
)
JOB = LearningJob(
    learning_job_id="lj-1", investigation_id="inv-1", alert_id="al-1", status="queued",
    trigger="explicit", created_at=NOW,
)
LESSON = Lesson(lesson_id="le-1", title="t", description="d", status="live")
SETTINGS = SystemSettings(system_id="tix", kind="ticketing", display_name="T", enabled=True,
                          settings={"queue": "sec"})
SIGNED = "https://blobs.invalid/signed?sig=1"

#: #1131's "API" section as (method, path), now under `/tenants/{tenant_id}` (#1306 O7).
EXISTING_ROUTES = {
    ("GET", "/tenants/{tenant_id}/alerts"),
    ("GET", "/tenants/{tenant_id}/alerts/{alert_id}"),
    ("POST", "/tenants/{tenant_id}/investigations"),
    ("GET", "/tenants/{tenant_id}/investigations"),
    ("GET", "/tenants/{tenant_id}/investigations/{investigation_id}"),
    ("POST", "/tenants/{tenant_id}/investigations/{investigation_id}/cancel"),
    ("DELETE", "/tenants/{tenant_id}/investigations/{investigation_id}"),
    ("GET", "/tenants/{tenant_id}/investigations/{investigation_id}/artifacts/{key}"),
    ("POST", "/tenants/{tenant_id}/learning-jobs"),
    ("GET", "/tenants/{tenant_id}/learning-jobs"),
    ("GET", "/tenants/{tenant_id}/learning-jobs/{learning_job_id}"),
    ("GET", "/tenants/{tenant_id}/lessons"),
    ("GET", "/tenants/{tenant_id}/systems"),
    ("PUT", "/tenants/{tenant_id}/systems/{system_id}"),
    ("PUT", "/tenants/{tenant_id}/systems/{system_id}/credentials"),
    ("POST", "/tenants/{tenant_id}/systems/{system_id}/check"),
}
#: What #1306 adds (design "Endpoints"; param names pinned by this suite).
IDENTITY_ROUTES = {
    ("GET", "/auth/login"),
    ("GET", "/auth/callback"),
    ("POST", "/auth/logout"),
    ("GET", "/me"),
    ("GET", "/tenants/{tenant_id}/members"),
    ("DELETE", "/tenants/{tenant_id}/members/{user_id}"),
    ("GET", "/tenants/{tenant_id}/invitations"),
    ("POST", "/tenants/{tenant_id}/invitations"),
    ("DELETE", "/tenants/{tenant_id}/invitations/{invitation_id}"),
    ("POST", "/invitations/{invitation_id}/accept"),
    ("GET", "/admin/tenants"),
    ("POST", "/admin/tenants/{tenant_id}/invitations"),
}
PUBLIC_ROUTES = EXISTING_ROUTES | IDENTITY_ROUTES

#: One successful call per route: (route, concrete path, body, the port answers it needs).
HAPPY: list[tuple[tuple[str, str], str, dict[str, Any] | None, dict[str, Any]]] = [
    (("GET", "/tenants/{tenant_id}/alerts"), f"{T}/alerts", None, {"list_alerts": [SUMMARY]}),
    (("GET", "/tenants/{tenant_id}/alerts/{alert_id}"), f"{T}/alerts/al-1", None, {"get_alert": ALERT}),
    (("POST", "/tenants/{tenant_id}/investigations"), f"{T}/investigations",
     {"alert_id": "al-1", "client_request_id": "r1"}, {"create_investigation": (INV, True)}),
    (("GET", "/tenants/{tenant_id}/investigations"), f"{T}/investigations", None, {"list_investigations": [INV]}),
    (("GET", "/tenants/{tenant_id}/investigations/{investigation_id}"), f"{T}/investigations/inv-1", None,
     {"get_investigation": INV}),
    (("POST", "/tenants/{tenant_id}/investigations/{investigation_id}/cancel"), f"{T}/investigations/inv-1/cancel", None,
     {"cancel_investigation": INV}),
    (("DELETE", "/tenants/{tenant_id}/investigations/{investigation_id}"), f"{T}/investigations/inv-1", None,
     {"delete_investigation": None}),
    (("GET", "/tenants/{tenant_id}/investigations/{investigation_id}/artifacts/{key}"),
     f"{T}/investigations/inv-1/artifacts/report.md", None,
     {"get_investigation": INV, "signed_url": SIGNED}),
    (("POST", "/tenants/{tenant_id}/learning-jobs"), f"{T}/learning-jobs",
     {"investigation_id": "inv-1", "client_request_id": "r1"}, {"create_learning_job": (JOB, True)}),
    (("GET", "/tenants/{tenant_id}/learning-jobs"), f"{T}/learning-jobs", None, {"list_learning_jobs": [JOB]}),
    (("GET", "/tenants/{tenant_id}/learning-jobs/{learning_job_id}"), f"{T}/learning-jobs/lj-1", None,
     {"get_learning_job": JOB}),
    (("GET", "/tenants/{tenant_id}/lessons"), f"{T}/lessons", None, {"list_lessons": [LESSON]}),
    (("GET", "/tenants/{tenant_id}/systems"), f"{T}/systems", None,
     {"list_systems": [SETTINGS], "has_credentials": False}),
    (("PUT", "/tenants/{tenant_id}/systems/{system_id}"), f"{T}/systems/tix",
     {"kind": "ticketing", "display_name": "T", "enabled": True, "settings": {}},
     {"put_system": (SETTINGS, True), "has_credentials": False}),
    (("PUT", "/tenants/{tenant_id}/systems/{system_id}/credentials"), f"{T}/systems/tix/credentials",
     {"credentials": {"api_token": "x"}},
     {"get_system": SETTINGS, "has_credentials": False, "put_credentials": None}),
    (("POST", "/tenants/{tenant_id}/systems/{system_id}/check"), f"{T}/systems/tix/check", None,
     {"get_system": SETTINGS, "has_credentials": True,
      "check": SystemCheck(ok=True, detail="fine")}),
]


#: The writes a route makes through a transaction; they carry no tenant — the transaction does.
TX_WRITES = {"create_investigation", "cancel_investigation", "delete_investigation",
             "create_learning_job", "put_system"}


class Scripted:
    """Every port the routes call. `answers` maps a port method's name to what it returns, an exception it..."""

    def __init__(self, answers: dict[str, Any]) -> None:
        self.answers = answers
        self.calls: list[tuple[str, tuple[Any, ...], dict[str, Any]]] = []
        self.transactions: list[tuple[str, str]] = []
        self.audits: list[tuple[str, str, str, str, str]] = []

    def transaction(self, tenant_id: str, actor: str) -> _ScriptedTransaction:
        return _ScriptedTransaction(self, tenant_id, actor)

    def __getattr__(self, name: str) -> Callable[..., Any]:
        if name.startswith("_"):
            raise AttributeError(name)

        def call(*args: Any, **kwargs: Any) -> Any:
            self.calls.append((name, args, kwargs))
            if name not in self.answers:
                raise AssertionError(f"unscripted port call: {name}{args}")
            answer = self.answers[name]
            if isinstance(answer, BaseException):
                raise answer
            return answer(*args, **kwargs) if callable(answer) else answer

        return call

    def called(self, name: str) -> list[tuple[tuple[Any, ...], dict[str, Any]]]:
        return [(args, kwargs) for n, args, kwargs in self.calls if n == name]


class _ScriptedTransaction:
    def __init__(self, ports: Scripted, tenant_id: str, actor: str) -> None:
        self.ports = ports
        self.tenant_id = tenant_id
        self.actor = actor
        self.pending: list[tuple[str, str, str, str, str]] = []

    def __enter__(self) -> _ScriptedTransaction:
        self.ports.transactions.append((self.tenant_id, self.actor))
        return self

    def __exit__(self, exc_type: type[BaseException] | None, *_: object) -> None:
        if exc_type is None:
            self.ports.audits.extend(self.pending)

    def __getattr__(self, name: str) -> Callable[..., Any]:
        if name.startswith("_"):
            raise AttributeError(name)
        return getattr(self.ports, name)

    def audit(self, action: str, target: str, detail: str = "") -> None:
        failure = self.ports.answers.get("audit")
        if isinstance(failure, BaseException):
            raise failure
        self.pending.append((self.tenant_id, self.actor, action, target, detail))


class _Unused:
    """A sign-in or mail port these route tests never exercise: any call is a failure."""

    def __getattr__(self, name: str) -> Callable[..., Any]:
        raise AssertionError(f"a route test reached the unused port: {name}")


def _identity() -> tuple[IdentityService, dict[str, str]]:
    """Ann is a member of A, Bob of B and Cy of both, each with a seeded session (O7). Returns the
    service and the seeded user ids by session value."""
    repo = InMemoryIdentityRepository()
    register_tenant(repo, TenantId(A))
    register_tenant(repo, TenantId(B))
    users: dict[str, str] = {}
    for email, tenant, session in (("ann@a.example", A, SESSION_A), ("bob@b.example", B, SESSION_B)):
        user = repo.add_user(email, created_at=NOW, status="active", display_name=email)
        repo.add_membership(user.id, TenantId(tenant), status="active", invited_by="system",
                            created_at=NOW, accepted_at=NOW)
        repo.add_session(session, user.id, now=NOW, expires_at=NOW + _dt.timedelta(days=7))
        users[session] = user.id
    cy = repo.add_user("cy@c.example", created_at=NOW, status="active", display_name="cy")
    for tenant in (A, B):
        repo.add_membership(cy.id, TenantId(tenant), status="active", invited_by="system",
                            created_at=NOW, accepted_at=NOW)
    repo.add_session(SESSION_AB, cy.id, now=NOW, expires_at=NOW + _dt.timedelta(days=7))
    users[SESSION_AB] = cy.id
    service = IdentityService(repo, signin=_Unused(), mail=_Unused(), clock=lambda: NOW,
                              bootstrap=Bootstrap(administrators=(), tenants={}))
    return service, users


def _deps(ports: Any) -> tuple[ApiDeps, dict[str, str]]:
    identity, users = _identity()
    return ApiDeps(
        identity=identity, frontend_origin=ORIGIN,
        alerts=ports, investigations=ports, learning_jobs=ports, lessons=ports,
        systems=ports, writes=ports, secrets=ports, checker=ports, artifact_links=ports,
    ), users


class Api:
    def __init__(self, **answers: Any) -> None:
        self.ports = Scripted(answers)
        deps, users = _deps(self.ports)
        #: Ann's user id, as the identity repository minted it.
        self.user = users[SESSION_A]
        self.client = TestClient(create_app(deps), base_url=BASE)

    def actions(self) -> list[str]:
        return [action for _, _, action, _, _ in self.ports.audits]

    def audited(self) -> list[tuple[str, str, str]]:
        """The committed audit events, as (action, target, detail)."""
        return [(action, target, detail) for _, _, action, target, detail in self.ports.audits]

    def lenient(self) -> TestClient:
        """A client that answers a server error as a 500 instead of raising it."""
        return TestClient(self.client.app, base_url=BASE, raise_server_exceptions=False)


# --- the contract --------------------------------------------------------------------------


def test_the_published_routes_are_exactly_1131s_list_under_tenants_plus_1306s() -> None:
    """Conflict updated, O7: #1131's routes move under `/tenants/{tenant_id}`; #1306 adds its own; no Bearer scheme (O6)."""
    doc = Api().client.get("/openapi.json").json()
    documented = {(method.upper(), path) for path, ops in doc["paths"].items() for method in ops}
    assert documented == PUBLIC_ROUTES
    schemes = doc.get("components", {}).get("securitySchemes", {})
    assert "HTTPBearer" not in schemes
    assert not [s for s in schemes.values() if str(s.get("scheme", "")).lower() == "bearer"]


def test_the_happy_path_table_covers_every_existing_route() -> None:
    assert {route for route, *_ in HAPPY} == EXISTING_ROUTES


def test_the_api_never_loads_the_runtime_or_the_learning_loop() -> None:
    """Conflict updated, A4: `defender.identity` joins the guard and loads no `defender.api` module."""
    probe = (
        "import json, sys; import defender.api.app, defender.api.demo, defender.api.serve; "
        "import defender.identity; "
        "print(json.dumps(sorted(sys.modules)))"
    )
    out = subprocess.run(
        [sys.executable, "-c", probe], cwd=REPO_ROOT, capture_output=True, text=True,
        encoding="utf-8", check=True,
    )
    assert api_forbidden(json.loads(out.stdout)) == []


def test_the_identity_package_loads_no_api_runtime_or_learning_module() -> None:
    """A4: `defender.identity` imports nothing from `api`, nor anything the API must never load
    (the learning loop and what was `defender.runtime` before #1308 placed it by layer)."""
    probe = "import json, sys; import defender.identity; print(json.dumps(sorted(sys.modules)))"
    out = subprocess.run(
        [sys.executable, "-c", probe], cwd=REPO_ROOT, capture_output=True, text=True,
        encoding="utf-8", check=True,
    )
    loaded = json.loads(out.stdout)
    assert [m for m in loaded if m.startswith("defender.api")] + api_forbidden(loaded) == []


def test_the_tenancy_package_loads_no_identity_module() -> None:
    """DC-4: `identity` sits right after `tenancy`, so importing `defender.tenancy` pulls nothing from it."""
    probe = (
        "import json, sys; import defender.tenancy; "
        "print(json.dumps(sorted(m for m in sys.modules if m.startswith('defender.identity'))))"
    )
    out = subprocess.run(
        [sys.executable, "-c", probe], cwd=REPO_ROOT, capture_output=True, text=True,
        encoding="utf-8", check=True,
    )
    assert json.loads(out.stdout) == []


# --- session and tenant --------------------------------------------------------------------


@pytest.mark.parametrize(("route", "path", "body", "answers"), HAPPY, ids=lambda v: str(v))
def test_every_route_asks_the_ports_as_the_sessions_user_in_the_paths_tenant(
    route: tuple[str, str], path: str, body: dict[str, Any] | None, answers: dict[str, Any]
) -> None:
    """Conflict updated, O7/P-D: the tenant is the path's T, the actor is the session's user id."""
    api = Api(**answers)
    response = api.client.request(route[0], path, headers=AUTH, json=body, follow_redirects=False)
    assert response.status_code < 400, response.text
    assert api.ports.calls, "the route asked no port"
    assert {args[0] for name, args, _ in api.ports.calls if name not in TX_WRITES} <= {A}
    assert set(api.ports.transactions) <= {(A, api.user)}
    assert {(tenant, user) for tenant, user, *_ in api.ports.audits} <= {(A, api.user)}
    if any(name in TX_WRITES for name, _, _ in api.ports.calls):
        assert api.ports.transactions == [(A, api.user)], "a write runs in one transaction"


@pytest.mark.parametrize(("route", "path", "body", "answers"), HAPPY, ids=lambda v: str(v))
def test_a_member_of_one_tenant_gets_404_and_no_port_call_for_another_tenants_path(
    route: tuple[str, str], path: str, body: dict[str, Any] | None, answers: dict[str, Any]
) -> None:
    """P-D (new): Ann, a member of A only, asking under B's path is a 404 before any port."""
    api = Api(**answers)
    response = api.client.request(route[0], path.replace(T, TB), headers=AUTH, json=body)
    assert response.status_code == 404
    assert response.headers["Content-Type"] == "application/problem+json"
    assert api.ports.calls == []
    assert api.ports.transactions == []
    # control: the same session on A's own path is served
    assert api.client.request(route[0], path, headers=AUTH, json=body,
                              follow_redirects=False).status_code < 400


@pytest.mark.parametrize(("route", "path", "body", "answers"), HAPPY, ids=lambda v: str(v))
@pytest.mark.parametrize("headers", [
    {"Origin": ORIGIN},
    {"Origin": ORIGIN, "Cookie": f"{SESSION_COOKIE}=not-a-session"},
    {"Origin": ORIGIN, "Authorization": f"Bearer {SESSION_A}"},
    {"Origin": ORIGIN, "Authorization": f"Basic {SESSION_A}"},
], ids=["no-cookie", "unknown-cookie", "session-value-as-bearer", "session-value-as-basic"])
def test_every_route_refuses_a_caller_without_a_known_session_cookie(
    route: tuple[str, str], path: str, body: dict[str, Any] | None, answers: dict[str, Any],
    headers: dict[str, str],
) -> None:
    """Conflict updated, O1/O6: no, unknown, or Bearer-carried session → 401, no port, no Bearer challenge."""
    api = Api(**answers)
    response = api.client.request(route[0], path, headers=headers, json=body)
    assert response.status_code == 401
    assert "Bearer" not in response.headers.get("WWW-Authenticate", "")
    assert api.ports.calls == []
    assert api.ports.transactions == []


@pytest.mark.parametrize(("route", "path", "body", "answers"),
                         [row for row in HAPPY if row[0][0] != "GET"], ids=lambda v: str(v))
@pytest.mark.parametrize("origin", [None, "https://evil.example", ORIGIN + ".evil.example", "null",
                                    ORIGIN.replace("https://", "http://"), "https://evil.example/" + ORIGIN,
                                    ORIGIN + ":8443"],
                         ids=["missing-origin", "foreign-origin", "suffixed-origin", "null-origin",
                              "http-origin", "origin-ending-with-ours", "other-port-origin"])
def test_every_state_changing_route_refuses_a_valid_session_without_the_frontend_origin(
    route: tuple[str, str], path: str, body: dict[str, Any] | None, answers: dict[str, Any],
    origin: str | None,
) -> None:
    """O6: a valid cookie with a missing or foreign Origin is 403 before any port; the same call with Origin is served."""
    api = Api(**answers)
    headers = {"Cookie": f"{SESSION_COOKIE}={SESSION_A}"} | ({} if origin is None else {"Origin": origin})
    response = api.client.request(route[0], path, headers=headers, json=body, follow_redirects=False)
    assert response.status_code == 403, response.text
    assert api.ports.calls == []
    assert api.ports.transactions == []
    # control: the same session with the configured Origin is served
    assert api.client.request(route[0], path, headers=AUTH, json=body,
                              follow_redirects=False).status_code < 400


@pytest.mark.parametrize("claim", ["Acme_Corp", "org_2NxAbCdEf", ""])
def test_a_path_tenant_that_fails_the_grammar_is_a_404_not_a_500(claim: str) -> None:
    """Conflict updated (was: a login whose tenant claim fails the grammar is a 401), r6 Fixed details: a malformed T is 404."""
    api = Api()
    response = api.lenient().get(f"/tenants/{claim}/alerts", headers=AUTH)
    assert response.status_code == 404
    assert api.ports.calls == []


@pytest.mark.parametrize(("path", "body"), [
    (f"{T}/investigations", {"alert_id": "al-1", "client_request_id": "r", "tenant_id": A}),
    (f"{T}/learning-jobs", {"investigation_id": "inv-1", "client_request_id": "r", "tenant_id": A}),
])
def test_a_body_cannot_name_a_tenant(path: str, body: dict[str, str]) -> None:
    """Conflict updated, O7: still no tenant in a body, now under the prefixed path."""
    api = Api()
    assert api.client.post(path, headers=AUTH, json=body).status_code == 422
    assert api.ports.calls == []


# --- creates: 201 or replay ----------------------------------------------------------------


@pytest.mark.parametrize(("path", "body", "port", "record", "location", "audit"), [
    (f"{T}/investigations", {"alert_id": "al-1", "client_request_id": "r1"}, "create_investigation",
     INV, f"{T}/investigations/inv-1", ("investigation.start", "inv-1", "alert al-1")),
    (f"{T}/learning-jobs", {"investigation_id": "inv-1", "client_request_id": "r1"},
     "create_learning_job", JOB, f"{T}/learning-jobs/lj-1", ("learning_job.start", "lj-1", "investigation inv-1")),
])
def test_a_create_is_a_201_with_location_only_when_the_store_created(
    path: str, body: dict[str, str], port: str, record: Any, location: str,
    audit: tuple[str, str, str],
) -> None:
    created = Api(**{port: (record, True)})
    response = created.client.post(path, headers=AUTH, json=body)
    assert response.status_code == 201
    assert response.headers["Location"] == BASE + location
    assert response.json() == record.model_dump(mode="json")
    assert created.ports.called(port) == [((*body.values(),), {})]
    assert created.ports.transactions == [(A, created.user)]
    assert created.audited() == [audit]

    replayed = Api(**{port: (record, False)})
    response = replayed.client.post(path, headers=AUTH, json=body)
    assert response.status_code == 200
    assert "Location" not in response.headers
    assert response.json() == record.model_dump(mode="json")
    assert replayed.ports.transactions == [(A, replayed.user)]
    assert replayed.audited() == [], "a replay is not a second start"


@pytest.mark.parametrize(("path", "body", "port", "record"), [
    (f"{T}/investigations", {"alert_id": "al-OTHER", "client_request_id": "r1"}, "create_investigation", INV),
    (f"{T}/learning-jobs", {"investigation_id": "inv-OTHER", "client_request_id": "r1"},
     "create_learning_job", JOB),
])
@pytest.mark.parametrize("created", [True, False])
def test_a_create_answered_for_another_target_is_a_500_and_commits_nothing(
    path: str, body: dict[str, str], port: str, record: Any, created: bool,
) -> None:
    api = Api(**{port: (record, created)})
    response = api.lenient().post(path, headers=AUTH, json=body)
    assert response.status_code == 500
    assert "Location" not in response.headers
    assert api.audited() == []


def test_a_create_whose_audit_write_fails_commits_nothing() -> None:
    api = Api(create_investigation=(INV, True), audit=RuntimeError("audit down"))
    response = api.lenient().post(f"{T}/investigations", headers=AUTH,
                                  json={"alert_id": "al-1", "client_request_id": "r1"})
    assert response.status_code == 500
    assert api.audited() == []


def test_put_system_is_a_201_at_its_own_url_when_created_and_200_when_replaced() -> None:
    body = {"kind": "ticketing", "display_name": "T", "enabled": False, "settings": {"q": "s"}}
    created = Api(put_system=(SETTINGS, True), has_credentials=False)
    response = created.client.put(f"{T}/systems/tix", headers=AUTH, params={"x": "1"}, json=body)
    assert (response.status_code, response.headers["Location"]) == (201, BASE + f"{T}/systems/tix")
    ((system_id, sent), kwargs), = created.ports.called("put_system")
    assert (system_id, sent.model_dump(), kwargs) == ("tix", body, {})
    replaced = Api(put_system=(SETTINGS, False), has_credentials=False)
    response = replaced.client.put(f"{T}/systems/tix", headers=AUTH, json=body)
    assert response.status_code == 200
    assert "Location" not in response.headers
    assert created.audited() == replaced.audited() == [("system.update", "tix", "")]


@pytest.mark.parametrize("model", [SystemPut, CredentialsPut])
def test_a_whole_record_put_body_has_no_defaults(model: type[Any]) -> None:
    """A PUT replaces the record, so a default would silently reset whatever a caller left out."""
    assert [name for name, field in model.model_fields.items() if not field.is_required()] == []


@pytest.mark.parametrize("missing", ["enabled", "settings"])
def test_put_system_without_a_field_is_refused(missing: str) -> None:
    api = Api()
    body = {"kind": "ticketing", "display_name": "T", "enabled": True, "settings": {}}
    del body[missing]
    assert api.client.put(f"{T}/systems/tix", headers=AUTH, json=body).status_code == 422
    assert api.ports.calls == []


@pytest.mark.parametrize(("method", "path", "port", "answer", "action"), [
    ("POST", f"{T}/investigations/inv-1/cancel", "cancel_investigation", INV, "investigation.cancel"),
    ("DELETE", f"{T}/investigations/inv-1", "delete_investigation", None, "investigation.delete"),
])
def test_a_write_is_audited_in_its_own_transaction(
    method: str, path: str, port: str, answer: Any, action: str,
) -> None:
    api = Api(**{port: answer})
    assert api.client.request(method, path, headers=AUTH).status_code < 400
    assert api.ports.called(port) == [(("inv-1",), {})]
    assert api.ports.transactions == [(A, api.user)]
    assert api.audited() == [(action, "inv-1", "")]


# --- refusals ------------------------------------------------------------------------------


@pytest.mark.parametrize(("path", "port"), [
    (f"{T}/alerts/al-1", "get_alert"),
    (f"{T}/investigations/inv-1", "get_investigation"),
    (f"{T}/investigations/inv-1/artifacts/report.md", "get_investigation"),
    (f"{T}/learning-jobs/lj-1", "get_learning_job"),
])
def test_a_read_the_store_answers_none_is_a_404(path: str, port: str) -> None:
    api = Api(**{port: None})
    assert api.client.get(path, headers=AUTH, follow_redirects=False).status_code == 404
    assert api.ports.audits == []


@pytest.mark.parametrize(("method", "path", "body", "port", "error", "code"), [
    ("POST", f"{T}/investigations/inv-1/cancel", None, "cancel_investigation", NotFound("x"), 404),
    ("POST", f"{T}/investigations/inv-1/cancel", None, "cancel_investigation", Conflict("x"), 409),
    ("DELETE", f"{T}/investigations/inv-1", None, "delete_investigation", NotFound("x"), 404),
    ("DELETE", f"{T}/investigations/inv-1", None, "delete_investigation", Conflict("x"), 409),
    ("POST", f"{T}/investigations", {"alert_id": "al-1", "client_request_id": "r"},
     "create_investigation", UnknownReference("x"), 422),
    ("POST", f"{T}/learning-jobs", {"investigation_id": "inv-1", "client_request_id": "r"},
     "create_learning_job", UnknownReference("x"), 422),
    ("POST", f"{T}/learning-jobs", {"investigation_id": "inv-1", "client_request_id": "r"},
     "create_learning_job", Conflict("x"), 409),
])
def test_a_store_refusal_maps_to_its_status_and_audits_nothing(
    method: str, path: str, body: dict[str, str] | None, port: str, error: Exception, code: int,
) -> None:
    api = Api(**{port: error})
    response = api.client.request(method, path, headers=AUTH, json=body)
    assert response.status_code == code
    assert response.headers["Content-Type"] == "application/problem+json"
    assert response.json() == {"type": "about:blank", "title": HTTPStatus(code).phrase,
                               "status": code, "detail": "x"}
    assert api.ports.audits == [], "the refused write's transaction committed nothing"


# --- artifacts -----------------------------------------------------------------------------


@pytest.mark.parametrize("key", ["report.md", "gather_raw/L1/0.json"])
def test_an_artifact_read_redirects_to_the_signed_link_and_is_audited(key: str) -> None:
    api = Api(get_investigation=INV, signed_url=SIGNED)
    response = api.client.get(f"{T}/investigations/inv-1/artifacts/{key}", headers=AUTH,
                              follow_redirects=False)
    assert response.status_code == 307
    assert response.headers["Location"] == SIGNED
    assert response.headers["Cache-Control"] == "no-store"
    assert api.ports.called("signed_url") == [((A, "inv-1", key), {})]
    assert api.audited() == [("artifact.read", "inv-1", key)]


def test_an_artifact_read_whose_link_fails_is_not_audited() -> None:
    api = Api(get_investigation=INV, signed_url=RuntimeError("signer down"))
    response = api.lenient().get(f"{T}/investigations/inv-1/artifacts/report.md", headers=AUTH,
                                 follow_redirects=False)
    assert response.status_code == 500
    assert api.ports.transactions == []
    assert api.ports.audits == []


def test_an_artifact_link_is_not_handed_out_unless_its_read_is_audited() -> None:
    api = Api(get_investigation=INV, signed_url=SIGNED, audit=RuntimeError("audit down"))
    response = api.lenient().get(f"{T}/investigations/inv-1/artifacts/report.md", headers=AUTH,
                                 follow_redirects=False)
    assert response.status_code == 500
    assert SIGNED not in response.text
    assert "Location" not in response.headers


@pytest.mark.parametrize("key", ["runtime.html", "%2E%2E/other/report.md", "report.md/x",
                                 "other/report.md"])
def test_only_keys_the_investigation_lists_are_answered(key: str) -> None:
    api = Api(get_investigation=INV)
    response = api.client.get(f"{T}/investigations/inv-1/artifacts/{key}", headers=AUTH,
                              follow_redirects=False)
    assert response.status_code == 404
    assert response.json()["detail"].startswith("no artifact"), "refused by the route's own list"
    assert api.ports.called("signed_url") == []
    assert api.ports.audits == []


# --- systems and credentials ---------------------------------------------------------------


@pytest.mark.parametrize("has", [True, False])
def test_has_credentials_is_the_secret_stores_answer(has: bool) -> None:
    api = Api(list_systems=[SETTINGS], has_credentials=has,
              get_system=SETTINGS, check=lambda tenant, system: SystemCheck(ok=True, detail="x"))
    listed = api.client.get(f"{T}/systems", headers=AUTH).json()["items"]
    assert listed == [System(**SETTINGS.model_dump(), has_credentials=has).model_dump(mode="json")]
    api.client.post(f"{T}/systems/tix/check", headers=AUTH)
    ((_, checked), _), = api.ports.called("check")
    assert checked.has_credentials is has
    assert api.ports.called("has_credentials")[0] == ((A, "tix"), {})


def test_credentials_are_written_through_and_never_echoed_or_audited() -> None:
    secret = "s3cr3t-value-never-echoed"
    api = Api(get_system=SETTINGS, has_credentials=False, put_credentials=None)
    response = api.client.put(f"{T}/systems/tix/credentials", headers=AUTH,
                              json={"credentials": {"api_token": secret}})
    assert (response.status_code, response.content) == (204, b"")
    assert api.ports.called("put_credentials") == [((A, "tix", {"api_token": secret}), {})]
    assert api.ports.called("has_credentials") == [], "an existence check, not a read"
    assert api.audited() == [("system.credentials", "tix", "fields: api_token")]
    assert secret not in repr(api.ports.audits)


def test_credentials_are_not_written_when_their_audit_write_fails() -> None:
    api = Api(get_system=SETTINGS, put_credentials=None, audit=RuntimeError("audit down"))
    response = api.lenient().put(f"{T}/systems/tix/credentials", headers=AUTH,
                                 json={"credentials": {"api_token": "x"}})
    assert response.status_code == 500
    assert api.ports.called("put_credentials") == []


def test_a_failed_credentials_write_commits_no_audit() -> None:
    api = Api(get_system=SETTINGS, put_credentials=RuntimeError("vault down"))
    response = api.lenient().put(f"{T}/systems/tix/credentials", headers=AUTH,
                                 json={"credentials": {"api_token": "x"}})
    assert response.status_code == 500
    assert api.ports.audits == []


#: Each as it is spelled inside a JSON string, so the body is valid JSON that decodes to it.
@pytest.mark.parametrize("key", [r"a\u0000b", r"\ud800", "", "has space", "x" * 65, "9lead"])
def test_a_credential_field_name_outside_the_grammar_is_refused(key: str) -> None:
    """A field name reaches the audit detail, so one the audit store would refuse never gets in."""
    api = Api()
    response = api.client.put(f"{T}/systems/tix/credentials", headers={**AUTH, "Content-Type": "application/json"},
                              content=('{"credentials": {"' + key + '": "v"}}').encode())
    assert response.status_code == 422
    assert api.ports.calls == []


def test_credentials_for_an_unknown_system_are_refused_before_the_secret_store() -> None:
    api = Api(get_system=None)
    response = api.client.put(f"{T}/systems/nope/credentials", headers=AUTH, json={"credentials": {"k": "v"}})
    assert response.status_code == 404
    assert api.ports.called("put_credentials") == []
    assert Api().client.put(f"{T}/systems/tix/credentials", headers=AUTH,
                            json={"credentials": {}}).status_code == 422


# --- errors: one shape, RFC 9457 ----------------------------------------------------------

PROBLEM_KEYS = {"type", "title", "status", "detail"}


@pytest.mark.parametrize(("method", "path", "body", "headers", "answers", "code"), [
    ("GET", f"{T}/alerts", None, {"Origin": ORIGIN}, {}, 401),
    ("GET", f"{TB}/alerts", None, AUTH, {}, 404),
    ("GET", f"{T}/alerts/al-1", None, AUTH, {"get_alert": None}, 404),
    ("GET", "/nowhere", None, AUTH, {}, 404),
    ("POST", f"{T}/alerts", None, AUTH, {}, 405),
    ("POST", f"{T}/investigations/inv-1/cancel", None, AUTH, {"cancel_investigation": Conflict("ended")}, 409),
    ("POST", f"{T}/investigations", {"alert_id": "al-1", "client_request_id": "r"}, AUTH,
     {"create_investigation": UnknownReference("no alert")}, 422),
    ("GET", f"{T}/alerts?cursor=zz", None, AUTH, {}, 422),
    ("GET", f"{T}/alerts?limit=0", None, AUTH, {}, 422),
    ("GET", f"{T}/alerts", None, AUTH, {"list_alerts": RuntimeError("db exploded at host-7")}, 500),
])
def test_every_error_is_an_rfc_9457_problem(  # conflict updated: O7 paths; O6 401 has no Bearer challenge; P-D 404 row
    method: str, path: str, body: dict[str, Any] | None, headers: dict[str, str],
    answers: dict[str, Any], code: int,
) -> None:
    api = Api(**answers)
    response = api.lenient().request(method, path, headers=headers, json=body)
    assert response.status_code == code
    assert response.headers["Content-Type"] == "application/problem+json"
    problem = response.json()
    assert PROBLEM_KEYS <= set(problem) <= PROBLEM_KEYS | {"errors"}
    assert (problem["type"], problem["title"], problem["status"]) == (
        "about:blank", HTTPStatus(code).phrase, code)
    if code == 401:
        assert "WWW-Authenticate" not in response.headers, "a session cookie has no challenge (O6)"
    if code == 500:
        assert problem["detail"] == "internal error", "a 500 says nothing about its cause"


def test_a_validation_problem_lists_what_failed_and_never_echoes_the_value() -> None:
    secret = 87654321987654321
    api = Api()
    response = api.client.put(f"{T}/systems/tix/credentials", headers=AUTH,
                              json={"credentials": {"api_token": secret}})
    assert response.status_code == 422
    problem = response.json()
    assert problem["errors"] == [{"loc": ["body", "credentials", "api_token"],
                                  "msg": "Input should be a valid string", "type": "string_type"}]
    assert str(secret) not in response.text


def test_the_published_contract_declares_each_routes_problems() -> None:
    doc = Api().client.get("/openapi.json").json()
    assert "HTTPValidationError" not in json.dumps(doc)
    declared: dict[tuple[str, str], set[int]] = {}
    for path, operations in doc["paths"].items():
        for method, operation in operations.items():
            errors = {int(s) for s in operation["responses"] if int(s) >= 400}
            declared[(method.upper(), path)] = errors
            if (method.upper(), path) not in EXISTING_ROUTES:
                continue
            for status in errors:
                assert operation["responses"][str(status)]["content"] == {
                    "application/problem+json": {"schema": {"$ref": "#/components/schemas/Problem"}}}
    assert all({401, 422, 500} <= errors for route, errors in declared.items()
               if route in EXISTING_ROUTES)
    assert declared[("POST", "/tenants/{tenant_id}/investigations/{investigation_id}/cancel")] >= {404, 409}
    assert declared[("DELETE", "/tenants/{tenant_id}/investigations/{investigation_id}")] >= {404, 409}
    assert declared[("POST", "/tenants/{tenant_id}/investigations")] >= {409}
    assert declared[("POST", "/tenants/{tenant_id}/learning-jobs")] >= {409}
    assert declared[("GET", "/tenants/{tenant_id}/investigations/{investigation_id}/artifacts/{key}")] >= {404}
    # P-D: every tenant route answers 404 to a non-member, so every one declares it.
    assert all(404 in errors for (_, path), errors in declared.items()
               if path.startswith("/tenants/{tenant_id}"))
    # F-4: every identity route but the two redirecting ones declares its 401 as a problem.
    signed_out = {("GET", "/auth/login"), ("GET", "/auth/callback")}
    for route in IDENTITY_ROUTES - signed_out:
        assert 401 in declared[route], route
        for status in declared[route]:
            content = doc["paths"][route[1]][route[0].lower()]["responses"][str(status)]["content"]
            assert content == {
                "application/problem+json": {"schema": {"$ref": "#/components/schemas/Problem"}}}, (route, status)


# --- the boundary: malformed input never reaches a port ------------------------------------


@pytest.mark.parametrize("param", ["fired_after", "fired_before"])
def test_a_time_without_an_offset_is_refused_at_the_boundary(param: str) -> None:
    api = Api()
    response = api.client.get(f"{T}/alerts", headers=AUTH, params={param: "2026-09-28T06:00:00"})
    assert response.status_code == 422
    assert api.ports.calls == []


@pytest.mark.parametrize("value", ["20260928", "2026", "1727500000.5", "-1"])
@pytest.mark.parametrize("param", ["fired_after", "fired_before"])
def test_a_bare_number_is_not_read_as_a_time(param: str, value: str) -> None:
    api = Api()
    response = api.client.get(f"{T}/alerts", headers=AUTH, params={param: value})
    assert response.status_code == 422
    assert api.ports.calls == []


def test_an_aware_time_reaches_the_store_as_the_same_instant_in_utc() -> None:
    api = Api(list_alerts=[SUMMARY])
    after = _dt.datetime(2026, 9, 28, 8, 0, tzinfo=_dt.timezone(_dt.timedelta(hours=2)))
    response = api.client.get(f"{T}/alerts", headers=AUTH, params={
        "fired_after": after.isoformat(), "severity": "high", "limit": 7,
    })
    assert response.json() == {"items": [SUMMARY.model_dump(mode="json")], "next_cursor": None}
    ((tenant,), kwargs), = api.ports.called("list_alerts")
    assert tenant == A
    assert kwargs == {"fired_after": after, "fired_before": None, "severity": "high",
                      "after": None, "limit": 8}
    assert kwargs["fired_after"].utcoffset() == _dt.timedelta(0)


def test_a_record_time_is_served_in_utc() -> None:
    odd = _dt.timezone(_dt.timedelta(minutes=19, seconds=32))
    inv = INV.model_validate({**INV.model_dump(), "created_at": NOW.astimezone(odd)})
    assert inv.created_at == NOW
    assert inv.created_at.utcoffset() == _dt.timedelta(0)
    assert inv.model_dump(mode="json")["created_at"] == "2026-09-28T12:00:00Z"


@pytest.mark.parametrize(("method", "path", "body"), [
    ("GET", f"{T}/alerts/%E2%9C%93", None),
    ("GET", f"{T}/investigations/a%20b", None),
    ("GET", f"{T}/learning-jobs/-leading-dash", None),
    ("PUT", f"{T}/systems/%E2%9C%93", {"kind": "k", "display_name": "d", "enabled": True, "settings": {}}),
    ("PUT", f"{T}/systems/a%20b/credentials", {"credentials": {"k": "v"}}),
    ("POST", f"{T}/systems/a%20b/check", None),
    ("POST", f"{T}/investigations/a%20b/cancel", None),
    ("DELETE", f"{T}/investigations/a%20b", None),
    ("GET", f"{T}/investigations/a%20b/artifacts/report.md", None),
    ("GET", f"{T}/learning-jobs?investigation_id=a%20b", None),
    ("POST", f"{T}/investigations", {"alert_id": "✓", "client_request_id": "r"}),
    ("POST", f"{T}/learning-jobs", {"investigation_id": "a b", "client_request_id": "r"}),
    ("GET", f"{T}/investigations?alert_id=%E2%9C%93", None),
])
def test_an_id_outside_the_grammar_is_refused_at_the_boundary(
    method: str, path: str, body: dict[str, str] | None
) -> None:
    api = Api()
    assert api.client.request(method, path, headers=AUTH, json=body).status_code == 422
    assert api.ports.calls == []
    assert api.ports.transactions == []


@pytest.mark.parametrize("limit", [0, MAX_PAGE + 1])
@pytest.mark.parametrize("path", [f"{T}/alerts", f"{T}/investigations", f"{T}/learning-jobs"])
def test_a_page_size_out_of_range_is_refused(path: str, limit: int) -> None:
    api = Api()
    assert api.client.get(path, headers=AUTH, params={"limit": limit}).status_code == 422
    assert api.ports.calls == []


def test_a_blank_client_request_id_is_refused() -> None:
    api = Api()
    assert api.client.post(f"{T}/investigations", headers=AUTH,
                           json={"alert_id": "al-1", "client_request_id": ""}).status_code == 422
    assert api.ports.calls == []


def test_a_disposition_outside_the_vocabulary_cannot_be_served() -> None:
    with pytest.raises(ValueError, match="not a disposition"):
        Investigation(investigation_id="i", alert_id="a", status="completed", disposition="fine",
                      cost_usd=0.0, created_at=NOW)


@pytest.mark.parametrize("bad", ["a/b", "a b", "a?b#c", "é", ""])
def test_an_id_outside_the_grammar_cannot_be_served(bad: str) -> None:
    with pytest.raises(ValueError, match="pattern"):
        INV.model_validate({**INV.model_dump(), "investigation_id": bad})
    with pytest.raises(ValueError, match="pattern"):
        SETTINGS.model_validate({**SETTINGS.model_dump(), "system_id": bad})


@pytest.mark.parametrize("legacy", ["Not_A_Tenant", "acme", "playground", "tenant-a", "blue"])
def test_a_principal_carries_a_checked_tenant(legacy) -> None:
    """Conflict updated (was: a caller from the login provider...): `Principal` is unchanged by #1306 (r7), still grammar-checked."""
    with pytest.raises(TenantRefused):
        Principal(tenant_id=legacy, user_id=USER)


def test_a_naive_time_cannot_be_served() -> None:
    with pytest.raises(ValueError, match="timezone"):
        Investigation(investigation_id="i", alert_id="a", status="queued", cost_usd=0.0,
                      created_at=NOW.replace(tzinfo=None))


# --- pagination ----------------------------------------------------------------------------

LATER = NOW + _dt.timedelta(hours=1)
INV_2 = INV.model_copy(update={"investigation_id": "inv-2", "created_at": LATER})
JOB_2 = JOB.model_copy(update={"learning_job_id": "lj-2", "created_at": LATER})
SUMMARY_2 = SUMMARY.model_copy(update={"alert_id": "al-2", "fired_at": LATER})
LESSON_2 = LESSON.model_copy(update={"lesson_id": "le-2"})
SETTINGS_2 = SETTINGS.model_copy(update={"system_id": "tiy"})

#: (path, port, the store's first two rows in the list's order, the position the second page
#: must start after — the first row's, as the port's order names it).
LISTS = [
    (f"{T}/alerts", "list_alerts", [SUMMARY_2, SUMMARY], (LATER, "al-2")),
    (f"{T}/investigations", "list_investigations", [INV_2, INV], (LATER, "inv-2")),
    (f"{T}/learning-jobs", "list_learning_jobs", [JOB_2, JOB], (LATER, "lj-2")),
    (f"{T}/lessons", "list_lessons", [LESSON, LESSON_2], "le-1"),
    (f"{T}/systems", "list_systems", [SETTINGS, SETTINGS_2], "tix"),
]


def _rows_after(rows: list[Any]) -> Callable[..., list[Any]]:
    """The store as a function of `after`: both rows from the start, the second after the first."""
    return lambda tenant, *, after, limit, **_filters: (rows if after is None else rows[1:])[:limit]


@pytest.mark.parametrize(("path", "port", "rows", "first_after"), LISTS, ids=[x[0] for x in LISTS])
def test_every_list_pages_by_cursor_from_the_last_row_served(
    path: str, port: str, rows: list[Any], first_after: Any,
) -> None:
    api = Api(**{port: _rows_after(rows), "has_credentials": False})
    first = api.client.get(path, headers=AUTH, params={"limit": 1}).json()
    assert len(first["items"]) == 1
    assert first["next_cursor"]
    second = api.client.get(path, headers=AUTH,
                            params={"limit": 1, "cursor": first["next_cursor"]}).json()
    assert len(second["items"]) == 1
    assert second["items"] != first["items"]
    assert second["next_cursor"] is None
    (_, first_kwargs), (_, second_kwargs) = api.ports.called(port)
    assert (first_kwargs["after"], first_kwargs["limit"]) == (None, 2)
    assert (second_kwargs["after"], second_kwargs["limit"]) == (first_after, 2)


def test_a_cursor_stays_short_whatever_the_filters_and_is_accepted_back() -> None:
    severity = "x" * 1600
    api = Api(list_alerts=_rows_after([SUMMARY_2, SUMMARY]))
    cursor = _cursor(api, f"{T}/alerts", {"severity": severity})
    assert len(cursor) < 400
    page = api.client.get(f"{T}/alerts", headers=AUTH,
                          params={"limit": 1, "severity": severity, "cursor": cursor})
    assert page.status_code == 200, page.text
    assert [a["alert_id"] for a in page.json()["items"]] == ["al-1"]


def _edited(cursor: str, **changes: Any) -> str:
    """`cursor` with fields of its JSON changed, re-encoded as the API encodes one."""
    body = json.loads(base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)))
    return base64.urlsafe_b64encode(json.dumps({**body, **changes}).encode()).decode().rstrip("=")


@pytest.mark.parametrize("bad_id", ["a b/é", "' OR 1=1 --", "", "\u0000", "x" * 1363])
@pytest.mark.parametrize(("path", "port", "rows"), [x[:3] for x in LISTS], ids=[x[0] for x in LISTS])
def test_an_edited_cursor_cannot_hand_a_port_an_id_outside_the_grammar(
    path: str, port: str, rows: list[Any], bad_id: str,
) -> None:
    api = Api(**{port: _rows_after(rows), "has_credentials": False})
    cursor = _edited(_cursor(api, path), id=bad_id)
    calls = len(api.ports.calls)
    response = api.client.get(path, headers=AUTH, params={"limit": 1, "cursor": cursor})
    assert response.status_code == 422
    assert len(api.ports.calls) == calls, "the edited cursor reached a port"


@pytest.mark.parametrize(("path", "port", "rows", "at"), [
    (f"{T}/investigations", "list_investigations", [INV_2, INV], None),
    (f"{T}/lessons", "list_lessons", [LESSON, LESSON_2], NOW.isoformat()),
])
def test_a_cursor_of_the_wrong_shape_for_its_list_is_refused(
    path: str, port: str, rows: list[Any], at: str | None,
) -> None:
    api = Api(**{port: _rows_after(rows)})
    cursor = _edited(_cursor(api, path), at=at)
    calls = len(api.ports.calls)
    response = api.client.get(path, headers=AUTH, params={"limit": 1, "cursor": cursor})
    assert response.status_code == 422
    assert "not a position in this list" in response.text
    assert len(api.ports.calls) == calls


@pytest.mark.parametrize("answer", [
    lambda tenant, *, after, limit, **_: [INV_2, INV][:limit],      # ignores `after`
    lambda tenant, *, after, limit, **_: [INV, INV_2][:limit],      # out of order
    lambda tenant, *, after, limit, **_: [INV_2, INV, INV, INV],    # more than asked
], ids=["repeats", "unordered", "oversized"])
def test_a_page_that_does_not_advance_is_a_500_not_an_endless_walk(answer: Any) -> None:
    client = Api(list_investigations=answer).lenient()
    params: dict[str, Any] = {"limit": 1}
    statuses = []
    for _ in range(3):
        response = client.get(f"{T}/investigations", headers=AUTH, params=params)
        statuses.append(response.status_code)
        if response.status_code != 200:
            break
        params = {"limit": 1, "cursor": response.json()["next_cursor"]}
    assert statuses[-1] == 500, statuses


def test_one_filter_instant_written_with_another_offset_keeps_its_cursor() -> None:
    api = Api(list_alerts=_rows_after([SUMMARY_2, SUMMARY]))
    cursor = _cursor(api, f"{T}/alerts", {"fired_after": "2026-09-20T08:00:00+02:00"})
    page = api.client.get(f"{T}/alerts", headers=AUTH, params={
        "limit": 1, "fired_after": "2026-09-20T06:00:00Z", "cursor": cursor})
    assert page.status_code == 200, page.text


def test_a_store_answering_full_system_records_is_still_served_from_its_settings() -> None:
    stored = System(**SETTINGS.model_dump(), has_credentials=False)
    api = Api(list_systems=[stored], get_system=stored, has_credentials=True,
              check=lambda tenant, system: SystemCheck(ok=True, detail=str(system.has_credentials)))
    assert api.client.get(f"{T}/systems", headers=AUTH).json()["items"][0]["has_credentials"] is True
    assert api.client.post(f"{T}/systems/tix/check", headers=AUTH).json()["detail"] == "True"


def test_systems_are_served_only_for_the_rows_on_the_page() -> None:
    api = Api(list_systems=[SETTINGS, SETTINGS_2], has_credentials=False)
    page = api.client.get(f"{T}/systems", headers=AUTH, params={"limit": 1}).json()
    assert [s["system_id"] for s in page["items"]] == ["tix"]
    assert api.ports.called("has_credentials") == [((A, "tix"), {})]


def test_a_short_page_is_the_last_page() -> None:
    api = Api(list_investigations=[INV_2, INV])
    page = api.client.get(f"{T}/investigations", headers=AUTH, params={"limit": 2}).json()
    assert (len(page["items"]), page["next_cursor"]) == (2, None)


def _cursor(api: Api, path: str, params: dict[str, str] | None = None) -> str:
    page = api.client.get(path, headers=AUTH, params={"limit": 1, **(params or {})}).json()
    cursor: str = page["next_cursor"]
    assert cursor
    return cursor


@pytest.mark.parametrize("cursor", [
    "!!not-base64!!",
    "bm90IGpzb24",                               # base64 of "not json"
    "eyJ2IjogMn0",                               # base64 of {"v": 2}
    "e30",                                       # base64 of {}
])
def test_a_cursor_this_api_did_not_issue_is_refused_before_the_store(cursor: str) -> None:
    api = Api()
    response = api.client.get(f"{T}/investigations", headers=AUTH, params={"cursor": cursor})
    assert response.status_code == 422
    assert api.ports.calls == []


def test_a_cursor_is_bound_to_its_list_its_tenant_and_its_filters() -> None:
    issuer = Api(list_investigations=[INV_2, INV], list_lessons=[LESSON, LESSON_2])
    by_alert = _cursor(issuer, f"{T}/investigations", {"alert_id": "al-1"})
    lessons = _cursor(issuer, f"{T}/lessons")

    api = Api()
    refusals = [
        api.client.get(f"{T}/investigations", headers=AUTH, params={"cursor": by_alert, "alert_id": "al-2"}),
        api.client.get(f"{T}/investigations", headers=AUTH, params={"cursor": by_alert}),
        api.client.get(f"{T}/systems", headers=AUTH, params={"cursor": lessons}),
        api.client.get(f"{TB}/lessons", headers=AUTH_B, params={"cursor": lessons}),
    ]
    assert [r.status_code for r in refusals] == [422, 422, 422, 422]
    assert api.ports.calls == []


@pytest.mark.parametrize(("path", "port", "rows", "_after"), LISTS, ids=[p.rsplit("/", 1)[1] for p, *_ in LISTS])
def test_a_cursor_from_one_tenant_is_refused_in_another_by_the_same_person(
        path: str, port: str, rows: list[Any], _after: Any) -> None:
    """P-D, O3: a cursor is bound to the path's tenant, not to the caller; a member of both tenants cannot carry it across."""
    api = Api(**{port: _rows_after(rows), "has_credentials": False})
    page = api.client.get(path, headers=AUTH_AB, params={"limit": 1}).json()
    cursor = page["next_cursor"]
    assert cursor
    assert api.client.get(path, headers=AUTH_AB, params={"limit": 1, "cursor": cursor}).status_code == 200  # control
    calls = len(api.ports.calls)
    other = path.replace(T, TB, 1)
    assert api.client.get(other, headers=AUTH_AB, params={"cursor": cursor}).status_code == 422
    assert len(api.ports.calls) == calls


def test_paging_the_demo_store_serves_every_row_once_across_tied_timestamps() -> None:
    store = InMemoryStore(lambda: NOW)
    fired = [NOW, NOW, NOW, LATER, NOW - _dt.timedelta(hours=1)]
    for n, at in enumerate(fired):
        store.add_alert(A, ALERT.model_copy(update={"alert_id": f"al-{n}", "fired_at": at}))
    client = TestClient(create_app(ApiDeps(
        identity=_identity()[0], frontend_origin=ORIGIN,
        alerts=store, investigations=store, learning_jobs=store, lessons=store, systems=store,
        writes=store, secrets=InMemorySecrets(), checker=StubSystemChecker(),
        artifact_links=StubArtifactLinks(),
    )), base_url=BASE)
    seen: list[str] = []
    params: dict[str, Any] = {"limit": 2}
    while True:
        page = client.get(f"{T}/alerts", headers=AUTH, params=params).json()
        seen += [a["alert_id"] for a in page["items"]]
        if page["next_cursor"] is None:
            break
        params = {"limit": 2, "cursor": page["next_cursor"]}
    assert seen == ["al-3", "al-2", "al-1", "al-0", "al-4"]


# --- the demo server -----------------------------------------------------------------------


def _session(value: str, origin: str) -> dict[str, str]:
    return {"Cookie": f"{SESSION_COOKIE}={value}", "Origin": origin}


def test_the_demo_seed_serves_each_named_tenant_only_its_own_records() -> None:
    """Conflict updated, O7: the demo's seeded sessions (was: bearer tokens) reach only their own tenant."""
    tenants = (DEMO_ONE, DEMO_TWO)
    deps = demo_deps(tenants, lambda: NOW)
    client = TestClient(create_app(deps), base_url=BASE)
    sessions = demo_sessions(tenants)
    seen: dict[str, set[str]] = {}
    for tenant in tenants:
        for role in DEMO_ROLES:
            auth = _session(sessions[f"{tenant}-{role}"], deps.frontend_origin)
            alerts = client.get(f"/tenants/{tenant}/alerts", headers=auth).json()["items"]
            assert alerts, (tenant, role)
            for alert in alerts:
                assert client.get(f"/tenants/{tenant}/alerts/{alert['alert_id']}",
                                  headers=auth).status_code == 200
            other = DEMO_TWO if tenant == DEMO_ONE else DEMO_ONE
            assert client.get(f"/tenants/{other}/alerts", headers=auth).status_code == 404
            body = client.get("/me", headers=auth).json()
            assert [t["tenant_id"] for t in body["tenants"]] == [tenant]
            # O5/K10: a member is never an administrator; the demo seeds members only.
            assert body["administrator"] is False
            assert client.get("/admin/tenants", headers=auth).status_code == 403
            seen.setdefault(tenant, set()).update(a["alert_id"] for a in alerts)
    assert set(seen) == set(tenants)
    assert not seen[DEMO_ONE] & seen[DEMO_TWO]
    auth = _session(sessions[f"{DEMO_ONE}-analyst"], deps.frontend_origin)
    systems = client.get(f"/tenants/{DEMO_ONE}/systems", headers=auth).json()["items"]
    assert {s["system_id"]: s["has_credentials"] for s in systems} == {"siem": False, "tickets": True}


def test_a_demo_session_outlasts_the_production_idle_limit() -> None:
    """The printed demo sessions keep working through a night unused; only their own lifetime ends them."""
    clock = {"now": NOW}
    deps = demo_deps((DEMO_ONE,), lambda: clock["now"])
    client = TestClient(create_app(deps), base_url=BASE)
    auth = _session(demo_sessions((DEMO_ONE,))[f"{DEMO_ONE}-analyst"], deps.frontend_origin)
    clock["now"] = NOW + _dt.timedelta(days=3)
    assert client.get("/me", headers=auth).status_code == 200
    clock["now"] = NOW + _dt.timedelta(days=366)
    assert client.get("/me", headers=auth).status_code == 401


def test_the_demo_sign_in_port_refuses_with_a_503_problem() -> None:
    """DC-4: the demo has no Keycloak; `/auth/login` answers a 503 problem, never a redirect."""
    client = TestClient(create_app(demo_deps((DEMO_ONE,), lambda: NOW)), base_url=BASE)
    response = client.get("/auth/login", follow_redirects=False)
    assert response.status_code == 503
    assert response.headers["Content-Type"] == "application/problem+json"
    assert "Location" not in response.headers


def test_the_demo_store_keeps_the_audit_events_a_transaction_commits() -> None:
    """Conflict updated, O7: the actor is the demo session's user id (read from `/me`)."""
    deps = demo_deps((DEMO_ONE,), lambda: NOW)
    client = TestClient(create_app(deps), base_url=BASE)
    auth = _session(demo_sessions((DEMO_ONE,))[f"{DEMO_ONE}-analyst"], deps.frontend_origin)
    user_id = client.get("/me", headers=auth).json()["user"]["id"]
    created = client.post(f"/tenants/{DEMO_ONE}/investigations", headers=auth,
                          json={"alert_id": f"{DEMO_ONE}-alert-0003", "client_request_id": "r1"})
    assert created.status_code == 201, created.text
    events = deps.writes.audit_events  # type: ignore[attr-defined]
    assert [(e.tenant_id, e.user_id, e.action, e.target) for e in events] == [
        (DEMO_ONE, user_id, "investigation.start", created.json()["investigation_id"])]


def test_the_demo_store_keys_records_by_tenant() -> None:
    store = InMemoryStore(lambda: NOW)
    store.add_alert(DEMO_ONE, ALERT)
    store.add_alert(DEMO_TWO, ALERT.model_copy(update={"title": "two's"}))
    one, two = store.get_alert(DEMO_ONE, "al-1"), store.get_alert(DEMO_TWO, "al-1")
    assert one is not None
    assert two is not None
    assert (one.title, two.title) == ("t", "two's")


@pytest.mark.parametrize(("tenants", "reason"), [
    ((), "at least one tenant"),
    ((DEMO_ONE, DEMO_ONE), "tenants repeat"),
    (("Not_A_Tenant",), "not a tenant id"),
])
def test_the_demo_seed_refuses_a_bad_tenant_list(tenants: tuple[str, ...], reason: str) -> None:
    with pytest.raises(ValueError, match=reason):
        demo_deps(tenants)
