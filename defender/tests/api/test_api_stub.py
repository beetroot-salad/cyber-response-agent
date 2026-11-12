"""The platform API HTTP layer over a scripted fake: routes, login seam, port-answer to response mapping."""
from __future__ import annotations

from defender.tests.support.shared._fixture_uuid import fixture_uuid

import base64
import datetime as _dt
import inspect
import json
from http import HTTPStatus
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import anyio
import pytest

pytest.importorskip("fastapi")

from fastapi.routing import APIRoute  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from defender.api import fakes as fakes_module, ports as ports_module  # noqa: E402
from defender.api.app import MAX_PAGE, create_app  # noqa: E402
from defender.api.demo import DEMO_ROLES, demo_deps, demo_id, demo_sessions  # noqa: E402
from defender.api.fakes import (  # noqa: E402
    InMemoryOffboarding,
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
from defender.jobs import errors as store_errors  # noqa: E402
from defender.identity import (  # noqa: E402
    Bootstrap,
    IdentityService,
    InMemoryIdentityRepository,
)
from defender.tenancy import InMemoryTenantRepository  # noqa: E402
from defender.records._tenant_id import TenantId  # noqa: E402
from pydantic import ValidationError  # noqa: E402
from defender.records.formats import AlertId  # noqa: E402
from defender.tests.support.tenancy._mapping1345 import ALERT_MAPPING_ROUTE, alert_mapping_url  # noqa: E402
from defender.tests.support.api._programs1307 import NoProgramsRealm  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[3]
NOW = _dt.datetime(2026, 9, 28, 12, 0, tzinfo=_dt.UTC)

A = fixture_uuid("tenant:tenant-a")
DEMO_ONE = fixture_uuid("tenant:t-one")
DEMO_TWO = fixture_uuid("tenant:t-two")
B = fixture_uuid("tenant:tenant-b")
USER = fixture_uuid("user:ann")
#: The tenant is the path's `T`; the caller is a session seeded through the identity repository,
#: sent as the `__Host-defender_session` cookie plus the configured `Origin`.
T = f"/tenants/{A}"
TB = f"/tenants/{B}"
SESSION_COOKIE = "__Host-defender_session"
SESSION_A = "session-value-of-ann"
SESSION_B = "session-value-of-bob"
#: Cy is a member of both A and B: one session for two tenants.
SESSION_AB = "session-value-of-cy"
ORIGIN = "https://app.defender.test"
AUTH = {"Cookie": f"{SESSION_COOKIE}={SESSION_A}", "Origin": ORIGIN}
AUTH_B = {"Cookie": f"{SESSION_COOKIE}={SESSION_B}", "Origin": ORIGIN}
AUTH_AB = {"Cookie": f"{SESSION_COOKIE}={SESSION_AB}", "Origin": ORIGIN}
BASE = "https://testserver"

ALERT = Alert(
    alert_id="a1000000-0000-4000-8000-000000000001", vendor="tickets", vendor_ticket_id="T-1", title="t", description="d",
    fired_at=NOW, changed_at=NOW, received_at=NOW, raw='{"id": "a1000000-0000-4000-8000-000000000001"}',
)
SUMMARY = AlertSummary.model_validate(ALERT.model_dump(exclude={"raw"}))
INV = Investigation(
    investigation_id="b1000000-0000-4000-8000-000000000001", alert_id="a1000000-0000-4000-8000-000000000001", status="completed", disposition="benign",
    request_key="req-1", attempt=1,
    cost_usd=1.5, cost_is_lower_limit=False, created_at=NOW, artifacts=["report.md", "gather_raw/L1/0.json"],
    # The knowledge revision the run used (`current` = the run record's `fresh`).
    knowledge={"status": "current", "commit": "f4e5c0de0000f4e5c0de0000f4e5c0de0000f4e5",
               "stale_kind": None},
)
JOB = LearningJob(
    learning_job_id="c1000000-0000-4000-8000-000000000001", investigation_id="b1000000-0000-4000-8000-000000000001", alert_id="a1000000-0000-4000-8000-000000000001", status="queued",
    trigger="explicit", created_at=NOW,
)
LESSON = Lesson(lesson_id="le-1", title="t", description="d", status="live")
SETTINGS = SystemSettings(system_id="tix", kind="ticketing", display_name="T", enabled=True,
                          settings={"queue": "sec"})
SIGNED = "https://blobs.invalid/signed?sig=1"
#: A credential value long enough for any kind's secret-field minimum (#1163 A4).
LONG = "v" * 40

#: #1345: the six entries (D4: a PUT names all of them, an unmapped one as an explicit null; a GET answers the same shape).
MAPPING_ENTRIES = ("signature", "event_time", "summary", "case_key", "title", "description")
#: A PUT body that maps two of the six; the other four are explicit nulls.
MAPPING_BODY = {**dict.fromkeys(MAPPING_ENTRIES), "signature": "rule.id", "title": "rule.description"}


def _alert_mapping_wire(entries: dict[str, str | None]) -> Any:
    """The wire model a mapping read answers (design-implied name `api.models.AlertMapping`: r5 says only "the wire
    model"; one model for the PUT body and the answer). Imported at call time: it does not exist before #1345."""
    from defender.api.models import AlertMapping

    return AlertMapping(**entries)


class _Answer:
    """A scripted port answer computed per call, with a stable repr: `HAPPY`'s ids are `str()` of
    its rows, and a lambda's repr carries its address, which differs between xdist workers."""

    def __init__(self, name: str, answer: Callable[..., Any]) -> None:
        self._name, self._answer = name, answer

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        return self._answer(*args, **kwargs)

    def __repr__(self) -> str:
        return f"<{self._name}>"


#: #1131's "API" section as (method, path), under `/tenants/{tenant_id}`.
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
    # #1345 O1: the tenant's alert mapping, read and replaced whole (sketch: invented path)
    ("GET", ALERT_MAPPING_ROUTE),
    ("PUT", ALERT_MAPPING_ROUTE),
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
    ("POST", "/admin/tenants"),
    ("GET", "/admin/tenants/{tenant_id}"),
    ("POST", "/admin/tenants/{tenant_id}/resume"),
    ("POST", "/admin/tenants/{tenant_id}/offboard"),
    ("POST", "/admin/tenants/{tenant_id}/rotate-forge-credential"),
}
#: What #1307 adds (design "Program and credential routes"; param names pinned by this suite). Conflict updated: r3.
PROGRAM_ROUTES = {
    ("POST", "/tenants/{tenant_id}/programs"),
    ("GET", "/tenants/{tenant_id}/programs"),
    ("DELETE", "/tenants/{tenant_id}/programs/{program_id}"),
    ("POST", "/tenants/{tenant_id}/programs/{program_id}/credentials"),
    ("GET", "/tenants/{tenant_id}/programs/{program_id}/credentials"),
    ("DELETE", "/tenants/{tenant_id}/programs/{program_id}/credentials/{credential_id}"),
}
IDENTITY_ROUTES = IDENTITY_ROUTES | PROGRAM_ROUTES  # same refusal contract as the members/invitations routes
PUBLIC_ROUTES = EXISTING_ROUTES | IDENTITY_ROUTES

#: One successful call per route: (route, concrete path, body, the port answers it needs).
HAPPY: list[tuple[tuple[str, str], str, dict[str, Any] | None, dict[str, Any]]] = [
    (("GET", "/tenants/{tenant_id}/alerts"), f"{T}/alerts", None, {"list_alerts": [SUMMARY]}),
    (("GET", "/tenants/{tenant_id}/alerts/{alert_id}"), f"{T}/alerts/a1000000-0000-4000-8000-000000000001", None, {"get_alert": ALERT}),
    (("POST", "/tenants/{tenant_id}/investigations"), f"{T}/investigations",
     {"alert_id": "a1000000-0000-4000-8000-000000000001", "client_request_id": "r1"}, {"create_investigation": (INV, True)}),
    (("GET", "/tenants/{tenant_id}/investigations"), f"{T}/investigations", None, {"list_investigations": [INV]}),
    (("GET", "/tenants/{tenant_id}/investigations/{investigation_id}"), f"{T}/investigations/b1000000-0000-4000-8000-000000000001", None,
     {"get_investigation": INV}),
    (("POST", "/tenants/{tenant_id}/investigations/{investigation_id}/cancel"), f"{T}/investigations/b1000000-0000-4000-8000-000000000001/cancel", None,
     {"cancel_investigation": INV}),
    (("DELETE", "/tenants/{tenant_id}/investigations/{investigation_id}"), f"{T}/investigations/b1000000-0000-4000-8000-000000000001", None,
     {"delete_investigation": None}),
    (("GET", "/tenants/{tenant_id}/investigations/{investigation_id}/artifacts/{key}"),
     f"{T}/investigations/b1000000-0000-4000-8000-000000000001/artifacts/report.md", None,
     {"get_investigation": INV, "signed_url": SIGNED}),
    (("POST", "/tenants/{tenant_id}/learning-jobs"), f"{T}/learning-jobs",
     {"investigation_id": "b1000000-0000-4000-8000-000000000001", "client_request_id": "r1"}, {"create_learning_job": (JOB, True)}),
    (("GET", "/tenants/{tenant_id}/learning-jobs"), f"{T}/learning-jobs", None, {"list_learning_jobs": [JOB]}),
    (("GET", "/tenants/{tenant_id}/learning-jobs/{learning_job_id}"), f"{T}/learning-jobs/c1000000-0000-4000-8000-000000000001", None,
     {"get_learning_job": JOB}),
    (("GET", "/tenants/{tenant_id}/lessons"), f"{T}/lessons", None, {"list_lessons": [LESSON]}),
    (("GET", "/tenants/{tenant_id}/systems"), f"{T}/systems", None,
     {"list_systems": [SETTINGS], "has_credentials": False}),
    (("PUT", "/tenants/{tenant_id}/systems/{system_id}"), f"{T}/systems/tix",
     {"kind": "ticketing", "display_name": "T", "enabled": True, "settings": {}},
     {"put_system": (SETTINGS, True), "has_credentials": False}),
    (("PUT", "/tenants/{tenant_id}/systems/{system_id}/credentials"), f"{T}/systems/tix/credentials",
     {"kind": "static", "credentials": {"api_token": LONG}},
     {"get_system": SETTINGS, "has_credentials": False, "put_credentials": None}),
    (("POST", "/tenants/{tenant_id}/systems/{system_id}/check"), f"{T}/systems/tix/check", None,
     {"get_system": SETTINGS, "has_credentials": True,
      "check": SystemCheck(ok=True, detail="fine")}),
    (("GET", ALERT_MAPPING_ROUTE), alert_mapping_url(A), None,
     {"get_alert_mapping": _Answer("saved mapping", lambda _tenant: _alert_mapping_wire(MAPPING_BODY))}),
    (("PUT", ALERT_MAPPING_ROUTE), alert_mapping_url(A), MAPPING_BODY,
     {"put_alert_mapping": _Answer("created from the body", lambda body: (body, True))}),
]


#: The writes a route makes through a transaction; they carry no tenant — the transaction does.
TX_WRITES = {"create_investigation", "cancel_investigation", "delete_investigation",
             "create_learning_job", "put_system", "put_alert_mapping"}


class Scripted:
    """Every port the routes call: `answers` maps a method name to its return value, an exception
    to raise, or a callable that answers the call; an unscripted call fails the test."""

    def __init__(self, answers: dict[str, Any]) -> None:
        self.answers = answers
        self.calls: list[tuple[str, tuple[Any, ...], dict[str, Any]]] = []
        self.transactions: list[tuple[str, str]] = []
        self.audits: list[tuple[str, str, str, str, str]] = []

    def transaction(self, tenant_id: str, principal: Any) -> _ScriptedTransaction:
        # Conflict updated (#1307 D6): the transaction takes the principal in place of the bare actor id.
        return _ScriptedTransaction(self, tenant_id, principal.actor_id)

    def __getattr__(self, name: str) -> Callable[..., Any]:
        if name.startswith("_"):
            raise AttributeError(name)

        async def call(*args: Any, **kwargs: Any) -> Any:
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

    async def __aenter__(self) -> _ScriptedTransaction:
        self.ports.transactions.append((self.tenant_id, self.actor))
        return self

    async def __aexit__(self, exc_type: type[BaseException] | None, *_: object) -> None:
        if exc_type is None:
            self.ports.audits.extend(self.pending)

    def __getattr__(self, name: str) -> Callable[..., Any]:
        if name.startswith("_"):
            raise AttributeError(name)
        return getattr(self.ports, name)

    async def audit(self, action: str, target: str, detail: str = "") -> None:
        failure = self.ports.answers.get("audit")
        if isinstance(failure, BaseException):
            raise failure
        self.pending.append((self.tenant_id, self.actor, action, target, detail))


class _Unused:
    """A sign-in or mail port these route tests never exercise: any call is a failure."""

    def __getattr__(self, name: str) -> Callable[..., Any]:
        raise AssertionError(f"a route test reached the unused port: {name}")


async def _seed_identity() -> tuple[IdentityService, dict[str, str], InMemoryTenantRepository]:
    """Ann is a member of A, Bob of B and Cy of both, each with a seeded session. Returns the
    service, the seeded user ids by session value and the tenant twin the service shares."""
    tenants = InMemoryTenantRepository()
    await tenants.add_tenant(TenantId(A), created_at=NOW)
    await tenants.add_tenant(TenantId(B), created_at=NOW)
    repo = InMemoryIdentityRepository(tenants=tenants)
    users: dict[str, str] = {}
    for email, tenant, session in (("ann@a.example", A, SESSION_A), ("bob@b.example", B, SESSION_B)):
        user = await repo.add_user(email, created_at=NOW, status="active", display_name=email)
        await repo.add_membership(user.id, TenantId(tenant), status="active", invited_by=None,
                            created_at=NOW, accepted_at=NOW)
        await repo.add_session(session, user.id, now=NOW, expires_at=NOW + _dt.timedelta(days=7))
        users[session] = user.id
    cy = await repo.add_user("cy@c.example", created_at=NOW, status="active", display_name="cy")
    for tenant in (A, B):
        await repo.add_membership(cy.id, TenantId(tenant), status="active", invited_by=None,
                            created_at=NOW, accepted_at=NOW)
    await repo.add_session(SESSION_AB, cy.id, now=NOW, expires_at=NOW + _dt.timedelta(days=7))
    users[SESSION_AB] = cy.id
    # Conflict updated (#1307 D7): the programs port is required; these routes never reach the realm.
    service = IdentityService(repo, signin=_Unused(), mail=_Unused(), clock=lambda: NOW,
                              bootstrap=Bootstrap(administrators=()), programs=NoProgramsRealm())
    return service, users, tenants


def _identity() -> tuple[IdentityService, dict[str, str], InMemoryTenantRepository]:
    """The seeded identity service, built in a throwaway loop: the in-memory repository holds no
    loop state, so the app's own loop can use it afterwards."""
    return anyio.run(_seed_identity)


def _deps(ports: Any) -> tuple[ApiDeps, dict[str, str]]:
    identity, users, tenants = _identity()
    return ApiDeps(
        identity=identity, tenants=tenants, frontend_origin=ORIGIN,
        alerts=ports, investigations=ports, learning_jobs=ports, lessons=ports,
        systems=ports, writes=ports, secrets=ports, checker=ports, artifact_links=ports, offboarding=ports,
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
    """#1131's routes live under `/tenants/{tenant_id}`, #1306 adds its own, and no Bearer scheme is published."""
    doc = Api().client.get("/openapi.json").json()
    documented = {(method.upper(), path) for path, ops in doc["paths"].items() for method in ops}
    assert documented == PUBLIC_ROUTES
    schemes = doc.get("components", {}).get("securitySchemes", {})
    assert "HTTPBearer" not in schemes
    assert not [s for s in schemes.values() if str(s.get("scheme", "")).lower() == "bearer"]


def test_the_happy_path_table_covers_every_existing_route() -> None:
    assert {route for route, *_ in HAPPY} == EXISTING_ROUTES


def test_the_api_never_loads_the_runtime_or_the_learning_loop() -> None:
    """The API modules, with `defender.identity`, load no runtime or learning-loop module."""
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


def test_1366_h3_the_api_loads_no_record_store_so_no_route_writes_system_records() -> None:
    """Guard: the API, demo wiring and server load nothing of the record writer, so no route writes records. (#1366 H3/R1)"""
    probe = (
        "import json, sys; import defender.api.app, defender.api.demo, defender.api.serve; "
        "print(json.dumps(sorted(m for m in sys.modules if m.startswith('defender.system_records'))))"
    )
    out = subprocess.run(
        [sys.executable, "-c", probe], cwd=REPO_ROOT, capture_output=True, text=True,
        encoding="utf-8", check=True,
    )
    assert json.loads(out.stdout) == []


def test_the_identity_package_loads_no_api_runtime_or_learning_module() -> None:
    """`defender.identity` imports nothing from `api`, nor anything the API must never load
    (the learning loop and what was `defender.runtime` before #1308 placed it by layer)."""
    probe = "import json, sys; import defender.identity; print(json.dumps(sorted(sys.modules)))"
    out = subprocess.run(
        [sys.executable, "-c", probe], cwd=REPO_ROOT, capture_output=True, text=True,
        encoding="utf-8", check=True,
    )
    loaded = json.loads(out.stdout)
    assert [m for m in loaded if m.startswith("defender.api")] + api_forbidden(loaded) == []


def test_the_tenancy_package_loads_no_identity_module() -> None:
    """`identity` sits right after `tenancy`, so importing `defender.tenancy` pulls nothing from it."""
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
    """The tenant is the path's T, the actor is the session's user id."""
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
    """Ann, a member of A only, asking under B's path is a 404 before any port."""
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
    """No, unknown, or Bearer-carried session → 401, no port; no Bearer challenge unless the request came with an
    `Authorization` header (#1307: then it is the programs' way in, challenged as RFC 6750 says)."""
    api = Api(**answers)
    response = api.client.request(route[0], path, headers=headers, json=body)
    assert response.status_code == 401
    if "Authorization" not in headers:
        assert "WWW-Authenticate" not in response.headers
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
    """A valid cookie with a missing or foreign Origin is 403 before any port; the same call with Origin is served."""
    api = Api(**answers)
    headers = {"Cookie": f"{SESSION_COOKIE}={SESSION_A}"} | ({} if origin is None else {"Origin": origin})
    response = api.client.request(route[0], path, headers=headers, json=body, follow_redirects=False)
    assert response.status_code == 403, response.text
    assert api.ports.calls == []
    assert api.ports.transactions == []
    # control: the same session with the configured Origin is served
    assert api.client.request(route[0], path, headers=AUTH, json=body,
                              follow_redirects=False).status_code < 400


@pytest.mark.parametrize(("claim", "code"), [("Acme_Corp", 422), ("org_2NxAbCdEf", 422), ("", 404)])
def test_a_path_tenant_that_fails_the_grammar_is_refused_not_a_500(claim: str, code: int) -> None:
    """A malformed T in the path is a 422 (#1382); an empty one matches no route (404)."""
    api = Api()
    response = api.lenient().get(f"/tenants/{claim}/alerts", headers=AUTH)
    assert response.status_code == code
    assert api.ports.calls == []


@pytest.mark.parametrize(("path", "body"), [
    (f"{T}/investigations", {"alert_id": "a1000000-0000-4000-8000-000000000001", "client_request_id": "r", "tenant_id": A}),
    (f"{T}/learning-jobs", {"investigation_id": "b1000000-0000-4000-8000-000000000001", "client_request_id": "r", "tenant_id": A}),
])
def test_a_body_cannot_name_a_tenant(path: str, body: dict[str, str]) -> None:
    """The tenant comes only from the prefixed path, never from a body."""
    api = Api()
    assert api.client.post(path, headers=AUTH, json=body).status_code == 422
    assert api.ports.calls == []


@pytest.mark.parametrize("bad", ["r\x00", "r\ud800"], ids=["NUL", "lone surrogate"])
@pytest.mark.parametrize(("path", "body"), [
    (f"{T}/investigations", {"alert_id": "a1000000-0000-4000-8000-000000000001"}),
    (f"{T}/learning-jobs", {"investigation_id": "b1000000-0000-4000-8000-000000000001"}),
])
def test_1379_a_client_request_id_postgresql_cannot_hold_is_a_422_naming_it(
    path: str, body: dict[str, str], bad: str,
) -> None:
    """Refused at the API's model, naming the field, reaching no store. (#1379 O1a)"""
    api = Api()
    # `json.dumps` escapes the surrogate as `\\ud800`, as a client's JSON would carry it.
    response = api.client.post(path, headers={**AUTH, "content-type": "application/json"},
                               content=json.dumps({**body, "client_request_id": bad}))
    assert response.status_code == 422, response.text
    assert [e["loc"] for e in response.json()["errors"]] == [["body", "client_request_id"]]
    assert api.ports.calls == []


# --- creates: 201 or replay ----------------------------------------------------------------


@pytest.mark.parametrize(("path", "body", "port", "record", "location", "audit"), [
    (f"{T}/investigations", {"alert_id": "a1000000-0000-4000-8000-000000000001", "client_request_id": "r1"}, "create_investigation",
     INV, f"{T}/investigations/b1000000-0000-4000-8000-000000000001", ("investigation.start", "b1000000-0000-4000-8000-000000000001", "alert a1000000-0000-4000-8000-000000000001")),
    (f"{T}/learning-jobs", {"investigation_id": "b1000000-0000-4000-8000-000000000001", "client_request_id": "r1"},
     "create_learning_job", JOB, f"{T}/learning-jobs/c1000000-0000-4000-8000-000000000001", ("learning_job.start", "c1000000-0000-4000-8000-000000000001", "investigation b1000000-0000-4000-8000-000000000001")),
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
    (f"{T}/investigations", {"alert_id": "a1000000-0000-4000-8000-0000000000ff", "client_request_id": "r1"}, "create_investigation", INV),
    (f"{T}/learning-jobs", {"investigation_id": "b1000000-0000-4000-8000-0000000000ff", "client_request_id": "r1"},
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
                                  json={"alert_id": "a1000000-0000-4000-8000-000000000001", "client_request_id": "r1"})
    assert response.status_code == 500
    assert api.audited() == []


def test_put_system_is_a_201_at_its_own_url_when_created_and_200_when_replaced() -> None:
    body = {"kind": "ticketing", "display_name": "T", "enabled": False, "settings": {"q": "s"}}
    created = Api(put_system=(SETTINGS, True), has_credentials=False)
    response = created.client.put(f"{T}/systems/tix", headers=AUTH, json=body)  # R7-2: a stray `x=1` here is now refused, see below
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


# --- #1345 O1: the alert mapping's routes (shape over the scripted ports; the rules are the store's) -------


def test_1345_put_alert_mapping_is_201_at_its_own_url_then_200_and_each_is_audited_after_commit() -> None:
    """The first save creates (201, Location), a later one replaces (200); the port gets the body as sent; the
    answer has all six entries, unmapped ones null; one `alert_mapping.update` event each. (#1345 O1)"""
    created = Api(put_alert_mapping=lambda body: (body, True))
    response = created.client.put(alert_mapping_url(A), headers=AUTH, json=MAPPING_BODY)
    assert (response.status_code, response.headers["Location"]) == (201, BASE + alert_mapping_url(A))
    assert response.json() == {entry: MAPPING_BODY.get(entry) for entry in MAPPING_ENTRIES}
    ((sent,), kwargs), = created.ports.called("put_alert_mapping")
    assert (sent.model_dump(), kwargs) == (MAPPING_BODY, {})  # r5: the port gets the validated wire model's `model_dump()`

    replaced = Api(put_alert_mapping=lambda body: (body, False))
    response = replaced.client.put(alert_mapping_url(A), headers=AUTH, json=MAPPING_BODY)
    assert response.status_code == 200
    assert "Location" not in response.headers
    # r5 O1: the action `alert_mapping.update`, target the tenant id.
    assert created.audited() == replaced.audited() == [("alert_mapping.update", A, "")]


def test_1345_the_audit_vocabulary_has_the_mapping_update() -> None:
    """`alert_mapping.update` is a new audit action. (#1345 O1)"""
    import typing

    assert "alert_mapping.update" in typing.get_args(ports_module.AuditAction)


def test_1345_get_alert_mapping_answers_all_six_entries_or_404_when_none_was_saved() -> None:
    """A saved mapping reads with every entry, unmapped ones null; a tenant with none is a not-found problem. (#1345 O1)"""
    saved = Api(get_alert_mapping=lambda _tenant: _alert_mapping_wire(MAPPING_BODY))
    response = saved.client.get(alert_mapping_url(A), headers=AUTH)
    assert response.status_code == 200
    assert response.json() == {entry: MAPPING_BODY.get(entry) for entry in MAPPING_ENTRIES}

    none = Api(get_alert_mapping=None)
    response = none.client.get(alert_mapping_url(A), headers=AUTH)
    assert response.status_code == 404
    assert response.headers["Content-Type"] == "application/problem+json"


@pytest.mark.parametrize(("body", "entry"), [
    ({**MAPPING_BODY, "case_key": " rule.id"}, "case_key"),  # surrounding whitespace
    ({**MAPPING_BODY, "summary": "rule..id"}, "summary"),  # an empty segment
    ({**MAPPING_BODY, "severity": "rule.level"}, "severity"),  # not one of the six
    ({k: v for k, v in MAPPING_BODY.items() if k != "event_time"}, "event_time"),  # D4: all six must be named
], ids=["invalid-path", "empty-segment", "unknown-entry", "missing-entry"])
def test_1345_an_invalid_or_incomplete_mapping_is_a_422_naming_the_entry_before_any_port_call(body: dict[str, str], entry: str) -> None:
    """The wire model refuses it (r5: validated through `records`' `check_mapping`; D4: all six named): 422 naming the
    entry, no port call, no audit. (#1345 O1, M2)"""
    api = Api()
    response = api.client.put(alert_mapping_url(A), headers=AUTH, json=body)
    assert response.status_code == 422, response.text
    assert entry in response.text
    assert (api.ports.calls, api.ports.audits) == ([], [])


def _over_the_fake() -> tuple[TestClient, InMemoryStore]:
    """The real app over the stub's own `InMemoryStore` (rule-free: it keeps what the wire model let through)."""
    store = InMemoryStore(lambda: NOW)
    identity, _, tenants = _identity()
    return TestClient(create_app(ApiDeps(
        identity=identity, tenants=tenants, frontend_origin=ORIGIN,
        alerts=store, investigations=store, learning_jobs=store, lessons=store, systems=store,
        writes=store, secrets=InMemorySecrets(), checker=StubSystemChecker(),
        artifact_links=StubArtifactLinks(), offboarding=InMemoryOffboarding(tenants, store, lambda: NOW),
    )), base_url=BASE), store


def test_1345_over_the_fake_a_mapping_is_404_then_201_then_200_and_reads_back_as_put() -> None:
    """GET is 404 until the first PUT (201, Location); a later PUT replaces whole (200); GET answers exactly the six
    entries the PUT named; each save is audited `alert_mapping.update` for the tenant. (#1345 O1)"""
    client, store = _over_the_fake()
    assert client.get(alert_mapping_url(A), headers=AUTH).status_code == 404

    first = client.put(alert_mapping_url(A), headers=AUTH, json=MAPPING_BODY)
    assert (first.status_code, first.headers["Location"]) == (201, BASE + alert_mapping_url(A))
    assert client.get(alert_mapping_url(A), headers=AUTH).json() == MAPPING_BODY

    other = {**dict.fromkeys(MAPPING_ENTRIES), "case_key": "ticket.key"}
    second = client.put(alert_mapping_url(A), headers=AUTH, json=other)
    assert (second.status_code, "Location" in second.headers) == (200, False)
    assert client.get(alert_mapping_url(A), headers=AUTH).json() == other, "a replace is whole: the earlier entries are gone"
    assert [(e.action, e.tenant_id, e.target) for e in store.audit_events] == [("alert_mapping.update", A, A)] * 2


@pytest.mark.parametrize(("body", "entry"), [
    ({**MAPPING_BODY, "case_key": " rule.id"}, "case_key"),
    ({**MAPPING_BODY, "summary": "rule..id"}, "summary"),
    ({**MAPPING_BODY, "summary": ""}, "summary"),
    ({**MAPPING_BODY, "summary": 7}, "summary"),
    ({**MAPPING_BODY, "severity": "rule.level"}, "severity"),
    ({k: v for k, v in MAPPING_BODY.items() if k != "description"}, "description"),
    ({}, "signature"),
], ids=["whitespace", "empty-segment", "empty-path", "not-a-string", "unknown-entry", "missing-entry", "empty-body"])
def test_1345_over_the_fake_an_invalid_or_incomplete_mapping_is_refused_alike_and_writes_nothing(
        body: dict[str, Any], entry: str) -> None:
    """The fake refuses exactly as the scripted ports do (the wire model applies the rules before any port): 422 naming
    the entry, no audit, the saved mapping untouched; a valid PUT right after is 201 (control). (#1345 O1, M2)"""
    client, store = _over_the_fake()
    scripted = Api()
    refused = client.put(alert_mapping_url(A), headers=AUTH, json=body)
    assert refused.status_code == 422, refused.text
    assert entry in refused.text, refused.text
    assert (scripted.client.put(alert_mapping_url(A), headers=AUTH, json=body).json()
            == refused.json()), "the fake and the scripted ports must give one 422"
    assert client.get(alert_mapping_url(A), headers=AUTH).status_code == 404
    assert store.audit_events == []

    assert client.put(alert_mapping_url(A), headers=AUTH, json=MAPPING_BODY).status_code == 201
    saved = {**MAPPING_BODY, "title": "data.title"}
    assert client.put(alert_mapping_url(A), headers=AUTH, json=saved).status_code == 200
    assert client.put(alert_mapping_url(A), headers=AUTH, json={**saved, "title": "a..b"}).status_code == 422
    assert client.get(alert_mapping_url(A), headers=AUTH).json() == saved, "a refused replace left the saved mapping"


def test_1345_an_alert_with_no_title_or_description_is_served_with_nulls() -> None:
    """The wire alert's title and description are nullable (a tenant with no mapping lists such alerts); a titled one
    is served as it is (control). (#1345 O2)"""
    untitled = SUMMARY.model_copy(update={"title": None, "description": None, "alert_id": "a1000000-0000-4000-8000-000000000002"})
    api = Api(list_alerts=[untitled, SUMMARY])
    items = api.client.get(f"{T}/alerts", headers=AUTH).json()["items"]
    assert [(i["title"], i["description"]) for i in items] == [(None, None), ("t", "d")]


def test_1345_the_wire_alert_validates_with_null_title_and_description() -> None:
    """Constructing (so validating; `model_copy` above skips validation) an `AlertSummary` with null title and description
    is accepted and keeps them null; the fields stay required (r5.1: required, may be null). (#1345 O2, r5.1)"""
    fields = SUMMARY.model_dump()
    built = AlertSummary(**{**fields, "title": None, "description": None})
    assert (built.title, built.description) == (None, None)
    for field in ("title", "description"):
        with pytest.raises(ValidationError):
            AlertSummary(**{k: v for k, v in fields.items() if k != field})


def test_1345_the_mapping_body_names_exactly_the_records_entries_all_required() -> None:
    """The wire model's fields are `records`' `MAPPING_KEYS`, none defaulted (a PUT replaces whole, D4). (#1345 O1)"""
    from defender.api.models import AlertMapping
    from defender.records._alert_input import MAPPING_KEYS

    assert list(AlertMapping.model_fields) == list(MAPPING_KEYS) == list(MAPPING_ENTRIES)
    assert [name for name, field in AlertMapping.model_fields.items() if not field.is_required()] == []


@pytest.mark.parametrize(("method", "path", "port", "answer", "action"), [
    ("POST", f"{T}/investigations/b1000000-0000-4000-8000-000000000001/cancel", "cancel_investigation", INV, "investigation.cancel"),
    ("DELETE", f"{T}/investigations/b1000000-0000-4000-8000-000000000001", "delete_investigation", None, "investigation.delete"),
])
def test_a_write_is_audited_in_its_own_transaction(
    method: str, path: str, port: str, answer: Any, action: str,
) -> None:
    api = Api(**{port: answer})
    assert api.client.request(method, path, headers=AUTH).status_code < 400
    assert api.ports.called(port) == [(("b1000000-0000-4000-8000-000000000001",), {})]
    assert api.ports.transactions == [(A, api.user)]
    assert api.audited() == [(action, "b1000000-0000-4000-8000-000000000001", "")]


# --- refusals ------------------------------------------------------------------------------


@pytest.mark.parametrize(("path", "port"), [
    (f"{T}/alerts/a1000000-0000-4000-8000-000000000001", "get_alert"),
    (f"{T}/investigations/b1000000-0000-4000-8000-000000000001", "get_investigation"),
    (f"{T}/investigations/b1000000-0000-4000-8000-000000000001/artifacts/report.md", "get_investigation"),
    (f"{T}/learning-jobs/c1000000-0000-4000-8000-000000000001", "get_learning_job"),
])
def test_a_read_the_store_answers_none_is_a_404(path: str, port: str) -> None:
    api = Api(**{port: None})
    assert api.client.get(path, headers=AUTH, follow_redirects=False).status_code == 404
    assert api.ports.audits == []


@pytest.mark.parametrize(("method", "path", "body", "port", "error", "code"), [
    ("POST", f"{T}/investigations/b1000000-0000-4000-8000-000000000001/cancel", None, "cancel_investigation", NotFound("x"), 404),
    ("POST", f"{T}/investigations/b1000000-0000-4000-8000-000000000001/cancel", None, "cancel_investigation", Conflict("x"), 409),
    ("DELETE", f"{T}/investigations/b1000000-0000-4000-8000-000000000001", None, "delete_investigation", NotFound("x"), 404),
    ("DELETE", f"{T}/investigations/b1000000-0000-4000-8000-000000000001", None, "delete_investigation", Conflict("x"), 409),
    ("POST", f"{T}/investigations", {"alert_id": "a1000000-0000-4000-8000-000000000001", "client_request_id": "r"},
     "create_investigation", UnknownReference("x"), 422),
    ("POST", f"{T}/learning-jobs", {"investigation_id": "b1000000-0000-4000-8000-000000000001", "client_request_id": "r"},
     "create_learning_job", UnknownReference("x"), 422),
    ("POST", f"{T}/learning-jobs", {"investigation_id": "b1000000-0000-4000-8000-000000000001", "client_request_id": "r"},
     "create_learning_job", Conflict("x"), 409),
    # the job store's own refusals, as the store raises them (#1342): nothing maps them to the API's
    ("POST", f"{T}/investigations/b1000000-0000-4000-8000-000000000001/cancel", None, "cancel_investigation", store_errors.NotFound("x"), 404),
    ("POST", f"{T}/investigations/b1000000-0000-4000-8000-000000000001/cancel", None, "cancel_investigation", store_errors.Conflict("x"), 409),
    ("DELETE", f"{T}/investigations/b1000000-0000-4000-8000-000000000001", None, "delete_investigation", store_errors.NotFound("x"), 404),
    ("DELETE", f"{T}/investigations/b1000000-0000-4000-8000-000000000001", None, "delete_investigation", store_errors.Conflict("x"), 409),
    ("POST", f"{T}/investigations", {"alert_id": "a1000000-0000-4000-8000-000000000001", "client_request_id": "r"},
     "create_investigation", store_errors.UnknownReference("x"), 422),
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
    response = api.client.get(f"{T}/investigations/b1000000-0000-4000-8000-000000000001/artifacts/{key}", headers=AUTH,
                              follow_redirects=False)
    assert response.status_code == 307
    assert response.headers["Location"] == SIGNED
    assert response.headers["Cache-Control"] == "no-store"
    assert api.ports.called("signed_url") == [((A, "b1000000-0000-4000-8000-000000000001", key), {})]
    assert api.audited() == [("artifact.read", "b1000000-0000-4000-8000-000000000001", key)]


def test_an_artifact_read_whose_link_fails_is_not_audited() -> None:
    api = Api(get_investigation=INV, signed_url=RuntimeError("signer down"))
    response = api.lenient().get(f"{T}/investigations/b1000000-0000-4000-8000-000000000001/artifacts/report.md", headers=AUTH,
                                 follow_redirects=False)
    assert response.status_code == 500
    assert api.ports.transactions == []
    assert api.ports.audits == []


def test_an_artifact_link_is_not_handed_out_unless_its_read_is_audited() -> None:
    api = Api(get_investigation=INV, signed_url=SIGNED, audit=RuntimeError("audit down"))
    response = api.lenient().get(f"{T}/investigations/b1000000-0000-4000-8000-000000000001/artifacts/report.md", headers=AUTH,
                                 follow_redirects=False)
    assert response.status_code == 500
    assert SIGNED not in response.text
    assert "Location" not in response.headers


@pytest.mark.parametrize("key", ["runtime.html", "%2E%2E/other/report.md", "report.md/x",
                                 "other/report.md"])
def test_only_keys_the_investigation_lists_are_answered(key: str) -> None:
    api = Api(get_investigation=INV)
    response = api.client.get(f"{T}/investigations/b1000000-0000-4000-8000-000000000001/artifacts/{key}", headers=AUTH,
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
    secret = "s3cr3t-value-never-echoed-" + LONG  # conflict updated: #1163 A4 (kind, minimum length)
    api = Api(get_system=SETTINGS, has_credentials=False, put_credentials=None)
    response = api.client.put(f"{T}/systems/tix/credentials", headers=AUTH,
                              json={"kind": "static", "credentials": {"api_token": secret}})
    assert (response.status_code, response.content) == (204, b"")
    assert api.ports.called("put_credentials") == [((A, "tix", "static", {"api_token": secret}), {})]
    assert api.ports.called("has_credentials") == [], "an existence check, not a read"
    assert api.audited() == [("system.credentials", "tix", "fields: api_token")]
    assert secret not in repr(api.ports.audits)


def test_credentials_are_not_written_when_their_audit_write_fails() -> None:
    api = Api(get_system=SETTINGS, put_credentials=None, audit=RuntimeError("audit down"))
    response = api.lenient().put(f"{T}/systems/tix/credentials", headers=AUTH,
                                 json={"kind": "static", "credentials": {"api_token": LONG}})
    assert response.status_code == 500
    assert api.ports.called("put_credentials") == []


def test_a_failed_credentials_write_commits_no_audit() -> None:
    api = Api(get_system=SETTINGS, put_credentials=RuntimeError("vault down"))
    response = api.lenient().put(f"{T}/systems/tix/credentials", headers=AUTH,
                                 json={"kind": "static", "credentials": {"api_token": LONG}})
    assert response.status_code == 500
    assert api.ports.audits == []


#: Each as it is spelled inside a JSON string, so the body is valid JSON that decodes to it.
@pytest.mark.parametrize("key", [r"a\u0000b", r"\ud800", "", "has space", "x" * 65, "9lead"])
def test_a_credential_field_name_outside_the_grammar_is_refused(key: str) -> None:
    """A field name reaches the audit detail, so one the audit store would refuse never gets in."""
    api = Api()
    response = api.client.put(f"{T}/systems/tix/credentials", headers={**AUTH, "Content-Type": "application/json"},
                              content=('{"kind": "static", "credentials": {"' + key + '": "' + LONG + '"}}').encode())
    assert response.status_code == 422
    assert api.ports.calls == []


def test_credentials_for_an_unknown_system_are_refused_before_the_secret_store() -> None:
    api = Api(get_system=None)
    response = api.client.put(f"{T}/systems/nope/credentials", headers=AUTH, json={"kind": "static", "credentials": {"k": LONG}})
    assert response.status_code == 404
    assert api.ports.called("put_credentials") == []
    assert Api().client.put(f"{T}/systems/tix/credentials", headers=AUTH,
                            json={"kind": "static", "credentials": {}}).status_code == 422


#: (kind, credentials, accepted): secret fields per kind, #1163 r7 A19. Static: every field
#: except `username`; oauth: every field except `client_id`.
CREDENTIAL_SHAPES = [
    ("static", {"api_key": LONG}, True),
    ("static", {"api_key": "x"}, False),
    ("static", {"username": "u", "password": LONG}, True),
    ("static", {"username": "u", "password": "x"}, False),
    ("static", {"username": "u", "api_key": LONG, "other": "x"}, False),
    ("static", {"api_key": LONG, "client_id": "c"}, False),
    ("static", {"api_key": LONG, "key_id": "k"}, False),
    ("static", {"api_key": LONG, "user": "u"}, False),
    ("static", {"api_key": LONG, "account": "a"}, False),
    ("static", {"api_key": LONG, "client_id": LONG}, True),
    ("oauth-client-credentials", {"client_id": "c", "client_secret": LONG}, True),
    ("oauth-client-credentials", {"client_id": "c", "client_secret": "x"}, False),
    ("oauth-client-credentials", {"client_id": "c", "client_secret": LONG, "audience": "x"}, False),
    ("oauth-client-credentials", {"client_id": "c", "client_secret": LONG, "audience": LONG}, True),
]


@pytest.mark.parametrize(("kind", "credentials", "accepted"), CREDENTIAL_SHAPES)
def test_a_secret_field_below_the_minimum_length_is_refused_at_write_time(
        kind: str, credentials: dict[str, str], accepted: bool) -> None:
    """A set is written whole with its kind; a too-short secret field of that kind is a 422 and
    reaches no store, a short non-secret field passes. #1163 O5, A4."""
    api = Api(get_system=SETTINGS, put_credentials=None)
    response = api.client.put(f"{T}/systems/tix/credentials", headers=AUTH,
                              json={"kind": kind, "credentials": credentials})
    assert response.status_code == (204 if accepted else 422), response.text
    assert api.ports.called("put_credentials") == (
        [((A, "tix", kind, credentials), {})] if accepted else [])


@pytest.mark.parametrize("kind", [None, "", "oauth", "other"])
def test_a_credential_write_without_a_known_kind_is_refused(kind: str | None) -> None:
    """The write API takes the kind; none, or one that is not static or
    oauth-client-credentials, is a 422 reaching no store. #1163 A4."""
    api = Api(get_system=SETTINGS, put_credentials=None)
    body = {"credentials": {"api_key": LONG}} | ({} if kind is None else {"kind": kind})
    assert api.client.put(f"{T}/systems/tix/credentials", headers=AUTH,
                          json=body).status_code == 422
    assert api.ports.called("put_credentials") == []


@pytest.mark.parametrize("method", ["GET", "POST", "DELETE", "PATCH"])
def test_no_route_reads_a_credential_back(method: str) -> None:
    """Only PUT exists on a system's credentials path; every other method is refused
    unrouted. #1163 O5."""
    api = Api(get_system=SETTINGS, has_credentials=True)
    response = api.client.request(method, f"{T}/systems/tix/credentials", headers=AUTH)
    assert response.status_code == 405
    assert api.ports.called("put_credentials") == []


# --- errors: one shape, RFC 9457 ----------------------------------------------------------

PROBLEM_KEYS = {"type", "title", "status", "detail"}


@pytest.mark.parametrize(("method", "path", "body", "headers", "answers", "code"), [
    ("GET", f"{T}/alerts", None, {"Origin": ORIGIN}, {}, 401),
    ("GET", f"{TB}/alerts", None, AUTH, {}, 404),
    ("GET", f"{T}/alerts/a1000000-0000-4000-8000-000000000001", None, AUTH, {"get_alert": None}, 404),
    ("GET", "/nowhere", None, AUTH, {}, 404),
    ("POST", f"{T}/alerts", None, AUTH, {}, 405),
    ("POST", f"{T}/investigations/b1000000-0000-4000-8000-000000000001/cancel", None, AUTH, {"cancel_investigation": Conflict("ended")}, 409),
    ("POST", f"{T}/investigations", {"alert_id": "a1000000-0000-4000-8000-000000000001", "client_request_id": "r"}, AUTH,
     {"create_investigation": UnknownReference("no alert")}, 422),
    ("GET", f"{T}/alerts?cursor=zz", None, AUTH, {}, 422),
    ("GET", f"{T}/alerts?limit=0", None, AUTH, {}, 422),
    ("GET", f"{T}/alerts", None, AUTH, {"list_alerts": RuntimeError("db exploded at host-7")}, 500),
])
def test_every_error_is_an_rfc_9457_problem(
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
        assert "WWW-Authenticate" not in response.headers, "a session-cookie 401 carries no challenge"
    if code == 500:
        assert problem["detail"] == "internal error", "a 500 says nothing about its cause"


def test_a_validation_problem_lists_what_failed_and_never_echoes_the_value() -> None:
    secret = 87654321987654321
    api = Api()
    response = api.client.put(f"{T}/systems/tix/credentials", headers=AUTH,
                              json={"kind": "static", "credentials": {"api_token": secret}})
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
    # Every tenant route answers 404 to a non-member, so every one declares it.
    assert all(404 in errors for (_, path), errors in declared.items()
               if path.startswith("/tenants/{tenant_id}"))
    # Every identity route but the two redirecting ones declares its 401 as a problem.
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
        "fired_after": after.isoformat(), "limit": 7,  # R7-2: the retired `severity` filter is no longer ignored, see below
    })
    assert response.json() == {"items": [SUMMARY.model_dump(mode="json")], "next_cursor": None}
    ((tenant,), kwargs), = api.ports.called("list_alerts")
    assert tenant == A
    assert kwargs == {"fired_after": after, "fired_before": None,
                      "after": None, "limit": 8}
    assert kwargs["fired_after"].utcoffset() == _dt.timedelta(0)


_UNKNOWN_QUERY_ROUTES = [
    ("GET", f"{T}/alerts?severity=high"),
    ("GET", f"{T}/alerts?limit=5&nonsense=1"),
    ("GET", f"{T}/alerts/a1000000-0000-4000-8000-000000000001?extra=1"),
    ("GET", f"{T}/investigations?bogus=x"),
    ("POST", f"{T}/investigations?bogus=x"),
    ("GET", f"{T}/learning-jobs?bogus=x"),
    ("GET", f"{T}/lessons?bogus=x"),
    ("GET", f"{T}/systems?bogus=x"),
    ("GET", f"{T}/members?bogus=x"),
]


@pytest.mark.parametrize(("method", "path"), _UNKNOWN_QUERY_ROUTES)
def test_r7_2_a_query_parameter_the_route_does_not_declare_is_a_422_problem_before_the_handler_runs(
        method: str, path: str) -> None:
    """An undeclared query parameter is a 422 problem with one `extra_forbidden` entry at `["query", name]`; no port is called. (R7-2)"""
    api = Api()
    name = path.split("?", 1)[1].split("&")[-1].split("=")[0]
    response = api.lenient().request(method, path, headers=AUTH, json={"alert_id": "a1000000-0000-4000-8000-000000000001", "client_request_id": "r"}
                                  if method == "POST" else None)
    assert response.status_code == 422, response.text
    assert response.headers["Content-Type"] == "application/problem+json"
    errors = response.json()["errors"]
    assert [(e["type"], e["loc"]) for e in errors if e["loc"] == ["query", name]] == [
        ("extra_forbidden", ["query", name])]
    assert api.ports.calls == [], "the handler ran for a request with an unknown query parameter"


def test_r7_2_a_put_with_an_undeclared_query_parameter_is_refused_and_changes_nothing() -> None:
    """`PUT /systems/tix?x=1` (once let through, its Location built without the query) is a 422 `extra_forbidden` at `["query", "x"]`; no system is written. (R7-2)"""
    api = Api(put_system=(SETTINGS, True), has_credentials=False)
    body = {"kind": "ticketing", "display_name": "T", "enabled": False, "settings": {"q": "s"}}
    response = api.client.put(f"{T}/systems/tix", headers=AUTH, params={"x": "1"}, json=body)
    assert response.status_code == 422
    assert [(e["type"], e["loc"]) for e in response.json()["errors"]] == [("extra_forbidden", ["query", "x"])]
    assert api.ports.called("put_system") == []


def test_r7_2_every_unknown_query_parameter_gets_its_own_entry() -> None:
    """Two undeclared parameters give two `extra_forbidden` entries, one per name. (R7-2)"""
    api = Api()
    response = api.lenient().get(f"{T}/alerts?one=1&two=2&limit=5", headers=AUTH)
    assert response.status_code == 422
    entries = sorted((e["type"], tuple(e["loc"])) for e in response.json()["errors"])
    assert entries == [("extra_forbidden", ("query", "one")), ("extra_forbidden", ("query", "two"))]


@pytest.mark.parametrize(("path", "answers"), [
    (f"{T}/alerts?limit=5&fired_after=2026-09-28T08:00:00Z", {"list_alerts": [SUMMARY]}),
    (f"{T}/investigations?alert_id=a1000000-0000-4000-8000-000000000001&limit=5", {"list_investigations": [INV]}),
    (f"{T}/learning-jobs?investigation_id=b1000000-0000-4000-8000-000000000001&limit=5", {"list_learning_jobs": []}),
    (f"{T}/lessons?limit=5", {"list_lessons": [LESSON]}),
])
def test_r7_2_control_declared_query_parameters_are_served_as_before(path: str, answers: dict[str, Any]) -> None:
    """Control: the declared parameters of the same routes answer 200. (R7-2)"""
    api = Api(**answers)
    assert api.client.get(path, headers=AUTH).status_code == 200


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
                           json={"alert_id": "a1000000-0000-4000-8000-000000000001", "client_request_id": ""}).status_code == 422
    assert api.ports.calls == []


def test_a_disposition_outside_the_vocabulary_cannot_be_served() -> None:
    with pytest.raises(ValueError, match="not a disposition"):
        Investigation(investigation_id="i", alert_id="a", status="completed", disposition="fine",
                      request_key="k", attempt=1, cost_usd=0.0, cost_is_lower_limit=False, created_at=NOW)


@pytest.mark.parametrize("bad", ["a/b", "a b", "a?b#c", "é", ""])
def test_an_id_outside_the_grammar_cannot_be_served(bad: str) -> None:
    with pytest.raises(ValueError, match="pattern"):
        INV.model_validate({**INV.model_dump(), "investigation_id": bad})
    with pytest.raises(ValueError, match="pattern"):
        SETTINGS.model_validate({**SETTINGS.model_dump(), "system_id": bad})


@pytest.mark.parametrize("legacy", ["Not_A_Tenant", "acme", "playground", "tenant-a", "blue"])
def test_a_principal_carries_a_checked_tenant(legacy) -> None:
    """`Principal`'s tenant is grammar-checked (#1382: as pydantic's own pattern error)."""
    with pytest.raises(ValidationError):
        Principal(tenant_id=legacy, actor_id=USER)


def test_a_naive_time_cannot_be_served() -> None:
    with pytest.raises(ValueError, match="timezone"):
        Investigation(investigation_id="i", alert_id="a", status="queued", cost_usd=0.0, cost_is_lower_limit=False,
                      request_key="k", attempt=1, created_at=NOW.replace(tzinfo=None))


# --- pagination ----------------------------------------------------------------------------

LATER = NOW + _dt.timedelta(hours=1)
INV_2 = INV.model_copy(update={"investigation_id": "b1000000-0000-4000-8000-000000000002", "created_at": LATER})
JOB_2 = JOB.model_copy(update={"learning_job_id": "c1000000-0000-4000-8000-000000000002", "created_at": LATER})
SUMMARY_2 = SUMMARY.model_copy(update={"alert_id": "a1000000-0000-4000-8000-000000000002", "fired_at": LATER})
LESSON_2 = LESSON.model_copy(update={"lesson_id": "le-2"})
SETTINGS_2 = SETTINGS.model_copy(update={"system_id": "tiy"})

#: (path, port, the store's first two rows in the list's order, the position the second page
#: must start after — the first row's, as the port's order names it).
LISTS = [
    (f"{T}/alerts", "list_alerts", [SUMMARY_2, SUMMARY], (LATER, "a1000000-0000-4000-8000-000000000002")),
    (f"{T}/investigations", "list_investigations", [INV_2, INV], (LATER, "b1000000-0000-4000-8000-000000000002")),
    (f"{T}/learning-jobs", "list_learning_jobs", [JOB_2, JOB], (LATER, "c1000000-0000-4000-8000-000000000002")),
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
    # #1342: alerts keep only moment filters, so the longest admitted filter is the investigations list's alert id
    # (#1382: a UUID, so every one is as long).
    alert_id = "a1000000-0000-4000-8000-000000000001"
    api = Api(list_investigations=_rows_after([INV_2, INV]))
    cursor = _cursor(api, f"{T}/investigations", {"alert_id": alert_id})
    assert len(cursor) < 400
    short = _cursor(Api(list_investigations=_rows_after([INV_2, INV])), f"{T}/investigations", {"alert_id": "a1000000-0000-4000-8000-000000000002"})
    assert len(cursor) == len(short), "the cursor grows with the filter: it carries it, not a digest"
    page = api.client.get(f"{T}/investigations", headers=AUTH,
                          params={"limit": 1, "alert_id": alert_id, "cursor": cursor})
    assert page.status_code == 200, page.text
    assert [i["investigation_id"] for i in page.json()["items"]] == ["b1000000-0000-4000-8000-000000000001"]


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
    by_alert = _cursor(issuer, f"{T}/investigations", {"alert_id": "a1000000-0000-4000-8000-000000000001"})
    lessons = _cursor(issuer, f"{T}/lessons")

    api = Api()
    refusals = [
        api.client.get(f"{T}/investigations", headers=AUTH, params={"cursor": by_alert, "alert_id": "a1000000-0000-4000-8000-000000000002"}),
        api.client.get(f"{T}/investigations", headers=AUTH, params={"cursor": by_alert}),
        api.client.get(f"{T}/systems", headers=AUTH, params={"cursor": lessons}),
        api.client.get(f"{TB}/lessons", headers=AUTH_B, params={"cursor": lessons}),
    ]
    assert [r.status_code for r in refusals] == [422, 422, 422, 422]
    assert api.ports.calls == []


@pytest.mark.parametrize(("path", "port", "rows", "_after"), LISTS, ids=[p.rsplit("/", 1)[1] for p, *_ in LISTS])
def test_a_cursor_from_one_tenant_is_refused_in_another_by_the_same_person(
        path: str, port: str, rows: list[Any], _after: Any) -> None:
    """A cursor is bound to the path's tenant, not to the caller: a member of both tenants cannot carry it across."""
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
        store.add_alert(A, ALERT.model_copy(update={"alert_id": f"a1000000-0000-4000-8000-{n:012d}", "fired_at": at}))
    identity, _, tenants = _identity()
    client = TestClient(create_app(ApiDeps(
        identity=identity, tenants=tenants, frontend_origin=ORIGIN,
        alerts=store, investigations=store, learning_jobs=store, lessons=store, systems=store,
        writes=store, secrets=InMemorySecrets(), checker=StubSystemChecker(),
        artifact_links=StubArtifactLinks(), offboarding=InMemoryOffboarding(tenants, store, lambda: NOW),
    )), base_url=BASE)
    seen: list[str] = []
    params: dict[str, Any] = {"limit": 2}
    while True:
        page = client.get(f"{T}/alerts", headers=AUTH, params=params).json()
        seen += [a["alert_id"] for a in page["items"]]
        if page["next_cursor"] is None:
            break
        params = {"limit": 2, "cursor": page["next_cursor"]}
    assert seen == ["a1000000-0000-4000-8000-000000000003", "a1000000-0000-4000-8000-000000000002", "a1000000-0000-4000-8000-000000000001", "a1000000-0000-4000-8000-000000000000", "a1000000-0000-4000-8000-000000000004"]



@pytest.mark.parametrize("status", ["queued", "running"])
def test_the_demo_store_refuses_to_delete_a_live_investigation_as_the_port_promises(status: str) -> None:
    """`delete_investigation` is a `Conflict` while the investigation is live (the port's
    contract, which the job store keeps); an ended one is deleted. (finalize #1354)"""
    store = InMemoryStore(lambda: NOW)
    store.add_alert(A, ALERT)

    async def scenario() -> tuple[bool, bool]:
        inv, _ = await store.create_investigation(A, ALERT.alert_id, "k1")
        store.add_investigation(A, inv.model_copy(update={"status": status}))
        with pytest.raises(Conflict):
            await store.delete_investigation(A, inv.investigation_id)
        kept = await store.get_investigation(A, inv.investigation_id) is not None
        store.add_investigation(A, inv.model_copy(update={"status": "completed"}))
        await store.delete_investigation(A, inv.investigation_id)
        return kept, await store.get_investigation(A, inv.investigation_id) is None

    assert anyio.run(scenario) == (True, True)

def _api_routes(routes: Any) -> Any:
    """Every route under `routes` as it is served: an included router (FastAPI includes them lazily)
    yields its effective routes, which carry include-level `dependencies=` as well."""
    for route in routes:
        if isinstance(route, APIRoute):
            yield route
        elif hasattr(route, "effective_candidates"):
            yield from _api_routes(route.effective_candidates())
        elif hasattr(route, "dependant"):
            yield route


def _walk_dependants(dependant: Any) -> Any:
    for sub in dependant.dependencies:
        yield sub.call
        yield from _walk_dependants(sub)


def test_every_route_and_every_dependency_is_a_coroutine_function() -> None:
    """D11: a sync endpoint or dependency runs in a worker thread with no event loop; none may."""
    app = create_app(_deps(Scripted({}))[0])
    routes = list(_api_routes(app.routes))
    calls = [r.endpoint for r in routes] + [c for r in routes for c in _walk_dependants(r.dependant)]
    assert len(routes) > 20
    assert any(r.path.endswith("/alerts") and r.methods == {"GET"} for r in routes)
    assert any(c.__name__ == "_administrator" for c in calls)
    assert [f"{c.__module__}.{c.__qualname__}" for c in calls if not inspect.iscoroutinefunction(c)] == []


def test_every_fake_port_method_is_a_coroutine_function_and_a_transaction_an_async_context() -> None:
    """D11/B: each fake implementing a `defender.api.ports` Protocol answers by `await`."""
    protocols = [p for p in vars(ports_module).values()
                 if isinstance(p, type) and getattr(p, "_is_protocol", False) and p.__module__ == ports_module.__name__]
    fakes = [f for f in vars(fakes_module).values() if isinstance(f, type) and f.__module__ == fakes_module.__name__]
    implemented = []
    for protocol in protocols:
        names = [n for n in vars(protocol) if not n.startswith("_") and callable(vars(protocol)[n])]
        for fake in fakes:
            if names and all(hasattr(fake, n) for n in names):
                implemented.append((fake.__name__, protocol.__name__))
                sync = [n for n in names if n != "transaction" and not inspect.iscoroutinefunction(getattr(fake, n))]
                assert sync == [], (fake.__name__, protocol.__name__)
    assert len(protocols) >= 9
    assert len(implemented) >= 9
    assert ("InMemoryStore", "AlertsRepository") in implemented
    assert ("_InMemoryTransaction", "WriteTransaction") in implemented
    transaction = InMemoryStore(lambda: NOW).transaction(A, Principal(tenant_id=A, actor_id=USER))  # the principal, not the bare id (#1307 D6)
    assert hasattr(transaction, "__aenter__")
    assert hasattr(transaction, "__aexit__")


# --- the demo server -----------------------------------------------------------------------


def _session(value: str, origin: str) -> dict[str, str]:
    return {"Cookie": f"{SESSION_COOKIE}={value}", "Origin": origin}


def test_the_demo_seed_serves_each_named_tenant_only_its_own_records() -> None:
    """The demo's seeded sessions reach only their own tenant."""
    tenants = (DEMO_ONE, DEMO_TWO)
    deps = anyio.run(demo_deps, tenants, lambda: NOW)
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
            # A member is never an administrator; the demo seeds members only.
            assert body["administrator"] is False
            assert client.get("/admin/tenants", headers=auth).status_code == 403
            seen.setdefault(tenant, set()).update(a["alert_id"] for a in alerts)
    assert set(seen) == set(tenants)
    assert not seen[DEMO_ONE] & seen[DEMO_TWO]
    auth = _session(sessions[f"{DEMO_ONE}-analyst"], deps.frontend_origin)
    systems = client.get(f"/tenants/{DEMO_ONE}/systems", headers=auth).json()["items"]
    assert {s["system_id"]: s["has_credentials"] for s in systems} == {"siem": False, "tickets": True}


def test_the_demo_seed_serves_every_investigation_with_an_exact_cost_beside_a_number() -> None:
    """The demo's investigations carry `cost_is_lower_limit` over the wire: false, each beside a number. (#1377 S2, S4)"""
    deps = anyio.run(demo_deps, (DEMO_ONE,), lambda: NOW)
    client = TestClient(create_app(deps), base_url=BASE)
    auth = _session(demo_sessions((DEMO_ONE,))[f"{DEMO_ONE}-analyst"], deps.frontend_origin)
    items = client.get(f"/tenants/{DEMO_ONE}/investigations", headers=auth).json()["items"]
    assert items
    assert all((i["cost_is_lower_limit"], i["cost_usd"] is not None) == (False, True) for i in items), items


def test_a_demo_session_outlasts_the_production_idle_limit() -> None:
    """The printed demo sessions keep working through a night unused; only their own lifetime ends them."""
    clock = {"now": NOW}
    deps = anyio.run(demo_deps, (DEMO_ONE,), lambda: clock["now"])
    client = TestClient(create_app(deps), base_url=BASE)
    auth = _session(demo_sessions((DEMO_ONE,))[f"{DEMO_ONE}-analyst"], deps.frontend_origin)
    clock["now"] = NOW + _dt.timedelta(days=3)
    assert client.get("/me", headers=auth).status_code == 200
    clock["now"] = NOW + _dt.timedelta(days=366)
    assert client.get("/me", headers=auth).status_code == 401


def test_the_demo_sign_in_port_refuses_with_a_503_problem() -> None:
    """The demo has no Keycloak; `/auth/login` answers a 503 problem, never a redirect."""
    client = TestClient(create_app(anyio.run(demo_deps, (DEMO_ONE,), lambda: NOW)), base_url=BASE)
    response = client.get("/auth/login", follow_redirects=False)
    assert response.status_code == 503
    assert response.headers["Content-Type"] == "application/problem+json"
    assert "Location" not in response.headers


def test_the_demo_store_keeps_the_audit_events_a_transaction_commits() -> None:
    """The actor is the demo session's user id (read from `/me`)."""
    deps = anyio.run(demo_deps, (DEMO_ONE,), lambda: NOW)
    client = TestClient(create_app(deps), base_url=BASE)
    auth = _session(demo_sessions((DEMO_ONE,))[f"{DEMO_ONE}-analyst"], deps.frontend_origin)
    user_id = client.get("/me", headers=auth).json()["user"]["id"]
    created = client.post(f"/tenants/{DEMO_ONE}/investigations", headers=auth,
                          json={"alert_id": demo_id(AlertId, DEMO_ONE, "alert-0003"), "client_request_id": "r1"})
    assert created.status_code == 201, created.text
    events = deps.writes.audit_events  # type: ignore[attr-defined]
    assert [(e.tenant_id, e.user_id, e.action, e.target) for e in events] == [
        (DEMO_ONE, user_id, "investigation.start", created.json()["investigation_id"])]


def test_the_demo_store_keys_records_by_tenant() -> None:
    store = InMemoryStore(lambda: NOW)
    store.add_alert(DEMO_ONE, ALERT)
    store.add_alert(DEMO_TWO, ALERT.model_copy(update={"title": "two's"}))
    one, two = anyio.run(store.get_alert, DEMO_ONE, "a1000000-0000-4000-8000-000000000001"), anyio.run(store.get_alert, DEMO_TWO, "a1000000-0000-4000-8000-000000000001")
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
        anyio.run(demo_deps, tenants)
