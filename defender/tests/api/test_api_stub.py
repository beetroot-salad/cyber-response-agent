"""The platform API HTTP layer over a scripted fake: routes, login seam, port-answer to response mapping."""
from __future__ import annotations

from defender.tests.support.api._mount1161 import API
from defender.tests.support.shared._fixture_uuid import fixture_uuid

import base64
import dataclasses
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

from defender.api import job_store as job_store_module, ports as ports_module  # noqa: E402
from defender.api.app import MAX_PAGE, create_app  # noqa: E402
from defender.api.models import (  # noqa: E402
    Alert,
    AlertSummary,
    Investigation,
    LearningJob,
    Lesson,
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
from defender.tests.support.tenancy._mapping1345 import ALERT_MAPPING_ROUTE, alert_mapping_url  # noqa: E402
from defender.tests.support.api._programs1307 import NoProgramsRealm  # noqa: E402
from defender.tests.support.tenancy._twin1496 import seed_tenant  # noqa: E402
from defender.tests.support.identity._seed1496 import seed_membership, seed_user  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[3]
NOW = _dt.datetime(2026, 9, 28, 12, 0, tzinfo=_dt.UTC)

A = fixture_uuid("tenant:tenant-a")
B = fixture_uuid("tenant:tenant-b")
USER = fixture_uuid("user:ann")
#: The tenant is the path's `T`; the caller is a session seeded through the identity repository,
#: sent as the `__Host-defender_session` cookie plus the configured `Origin`.
T = f"{API}/tenants/{A}"
TB = f"{API}/tenants/{B}"
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
SUMMARY = AlertSummary.model_validate({**ALERT.model_dump(exclude={"raw"}), "outcome": None, "latest_status": None})  # #1581: the list adds the two (conflict, updated)
INV = Investigation(
    investigation_id="b1000000-0000-4000-8000-000000000001", alert_id="a1000000-0000-4000-8000-000000000001", status="completed", disposition="benign",
    request_key="req-1", attempt=1,
    cost_usd=1.5, cost_is_lower_limit=False, created_at=NOW, artifacts=["report.md", "gather_raw/L1/0.json"],
    update_ticket=False,  # #1471 C-4: the request's flag
    # The knowledge revision the run used (`current` = the run record's `fresh`).
    knowledge={"status": "current", "commit": "f4e5c0de0000f4e5c0de0000f4e5c0de0000f4e5",
               "stale_kind": None},
)
JOB = LearningJob(
    learning_job_id="c1000000-0000-4000-8000-000000000001", investigation_id="b1000000-0000-4000-8000-000000000001", alert_id="a1000000-0000-4000-8000-000000000001", status="queued",
    trigger="explicit", created_at=NOW,
)
LESSON = Lesson(lesson_id="le-1", title="t", description="d", status="live")
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
    ("GET", API + "/tenants/{tenant_id}/alerts"),
    ("GET", API + "/tenants/{tenant_id}/alerts/{alert_id}"),
    ("POST", API + "/tenants/{tenant_id}/investigations"),
    ("GET", API + "/tenants/{tenant_id}/investigations"),
    ("GET", API + "/tenants/{tenant_id}/investigations/{investigation_id}"),
    ("POST", API + "/tenants/{tenant_id}/investigations/{investigation_id}/cancel"),
    ("DELETE", API + "/tenants/{tenant_id}/investigations/{investigation_id}"),
    ("GET", API + "/tenants/{tenant_id}/investigations/{investigation_id}/artifacts/{key}"),
    ("POST", API + "/tenants/{tenant_id}/learning-jobs"),
    ("GET", API + "/tenants/{tenant_id}/learning-jobs"),
    ("GET", API + "/tenants/{tenant_id}/learning-jobs/{learning_job_id}"),
    ("GET", API + "/tenants/{tenant_id}/lessons"),
    # #1470: the config routes in the record's shape (their behaviour is `test_1470_config_routes`, over the real store)
    ("GET", API + "/tenants/{tenant_id}/adapters"),
    ("GET", API + "/tenants/{tenant_id}/systems"),
    ("GET", API + "/tenants/{tenant_id}/systems/{system_id}"),
    ("PUT", API + "/tenants/{tenant_id}/systems/{system_id}"),
    ("DELETE", API + "/tenants/{tenant_id}/systems/{system_id}"),
    ("PUT", API + "/tenants/{tenant_id}/systems/{system_id}/credentials"),
    ("POST", API + "/tenants/{tenant_id}/systems/{system_id}/check"),
    ("GET", API + "/tenants/{tenant_id}/case-record"),
    ("PUT", API + "/tenants/{tenant_id}/case-record"),
    ("DELETE", API + "/tenants/{tenant_id}/case-record"),
    # #1345 O1: the tenant's alert mapping, read and replaced whole (sketch: invented path)
    ("GET", ALERT_MAPPING_ROUTE),
    ("PUT", ALERT_MAPPING_ROUTE),
    # #1485 O1, O2: the tenant's set-aside items and parked batches (Names, Routes)
    ("GET", API + "/tenants/{tenant_id}/learning/items"),
    ("GET", API + "/tenants/{tenant_id}/learning/parked-batches"),
    # #1537 O1-O3: a person's release of an item and of a batch, and an abandon request (names as the design's API section gives them)
    ("POST", API + "/tenants/{tenant_id}/learning/items/{item_id}/release"),
    ("POST", API + "/tenants/{tenant_id}/learning/batches/{batch_id}/release"),
    ("POST", API + "/tenants/{tenant_id}/learning/batches/{batch_id}/abandon"),
    # Home redesign: where a browser opens the tenant's knowledge repository
    ("GET", API + "/tenants/{tenant_id}/repository"),
}
#: What #1306 adds (design "Endpoints"; param names pinned by this suite).
IDENTITY_ROUTES = {
    ("GET", API + "/auth/login"),
    ("GET", API + "/auth/callback"),
    ("POST", API + "/auth/logout"),
    ("GET", API + "/me"),
    ("GET", API + "/tenants/{tenant_id}/members"),
    ("DELETE", API + "/tenants/{tenant_id}/members/{user_id}"),
    ("GET", API + "/tenants/{tenant_id}/invitations"),
    ("POST", API + "/tenants/{tenant_id}/invitations"),
    ("DELETE", API + "/tenants/{tenant_id}/invitations/{invitation_id}"),
    ("POST", API + "/invitations/{invitation_id}/accept"),
    ("GET", API + "/admin/tenants"),
    ("POST", API + "/admin/tenants/{tenant_id}/invitations"),
    ("POST", API + "/admin/tenants"),
    ("GET", API + "/admin/tenants/{tenant_id}"),
    ("POST", API + "/admin/tenants/{tenant_id}/resume"),
    ("POST", API + "/admin/tenants/{tenant_id}/offboard"),
    ("POST", API + "/admin/tenants/{tenant_id}/rotate-forge-credential"),
}
#: What #1307 adds (design "Program and credential routes"; param names pinned by this suite). Conflict updated: r3.
PROGRAM_ROUTES = {
    ("POST", API + "/tenants/{tenant_id}/programs"),
    ("GET", API + "/tenants/{tenant_id}/programs"),
    ("DELETE", API + "/tenants/{tenant_id}/programs/{program_id}"),
    ("POST", API + "/tenants/{tenant_id}/programs/{program_id}/credentials"),
    ("GET", API + "/tenants/{tenant_id}/programs/{program_id}/credentials"),
    ("DELETE", API + "/tenants/{tenant_id}/programs/{program_id}/credentials/{credential_id}"),
}
IDENTITY_ROUTES = IDENTITY_ROUTES | PROGRAM_ROUTES  # same refusal contract as the members/invitations routes
#: What #1471 adds (surface §1): readiness and adoption, under the tenant and the admin routes. Their behaviour is
#: `test_1471_host_requests_api`, over the real store, so they are listed here and not scripted (repair 5).
HOST_REQUEST_ROUTES = {
    ("POST", API + "/tenants/{tenant_id}/readiness"),
    ("GET", API + "/tenants/{tenant_id}/readiness/{readiness_id}"),
    ("POST", API + "/tenants/{tenant_id}/systems/{system_id}/adoptions"),
    ("GET", API + "/tenants/{tenant_id}/adoptions/{adoption_id}"),
    ("POST", API + "/admin/tenants/{tenant_id}/readiness"),
    ("GET", API + "/admin/tenants/{tenant_id}/readiness/{readiness_id}"),
    ("POST", API + "/admin/tenants/{tenant_id}/systems/{system_id}/adoptions"),
    ("GET", API + "/admin/tenants/{tenant_id}/adoptions/{adoption_id}"),
}
#: What #1546 adds (r9 "Retention setting": "a per-tenant row, both values NOT NULL, 30-730 days, written through the API
#: (`config.write`, audited)"; the path is `test_1546_retention_route`'s pin). Its behaviour is that file's, over the real
#: store, so it is listed here and not scripted, as the host-request routes are.
EVIDENCE_RETENTION_ROUTES = {
    ("GET", API + "/tenants/{tenant_id}/evidence-retention"),
    ("PUT", API + "/tenants/{tenant_id}/evidence-retention"),
}
PUBLIC_ROUTES = EXISTING_ROUTES | IDENTITY_ROUTES | HOST_REQUEST_ROUTES | EVIDENCE_RETENTION_ROUTES

#: One successful call per route: (route, concrete path, body, the port answers it needs).
HAPPY: list[tuple[tuple[str, str], str, dict[str, Any] | None, dict[str, Any]]] = [
    (("GET", API + "/tenants/{tenant_id}/alerts"), f"{T}/alerts", None, {"list_alerts": [SUMMARY]}),
    (("GET", API + "/tenants/{tenant_id}/alerts/{alert_id}"), f"{T}/alerts/a1000000-0000-4000-8000-000000000001", None, {"get_alert": ALERT}),
    (("POST", API + "/tenants/{tenant_id}/investigations"), f"{T}/investigations",
     {"alert_id": "a1000000-0000-4000-8000-000000000001", "client_request_id": "r1"}, {"create_investigation": (INV, True)}),
    (("GET", API + "/tenants/{tenant_id}/investigations"), f"{T}/investigations", None, {"list_investigations": [INV]}),
    (("GET", API + "/tenants/{tenant_id}/investigations/{investigation_id}"), f"{T}/investigations/b1000000-0000-4000-8000-000000000001", None,
     {"get_investigation": INV}),
    (("POST", API + "/tenants/{tenant_id}/investigations/{investigation_id}/cancel"), f"{T}/investigations/b1000000-0000-4000-8000-000000000001/cancel", None,
     {"cancel_investigation": INV}),
    (("DELETE", API + "/tenants/{tenant_id}/investigations/{investigation_id}"), f"{T}/investigations/b1000000-0000-4000-8000-000000000001", None,
     {"delete_investigation": None}),
    (("GET", API + "/tenants/{tenant_id}/investigations/{investigation_id}/artifacts/{key}"),
     f"{T}/investigations/b1000000-0000-4000-8000-000000000001/artifacts/report.md", None,
     {"get_investigation": INV, "signed_url": SIGNED}),
    (("POST", API + "/tenants/{tenant_id}/learning-jobs"), f"{T}/learning-jobs",
     {"investigation_id": "b1000000-0000-4000-8000-000000000001", "client_request_id": "r1"}, {"create_learning_job": (JOB, True)}),
    (("GET", API + "/tenants/{tenant_id}/learning-jobs"), f"{T}/learning-jobs", None, {"list_learning_jobs": [JOB]}),
    (("GET", API + "/tenants/{tenant_id}/learning-jobs/{learning_job_id}"), f"{T}/learning-jobs/c1000000-0000-4000-8000-000000000001", None,
     {"get_learning_job": JOB}),
    (("GET", API + "/tenants/{tenant_id}/lessons"), f"{T}/lessons", None, {"list_lessons": [LESSON]}),
    (("GET", ALERT_MAPPING_ROUTE), alert_mapping_url(A), None,
     {"get_alert_mapping": _Answer("saved mapping", lambda _tenant: _alert_mapping_wire(MAPPING_BODY))}),
    (("PUT", ALERT_MAPPING_ROUTE), alert_mapping_url(A), MAPPING_BODY,
     {"put_alert_mapping": _Answer("created from the body", lambda _principal, body: (body, True))}),
    # #1485: an empty page is a served list; the wire models are built inside the cases, never at collection.
    (("GET", API + "/tenants/{tenant_id}/learning/items"), f"{T}/learning/items", None, {"list_set_aside": []}),
    (("GET", API + "/tenants/{tenant_id}/learning/parked-batches"), f"{T}/learning/parked-batches", None,
     {"list_parked_batches": []}),
]


#: The announcing writes: each one port call that commits then announces, taking the principal first (#1083 Ports,
#: Am-2, Am-6). The systems and credentials writes announce through the real ports (#1470: `test_1470_*`).
WRITES = {"create_investigation", "cancel_investigation", "delete_investigation",
          "create_learning_job", "put_alert_mapping"}
#: Every call whose first argument is the principal: the writes and the audit-only port's `announce`.
PRINCIPAL_CALLS = WRITES | {"announce"}


class Scripted:
    """Every port the routes call: `answers` maps a method name to its return value, an exception
    to raise, or a callable that answers the call; an unscripted call fails the test.

    A write that does not raise is recorded in `written`; the audit-only port's `announce` records into `audits`.
    This port announces nothing for a write: announcing is the real store's job, tested over it (#1496)."""

    def __init__(self, answers: dict[str, Any]) -> None:
        self.answers = answers
        self.calls: list[tuple[str, tuple[Any, ...], dict[str, Any]]] = []
        self.written: list[tuple[str, Principal]] = []
        self.audits: list[tuple[str, str, str, str, str]] = []

    async def announce(self, principal: Principal, action: str, target: str, detail: str = "") -> None:
        """The audit-only port (#1083 Ports): scripted like any call, recorded as an event when it answers."""
        self.calls.append(("announce", (principal, action, target, detail), {}))
        failure = self.answers.get("announce")
        if isinstance(failure, BaseException):
            raise failure
        self.audits.append((principal.tenant_id, principal.actor_id, action, target, detail))

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
            result = answer(*args, **kwargs) if callable(answer) else answer
            if name in WRITES:
                self.written.append((name, args[0]))
            return result

        return call

    def called(self, name: str) -> list[tuple[tuple[Any, ...], dict[str, Any]]]:
        return [(args, kwargs) for n, args, kwargs in self.calls if n == name]


class _Unused:
    """A sign-in or mail port these route tests never exercise: any call is a failure."""

    def __getattr__(self, name: str) -> Callable[..., Any]:
        raise AssertionError(f"a route test reached the unused port: {name}")


async def _seed_identity() -> tuple[IdentityService, dict[str, str], InMemoryTenantRepository]:
    """Ann is a member of A, Bob of B and Cy of both, each with a seeded session. Returns the
    service, the seeded user ids by session value and the tenant twin the service shares."""
    tenants = InMemoryTenantRepository()
    await seed_tenant(tenants, TenantId(A), created_at=NOW)
    await seed_tenant(tenants, TenantId(B), created_at=NOW)
    repo = InMemoryIdentityRepository(tenants=tenants)
    users: dict[str, str] = {}
    for email, tenant, session in (("ann@a.example", A, SESSION_A), ("bob@b.example", B, SESSION_B)):
        user = await seed_user(repo, email, created_at=NOW, status="active", display_name=email)
        await seed_membership(repo, user.id, TenantId(tenant), status="active", invited_by=None,
                            created_at=NOW, accepted_at=NOW)
        await repo.add_session(session, user.id, now=NOW, expires_at=NOW + _dt.timedelta(days=7))
        users[session] = user.id
    cy = await seed_user(repo, "cy@c.example", created_at=NOW, status="active", display_name="cy")
    for tenant in (A, B):
        await seed_membership(repo, cy.id, TenantId(tenant), status="active", invited_by=None,
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
        alerts=ports, investigations=ports, learning_jobs=ports, learning_work=ports, lessons=ports,
        systems=ports, writes=ports, secrets=ports, checker=ports, artifact_links=ports, offboarding=ports,
        alert_mapping=ports, audit=ports,  # FC-11 and the audit-only port (Am-5: every construction site)
        **({"host_requests": ports} if "host_requests" in {f.name for f in dataclasses.fields(ApiDeps)} else {}),  # #1471
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
    doc = Api().client.get(API + "/openapi.json").json()
    documented = {(method.upper(), path) for path, ops in doc["paths"].items() for method in ops}
    assert documented == PUBLIC_ROUTES
    schemes = doc.get("components", {}).get("securitySchemes", {})
    assert "HTTPBearer" not in schemes
    assert not [s for s in schemes.values() if str(s.get("scheme", "")).lower() == "bearer"]


#: The routes this suite does not script: #1470's config routes answer from the real record store (`test_1470_*`), and the
#: check still refuses (the `REFUSED` sweep below).
CONFIG = {route for route in EXISTING_ROUTES if any(w in route[1] for w in ("/systems", "/adapters", "/case-record"))}
#: #1537's three learning actions answer from the real adapter over a real store (`test_learning_actions_1537`: success,
#: refusals, audit, roles), so they are not scripted here; the sweeps over `EXISTING_ROUTES` (declared problems) still cover them.
LEARNING_ACTIONS = {route for route in EXISTING_ROUTES
                    if route[0] == "POST" and route[1].endswith(("/release", "/abandon")) and "/learning/" in route[1]}
#: The home redesign's repository read answers from the tenant store's record (`test_1083_real_server`'s `home_` tests:
#: served, refused forms, another tenant's 404), so it is not scripted here.
REPOSITORY = {("GET", API + "/tenants/{tenant_id}/repository")}


def test_the_happy_path_table_covers_every_existing_route() -> None:
    """Every route is scripted here, answered by the real store (`CONFIG`, `LEARNING_ACTIONS`), or refused with its owner's number."""
    assert {route for route, *_ in HAPPY} == EXISTING_ROUTES - CONFIG - LEARNING_ACTIONS - REPOSITORY
    assert REPOSITORY <= EXISTING_ROUTES
    assert len(CONFIG) == 10
    assert len(LEARNING_ACTIONS) == 3


def test_the_api_never_loads_the_runtime_or_the_learning_loop() -> None:
    """The API modules, with `defender.identity`, load no runtime or learning-loop module."""
    probe = (
        "import json, sys; import defender.api.app, defender.api_server; "
        "import defender.identity; "
        "print(json.dumps(sorted(sys.modules)))"
    )
    out = subprocess.run(
        [sys.executable, "-c", probe], cwd=REPO_ROOT, capture_output=True, text=True,
        encoding="utf-8", check=True,
    )
    assert api_forbidden(json.loads(out.stdout)) == []


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
    assert {args[0] for name, args, _ in api.ports.calls if name not in PRINCIPAL_CALLS} <= {A}
    principals = [args[0] for name, args, _ in api.ports.calls if name in PRINCIPAL_CALLS]
    assert {(p.tenant_id, p.actor_id, p.credential_id) for p in principals} <= {(A, api.user, None)}
    assert {(tenant, user) for tenant, user, *_ in api.ports.audits} <= {(A, api.user)}
    writes = [name for name, _, _ in api.ports.calls if name in WRITES]
    assert [name for name, _ in api.ports.written] == writes, "each write is one call, naming the principal first"
    assert len(writes) <= 1, "a route makes one write"


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
    assert api.ports.written == []
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
    assert api.ports.written == []


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
    assert api.ports.written == []
    # control: the same session with the configured Origin is served
    assert api.client.request(route[0], path, headers=AUTH, json=body,
                              follow_redirects=False).status_code < 400


@pytest.mark.parametrize(("claim", "code"), [("Acme_Corp", 422), ("org_2NxAbCdEf", 422), ("", 404)])
def test_a_path_tenant_that_fails_the_grammar_is_refused_not_a_500(claim: str, code: int) -> None:
    """A malformed T in the path is a 422 (#1382); an empty one matches no route (404)."""
    api = Api()
    response = api.lenient().get(f"{API}/tenants/{claim}/alerts", headers=AUTH)
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


@pytest.mark.parametrize(("path", "body", "port", "record", "location", "flag"), [
    # #1471 C-3/C-4: the investigation create's port call also carries the request's `update_ticket` (default false).
    (f"{T}/investigations", {"alert_id": "a1000000-0000-4000-8000-000000000001", "client_request_id": "r1"}, "create_investigation",
     INV, f"{T}/investigations/b1000000-0000-4000-8000-000000000001", [False]),
    (f"{T}/learning-jobs", {"investigation_id": "b1000000-0000-4000-8000-000000000001", "client_request_id": "r1"},
     "create_learning_job", JOB, f"{T}/learning-jobs/c1000000-0000-4000-8000-000000000001", []),
])
def test_a_create_is_a_201_with_location_only_when_the_store_created(
    path: str, body: dict[str, str], port: str, record: Any, location: str, flag: list[bool],
) -> None:
    """A create is one write call, principal first; 201 with Location when created, 200 without on a replay; the route announces nothing. (Ports, P2)"""
    created = Api(**{port: (record, True)})
    response = created.client.post(path, headers=AUTH, json=body)
    assert response.status_code == 201
    assert response.headers["Location"] == location
    assert response.json() == record.model_dump(mode="json")
    [(args, kwargs)] = created.ports.called(port)
    # #1471 C-4 names the flag, not how the route passes it: bound to the port's own signature, positional or keyword
    # are the same call, and the flag must still be passed (not left to the port's default).
    signature = inspect.signature(getattr(ports_module.Writes, port))
    params = [name for name in signature.parameters if name != "self"]
    expected = [Principal(tenant_id=A, actor_id=created.user), *body.values(), *flag]
    assert args[:1] == (expected[0],), "principal first"
    bound = signature.bind(None, *args, **kwargs).arguments
    assert {k: v for k, v in bound.items() if k != "self"} == dict(zip(params, expected, strict=True)), (args, kwargs)
    assert [name for name, _ in created.ports.written] == [port]
    assert created.ports.audits == [], "the route announces nothing"

    replayed = Api(**{port: (record, False)})
    response = replayed.client.post(path, headers=AUTH, json=body)
    assert response.status_code == 200
    assert "Location" not in response.headers
    assert response.json() == record.model_dump(mode="json")
    assert [name for name, _ in replayed.ports.written] == [port]
    assert replayed.ports.audits == []


@pytest.mark.parametrize(("path", "body", "port", "record"), [
    (f"{T}/investigations", {"alert_id": "a1000000-0000-4000-8000-0000000000ff", "client_request_id": "r1"}, "create_investigation", INV),
    (f"{T}/learning-jobs", {"investigation_id": "b1000000-0000-4000-8000-0000000000ff", "client_request_id": "r1"},
     "create_learning_job", JOB),
])
@pytest.mark.parametrize("created", [True, False])
def test_a_create_answered_for_another_target_is_a_500_over_the_committed_write(
    path: str, body: dict[str, str], port: str, record: Any, created: bool,
) -> None:
    """The answer check runs after commit: a 500, the write stands, the route announces nothing. (Ports)"""
    api = Api(**{port: (record, created)})
    response = api.lenient().post(path, headers=AUTH, json=body)
    assert response.status_code == 500
    assert "Location" not in response.headers
    assert [name for name, _ in api.ports.written] == [port]
    assert api.ports.audits == []


@pytest.mark.parametrize(("route", "path", "body", "answers"), [row for row in HAPPY if any(n in WRITES for n in row[3])],
                         ids=lambda v: str(v))
def test_a_write_port_that_raises_answers_500_with_the_write_called_and_the_route_announces_nothing(
    route: tuple[str, str], path: str, body: dict[str, Any] | None, answers: dict[str, Any],
) -> None:
    """Every announcing write: a port exception is a 500 after the write call was made; the route announces nothing. (Am-2, P2)"""
    served = Api(**answers)
    assert served.client.request(route[0], path, headers=AUTH, json=body).status_code < 400  # control
    [name] = WRITES & answers.keys()
    failing = Api(**{**answers, name: RuntimeError("port down")})
    response = failing.lenient().request(route[0], path, headers=AUTH, json=body)
    assert response.status_code == 500
    assert failing.ports.called(name) != []
    assert failing.ports.audits == []


# --- #1345 O1: the alert mapping's routes (shape over the scripted ports; the rules are the store's) -------


def test_1345_put_alert_mapping_is_201_at_its_own_url_then_200_and_the_route_announces_nothing() -> None:
    """The first save creates (201, Location), a later one replaces (200); the port gets the body as sent; the
    answer has all six entries, unmapped ones null; one `alert_mapping.update` event each. (#1345 O1)"""
    created = Api(put_alert_mapping=lambda _principal, body: (body, True))
    response = created.client.put(alert_mapping_url(A), headers=AUTH, json=MAPPING_BODY)
    assert (response.status_code, response.headers["Location"]) == (201, alert_mapping_url(A))
    assert response.json() == {entry: MAPPING_BODY.get(entry) for entry in MAPPING_ENTRIES}
    ((principal, sent), kwargs), = created.ports.called("put_alert_mapping")
    assert (principal, sent.model_dump(), kwargs) == (Principal(tenant_id=A, actor_id=created.user), MAPPING_BODY, {})  # r5: the port gets the validated wire model's `model_dump()`

    replaced = Api(put_alert_mapping=lambda _principal, body: (body, False))
    response = replaced.client.put(alert_mapping_url(A), headers=AUTH, json=MAPPING_BODY)
    assert response.status_code == 200
    assert "Location" not in response.headers
    assert created.ports.audits == replaced.ports.audits == [], "the write port announces `alert_mapping.update`"


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
    ({**MAPPING_BODY, "description": 42}, "description"),  # not a path
    ({**MAPPING_BODY, "summary": ""}, "summary"),  # an empty path
], ids=["invalid-path", "empty-segment", "unknown-entry", "missing-entry", "not-a-path", "empty-path"])
def test_1345_an_invalid_or_incomplete_mapping_is_a_422_naming_the_entry_before_any_port_call(body: dict[str, str], entry: str) -> None:
    """The wire model refuses it (r5: validated through `records`' `check_mapping`; D4: all six named): 422 naming the
    entry, no port call, no audit. (#1345 O1, M2)"""
    api = Api()
    response = api.client.put(alert_mapping_url(A), headers=AUTH, json=body)
    assert response.status_code == 422, response.text
    assert entry in response.text
    assert (api.ports.calls, api.ports.audits) == ([], [])


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
def test_a_cancel_or_delete_is_one_write_call_naming_the_principal_and_the_route_announces_nothing(
    method: str, path: str, port: str, answer: Any, action: str,
) -> None:
    """`action` is announced by the write port (store contract), never by the route. (Ports, P2)"""
    api = Api(**{port: answer})
    assert api.client.request(method, path, headers=AUTH).status_code < 400
    assert api.ports.called(port) == [((Principal(tenant_id=A, actor_id=api.user), "b1000000-0000-4000-8000-000000000001"), {})]
    assert [name for name, _ in api.ports.written] == [port]
    assert api.ports.audits == []


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
def test_a_store_refusal_maps_to_its_status_and_writes_and_announces_nothing(
    method: str, path: str, body: dict[str, str] | None, port: str, error: Exception, code: int,
) -> None:
    api = Api(**{port: error})
    response = api.client.request(method, path, headers=AUTH, json=body)
    assert response.status_code == code
    assert response.headers["Content-Type"] == "application/problem+json"
    assert response.json() == {"type": "about:blank", "title": HTTPStatus(code).phrase,
                               "status": code, "detail": "x"}
    assert (api.ports.written, api.ports.audits) == ([], []), "a refused write is not recorded and the route announces nothing"


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
    assert api.ports.written == []
    assert api.ports.audits == []


def test_an_artifact_link_is_not_handed_out_unless_its_read_is_audited() -> None:
    api = Api(get_investigation=INV, signed_url=SIGNED, announce=RuntimeError("audit down"))
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
                              json={"for_version": 1, "credentials": {"api_token": secret}})
    assert response.status_code == 422
    problem = response.json()
    assert problem["errors"] == [{"loc": ["body", "credentials", "api_token"],
                                  "msg": "Input should be a valid string", "type": "string_type"}]
    assert str(secret) not in response.text


def test_1537_the_published_contract_declares_the_learning_actions_refusals_and_their_success_status() -> None:
    """Each of the three learning actions publishes the 404 (not the tenant's) and the 409 (not in an actionable state) its refusals answer with, as problems; a release answers 200 and an abandon request 202. (O1-O3, PR3)"""
    doc = Api().client.get(API + "/openapi.json").json()
    base = API + "/tenants/{tenant_id}/learning"
    for path, success, other in ((f"{base}/items/{{item_id}}/release", "200", "202"),
                                 (f"{base}/batches/{{batch_id}}/release", "200", "202"),
                                 (f"{base}/batches/{{batch_id}}/abandon", "202", "200")):
        responses = doc["paths"][path]["post"]["responses"]
        assert {success, "404", "409"} <= set(responses), (path, sorted(responses))
        assert other not in responses, (path, sorted(responses))
        for refusal in ("404", "409"):
            assert responses[refusal]["content"] == {
                "application/problem+json": {"schema": {"$ref": "#/components/schemas/Problem"}}}, (path, refusal)


def test_the_published_contract_declares_each_routes_problems() -> None:
    doc = Api().client.get(API + "/openapi.json").json()
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
    assert declared[("POST", API + "/tenants/{tenant_id}/investigations/{investigation_id}/cancel")] >= {404, 409}
    assert declared[("DELETE", API + "/tenants/{tenant_id}/investigations/{investigation_id}")] >= {404, 409}
    assert declared[("POST", API + "/tenants/{tenant_id}/investigations")] >= {409}
    refusable = {route for route in EXISTING_ROUTES if "/lessons" in route[1] or route[1].endswith("/check")}
    assert len(refusable) == 2
    assert all(501 in declared[route] for route in refusable), "the 501 is documented on every route of the unbacked families (O8)"
    assert declared[("POST", API + "/tenants/{tenant_id}/learning-jobs")] >= {409}
    assert declared[("GET", API + "/tenants/{tenant_id}/investigations/{investigation_id}/artifacts/{key}")] >= {404}
    # Every tenant route answers 404 to a non-member, so every one declares it.
    assert all(404 in errors for (_, path), errors in declared.items()
               if path.startswith(API + "/tenants/{tenant_id}"))
    # Every identity route but the two redirecting ones declares its 401 as a problem.
    signed_out = {("GET", API + "/auth/login"), ("GET", API + "/auth/callback")}
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
    assert kwargs == {"fired_after": after, "fired_before": None, "outcome": None,
                      "after": None, "limit": 8}  # #1581 O2: the route hands the port the filter, None when absent (conflict, updated)
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
    ("GET", f"{T}/learning/items?bogus=x"),          # #1485
    ("GET", f"{T}/learning/items?limit=5&fired_after=2026-09-28T08:00:00Z"),
    ("GET", f"{T}/learning/parked-batches?status=held"),
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
    (f"{T}/learning/items?status=held&limit=5", {"list_set_aside": []}),          # #1485
    (f"{T}/learning/parked-batches?limit=5", {"list_parked_batches": []}),
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
    ("PUT", f"{T}/systems/%E2%9C%93", {"replaces": 0, "enabled": True, "settings": {}, "access": ""}),
    ("PUT", f"{T}/systems/a%20b/credentials", {"for_version": 1, "credentials": {"k": "v"}}),
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
    assert api.ports.written == []


@pytest.mark.parametrize("limit", [0, MAX_PAGE + 1])
@pytest.mark.parametrize("path", [f"{T}/alerts", f"{T}/investigations", f"{T}/learning-jobs",
                                  f"{T}/learning/items", f"{T}/learning/parked-batches"])
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
                      request_key="k", attempt=1, cost_usd=0.0, cost_is_lower_limit=False, created_at=NOW,
                      update_ticket=False)


@pytest.mark.parametrize("bad", ["a/b", "a b", "a?b#c", "é", ""])
def test_an_id_outside_the_grammar_cannot_be_served(bad: str) -> None:
    with pytest.raises(ValueError, match="pattern"):
        INV.model_validate({**INV.model_dump(), "investigation_id": bad})


@pytest.mark.parametrize("legacy", ["Not_A_Tenant", "acme", "playground", "tenant-a", "blue"])
def test_a_principal_carries_a_checked_tenant(legacy) -> None:
    """`Principal`'s tenant is grammar-checked (#1382: as pydantic's own pattern error)."""
    with pytest.raises(ValidationError):
        Principal(tenant_id=legacy, actor_id=USER)


def test_a_naive_time_cannot_be_served() -> None:
    with pytest.raises(ValueError, match="timezone"):
        Investigation(investigation_id="i", alert_id="a", status="queued", cost_usd=0.0, cost_is_lower_limit=False,
                      request_key="k", attempt=1, created_at=NOW.replace(tzinfo=None), update_ticket=False)


# --- pagination ----------------------------------------------------------------------------

LATER = NOW + _dt.timedelta(hours=1)
INV_2 = INV.model_copy(update={"investigation_id": "b1000000-0000-4000-8000-000000000002", "created_at": LATER})
JOB_2 = JOB.model_copy(update={"learning_job_id": "c1000000-0000-4000-8000-000000000002", "created_at": LATER})
SUMMARY_2 = SUMMARY.model_copy(update={"alert_id": "a1000000-0000-4000-8000-000000000002", "fired_at": LATER})
LESSON_2 = LESSON.model_copy(update={"lesson_id": "le-2"})

#: (path, port, the store's first two rows in the list's order, the position the second page
#: must start after — the first row's, as the port's order names it).
LISTS = [
    (f"{T}/alerts", "list_alerts", [SUMMARY_2, SUMMARY], (LATER, "a1000000-0000-4000-8000-000000000002")),
    (f"{T}/investigations", "list_investigations", [INV_2, INV], (LATER, "b1000000-0000-4000-8000-000000000002")),
    (f"{T}/learning-jobs", "list_learning_jobs", [JOB_2, JOB], (LATER, "c1000000-0000-4000-8000-000000000002")),
    (f"{T}/lessons", "list_lessons", [LESSON, LESSON_2], "le-1"),
]


def _rows_after(rows: list[Any]) -> Callable[..., list[Any]]:
    """The store as a function of `after`: both rows from the start, the second after the first."""
    return lambda tenant, *, after, limit, **_filters: (rows if after is None else rows[1:])[:limit]


@pytest.mark.parametrize(("path", "port", "rows", "first_after"), LISTS, ids=[x[0] for x in LISTS])
def test_every_list_pages_by_cursor_from_the_last_row_served(
    path: str, port: str, rows: list[Any], first_after: Any,
) -> None:
    api = Api(**{port: _rows_after(rows)})
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
    api = Api(**{port: _rows_after(rows)})
    cursor = _edited(_cursor(api, path), id=bad_id)
    calls = len(api.ports.calls)
    response = api.client.get(path, headers=AUTH, params={"limit": 1, "cursor": cursor})
    assert response.status_code == 422
    assert len(api.ports.calls) == calls, "the edited cursor reached a port"


@pytest.mark.parametrize("bad_id", ["abc", "A1000000-0000-4000-8000-000000000002", "not-a-uuid-but-a-record-id"])
@pytest.mark.parametrize(("path", "port", "rows"), [x[:3] for x in LISTS[:3]], ids=[x[0] for x in LISTS[:3]])
def test_an_edited_cursor_with_an_id_not_of_the_lists_family_is_refused_before_the_store(
    path: str, port: str, rows: list[Any], bad_id: str,
) -> None:
    """A newest-first list's cursor id is read as the items' own id (canonical lowercase UUID): anything else, even a
    valid record id or the same UUID in upper case, is not a position in the list (422), never a store error. (#1498)"""
    api = Api(**{port: _rows_after(rows)})
    cursor = _edited(_cursor(api, path), id=bad_id)
    calls = len(api.ports.calls)
    response = api.client.get(path, headers=AUTH, params={"limit": 1, "cursor": cursor})
    assert response.status_code == 422
    assert "not a position in this list" in response.text
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


# --- #1485: the learning lists (items, parked batches): paging, filters, wire, demo ---------------------------------

ITEM_ID = "e1000000-0000-4000-8000-000000000001"
ITEM_ID_2 = "e1000000-0000-4000-8000-000000000002"
BATCH = "d1000000-0000-4000-8000-000000000001"
BATCH_2 = "d1000000-0000-4000-8000-000000000002"
LEARNING_ITEMS = f"{T}/learning/items"
LEARNING_PARKED = f"{T}/learning/parked-batches"
SCRIPT_REASON = '<script>alert("x")</script> & "q" \\n </td>'
ITEM_WIRE_FIELDS = {"item_id", "kind", "key", "status", "reason", "cause", "source_run", "batch_id", "pr_number", "updated_at"}
PARKED_WIRE_FIELDS = {"batch_id", "batch_kind", "lane", "blocks_lane", "branch", "pr_number", "reason", "cause", "parked_at",
                      "releasable", "abandon_requested_at", "last_checked", "created_at", "items"}


def _learning_api(**answers: Any) -> Api:
    """`Api` whose `learning_work` port is its scripted port too: `_deps`'s wiring with that one field replaced."""
    api = Api(**answers)
    api.client = TestClient(create_app(dataclasses.replace(api.client.app.state.deps, learning_work=api.ports)),
                            base_url=BASE)
    return api


def _set_aside_rows() -> list[Any]:
    """Two held items tied on `updated_at`, in the list's order (id descending). Built in the case, not at import."""
    from defender.api.models import SetAsideItem

    first = SetAsideItem(item_id=ITEM_ID_2, kind="finding", key="run 1/f 02", status="held", reason=SCRIPT_REASON,
                         cause="curator_held", source_run="run-1", batch_id=BATCH, pr_number=7, updated_at=LATER)
    return [first, first.model_copy(update={"item_id": ITEM_ID, "key": "run 1/f 01", "status": "dead", "reason": None,
                                            "cause": "attempt_ceiling", "source_run": None, "batch_id": None, "pr_number": None})]


def _parked_rows() -> list[Any]:
    """Two parked batches, newest first."""
    from defender.api.models import ParkedBatch, ParkedItemRef

    first = ParkedBatch(batch_id=BATCH_2, batch_kind="author", lane="author", blocks_lane=True, branch="learning/b2",
                        pr_number=9, reason="the forge refused 3 times", cause="forge_credential_refused",
                        parked_at=LATER, releasable=True, abandon_requested_at=None, last_checked=NOW, created_at=LATER,
                        items=[ParkedItemRef(kind="finding", key="f1")])
    return [first, first.model_copy(update={"batch_id": BATCH, "created_at": NOW, "items": [], "blocks_lane": False,
                                            "batch_kind": "revert", "pr_number": None, "reason": None,
                                            "cause": "foreign_pr", "parked_at": None, "releasable": False,
                                            "abandon_requested_at": LATER, "last_checked": None})]


#: (list name, path, port, rows, the position the second page must start after)
_LEARNING_LISTS = [
    ("learning-items", LEARNING_ITEMS, "list_set_aside", _set_aside_rows, (LATER, ITEM_ID_2)),
    ("parked-batches", LEARNING_PARKED, "list_parked_batches", _parked_rows, (LATER, BATCH_2)),
]


@pytest.mark.parametrize(("name", "path", "port", "rows", "first_after"), _LEARNING_LISTS, ids=[x[0] for x in _LEARNING_LISTS])
def test_1485_each_learning_list_pages_by_cursor_from_the_last_row_served(
    name: str, path: str, port: str, rows: Callable[[], list[Any]], first_after: Any,
) -> None:
    """Both lists page like every list: the port is asked `limit + 1` after nothing, then after (time, id) of the last
    row served; the default page is `DEFAULT_PAGE`. (Paging)"""
    from defender.api.app import DEFAULT_PAGE

    api = _learning_api(**{port: _rows_after(rows())})
    first = api.client.get(path, headers=AUTH, params={"limit": 1}).json()
    second = api.client.get(path, headers=AUTH, params={"limit": 1, "cursor": first["next_cursor"]}).json()
    assert (len(first["items"]), len(second["items"]), second["next_cursor"]) == (1, 1, None)
    (_, a), (_, b) = api.ports.called(port)
    assert (a["after"], a["limit"], b["after"], b["limit"]) == (None, 2, first_after, 2)
    plain = _learning_api(**{port: _rows_after(rows())})
    plain.client.get(path, headers=AUTH)
    assert plain.ports.called(port)[0][1]["limit"] == DEFAULT_PAGE + 1


@pytest.mark.parametrize(("name", "path", "port", "rows", "_after"), _LEARNING_LISTS, ids=[x[0] for x in _LEARNING_LISTS])
def test_1485_a_learning_list_serves_exactly_its_wire_fields_and_a_reason_as_plain_text(
    name: str, path: str, port: str, rows: Callable[[], list[Any]], _after: Any,
) -> None:
    """Each served row carries exactly the wire's fields (`item_id` and `batch_id` included, no payload or counters) and
    a `<script>` reason comes back byte for byte, unescaped. (Wire models, P2)"""
    api = _learning_api(**{port: _rows_after(rows())})
    response = api.client.get(path, headers=AUTH)
    assert response.status_code == 200, response.text
    served = response.json()["items"]
    assert [set(row) for row in served] == [ITEM_WIRE_FIELDS if name == "learning-items" else PARKED_WIRE_FIELDS] * 2
    if name == "learning-items":
        assert served[0]['reason'] == SCRIPT_REASON
        assert served[0]['item_id'] == ITEM_ID_2
        assert '<script>' in response.text
        assert '&lt;' not in response.text
        assert '\\u003c' not in response.text
        assert (served[1]["status"], served[1]["reason"], served[1]["batch_id"], served[1]["pr_number"]) == ("dead", None, None, None)
        assert (served[0]["cause"], served[1]["cause"]) == ("curator_held", "attempt_ceiling")
    else:
        assert [set(i) for i in served[0]["items"]] == [{"kind", "key"}]
        assert (served[0]["blocks_lane"], served[1]["blocks_lane"], served[1]["items"]) == (True, False, [])
        assert (served[0]["cause"], served[0]["releasable"], served[1]["releasable"]) == ("forge_credential_refused", True, False)
        assert (served[0]["abandon_requested_at"], served[1]["parked_at"], served[1]["last_checked"]) == (None, None, None)
        assert served[1]["abandon_requested_at"] is not None


@pytest.mark.parametrize("path", [LEARNING_ITEMS, LEARNING_PARKED])
def test_1485_a_learning_list_whose_tied_rows_are_not_in_id_descending_order_is_a_500_not_a_page(path: str) -> None:
    """Ties list by id descending: a port that answers the tied rows ascending broke its promise (500); control: the
    descending answer is served. (Paging)"""
    port, rows = ("list_set_aside", _set_aside_rows) if path == LEARNING_ITEMS else ("list_parked_batches", _parked_rows)
    ordered = rows()
    if path == LEARNING_PARKED:  # the two batches must tie for the case to bite
        ordered = [ordered[0], ordered[1].model_copy(update={"created_at": ordered[0].created_at})]
    else:
        ordered = [ordered[0], ordered[1].model_copy(update={"updated_at": ordered[0].updated_at})]
    ok = _learning_api(**{port: ordered})
    assert ok.client.get(path, headers=AUTH).status_code == 200
    broke = _learning_api(**{port: ordered[::-1]})
    assert broke.lenient().get(path, headers=AUTH).status_code == 500


@pytest.mark.parametrize("bad_id", ["abc", "A1000000-0000-4000-8000-000000000002", "not-a-uuid-but-a-record-id", "a b/é",
                                    "' OR 1=1 --", "", "\u0000", "x" * 1363])
@pytest.mark.parametrize(("name", "path", "port", "rows", "_after"), _LEARNING_LISTS, ids=[x[0] for x in _LEARNING_LISTS])
def test_1485_an_edited_learning_cursor_whose_id_is_not_a_uuid_is_refused_before_the_port(
    name: str, path: str, port: str, rows: Callable[[], list[Any]], _after: Any, bad_id: str,
) -> None:
    """A cursor edited to carry an id that is not a canonical UUID is a 422, whatever the text, and no port is asked. (Paging)"""
    api = _learning_api(**{port: _rows_after(rows())})
    cursor = _edited(_cursor(api, path), id=bad_id)
    calls = len(api.ports.calls)
    response = api.client.get(path, headers=AUTH, params={"limit": 1, "cursor": cursor})
    assert response.status_code == 422
    assert len(api.ports.calls) == calls, "the edited cursor reached a port"


@pytest.mark.parametrize(("name", "path", "port", "rows", "_after"), _LEARNING_LISTS, ids=[x[0] for x in _LEARNING_LISTS])
def test_1485_a_learning_cursor_of_the_wrong_shape_is_refused(
    name: str, path: str, port: str, rows: Callable[[], list[Any]], _after: Any,
) -> None:
    """A cursor with no time (an id-ordered list's) is not a position in a (time, id) list: 422, no port. (Paging)"""
    api = _learning_api(**{port: _rows_after(rows())})
    cursor = _edited(_cursor(api, path), at=None)
    calls = len(api.ports.calls)
    response = api.client.get(path, headers=AUTH, params={"limit": 1, "cursor": cursor})
    assert response.status_code == 422
    assert "not a position in this list" in response.text
    assert len(api.ports.calls) == calls


#: (list, its port, its rows) for the cursor sources: the two learning lists and one list of piece 1.
_CURSOR_SOURCES = {
    "learning-items": (LEARNING_ITEMS, "list_set_aside", _set_aside_rows),
    "parked-batches": (LEARNING_PARKED, "list_parked_batches", _parked_rows),
    "alerts": (f"{T}/alerts", "list_alerts", lambda: [SUMMARY_2, SUMMARY]),
}


@pytest.mark.parametrize(("source", "target"), [
    ("learning-items", "parked-batches"), ("learning-items", "alerts"),
    ("parked-batches", "learning-items"), ("alerts", "learning-items"),
])
def test_1485_a_cursor_of_one_list_given_to_another_is_a_422_and_the_target_port_is_never_asked(
    source: str, target: str,
) -> None:
    """An items cursor on another list, and another list's cursor on `learning/items`, is a 422 before the port is
    asked; control: each cursor first pages its own list. (Paging, Names)"""
    path, port, rows = _CURSOR_SOURCES[source]
    minted = _learning_api(**{port: _rows_after(rows())})
    cursor = _cursor(minted, path)
    own = minted.client.get(path, headers=AUTH, params={"limit": 1, "cursor": cursor})
    assert own.status_code == 200, own.text

    target_path, target_port, target_rows = _CURSOR_SOURCES[target]
    api = _learning_api(**{target_port: _rows_after(target_rows())})
    response = api.client.get(target_path, headers=AUTH, params={"limit": 1, "cursor": cursor})
    assert response.status_code == 422, response.text
    assert api.ports.calls == [], "the cursor reached a port"


@pytest.mark.parametrize(("status", "asked"), [("held", "held"), ("dead", "dead"), (None, None)])
def test_1485_the_items_status_filter_reaches_the_port_as_given(status: str | None, asked: str | None) -> None:
    """`status=held|dead` is passed to the port as that status, no `status` as `None`. (Names, Routes)"""
    api = _learning_api(list_set_aside=_rows_after(_set_aside_rows()))
    response = api.client.get(LEARNING_ITEMS, headers=AUTH, params={} if status is None else {"status": status})
    assert response.status_code == 200, response.text
    assert api.ports.called("list_set_aside")[0][1]["status"] == asked


@pytest.mark.parametrize("bad", ["waiting", "in_batch", "published", "skipped", "Held", "HELD", "held,dead", "", "all"])
def test_1485_a_status_outside_held_and_dead_is_a_422_before_any_port(bad: str) -> None:
    """Any other status, a stored one included, is a 422 with the port never asked; control: `dead` reaches it. (Names)"""
    api = _learning_api(list_set_aside=_rows_after(_set_aside_rows()))
    assert api.client.get(LEARNING_ITEMS, headers=AUTH, params={"status": bad}).status_code == 422
    assert api.ports.calls == []
    assert api.client.get(LEARNING_ITEMS, headers=AUTH, params={"status": "dead"}).status_code == 200


def test_1485_an_items_cursor_is_bound_to_its_status_filter() -> None:
    """A cursor minted under `status=held` is refused under `status=dead` and under no status; control: under `held` it
    pages on. (Routes: filters)"""
    api = _learning_api(list_set_aside=_rows_after(_set_aside_rows()))
    cursor = _cursor(api, LEARNING_ITEMS, {"status": "held"})
    calls = len(api.ports.calls)
    assert api.client.get(LEARNING_ITEMS, headers=AUTH, params={"limit": 1, "status": "held", "cursor": cursor}).status_code == 200
    calls = len(api.ports.calls)
    for params in ({"status": "dead"}, {}):
        assert api.client.get(LEARNING_ITEMS, headers=AUTH, params={"cursor": cursor, **params}).status_code == 422, params
    assert len(api.ports.calls) == calls


def test_1485_the_parked_list_declares_no_status_and_no_filter_name() -> None:
    """`status` (or any filter name) on `parked-batches` is an undeclared query name: a 422 `extra_forbidden`, no port;
    control: its own `limit` is served. (Routes, R7-2)"""
    api = _learning_api(list_parked_batches=_rows_after(_parked_rows()))
    for name in ("status", "kind", "fired_after"):
        r = api.client.get(LEARNING_PARKED, headers=AUTH, params={name: "held"})
        assert r.status_code == 422, name
        assert [(e["type"], e["loc"]) for e in r.json()["errors"]] == [("extra_forbidden", ["query", name])]
    assert api.ports.calls == []
    assert api.client.get(LEARNING_PARKED, headers=AUTH, params={"limit": 5}).status_code == 200


def test_1485_the_published_schemas_name_exactly_the_wire_fields() -> None:
    """The published document's `SetAsideItem`, `ParkedBatch` and `ParkedItemRef` carry exactly the wire's fields. (Wire models)"""
    schemas = Api().client.get(API + "/openapi.json").json()["components"]["schemas"]
    assert set(schemas["SetAsideItem"]["properties"]) == ITEM_WIRE_FIELDS
    assert set(schemas["ParkedBatch"]["properties"]) == PARKED_WIRE_FIELDS
    assert set(schemas["ParkedItemRef"]["properties"]) == {"kind", "key"}


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
    api = Api(**{port: _rows_after(rows)})
    page = api.client.get(path, headers=AUTH_AB, params={"limit": 1}).json()
    cursor = page["next_cursor"]
    assert cursor
    assert api.client.get(path, headers=AUTH_AB, params={"limit": 1, "cursor": cursor}).status_code == 200  # control
    calls = len(api.ports.calls)
    other = path.replace(T, TB, 1)
    assert api.client.get(other, headers=AUTH_AB, params={"cursor": cursor}).status_code == 422
    assert len(api.ports.calls) == calls


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


def test_every_port_method_is_a_coroutine_function_and_the_write_port_has_no_transaction() -> None:
    """D11/B: every method each `defender.api.ports` Protocol declares answers by `await`, whether or not anything
    implements it yet (a backing added later inherits the shape), and the real ports (`JobStorePorts`, the one object
    the server hands every backed family) keep it for each Protocol they implement (#1496: no fakes to check)."""
    protocols = [p for p in vars(ports_module).values()
                 if isinstance(p, type) and getattr(p, "_is_protocol", False) and p.__module__ == ports_module.__name__]
    declared = {p.__name__: [n for n in vars(p) if not n.startswith("_") and callable(vars(p)[n])] for p in protocols}
    sync = {p.__name__: [n for n in declared[p.__name__] if not inspect.iscoroutinefunction(vars(p)[n])] for p in protocols}
    assert sync == dict.fromkeys(declared, []), sync
    assert len(protocols) >= 9, declared
    assert all(declared.values()), declared  # every Protocol declares a method: none is checked vacuously
    real = job_store_module.JobStorePorts
    implemented = [p.__name__ for p in protocols if declared[p.__name__] and all(hasattr(real, n) for n in declared[p.__name__])]
    for protocol in protocols:
        if protocol.__name__ in implemented:
            assert [n for n in declared[protocol.__name__] if not inspect.iscoroutinefunction(getattr(real, n))] == [], protocol
    assert {"AlertsRepository", "Writes", "AlertMappingRepository", "Offboarding"} <= set(implemented), implemented
    assert not hasattr(ports_module, "WriteTransaction")
    assert not hasattr(real, "transaction")


# --- #1083: writes are single calls; the alert mapping has its own read port; unbacked families refuse -------


@pytest.mark.parametrize(("route", "path", "body", "answers"), HAPPY, ids=lambda v: str(v))
def test_1083_only_the_artifact_read_announces_through_the_audit_port(
    route: tuple[str, str], path: str, body: dict[str, Any] | None, answers: dict[str, Any],
) -> None:
    """Every other route (reads, work writes, systems, mapping) calls `announce` never: the write port announces. (P2, Am-4)"""
    api = Api(**answers)
    assert api.client.request(route[0], path, headers=AUTH, json=body, follow_redirects=False).status_code < 400
    announced_by_route = [name for name, _, _ in api.ports.calls if name == "announce"]
    assert announced_by_route == (["announce"] if path.endswith("/artifacts/report.md") else [])
    assert [(a, t) for _, _, a, t, _ in api.ports.audits] == (
        [("artifact.read", "b1000000-0000-4000-8000-000000000001")] if announced_by_route else [])


def test_1083_a_mapping_replace_answers_what_the_write_port_returned_not_the_body() -> None:
    """The port returns the mapping it holds and whether it created it; the route answers exactly that, 201 or 200. (Am-8)"""
    held = {**MAPPING_BODY, "signature": "stored.signature"}
    for created, status in ((True, 201), (False, 200)):
        api = Api(put_alert_mapping=lambda _principal, _body, held=held, created=created: (_alert_mapping_wire(held), created))
        response = api.client.put(alert_mapping_url(A), headers=AUTH, json=MAPPING_BODY)
        assert (response.status_code, response.json()) == (status, held)
        assert ("Location" in response.headers) is created


def test_1083_the_alert_mapping_reads_from_its_own_port_while_the_systems_port_refuses_whole() -> None:
    """`GET /alert-mapping` asks the alert-mapping port, never the systems port (G2, FC-11)."""
    deps, _ = _deps(Scripted({}))
    mapping = Scripted({"get_alert_mapping": lambda _tenant: _alert_mapping_wire(MAPPING_BODY)})
    deps = dataclasses.replace(deps, systems=_Unused(), alert_mapping=mapping)
    response = TestClient(create_app(deps), base_url=BASE).get(alert_mapping_url(A), headers=AUTH)
    assert (response.status_code, response.json()) == (200, MAPPING_BODY)
    assert mapping.called("get_alert_mapping") == [((A,), {})]


def _refusing(issue: str) -> Any:
    """FORCED CHOICE FC-15: the whole-refusing port is `defender.api.refusing.Refusing(issue)`: any method called on it
    refuses with the 501 the app maps, naming `issue`. Imported at call time; it does not exist before #1083."""
    from defender.api.refusing import Refusing

    return Refusing(issue)


def _refusing_client(others: dict[str, Any]) -> TestClient:
    """The app over refusing ports for lessons and the checker; the rest scripted by `others`."""
    deps, _ = _deps(Scripted(others))
    deps = dataclasses.replace(deps, lessons=_refusing("#1082"), checker=_refusing("#1460"))
    return TestClient(create_app(deps), base_url=BASE)


#: Every route still refusing, with the issue that owns it: the lessons (#1082, in the happy table) and the connection
#: check (#1460; #1470 O15, D-C), whose route is not scripted because it has no answer.
REFUSED = [(route, path, body, "#1082") for route, path, body, _ in HAPPY if "/lessons" in path] + [
    (("POST", API + "/tenants/{tenant_id}/systems/{system_id}/check"), f"{T}/systems/tix/check", None, "#1460")]


def test_1083_the_refused_family_is_the_lessons_and_the_check() -> None:
    """Control on the sweep: two routes, their two owners, and neither is this piece. (O8, #1470 O15)"""
    assert len(REFUSED) == 2
    assert {issue for *_, issue in REFUSED} == {"#1082", "#1460"}


@pytest.mark.parametrize(("route", "path", "body", "issue"), REFUSED, ids=lambda v: str(v))
def test_1083_a_member_gets_501_naming_the_issue_a_non_member_404_and_a_stranger_401(
    route: tuple[str, str], path: str, body: dict[str, Any] | None, issue: str,
) -> None:
    """Given refusing ports: sign-in, membership and permission run first; a member's call is a 501 problem. (O8, P1, FC-8)"""
    client = _refusing_client({})
    refused = client.request(route[0], path, headers=AUTH, json=body)
    assert refused.status_code == 501, refused.text
    assert refused.headers["Content-Type"] == "application/problem+json"
    problem = refused.json()
    assert (problem["title"], problem["status"]) == ("Not Implemented", 501)
    assert issue in problem["detail"]
    assert client.request(route[0], path, headers=AUTH_B, json=body).status_code == 404
    assert client.request(route[0], path, headers={"Origin": ORIGIN}, json=body).status_code == 401


def test_1083_control_the_same_deps_serve_the_backed_families() -> None:
    """With the families refused, alerts and the mapping still answer: the 501 is the families', not the app's. (O8)"""
    client = _refusing_client({"list_alerts": [SUMMARY], "get_alert_mapping": lambda _t: _alert_mapping_wire(MAPPING_BODY)})
    assert client.get(f"{T}/alerts", headers=AUTH).status_code == 200
    assert client.get(alert_mapping_url(A), headers=AUTH).json() == MAPPING_BODY


def test_1083_the_published_document_is_the_same_whichever_ports_are_passed_and_is_not_marked_stub() -> None:
    """A scripted and a refusing-ports document are one document; its summary does not say "not yet real". (O8, Am-2)"""
    refusing = _refusing_client({}).get(API + "/openapi.json").json()
    assert refusing["paths"]
    assert refusing == Api().client.get(API + "/openapi.json").json()
    assert "not yet real" not in json.dumps(refusing["info"]).lower()


# --- #1581: each listed alert's outcome and latest status, and the outcome filter -------------------------------------------

def _filtered_cursor_api() -> Api:
    return Api(list_alerts=_rows_after([SUMMARY_2, SUMMARY]))


def test_alert_list_o1_each_item_carries_outcome_and_latest_status_null_spelled_out() -> None:
    """Every listed alert has both keys, with the port's values and null when it has none. (O1, AP2)"""
    judged = SUMMARY_2.model_copy(update={"outcome": "malicious", "latest_status": "running"})
    api = Api(list_alerts=[judged, SUMMARY])
    items = api.client.get(f"{T}/alerts", headers=AUTH).json()["items"]
    assert [(i["outcome"], i["latest_status"]) for i in items] == [("malicious", "running"), (None, None)]
    assert all({"outcome", "latest_status"} <= set(i) for i in items), "a null is in the item, not left out"
    assert all("raw" not in i for i in items)


def test_alert_list_o1_the_single_read_carries_no_outcome() -> None:
    """`GET /alerts/{id}` answers the listed fields and `raw` only. (O1 non-obligation: the single read is unchanged)"""
    api = Api(get_alert=ALERT)
    body = api.client.get(f"{T}/alerts/{ALERT.alert_id}", headers=AUTH).json()
    assert "outcome" not in body
    assert "latest_status" not in body


def test_alert_list_o2_a_disposition_reaches_the_port_as_itself_and_no_filter_as_none() -> None:
    """Each of the five dispositions is handed to the port as that value, and an absent `outcome` as `None`. (O2)"""
    from defender._vocab import DISPOSITION_VALUES

    api = Api(list_alerts=[SUMMARY])
    for value in DISPOSITION_VALUES:
        assert api.client.get(f"{T}/alerts", headers=AUTH, params={"outcome": value}).status_code == 200, value
    assert api.client.get(f"{T}/alerts", headers=AUTH).status_code == 200
    handed = [kwargs["outcome"] for _, kwargs in api.ports.called("list_alerts")]
    assert handed == [*DISPOSITION_VALUES, None]


def test_alert_list_o2_none_reaches_the_port_as_the_no_outcome_marker_never_the_string() -> None:
    """`outcome=none` is handed to the port as the `NoOutcome` marker, not the string `none`, and not as no filter. (O2, AP4)"""
    from defender._vocab import NoOutcome

    api = Api(list_alerts=[SUMMARY])
    assert api.client.get(f"{T}/alerts", headers=AUTH, params={"outcome": "none"}).status_code == 200
    [(_, kwargs)] = api.ports.called("list_alerts")
    assert isinstance(kwargs["outcome"], NoOutcome)
    assert kwargs["outcome"] != "none"


@pytest.mark.parametrize("value", ["evil", "NONE", "None", "Benign", "benign,malicious", "unsanctioned-benign", " benign", "false_positive", ""])
def test_alert_list_o2_a_value_outside_the_six_is_a_422_about_outcome_and_no_port_call(value: str) -> None:
    """A value that is not exactly one of the five codes or `none` is refused as the `outcome` query value (not the
    undeclared-name refusal) before the store; control: `benign` is served. (O2)"""
    api = Api(list_alerts=[SUMMARY])
    response = api.client.get(f"{T}/alerts", headers=AUTH, params={"outcome": value})
    assert response.status_code == 422
    assert [(tuple(e["loc"]), e["type"] == "extra_forbidden") for e in response.json()["errors"]] == [(("query", "outcome"), False)]
    assert api.ports.calls == []
    assert api.client.get(f"{T}/alerts", headers=AUTH, params={"outcome": "benign"}).status_code == 200


def test_alert_list_o2_a_cursor_is_bound_to_the_outcome_filter() -> None:
    """A cursor minted under one outcome filter is refused under another, under `none` and under none at all, and a `none`
    cursor under a disposition; control: under its own it pages on. No refusal reaches the port. (O2)"""
    api = _filtered_cursor_api()
    under_benign = _cursor(api, f"{T}/alerts", {"outcome": "benign"})
    under_none = _cursor(api, f"{T}/alerts", {"outcome": "none"})
    served = len(api.ports.calls)
    assert api.client.get(f"{T}/alerts", headers=AUTH, params={"limit": 1, "outcome": "benign", "cursor": under_benign}).status_code == 200
    assert api.client.get(f"{T}/alerts", headers=AUTH, params={"limit": 1, "outcome": "none", "cursor": under_none}).status_code == 200
    served = len(api.ports.calls)
    for params in ({"outcome": "malicious", "cursor": under_benign}, {"outcome": "none", "cursor": under_benign},
                   {"cursor": under_benign}, {"outcome": "benign", "cursor": under_none}, {"cursor": under_none}):
        assert api.client.get(f"{T}/alerts", headers=AUTH, params=params).status_code == 422, params
        assert "the filters changed" in api.client.get(f"{T}/alerts", headers=AUTH, params=params).text, params
    assert len(api.ports.calls) == served


def test_alert_list_o2_a_cursor_minted_without_the_filter_is_refused_under_one() -> None:
    """The other way: an unfiltered cursor is refused under `outcome` as a changed filter, and pages on unfiltered. (O2)"""
    api = _filtered_cursor_api()
    plain = _cursor(api, f"{T}/alerts")
    served = len(api.ports.calls)
    assert api.client.get(f"{T}/alerts", headers=AUTH, params={"limit": 1, "cursor": plain}).status_code == 200, "control: under no filter it pages on"
    served = len(api.ports.calls)
    refused = api.client.get(f"{T}/alerts", headers=AUTH, params={"outcome": "benign", "cursor": plain})
    assert refused.status_code == 422
    assert "the filters changed" in refused.text
    assert len(api.ports.calls) == served


# --- #1581 O2: a cursor is bound to every filter of its route, whatever the route (generated from the published document) ------

#: Each paged route's path in the published document, with its port and the store's first two rows in the route's order. A
#: paged route that has a filter and is not here fails `test_..._every_filter...` below.
_PAGED_ROUTES: dict[str, tuple[str, Callable[[], list[Any]]]] = {
    API + "/tenants/{tenant_id}/alerts": ("list_alerts", lambda: [SUMMARY_2, SUMMARY]),
    API + "/tenants/{tenant_id}/investigations": ("list_investigations", lambda: [INV_2, INV]),
    API + "/tenants/{tenant_id}/learning-jobs": ("list_learning_jobs", lambda: [JOB_2, JOB]),
    API + "/tenants/{tenant_id}/learning/items": ("list_set_aside", _set_aside_rows),
}
_INSTANT = _dt.datetime(2026, 3, 4, 5, 6, 7, 123456, tzinfo=_dt.UTC)


def _filter_kinds(doc: dict[str, Any], operation: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Each query parameter of the operation other than `cursor` and `limit`, as its schema with `null` and refs resolved."""
    kinds: dict[str, dict[str, Any]] = {}
    for param in operation.get("parameters", []):
        if param["in"] != "query" or param["name"] in {"cursor", "limit"}:
            continue
        schema = param["schema"]
        [schema] = [m for m in schema.get("anyOf", [schema]) if m.get("type") != "null"]
        if "$ref" in schema:
            schema = doc["components"]["schemas"][schema["$ref"].rsplit("/", 1)[1]]
        kinds[param["name"]] = schema
    return kinds


def _spellings(name: str, schema: dict[str, Any], index: int) -> tuple[str, list[str]]:
    """A value for the `index`-th parameter of its kind, and its neighbours: the same filter changed by its smallest unit, or
    another member of its enum."""
    if "enum" in schema:
        members = list(schema["enum"])
        return members[index % len(members)], [m for m in members if m != members[index % len(members)]]
    if schema.get("format") == "date-time":
        at = _INSTANT + _dt.timedelta(hours=index)
        return at.isoformat(), [(at + _dt.timedelta(microseconds=1)).isoformat(), (at - _dt.timedelta(microseconds=1)).isoformat()]
    if "[0-9a-f]{8}" in schema.get("pattern", ""):
        return fixture_uuid(f"filter:{name}:{index}"), [fixture_uuid(f"filter:{name}:other")]
    if schema.get("type") == "integer":
        return str(index + 1), [str(index + 2)]
    return f"{name}-{index}", [f"{name}-other"]


def test_alert_list_o2_a_cursor_is_bound_to_every_filter_of_its_route_each_change_removal_swap_and_addition_is_422_before_the_port() -> None:  # noqa: C901 — every route, filter and way of changing it
    """For every paged route with filters, read from the published document: a cursor minted with all of them set pages on
    with the same ones, and is refused (422 "the filters changed", the port never asked) when any one is changed by its
    smallest unit or to any other enum member, removed, moved to another filter of its kind, swapped with one, or added to a
    cursor minted without it. (O2)"""
    doc = Api().client.get(API + "/openapi.json").json()
    routes = {path.replace("{tenant_id}", A): (path, _filter_kinds(doc, ops["get"])) for path, ops in doc["paths"].items()
              if "get" in ops and any(p["name"] == "cursor" for p in ops["get"].get("parameters", []))}
    with_filters = {template for template, kinds in routes.values() if kinds}
    assert with_filters == set(_PAGED_ROUTES), f"premise: a paged route with filters is scripted here: {sorted(with_filters ^ set(_PAGED_ROUTES))}"
    alerts = routes[f"{T}/alerts"][1]
    assert {"fired_after", "fired_before", "outcome"} <= set(alerts), f"premise: the alert list's filters are in the document: {sorted(alerts)}"
    for path, (template, kinds) in routes.items():
        if not kinds:
            continue
        port, rows = _PAGED_ROUTES[template]
        api = _learning_api(**{port: _rows_after(rows())})
        nth: dict[str, int] = {}
        minted: dict[str, str] = {}
        others: dict[str, list[str]] = {}
        for name, schema in kinds.items():
            key = json.dumps({k: v for k, v in schema.items() if k != "title"}, sort_keys=True)
            minted[name], others[name] = _spellings(name, schema, nth.get(key, 0))
            nth[key] = nth.get(key, 0) + 1
        kind_of = {name: json.dumps({k: v for k, v in schema.items() if k != "title"}, sort_keys=True) for name, schema in kinds.items()}

        def refused(minted_with: dict[str, str], sent: dict[str, str], why: str, path: str = path, api: Api = api) -> None:
            cursor = _cursor(api, path, minted_with)
            served = len(api.ports.calls)
            response = api.client.get(path, headers=AUTH, params={"limit": 1, "cursor": cursor, **sent})
            assert (response.status_code, "the filters changed" in response.text) == (422, True), f"{path}: {why}: {response.text}"
            assert len(api.ports.calls) == served, f"{path}: {why}: the port was asked"

        cursor = _cursor(api, path, minted)
        assert api.client.get(path, headers=AUTH, params={"limit": 1, "cursor": cursor, **minted}).status_code == 200, f"{path}: control"
        for name in kinds:
            for other in others[name]:
                refused(minted, {**minted, name: other}, f"{name} changed to {other}")
            refused(minted, {k: v for k, v in minted.items() if k != name}, f"{name} removed")
            refused({k: v for k, v in minted.items() if k != name}, minted, f"{name} added")
            refused({}, {name: minted[name]}, f"{name} added to an unfiltered cursor")
            for other in kinds:
                if other != name and kind_of[other] == kind_of[name]:
                    refused({name: minted[name]}, {other: minted[name]}, f"{name} moved to {other}")
                    refused(minted, {**minted, name: minted[other], other: minted[name]}, f"{name} and {other} swapped")
            if "enum" in kinds[name]:
                for was in kinds[name]["enum"]:
                    for now in kinds[name]["enum"]:
                        if was != now:
                            refused({name: was}, {name: now}, f"{name} {was} -> {now}")
