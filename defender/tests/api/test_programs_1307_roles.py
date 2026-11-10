"""#1307: fixed roles and program creation (O2 order, O3, O4, P-H, D8)."""
from __future__ import annotations

import pytest

pytest.importorskip("fastapi")

pytestmark = [
    pytest.mark.filterwarnings("error:coroutine .* was never awaited:RuntimeWarning"),
    pytest.mark.filterwarnings("error::pytest.PytestUnraisableExceptionWarning"),
]

from typing import Any  # noqa: E402

from fastapi import FastAPI  # noqa: E402

from defender.api.app import Authed, create_app, unauthenticated_routes, undeclared_routes  # noqa: E402  (forced choice FC-A1: see the contract map)
from defender.identity import DataRuleViolation  # noqa: E402
from defender.tests.support.api._identity1306 import (  # noqa: E402
    ALERT,
    NEW,
    T1,
    T2,
    UNKNOWN,
    AuditLog,
    items,
    masked,
    user_id,
)
from defender.tests.support.api._programs1307 import (  # noqa: E402
    create_program,
    issue_key,
    soar,
    start_investigation,
)
from defender.tests.support.api._routes1307a import (  # noqa: E402
    PATH_ID,
    PUBLIC,
    app_routes,
    concrete,
    normal,
    route_id,
    route_table_deps,
)
from defender.tests.support.tenancy._mapping1345 import PLANTED_ALERT_MAPPING  # noqa: E402

#: The design's permission table (O3), written out: route -> permission, permission -> roles.
TENANT = "/tenants/{}"
PERMISSION_OF = {
    ("GET", f"{TENANT}/alerts"): "work.read",
    ("GET", f"{TENANT}/alerts/{{}}"): "work.read",
    ("POST", f"{TENANT}/investigations"): "investigations.run",
    ("GET", f"{TENANT}/investigations"): "work.read",
    ("GET", f"{TENANT}/investigations/{{}}"): "work.read",
    ("POST", f"{TENANT}/investigations/{{}}/cancel"): "investigations.run",
    ("DELETE", f"{TENANT}/investigations/{{}}"): "investigations.delete",
    ("GET", f"{TENANT}/investigations/{{}}/artifacts/{{}}"): "work.read",
    ("POST", f"{TENANT}/learning-jobs"): "learning.run",
    ("GET", f"{TENANT}/learning-jobs"): "work.read",
    ("GET", f"{TENANT}/learning-jobs/{{}}"): "work.read",
    ("GET", f"{TENANT}/lessons"): "work.read",
    ("GET", f"{TENANT}/systems"): "config.read",
    ("PUT", f"{TENANT}/systems/{{}}"): "config.write",
    ("PUT", f"{TENANT}/systems/{{}}/credentials"): "config.write",
    ("POST", f"{TENANT}/systems/{{}}/check"): "config.write",
    ("GET", f"{TENANT}/alert-mapping"): "config.read",
    ("PUT", f"{TENANT}/alert-mapping"): "config.write",
    ("GET", f"{TENANT}/members"): "people.manage",
    ("DELETE", f"{TENANT}/members/{{}}"): "people.manage",
    ("GET", f"{TENANT}/invitations"): "people.manage",
    ("POST", f"{TENANT}/invitations"): "people.manage",
    ("DELETE", f"{TENANT}/invitations/{{}}"): "people.manage",
    ("POST", f"{TENANT}/programs"): "people.manage",
    ("GET", f"{TENANT}/programs"): "people.manage",
    ("DELETE", f"{TENANT}/programs/{{}}"): "people.manage",
    ("POST", f"{TENANT}/programs/{{}}/credentials"): "people.manage",
    ("GET", f"{TENANT}/programs/{{}}/credentials"): "people.manage",
    ("DELETE", f"{TENANT}/programs/{{}}/credentials/{{}}"): "people.manage",
}
AUTOMATION = {"work.read", "investigations.run"}  # admin holds every permission above
#: Routes outside /tenants/ and how each is classified (O2): public, person only, any caller, platform.
OUTSIDE = {
    ("GET", "/auth/login"), ("GET", "/auth/callback"),
    ("POST", "/auth/logout"), ("POST", "/invitations/{}/accept"),
    ("GET", "/me"),
    ("GET", "/admin/tenants"), ("POST", "/admin/tenants"), ("GET", "/admin/tenants/{}"),
    ("POST", "/admin/tenants/{}/resume"), ("POST", "/admin/tenants/{}/offboard"),
    ("POST", "/admin/tenants/{}/rotate-forge-credential"), ("POST", "/admin/tenants/{}/invitations"),
}
BODIES: dict[tuple[str, str], dict[str, object]] = {
    ("POST", f"{TENANT}/investigations"): {"alert_id": ALERT.alert_id, "client_request_id": "rq"},
    ("POST", f"{TENANT}/learning-jobs"): {"investigation_id": PATH_ID, "client_request_id": "jq"},
    ("PUT", f"{TENANT}/systems/{{}}"): {"kind": "ticketing", "display_name": "T", "enabled": True, "settings": {}},
    ("PUT", f"{TENANT}/systems/{{}}/credentials"): {"kind": "static", "credentials": {"api_token": "v" * 40}},
    ("PUT", f"{TENANT}/alert-mapping"): dict(PLANTED_ALERT_MAPPING),
    ("POST", f"{TENANT}/invitations"): {"email": NEW},
    ("POST", f"{TENANT}/programs"): {"display_name": "child"},
    ("POST", f"{TENANT}/programs/{{}}/credentials"): {"kind": "key", "name": "k"},
}
TENANT_ROUTES = sorted(PERMISSION_OF)


def _served_template(route: tuple[str, str]) -> str:
    """The app's own template for a table row: the table's `{}` placeholders carry no names, `concrete` fills named ones."""
    (template,) = [p for m, p in app_routes() if (m, normal(p)) == route]
    return template


def _call(client: Any, route: tuple[str, str]) -> Any:
    kwargs = {"json": BODIES[route]} if route in BODIES else {}
    return client.request(route[0], concrete(_served_template(route)), **kwargs)


# --- O3, P-H: the permission table over the whole class of routes ---------------------------------

def test_every_tenant_route_is_in_the_permission_table_and_every_other_route_is_classified() -> None:
    """No route of the app escapes the table or the outside-tenants categories (O3, O2, P-H)."""
    routes = {(m, normal(p)) for m, p in app_routes()}
    assert {r for r in routes if r[1].startswith(TENANT)} == set(PERMISSION_OF)
    assert {r for r in routes if not r[1].startswith(TENANT)} == OUTSIDE
    assert set(app_routes()) >= PUBLIC


@pytest.mark.parametrize("route", TENANT_ROUTES, ids=route_id)
def test_automation_holds_exactly_its_permissions_and_admin_holds_every_one(route: tuple[str, str]) -> None:
    """403 for a program iff the route's permission is outside automation's row; an admin never gets 403 (O3, D4, D8)."""
    s = soar()
    permission = PERMISSION_OF[route]
    granted = _call(s.program(), route)
    if permission in AUTOMATION:
        assert granted.status_code not in (401, 403), (permission, granted.text)
    else:
        assert granted.status_code == 403, (permission, granted.text)
    assert _call(s.ann, route).status_code not in (401, 403), permission


def test_automation_reads_work_and_runs_investigations() -> None:
    """automation: `work.read` and `investigations.run` end to end (O3)."""
    s = soar()
    program = s.program()
    assert [a["alert_id"] for a in items(program.get(f"/tenants/{T1}/alerts"))] == [ALERT.alert_id]
    started = start_investigation(program, T1)
    assert started.status_code == 201, started.text
    investigation_id = started.json()["investigation_id"]
    assert program.get(f"/tenants/{T1}/investigations/{investigation_id}").status_code == 200
    assert program.post(f"/tenants/{T1}/investigations/{investigation_id}/cancel").status_code == 200
    assert program.get(f"/tenants/{T1}/learning-jobs").status_code == 200


def test_a_program_cannot_start_a_learning_job_and_an_admin_can() -> None:
    """D8: `automation` is refused `learning.run`, and nothing is queued by the refused call (O3)."""
    s = soar()
    investigation_id = start_investigation(s.ann, T1).json()["investigation_id"]
    body = {"investigation_id": investigation_id, "client_request_id": "j1"}
    before = items(s.ann.get(f"/tenants/{T1}/learning-jobs"))
    assert s.program().post(f"/tenants/{T1}/learning-jobs", json=body).status_code == 403
    assert items(s.ann.get(f"/tenants/{T1}/learning-jobs")) == before
    assert s.ann.post(f"/tenants/{T1}/learning-jobs", json=body).status_code != 403


def test_a_program_is_refused_the_system_check_as_config_write() -> None:
    """The system check is `config.write` (O3): refused to automation with its settings read also refused."""
    s = soar()
    assert s.program().post(f"/tenants/{T1}/systems/tix/check").status_code == 403
    assert s.program().get(f"/tenants/{T1}/systems").status_code == 403
    assert s.ann.post(f"/tenants/{T1}/systems/tix/check").status_code not in (401, 403)


# --- O2: the order under /tenants/{T}/ (D1) ---------------------------------------------------------

def test_membership_is_checked_before_permission() -> None:
    """A program outside the tenant is told what an unknown tenant is told (404), not 403, on a route it lacks (O2, D1)."""
    s = soar()
    program = s.program()
    path = "/invitations"
    unknown = program.post(f"/tenants/{UNKNOWN}{path}", json={"email": NEW})
    foreign = program.post(f"/tenants/{T2}{path}", json={"email": NEW})
    assert foreign.status_code == unknown.status_code == 404
    assert masked(foreign, T2) == masked(unknown, UNKNOWN)
    assert program.post(f"/tenants/{T1}{path}", json={"email": NEW}).status_code == 403  # control: a member
    assert s.ann.post(f"/tenants/{T1}{path}", json={"email": NEW}).status_code == 202  # control: permitted


def test_permission_is_checked_before_the_ids_in_the_path() -> None:
    """A member without the permission is 403 even for an id that names nothing; an admin gets 404 for it (O2, D1)."""
    s = soar()
    ghost = f"/tenants/{T1}/investigations/{PATH_ID}"
    assert s.program().delete(ghost).status_code == 403
    assert s.ann.delete(ghost).status_code == 404
    assert s.program().get(ghost).status_code == 404  # permitted read: then the id is looked up


def test_a_program_or_credential_id_of_another_tenant_is_404_under_the_path_tenant() -> None:
    """Ids below T must belong to T: another tenant's program, another program's credential -> 404 (O2, A3)."""
    s = soar()
    theirs = str(create_program(s.bob, T2, "B's SOAR")["id"])
    their_key, _ = issue_key(s.bob, T2, theirs)
    assert s.ann.post(f"/tenants/{T1}/programs/{theirs}/credentials",
                      json={"kind": "key", "name": "x"}).status_code == 404
    assert s.ann.get(f"/tenants/{T1}/programs/{theirs}/credentials").status_code == 404
    assert s.ann.delete(f"/tenants/{T1}/programs/{theirs}").status_code == 404
    second = str(create_program(s.ann, T1, "second")["id"])
    assert s.ann.delete(f"/tenants/{T1}/programs/{second}/credentials/{s.key_id}").status_code == 404
    assert s.ann.delete(f"/tenants/{T1}/programs/{theirs}/credentials/{their_key}").status_code == 404
    assert s.world.bearer(s.key).get(f"/tenants/{T1}/alerts").status_code == 200
    mine = s.ann.get(f"/tenants/{T1}/programs/{s.program_id}/credentials")
    assert [r["id"] for r in items(mine)] == [s.key_id]  # control: its own listing works


def test_a_persons_id_is_not_a_program_id() -> None:
    """Program routes answer 404 for a person's user id and leave the person untouched (D8, P-F, P-I)."""
    s = soar()
    carl = s.world.member(s.ann, T1, "carl@a.example")
    carl_id = user_id(carl)
    assert s.ann.post(f"/tenants/{T1}/programs/{carl_id}/credentials", json={"kind": "key", "name": "k"}).status_code == 404
    assert s.ann.get(f"/tenants/{T1}/programs/{carl_id}/credentials").status_code == 404
    assert s.ann.delete(f"/tenants/{T1}/programs/{carl_id}").status_code == 404
    assert carl.get(f"/tenants/{T1}/alerts").status_code == 200
    assert carl_id not in [p["id"] for p in items(s.ann.get(f"/tenants/{T1}/programs"))]
    assert s.ann.get(f"/tenants/{T1}/programs/{s.program_id}/credentials").status_code == 200  # control


# --- P-H, D10: an undeclared route is found by the checker -----------------------------------------

def _plain(path: str, *methods: str) -> FastAPI:
    app = FastAPI()

    async def handler() -> dict[str, str]:
        return {}

    app.add_api_route(path, handler, methods=list(methods))
    return app


def test_the_real_app_has_no_undeclared_route() -> None:
    """Every route the app serves declares a permission or a category (P-H, D10)."""
    s = soar()
    assert undeclared_routes(s.world.app) == []


def test_the_checker_reports_a_route_that_declares_nothing_inside_or_outside_tenants() -> None:
    """A plain route is reported by method and path; built-in docs routes and the real app's are not (P-H, D10)."""
    assert undeclared_routes(FastAPI()) == []  # control: openapi/docs routes are not routes of ours
    assert undeclared_routes(_plain("/tenants/{tenant_id}/widgets", "GET")) == [("GET", "/tenants/{tenant_id}/widgets")]
    assert undeclared_routes(_plain("/elsewhere", "POST", "DELETE")) == [("DELETE", "/elsewhere"), ("POST", "/elsewhere")]
    real = soar().world.app
    real.add_api_route("/tenants/{tenant_id}/widgets", lambda: {}, methods=["GET"])
    assert undeclared_routes(real) == [("GET", "/tenants/{tenant_id}/widgets")]


def test_a_route_that_asks_for_its_caller_outside_the_authenticating_routers_is_reported() -> None:
    """Only the module's routers authenticate before the body is read and hand the caller on (A7): a route asking for
    the caller anywhere else would answer every request with a 500, so `create_app` refuses it (#1450 review)."""
    real = soar().world.app
    assert unauthenticated_routes(real) == []  # control: every route of the real app is made by `_router`

    async def asks(caller: Authed) -> dict[str, str]:
        return {}

    async def public() -> dict[str, str]:
        return {}

    real.add_api_route("/tenants/{tenant_id}/widgets", asks, methods=["GET"])
    real.add_api_route("/open", public, methods=["GET"])  # control: a route not asking for the caller is fine anywhere
    assert unauthenticated_routes(real) == [("GET", "/tenants/{tenant_id}/widgets")]


def test_the_app_does_not_start_when_one_of_its_routers_holds_a_route_that_declares_nothing() -> None:
    """P-H, D10: "a route that declares neither fails app start" is `create_app`'s own check. The seam is the one the app is built
    from: a route added to one of its routers before `create_app` runs (the route is taken off again afterwards, so the control and
    every other test build the real app). The failure names the route; the same call without the extra route builds."""
    from fastapi import APIRouter

    from defender.api import app as app_module

    routers = [v for v in vars(app_module).values() if isinstance(v, APIRouter) and v.routes]  # every one `create_app` includes
    assert len(routers) >= 2  # control: the module's routers were found by what they are, not by a name
    assert undeclared_routes(create_app(route_table_deps())) == []  # control: the real routers build
    for router in routers:
        before = list(router.routes)
        router.add_api_route("/undeclared-1307", lambda: {}, methods=["GET"])
        try:
            with pytest.raises(Exception, match="undeclared-1307"):
                create_app(route_table_deps())
        finally:
            router.routes[:] = before
    assert undeclared_routes(create_app(route_table_deps())) == []


def test_an_admin_creates_a_program_that_is_an_active_automation_member_with_no_email(caplog) -> None:
    """Program creation: active at once, one automation membership in the tenant, creator recorded, audited (O4, O8)."""
    audit = AuditLog(caplog)
    s = soar()
    mark = audit.mark()
    created = create_program(s.ann, T1, "Ticket sync")
    program_id = str(created["id"])
    assert created["display_name"] == "Ticket sync"
    listed = {p["id"]: p for p in items(s.ann.get(f"/tenants/{T1}/programs"))}
    assert set(listed) == {s.program_id, program_id}
    assert listed[program_id]["created_by"] == s.ann.get("/me").json()["user"]["id"]
    user = s.world.call(s.world.raw_repo.user, program_id)
    assert (user.kind, user.email, user.status, user.signin_account_id) == ("program", None, "active", None)
    [membership] = s.world.call(s.world.raw_repo.memberships_of_user, program_id)
    assert (str(membership.tenant_id), membership.status, membership.role) == (T1, "active", "automation")
    assert [(e.action, e.target) for e in audit.since(mark)] == [("program.create", program_id)]


def test_a_program_cannot_be_given_a_second_membership() -> None:
    """A program belongs to exactly one tenant; no invitation can address it (O4, D5)."""
    s = soar()
    before = s.world.call(s.world.raw_repo.memberships_of_user, s.program_id)
    with pytest.raises(DataRuleViolation):
        s.world.call(s.world.raw_repo.ensure_invitation, s.program_id, T2, invited_by=None,
                     now=s.world.clock())
    assert s.world.call(s.world.raw_repo.memberships_of_user, s.program_id) == before
