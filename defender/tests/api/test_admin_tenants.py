"""#1214 r9: the administrator tenant endpoints and the identity seam over the API (O2, O10, RC-3, DC-6).

Plain cases run on #1306's world over the in-memory tenant twin; the cases that need a failed or running
job use the lifecycle world (imported where used, so a missing `defender.lifecycle` reds only those)."""
from __future__ import annotations

import datetime as _dt
import threading
import uuid
from http import HTTPStatus
from typing import Any

import pytest

pytest.importorskip("fastapi")

pytestmark = [
    pytest.mark.filterwarnings("error:coroutine .* was never awaited:RuntimeWarning"),
    pytest.mark.filterwarnings("error::pytest.PytestUnraisableExceptionWarning"),
]

from defender.tenancy import InMemoryTenantRepository  # noqa: E402
from defender.tests.support.api._identity1306 import (  # noqa: E402
    ANN,
    BOB,
    EMPTY,
    LAB,
    ME,
    NEW,
    NINA,
    OPS,
    SESSION_COOKIE,
    T1,
    T2,
    UNKNOWN,
    AuditLog,
    InjectedFailure,
    World,
    items,
    lab,
    tenants_of,
    user_id,
)

CREATE, RESUME, OFFBOARD, ROTATE = "tenant.create", "tenant.resume", "tenant.offboard", "tenant.rotate"
ITEM_KEYS = {"tenant_id", "state", "pending_action", "step", "step_actor", "failure", "created_at"}
MALFORMED = "not-a-tenant-id"
WAIT = 10.0
STATES = ["creating", "offboarding", "offboarded"]  # every state that is not `active`
#: The states an invitation can be found in: it was written while the tenant was `active` (P-L), then the tenant moved.
SEEDED_STATES = ["offboarding", "offboarded"]


@pytest.fixture
def audit(caplog: Any) -> AuditLog:
    return AuditLog(caplog)


def _is_uuid4(text: str) -> bool:
    try:
        return uuid.UUID(text).version == 4 and str(uuid.UUID(text)) == text
    except ValueError:
        return False


def _admin_world(**kwargs: Any) -> tuple[World, Any]:
    world = World(administrators=[OPS], **kwargs)
    return world, world.sign_in_admin()


def _item(ops: Any, tenant: str) -> dict[str, Any]:
    got = ops.get(f"/admin/tenants/{tenant}")
    assert got.status_code == 200, got.text
    body: dict[str, Any] = got.json()
    return body


def _events(audit: AuditLog, mark: int) -> list[tuple[str, str, str | None]]:
    return [(e.action, e.actor, e.target) for e in audit.since(mark) if e.action.startswith("tenant.")]


def _problem(response: Any, code: int) -> None:
    assert response.status_code == code, response.text
    assert response.headers["content-type"] == "application/problem+json"
    problem = response.json()
    assert (problem["status"], problem["title"]) == (code, HTTPStatus(code).phrase)


# --- create, read ----------------------------------------------------------------------------------

@pytest.mark.parametrize("body", [None, {}])
def test_create_answers_202_with_the_item_and_a_location_and_makes_no_membership(
        body: Any, audit: AuditLog) -> None:
    """No body: 202, the item of a `creating` tenant (job at `names`, service), Location, no membership (O1, O2, RC-3)."""
    world, ops = _admin_world()
    mark = audit.mark()
    made = ops.post("/admin/tenants", json=body) if body is not None else ops.post("/admin/tenants")
    assert made.status_code == 202, made.text
    item = made.json()
    assert set(item) == ITEM_KEYS
    assert _is_uuid4(item["tenant_id"])
    assert (item["state"], item["pending_action"], item["step"], item["step_actor"], item["failure"]) == (
        "creating", "create", "names", "service", None)
    assert _dt.datetime.fromisoformat(item["created_at"]) == world.clock.now
    assert made.headers["location"] == f"/admin/tenants/{item['tenant_id']}"
    assert _item(ops, item["tenant_id"]) == item
    assert world.call(world.raw_repo.memberships_of_tenant, item["tenant_id"]) == []
    assert _events(audit, mark) == [(CREATE, user_id(ops), item["tenant_id"])]
    other = ops.post("/admin/tenants").json()["tenant_id"]  # control: every request mints a new one
    assert other != item["tenant_id"]


def test_the_list_and_the_get_show_the_job_of_every_tenant() -> None:
    """Items carry the seven fields; a seeded active tenant shows no pending job; list and get agree (O2, DC-6)."""
    world = lab()
    ops = world.sign_in_admin()
    created = ops.post("/admin/tenants").json()
    listed = items(ops.get("/admin/tenants"))
    assert sorted(i["tenant_id"] for i in listed) == sorted([LAB, created["tenant_id"]])
    assert all(set(i) == ITEM_KEYS for i in listed)
    by_id = {i["tenant_id"]: i for i in listed}
    assert by_id[created["tenant_id"]] == created
    lab_item = by_id[LAB]
    assert (lab_item["state"], lab_item["pending_action"], lab_item["step"], lab_item["step_actor"],
            lab_item["failure"]) == ("active", None, None, None, None)
    assert _dt.datetime.fromisoformat(lab_item["created_at"]) == world.clock.now
    assert _item(ops, LAB) == lab_item


@pytest.mark.parametrize(("tenant", "code"), [(UNKNOWN, 404), (MALFORMED, 422)])
def test_an_unknown_or_malformed_tenant_is_refused_on_every_tenant_route(tenant: str, code: int, audit: AuditLog) -> None:
    """Get, resume, offboard and rotate answer 404 for a tenant that is not there, 422 for a malformed id (#1382);
    nothing is audited (O2, RC-3)."""
    world, ops = _admin_world()
    world.register(EMPTY)
    mark = audit.mark()
    for method, path in (("GET", ""), ("POST", "/resume"), ("POST", "/offboard"), ("POST", "/rotate-forge-credential")):
        _problem(ops.request(method, f"/admin/tenants/{tenant}{path}"), code)
    assert _events(audit, mark) == []
    assert ops.post(f"/admin/tenants/{EMPTY}/offboard").status_code == 202  # control: a real tenant


# --- the transition table ---------------------------------------------------------------------------

def _in(world: World, ops: Any, state: str) -> str:
    """A tenant in `state`, reached only through the API and the seeder."""
    if state == "creating":
        return str(ops.post("/admin/tenants").json()["tenant_id"])
    tenant = str(uuid.uuid4())
    world.register(tenant)
    if state == "rotating":
        assert ops.post(f"/admin/tenants/{tenant}/rotate-forge-credential").status_code == 202
    if state == "offboarding":
        assert ops.post(f"/admin/tenants/{tenant}/offboard").status_code == 202
    return tenant


#: (state of the tenant, route) -> status. 409: resume with no failure; offboard unless creating|active; rotate
#: unless active with nothing pending (r9 Endpoints).
TABLE = [
    ("creating", "resume", 409), ("creating", "offboard", 202), ("creating", "rotate-forge-credential", 409),
    ("active", "resume", 409), ("active", "offboard", 202), ("active", "rotate-forge-credential", 202),
    ("rotating", "resume", 409), ("rotating", "offboard", 202), ("rotating", "rotate-forge-credential", 409),
    ("offboarding", "resume", 409), ("offboarding", "offboard", 409), ("offboarding", "rotate-forge-credential", 409),
]
AFTER = {  # the item an accepted request leaves (RC-3, DC-4): offboard sets the first offboard step
    "offboard": ("offboarding", "offboard", "offboard", "service", None),
    "rotate-forge-credential": ("active", "rotate", "names", "service", None),
}
AUDITED = {"resume": RESUME, "offboard": OFFBOARD, "rotate-forge-credential": ROTATE}


@pytest.mark.parametrize(("state", "route", "code"), TABLE)
def test_a_request_is_accepted_or_refused_by_the_tenants_state(
        state: str, route: str, code: int, audit: AuditLog) -> None:
    """202 with the new item and one audit event, or 409 with the row untouched and no event (r9 Endpoints, RC-3, O10)."""
    world, ops = _admin_world()
    tenant = _in(world, ops, state)
    before = _item(ops, tenant)
    mark = audit.mark()
    asked = ops.post(f"/admin/tenants/{tenant}/{route}")
    if code == 409:
        _problem(asked, 409)
        assert _item(ops, tenant) == before
        assert _events(audit, mark) == []
        return
    assert asked.status_code == 202, asked.text
    item = asked.json()
    assert (item["state"], item["pending_action"], item["step"], item["step_actor"], item["failure"]) == AFTER[route]
    assert item["tenant_id"] == tenant
    assert item["created_at"] == before["created_at"]
    assert _item(ops, tenant) == item
    assert _events(audit, mark) == [(AUDITED[route], user_id(ops), tenant)]


# --- refusals ---------------------------------------------------------------------------------------

ROUTES = [
    ("create", "POST", "/admin/tenants", 202), ("list", "GET", "/admin/tenants", 200),
    ("get", "GET", "/admin/tenants/{T}", 200), ("resume", "POST", "/admin/tenants/{T}/resume", 409),
    ("offboard", "POST", "/admin/tenants/{T}/offboard", 202),
    ("rotate", "POST", "/admin/tenants/{T}/rotate-forge-credential", 202),
]


@pytest.mark.parametrize(("name", "method", "path", "ok"), ROUTES)
def test_only_a_code_backed_administrator_session_reaches_the_tenant_routes(
        name: str, method: str, path: str, ok: int, audit: AuditLog) -> None:
    """A member, nobody, a flagged user without a code and a foreign origin are refused alike and change nothing; the administrator is not (O2, #1306 O5/K10)."""
    world = lab()
    ops = world.sign_in_admin()
    member = world.sign_in(ME)
    assert member.delete(f"/tenants/{LAB}/members/{user_id(member)}").status_code == 204
    world.restart(administrators=[OPS, ME])  # `member` is flagged now, but its session used no code
    foreign = world.client_with_cookie(ops.cookies[SESSION_COOKIE], origin="https://evil.example")
    mark = audit.mark()
    before = items(ops.get("/admin/tenants"))
    refusals = {"member without a code": (member, 403), "anonymous": (world.client(), 401)}
    if method == "POST":
        refusals["foreign origin"] = (foreign, 403)
    for tenant in (LAB, UNKNOWN, MALFORMED):  # the same answer whatever the tenant (no probing)
        for who, (browser, code) in refusals.items():
            response = browser.request(method, path.replace("{T}", tenant))
            assert response.status_code == code, f"{who}: {response.status_code} {response.text}"
    assert items(ops.get("/admin/tenants")) == before
    assert _events(audit, mark) == []
    answered = ops.request(method, path.replace("{T}", LAB))  # control: the administrator is not refused
    assert answered.status_code == ok, answered.text


# --- an event only after the commit ----------------------------------------------------------------

class FailingTenants(InMemoryTenantRepository):
    """The in-memory tenant twin whose named request raises instead of writing (injected input)."""

    failing: set[str]

    def __init__(self) -> None:
        super().__init__()
        self.failing = set()

    async def request_create(self, *args: Any, **kwargs: Any) -> Any:
        if "request_create" in self.failing:
            raise InjectedFailure("request_create failed")
        return await super().request_create(*args, **kwargs)

    async def request_offboard(self, *args: Any, **kwargs: Any) -> Any:
        if "request_offboard" in self.failing:
            raise InjectedFailure("request_offboard failed")
        return await super().request_offboard(*args, **kwargs)

    async def request_rotate(self, *args: Any, **kwargs: Any) -> Any:
        if "request_rotate" in self.failing:
            raise InjectedFailure("request_rotate failed")
        return await super().request_rotate(*args, **kwargs)


@pytest.mark.parametrize(("write", "path", "action"), [
    ("request_create", "/admin/tenants", CREATE),
    ("request_offboard", "/admin/tenants/{T}/offboard", OFFBOARD),
    ("request_rotate", "/admin/tenants/{T}/rotate-forge-credential", ROTATE),
])
def test_a_request_whose_write_fails_logs_nothing_and_the_retry_logs_one(
        write: str, path: str, action: str, audit: AuditLog) -> None:
    """The event follows the commit (K11, O10): a failed write leaves no row change and no event; the same request then logs."""
    tenants = FailingTenants()
    world = World(administrators=[OPS], tenant_repo=tenants)
    world.register(LAB)
    ops = world.sign_in_admin()
    failing_browser = world.client_with_cookie(ops.cookies[SESSION_COOKIE], raise_errors=False)
    before = items(ops.get("/admin/tenants"))
    tenants.failing.add(write)
    mark = audit.mark()
    assert failing_browser.post(path.replace("{T}", LAB)).status_code >= 500
    assert items(ops.get("/admin/tenants")) == before
    assert _events(audit, mark) == []
    tenants.failing.clear()  # control: the same request, written, is logged
    assert failing_browser.post(path.replace("{T}", LAB)).status_code == 202
    assert [e[0] for e in _events(audit, mark)] == [action]


# --- #1360: the offboard request ends the tenant's jobs through the offboarding port (D6, O3) ----------------

#: (kind, status, failure_reason / reason) of the jobs each tenant is seeded with; the first four are live.
INVESTIGATIONS = [("queued", None), ("running", None), ("completed", None), ("failed", "worker_error"),
                  ("aborted", "cancelled"), ("unparseable", None)]
LEARNING_JOBS = [("queued", None), ("running", None), ("completed", None), ("failed", "worker_error"),
                 ("skipped", "expired")]
LIVE = {"queued", "running"}


def _uid(kind: str, tenant_n: int, i: int) -> str:
    return f"{kind}{tenant_n:07d}-0000-4000-8000-{i:012d}"


def _seed_jobs(world: World, tenant: str, n: int) -> dict[str, Any]:
    """`tenant` with one job of each status, each ended one with its own `finished_at`; returns the stored rows by name."""
    from defender.api.models import Investigation, LearningJob

    at = world.clock()
    ended_at = at - _dt.timedelta(days=1)
    rows: dict[str, Any] = {}
    for i, (status, reason) in enumerate(INVESTIGATIONS):
        rows[f"inv-{status}"] = world.store.add_investigation(tenant, Investigation(
            investigation_id=_uid("b", n, i), alert_id=_uid("a", n, i), status=status, created_at=at, cost_usd=0.0,
            cost_is_lower_limit=False, request_key=f"k{i}", attempt=1, failure_reason=reason,
            finished_at=None if status in LIVE else ended_at))
    for i, (status, reason) in enumerate(LEARNING_JOBS):
        rows[f"job-{status}"] = world.store.add_learning_job(tenant, LearningJob(
            learning_job_id=_uid("c", n, i), investigation_id=_uid("b", n, 2), alert_id=_uid("a", n, 2), status=status,
            trigger="explicit", created_at=at, reason=reason, finished_at=None if status in LIVE else ended_at))
    return rows


def _stored(world: World, tenant: str, seeded: dict[str, Any]) -> dict[str, Any]:
    """Every seeded row as the store holds it now."""
    return {name: world.call(world.store.get_investigation if name.startswith("inv") else world.store.get_learning_job,
                             tenant, row.investigation_id if name.startswith("inv") else row.learning_job_id)
            for name, row in seeded.items()}


@pytest.mark.parametrize("state", ["active", "creating"])
def test_1360_d6_the_offboard_request_ends_the_tenants_live_jobs_before_it_answers(state: str) -> None:
    """202 and, by then, every queued/running job of the tenant ended with `tenant_offboarded`; ended jobs and other tenants' jobs untouched; a second request (409) re-ends nothing. (#1360 D6, O3)"""
    world, ops = _admin_world()
    world.register(T1, state=state)
    world.register(T2)
    mine, theirs = _seed_jobs(world, T1, 1), _seed_jobs(world, T2, 2)
    world.clock.advance(_dt.timedelta(hours=1))
    now = world.clock()

    assert ops.post(f"/admin/tenants/{T1}/offboard").status_code == 202
    ended = _stored(world, T1, mine)
    for name, row in ended.items():
        if name.split("-")[1] in LIVE:
            assert row.status == ("aborted" if name.startswith("inv") else "skipped"), name
            assert (row.failure_reason if name.startswith("inv") else row.reason) == "tenant_offboarded", name
            assert row.finished_at == now, name
            assert "offboard" in ((row.failure_message if name.startswith("inv") else row.message) or "").lower(), name
        else:
            assert row == mine[name], f"{name}: a job that was not live was changed"
    assert _stored(world, T2, theirs) == theirs, "another tenant's jobs were touched"

    world.clock.advance(_dt.timedelta(hours=1))
    assert ops.post(f"/admin/tenants/{T1}/offboard").status_code == 409
    assert _stored(world, T1, mine) == ended, "an ended job was ended again"


@pytest.mark.parametrize(("tenant_state", "code"), [("offboarding", 409), ("offboarded", 409), (None, 404)])
def test_1360_d6_a_refused_offboard_request_ends_no_job(tenant_state: str | None, code: int) -> None:
    """409 for a tenant already offboarding/offboarded and 404 for an unknown one leave every job as it was; the same flow on an active tenant ends them. (#1360 D6, O3)"""
    world, ops = _admin_world()
    world.register(T2)
    if tenant_state is not None:
        world.register(T1, state=tenant_state)
    refused, control = _seed_jobs(world, T1, 1), _seed_jobs(world, T2, 2)

    assert ops.post(f"/admin/tenants/{T1}/offboard").status_code == code
    assert _stored(world, T1, refused) == refused, "a refused request ended a job"
    assert ops.post(f"/admin/tenants/{T2}/offboard").status_code == 202
    assert _stored(world, T2, control)["inv-queued"].status == "aborted", "control: an accepted request ends them"


def test_1360_d6_the_route_reaches_the_tenant_and_its_jobs_only_through_the_offboarding_port(audit: AuditLog) -> None:
    """One port call with the tenant and the administrator; a port that fails leaves tenant and jobs as they were and logs nothing, the retry does all three. (#1360 D6)"""
    world, ops = _admin_world()
    world.register(T1)
    seeded = _seed_jobs(world, T1, 1)
    failing_ops = world.client_with_cookie(ops.cookies[SESSION_COOKIE], raise_errors=False)
    before = items(ops.get("/admin/tenants"))
    world.offboarding.failing = True
    mark = audit.mark()

    assert failing_ops.post(f"/admin/tenants/{T1}/offboard").status_code >= 500
    assert world.offboarding.calls == [(T1, user_id(ops))]
    assert items(ops.get("/admin/tenants")) == before, "the tenant moved though the port failed"
    assert _stored(world, T1, seeded) == seeded
    assert _events(audit, mark) == []

    world.offboarding.failing = False
    assert failing_ops.post(f"/admin/tenants/{T1}/offboard").status_code == 202
    assert world.offboarding.calls == [(T1, user_id(ops))] * 2
    assert _item(ops, T1)["state"] == "offboarding"
    assert _stored(world, T1, seeded)["inv-queued"].status == "aborted"
    assert [e[0] for e in _events(audit, mark)] == [OFFBOARD]


def test_1360_d6_a_malformed_tenant_id_never_reaches_the_offboarding_port() -> None:
    """422 before the port is called; a real tenant's request calls it once. (#1360 D6)"""
    world, ops = _admin_world()
    world.register(T1)
    assert ops.post(f"/admin/tenants/{MALFORMED}/offboard").status_code == 422
    assert world.offboarding.calls == []
    assert ops.post(f"/admin/tenants/{T1}/offboard").status_code == 202
    assert [t for t, _ in world.offboarding.calls] == [T1]


def test_1360_d6_the_dev_composition_ends_the_offboarded_demo_tenants_live_jobs_and_no_other_demo_tenants() -> None:
    """Through `demo_deps` (the development composition), `create_app` and the admin route: offboarding one demo tenant
    moves it and ends its live demo jobs; the other demo tenant, active, keeps its live job. (#1360 D6, O3)

    `demo_deps` seeds members only (`Bootstrap(administrators=())`), so no existing machinery signs in an administrator:
    the test seeds one flagged user with a one-time-code session through the identity repository the demo composed
    (the service's `_repo`), exactly the rows a real administrator's sign-in leaves."""
    import anyio
    from fastapi.testclient import TestClient

    from defender.api.app import create_app
    from defender.api.demo import demo_deps, demo_id
    from defender.api.models import Investigation, LearningJob
    from defender.records.formats import AlertId, InvestigationId, LearningJobId
    from defender.tests.support.shared._fixture_uuid import fixture_uuid

    one, two = fixture_uuid("tenant:1360-demo-one"), fixture_uuid("tenant:1360-demo-two")
    now = _dt.datetime(2026, 9, 28, 12, 0, tzinfo=_dt.UTC)
    deps = anyio.run(demo_deps, (one, two), lambda: now)
    store = deps.writes

    async def seed_admin() -> None:
        repo = deps.identity._repo  # type: ignore[attr-defined]
        user = await repo.add_user("ops@demo.example", created_at=now, status="active", display_name="ops",
                                   is_platform_admin=True)
        await repo.add_session("demo-admin-session", user.id, now=now, expires_at=now + _dt.timedelta(days=7), used_otp=True)
    anyio.run(seed_admin)

    def live_pair(tenant: str, name: str) -> tuple[Any, Any]:
        inv = store.add_investigation(tenant, Investigation(
            investigation_id=demo_id(InvestigationId, tenant, f"inv-{name}"), alert_id=demo_id(AlertId, tenant, "alert-0001"),
            status="queued", request_key=f"k-{name}", attempt=1, cost_usd=0.0, cost_is_lower_limit=False, created_at=now))
        job = store.add_learning_job(tenant, LearningJob(
            learning_job_id=demo_id(LearningJobId, tenant, f"lj-{name}"), investigation_id=inv.investigation_id,
            alert_id=inv.alert_id, status="queued", trigger="explicit", created_at=now))
        return inv, job

    live_pair(one, "queued")
    theirs = live_pair(two, "queued")
    seeded_running = demo_id(InvestigationId, one, "inv-running")  # the demo's own live job of the first tenant
    seeded_done = demo_id(InvestigationId, one, "inv-completed")

    def stored(tenant: str) -> dict[str, Any]:
        inv = anyio.run(store.get_investigation, tenant, demo_id(InvestigationId, tenant, "inv-queued"))
        job = anyio.run(store.get_learning_job, tenant, demo_id(LearningJobId, tenant, "lj-queued"))
        return {"inv": inv, "job": job}

    client = TestClient(create_app(deps), base_url="https://testserver")
    client.cookies.set("__Host-defender_session", "demo-admin-session")
    headers = {"Origin": deps.frontend_origin}
    assert client.get("/me", headers=headers).json()["administrator"] is True, "premise: the seeded session is an administrator's"
    done_before = anyio.run(store.get_investigation, one, seeded_done)
    assert anyio.run(store.get_investigation, one, seeded_running).status == "running", "premise: the demo seeds a live job"

    response = client.post(f"/admin/tenants/{one}/offboard", headers=headers)
    assert response.status_code == 202, response.text

    assert client.get(f"/admin/tenants/{one}").json()["state"] == "offboarding"
    assert client.get(f"/admin/tenants/{two}").json()["state"] == "active"
    gone = anyio.run(store.get_investigation, one, seeded_running)
    assert (gone.status, gone.failure_reason, gone.finished_at) == ("aborted", "tenant_offboarded", now)
    ended = stored(one)
    assert (ended["inv"].status, ended["inv"].failure_reason) == ("aborted", "tenant_offboarded")
    assert (ended["job"].status, ended["job"].reason) == ("skipped", "tenant_offboarded")
    assert anyio.run(store.get_investigation, one, seeded_done) == done_before, "a completed demo investigation was changed"
    assert stored(two) == {"inv": theirs[0], "job": theirs[1]}, "the other demo tenant's live jobs were touched"


# --- the lifecycle world: failures and running steps ------------------------------------------------

@pytest.fixture
def jobs(tmp_path: Any, data_root: Any) -> Any:
    from defender.tests.tenancy.lifecycle_1214._support import LifecycleWorld

    world = LifecycleWorld(tmp_path, data_root)
    yield world
    world.close()


REPOS = "/api/v1/orgs/tenants/repos"


def _failed_create(jobs: Any) -> str:
    jobs.forge.fail_next[("POST", REPOS)] = 500
    tenant = jobs.create()
    jobs.drive()
    return str(tenant)


def test_a_failed_job_shows_its_step_and_the_external_answer_and_resume_clears_it(jobs: Any, audit: AuditLog) -> None:
    """The item carries the restart point and the failure naming the step and the answer, never a secret; resume answers 202 with the failure cleared (O2, O3, O10)."""
    tenant = _failed_create(jobs)
    item = jobs.item(tenant)
    assert (item["state"], item["pending_action"], item["step_actor"]) == ("creating", "create", "service")
    assert item["step"] == "repo"
    assert isinstance(item["failure"], str)
    assert "repo" in item["failure"]
    assert "injected 500" in item["failure"]
    assert jobs.config.forge_admin_token not in item["failure"]
    mark = audit.mark()
    resumed = jobs.ops.post(f"/admin/tenants/{tenant}/resume")
    assert resumed.status_code == 202, resumed.text
    assert (resumed.json()["failure"], resumed.json()["step"], resumed.json()["state"]) == (None, "repo", "creating")
    assert _events(audit, mark) == [(RESUME, user_id(jobs.ops), tenant)]
    again = jobs.ops.post(f"/admin/tenants/{tenant}/resume")  # control: nothing is left to resume
    _problem(again, 409)


def test_rotate_is_refused_for_a_failed_create_and_offboard_replaces_the_failed_job(jobs: Any) -> None:
    """A failed create is `creating`: rotate 409; offboard 202 clears the failure and sets the first offboard step (r9 Endpoints, DC-4)."""
    tenant = _failed_create(jobs)
    before = jobs.item(tenant)
    _problem(jobs.ops.post(f"/admin/tenants/{tenant}/rotate-forge-credential"), 409)
    assert jobs.item(tenant) == before
    asked = jobs.ops.post(f"/admin/tenants/{tenant}/offboard")
    assert asked.status_code == 202, asked.text
    item = asked.json()
    assert (item["state"], item["pending_action"], item["step"], item["step_actor"], item["failure"]) == (
        "offboarding", "offboard", "offboard", "service", None)


def test_an_offboarded_tenant_stays_readable_and_takes_no_request(jobs: Any) -> None:
    """The tombstone is listed and gettable with `delete_repo` pending; resume, offboard, rotate are 409 (O2, r9 Endpoints)."""
    tenant = jobs.active_tenant()
    assert jobs.ops.post(f"/admin/tenants/{tenant}/offboard").status_code == 202
    jobs.drive()
    item = jobs.item(tenant)
    assert (item["state"], item["pending_action"], item["failure"]) == ("offboarded", "delete_repo", None)
    assert tenant in [i["tenant_id"] for i in items(jobs.ops.get("/admin/tenants"))]
    for route in ("resume", "offboard", "rotate-forge-credential"):
        _problem(jobs.ops.post(f"/admin/tenants/{tenant}/{route}"), 409)
    assert jobs.item(tenant) == item


def _within(seconds: float, fn: Any) -> Any:
    out: dict[str, Any] = {}
    thread = threading.Thread(target=lambda: out.setdefault("result", fn()), daemon=True)
    thread.start()
    thread.join(seconds)
    assert not thread.is_alive(), "the request did not return while a step was running"
    return out["result"]


def test_requests_return_while_a_step_is_running_and_the_late_commit_does_not_undo_an_offboard(jobs: Any) -> None:
    """With the service blocked inside a step of T, the API reads, refuses and accepts at once (it takes no lock); the stale worker then leaves the offboard intact (P6, RC-3)."""
    import asyncio

    tenant = jobs.create()
    inside, release = threading.Event(), threading.Event()

    def block() -> None:
        inside.set()
        assert release.wait(WAIT)
    jobs.forge.during[("POST", REPOS)] = block
    service = jobs.new_service(jobs.tenants, identity=jobs.service)
    worker = threading.Thread(target=lambda: asyncio.run(service.work()), daemon=True)
    worker.start()
    try:
        assert inside.wait(WAIT), "the service never reached the repo step"
        assert _within(WAIT, lambda: jobs.ops.get(f"/admin/tenants/{tenant}")).status_code == 200
        assert _within(WAIT, lambda: jobs.ops.post(f"/admin/tenants/{tenant}/rotate-forge-credential")).status_code == 409
        asked = _within(WAIT, lambda: jobs.ops.post(f"/admin/tenants/{tenant}/offboard"))
        assert asked.status_code == 202, asked.text
    finally:
        release.set()
        worker.join(WAIT)
    assert not worker.is_alive()
    item = jobs.item(tenant)
    assert (item["state"], item["pending_action"], item["failure"]) == ("offboarding", "offboard", None)


# --- the identity seam over the API (DC-6) ----------------------------------------------------------

@pytest.mark.parametrize("route", ["members", "invitations", "alerts"])
def test_a_tenant_that_is_offboarding_is_404_to_its_member_and_an_active_one_is_not(route: str) -> None:
    """`member_of` needs the tenant present and `active`: the member of an offboarding tenant gets 404 before any worker ran (r9 Identity seam)."""
    world = World(administrators=[OPS], tenants={LAB: [ME], T2: [BOB]})
    member, other = world.sign_in(ME), world.sign_in(BOB)
    assert member.get(f"/tenants/{LAB}/{route}").status_code == 200  # control: active
    assert other.get(f"/tenants/{T2}/{route}").status_code == 200
    ops = world.sign_in_admin()
    assert ops.post(f"/admin/tenants/{LAB}/offboard").status_code == 202
    assert member.get(f"/tenants/{LAB}/{route}").status_code == 404
    assert other.get(f"/tenants/{T2}/{route}").status_code == 200  # another tenant is unaffected


def test_a_member_reaches_nothing_of_an_offboarded_tenant(jobs: Any) -> None:
    """After the whole offboard job, the former member still gets 404 and `/me` lists nothing (O4, r9 Identity seam)."""
    tenant = jobs.active_tenant()
    member = jobs.member_of(tenant)
    assert tenant in tenants_of(member)
    assert jobs.ops.post(f"/admin/tenants/{tenant}/offboard").status_code == 202
    jobs.drive()
    assert member.get(f"/tenants/{tenant}/members").status_code == 404
    assert tenants_of(member) == set()


def test_me_lists_only_memberships_of_active_tenants() -> None:
    """Both memberships are listed while both tenants are active; an offboarding tenant drops out (r9 Identity seam)."""
    world = World(administrators=[OPS], tenants={LAB: [ME], T2: [ME]})
    member = world.sign_in(ME)
    assert tenants_of(member) == {LAB, T2}
    assert world.sign_in_admin().post(f"/admin/tenants/{LAB}/offboard").status_code == 202
    assert tenants_of(member) == {T2}


@pytest.mark.parametrize("state", SEEDED_STATES)
def test_an_invitation_to_a_tenant_that_is_not_active_cannot_be_accepted(state: str) -> None:
    """Explicit accept: 404 and no membership once the tenant is offboarding or offboarded; the active tenant's invitation accepts (r9 Identity seam, P-L)."""
    world = World(administrators=[OPS], tenants={LAB: [ME]})
    member = world.sign_in(ME)
    world.register(T1)
    world.register(T2)
    world.seed_first_members(T1, [ME])
    world.seed_first_members(T2, [ME])
    [stale] = world.call(world.raw_repo.memberships_of_tenant, T1)
    [live] = world.call(world.raw_repo.memberships_of_tenant, T2)
    world.move_tenant(T1, state)
    assert member.post(f"/invitations/{stale.id}/accept").status_code == 404
    assert tenants_of(member) == {LAB}
    assert member.post(f"/invitations/{live.id}/accept").status_code == 200  # control
    assert tenants_of(member) == {LAB, T2}


@pytest.mark.parametrize("state", SEEDED_STATES)
def test_the_first_sign_in_joins_only_active_tenants(state: str) -> None:
    """Accept at sign-in skips an invitation to a tenant that is offboarding or offboarded and takes the active one (r9 Identity seam, P-L)."""
    world = World(administrators=[OPS])
    world.register(T1)
    world.register(T2)
    world.seed_first_members(T1, [ME])
    world.seed_first_members(T2, [ME])
    world.move_tenant(T1, state)
    world.send_pending()
    assert tenants_of(world.sign_in(ME)) == {T2}


@pytest.mark.parametrize("state", STATES)
def test_an_administrator_cannot_invite_into_a_tenant_that_is_not_active(state: str, audit: AuditLog) -> None:
    """The invite route treats a non-active tenant as absent (404, no row, no event); an active empty one takes it (r9 Identity seam)."""
    world, ops = _admin_world()
    world.register(T1, state=state)
    world.register(EMPTY)
    mark = audit.mark()
    assert ops.post(f"/admin/tenants/{T1}/invitations", json={"email": NEW}).status_code == 404
    assert audit.since(mark) == []
    assert world.call(world.raw_repo.memberships_of_tenant, T1) == []
    assert ops.post(f"/admin/tenants/{EMPTY}/invitations", json={"email": NEW}).status_code == 202  # control


def test_end_tenant_ends_every_membership_and_revokes_every_invitation_as_system(audit: AuditLog) -> None:
    """`end_tenant(T, now=)`: active members end (ended_by system), invitations revoke; member.remove / invitation.revoke by `system`; other tenants and past rows are untouched (r9 Identity seam)."""
    world = World(administrators=[OPS], tenants={T1: [ANN], T2: [BOB]})
    ann, bob = world.sign_in(ANN), world.sign_in(BOB)
    nina = world.member(ann, T1, NINA)
    gone = world.member(ann, T1, NEW)
    assert gone.delete(f"/tenants/{T1}/members/{user_id(gone)}").status_code == 204  # a past leaver
    pending = world.invite(ann, T1, "later@n.example").json()["id"]
    rows = {m.id: m for m in world.call(world.raw_repo.memberships_of_tenant, T1)}
    elsewhere = world.call(world.raw_repo.memberships_of_tenant, T2)
    assert world.sign_in_admin().post(f"/admin/tenants/{T1}/offboard").status_code == 202
    mark = audit.mark()
    world.call(world.service.end_tenant, T1, now=world.clock())
    after = {m.id: m for m in world.call(world.raw_repo.memberships_of_tenant, T1)}
    ended = {r.id for r in rows.values() if r.status == "active"}
    assert len(ended) == 2
    assert pending in after
    assert {after[i].status for i in ended} == {"ended"}
    assert {after[i].ended_by for i in ended} == {None}
    assert after[pending].status == "revoked"
    [past] = [r for r in rows.values() if r.status == "ended"]
    assert after[past.id] == past  # control: an earlier leaver keeps their own record
    assert world.call(world.raw_repo.memberships_of_tenant, T2) == elsewhere
    users = {user_id(ann), user_id(nina)}
    assert sorted(((e.action, e.actor, e.tenant_id, e.target) for e in audit.since(mark)), key=repr) == sorted(
        [("invitation.revoke", "system", T1, pending), *(("member.remove", "system", T1, u) for u in users)], key=repr)
    mark = audit.mark()
    world.call(world.service.end_tenant, T1, now=world.clock())  # idempotent: nothing left to end
    assert audit.since(mark) == []
    assert bob.get(f"/tenants/{T2}/members").status_code == 200


# --- R7-2: unknown query parameters are refused API-wide -------------------------------------------

@pytest.mark.parametrize("method", ["get", "post"])
def test_r7_2_an_admin_route_refuses_an_undeclared_query_parameter_and_does_nothing(method: str) -> None:
    """`/admin/tenants?bogus=1` is a 422 problem with `extra_forbidden` at `["query", "bogus"]`; no tenant is made. (R7-2)"""
    world, ops = _admin_world()
    before = len(ops.get("/admin/tenants").json()["items"])
    refused = getattr(ops, method)("/admin/tenants?bogus=1")
    _problem(refused, 422)
    assert [(e["type"], e["loc"]) for e in refused.json()["errors"]] == [("extra_forbidden", ["query", "bogus"])]
    assert len(ops.get("/admin/tenants").json()["items"]) == before


def test_r7_2_control_the_same_admin_routes_without_the_parameter_answer() -> None:
    """Control: the list answers 200 and the create 202 with no query string. (R7-2)"""
    world, ops = _admin_world()
    assert ops.get("/admin/tenants").status_code == 200
    assert ops.post("/admin/tenants").status_code == 202
