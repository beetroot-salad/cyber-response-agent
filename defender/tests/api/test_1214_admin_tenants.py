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


@pytest.mark.parametrize("tenant", [UNKNOWN, MALFORMED])
def test_an_unknown_or_malformed_tenant_is_404_on_every_tenant_route(tenant: str, audit: AuditLog) -> None:
    """Get, resume, offboard and rotate answer 404 for a tenant that is not there; nothing is audited (O2, RC-3)."""
    world, ops = _admin_world()
    world.register(EMPTY)
    mark = audit.mark()
    for method, path in (("GET", ""), ("POST", "/resume"), ("POST", "/offboard"), ("POST", "/rotate-forge-credential")):
        _problem(ops.request(method, f"/admin/tenants/{tenant}{path}"), 404)
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


@pytest.mark.parametrize("state", STATES)
def test_an_invitation_to_a_tenant_that_is_not_active_cannot_be_accepted(state: str) -> None:
    """Explicit accept: 404 and no membership for a `creating`, `offboarding` or `offboarded` tenant; the active tenant's invitation accepts (r9 Identity seam)."""
    world = World(administrators=[OPS], tenants={LAB: [ME]})
    member = world.sign_in(ME)
    world.register(T1, state=state)
    world.register(T2)
    world.seed_first_members(T1, [ME])
    world.seed_first_members(T2, [ME])
    [stale] = world.call(world.raw_repo.memberships_of_tenant, T1)
    [live] = world.call(world.raw_repo.memberships_of_tenant, T2)
    assert member.post(f"/invitations/{stale.id}/accept").status_code == 404
    assert tenants_of(member) == {LAB}
    assert member.post(f"/invitations/{live.id}/accept").status_code == 200  # control
    assert tenants_of(member) == {LAB, T2}


@pytest.mark.parametrize("state", STATES)
def test_the_first_sign_in_joins_only_active_tenants(state: str) -> None:
    """Accept at sign-in skips an invitation to a tenant that is not active and takes the active one (r9 Identity seam)."""
    world = World(administrators=[OPS])
    world.register(T1, state=state)
    world.register(T2)
    world.seed_first_members(T1, [ME])
    world.seed_first_members(T2, [ME])
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
    assert {after[i].ended_by for i in ended} == {"system"}
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
