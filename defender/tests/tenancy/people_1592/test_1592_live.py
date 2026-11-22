# ruff: noqa: PT018 — each compound assert states one fact about one response
"""#1592 F10 on real Forgejo (`live`): the shipped settings, Keycloak with the shipped realm, the edge's Forgejo site,
the sessions database from the shipped script, and the lifecycle's request worker run in-process. CI's `forgejo-live`
job runs it; locally every case skips without its inputs (`_live1592.INPUTS`), under `CI` an unset input fails.
"""
from __future__ import annotations

import asyncio
import base64
import dataclasses
import datetime as dt
import inspect
import os
import re
import threading
import time
import urllib.parse
import uuid
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from defender.tests.identity.test_live_keycloak_1161 import PASSWORD  # noqa: F401 — the people's password
from defender.tests.support.identity._seed1496 import seed_membership, seed_user
from defender.tests.support.tenancy._active1214 import offboard_on_database
from defender.tests.support.shared._postgres1339 import database, execute
from defender.tests.support.frontend import _allowlist1592 as allowlist
from defender.tests.tenancy.people_1592 import _gob1592 as oracle
from defender.tests.tenancy.people_1592._live1592 import FORM_ACTION, CALL_TIMEOUT, Live1592, NOW, new_tenant_id, raw_get, raw_request, require_environment
from defender.tests.tenancy.people_1592._spec1592 import Clock, PeopleForge, login_of, people_config
from defender.tests.tenancy.people_1592._world1592 import People

pytestmark = [pytest.mark.live, pytest.mark.anyio]


@pytest.fixture(scope="module")
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture(scope="module")
def live() -> Iterator[Live1592]:
    return Live1592(require_environment(os.environ))


@dataclasses.dataclass
class Person:
    sub: str
    username: str
    user: Any

    @property
    def login(self) -> str:
        return login_of(self.user.id)


class Rig:
    """The product's databases, the real worker, and the people and tenants a case makes."""

    def __init__(self, live: Live1592, world: People, **config: Any) -> None:
        self.live, self.world, self.config = live, world, config
        self.worker: Any = None
        self.tenants_made: list[str] = []
        self.subs: list[str] = []

    @property
    def identity(self) -> Any:
        return self.world.identity

    def make_worker(self, **config: Any) -> Any:
        from defender.lifecycle import PeopleWorker, PostgresForgeSessions

        cfg = dataclasses.replace(self.world.config, **{**self.config, **config})
        forge = httpx.AsyncClient(base_url=self.live.private, timeout=CALL_TIMEOUT * 6,
                                  headers={"Authorization": f"token {self.live.env['DEFENDER_LIVE_FORGEJO_ADMIN_TOKEN']}"})
        port = PostgresForgeSessions(self.live.env["DEFENDER_LIVE_SESSIONS_LIFECYCLE_DSN"], statement_timeout=CALL_TIMEOUT)
        return PeopleWorker(self.world.tenants, identity=self.identity, forge=forge, sessions=port, config=cfg,
                            clock=lambda: dt.datetime.now(dt.UTC))

    async def step(self, n: int = 1) -> None:
        """`n` polls of the real worker, each followed by its tasks."""
        self.worker = self.worker or self.make_worker()
        for _ in range(n):
            await self.worker.poll()
            await asyncio.wait_for(self.worker.settle(), timeout=60)

    async def until_quiet(self, polls: int = 4) -> None:
        for _ in range(polls):
            await self.step()
            if not await self.world.open_requests():
                return
        raise AssertionError(f"requests left after {polls} polls: {await self.world.open_requests()}")

    async def tenant(self) -> str:
        tenant = new_tenant_id()
        await self.world.tenant(tenant, team=False)
        self.live.build_tenant_forge(tenant)
        self.tenants_made.append(tenant)
        return tenant

    async def person(self, *tenants: str, settle: bool = True, display_name: str = "") -> Person:
        sub, username = self.live.keycloak_person()
        self.subs.append(sub)
        user = await seed_user(self.identity, f"{username}@live.example", created_at=NOW, status="active", signin_account_id=sub,
                              display_name=display_name)
        for tenant in tenants:
            await seed_membership(self.identity, user.id, tenant, status="active", invited_by=None, created_at=NOW, accepted_at=NOW)
        if settle:
            await self.until_quiet()
        return Person(sub, username, user)

    def session_rows(self) -> dict[str, tuple[bytes, Any]]:
        rows = execute(self.live.sessions.dsn, "SELECT key, data, signed_in_at FROM session")
        return {k.strip(): (bytes(d or b""), at) for k, d, at in rows}


@pytest.fixture
async def rig(live: Live1592, tmp_path: Path, data_root: Path) -> AsyncIterator[Rig]:
    from defender.identity.postgres import PostgresIdentityRepository
    from defender.tenancy.postgres import PostgresTenantRepository

    with database(migrated=True) as dsn:
        config = people_config(tmp_path, data_root, sessions_dsn=live.env["DEFENDER_LIVE_SESSIONS_LIFECYCLE_DSN"],
                               keycloak_source_id=live.source_id, people_poll=0.5)
        world = People(PostgresTenantRepository(dsn), PostgresIdentityRepository(dsn), PeopleForge(tmp_path / "unused"),
                       live.sessions, config, Clock(), dsn=dsn)
        made = Rig(live, world)
        try:
            yield made
        finally:
            for sub in made.subs:
                live.keycloak.delete_user(sub)
            await world.identity.close()
            await world.tenants.close()


def reached_link_page(visit: Any) -> bool:
    return any(urllib.parse.urlsplit(u).path.startswith("/user/link_account") and s == 200 for _m, u, s in visit.trail)


def repo(tenant: str) -> str:
    return f"/t-{tenant}/knowledge"


# --- S4-1, S4-15: the edge -----------------------------------------------------------------------------------

def holds(data: bytes, uid: int) -> bool:
    """Whether a session row's data holds the signed-in `uid` entry for exactly this user (the test's gob oracle)."""
    at = data.find(oracle.UID_ENTRY)
    return at >= 0 and data[at + len(oracle.UID_ENTRY):].startswith(oracle.uid_value(uid))


def session_keys(rig: Rig, visit: Any) -> set[str]:
    """The keys of the session rows the visit's cookie jar names (a Forgejo cookie's value is its row's key)."""
    forge_host = visit.host()
    values = {c.value for c in visit.client.cookies.jar if c.domain.split(":")[0] == forge_host}
    return values & set(rig.session_rows())


async def test_s4_1_paths_off_the_allowlist_are_refused_at_the_edge(rig: Rig, live: Live1592):
    """S4-1: every off-list path, with its method, signed in and not, is 404 at the edge, while Forgejo itself serves some of them."""
    tenant = await rig.tenant()
    person = await rig.person(tenant)
    cookie = live.sign_in(person.username).cookie_header()
    assert raw_request(live.edge, "GET", repo(tenant), cookie=cookie).status == 200, "control: an allowlisted path reaches this member"
    answered = [(path, raw_request(live.private, "GET", path, cookie=cookie).status) for path in allowlist.FORGEJO_SERVES]
    # The control, per path: Forgejo itself answers this member (so the 404 below is the edge's refusal, not Forgejo's).
    assert [path for path, status in answered if status == 404 or status >= 500] == [], answered
    not_refused = []
    for _why, cases in allowlist.off_list(repo(tenant)).items():
        for method, path in cases:
            for who in (cookie, None):
                status = raw_request(live.edge, method, path, cookie=who).status
                if status != 404:
                    not_refused.append((method, path, bool(who), status))
    assert not_refused == []
    for path in allowlist.FORGEJO_SERVES:
        assert raw_request(live.edge, "GET", path, cookie=cookie).status == 404, path


def _seed_content(live: Live1592, tenant: str, marker: str) -> None:
    """The files the allowlist's instances name, each holding `marker`, and a branch to compare."""
    path = f"t-{tenant}/knowledge"
    sha = live.admin.get(f"/repos/{path}/contents/README.md").json()["sha"]
    live.ok(live.admin.put(f"/repos/{path}/contents/README.md", json={
        "content": base64.b64encode(marker.encode()).decode(), "message": "marker", "branch": "main", "sha": sha}))
    for name in ("a.md", "a.png", "agent/skills/a.md"):
        live.put_file(path, name, marker.encode())
    live.put_file(path, "b.md", marker.encode(), new_branch="feature")


CALLBACK = "/user/oauth2/product/callback"
PUBLIC_ASSETS = ("/assets/", "/avatars/", "/favicon.ico")
SIGN_IN_PREFIXES = ("/user/oauth2/", "/realms/")


def no_session_answer_ok(method: str, path: str, status: int, where: str | None, hosts: frozenset[str]) -> bool:
    """F10's no-session set for one allowlisted path: a 4xx refusal anywhere; a redirect (to no host, or to `hosts`, the
    edge and Keycloak) only to the sign-in page or start or the realm, from a public asset to a public asset, or from a
    POST back to the site's landing page or with an explicitly empty Location (never a missing one); a 200 only for a GET of the landing page, the sign-in page or a public asset;
    a 500 only for the callback."""
    if 400 <= status < 500:
        return True
    if 300 <= status < 400:
        if where is None:  # no Location header at all: a redirect that goes nowhere is not one the design names
            return False
        target = urllib.parse.urlsplit(where)
        if target.netloc and target.netloc not in hosts:
            return False
        if target.path == "/user/login" or target.path.startswith(SIGN_IN_PREFIXES):
            return True
        if method == "POST" and target.path in ("", "/") and not target.query:
            return True
        return path.startswith(PUBLIC_ASSETS) and target.path.startswith(PUBLIC_ASSETS)
    if status == 200:
        return method == "GET" and (path in ("/", "/user/login") or path.startswith(PUBLIC_ASSETS))
    return status == 500 and path == CALLBACK


def test_s4_15_classifier_accepts_the_ruled_answers_and_rejects_the_others():
    """S4-15 / F10: the no-session classifier takes exactly the answers the design names."""
    hosts = frozenset({"forge.localhost:3000", "kc:8080"})
    ok = [("GET", "/x", 401, ""), ("POST", "/x", 403, ""), ("GET", "/x", 404, ""), ("GET", "/", 303, "/user/login"),
          ("GET", "/", 303, "/user/login?redirect_to=%2F"), ("GET", "/", 303, "http://forge.localhost:3000/user/login"),
          ("GET", "/", 302, "http://kc:8080/realms/r/auth"), ("GET", "/x", 307, "/user/oauth2/product?a=1"),
          ("GET", "/user/login", 200, ""), ("GET", "/assets/js/index.js", 200, ""), ("GET", CALLBACK, 500, ""),
          ("GET", "/avatars/ab", 303, "/user/login"),
          ("GET", "/favicon.ico", 301, "/assets/img/favicon.png"), ("GET", "/assets/a", 301, "/assets/b"),
          ("GET", "/assets/a", 301, "http://forge.localhost:3000/assets/b"), ("GET", "/", 200, ""),
          ("POST", "/user/logout", 303, "/"), ("POST", "/-/fetch-redirect", 303, ""),
          ("POST", "/user/logout", 303, "http://forge.localhost:3000/")]
    bad = [("GET", "/x", 200, ""), ("GET", "/user/login/x", 200, ""), ("POST", "/user/logout", 200, ""),
           ("GET", "/", 302, "/elsewhere"), ("GET", "/x", 302, ""), ("POST", "/user/logout", 302, "https://evil/other"),
           ("GET", "/x", 500, ""), ("POST", CALLBACK, 200, ""), ("GET", "/x", 502, ""), ("GET", CALLBACK, 302, "/"),
           ("GET", "/assets/a", 301, "http://evil/assets/b"), ("GET", "/assets/a", 301, "/repo/private"),
           ("GET", "/x", 301, "/assets/b"), ("GET", "/", 302, "/user/login_x"), ("GET", "/", 302, "/user/login/x"),
           ("GET", "/", 302, "http://evil/realms/r/auth"), ("GET", "/", 302, "http://evil/user/login"),
           ("POST", "/user/logout", 303, "http://evil/"), ("POST", "/user/logout", 303, "/repo/x"),
           ("GET", "/x", 303, "/"), ("POST", "/", 200, ""),
           ("POST", "/-/fetch-redirect", 303, None), ("POST", "/user/logout", 302, None), ("GET", "/", 303, None),
           ("GET", "/x", 307, None), ("GET", "/assets/a", 301, None)]
    assert [c for c in ok if not no_session_answer_ok(*c, hosts)] == []
    assert [c for c in bad if no_session_answer_ok(*c, hosts)] == []


async def test_s4_15_every_allowlisted_path_asked_with_no_session_never_shows_tenant_content(rig: Rig, live: Live1592):
    """S4-15 / OD-1a, F10: each allowlist entry, anonymously, answers only what the design names, with no tenant content."""
    tenant = await rig.tenant()
    name = f"Member {uuid.uuid4().hex[:10]}"
    person = await rig.person(tenant, display_name=name)
    marker = f"TENANT-CONTENT-{uuid.uuid4().hex}"
    _seed_content(live, tenant, marker)
    member = httpx.Client(base_url=live.edge, follow_redirects=False, timeout=30, headers={"Cookie": live.sign_in(person.username).cookie_header()})
    seen = member.get(f"{repo(tenant)}/raw/branch/main/agent/skills/a.md")
    assert seen.status_code == 200 and marker in seen.text, "control: a member reads the marker through the edge"
    anonymous = httpx.Client(base_url=live.edge, follow_redirects=False, timeout=30)
    wrong = []
    hosts = frozenset({urllib.parse.urlsplit(live.edge).netloc, urllib.parse.urlsplit(live.keycloak.base).netloc})
    for method, path in allowlist.allowed(repo(tenant)):
        response = anonymous.request(method, path)
        status, where = response.status_code, response.headers.get("location")  # None: no Location header at all
        assert marker not in response.text, (method, path)
        if status == 200:  # a 3xx's redirect_to echoes the path asked for, so only a 200 body must be free of the tenant's names
            leaked = [what for what in (f"t-{tenant}", name) if what in response.text]
            leaked += [m.group(0) for m in re.finditer(rf"(?<![\w-]){re.escape(person.login)}(?![\w-])", response.text)]
            assert leaked == [], (method, path, leaked)
        ok = no_session_answer_ok(method, path, status, where, hosts)
        if not ok:
            wrong.append((method, path, status, where))
    assert wrong == []


# --- S4-2, S4-3: sign-in by the wrong person -----------------------------------------------------------------

LINK_PATHS = ["/user/oauth2/product", "/user/oauth2/product/", "/User/OAuth2/product", "//user/oauth2/product",
              "/user/oauth2/product?redirect_to=%2F", "/user/oauth2/product/../product", "/user/oauth2/%70roduct"]


@pytest.mark.parametrize("mallory_has_account", [False, True], ids=["unknown-sub", "has-account"])
@pytest.mark.parametrize("path", LINK_PATHS)
async def test_s4_2_the_cookie_drop_defeats_the_signed_in_link(rig: Rig, live: Live1592, path: str, mallory_has_account: bool):
    """S4-2 / P25, P26: Alice signed in, Keycloak holding Mallory: no start variant touches Alice's session row, links Mallory, or reaches the link page."""
    tenant = await rig.tenant()
    alice = await rig.person(tenant)
    if mallory_has_account:
        mallory = await rig.person(tenant)
        mallory_sub, mallory_name, mallory_uid = mallory.sub, mallory.username, live.account(mallory.login)["id"]
    else:
        mallory_sub, mallory_name = live.keycloak_person()
        rig.subs.append(mallory_sub)
        mallory_uid = None
    alice_uid = live.account(alice.login)["id"]
    login_before, accounts_before = live.account(alice.login)["login_name"], live.accounts()
    visit_a = live.sign_in(alice.username)  # Alice's Forgejo session; Keycloak holds Alice
    alice_keys = session_keys(rig, visit_a)
    assert alice_keys and all(holds(rig.session_rows()[k][0], alice_uid) for k in alice_keys), "control: Alice's cookie names her signed-in row"
    visit_m = live.browse("/user/oauth2/product", username=mallory_name)  # Keycloak now holds Mallory (in another browser)
    for cookie in list(visit_a.client.cookies.jar):  # Alice's browser keeps her Forgejo cookie and gets Mallory's Keycloak session
        if cookie.domain.split(":")[0] != visit_a.host():
            visit_a.client.cookies.jar.clear(cookie.domain, cookie.path, cookie.name)
    for cookie in visit_m.client.cookies.jar:
        if cookie.domain.split(":")[0] != visit_m.host():
            visit_a.client.cookies.jar.set_cookie(cookie)
    holding_alice = {k for k, (d, _a) in rig.session_rows().items() if holds(d, alice_uid)}
    attack = live.browse(path, client=visit_a.client, username=mallory_name)  # Mallory's password, typed in Alice's browser
    assert not reached_link_page(attack), (path, attack.trail)
    rows = rig.session_rows()
    # Alice's session was never part of the start: her row is where it was, and nothing new signed in as her.
    assert {k for k, (d, _a) in rows.items() if holds(d, alice_uid)} == holding_alice, (path, attack.trail)
    assert alice_keys <= set(rows)
    assert live.account(alice.login)["login_name"] == login_before and live.accounts() == accounts_before
    edge_netloc = urllib.parse.urlsplit(live.edge).netloc
    if all(urllib.parse.urlsplit(u).netloc == edge_netloc and 400 <= s < 500 for _m, u, s in attack.trail):
        # the trail never left the start (the edge or Forgejo refused the variant with some 4xx, not only 404): no new session
        assert not session_keys(rig, attack) - alice_keys, attack.trail
    elif mallory_uid is not None:  # forwarded: the attack's session is Mallory's, never Alice's
        final = session_keys(rig, attack) - alice_keys
        assert final and all(holds(rows[k][0], mallory_uid) and not holds(rows[k][0], alice_uid) for k in final), attack.trail
    else:  # forwarded, the unknown identity arrived with no session of Alice's: the link page, refused
        assert any(urllib.parse.urlsplit(u).path.startswith("/user/link_account") and s == 404 for _m, u, s in attack.trail), attack.trail
    fresh = live.browse("/user/oauth2/product", username=mallory_name)  # Mallory alone, later: she is not Alice
    assert not {k for k in session_keys(rig, fresh) if holds(rig.session_rows()[k][0], alice_uid)}, fresh.trail
    assert raw_get(live.edge, "/user/link_account").status == 404


async def test_s4_2_keycloak_asks_for_the_password_again_though_it_holds_the_session(rig: Rig, live: Live1592):
    """S4-2 / OD-4: a person signed in at Forgejo and holding a Keycloak session, starting again in the same browser, is served Keycloak's login form."""
    tenant = await rig.tenant()
    person = await rig.person(tenant)
    visit = live.sign_in(person.username)
    assert any("/realms/" in u and "/auth" in u for _m, u, _s in visit.trail), f"control: the sign-in went through Keycloak: {visit.trail}"
    again = live.browse("/user/oauth2/product", client=visit.client)  # no username: stops wherever Keycloak stops
    assert any("/realms/" in u for _m, u, _s in again.trail), f"the start did not reach Keycloak: {again.trail}"
    assert again.final is not None and again.final.status_code == 200, again.trail
    action = FORM_ACTION.search(again.final.text)
    assert action and "login-actions" in action.group(1), f"Keycloak did not serve its login form again (the session was reused): {again.trail}"


async def test_s4_3_an_unknown_sub_gets_no_account(rig: Rig, live: Live1592):
    """S4-3: a Keycloak person no one made an account for creates none and cannot reach the link page."""
    before = live.accounts()
    sub, username = live.keycloak_person()
    rig.subs.append(sub)
    visit = live.browse("/user/oauth2/product", username=username)
    assert any(urllib.parse.urlsplit(u).path.startswith("/user/link_account") and s == 404 for _m, u, s in visit.trail), \
        f"control: the unknown sub reached Forgejo's link step, which the edge refused: {visit.trail}"
    assert live.accounts() == before
    assert not reached_link_page(visit), visit.trail
    assert visit.final is not None and visit.final.status_code in (302, 303, 404)
    assert raw_get(live.edge, "/user/link_account", cookie=visit.cookie_header()).status == 404


# --- S4-4: isolation -----------------------------------------------------------------------------------------

async def test_s4_4_a_member_of_one_tenant_sees_nothing_of_another(rig: Rig, live: Live1592):
    """S4-4: as T1's member, T2's repository and organisation are 404 and T2's people are not listed."""
    t1, t2 = await rig.tenant(), await rig.tenant()
    a, b = await rig.person(t1), await rig.person(t2)
    cookie = live.sign_in(a.username).cookie_header()
    for path in (repo(t2), f"/t-{t2}", f"/t-{t2}/-/teams", f"/api/v1/repos/t-{t2}/knowledge", f"/api/v1/orgs/t-{t2}/teams"):
        assert raw_get(live.private, path, cookie=cookie).status in (403, 404), path
        assert raw_get(live.edge, path, cookie=cookie).status == 404, path
    found = live.private + "/api/v1/users/search?q=p-"
    listed = httpx.get(found, headers={"Cookie": cookie}).text
    assert b.login not in listed
    assert raw_get(live.private, repo(t1), cookie=cookie).status == 200


# --- S4-5, S4-7: a request cuts access -----------------------------------------------------------------------

def _logged_in(live: Live1592, cookie: str) -> bool:
    r = httpx.get(live.private + "/user/settings", headers={"Cookie": cookie}, follow_redirects=False)
    return r.status_code == 200


@pytest.mark.parametrize("cause", ["membership_end", "offboard", "sign_out"])
async def test_s4_5_each_cause_reaches_forgejo_through_a_request(rig: Rig, live: Live1592, cause: str):
    """S4-5: a membership end, an offboarding and a sign-out each cut access within the worker's polls."""
    tenant = await rig.tenant()
    person = await rig.person(tenant)
    visit = live.sign_in(person.username)
    cookie = visit.cookie_header()
    uid = live.account(person.login)["id"]
    keys = session_keys(rig, visit)
    before = rig.session_rows()
    assert keys and all(before[k][1] is not None and holds(before[k][0], uid) for k in keys), \
        "control: the cookie names a stamped row of this person"
    assert _logged_in(live, cookie) and person.login in live.team_members(tenant)
    if cause == "membership_end":
        await rig.world.end(person.user, tenant)
    elif cause == "offboard":
        await offboard_on_database(rig.world.dsn, tenant)
    else:
        await rig.world.sign_out(person.user)
    await rig.until_quiet()
    if cause != "sign_out":
        assert person.login not in live.team_members(tenant)
        assert live.account(person.login)["prohibit_login"]
    # The rows are gone from the table itself, read before any request reuses the cookie (Forgejo may revive a row it is
    # asked about); a suspension alone would also end the login, so only the table shows the session step ran.
    after = rig.session_rows()
    assert not keys & set(after), "the person's session rows were not deleted"
    assert not [k for k, (d, _a) in after.items() if holds(d, uid)]
    assert not _logged_in(live, cookie)


async def test_s4_7_a_sign_out_deletes_older_sessions_and_keeps_a_newer_one(rig: Rig, live: Live1592):
    """S4-7 / F11: the session begun before the sign-out goes, the one begun after it stays."""
    tenant = await rig.tenant()
    person = await rig.person(tenant)
    older = live.sign_in(person.username)
    time.sleep(1.2)
    await rig.world.sign_out(person.user)
    time.sleep(1.2)
    newer = live.sign_in(person.username)
    assert _logged_in(live, older.cookie_header()) and _logged_in(live, newer.cookie_header()), "control: both sessions work"
    await rig.until_quiet()
    assert not _logged_in(live, older.cookie_header())
    assert _logged_in(live, newer.cookie_header())


# --- S4-6, S4-8: the cap -------------------------------------------------------------------------------------

CAP = 4.0


async def test_s4_6_the_cap_ends_a_session_that_is_in_use(rig: Rig, live: Live1592):
    """S4-6 / F11: with the cap set short, a session used throughout is ended by the next cap run."""
    tenant = await rig.tenant()
    person = await rig.person(tenant)
    worker = rig.make_worker(forge_session_cap=CAP, forge_cap_every=1.0)
    rig.worker = worker
    visit = live.sign_in(person.username)
    assert _logged_in(live, visit.cookie_header()), "control: the session works before the cap"
    deadline = time.monotonic() + 40
    while _logged_in(live, visit.cookie_header()) and time.monotonic() < deadline:
        await rig.step()
        time.sleep(0.5)
    assert not _logged_in(live, visit.cookie_header())


async def test_s4_8_a_row_revived_by_requests_in_flight_is_gone_by_the_next_cap_run(rig: Rig, live: Live1592):
    """S4-8 / P35: parallel requests on the cookie while its row is deleted; the next cap run leaves no row of it."""
    tenant = await rig.tenant()
    person = await rig.person(tenant)
    visit = live.sign_in(person.username)
    cookie = visit.cookie_header()
    stop = threading.Event()

    def hammer() -> None:
        with httpx.Client(timeout=15) as client:
            while not stop.is_set():
                client.get(live.private + "/", headers={"Cookie": cookie}, follow_redirects=False)

    threads = [threading.Thread(target=hammer) for _ in range(8)]
    for t in threads:
        t.start()
    time.sleep(1)
    execute(live.sessions.dsn, "DELETE FROM session WHERE signed_in_at IS NOT NULL")
    time.sleep(2)
    stop.set()
    for t in threads:
        t.join()
    # Whatever the hammer did, make the revival certain: an unstamped row holding this person's uid (Forgejo re-inserts a
    # deleted row's data without the stamp). The cap is long, so only the job's second rule can delete it.
    uid = live.account(person.login)["id"]
    revived_key = uuid.uuid4().hex[:16]
    live.sessions.plant(revived_key, oracle.signed_in_data(uid), signed_in_at=None)
    anonymous_key = uuid.uuid4().hex[:16]
    live.sessions.plant(anonymous_key, oracle.ANONYMOUS_P31, signed_in_at=None)
    assert revived_key in rig.session_rows(), "control: the revived row exists before the cap run"
    rig.worker = rig.make_worker(forge_session_cap=3600.0)
    assert await rig.worker.cap() is not None, "the cap job failed"
    rows = rig.session_rows()
    assert revived_key not in rows, "the cap run left a revived (unstamped) row holding a uid"
    assert not [k for k, (d, at) in rows.items() if at is None and oracle.UID_ENTRY in d], \
        "an unstamped row holding UID_ENTRY (Forgejo's own revival included) survived the cap run"
    assert anonymous_key in rows, "control: an anonymous row (no uid) is left to Forgejo's own expiry"


# --- S4-9: the stages ----------------------------------------------------------------------------------------

async def test_s4_9_every_stage_row_is_stamped_selected_and_read_with_a_uid_above_255(rig: Rig, live: Live1592):
    """S4-9 / V4: each signed-in stage is stamped and decodes; a person whose uid is above 255 loses every one on sign-out."""
    from defender.lifecycle import session_uid  # G2's candidate name

    tenant = await rig.tenant()
    while len(live.accounts()) < 260:  # accounts to push the next id past one byte
        live.ok(live.admin.post("/admin/users", json={"username": f"fill-{uuid.uuid4().hex[:12]}", "email": f"{uuid.uuid4().hex}@live.example",
                                                        "password": uuid.uuid4().hex, "must_change_password": False}))
    person = await rig.person(tenant)
    uid = live.account(person.login)["id"]
    assert uid > 255
    from defender.lifecycle import PostgresForgeSessions

    port = PostgresForgeSessions(live.env["DEFENDER_LIVE_SESSIONS_LIFECYCLE_DSN"], statement_timeout=CALL_TIMEOUT)
    stages: dict[str, tuple[dict[str, tuple[bytes, Any]], set[str]]] = {}
    suspended_uid: list[int] = []

    async def snap(name: str) -> None:
        """The table, and what the worker's own prefilter (`signed_in_rows()`) selects, at this stage."""
        rows = rig.session_rows()
        selected = {row.key.strip() for row in await port.signed_in_rows()}
        stages[name] = (rows, selected)
        stamped_with_uid = {k for k, (d, at) in rows.items() if at is not None and oracle.UID_ENTRY in d}
        assert selected == stamped_with_uid, f"{name}: the prefilter selects {selected ^ stamped_with_uid} wrongly"
        for key, (data, at) in rows.items():
            if oracle.UID_ENTRY in data:  # every row holding a uid is stamped and reads as one of the two people's
                assert at is not None, f"{name}: row {key} holds a uid and has no signed_in_at"
                assert session_uid(data) in {uid, *suspended_uid}, (name, key)
                assert data[data.index(oracle.UID_ENTRY) + len(oracle.UID_ENTRY):].startswith(oracle.uid_value(session_uid(data))), (name, key)

    await snap("empty")
    anon = live.browse("/user/oauth2/product")                                   # sign-in start
    await snap("start")
    visit = live.browse("/user/oauth2/product", username=person.username)        # callback
    await snap("callback")
    cookie_rows = {"callback": session_keys(rig, visit)}
    live.browse("/", client=visit.client)                                        # page load
    await snap("page-load")
    cookie_rows["page-load"] = session_keys(rig, visit)
    for stage, mine in cookie_rows.items():  # the signed-in stages: the visit's own row is selected, stamped, and this person's
        rows, selected = stages[stage]
        assert mine and mine <= selected, f"{stage}: the person's cookie row is not selected by the prefilter"
        assert all(rows[k][1] is not None and holds(rows[k][0], uid) and session_uid(rows[k][0]) == uid for k in mine), stage
    ghost, ghost_name = live.keycloak_person()
    rig.subs.append(ghost)
    live.browse("/user/oauth2/product", username=ghost_name)                     # unknown-sub callback
    await snap("unknown-sub")
    suspended = await rig.person(tenant)
    suspended_uid.append(live.account(suspended.login)["id"])
    live.ok(live.admin.patch(f"/admin/users/{suspended.login}", json={"login_name": suspended.sub, "source_id": live.source_id, "prohibit_login": True}))
    live.browse("/user/oauth2/product", username=suspended.username)             # suspended callback
    await snap("suspended")
    live.browse("/user/oauth2/product", client=visit.client)                     # cookie-dropped start
    await snap("dropped-start")
    assert anon.trail
    assert any(oracle.UID_ENTRY in d for d, _a in stages["dropped-start"][0].values()), "control: some row holds the uid entry"
    await rig.world.sign_out(person.user)
    await rig.until_quiet()
    left = [k for k, (d, _a) in rig.session_rows().items() if oracle.UID_ENTRY in d and session_uid(d) == uid]
    assert left == []


# --- S4-10: model-written files ------------------------------------------------------------------------------

SCRIPT = "window.__ran=1;console.log('RAN');alert('RAN')"
FILES = {
    "a.html": f"<html><script>{SCRIPT}</script></html>",
    "a.svg": f'<svg xmlns="http://www.w3.org/2000/svg" onload="{SCRIPT}"><script>{SCRIPT}</script></svg>',
    "a.xhtml": f'<html xmlns="http://www.w3.org/1999/xhtml"><script>{SCRIPT}</script></html>',
    "a.xml": '<?xml-stylesheet type="text/xsl" href="a.xsl"?><r/>',
    "a.xsl": ('<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">'
              f'<xsl:template match="/"><html xmlns="http://www.w3.org/1999/xhtml"><script>{SCRIPT}</script></html></xsl:template></xsl:stylesheet>'),
    "a.pdf": "%PDF-1.4\n1 0 obj<</Type/Catalog/OpenAction<</S/JavaScript/JS(app.alert(1))>>>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF",
    "noext": f"<html><script>{SCRIPT}</script></html>",
}


async def test_s4_10_model_written_files_run_no_script(rig: Rig, live: Live1592):
    """S4-10: under raw/, media/ and src/ none of the file types runs a script in Chromium."""
    from playwright.sync_api import sync_playwright

    tenant = await rig.tenant()
    person = await rig.person(tenant)
    for name, text in FILES.items():
        live.put_file(f"t-{tenant}/knowledge", name, text.encode())
    cookies = [{"name": c.name, "value": c.value, "url": live.edge} for c in live.sign_in(person.username).client.cookies.jar
               if c.domain.split(":")[0] == urllib.parse.urlsplit(live.edge).hostname]

    def browse() -> tuple[list[str], dict[str, int]]:
        ran: list[str] = []
        loaded: dict[str, int] = {}
        with sync_playwright() as pw:
            chromium = pw.chromium.launch()
            context = chromium.new_context()
            context.add_cookies(cookies)
            for kind in ("raw", "media", "src"):
                for name in FILES:
                    page = context.new_page()
                    page.on("console", lambda m, n=f"{kind}/{name}": ran.append(n) if "RAN" in m.text else None)
                    page.on("dialog", lambda d, n=f"{kind}/{name}": (ran.append(n), d.dismiss()))
                    try:
                        loaded[f"{kind}/{name}"] = page.goto(f"{live.edge}{repo(tenant)}/{kind}/branch/main/{name}").status
                    except Exception:  # noqa: BLE001 — a download (a PDF) starts instead of a navigation: no script runs in it
                        loaded[f"{kind}/{name}"] = -1
                    page.wait_for_timeout(700)
                    try:
                        if page.evaluate("window.__ran"):
                            ran.append(f"{kind}/{name}")
                    except Exception:  # noqa: BLE001 — a page that is no document has no window to read
                        pass
                    page.close()
            chromium.close()
        return ran, loaded

    import anyio

    ran, loaded = await anyio.to_thread.run_sync(browse)
    # The control: the pages were served (a 404 runs nothing either), so "no script ran" is about the files' bytes.
    assert [k for k in ("raw/a.html", "src/a.html", "raw/noext", "raw/a.svg") if loaded.get(k) != 200] == [], loaded
    assert ran == []


# --- S4-11, S4-12: the sessions database ---------------------------------------------------------------------

async def test_s4_11_a_non_superuser_product_login_cannot_connect(live: Live1592):
    """S4-11: the product's own login is refused by the sessions database."""
    import psycopg

    psycopg.connect(live.sessions.dsn, connect_timeout=5).close()  # control: the server is up and answers the superuser
    with pytest.raises(psycopg.OperationalError, match=r"(?i)denied|authentication|not allowed|no pg_hba"):
        psycopg.connect(live.env["DEFENDER_LIVE_SESSIONS_PRODUCT_DSN"], connect_timeout=5)


async def test_s4_12_ten_thousand_anonymous_rows_stay_within_the_call_timeout(rig: Rig, live: Live1592):
    """S4-12 / V5: with 10 000 anonymous rows, a sign-in start and the cap run each finish within the call timeout, unthrottled."""
    import psycopg

    tenant = await rig.tenant()
    person = await rig.person(tenant)
    with psycopg.connect(live.sessions.dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.executemany("INSERT INTO session (key, data, expiry) VALUES (%s, %s, 2000000000)",
                        [(uuid.uuid4().hex[:16], oracle.ANONYMOUS_P31) for _ in range(10_000)])
    took, statuses = [], []
    for _ in range(20):
        began = time.monotonic()
        statuses.append(httpx.get(live.edge + "/user/oauth2/product", follow_redirects=False, timeout=30).status_code)
        took.append(time.monotonic() - began)
    assert 429 not in statuses and 503 not in statuses
    assert max(took) < CALL_TIMEOUT, took
    rig.worker = rig.make_worker()
    began = time.monotonic()
    assert await rig.worker.cap() is not None, "the cap job failed or timed out"
    assert time.monotonic() - began < CALL_TIMEOUT
    await rig.world.sign_out(person.user)
    await rig.until_quiet()


# --- S4-13: resync -------------------------------------------------------------------------------------------

async def test_s4_13_resync_restores_a_hand_edited_team_and_a_hand_suspension(rig: Rig, live: Live1592, tmp_path: Path):
    """S4-13: after a hand removal from the team and a hand suspension, `resync-people` and the worker restore both."""
    import subprocess
    import sys

    token_file = tmp_path / "forge-admin-token"
    token_file.write_text(live.env["DEFENDER_LIVE_FORGEJO_ADMIN_TOKEN"] + "\n", encoding="utf-8")
    token_file.chmod(0o600)
    tenant = await rig.tenant()
    a, b = await rig.person(tenant), await rig.person(tenant)
    live.ok(live.admin.delete(f"/teams/{live.team_id(tenant)}/members/{a.login}"))
    live.ok(live.admin.patch(f"/admin/users/{b.login}", json={"login_name": b.sub, "source_id": live.source_id, "prohibit_login": True}))
    assert a.login not in live.team_members(tenant) and live.account(b.login)["prohibit_login"], "control: the hand edits are in place"
    # The child imports `defender` as pytest does (pyproject's `pythonpath = [".."]`): the checkout root first on its path.
    root = Path(__file__).resolve().parents[4]
    inherited = os.environ.get("PYTHONPATH", "")
    run = subprocess.run([sys.executable, "-m", "defender.lifecycle", "resync-people"], capture_output=True, text=True, timeout=120,
                         cwd=root, env={**os.environ, "PYTHONPATH": os.pathsep.join(p for p in (str(root), inherited) if p),
                                        "DEFENDER_DATABASE_DSN": rig.world.dsn,
                              "DEFENDER_LIFECYCLE_FORGE_URL": live.private,
                              "DEFENDER_LIFECYCLE_FORGE_ADMIN_TOKEN_FILE": str(token_file),
                              "DEFENDER_LIFECYCLE_KEYCLOAK_SOURCE_ID": str(live.source_id)})
    assert run.returncode == 0, run.stderr
    # resync-people records (U, none) for every `p-` account on the source, the earlier cases' people included, and the
    # worker starts at most `people_concurrency` runs a poll (r15.2 "Taking work"): enough polls for all of them.
    users = {user for user, _tenant in await rig.world.open_requests() if user is not None}
    await rig.until_quiet(-(-len(users) // rig.world.config.people_concurrency) + 4)
    assert {a.login, b.login} <= live.team_members(tenant)
    assert not live.account(b.login)["prohibit_login"]


# --- S4-14: the census of the bots' forge client -------------------------------------------------------------

def _public_methods(cls: type) -> list[str]:
    return sorted(n for n, m in inspect.getmembers(cls, inspect.isfunction) if not n.startswith("_"))


def _clients() -> dict[str, type]:
    from defender.learning.author.version_control.forgejo import ForgejoForge

    return {"ForgejoForge": ForgejoForge}


@pytest.mark.parametrize("name", ["ForgejoForge"])
def test_s4_14_every_public_method_of_the_forge_clients_has_a_live_case(name: str):
    """S4-14: a public method with no `test_forge_client_<name>_<method>` case in this module fails the census."""
    here = globals()
    missing = [m for m in _public_methods(_clients()[name]) if f"test_forge_client_{name}_{m}" not in here]
    assert not missing, missing


@dataclasses.dataclass
class BotWorld:
    forge: Any
    repo: str
    branch: str
    number: int


class _Token:
    def __init__(self, token: str) -> None:
        self._token = token

    def token(self, min_validity: int = 0) -> str:
        return self._token


@pytest.fixture
async def bot(rig: Rig, live: Live1592) -> AsyncIterator[BotWorld]:
    from defender.learning.author.version_control.forgejo import ForgejoForge

    tenant = await rig.tenant()
    path = f"t-{tenant}/knowledge"
    # `main`'s rule as the lifecycle writes it (r15.2 "Who may merge T's `main`": the merge whitelist, exactly team
    # `members`; #1163 A23): push off and the bot, a collaborator outside the team, on no whitelist.
    live.ok(live.admin.post(f"/repos/{path}/branch_protections", json={
        "rule_name": "main", "branch_name": "main", "enable_push": False, "enable_push_whitelist": False,
        "enable_force_push": False, "enable_merge_whitelist": True, "merge_whitelist_usernames": [],
        "merge_whitelist_teams": ["members"]}))
    live.ok(live.admin.post(f"/repos/{path}/labels", json={"name": "feedback", "color": "#00aabb"}))
    branch = f"learning/{uuid.uuid4().hex[:8]}"
    live.ok(live.admin.post(f"/repos/{path}/branches", json={"new_branch_name": branch, "old_branch_name": "main"}))
    live.ok(live.admin.post(f"/repos/{path}/contents/{branch.split('/')[1]}.md", json={
        "content": base64.b64encode(b"x").decode(), "branch": branch, "message": "lesson"}))
    with httpx.Client() as client:
        forge = ForgejoForge(origin=f"{live.private}/{path}.git", identity=_Token(live.env["DEFENDER_LIVE_FORGEJO_BOT_TOKEN"]), client=client)
        opened = forge.open_pr(base="main", head=branch, title="t", body="b")
        yield BotWorld(forge, path, branch, opened.number)


async def test_forge_client_ForgejoForge_open_pr(bot: BotWorld):
    """S4-14: open_pr."""
    assert bot.number > 0


async def test_forge_client_ForgejoForge_repository_id(bot: BotWorld):
    """S4-14: repository_id."""
    assert bot.forge.repository_id() > 0


async def test_forge_client_ForgejoForge_verify_main_protection(bot: BotWorld):
    """S4-14: verify_main_protection."""
    bot.forge.verify_main_protection()


async def test_forge_client_ForgejoForge_list_open_prs(bot: BotWorld):
    """S4-14: list_open_prs."""
    assert bot.forge.list_open_prs("learning/")


async def test_forge_client_ForgejoForge_pull_requests(bot: BotWorld):
    """S4-14: pull_requests."""
    assert [p.number for p in bot.forge.pull_requests()] == [bot.number]


async def test_forge_client_ForgejoForge_pull_request(bot: BotWorld):
    """S4-14: pull_request."""
    assert bot.forge.pull_request(bot.number).number == bot.number


async def test_forge_client_ForgejoForge_reviews(bot: BotWorld):
    """S4-14: reviews."""
    assert bot.forge.reviews(bot.number) == []


async def test_forge_client_ForgejoForge_comments(bot: BotWorld):
    """S4-14: comments."""
    assert bot.forge.comments(bot.number) == []


async def test_forge_client_ForgejoForge_close_pr(bot: BotWorld):
    """S4-14: close_pr."""
    bot.forge.close_pr(bot.number)
    assert bot.forge.pull_request(bot.number).status == "closed"


async def test_forge_client_ForgejoForge_reopen_pr(bot: BotWorld):
    """S4-14: reopen_pr."""
    bot.forge.close_pr(bot.number)
    bot.forge.reopen_pr(bot.number)
    assert bot.forge.pull_request(bot.number).status == "open"


async def test_forge_client_ForgejoForge_label_id(bot: BotWorld):
    """S4-14: label_id."""
    assert bot.forge.label_id("feedback") > 0


async def test_forge_client_ForgejoForge_create_issue(bot: BotWorld):
    """S4-14: create_issue."""
    assert bot.forge.create_issue(title="i", body="b", label="feedback")["number"] > 0


async def test_forge_client_ForgejoForge_list_issues(bot: BotWorld):
    """S4-14: list_issues."""
    made = bot.forge.create_issue(title="i", body="b", label="feedback")
    assert made["number"] in [i["number"] for i in bot.forge.list_issues(label="feedback", created_by="live-bot")]


async def test_forge_client_ForgejoForge_get_issue(bot: BotWorld):
    """S4-14: get_issue."""
    made = bot.forge.create_issue(title="i", body="b", label="feedback")
    assert bot.forge.get_issue(made["number"])["number"] == made["number"]


async def test_forge_client_ForgejoForge_create_comment(bot: BotWorld):
    """S4-14: create_comment."""
    assert bot.forge.create_comment(bot.number, "hello")["id"] > 0


async def test_forge_client_ForgejoForge_list_comments(bot: BotWorld):
    """S4-14: list_comments."""
    bot.forge.create_comment(bot.number, "hello")
    assert bot.forge.list_comments(bot.number)


async def test_forge_client_ForgejoForge_list_repo_comments(bot: BotWorld):
    """S4-14: list_repo_comments."""
    bot.forge.create_comment(bot.number, "hello")
    assert bot.forge.list_repo_comments()


async def test_forge_client_host_actor_reads(bot: BotWorld, live: Live1592):
    """S4-14: the host actor's two bot reads (`_host.py`): the repository, and `main` protected, unpushable, unmergeable."""
    bearer = {"Authorization": f"Bearer {live.env['DEFENDER_LIVE_FORGEJO_BOT_TOKEN']}"}
    repo = httpx.get(f"{live.private}/api/v1/repos/{bot.repo}", headers=bearer)
    assert repo.status_code == 200
    branch = httpx.get(f"{live.private}/api/v1/repos/{bot.repo}/branches/main", headers=bearer)
    assert branch.status_code == 200
    body = branch.json()
    assert body["protected"] is True and body["user_can_push"] is False and body["user_can_merge"] is False
