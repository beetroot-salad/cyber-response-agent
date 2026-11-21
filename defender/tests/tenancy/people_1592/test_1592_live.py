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
from defender.tests.tenancy.people_1592 import _gob1592 as oracle
from defender.tests.tenancy.people_1592._live1592 import CALL_TIMEOUT, Live1592, NOW, new_tenant_id, raw_get, require_environment
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

    async def person(self, *tenants: str, settle: bool = True) -> Person:
        sub, username = self.live.keycloak_person()
        self.subs.append(sub)
        user = await seed_user(self.identity, f"{username}@live.example", created_at=NOW, status="active", signin_account_id=sub)
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

#: Off the allowlist; `{R}` is the repository's path. `reachable` paths answer a signed-in member at Forgejo itself, so a
#: 404 at the edge is the edge's refusal, not Forgejo's.
OFF_LIST = [
    ("{R}.git/info/refs?service=git-upload-pack", False), ("{R}/info/refs?service=git-upload-pack", False),
    ("{R}.git", False), ("{R}/../../user/settings", True), ("/%2e%2e/user/settings", True), ("/user/./settings", True),
    ("/t-x//knowledge", False), ("{R}%2fsettings", False), ("{R}//settings", False), ("/User/Settings", True),
    ("/USER/SETTINGS", True), ("/API/v1/version", True), ("/api/v1/version", True), ("/api/swagger", True),
    ("/user/settings", True), ("/user/settings/applications", True), ("/user/link_account", True),
    ("/user/link_account_signup", True), ("/-/admin", True), ("/explore/repos", True), ("/explore/users", True),
    ("{R}/settings", False), ("{R}/settings/hooks", False), ("{R}/hooks", False), ("{R}/settings/collaboration", False),
    ("/user/login", True), ("/user/sign_up", True), ("/user/forgot_password", True), ("/notifications", True),
    ("/repo/create", True), ("/repo/migrate", True), ("/org/create", True), ("/user/oauth2/product/../../settings", True),
]


async def test_s4_1_paths_off_the_allowlist_are_refused_at_the_edge(rig: Rig, live: Live1592):
    """S4-1: generated off-list paths, signed in and not, answer 404 at the edge where Forgejo itself would answer."""
    tenant = await rig.tenant()
    person = await rig.person(tenant)
    visit = live.sign_in(person.username)
    cookie = visit.cookie_header()
    refused, reachable_behind = [], []
    for template, reachable in OFF_LIST:
        path = template.replace("{R}", repo(tenant))
        for who in (cookie, None):
            status = raw_get(live.edge, path, cookie=who).status
            if status != 404:
                refused.append((path, bool(who), status))
        if reachable:
            behind = raw_get(live.private, path.replace("/../", "/").replace("%2e%2e/", ""), cookie=cookie).status
            reachable_behind.append((path, behind))
    assert not refused
    # The control: some of these really are served by Forgejo to this member, so the 404s above are the edge's doing.
    assert any(status != 404 for path, status in reachable_behind if path in ("/user/settings", "/explore/repos"))


ALLOWLISTED = ["/", "/repo/search", "/avatars/{hex}", "{R}", "{R}/raw/branch/main/README.md", "{R}/media/branch/main/README.md",
               "{R}/src/branch/main/README.md", "{R}/pulls", "{R}/issues", "/user/oauth2/product", "/assets/css/index.css"]


async def test_s4_15_allowlisted_paths_asked_with_no_session_never_show_tenant_content(rig: Rig, live: Live1592):
    """S4-15 / OD-1a: no session on any allowlisted path gets a sign-in redirect, a public asset or 404, never content."""
    tenant = await rig.tenant()
    marker = f"TENANT-CONTENT-{uuid.uuid4().hex}"
    live.ok(live.admin.put(f"/repos/t-{tenant}/knowledge/contents/README.md", json={
        "content": base64.b64encode(marker.encode()).decode(), "message": "marker", "branch": "main",
        "sha": live.admin.get(f"/repos/t-{tenant}/knowledge/contents/README.md").json()["sha"]}))
    anonymous = httpx.Client(base_url=live.edge, follow_redirects=False, timeout=30)
    for template in ALLOWLISTED:
        path = template.replace("{R}", repo(tenant)).replace("{hex}", uuid.uuid4().hex)
        response = anonymous.get(path)
        assert marker not in response.text, path
        assert response.status_code in (301, 302, 303, 307, 404) or (response.status_code == 200 and path.startswith(("/assets", "/avatars"))), (path, response.status_code)
        if response.is_redirect:
            assert "/user/login" in response.headers["location"] or "/user/oauth2/" in response.headers["location"] \
                or "/keycloak" in response.headers["location"] or "/realms/" in response.headers["location"], (path, response.headers["location"])


# --- S4-2, S4-3: sign-in by the wrong person -----------------------------------------------------------------

LINK_PATHS = ["/user/oauth2/product", "/user/oauth2/product/", "/User/OAuth2/product", "//user/oauth2/product",
              "/user/oauth2/product?redirect_to=%2F", "/user/oauth2/product/../product", "/user/oauth2/%70roduct"]


async def test_s4_2_the_cookie_drop_defeats_the_signed_in_link(rig: Rig, live: Live1592):
    """S4-2 / P25, P26: Alice signed in, Keycloak holding Mallory, a start on any path variant never reaches the link page."""
    tenant = await rig.tenant()
    alice, mallory = await rig.person(tenant), await rig.person(tenant)
    before = live.account(alice.login)["login_name"]
    for path in LINK_PATHS:
        mallory_visit = live.sign_in(mallory.username)  # Keycloak now holds Mallory's session in this client's jar
        for cookie in list(mallory_visit.client.cookies.jar):
            if cookie.domain.split(":")[0] == mallory_visit.host():
                mallory_visit.client.cookies.jar.clear(cookie.domain, cookie.path, cookie.name)
        alice_visit = live.sign_in(alice.username)  # a fresh client: Alice's Forgejo session, Keycloak holds Alice
        for kc_cookie in mallory_visit.client.cookies.jar:  # Keycloak's session cookies are Mallory's
            alice_visit.client.cookies.jar.set_cookie(kc_cookie)
        visit = live.browse(path, client=alice_visit.client)
        assert not reached_link_page(visit), (path, visit.trail)
        assert live.ok(live.admin.get(f"/users/{alice.login}")).json()["login_name"] == before
        assert live.account(mallory.login)["login_name"] == mallory.sub
    assert raw_get(live.edge, "/user/link_account").status == 404


async def test_s4_3_an_unknown_sub_gets_no_account(rig: Rig, live: Live1592):
    """S4-3: a Keycloak person no one made an account for creates none and cannot reach the link page."""
    before = live.accounts()
    sub, username = live.keycloak_person()
    rig.subs.append(sub)
    visit = live.browse("/user/oauth2/product", username=username)
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
    cookie = live.sign_in(person.username).cookie_header()
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
    assert not rig.session_rows() or all(rig.world.sessions.keys() != {k} for k in [cookie])
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
    rig.worker = rig.make_worker(forge_session_cap=CAP, forge_cap_every=1.0)
    time.sleep(CAP + 1)
    await rig.step(2)
    revived = [d for d, _at in rig.session_rows().values() if oracle.UID_ENTRY in d]
    assert revived == []


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
    stages: dict[str, dict[str, tuple[bytes, Any]]] = {}

    def snap(name: str) -> None:
        stages[name] = rig.session_rows()

    snap("empty")
    anon = live.browse("/user/oauth2/product")                                   # sign-in start
    snap("start")
    visit = live.browse("/user/oauth2/product", username=person.username)        # callback
    snap("callback")
    live.browse("/", client=visit.client)                                        # page load
    snap("page-load")
    ghost, ghost_name = live.keycloak_person()
    rig.subs.append(ghost)
    live.browse("/user/oauth2/product", username=ghost_name)                     # unknown-sub callback
    snap("unknown-sub")
    suspended = await rig.person(tenant)
    live.ok(live.admin.patch(f"/admin/users/{suspended.login}", json={"login_name": suspended.sub, "source_id": live.source_id, "prohibit_login": True}))
    live.browse("/user/oauth2/product", username=suspended.username)             # suspended callback
    snap("suspended")
    live.browse("/user/oauth2/product", client=visit.client)                     # cookie-dropped start
    snap("dropped-start")
    assert anon.trail
    mine = {k: v for k, v in rig.session_rows().items() if oracle.UID_ENTRY in v[0]}
    assert mine, "no session row holds the uid entry"
    for key, (data, stamped) in mine.items():
        assert stamped is not None, f"stage row {key} holds a uid and has no signed_in_at"
        at = data.index(oracle.UID_ENTRY) + len(oracle.UID_ENTRY)
        assert data[at:].startswith(oracle.uid_value(session_uid(data))), key
        assert session_uid(data) in (uid, live.account(suspended.login)["id"])
        if session_uid(data) == uid:
            assert data[at:].startswith(oracle.uid_value(uid))
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

    def browse() -> list[str]:
        ran: list[str] = []
        with sync_playwright() as pw:
            chromium = pw.chromium.launch()
            context = chromium.new_context()
            context.add_cookies(cookies)
            for kind in ("raw", "media", "src"):
                for name in FILES:
                    page = context.new_page()
                    page.on("console", lambda m, n=f"{kind}/{name}": ran.append(n) if "RAN" in m.text else None)
                    page.on("dialog", lambda d, n=f"{kind}/{name}": (ran.append(n), d.dismiss()))
                    page.goto(f"{live.edge}{repo(tenant)}/{kind}/branch/main/{name}")
                    page.wait_for_timeout(700)
                    try:
                        if page.evaluate("window.__ran"):
                            ran.append(f"{kind}/{name}")
                    except Exception:  # noqa: BLE001 — a page that is no document has no window to read
                        pass
                    page.close()
            chromium.close()
        return ran

    import anyio

    assert await anyio.to_thread.run_sync(browse) == []


# --- S4-11, S4-12: the sessions database ---------------------------------------------------------------------

async def test_s4_11_a_non_superuser_product_login_cannot_connect(live: Live1592):
    """S4-11: the product's own login is refused by the sessions database."""
    import psycopg

    with pytest.raises(psycopg.OperationalError):
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
    rig.worker = rig.make_worker(forge_cap_every=1.0)
    time.sleep(1.1)
    began = time.monotonic()
    await rig.step()
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
    run = subprocess.run([sys.executable, "-m", "defender.lifecycle", "resync-people"], capture_output=True, text=True, timeout=120,
                         env={**os.environ, "DEFENDER_DATABASE_DSN": rig.world.dsn,
                              "DEFENDER_LIFECYCLE_FORGE_URL": live.private,
                              "DEFENDER_LIFECYCLE_FORGE_ADMIN_TOKEN_FILE": str(token_file),
                              "DEFENDER_LIFECYCLE_KEYCLOAK_SOURCE_ID": str(live.source_id)})
    assert run.returncode == 0, run.stderr
    await rig.until_quiet(6)
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
    live.ok(live.admin.post(f"/repos/{path}/branch_protections", json={"branch_name": "main", "enable_push": False}))
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
    assert bot.forge.pull_request(bot.number).state != "open"


async def test_forge_client_ForgejoForge_reopen_pr(bot: BotWorld):
    """S4-14: reopen_pr."""
    bot.forge.close_pr(bot.number)
    bot.forge.reopen_pr(bot.number)
    assert bot.forge.pull_request(bot.number).state == "open"


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
