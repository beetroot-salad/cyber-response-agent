"""#1592 F10 live machinery (test-only, NO test functions): the inputs of CI's `forgejo-live` job and the guard that
fails under CI, a thin rig over a real Forgejo (its edge site, its private API, the sessions database, Keycloak) and
the lifecycle's request worker run in-process.

Inputs (all of them must be set, or the cases skip locally and FAIL under `CI`):

    DEFENDER_LIVE_FORGEJO_URL                the edge's Forgejo site, as the Forgejo domain spells it (the `ROOT_URL` origin)
    DEFENDER_LIVE_FORGEJO_PRIVATE_URL        Forgejo on the private network, as the lifecycle and the bots reach it
    DEFENDER_LIVE_FORGEJO_ADMIN_TOKEN        an administrator's token (the lifecycle's)
    DEFENDER_LIVE_FORGEJO_BOT_TOKEN          a non-administrator's token (a tenant bot's stand-in)
    DEFENDER_LIVE_FORGEJO_SOURCE_ID          the Keycloak login source `product`'s id
    DEFENDER_LIVE_KEYCLOAK_URL               the dev Keycloak with the shipped realm
    DEFENDER_LIVE_SESSIONS_DSN               `forgejo_sessions`, as a superuser (plants and reads rows)
    DEFENDER_LIVE_SESSIONS_LIFECYCLE_DSN     `forgejo_sessions`, as the lifecycle's login (`fs_lifecycle`)
    DEFENDER_LIVE_SESSIONS_PRODUCT_DSN       `forgejo_sessions`, as a non-superuser product login (must be refused)
    DEFENDER_TEST_POSTGRES_DSN               the server the product databases are made on

Never point these at the dev compose's own Forgejo or its containers: the cases create organisations, users and sessions.
"""
from __future__ import annotations

import datetime as dt
import html
import http.client
import re
import urllib.parse
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

import httpx
import pytest

from defender.tests.identity.test_live_keycloak_1161 import PASSWORD, Live
from defender.tests.tenancy.people_1592._spec1592 import Sessions

INPUTS = (
    "DEFENDER_LIVE_FORGEJO_URL", "DEFENDER_LIVE_FORGEJO_PRIVATE_URL", "DEFENDER_LIVE_FORGEJO_ADMIN_TOKEN",
    "DEFENDER_LIVE_FORGEJO_BOT_TOKEN", "DEFENDER_LIVE_FORGEJO_SOURCE_ID", "DEFENDER_LIVE_KEYCLOAK_URL",
    "DEFENDER_LIVE_SESSIONS_DSN", "DEFENDER_LIVE_SESSIONS_LIFECYCLE_DSN", "DEFENDER_LIVE_SESSIONS_PRODUCT_DSN",
    "DEFENDER_TEST_POSTGRES_DSN",
)
CALL_TIMEOUT = 5.0


def require_environment(env: Mapping[str, str]) -> dict[str, str]:
    """The inputs, or: a failure when `CI` is set (a check that cannot run there is a failure, #1566), else a skip."""
    missing = [name for name in INPUTS if not env.get(name)]
    if missing:
        if env.get("CI"):
            pytest.fail(f"forgejo-live: not set in CI: {missing}")
        pytest.skip(f"no live Forgejo (not set: {missing})")
    return {name: env[name].rstrip("/") if name.endswith("_URL") else env[name] for name in INPUTS}


def raw_get(url: str, path: str, *, cookie: str | None = None) -> http.client.HTTPResponse:
    """GET `path` exactly as written (no dot-segment or slash normalisation, which httpx does), no redirects."""
    parts = urllib.parse.urlsplit(url)
    connection = http.client.HTTPConnection(parts.hostname or "", parts.port or 80, timeout=15)
    headers = {"Host": parts.netloc}
    if cookie:
        headers["Cookie"] = cookie
    connection.request("GET", path, headers=headers)
    response = connection.getresponse()
    response.read()
    connection.close()
    return response


@dataclass
class Visit:
    """A browser-like client and the requests of one navigation, as `(method, url, status)`."""

    client: httpx.Client
    trail: list[tuple[str, str, int]] = field(default_factory=list)
    final: httpx.Response | None = None

    def paths(self) -> list[str]:
        return [urllib.parse.urlsplit(u).path for _m, u, _s in self.trail]

    def cookie_header(self) -> str:
        return "; ".join(f"{c.name}={c.value}" for c in self.client.cookies.jar if c.domain.split(":")[0] == self.host())

    def host(self) -> str:
        return str(urllib.parse.urlsplit(str(self.client.base_url)).hostname)


_FORM_ACTION = re.compile(r'<form[^>]*id="kc-form-login"[^>]*action="([^"]+)"')


class Live1592:
    """Real Forgejo and Keycloak: browser-like sign-ins over HTTP, the admin API, the sessions database."""

    def __init__(self, env: dict[str, str]) -> None:
        self.env = env
        self.edge = env["DEFENDER_LIVE_FORGEJO_URL"]
        self.private = env["DEFENDER_LIVE_FORGEJO_PRIVATE_URL"]
        self.source_id = int(env["DEFENDER_LIVE_FORGEJO_SOURCE_ID"])
        self.admin = httpx.Client(base_url=f"{self.private}/api/v1", timeout=30,
                                  headers={"Authorization": f"token {env['DEFENDER_LIVE_FORGEJO_ADMIN_TOKEN']}"})
        self.sessions = Sessions(env["DEFENDER_LIVE_SESSIONS_DSN"])
        self.keycloak = Live(env["DEFENDER_LIVE_KEYCLOAK_URL"])

    # Forgejo's own state, as an administrator reads it ----------------------------------------------
    def ok(self, response: httpx.Response, *statuses: int) -> httpx.Response:
        assert response.status_code in (statuses or (200, 201, 204)), (response.request.url, response.status_code, response.text[:300])
        return response

    def account(self, login: str) -> dict[str, Any] | None:
        response = self.admin.get(f"/users/{login}")
        return response.json() if response.status_code == 200 else None

    def accounts(self) -> set[str]:
        found, page = set(), 1
        while rows := self.ok(self.admin.get("/admin/users", params={"page": page, "limit": 50})).json():
            found |= {row["login"] for row in rows}
            page += 1
        return found

    def team_id(self, tenant: str) -> int:
        teams = self.ok(self.admin.get(f"/orgs/t-{tenant}/teams/search", params={"q": "members"})).json()["data"]
        return next(t["id"] for t in teams if t["name"] == "members")

    def team_members(self, tenant: str) -> set[str]:
        return {u["login"] for u in self.ok(self.admin.get(f"/teams/{self.team_id(tenant)}/members")).json()}

    def build_tenant_forge(self, tenant: str) -> None:
        """Organisation `t-<T>` with team `members` (write, no org-wide repository rights) holding repo `knowledge`, and
        the stand-in bot a collaborator with write."""
        org = f"t-{tenant}"
        self.ok(self.admin.post("/orgs", json={"username": org, "visibility": "private"}))
        self.ok(self.admin.post(f"/orgs/{org}/teams", json={
            "name": "members", "permission": "write", "includes_all_repositories": False, "can_create_org_repo": False,
            "units": ["repo.code", "repo.pulls", "repo.issues"]}))
        self.ok(self.admin.post(f"/orgs/{org}/repos", json={"name": "knowledge", "private": True, "auto_init": True,
                                                            "default_branch": "main", "readme": "Default"}))
        self.ok(self.admin.put(f"/teams/{self.team_id(tenant)}/repos/{org}/knowledge"))
        self.ok(self.admin.put(f"/repos/{org}/knowledge/collaborators/live-bot", json={"permission": "write"}))

    def put_file(self, repo: str, path: str, content: bytes, *, branch: str = "main", new_branch: str | None = None) -> None:
        import base64

        body: dict[str, Any] = {"content": base64.b64encode(content).decode(), "branch": branch, "message": f"add {path}"}
        if new_branch:
            body["new_branch"] = new_branch
        self.ok(self.admin.post(f"/repos/{repo}/contents/{path}", json=body))

    # Keycloak and the edge ---------------------------------------------------------------------------
    def keycloak_person(self) -> tuple[str, str]:
        """(sub, username) of a new Keycloak user with a password."""
        return self.keycloak.create_user(otp=False)

    def browse(self, path: str, *, client: httpx.Client | None = None, username: str | None = None, hops: int = 12) -> Visit:
        """GET `path` on the edge site and follow redirects by hand across Forgejo and Keycloak, filling Keycloak's login
        form as `username` when it is asked. `client` (a `Visit.client`) carries the cookies of earlier visits."""
        client = client or httpx.Client(base_url=self.edge, timeout=30, follow_redirects=False)
        visit = Visit(client)
        response = client.get(path)
        for _ in range(hops):
            visit.trail.append((response.request.method, str(response.request.url), response.status_code))
            visit.final = response
            if response.is_redirect:
                response = client.get(urllib.parse.urljoin(str(response.url), response.headers["location"]))
                continue
            form = _FORM_ACTION.search(response.text) if response.status_code == 200 else None
            if form and username:
                data = {"username": username, "password": PASSWORD}
                response = client.post(html.unescape(form.group(1)), data=data)
                username = None  # one attempt: a second form means the credentials were refused
                continue
            break
        return visit

    def sign_in(self, username: str) -> Visit:
        """A person's sign-in at Forgejo through the edge: the start path, Keycloak's form, the callback."""
        visit = self.browse("/user/oauth2/product", username=username)
        assert visit.cookie_header(), f"no Forgejo session cookie after sign-in: {visit.trail}"
        return visit


def new_tenant_id() -> str:
    return str(uuid.uuid4())


NOW = dt.datetime(2026, 11, 21, 12, 0, tzinfo=dt.UTC)
