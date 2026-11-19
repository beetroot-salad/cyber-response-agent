# ruff: noqa: PT018 — each compound assert states one fact about one response
"""#1161 B8, D6 on the real dev Keycloak (`live`): two sign-ins of one browser in either order (C38, D6's reopening
trigger), an OTP sign-in's `amr`, and the account shapes `FakeKeycloak` models without having observed them (the credential
list, the user `GET` and `PUT`). CI's `keycloak-live` job runs it against the dev compose Keycloak (#1566). With
`DEFENDER_LIVE_KEYCLOAK_URL` unset it skips; once it names a Keycloak, a missing Playwright fails rather than skips.

Inputs (test-only environment; the realm is the committed export, whose client secrets and redirect URI are read from it):

    DEFENDER_LIVE_KEYCLOAK_URL   the dev Keycloak with the realm imported, e.g. http://keycloak:8080

    PYTHONPATH="$PWD" defender/.venv/bin/python -m pytest -m live defender/tests/identity/test_live_keycloak_1161.py

Playwright (and its Chromium) must be importable; the sign-in is the one the API sends: `prompt=login`, PKCE S256,
`scope=openid profile`, the callback's address answered by the test (no server there)."""
from __future__ import annotations

import base64
import fcntl
import hashlib
import hmac
import http.server
import json
import os
import re
import struct
import tempfile
import threading
import time
import urllib.parse
import uuid
from collections.abc import Iterator
from typing import Any

import httpx
import pytest

from defender._git import REPO_ROOT
from defender.tests.identity.test_identity_realm_export import THEME, THEME_NAME, stylesheet_references, theme_properties

pytestmark = pytest.mark.live

REALM = "defender"
PASSWORD = "live-1161-pw"
#: The people we create carry a throwaway TOTP secret, stored as Keycloak stores it (raw text, whose bytes are the
#: HMAC key); a code for it is computed here.
TOTP_SECRET = "live-1161-totp-seed!"


def _realm_export() -> dict[str, Any]:
    return json.loads((REPO_ROOT / ".devcontainer" / "keycloak" / "realm-defender.json").read_text(encoding="utf-8"))


def _client(realm: dict[str, Any], client_id: str) -> dict[str, Any]:
    return next(c for c in realm["clients"] if c["clientId"] == client_id)


def _totp(secret: str, at: float | None = None) -> str:
    key = secret.encode()
    counter = int((time.time() if at is None else at) // 30)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    return f"{(struct.unpack('>I', digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 10**6:06d}"


class Live:
    """The Keycloak, the sign-in client as the API uses it, and the admin client as the identity service uses it."""

    def __init__(self, base: str) -> None:
        realm = _realm_export()
        self.base = base.rstrip("/")
        self.realm_url = f"{self.base}/realms/{REALM}"
        sign_in, admin = _client(realm, "defender-api"), _client(realm, "defender-api-admin")
        self.client = (sign_in["clientId"], sign_in["secret"])
        self.callback = sign_in["redirectUris"][0]
        token = httpx.post(f"{self.realm_url}/protocol/openid-connect/token", auth=(admin["clientId"], admin["secret"]),
                           data={"grant_type": "client_credentials"})
        assert token.status_code == 200, token.text
        self.admin = {"Authorization": f"Bearer {token.json()['access_token']}"}
        self.users = f"{self.base}/admin/realms/{REALM}/users"

    def create_user(self, *, otp: bool) -> tuple[str, str]:
        """(id, username) of a new enabled user with a password, and a TOTP credential when `otp`."""
        name = f"live-1161-{uuid.uuid4().hex[:10]}"
        credentials: list[dict[str, Any]] = [{"type": "password", "value": PASSWORD, "temporary": False}]
        if otp:
            credentials.append({"type": "otp", "secretData": json.dumps({"value": TOTP_SECRET}), "credentialData": json.dumps(
                {"subType": "totp", "digits": 6, "period": 30, "algorithm": "HmacSHA1"})})
        made = httpx.post(self.users, headers=self.admin, json={
            "username": name, "email": f"{name}@live.example", "emailVerified": True, "enabled": True,
            "firstName": "Live", "lastName": "Check", "credentials": credentials})
        assert made.status_code == 201, (made.status_code, made.text)
        return made.headers["location"].rsplit("/", 1)[1], name

    def delete_user(self, user_id: str) -> None:
        httpx.delete(f"{self.users}/{user_id}", headers=self.admin)

    def authorize_url(self, state: str, nonce: str, challenge: str) -> str:
        """The sign-in start's authorize URL, as `KeycloakSignIn.begin_signin` builds it."""
        query = {"response_type": "code", "client_id": self.client[0], "redirect_uri": self.callback,
                 "scope": "openid profile", "state": state, "nonce": nonce, "prompt": "login",
                 "code_challenge": challenge, "code_challenge_method": "S256"}
        return f"{self.realm_url}/protocol/openid-connect/auth?{urllib.parse.urlencode(query)}"

    def exchange(self, code: str, verifier: str) -> httpx.Response:
        return httpx.post(f"{self.realm_url}/protocol/openid-connect/token", auth=self.client, data={
            "grant_type": "authorization_code", "code": code, "code_verifier": verifier, "redirect_uri": self.callback})


@pytest.fixture
def live() -> Live:
    url = os.environ.get("DEFENDER_LIVE_KEYCLOAK_URL")
    if not url:
        if os.environ.get("CI"):  # CI's keycloak-live job: a check that cannot run is a failure (#1566)
            pytest.fail("DEFENDER_LIVE_KEYCLOAK_URL is not set in CI")
        pytest.skip("set DEFENDER_LIVE_KEYCLOAK_URL (the dev Keycloak with the defender realm imported)")
    return Live(url)


@pytest.fixture
def person(live: Live) -> Iterator[tuple[str, str]]:
    user_id, name = live.create_user(otp=False)
    try:
        yield user_id, name
    finally:
        live.delete_user(user_id)


def _pkce() -> tuple[str, str]:
    verifier = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
    return verifier, base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()


def _claims(id_token: str) -> dict[str, Any]:
    payload = id_token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))


class Browser:
    """One Chromium context whose callback address is answered by the test, so a tab ends there with its `code`."""

    def __init__(self, live: Live, pw: Any) -> None:
        self.live = live
        self.chromium = pw.chromium.launch()
        self.fresh()

    def fresh(self) -> None:
        """A new browser profile: no session of an earlier person (Keycloak keeps one and re-asks only its password)."""
        self.context = self.chromium.new_context()
        self.context.set_default_timeout(30_000)

    def open(self, state: str) -> tuple[Any, str, str]:
        """A tab on the sign-in form of attempt `state`; its page, PKCE verifier and nonce."""
        verifier, challenge = _pkce()
        nonce = f"n-{state}"
        page = self.context.new_page()
        page.goto(self.live.authorize_url(state, nonce, challenge))
        return page, verifier, nonce

    def submit(self, page: Any, username: str, otp: str | None = None) -> dict[str, str]:
        """Fill and submit whichever form the tab shows until it reaches the callback; the callback's query."""
        for _ in range(4):
            if page.url.startswith(self.live.callback):
                break
            if page.locator("#username").count() and page.locator("#username").is_editable():
                page.fill("#username", username)
            if page.locator("#password").count():
                page.fill("#password", PASSWORD)
            elif otp is not None and page.locator("#otp").count():
                page.fill("#otp", otp)
            else:
                raise AssertionError(f"no form to submit at {page.url}: {page.inner_text('body')[:200]!r}")
            try:
                with page.expect_navigation(timeout=15_000):
                    page.click("#kc-login")
            except Exception:  # noqa: BLE001 — a form that re-renders in place: look again
                continue
        assert page.url.startswith(self.live.callback), (page.url, page.inner_text("body")[:200])
        return dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(page.url).query))

    def close(self) -> None:
        self.chromium.close()


class _Answers(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 — the callback address answers anything
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"callback")

    def log_message(self, *args: Any) -> None:
        pass


@pytest.fixture
def browser(live: Live) -> Iterator[Browser]:
    """A Chromium, and a listener on the registered callback's address (held under a file lock: one test at a time)."""
    from playwright import sync_api  # a named Keycloak with no Playwright is a failure, never a skip (#1566)
    callback = urllib.parse.urlsplit(live.callback)
    with open(os.path.join(tempfile.gettempdir(), "defender-live-1161-callback.lock"), "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        server = http.server.HTTPServer(("127.0.0.1", callback.port or 80), _Answers)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            with sync_api.sync_playwright() as pw:
                opened = Browser(live, pw)
                try:
                    yield opened
                finally:
                    opened.close()
        finally:
            server.shutdown()
            server.server_close()


@pytest.mark.parametrize("order", ["AB", "BA"])
def test_1161_c38_two_sign_ins_of_one_browser_each_complete_to_their_own_state_in_either_order(
        live, person, browser, order):
    """Two tabs open before either submits, completed in `order`: each callback carries its own `state` and a code that
    exchanges to an ID token for this person with its own `nonce`. (C38, D6, B8)"""
    user_id, name = person
    tabs = {state: browser.open(state) for state in "AB"}
    for state in order:
        page, verifier, nonce = tabs[state]
        query = browser.submit(page, name)
        assert query["state"] == state, query
        token = live.exchange(query["code"], verifier)
        assert token.status_code == 200, (state, token.text)
        claims = _claims(token.json()["id_token"])
        assert (claims["sub"], claims["nonce"]) == (user_id, nonce)


def test_1161_b8_an_otp_sign_in_lists_pwd_and_otp_in_amr_and_a_password_one_only_pwd(live, browser):
    """The realm's `amr` mapper: the claim is a list, `["pwd", "otp"]` after a code was entered, `["pwd"]` before. (A1, C13)"""
    with_otp, name_otp = live.create_user(otp=True)
    without, name_pwd = live.create_user(otp=False)
    try:
        page, verifier, _ = browser.open("otp")
        query = browser.submit(page, name_otp, otp=_totp(TOTP_SECRET))
        claims = _claims(live.exchange(query["code"], verifier).json()["id_token"])
        assert (claims["sub"], claims["amr"]) == (with_otp, ["pwd", "otp"])
        browser.fresh()
        page, verifier, _ = browser.open("pwd")
        query = browser.submit(page, name_pwd)
        claims = _claims(live.exchange(query["code"], verifier).json()["id_token"])
        assert (claims["sub"], claims["amr"]) == (without, ["pwd"])
    finally:
        live.delete_user(with_otp)
        live.delete_user(without)


def test_1161_the_credential_list_and_user_record_have_the_shapes_the_fake_models(live, person):
    """What `has_otp` and `require_otp_setup` rely on, and what `FakeKeycloak` answers: the credential list is a list of
    `{id, type, createdDate}`; the user record has `requiredActions`; a `PUT` of it back with one more action is a 204 and reads back. (R11)"""
    user_id, _ = person
    url = f"{live.users}/{user_id}"
    listed = httpx.get(f"{url}/credentials", headers=live.admin)
    assert listed.status_code == 200 and isinstance(listed.json(), list), listed.text
    assert [c["type"] for c in listed.json()] == ["password"]
    assert {"id", "type", "createdDate"} <= set(listed.json()[0]), listed.json()[0]
    record = httpx.get(url, headers=live.admin)
    assert record.status_code == 200, record.text
    user = record.json()
    assert user["id"] == user_id and user.get("requiredActions", []) == []
    user["requiredActions"] = ["CONFIGURE_TOTP"]
    put = httpx.put(url, headers=live.admin, json=user)
    assert put.status_code == 204, (put.status_code, put.text)
    assert httpx.get(url, headers=live.admin).json()["requiredActions"] == ["CONFIGURE_TOTP"]
    assert httpx.get(f"{live.users}/{uuid.uuid4()}/credentials", headers=live.admin).status_code == 404  # an unknown id


def test_1540_f5_the_dev_login_page_links_the_theme_stylesheet_and_serves_it_and_its_images(live):
    """The dev realm's login page links the parent's stylesheet then the theme's own, each answers 200, and so does
    every file the theme's stylesheet references (the illustration, the tokens). (F5, C10)"""
    state, nonce, challenge = "1540", "1540", _pkce()[1]
    page = httpx.get(live.authorize_url(state, nonce, challenge), follow_redirects=True)
    assert page.status_code == 200, page.text[:300]
    parent_styles, own = theme_properties(THEME)["styles"].split()
    tags = [t for t in re.findall(r"<link\b[^>]*>", page.text) if 'rel="stylesheet"' in t]
    served = [urllib.parse.urlsplit(m.group(1)).path for t in tags if (m := re.search(r'href="([^"]+)"', t))]
    ends = {name: [p for p in served if p.endswith(f"/login/{THEME_NAME}/{name}")] for name in (parent_styles, own)}
    assert all(ends.values()), f"the login page links {served}; expected the theme's {parent_styles} and {own}"
    order = [p for p in served if p in {ends[parent_styles][0], ends[own][0]}]
    assert order == [ends[parent_styles][0], ends[own][0]], order
    sheet_url = live.base + ends[own][0]
    sheet = httpx.get(sheet_url)
    assert sheet.status_code == 200, (sheet_url, sheet.status_code)
    assert httpx.get(live.base + ends[parent_styles][0]).status_code == 200
    refs = stylesheet_references(sheet.text)
    assert refs, "the theme's stylesheet references its illustration and tokens"
    answers = {ref: httpx.get(urllib.parse.urljoin(sheet_url, ref)).status_code for ref in refs}
    assert set(answers.values()) == {200}, answers
