"""#1306 DC-8 — the Keycloak sign-in adapter, driven through an injected HTTP transport that plays
Keycloak's endpoints as probed in C9/C13. No Keycloak runs; ID tokens are signed with RS256 keys
minted here. The tests read what the transport RECEIVED, not only what the adapter returned.
"""
from __future__ import annotations

import base64
import dataclasses
import datetime as dt
import hashlib
import hmac
import json
import urllib.parse
from collections.abc import AsyncIterator, Callable
from typing import Any, cast

import httpx
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

# Production names (Pinned interface): a missing module is the expected red.
from defender.identity import SignInRefused, SignInUnavailable, VerifiedSignIn
from defender.tests.support.api._server1083 import (
    ADMIN_CLIENTS,
    ADMIN_READ,
    BACK,
    ELSEWHERE_ISSUER,
    FAULTS,
    FRONT,
    PROGRAMS_REALM,
    REALMS,
    SIGNIN_REALM,
    STEP_KINDS,
    STEPS,
    Fail,
    FakeKeycloak,
    closed_port,
    realms_named,
)
from defender.identity.keycloak import KeycloakPrograms, KeycloakSignIn

pytestmark = pytest.mark.anyio

NOW = dt.datetime(2026, 10, 26, 9, 0, tzinfo=dt.UTC)
BASE = "https://kc.test"
REALM = "defender"
ISSUER = f"{BASE}/realms/{REALM}"
CLIENT_ID = "defender-api"
CLIENT_SECRET = "api-secret"
ADMIN_CLIENT_ID = "defender-api-admin"
ADMIN_CLIENT_SECRET = "admin-secret"
REDIRECT_URI = "https://api.defender.test/auth/callback"
ADMIN_TOKEN = "admin-access-token"
SEVEN_DAYS = dt.timedelta(days=7)
KID = "kid-1"
ACCOUNT = "9f0c1c9e-1111-4222-8333-444455556666"
USER_ID = "7d1a2b3c-aaaa-4bbb-8ccc-ddddeeeeffff"


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _int_b64(value: int) -> str:
    return _b64(value.to_bytes((value.bit_length() + 7) // 8, "big"))


class Signer:
    """One RS256 key pair and the JWKS entry that publishes it."""

    def __init__(self, kid: str = KID) -> None:
        self.kid = kid
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def jwk(self) -> dict:
        numbers = self.key.public_key().public_numbers()
        return {"kty": "RSA", "use": "sig", "alg": "RS256", "kid": self.kid,
                "n": _int_b64(numbers.n), "e": _int_b64(numbers.e)}

    def public_pem(self) -> bytes:
        return self.key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)

    def sign(self, claims: dict, *, kid: str | None = None) -> str:
        head = _b64(json.dumps({"alg": "RS256", "typ": "JWT", "kid": kid or self.kid}).encode())
        body = _b64(json.dumps(claims).encode())
        sig = self.key.sign(f"{head}.{body}".encode(), padding.PKCS1v15(), hashes.SHA256())
        return f"{head}.{body}.{_b64(sig)}"


def claims(**over) -> dict:
    base = {"iss": ISSUER, "aud": CLIENT_ID, "sub": ACCOUNT, "nonce": "n1", "name": "Ada Ops",
            "iat": int(NOW.timestamp()) - 60, "exp": int(NOW.timestamp()) + 300, "amr": ["pwd"]}
    base.update(over)
    return {k: v for k, v in base.items() if v is not None}


@dataclasses.dataclass
class Seen:
    method: str
    path: str
    query: dict[str, list[str]]
    headers: httpx.Headers
    body: bytes

    def json(self):
        return json.loads(self.body)

    def form(self) -> dict[str, str]:
        return {k: v[0] for k, v in urllib.parse.parse_qs(self.body.decode()).items()}


class _AsyncOnly(httpx.AsyncBaseTransport):
    """Serves async clients only: a sync `httpx.Client` over it has no `handle_request` to call."""

    def __init__(self, handler: Callable[[httpx.Request], httpx.Response]) -> None:
        self._handler = handler

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        await request.aread()
        return self._handler(request)


class Keycloak:
    """Keycloak's endpoints as a transport. `id_token` is what the token endpoint hands out."""

    def __init__(self, signer: Signer) -> None:
        self.signer = signer
        self.jwks_keys = [signer.jwk()]
        self.id_token = ""
        self.token_status = 200
        self.seen: list[Seen] = []
        self.opened: list[KeycloakSignIn] = []
        self.users: dict[str, str] = {}  # username -> id
        self.create_status = 201
        self.email_status = 204
        self.credentials: list[dict] = []
        self.required_actions: list[str] = []
        self.new_id = USER_ID
        #: Raised by the transport (not answered) on the admin API / on the admin token request.
        self.admin_error: Exception | None = None
        self.token_error: Exception | None = None
        #: When set, the HTTP status every admin API call / the admin token request answers with.
        self.admin_status: int | None = None
        self.admin_token_status: int | None = None
        #: The admin token's stated `expires_in`, in seconds; unset, the answer carries none.
        self.admin_token_lifetime: int | None = None

    # --- the transport ---------------------------------------------------------------------
    def transport(self) -> httpx.AsyncBaseTransport:
        return _AsyncOnly(self._handle)

    def _handle(self, request: httpx.Request) -> httpx.Response:  # noqa: C901, PLR0912
        url = request.url
        self.seen.append(Seen(request.method, url.path, urllib.parse.parse_qs(url.query.decode()),
                              request.headers, request.content))
        path, method = url.path, request.method
        if path == f"/realms/{REALM}/.well-known/openid-configuration":
            return httpx.Response(200, json={
                "issuer": ISSUER,
                "authorization_endpoint": f"{ISSUER}/protocol/openid-connect/auth",
                "token_endpoint": f"{ISSUER}/protocol/openid-connect/token",
                "jwks_uri": f"{ISSUER}/protocol/openid-connect/certs"})
        if path == f"/realms/{REALM}/protocol/openid-connect/certs":
            return httpx.Response(200, json={"keys": self.jwks_keys})
        if path == f"/realms/{REALM}/protocol/openid-connect/token":
            form = urllib.parse.parse_qs(request.content.decode())
            if form.get("grant_type") == ["client_credentials"]:
                if self.token_error:
                    raise self.token_error
                if self.admin_token_status is not None:
                    return httpx.Response(self.admin_token_status, json={"error": "unauthorized_client"})
                granted = {"access_token": ADMIN_TOKEN, "token_type": "Bearer"}
                if self.admin_token_lifetime is not None:
                    granted["expires_in"] = self.admin_token_lifetime
                return httpx.Response(200, json=granted)
            if self.token_status != 200:
                return httpx.Response(self.token_status, json={"error": "invalid_grant"})
            return httpx.Response(200, json={"access_token": "kc-access-secret", "token_type": "Bearer",
                                             "refresh_token": "kc-refresh-secret", "id_token": self.id_token})
        admin = f"/admin/realms/{REALM}/users"
        if not path.startswith(admin):
            return httpx.Response(404)
        if request.headers.get("authorization") != f"Bearer {ADMIN_TOKEN}":
            return httpx.Response(401)
        if self.admin_error:
            raise self.admin_error
        if self.admin_status is not None:
            return httpx.Response(self.admin_status, json={"error": "scripted"})
        rest = path[len(admin):]
        if rest == "" and method == "POST":
            body = json.loads(request.content)
            if self.create_status == 201:
                self.users[body["username"]] = self.new_id
                return httpx.Response(201, headers={"Location": f"{BASE}{admin}/{self.new_id}"})
            return httpx.Response(self.create_status, json={"errorMessage": "exists"})
        if rest == "" and method == "GET":
            wanted = url.params["username"]
            exact = url.params.get("exact") == "true"
            hits = [{"id": i, "username": u} for u, i in self.users.items()
                    if (u == wanted if exact else wanted in u)]
            return httpx.Response(200, json=hits)
        if rest.endswith("/execute-actions-email") and method == "PUT":
            return httpx.Response(self.email_status)
        if rest.endswith("/credentials") and method == "GET":
            return httpx.Response(200, json=self.credentials)
        if method == "GET":
            return httpx.Response(200, json={"id": rest[1:], "requiredActions": self.required_actions})
        if method == "PUT":
            return httpx.Response(204)
        return httpx.Response(404)

    # --- views -------------------------------------------------------------------------------
    def calls(self, method: str, suffix: str) -> list[Seen]:
        return [s for s in self.seen if s.method == method and s.path.endswith(suffix)]

    def admin_writes(self) -> list[Seen]:
        return [s for s in self.seen if s.path.startswith("/admin/") and s.method != "GET"]


@pytest.fixture
async def kc() -> AsyncIterator[Keycloak]:
    """The fake Keycloak; every adapter a test builds on it is closed in the test's loop afterwards."""
    fake = Keycloak(Signer())
    try:
        yield fake
    finally:
        for port in fake.opened:
            await port.close()


def adapter(kc: Keycloak, *, now: dt.datetime = NOW, clock: Callable[[], dt.datetime] | None = None) -> KeycloakSignIn:
    port = KeycloakSignIn(
        issuer=ISSUER, client_id=CLIENT_ID, client_secret=CLIENT_SECRET, redirect_uri=REDIRECT_URI,
        admin_client_id=ADMIN_CLIENT_ID, admin_client_secret=ADMIN_CLIENT_SECRET,
        transport=kc.transport(), clock=clock or (lambda: now))
    kc.opened.append(port)
    return port


async def sign_in(kc: Keycloak, token: str, *, nonce: str = "n1") -> VerifiedSignIn:
    kc.id_token = token
    port = adapter(kc)
    await port.begin_signin(state="s1", nonce=nonce, code_challenge="chal")
    return await port.finish_signin(code="code-1", code_verifier="verifier-1", nonce=nonce)


# --- begin_signin ----------------------------------------------------------------------------

async def test_begin_signin_url_carries_the_pkce_login_prompt_and_the_configured_client(kc):
    """The sign-in URL forces the password prompt and PKCE S256 (DC-8, C12)."""
    url = urllib.parse.urlsplit(await adapter(kc).begin_signin(state="st-9", nonce="no-9", code_challenge="ch-9"))
    query = urllib.parse.parse_qs(url.query)
    assert f"{url.scheme}://{url.netloc}{url.path}" == f"{ISSUER}/protocol/openid-connect/auth"
    assert query["prompt"] == ["login"]
    assert query["code_challenge_method"] == ["S256"]
    assert query["code_challenge"] == ["ch-9"]
    assert query["state"] == ["st-9"]
    assert query["nonce"] == ["no-9"]
    assert query["redirect_uri"] == [REDIRECT_URI]
    assert query["client_id"] == [CLIENT_ID]
    assert query["response_type"] == ["code"]
    assert "openid" in query["scope"][0].split()
    assert CLIENT_SECRET not in url.query


# --- finish_signin: the positive control and what the token endpoint received --------------

async def test_finish_signin_exchanges_the_code_with_its_verifier_and_returns_the_verified_identity(kc):
    """A correctly signed token yields VerifiedSignIn; the code, verifier and redirect_uri are sent (DC-8)."""
    result = await sign_in(kc, kc.signer.sign(claims(amr=["pwd", "otp"])))
    assert result == VerifiedSignIn(account_id=ACCOUNT, name="Ada Ops", amr=("pwd", "otp"))
    [sent] = [s for s in kc.calls("POST", "/openid-connect/token")
              if s.form().get("grant_type") == "authorization_code"]
    form = sent.form()
    assert (form["code"], form["code_verifier"], form["redirect_uri"]) == ("code-1", "verifier-1", REDIRECT_URI)
    basic = "Basic " + base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()
    assert sent.headers.get("authorization") == basic or (
        form.get("client_id"), form.get("client_secret")) == (CLIENT_ID, CLIENT_SECRET)


def _holds(obj: object, needle: str) -> bool:
    """Does `needle` occur in what `obj` keeps: its attributes, walked through containers and
    defender objects (not into third-party objects such as the HTTP client)."""
    seen: set[int] = set()
    todo: list[object] = [obj]
    while todo:
        o = todo.pop()
        if id(o) in seen:
            continue
        seen.add(id(o))
        if isinstance(o, str) and needle in o or isinstance(o, bytes | bytearray) and needle.encode() in o:
            return True
        if isinstance(o, dict):
            todo += [*o.keys(), *o.values()]
        elif isinstance(o, list | tuple | set | frozenset):
            todo += list(o)
        elif type(o).__module__.startswith("defender."):
            todo += list(getattr(o, "__dict__", {}).values())
            todo += [getattr(o, n, None) for k in type(o).__mro__ for n in getattr(k, "__slots__", ())]
    return False


async def test_keycloaks_tokens_never_leave_the_adapter(kc):
    """The result carries only account_id, name and amr, and the adapter keeps none of Keycloak's tokens (O6, K7/H5)."""
    kc.id_token = kc.signer.sign(claims())
    port = adapter(kc)
    await port.begin_signin(state="s1", nonce="n1", code_challenge="chal")
    result = await port.finish_signin(code="code-1", code_verifier="verifier-1", nonce="n1")
    assert {f.name for f in dataclasses.fields(result)} == {"account_id", "name", "amr"}
    leaked = repr(result) + json.dumps(dataclasses.asdict(result))
    assert _holds(port, CLIENT_SECRET)  # control: the walk reaches what the adapter holds
    for secret in ("kc-access-secret", "kc-refresh-secret", kc.id_token):
        assert secret not in leaked
        assert not _holds(port, secret)


async def test_a_token_without_amr_reports_no_methods_and_so_no_otp(kc):
    """A missing amr is the empty tuple, not an error and not otp (C13)."""
    assert (await sign_in(kc, kc.signer.sign(claims(amr=None)))).amr == ()


async def test_a_token_without_a_name_reports_no_name_not_the_username(kc):
    """`preferred_username` is the id our own code gave the account, never a display name."""
    assert (await sign_in(kc, kc.signer.sign(claims(name=None, preferred_username=USER_ID)))).name == ""


async def test_an_audience_list_that_contains_the_client_is_accepted(kc):
    """Positive control for the audience refusal: aud may be a list holding our client id."""
    assert (await sign_in(kc, kc.signer.sign(claims(aud=["account", CLIENT_ID])))).account_id == ACCOUNT


# --- finish_signin: refusals (each paired with the control above on the same fixture) -------

def _foreign_key_token(kc: Keycloak) -> str:
    return Signer().sign(claims())  # right kid, wrong key


def _hs256_with_public_key(kc: Keycloak) -> str:
    head = _b64(json.dumps({"alg": "HS256", "typ": "JWT", "kid": KID}).encode())
    body = _b64(json.dumps(claims()).encode())
    mac = hmac.new(kc.signer.public_pem(), f"{head}.{body}".encode(), hashlib.sha256).digest()
    return f"{head}.{body}.{_b64(mac)}"


def _unsigned(kc: Keycloak) -> str:
    head = _b64(json.dumps({"alg": "none", "typ": "JWT", "kid": KID}).encode())
    return f"{head}.{_b64(json.dumps(claims()).encode())}."


@pytest.mark.parametrize("make", [
    pytest.param(_foreign_key_token, id="bad-signature"),
    pytest.param(lambda kc: kc.signer.sign(claims(), kid="unknown-kid"), id="unknown-kid"),
    pytest.param(lambda kc: kc.signer.sign(claims(iss="https://evil.test/realms/defender")), id="wrong-issuer"),
    pytest.param(lambda kc: kc.signer.sign(claims(iss=f"{BASE}/realms/other-realm")), id="same-host-other-realm"),
    pytest.param(lambda kc: kc.signer.sign(claims(iss=f"{ISSUER}-other")), id="issuer-sharing-our-prefix"),
    pytest.param(lambda kc: kc.signer.sign(claims(aud="some-other-client")), id="wrong-audience"),
    pytest.param(lambda kc: kc.signer.sign(claims(aud=["account", "other"])), id="audience-list-without-us"),
    pytest.param(lambda kc: kc.signer.sign(claims(aud=ADMIN_CLIENT_ID)), id="audience-containing-our-id"),
    pytest.param(lambda kc: kc.signer.sign(claims(aud=["account", "x" + CLIENT_ID])), id="audience-list-lookalike"),
    pytest.param(lambda kc: kc.signer.sign(claims(exp=None)), id="missing-exp"),
    pytest.param(lambda kc: kc.signer.sign(claims(nonce="n-other")), id="wrong-nonce"),
    pytest.param(lambda kc: kc.signer.sign(claims(nonce=None)), id="missing-nonce"),
    pytest.param(lambda kc: kc.signer.sign(claims(exp=int(NOW.timestamp()) - 1)), id="expired"),
    pytest.param(_hs256_with_public_key, id="hs256-confusion"),
    pytest.param(_unsigned, id="alg-none"),
    pytest.param(lambda kc: kc.signer.sign(claims(sub=None)), id="no-subject"),
])
async def test_finish_signin_refuses_a_token_that_fails_verification(kc, make):
    """Signature, key id, issuer, audience, nonce, expiry and algorithm are all checked (DC-8)."""
    kc.id_token = make(kc)
    port = adapter(kc)
    await port.begin_signin(state="s1", nonce="n1", code_challenge="chal")
    with pytest.raises(SignInRefused):
        await port.finish_signin(code="code-1", code_verifier="verifier-1", nonce="n1")


async def test_finish_signin_refuses_when_keycloak_rejects_the_code(kc):
    """A failed code exchange is a refusal, not a crash and not an identity."""
    kc.token_status = 400
    kc.id_token = kc.signer.sign(claims())
    port = adapter(kc)
    with pytest.raises(SignInRefused):
        await port.finish_signin(code="used-code", code_verifier="verifier-1", nonce="n1")


async def test_the_nonce_the_caller_passes_is_the_one_checked(kc):
    """A token whose nonce matches the token endpoint's note but not the caller's is refused."""
    kc.id_token = kc.signer.sign(claims(nonce="n1"))
    with pytest.raises(SignInRefused):
        await adapter(kc).finish_signin(code="c", code_verifier="v", nonce="n-from-our-cookie")
    assert (await adapter(kc).finish_signin(code="c", code_verifier="v", nonce="n1")).account_id == ACCOUNT


# --- the admin API ----------------------------------------------------------------------------

async def test_create_account_sends_our_user_id_as_username_verified_with_mapped_required_actions(kc):
    """username = our user id, emailVerified, set_password/set_up_otp -> UPDATE_PASSWORD/CONFIGURE_TOTP (C9)."""
    account = await adapter(kc).create_account(
        username=USER_ID, email="ada@example.test", required_actions=frozenset({"set_password", "set_up_otp"}))
    assert account == USER_ID
    [sent] = kc.calls("POST", f"/admin/realms/{REALM}/users")
    body = sent.json()
    assert body["username"] == USER_ID
    assert body["email"] == "ada@example.test"
    assert body["emailVerified"] is True
    assert body["enabled"] is True
    assert sorted(body["requiredActions"]) == ["CONFIGURE_TOTP", "UPDATE_PASSWORD"]
    assert sent.headers["authorization"] == f"Bearer {ADMIN_TOKEN}"
    [grant] = [s for s in kc.calls("POST", "/openid-connect/token") if s.form()["grant_type"] == "client_credentials"]
    basic = "Basic " + base64.b64encode(f"{ADMIN_CLIENT_ID}:{ADMIN_CLIENT_SECRET}".encode()).decode()
    form = grant.form()
    if "client_id" in form:  # A1: the service account authenticates as itself, never as the sign-in client
        assert (form["client_id"], form.get("client_secret")) == (ADMIN_CLIENT_ID, ADMIN_CLIENT_SECRET)
        assert "authorization" not in grant.headers
    else:
        assert grant.headers.get("authorization") == basic


async def test_create_account_with_only_set_password_requires_no_otp_setup(kc):
    """A plain invitee is not made to set up a one-time code (r6 flow 1)."""
    await adapter(kc).create_account(username=USER_ID, email="a@example.test", required_actions=frozenset({"set_password"}))
    [sent] = kc.calls("POST", f"/admin/realms/{REALM}/users")
    assert sent.json()["requiredActions"] == ["UPDATE_PASSWORD"]


async def test_create_account_reads_the_new_id_from_the_location_header(kc):
    """The returned account id is the one Keycloak chose (P-B)."""
    kc.new_id = "kc-chosen-id"
    assert await adapter(kc).create_account(
        username=USER_ID, email="a@example.test", required_actions=frozenset({"set_password"})) == "kc-chosen-id"


async def test_a_conflict_on_create_finds_the_existing_account_by_exact_username(kc):
    """Create-or-find: a retry gets the same account, never a username-prefix lookalike (P-C)."""
    kc.users = {USER_ID + "0": "decoy-id", USER_ID: "existing-id"}
    kc.create_status = 409
    account = await adapter(kc).create_account(
        username=USER_ID, email="a@example.test", required_actions=frozenset({"set_password"}))
    assert account == "existing-id"
    [lookup] = kc.calls("GET", f"/admin/realms/{REALM}/users")
    assert lookup.query["username"] == [USER_ID]
    assert lookup.query["exact"] == ["true"]


async def test_a_conflict_with_no_account_of_that_username_is_not_papered_over(kc):
    """A 409 caused by someone else's email must not return a wrong id."""
    kc.create_status = 409
    with pytest.raises(SignInUnavailable):
        await adapter(kc).create_account(username=USER_ID, email="a@example.test", required_actions=frozenset())


async def test_send_set_password_email_asks_for_a_seven_day_action_link_for_that_account(kc):
    """PUT .../execute-actions-email?lifespan=604800 with UPDATE_PASSWORD (C9)."""
    await adapter(kc).send_set_password_email(USER_ID, lifespan=SEVEN_DAYS)
    [sent] = kc.calls("PUT", "/execute-actions-email")
    assert sent.path == f"/admin/realms/{REALM}/users/{USER_ID}/execute-actions-email"
    assert sent.query["lifespan"] == ["604800"]
    assert sent.json() == ["UPDATE_PASSWORD"]
    assert sent.headers["authorization"] == f"Bearer {ADMIN_TOKEN}"


async def test_a_failed_email_send_is_reported_so_the_sender_keeps_it_pending(kc):
    """Keycloak refusing the send raises; success (above) does not (r6 flow 1 retry)."""
    kc.email_status = 500
    with pytest.raises(SignInUnavailable):
        await adapter(kc).send_set_password_email(USER_ID, lifespan=SEVEN_DAYS)


_TRANSPORT_ERRORS = [
    pytest.param(httpx.ConnectError("connection refused"), id="connect-error"),
    pytest.param(httpx.ReadTimeout("timed out"), id="read-timeout"),
]
_ADMIN_CALLS = {
    "send_set_password_email": lambda port: port.send_set_password_email(USER_ID, lifespan=SEVEN_DAYS),
    "create_account": lambda port: port.create_account(
        username=USER_ID, email="a@example.test", required_actions=frozenset({"set_password"})),
    "has_otp": lambda port: port.has_otp(USER_ID),
    "require_otp_setup": lambda port: port.require_otp_setup(USER_ID),
}


@pytest.mark.parametrize("where", ["admin-api", "admin-token"])
@pytest.mark.parametrize("call", sorted(_ADMIN_CALLS))
@pytest.mark.parametrize("error", _TRANSPORT_ERRORS)
async def test_a_transport_error_on_the_admin_side_surfaces_as_sign_in_unavailable(kc, error, call, where):
    """A refused connection or a timeout raises SignInUnavailable, so the sender keeps the send pending (R-4)."""
    port = adapter(kc)
    setattr(kc, "admin_error" if where == "admin-api" else "token_error", error)
    with pytest.raises(SignInUnavailable):
        await _ADMIN_CALLS[call](port)
    kc.admin_error = kc.token_error = None
    await _ADMIN_CALLS[call](adapter(kc))  # control: the same call on the same fake succeeds


@pytest.mark.parametrize("where", ["admin-api", "admin-token"])
@pytest.mark.parametrize("call", sorted(_ADMIN_CALLS))
@pytest.mark.parametrize("status", [403, 500, 503])
async def test_an_http_error_on_the_admin_side_surfaces_as_sign_in_unavailable(kc, status, call, where):
    """Keycloak answering an admin call (or the service-account token) with an error is unavailable, never an answer (SignInUnavailable)."""
    setattr(kc, "admin_status" if where == "admin-api" else "admin_token_status", status)
    with pytest.raises(SignInUnavailable):
        await _ADMIN_CALLS[call](adapter(kc))
    kc.admin_status = kc.admin_token_status = None
    await _ADMIN_CALLS[call](adapter(kc))  # control: the same call on the same fake succeeds


@pytest.mark.parametrize(("credentials", "expected"), [
    pytest.param([{"type": "password"}, {"type": "otp"}], True, id="password-and-otp"),
    pytest.param([{"type": "password"}], False, id="password-only"),
    pytest.param([{"type": "password"}, {"type": "webauthn"}], False, id="other-second-factor"),
    pytest.param([], False, id="none"),
])
async def test_has_otp_reads_the_accounts_credential_list(kc, credentials, expected):
    """has_otp is true exactly when the credential list holds an `otp` credential (C13)."""
    kc.credentials = credentials
    assert await adapter(kc).has_otp(USER_ID) is expected
    [read] = kc.calls("GET", "/credentials")
    assert read.path == f"/admin/realms/{REALM}/users/{USER_ID}/credentials"


async def test_require_otp_setup_puts_configure_totp_on_that_account(kc):
    """The account is made to set up a one-time code at next sign-in (C13)."""
    await adapter(kc).require_otp_setup(USER_ID)
    [put] = [s for s in kc.admin_writes() if s.method == "PUT"]
    assert put.path == f"/admin/realms/{REALM}/users/{USER_ID}"
    assert "CONFIGURE_TOTP" in put.json()["requiredActions"]


async def test_reads_change_nothing_at_keycloak(kc):
    """has_otp and sign-in are read-only on the admin API (control for the write assertions)."""
    await adapter(kc).has_otp(USER_ID)
    await sign_in(kc, kc.signer.sign(claims()))
    # Positive control: both calls did reach Keycloak, the credential read on the admin API.
    assert any(s.method == "GET" and s.path.endswith(f"/users/{USER_ID}/credentials") for s in kc.seen)
    assert kc.admin_writes() == []


def _admin_token_requests(kc: Keycloak) -> int:
    return sum(1 for s in kc.calls("POST", "/openid-connect/token")
               if s.form().get("grant_type") == "client_credentials")


async def test_the_admin_token_is_reused_until_shortly_before_it_expires(kc):
    """One client-credentials grant serves admin calls while it has more than 30 s left."""
    kc.admin_token_lifetime = 300
    clock = {"now": NOW}
    port = adapter(kc, clock=lambda: clock["now"])
    await port.require_otp_setup(USER_ID)  # a read and a write
    await port.has_otp(USER_ID)
    assert _admin_token_requests(kc) == 1
    clock["now"] = NOW + dt.timedelta(seconds=269)
    await port.has_otp(USER_ID)
    assert _admin_token_requests(kc) == 1
    clock["now"] = NOW + dt.timedelta(seconds=270)
    await port.has_otp(USER_ID)
    assert _admin_token_requests(kc) == 2


async def test_an_admin_token_with_no_stated_lifetime_is_not_reused(kc):
    """Without `expires_in` there is nothing to bound reuse by, so each admin call asks afresh."""
    port = adapter(kc)
    await port.has_otp(USER_ID)
    await port.has_otp(USER_ID)
    assert _admin_token_requests(kc) == 2


# --- #1349 B3: the address the API itself reaches Keycloak at --------------------------------


class _Wire(httpx.AsyncBaseTransport):
    """Records each request's full URL, then hands the fake the same request with `prefix`
    removed from the path (the fake serves Keycloak's paths from the root)."""

    def __init__(self, kc: Keycloak, prefix: str = "") -> None:
        self._inner, self._prefix, self.urls = kc.transport(), prefix, []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.urls.append(str(request.url.copy_with(query=None)))
        assert request.url.path.startswith(self._prefix)
        request.url = request.url.copy_with(path=request.url.path[len(self._prefix):])
        return await self._inner.handle_async_request(request)


async def _every_server_call(kc: Keycloak, *, issuer: str, wire: _Wire, **setting: str) -> str:
    """Drive a sign-in, a key fetch, the admin token and the admin API; the sign-in URL handed to the browser."""
    kc.id_token = kc.signer.sign(claims(iss=issuer))
    port = KeycloakSignIn(
        issuer=issuer, client_id=CLIENT_ID, client_secret=CLIENT_SECRET, redirect_uri=REDIRECT_URI,
        admin_client_id=ADMIN_CLIENT_ID, admin_client_secret=ADMIN_CLIENT_SECRET,
        transport=wire, clock=lambda: NOW, **setting)
    kc.opened.append(port)
    browser = await port.begin_signin(state="s1", nonce="n1", code_challenge="chal")
    await port.finish_signin(code="code-1", code_verifier="verifier-1", nonce="n1")
    await port.create_account(username="u-1", email="ann@x.org", required_actions=frozenset())
    await port.has_otp(USER_ID)
    return browser


async def test_with_a_server_url_every_call_the_api_makes_goes_there_and_the_browser_and_token_keep_the_issuer(kc):
    """The browser's sign-in URL and the token's `iss` stay the public issuer; token exchange,
    keys, admin token and admin API go to the server address."""
    wire = _Wire(kc)
    browser = await _every_server_call(kc, issuer=ISSUER, wire=wire, server_url="http://keycloak.internal:8080")
    assert browser.startswith(f"{ISSUER}/protocol/openid-connect/auth?")
    assert {urllib.parse.urlsplit(u).netloc for u in wire.urls} == {"keycloak.internal:8080"}
    assert f"http://keycloak.internal:8080/realms/{REALM}/protocol/openid-connect/certs" in wire.urls
    assert f"http://keycloak.internal:8080/realms/{REALM}/protocol/openid-connect/token" in wire.urls
    assert f"http://keycloak.internal:8080/admin/realms/{REALM}/users" in wire.urls


async def test_a_token_naming_the_server_address_as_issuer_is_refused(kc):
    """`iss` is checked against the public issuer, never against the server address."""
    server = "http://keycloak.internal:8080"
    kc.id_token = kc.signer.sign(claims(iss=f"{server}/realms/{REALM}"))
    port = KeycloakSignIn(
        issuer=ISSUER, client_id=CLIENT_ID, client_secret=CLIENT_SECRET, redirect_uri=REDIRECT_URI,
        admin_client_id=ADMIN_CLIENT_ID, admin_client_secret=ADMIN_CLIENT_SECRET,
        transport=kc.transport(), clock=lambda: NOW, server_url=server)
    kc.opened.append(port)
    await port.begin_signin(state="s1", nonce="n1", code_challenge="chal")
    with pytest.raises(SignInRefused):
        await port.finish_signin(code="code-1", code_verifier="verifier-1", nonce="n1")


@pytest.mark.parametrize(("issuer", "setting", "reached"), [
    # no setting: everything from the issuer, path prefix included (today's behavior)
    ("https://kc.test/auth/realms/defender", {}, "https://kc.test/auth"),
    # the setting replaces everything before /realms/, prefix and all
    ("https://kc.test/auth/realms/defender", {"server_url": "http://kc-int:8080/auth"}, "http://kc-int:8080/auth"),
    ("https://kc.test/realms/defender", {"server_url": "http://kc-int:8080/"}, "http://kc-int:8080"),
])
async def test_the_server_url_replaces_what_comes_before_realms_in_the_issuer(kc, issuer, setting, reached):
    prefix = urllib.parse.urlsplit(reached).path
    wire = _Wire(kc, prefix)
    browser = await _every_server_call(kc, issuer=issuer, wire=wire, **setting)
    assert browser.startswith(f"{issuer}/protocol/openid-connect/auth?")
    assert wire.urls
    assert all(u.startswith((f"{reached}/realms/{REALM}/", f"{reached}/admin/realms/{REALM}/")) for u in wire.urls), wire.urls


@pytest.mark.parametrize("issuer", ["https://kc.test", "https://kc.test/auth", "https://kc.test/realms/",
                                    "kc.test/realms/defender", "https://kc.test/realms/defender?x=1",
                                    "https://kc.test/realms/defender/account"])
def test_an_issuer_that_is_not_a_realm_url_refuses_construction_naming_the_setting(issuer):
    with pytest.raises(ValueError, match="issuer"):
        KeycloakSignIn(
            issuer=issuer, client_id=CLIENT_ID, client_secret=CLIENT_SECRET, redirect_uri=REDIRECT_URI,
            admin_client_id=ADMIN_CLIENT_ID, admin_client_secret=ADMIN_CLIENT_SECRET)


@pytest.mark.parametrize("server_url", [
    "keycloak:8080", "//keycloak:8080", "ftp://keycloak:8080", "http://keycloak:8080/?x=1",
    "http://keycloak:8080/#f", "", "http:///auth",
    "http://keycloak:8080\n", " http://keycloak:8080", "http://key\tcloak:8080",  # pasted with whitespace
    "http://keycloak:abc", "http://keycloak:99999",  # a port that is not one
    "http://user:pw@keycloak:8080",  # credentials in the address
    "http://kc-int:8080/realms/defender", "http://kc-int:8080/auth/realms",  # the issuer, not the server
    "http://[::1:8080",  # a broken IPv6 host, which the URL parser refuses in its own words
])
def test_a_malformed_server_url_refuses_construction(server_url):
    with pytest.raises(ValueError, match="server_url"):
        KeycloakSignIn(
            issuer=ISSUER, client_id=CLIENT_ID, client_secret=CLIENT_SECRET, redirect_uri=REDIRECT_URI,
            admin_client_id=ADMIN_CLIENT_ID, admin_client_secret=ADMIN_CLIENT_SECRET, server_url=server_url)


async def test_a_sign_in_right_after_keycloak_rotates_its_key_verifies(kc):
    """The sign-in realm follows a rotation at once: a second sign-in seconds after the first, under a key the held
    set lacks, fetches the set again and verifies (#1450 review: no refetch window on this realm, whose ID tokens
    come from Keycloak itself)."""
    port = adapter(kc)
    kc.id_token = kc.signer.sign(claims())
    await port.begin_signin(state="s1", nonce="n1", code_challenge="chal")
    assert (await port.finish_signin(code="code-1", code_verifier="verifier-1", nonce="n1")).account_id
    rotated = Signer(kid="kid-rotated")
    kc.jwks_keys.append(rotated.jwk())
    kc.id_token = rotated.sign(claims())
    await port.begin_signin(state="s2", nonce="n1", code_challenge="chal")
    assert (await port.finish_signin(code="code-1", code_verifier="verifier-1", nonce="n1")).account_id
    assert sum(1 for s in kc.seen if s.path.endswith("/certs")) == 2



# --- the start-up probe of both adapters (#1083 O3, Am-9) ------------------------------------------
# Both realms over the shared fake that answers as the dev Keycloak was observed to (code map, "Live Keycloak admin").
# FC-6 pins only the first step's name ("discovery"); the other steps are told apart by realm and by outcome.

def probed(realm: str, *, transport: httpx.AsyncBaseTransport | None, server_url: str = BACK):
    """The realm's adapter as the composition builds it: the issuer on the front channel, reached at `server_url`."""
    issuer = f"{FRONT}/realms/{realm}"
    if realm == SIGNIN_REALM:
        admin_id, admin_secret = ADMIN_CLIENTS[SIGNIN_REALM]
        return KeycloakSignIn(issuer=issuer, client_id=CLIENT_ID, client_secret=CLIENT_SECRET,
                              redirect_uri=REDIRECT_URI, admin_client_id=admin_id,
                              admin_client_secret=admin_secret, server_url=server_url,
                              transport=transport, clock=lambda: NOW)
    admin_id, admin_secret = ADMIN_CLIENTS[PROGRAMS_REALM]
    return KeycloakPrograms(issuer=issuer, audience="defender-api-programs",
                            admin_client_id=admin_id, admin_client_secret=admin_secret,
                            server_url=server_url, transport=transport, clock=lambda: NOW)


async def probe_of(realm: str, fake: FakeKeycloak) -> object:
    """What the realm's probe returns (FC-7: None)."""
    port = probed(realm, transport=fake)
    try:
        return await cast(Any, port).probe()
    finally:
        await port.close()


async def refusal_of(realm: str, fake: FakeKeycloak) -> str:
    with pytest.raises(SignInUnavailable) as refused:
        await probe_of(realm, fake)
    return str(refused.value)


def paths(fake: FakeKeycloak) -> list[tuple[str, str]]:
    return [(method, path.split("/", 1)[1]) for method, path in fake.seen]


def admin_reads(fake: FakeKeycloak) -> list[str]:
    return [path for method, path in paths(fake) if method == "GET" and path.startswith("admin/")]


def _sibling(realm: str) -> str:
    return next(r for r in REALMS if r != realm)


@pytest.mark.parametrize("realm", REALMS)
async def test_1083_o3_a_healthy_realm_passes_the_probe_with_reads_only(realm):
    """A healthy realm's probe returns None having made only reads (the token request apart). (O3)"""
    fake = FakeKeycloak()
    assert await probe_of(realm, fake) is None
    assert sorted(paths(fake)) == sorted([
        ("GET", f"realms/{realm}/.well-known/openid-configuration"),
        ("GET", f"realms/{realm}/protocol/openid-connect/certs"),
        ("POST", f"realms/{realm}/protocol/openid-connect/token"),
        ("GET", f"admin/realms/{realm}/{ADMIN_READ[realm]}")])
    assert fake.unmodelled == []


async def test_1083_am9_each_realm_probe_reads_the_resource_its_role_covers():
    """The sign-in probe reads users, the programs probe reads clients; the other would be refused 403. (Am-9)"""
    reads = {}
    for realm in REALMS:
        fake = FakeKeycloak()
        await probe_of(realm, fake)
        reads[realm] = admin_reads(fake)
    assert reads == {SIGNIN_REALM: [f"admin/realms/{SIGNIN_REALM}/users"],
                     PROGRAMS_REALM: [f"admin/realms/{PROGRAMS_REALM}/clients"]}


@pytest.mark.parametrize("realm", REALMS)
async def test_1083_am9_the_other_resource_is_refused_to_the_realms_admin_client(realm):
    """The fake refuses the resource a realm's role does not cover, so a probe reading it would fail. (Am-9)"""
    wrong = "clients" if ADMIN_READ[realm] == "users" else "users"
    async with httpx.AsyncClient(transport=FakeKeycloak(), base_url=BACK) as client:
        granted = await client.post(f"/realms/{realm}/protocol/openid-connect/token", auth=ADMIN_CLIENTS[realm],
                                    data={"grant_type": "client_credentials"})
        bearer = {"Authorization": f"Bearer {granted.json()['access_token']}"}
        right = await client.get(f"/admin/realms/{realm}/{ADMIN_READ[realm]}", headers=bearer)
        refused = await client.get(f"/admin/realms/{realm}/{wrong}", headers=bearer)
    assert (right.status_code, refused.status_code) == (200, 403)


@pytest.mark.parametrize("realm", REALMS)
async def test_1083_o3_a_missing_realm_refuses_at_discovery_naming_the_realm(realm):
    """A realm Keycloak does not have refuses at discovery naming the realm; its sibling still passes. (O3)"""
    fake = FakeKeycloak([Fail(realm, "discovery", "not_found")])
    message = await refusal_of(realm, fake)
    assert realms_named(message) == {realm}
    assert "discovery" in message
    assert admin_reads(fake) == []
    assert not any(method == "POST" for method, _ in paths(fake))
    assert await probe_of(_sibling(realm), fake) is None


@pytest.mark.parametrize("realm", REALMS)
async def test_1083_o3_discovery_naming_another_issuer_refuses_naming_both(realm):
    """Discovery naming an issuer other than the configured one refuses, naming both and the step. (O3)"""
    fake = FakeKeycloak([Fail(realm, "discovery", "wrong_issuer")])
    message = await refusal_of(realm, fake)
    assert all(part in message for part in (realm, "discovery", f"{FRONT}/realms/{realm}", ELSEWHERE_ISSUER)), message
    assert admin_reads(fake) == []
    assert await probe_of(_sibling(realm), fake) is None


@pytest.mark.parametrize("realm", REALMS)
async def test_1083_o3_a_wrong_admin_secret_refuses_at_the_token_step_naming_the_realm(realm):
    """A refused admin client secret refuses naming the realm, with no admin read made; its sibling passes. (O3)"""
    fake = FakeKeycloak([Fail(realm, "token", "bad_secret")])
    message = await refusal_of(realm, fake)
    assert realm in message
    assert ("POST", f"realms/{realm}/protocol/openid-connect/token") in paths(fake)
    assert admin_reads(fake) == []
    assert await probe_of(_sibling(realm), fake) is None


@pytest.mark.parametrize("realm", REALMS)
async def test_1083_o3_an_admin_read_refused_for_want_of_the_role_refuses_naming_the_realm(realm):
    """A service account without the role covering the read refuses naming the realm; its sibling passes. (O3)"""
    fake = FakeKeycloak([Fail(realm, "admin", "no_role")])
    message = await refusal_of(realm, fake)
    assert realm in message
    assert admin_reads(fake) == [f"admin/realms/{realm}/{ADMIN_READ[realm]}"]
    assert await probe_of(_sibling(realm), fake) is None


@pytest.mark.parametrize(("realm", "step", "kind"),
                         [(realm, step, kind) for (realm, step), kinds in FAULTS.items() for kind in kinds])
async def test_1083_o3_every_failure_of_every_step_refuses_naming_the_realm_alone(realm, step, kind):
    """Each failure kind of each probe step refuses, naming its realm and not the other; the sibling passes. (O3, FC-6)"""
    fake = FakeKeycloak([Fail(realm, step, kind)])
    message = await refusal_of(realm, fake)
    assert realms_named(message) == {realm}, message
    if step == "discovery":
        assert "discovery" in message
    assert await probe_of(_sibling(realm), fake) is None


@pytest.mark.parametrize("realm", REALMS)
async def test_1083_o3_a_key_set_with_no_usable_key_refuses_apart_from_the_other_steps(realm):
    """A keys answer that fails or holds no signing key refuses with a message no other step's failure gives. (O3, FC-6)"""
    other_steps = {await refusal_of(realm, FakeKeycloak([Fail(realm, step, kind)]))
                   for step in STEP_KINDS if step != "keys" for kind in STEP_KINDS[step]}
    assert await probe_of(realm, FakeKeycloak()) is None  # positive control: the intact set passes
    for kind in STEP_KINDS["keys"]:
        message = await refusal_of(realm, FakeKeycloak([Fail(realm, "keys", kind)]))
        assert message not in other_steps, (kind, message)


@pytest.mark.parametrize("realm", REALMS)
async def test_1083_o3_the_four_representative_failures_get_four_messages(realm):
    """The four steps' failures of one realm are told apart by their messages, each naming the realm. (O3, FC-6)"""
    representative = {"discovery": "not_found", "keys": "empty", "token": "bad_secret", "admin": "no_role"}
    messages = {step: await refusal_of(realm, FakeKeycloak([Fail(realm, step, kind)]))
                for step, kind in representative.items()}
    assert all(realm in message for message in messages.values())
    assert len(set(messages.values())) == len(messages)


async def test_1083_f13_the_fake_answers_only_the_back_channel_host_and_refuses_an_unknown_bearer():
    """The fake 404s another host (unmodelled) and 401s an unknown bearer, as the host it models would. (FC-17)"""
    realm = SIGNIN_REALM
    fake = FakeKeycloak()
    async with httpx.AsyncClient(transport=fake) as client:
        discovery = f"/realms/{realm}/.well-known/openid-configuration"
        assert (await client.get(f"{BACK}{discovery}")).status_code == 200  # control: the back-channel host
        other = await client.get(f"{FRONT}{discovery}")
        assert other.status_code == 404
        users = f"{BACK}/admin/realms/{realm}/users"
        assert (await client.get(users, headers={"Authorization": f"Bearer admin-{realm}"})).status_code == 200
        assert (await client.get(users, headers={"Authorization": "Bearer not-a-token"})).status_code == 401
        assert (await client.get(users)).status_code == 401
    assert fake.unmodelled == [("GET", f"{FRONT}{discovery}")]


def test_1083_f13_the_fake_keeps_each_realms_signing_key_for_minting():
    """The fake publishes each realm's signing key from the private key it keeps; the realms' keys differ. (FC-17)"""
    fake = FakeKeycloak()
    for realm in REALMS:
        [signing] = [k for k in fake.keys[realm] if k["use"] == "sig"]
        assert signing["n"] == _int_b64(fake.signing_keys[realm].public_key().public_numbers().n)
    assert fake.signing_keys[SIGNIN_REALM] is not fake.signing_keys[PROGRAMS_REALM]


@pytest.mark.parametrize("realm", REALMS)
async def test_1083_o3_an_unreachable_keycloak_refuses_naming_the_realm_and_the_address(realm):
    """A Keycloak nobody listens for refuses at discovery naming the realm and the address tried. (O3)"""
    port_number = closed_port()
    port = probed(realm, transport=None, server_url=f"http://127.0.0.1:{port_number}")
    try:
        with pytest.raises(SignInUnavailable) as refused:
            await port.probe()
    finally:
        await port.close()
    message = str(refused.value)
    assert all(part in message for part in (realm, "discovery", f"127.0.0.1:{port_number}")), message
    assert await probe_of(realm, FakeKeycloak()) is None


# --- the probe over a generated failure space (#1083 O3, FC-6/7) ----------------------------------------------------

def _transport_errors() -> list[type[httpx.TransportError]]:
    """`httpx.TransportError` and every subclass, timeouts included."""
    found, todo = [], [httpx.TransportError]
    while todo:
        cls = todo.pop()
        found.append(cls)
        todo += cls.__subclasses__()
    return found


def _issuers_one_component_off(issuer: str) -> list[str]:
    """The configured issuer with exactly one of scheme, host, port, path or trailing slash changed."""
    parts = urllib.parse.urlsplit(issuer)
    host, port, path = parts.hostname, parts.port, parts.path

    def at(scheme: str = parts.scheme, netloc: str = parts.netloc, path: str = path) -> str:
        return urllib.parse.urlunsplit((scheme, netloc, path, "", ""))

    return [at(scheme="https"), at(netloc=f"127.0.0.1:{port}"), at(netloc=f"keycloak:{port}"),
            at(netloc=f"{host}:{port + 1}"), at(netloc=f"{host}"), at(netloc=f"{host}:80"),
            at(path="/realms/elsewhere"), at(path=f"{path}/more"), at(path=f"{path}x"), at(path=f"/prefix{path}"),
            at(path=f"{path}/")]


def _jwk_material(kty: str, rsa_key: Any) -> dict[str, str]:
    """Real public key material of the type `kty`, so a key is refused for its labels, never for being malformed."""
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519

    if kty == "RSA":
        numbers = rsa_key.public_key().public_numbers()
        return {"n": _int_b64(numbers.n), "e": _int_b64(numbers.e)}
    if kty == "EC":
        point = ec.generate_private_key(ec.SECP256R1()).public_key().public_numbers()
        return {"crv": "P-256", "x": _b64(point.x.to_bytes(32, "big")), "y": _b64(point.y.to_bytes(32, "big"))}
    if kty == "OKP":
        raw = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return {"crv": "Ed25519", "x": _b64(raw)}
    return {"k": _b64(b"a shared secret of thirty-two by")}


def _key_sets_without_an_rs256_signing_key(fake: FakeKeycloak, realm: str) -> list[list[dict[str, Any]]]:
    """Each realistic key set beside the realm's encryption key whose one other key is not an RS256 signing key by its
    labels (kty, alg, use; an absent `alg` or `use` reads as RS256 / sig, so those are left out as ambiguous)."""
    sets = []
    for kty in ("RSA", "EC", "oct", "OKP"):
        for alg in (None, "RS256", "RS384", "RS512", "PS256", "ES256", "HS256", "EdDSA", "RSA-OAEP"):
            for use in (None, "sig", "enc"):
                if kty == "RSA" and alg in (None, "RS256") and use in (None, "sig"):
                    continue
                key = {"kid": "candidate", "kty": kty, **_jwk_material(kty, fake.signing_keys[realm])}
                key |= ({"alg": alg} if alg else {}) | ({"use": use} if use else {})
                sets.append([key, fake.keys[realm][1]])
    return sets


def _failure_space(fake: FakeKeycloak, realm: str, step: str) -> list[tuple[str, Callable[[httpx.Request], httpx.Response]]]:
    """(label, answer) for every member of the step's failure space."""
    import http

    def status(code: int) -> Callable[[httpx.Request], httpx.Response]:
        return lambda request: httpx.Response(code, json={"error": "generated"})

    def raising(cls: type[httpx.TransportError]) -> Callable[[httpx.Request], httpx.Response]:
        def answer(request: httpx.Request) -> httpx.Response:
            raise cls("generated", request=request)
        return answer

    def body(document: dict[str, Any]) -> Callable[[httpx.Request], httpx.Response]:
        return lambda request: httpx.Response(200, json=document)

    space = [(f"status {s.value}", status(s.value)) for s in http.HTTPStatus if 300 <= s.value < 600]
    space += [(f"raises {cls.__name__}", raising(cls)) for cls in _transport_errors()]
    if step == "discovery":
        issuer = fake.issuer(realm)
        space += [(f"issuer {other}", body({"issuer": other, "jwks_uri": f"{issuer}/protocol/openid-connect/certs"}))
                  for other in _issuers_one_component_off(issuer)]
    if step == "keys":
        space += [(f"keys {json.dumps([{k: v for k, v in key.items() if k in ('kty', 'alg', 'use')} for key in keys])}",
                   body({"keys": keys})) for keys in _key_sets_without_an_rs256_signing_key(fake, realm)]
    return space


@pytest.mark.parametrize("realm", REALMS)
async def test_1083_o3_every_member_of_each_steps_failure_space_refuses_naming_the_realm_and_the_step(realm):
    """Every non-2xx status, transport error, issuer one component off and key set with no RS256 signing key refuses,
    naming the realm and the step (and the address for a transport error). (O3, FC-6, FC-7)"""
    assert await probe_of(realm, FakeKeycloak()) is None  # positive control: the healthy realm passes
    messages: dict[str, set[str]] = {}
    wrong = []
    for step in STEPS:
        fake = FakeKeycloak()
        port = probed(realm, transport=fake)  # one adapter per step, as start builds it; earlier steps answer healthily
        try:
            for label, answer in _failure_space(fake, realm, step):
                fake.answers[(realm, step)] = answer
                try:
                    await cast(Any, port).probe()
                except SignInUnavailable as refused:
                    message = str(refused)
                else:
                    wrong.append(f"{step} {label}: passed")
                    continue
                messages.setdefault(step, set()).add(message)
                if realms_named(message) != {realm}:
                    wrong.append(f"{step} {label}: names realms {realms_named(message)}: {message}")
                if step == "discovery" and "discovery" not in message:
                    wrong.append(f"{step} {label}: does not name the discovery step: {message}")
                if label.startswith("raises") and urllib.parse.urlsplit(BACK).netloc not in message:
                    wrong.append(f"{step} {label}: does not name the address: {message}")
        finally:
            await port.close()
    assert wrong == [], "\n".join(wrong)
    # FC-6 names only the first step; the others are told apart: no message is given by two steps.
    shared = {(a, b): messages[a] & messages[b] for a in STEPS for b in STEPS if a < b}
    assert all(not both for both in shared.values()), shared
