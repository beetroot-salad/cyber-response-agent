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

import httpx
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

# Production names (Pinned interface): a missing module is the expected red.
from defender.identity import SignInRefused, SignInUnavailable, VerifiedSignIn
from defender.identity.keycloak import KeycloakSignIn

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


class Keycloak:
    """Keycloak's endpoints as a transport. `id_token` is what the token endpoint hands out."""

    def __init__(self, signer: Signer) -> None:
        self.signer = signer
        self.jwks_keys = [signer.jwk()]
        self.id_token = ""
        self.token_status = 200
        self.seen: list[Seen] = []
        self.users: dict[str, str] = {}  # username -> id
        self.create_status = 201
        self.email_status = 204
        self.credentials: list[dict] = []
        self.required_actions: list[str] = []
        self.new_id = USER_ID

    # --- the transport ---------------------------------------------------------------------
    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self._handle)

    def _handle(self, request: httpx.Request) -> httpx.Response:  # noqa: C901
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
                return httpx.Response(200, json={"access_token": ADMIN_TOKEN, "token_type": "Bearer"})
            if self.token_status != 200:
                return httpx.Response(self.token_status, json={"error": "invalid_grant"})
            return httpx.Response(200, json={"access_token": "kc-access-secret", "token_type": "Bearer",
                                             "refresh_token": "kc-refresh-secret", "id_token": self.id_token})
        admin = f"/admin/realms/{REALM}/users"
        if not path.startswith(admin):
            return httpx.Response(404)
        if request.headers.get("authorization") != f"Bearer {ADMIN_TOKEN}":
            return httpx.Response(401)
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
def kc() -> Keycloak:
    return Keycloak(Signer())


def adapter(kc: Keycloak, *, now: dt.datetime = NOW) -> KeycloakSignIn:
    return KeycloakSignIn(
        issuer=ISSUER, client_id=CLIENT_ID, client_secret=CLIENT_SECRET, redirect_uri=REDIRECT_URI,
        admin_realm=REALM, admin_client_id=ADMIN_CLIENT_ID, admin_client_secret=ADMIN_CLIENT_SECRET,
        transport=kc.transport(), clock=lambda: now)


def sign_in(kc: Keycloak, token: str, *, nonce: str = "n1") -> VerifiedSignIn:
    kc.id_token = token
    port = adapter(kc)
    port.begin_signin(state="s1", nonce=nonce, code_challenge="chal")
    return port.finish_signin(code="code-1", code_verifier="verifier-1", nonce=nonce)


# --- begin_signin ----------------------------------------------------------------------------

def test_begin_signin_url_carries_the_pkce_login_prompt_and_the_configured_client(kc):
    """The sign-in URL forces the password prompt and PKCE S256 (DC-8, C12)."""
    url = urllib.parse.urlsplit(adapter(kc).begin_signin(state="st-9", nonce="no-9", code_challenge="ch-9"))
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

def test_finish_signin_exchanges_the_code_with_its_verifier_and_returns_the_verified_identity(kc):
    """A correctly signed token yields VerifiedSignIn; the code, verifier and redirect_uri are sent (DC-8)."""
    result = sign_in(kc, kc.signer.sign(claims(amr=["pwd", "otp"])))
    assert result == VerifiedSignIn(account_id=ACCOUNT, name="Ada Ops", amr=("pwd", "otp"))
    [sent] = [s for s in kc.calls("POST", "/openid-connect/token")
              if s.form().get("grant_type") == "authorization_code"]
    form = sent.form()
    assert (form["code"], form["code_verifier"], form["redirect_uri"]) == ("code-1", "verifier-1", REDIRECT_URI)
    basic = "Basic " + base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()
    assert sent.headers.get("authorization") == basic or (
        form.get("client_id"), form.get("client_secret")) == (CLIENT_ID, CLIENT_SECRET)


def test_keycloaks_tokens_never_leave_the_adapter(kc):
    """The result carries only account_id, name and amr (K7/H5)."""
    result = sign_in(kc, kc.signer.sign(claims()))
    assert {f.name for f in dataclasses.fields(result)} == {"account_id", "name", "amr"}
    leaked = repr(result) + json.dumps(dataclasses.asdict(result))
    for secret in ("kc-access-secret", "kc-refresh-secret", kc.id_token):
        assert secret not in leaked


def test_a_token_without_amr_reports_no_methods_and_so_no_otp(kc):
    """A missing amr is the empty tuple, not an error and not otp (C13)."""
    assert sign_in(kc, kc.signer.sign(claims(amr=None))).amr == ()


def test_an_audience_list_that_contains_the_client_is_accepted(kc):
    """Positive control for the audience refusal: aud may be a list holding our client id."""
    assert sign_in(kc, kc.signer.sign(claims(aud=["account", CLIENT_ID]))).account_id == ACCOUNT


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
    pytest.param(lambda kc: kc.signer.sign(claims(aud="some-other-client")), id="wrong-audience"),
    pytest.param(lambda kc: kc.signer.sign(claims(aud=["account", "other"])), id="audience-list-without-us"),
    pytest.param(lambda kc: kc.signer.sign(claims(nonce="n-other")), id="wrong-nonce"),
    pytest.param(lambda kc: kc.signer.sign(claims(nonce=None)), id="missing-nonce"),
    pytest.param(lambda kc: kc.signer.sign(claims(exp=int(NOW.timestamp()) - 1)), id="expired"),
    pytest.param(_hs256_with_public_key, id="hs256-confusion"),
    pytest.param(_unsigned, id="alg-none"),
    pytest.param(lambda kc: kc.signer.sign(claims(sub=None)), id="no-subject"),
])
def test_finish_signin_refuses_a_token_that_fails_verification(kc, make):
    """Signature, key id, issuer, audience, nonce, expiry and algorithm are all checked (DC-8)."""
    kc.id_token = make(kc)
    port = adapter(kc)
    port.begin_signin(state="s1", nonce="n1", code_challenge="chal")
    with pytest.raises(SignInRefused):
        port.finish_signin(code="code-1", code_verifier="verifier-1", nonce="n1")


def test_finish_signin_refuses_when_keycloak_rejects_the_code(kc):
    """A failed code exchange is a refusal, not a crash and not an identity."""
    kc.token_status = 400
    kc.id_token = kc.signer.sign(claims())
    port = adapter(kc)
    with pytest.raises(SignInRefused):
        port.finish_signin(code="used-code", code_verifier="verifier-1", nonce="n1")


def test_the_nonce_the_caller_passes_is_the_one_checked(kc):
    """A token whose nonce matches the token endpoint's note but not the caller's is refused."""
    kc.id_token = kc.signer.sign(claims(nonce="n1"))
    with pytest.raises(SignInRefused):
        adapter(kc).finish_signin(code="c", code_verifier="v", nonce="n-from-our-cookie")
    assert adapter(kc).finish_signin(code="c", code_verifier="v", nonce="n1").account_id == ACCOUNT


# --- the admin API ----------------------------------------------------------------------------

def test_create_account_sends_our_user_id_as_username_verified_with_mapped_required_actions(kc):
    """username = our user id, emailVerified, set_password/set_up_otp -> UPDATE_PASSWORD/CONFIGURE_TOTP (C9)."""
    account = adapter(kc).create_account(
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
    assert grant.form().get("client_id", ADMIN_CLIENT_ID) == ADMIN_CLIENT_ID


def test_create_account_with_only_set_password_requires_no_otp_setup(kc):
    """A plain invitee is not made to set up a one-time code (r6 flow 1)."""
    adapter(kc).create_account(username=USER_ID, email="a@example.test", required_actions=frozenset({"set_password"}))
    [sent] = kc.calls("POST", f"/admin/realms/{REALM}/users")
    assert sent.json()["requiredActions"] == ["UPDATE_PASSWORD"]


def test_create_account_reads_the_new_id_from_the_location_header(kc):
    """The returned account id is the one Keycloak chose (P-B)."""
    kc.new_id = "kc-chosen-id"
    assert adapter(kc).create_account(
        username=USER_ID, email="a@example.test", required_actions=frozenset({"set_password"})) == "kc-chosen-id"


def test_a_conflict_on_create_finds_the_existing_account_by_exact_username(kc):
    """Create-or-find: a retry gets the same account, never a username-prefix lookalike (P-C)."""
    kc.users = {USER_ID + "0": "decoy-id", USER_ID: "existing-id"}
    kc.create_status = 409
    account = adapter(kc).create_account(
        username=USER_ID, email="a@example.test", required_actions=frozenset({"set_password"}))
    assert account == "existing-id"
    [lookup] = kc.calls("GET", f"/admin/realms/{REALM}/users")
    assert lookup.query["username"] == [USER_ID]
    assert lookup.query["exact"] == ["true"]


def test_a_conflict_with_no_account_of_that_username_is_not_papered_over(kc):
    """A 409 caused by someone else's email must not return a wrong id."""
    kc.create_status = 409
    with pytest.raises(SignInUnavailable):
        adapter(kc).create_account(username=USER_ID, email="a@example.test", required_actions=frozenset())


def test_send_set_password_email_asks_for_a_seven_day_action_link_for_that_account(kc):
    """PUT .../execute-actions-email?lifespan=604800 with UPDATE_PASSWORD (C9)."""
    adapter(kc).send_set_password_email(USER_ID, lifespan=SEVEN_DAYS)
    [sent] = kc.calls("PUT", "/execute-actions-email")
    assert sent.path == f"/admin/realms/{REALM}/users/{USER_ID}/execute-actions-email"
    assert sent.query["lifespan"] == ["604800"]
    assert sent.json() == ["UPDATE_PASSWORD"]
    assert sent.headers["authorization"] == f"Bearer {ADMIN_TOKEN}"


def test_a_failed_email_send_is_reported_so_the_sender_keeps_it_pending(kc):
    """Keycloak refusing the send raises; success (above) does not (r6 flow 1 retry)."""
    kc.email_status = 500
    with pytest.raises(SignInUnavailable):
        adapter(kc).send_set_password_email(USER_ID, lifespan=SEVEN_DAYS)


@pytest.mark.parametrize(("credentials", "expected"), [
    pytest.param([{"type": "password"}, {"type": "otp"}], True, id="password-and-otp"),
    pytest.param([{"type": "password"}], False, id="password-only"),
    pytest.param([{"type": "password"}, {"type": "webauthn"}], False, id="other-second-factor"),
    pytest.param([], False, id="none"),
])
def test_has_otp_reads_the_accounts_credential_list(kc, credentials, expected):
    """has_otp is true exactly when the credential list holds an `otp` credential (C13)."""
    kc.credentials = credentials
    assert adapter(kc).has_otp(USER_ID) is expected
    [read] = kc.calls("GET", "/credentials")
    assert read.path == f"/admin/realms/{REALM}/users/{USER_ID}/credentials"


def test_require_otp_setup_puts_configure_totp_on_that_account(kc):
    """The account is made to set up a one-time code at next sign-in (C13)."""
    adapter(kc).require_otp_setup(USER_ID)
    [put] = [s for s in kc.admin_writes() if s.method == "PUT"]
    assert put.path == f"/admin/realms/{REALM}/users/{USER_ID}"
    assert "CONFIGURE_TOTP" in put.json()["requiredActions"]


def test_reads_change_nothing_at_keycloak(kc):
    """has_otp and sign-in are read-only on the admin API (control for the write assertions)."""
    adapter(kc).has_otp(USER_ID)
    sign_in(kc, kc.signer.sign(claims()))
    # Positive control: both calls did reach Keycloak, the credential read on the admin API.
    assert any(s.method == "GET" and s.path.endswith(f"/users/{USER_ID}/credentials") for s in kc.seen)
    assert kc.admin_writes() == []
