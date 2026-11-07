"""#1307 — the programs-realm Keycloak adapter (token verification, client creation) over a fake transport
playing realm `defender-programs` as probed in C21/C22/C27. No Keycloak runs — sketch.

Forced choice (FC-9): `KeycloakPrograms(issuer=, audience=, admin_client_id=, admin_client_secret=,
transport=, clock=)` in `defender.identity.keycloak`; the 60 s refetch window reads the injected clock.
"""
from __future__ import annotations

import datetime as dt
import json
import urllib.parse
from collections.abc import AsyncIterator, Callable

import httpx
import pytest

# Production names: a missing name is the expected red.
from defender.identity import SignInRefused, VerifiedProgramToken
from defender.identity.keycloak import KeycloakPrograms
from defender.tests.identity.test_1306_keycloak_adapter import Seen, Signer, _AsyncOnly, _b64

pytestmark = pytest.mark.anyio

NOW = dt.datetime(2026, 11, 7, 9, 0, tzinfo=dt.UTC)
BASE = "https://kc.test"
REALM = "defender-programs"
ISSUER = f"{BASE}/realms/{REALM}"
PEOPLE_ISSUER = f"{BASE}/realms/defender"
AUDIENCE = "defender-api-programs"
ADMIN_CLIENT_ID = "defender-api-programs-admin"
ADMIN_TOKEN = "programs-admin-token"
CREDENTIAL = "4b1f2a3c-0000-4000-8000-00000000c001"
BUILT_IN_CLIENTS = ("account", "account-console", "admin-cli", "broker", "realm-management",
                    "security-admin-console")
SERVICE_ACCOUNT = "9a8b7c6d-0000-4000-8000-0000000005a1"


def token_claims(**over) -> dict:
    base = {"iss": ISSUER, "aud": [AUDIENCE, "account"], "azp": CREDENTIAL, "sub": SERVICE_ACCOUNT,
            "typ": "Bearer", "iat": int(NOW.timestamp()) - 10, "exp": int(NOW.timestamp()) + 290}
    base.update(over)
    return {k: v for k, v in base.items() if v is not None}


class ProgramsKeycloak:
    """The programs realm's endpoints as a transport, recording every request."""

    def __init__(self, signer: Signer) -> None:
        self.signer = signer
        self.jwks_keys = [signer.jwk()]
        self.seen: list[Seen] = []
        self.clients: dict[str, dict] = {}  # internal id -> representation
        self.opened: list[KeycloakPrograms] = []

    def transport(self) -> httpx.AsyncBaseTransport:
        return _AsyncOnly(self._handle)

    def _handle(self, request: httpx.Request) -> httpx.Response:  # noqa: PLR0911
        url, method = request.url, request.method
        self.seen.append(Seen(method, url.path, urllib.parse.parse_qs(url.query.decode()),
                              request.headers, request.content))
        oidc = f"/realms/{REALM}/protocol/openid-connect"
        if url.path == f"{oidc}/certs":
            return httpx.Response(200, json={"keys": self.jwks_keys})
        if url.path == f"{oidc}/token":
            return httpx.Response(200, json={"access_token": ADMIN_TOKEN, "token_type": "Bearer", "expires_in": 300})
        admin = f"/admin/realms/{REALM}/clients"
        if not url.path.startswith(admin) or request.headers.get("authorization") != f"Bearer {ADMIN_TOKEN}":
            return httpx.Response(404)
        rest = url.path[len(admin):].strip("/").split("/") if url.path != admin else []
        if not rest and method == "POST":
            body = json.loads(request.content)
            if body["id"] in self.clients or any(c["clientId"] == body["clientId"] for c in self.clients.values()):
                return httpx.Response(409)
            self.clients[body["id"]] = body
            return httpx.Response(201, headers={"Location": f"{BASE}{admin}/{body['id']}"})
        if not rest and method == "GET":
            return httpx.Response(200, json=list(self.clients.values()))
        if rest[1:] == ["service-account-user"]:
            return httpx.Response(200, json={"id": SERVICE_ACCOUNT, "username": f"service-account-{rest[0]}"})
        if rest[1:] == ["client-secret"]:
            return httpx.Response(200, json={"type": "secret", "value": "kc-generated-secret"})
        if len(rest) == 1 and method == "DELETE":
            return httpx.Response(204 if self.clients.pop(rest[0], None) else 404)
        return httpx.Response(404)

    def certs_fetches(self) -> int:
        return sum(1 for s in self.seen if s.path.endswith("/certs"))

    def created(self) -> list[dict]:
        return [s.json() for s in self.seen if s.method == "POST" and s.path.endswith("/clients")]


@pytest.fixture
async def kc() -> AsyncIterator[ProgramsKeycloak]:
    fake = ProgramsKeycloak(Signer())
    try:
        yield fake
    finally:
        for port in fake.opened:
            await port.close()


class Clock:
    def __init__(self) -> None:
        self.now = NOW

    def __call__(self) -> dt.datetime:
        return self.now


def adapter(kc: ProgramsKeycloak, clock: Callable[[], dt.datetime] = lambda: NOW) -> KeycloakPrograms:
    port = KeycloakPrograms(issuer=ISSUER, audience=AUDIENCE, admin_client_id=ADMIN_CLIENT_ID,
                            admin_client_secret="programs-admin-secret", transport=kc.transport(), clock=clock)
    kc.opened.append(port)
    return port


# --- verification -----------------------------------------------------------------------------

async def test_a_programs_realm_access_token_verifies_to_its_client_and_subject(kc):
    """RS256, programs issuer, programs audience, `typ` Bearer, unexpired -> client id + `sub` (Verify)."""
    verified = await adapter(kc).verify_token(kc.signer.sign(token_claims()))
    assert verified == VerifiedProgramToken(client_id=CREDENTIAL, subject=SERVICE_ACCOUNT,
                                            expires_at=NOW + dt.timedelta(seconds=290))


@pytest.mark.parametrize("over", [
    pytest.param({"typ": "ID"}, id="typ-not-bearer"),
    pytest.param({"typ": None}, id="typ-missing"),
    pytest.param({"aud": ["account"]}, id="no-programs-audience"),
    pytest.param({"aud": "defender-api"}, id="people-client-audience"),
    pytest.param({"iss": PEOPLE_ISSUER}, id="people-realm-issuer"),
    pytest.param({"exp": int(NOW.timestamp()) - 1}, id="expired"),
])
async def test_a_token_failing_one_claim_check_is_refused(kc, over):
    """typ, aud, iss, exp are each checked (Verify, C21/C22, RFC 8725)."""
    port = adapter(kc)
    assert (await port.verify_token(kc.signer.sign(token_claims()))).client_id == CREDENTIAL
    with pytest.raises(SignInRefused):
        await port.verify_token(kc.signer.sign(token_claims(**over)))


async def test_a_token_not_signed_rs256_by_the_realm_is_refused(kc):
    """Algorithm RS256 only; an HS256 token keyed with the public key is refused (Verify)."""
    import hashlib
    import hmac

    head = _b64(json.dumps({"alg": "HS256", "typ": "JWT", "kid": kc.signer.kid}).encode())
    body = _b64(json.dumps(token_claims()).encode())
    sig = hmac.new(kc.signer.public_pem(), f"{head}.{body}".encode(), hashlib.sha256).digest()
    with pytest.raises(SignInRefused):
        await adapter(kc).verify_token(f"{head}.{body}.{_b64(sig)}")


async def test_an_unknown_key_id_refetches_the_key_set_at_most_once_per_minute(kc):
    """Unknown kid: one refetch, then 401s without traffic until 60 s pass (Verify, C1 amplification)."""
    clock = Clock()
    port = adapter(kc, clock)
    assert (await port.verify_token(kc.signer.sign(token_claims()))).client_id == CREDENTIAL
    clock.now += dt.timedelta(seconds=60)  # the warm-up was itself a fetch; start a fresh window
    fetched = kc.certs_fetches()
    for n in range(3):
        with pytest.raises(SignInRefused):
            await port.verify_token(kc.signer.sign(token_claims(), kid=f"random-{n}"))
    assert kc.certs_fetches() == fetched + 1
    rotated = Signer(kid="kid-2")
    kc.jwks_keys.append(rotated.jwk())
    clock.now += dt.timedelta(seconds=59)
    with pytest.raises(SignInRefused):
        await port.verify_token(rotated.sign(token_claims()))
    assert kc.certs_fetches() == fetched + 1
    clock.now += dt.timedelta(seconds=1)
    assert (await port.verify_token(rotated.sign(token_claims()))).subject == SERVICE_ACCOUNT
    assert kc.certs_fetches() == fetched + 2


# --- client creation ----------------------------------------------------------------------------

async def test_a_client_is_created_under_the_credential_id_for_service_accounts_only(kc):
    """id = clientId = credential id; confidential, service accounts only, 300 s tokens, programs audience (Create, C27)."""
    service_account, secret = await adapter(kc).create_client(CREDENTIAL)
    assert (service_account, secret) == (SERVICE_ACCOUNT, "kc-generated-secret")
    [body] = kc.created()
    assert body["id"] == body["clientId"] == CREDENTIAL
    assert body["publicClient"] is False
    assert body["serviceAccountsEnabled"] is True
    assert body["standardFlowEnabled"] is False
    assert body["implicitFlowEnabled"] is False
    assert body["directAccessGrantsEnabled"] is False
    assert body["attributes"]["access.token.lifespan"] == "300"
    [mapper] = [m for m in body["protocolMappers"] if m["protocolMapper"] == "oidc-audience-mapper"]
    assert mapper["config"]["included.custom.audience"] == AUDIENCE
    assert mapper["config"]["access.token.claim"] == "true"
    assert mapper["config"].get("id.token.claim", "false") == "false"


async def test_listing_skips_the_apis_own_clients_and_delete_removes_one(kc):
    """`client_ids` names program clients only; `delete_client` of an absent client is no error (Reconciliation, FC-1)."""
    # Every Keycloak realm also holds built-in clients (GAP: the design says the realm holds nothing else).
    for client_id in (ADMIN_CLIENT_ID, AUDIENCE, *BUILT_IN_CLIENTS):
        kc.clients[f"internal-{client_id}"] = {"id": f"internal-{client_id}", "clientId": client_id}
    port = adapter(kc)
    await port.create_client(CREDENTIAL)
    assert await port.client_ids() == {CREDENTIAL}
    await port.delete_client(CREDENTIAL)
    await port.delete_client(CREDENTIAL)
    assert await port.client_ids() == set()
    assert len(kc.clients) == 2 + len(BUILT_IN_CLIENTS)
