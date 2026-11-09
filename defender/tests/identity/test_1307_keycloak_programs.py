"""#1307 — the programs-realm Keycloak adapter (token verification, client administration) over a fake transport
playing realm `defender-programs` as probed in C21/C22/C27. Hermetic: no Keycloak runs.

Forced choice (FC-9): `KeycloakPrograms(issuer=, audience=, admin_client_id=, admin_client_secret=, transport=,
clock=)` in `defender.identity.keycloak`; the 60 s refetch window reads the injected clock. Every failure of an
admin call or of a key-set fetch is `SignInUnavailable`; a token that does not verify is `SignInRefused`.

Grounding assumptions the fake makes (to re-establish live): the client list honours `first`/`max`, and without
`max` answers its first 100 clients only; `GET .../client-secret` reads the secret a new confidential client got.
"""
from __future__ import annotations

import asyncio
import base64
import datetime as dt
import hashlib
import hmac
import json
import random
import urllib.parse
import uuid
from collections.abc import AsyncIterator, Callable

import httpx
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

# Production names: a missing name is the expected red.
from defender.identity import SignInRefused, SignInUnavailable, VerifiedProgramToken
from defender.identity.keycloak import KeycloakPrograms
from defender.tests.identity.test_1306_keycloak_adapter import Seen, Signer, _AsyncOnly, _b64

pytestmark = pytest.mark.anyio

NOW = dt.datetime(2026, 11, 7, 9, 0, tzinfo=dt.UTC)
BASE = "https://kc.test"
REALM = "defender-programs"
OTHER_REALM = "other-programs"
AUDIENCE = "defender-api-programs"
PEOPLE_AUDIENCE = "defender-api"
ADMIN_CLIENT_ID = "defender-api-programs-admin"
ADMIN_CLIENT_SECRET = "programs-admin-secret"
ADMIN_TOKEN = "programs-admin-token"
CREDENTIAL = "4b1f2a3c-0000-4000-8000-00000000c001"
OTHER_CREDENTIAL = "4b1f2a3c-0000-4000-8000-00000000c002"
BUILT_IN_CLIENTS = ("account", "account-console", "admin-cli", "broker", "realm-management",
                    "security-admin-console")
SERVICE_ACCOUNT = "9a8b7c6d-0000-4000-8000-0000000005a1"
WINDOW = dt.timedelta(seconds=60)
MAX_AGE = dt.timedelta(minutes=10)


def issuer_of(realm: str) -> str:
    return f"{BASE}/realms/{realm}"


ISSUER = issuer_of(REALM)
PEOPLE_ISSUER = issuer_of("defender")


def token_claims(**over) -> dict:
    base = {"iss": ISSUER, "aud": [AUDIENCE, "account"], "azp": CREDENTIAL, "sub": SERVICE_ACCOUNT,
            "typ": "Bearer", "iat": int(NOW.timestamp()) - 10, "exp": int(NOW.timestamp()) + 290}
    base.update(over)
    return {k: v for k, v in base.items() if v is not None}


class ProgramsKeycloak:
    """One realm's endpoints as a transport, recording every request. `fail[op]` scripts an operation
    (`certs`, `token`, `create`, `service-account`, `secret`, `delete`, `list`): an exception is raised by the
    transport, an int is the status answered."""

    def __init__(self, signer: Signer, realm: str = REALM) -> None:
        self.signer = signer
        self.realm = realm
        self.jwks_keys = [signer.jwk()]
        self.seen: list[Seen] = []
        self.clients: dict[str, dict] = {}  # internal id -> representation
        self.opened: list[KeycloakPrograms] = []
        self.fail: dict[str, Exception | int] = {}

    def transport(self) -> httpx.AsyncBaseTransport:
        return _AsyncOnly(self._handle)

    def _scripted(self, op: str) -> httpx.Response | None:
        failure = self.fail.get(op)
        if isinstance(failure, Exception):
            raise failure
        return None if failure is None else httpx.Response(failure, json={"error": "scripted"})

    def _admin_authenticated(self, form: dict[str, list[str]], request: httpx.Request) -> bool:
        basic = "Basic " + base64.b64encode(f"{ADMIN_CLIENT_ID}:{ADMIN_CLIENT_SECRET}".encode()).decode()
        in_form = form.get("client_id") == [ADMIN_CLIENT_ID] and form.get("client_secret") == [ADMIN_CLIENT_SECRET]
        return in_form or request.headers.get("authorization") == basic

    def _handle(self, request: httpx.Request) -> httpx.Response:  # noqa: PLR0911, PLR0912, C901
        url, method = request.url, request.method
        self.seen.append(Seen(method, url.path, urllib.parse.parse_qs(url.query.decode()),
                              request.headers, request.content))
        oidc = f"/realms/{self.realm}/protocol/openid-connect"
        if url.path == f"{oidc}/certs":
            return self._scripted("certs") or httpx.Response(200, json={"keys": self.jwks_keys})
        if url.path == f"{oidc}/token":
            form = urllib.parse.parse_qs(request.content.decode())
            if form.get("grant_type") != ["client_credentials"] or not self._admin_authenticated(form, request):
                return httpx.Response(401, json={"error": "unauthorized_client"})
            return self._scripted("token") or httpx.Response(
                200, json={"access_token": ADMIN_TOKEN, "token_type": "Bearer", "expires_in": 300})
        admin = f"/admin/realms/{self.realm}/clients"
        if not url.path.startswith(admin) or request.headers.get("authorization") != f"Bearer {ADMIN_TOKEN}":
            return httpx.Response(404)
        rest = url.path[len(admin):].strip("/").split("/") if url.path != admin else []
        if not rest and method == "POST":
            if (scripted := self._scripted("create")) is not None:
                return scripted
            body = json.loads(request.content)
            if body["id"] in self.clients or any(c["clientId"] == body["clientId"] for c in self.clients.values()):
                return httpx.Response(409)
            self.clients[body["id"]] = body
            return httpx.Response(201, headers={"Location": f"{BASE}{admin}/{body['id']}"})
        if not rest and method == "GET":
            if (scripted := self._scripted("list")) is not None:
                return scripted
            query = urllib.parse.parse_qs(url.query.decode())
            first, limit = int(query.get("first", ["0"])[0]), int(query.get("max", ["100"])[0])
            page = [{"id": c["id"], "clientId": c["clientId"]} for c in self.clients.values()][first:first + limit]
            return httpx.Response(200, json=page)
        if rest[0] not in self.clients and method != "DELETE":
            return httpx.Response(404)
        if rest[1:] == ["service-account-user"]:
            return self._scripted("service-account") or httpx.Response(
                200, json={"id": SERVICE_ACCOUNT, "username": f"service-account-{rest[0]}"})
        if rest[1:] == ["client-secret"]:
            return self._scripted("secret") or httpx.Response(200, json={"type": "secret", "value": "kc-generated-secret"})
        if len(rest) == 1 and method == "DELETE":
            return self._scripted("delete") or httpx.Response(204 if self.clients.pop(rest[0], None) else 404)
        return httpx.Response(404)

    # --- views -------------------------------------------------------------------------------
    def certs_fetches(self) -> int:
        return sum(1 for s in self.seen if s.path.endswith("/certs"))

    def created(self) -> list[dict]:
        return [s.json() for s in self.seen if s.method == "POST" and s.path.endswith("/clients")]

    def writes(self) -> list[Seen]:
        return [s for s in self.seen if s.path.startswith("/admin/") and s.method != "GET"]


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
    port = KeycloakPrograms(issuer=issuer_of(kc.realm), audience=AUDIENCE, admin_client_id=ADMIN_CLIENT_ID,
                            admin_client_secret=ADMIN_CLIENT_SECRET, transport=kc.transport(), clock=clock)
    kc.opened.append(port)
    return port


# --- verification: the accepted shapes ------------------------------------------------------------

async def test_a_programs_realm_access_token_verifies_to_its_client_and_subject(kc):
    """RS256, programs issuer, programs audience, `typ` Bearer, unexpired -> client id, `sub`, `exp` (Verify)."""
    verified = await adapter(kc).verify_token(kc.signer.sign(token_claims()))
    assert verified == VerifiedProgramToken(client_id=CREDENTIAL, subject=SERVICE_ACCOUNT,
                                            expires_at=NOW + dt.timedelta(seconds=290))
    assert [s.path for s in kc.seen if s.path.endswith("/certs")] == [f"/realms/{REALM}/protocol/openid-connect/certs"]


@pytest.mark.parametrize("aud", [AUDIENCE, [AUDIENCE], ["account", AUDIENCE]], ids=["string", "list-of-one", "list-with-account"])
async def test_the_programs_audience_may_stand_alone_or_in_a_list(kc, aud):
    """`aud` contains the programs audience, as a string or among others (Verify, C22)."""
    assert (await adapter(kc).verify_token(kc.signer.sign(token_claims(aud=aud)))).client_id == CREDENTIAL


# --- verification: refusals, each beside the accepted control on the same adapter ------------------

def _hs256_with_public_key(kc: ProgramsKeycloak) -> str:
    head = _b64(json.dumps({"alg": "HS256", "typ": "JWT", "kid": kc.signer.kid}).encode())
    body = _b64(json.dumps(token_claims()).encode())
    return f"{head}.{body}.{_b64(hmac.new(kc.signer.public_pem(), f'{head}.{body}'.encode(), hashlib.sha256).digest())}"


def _rs384_by_the_realm_key(kc: ProgramsKeycloak) -> str:
    head = _b64(json.dumps({"alg": "RS384", "typ": "JWT", "kid": kc.signer.kid}).encode())
    body = _b64(json.dumps(token_claims()).encode())
    sig = kc.signer.key.sign(f"{head}.{body}".encode(), padding.PKCS1v15(), hashes.SHA384())
    return f"{head}.{body}.{_b64(sig)}"


def _unsigned(kc: ProgramsKeycloak) -> str:
    head = _b64(json.dumps({"alg": "none", "typ": "JWT", "kid": kc.signer.kid}).encode())
    return f"{head}.{_b64(json.dumps(token_claims()).encode())}."


def _without_kid(kc: ProgramsKeycloak) -> str:
    head = _b64(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
    body = _b64(json.dumps(token_claims()).encode())
    sig = kc.signer.key.sign(f"{head}.{body}".encode(), padding.PKCS1v15(), hashes.SHA256())
    return f"{head}.{body}.{_b64(sig)}"


def _claims_token(**over) -> Callable[[ProgramsKeycloak], str]:
    return lambda kc: kc.signer.sign(token_claims(**over))


@pytest.mark.parametrize("make", [
    pytest.param(lambda kc: Signer(kc.signer.kid).sign(token_claims()), id="foreign-key-same-kid"),
    pytest.param(_hs256_with_public_key, id="hs256-confusion"),
    pytest.param(_rs384_by_the_realm_key, id="rs-but-not-256"),
    pytest.param(_unsigned, id="alg-none"),
    pytest.param(_without_kid, id="no-key-id"),
    pytest.param(_claims_token(typ="ID"), id="typ-id"),
    pytest.param(_claims_token(typ="Refresh"), id="typ-refresh"),
    pytest.param(_claims_token(typ=None), id="typ-missing"),
    pytest.param(_claims_token(aud=["account"]), id="no-programs-audience"),
    pytest.param(_claims_token(aud=PEOPLE_AUDIENCE), id="people-client-audience"),
    pytest.param(_claims_token(aud=["account", "x" + AUDIENCE]), id="audience-lookalike"),
    pytest.param(_claims_token(aud=None), id="audience-missing"),
    pytest.param(_claims_token(iss=PEOPLE_ISSUER), id="people-realm-issuer"),
    pytest.param(_claims_token(iss=f"{ISSUER}-other"), id="issuer-sharing-our-prefix"),
    pytest.param(_claims_token(iss="https://evil.test/realms/defender-programs"), id="foreign-host-issuer"),
    pytest.param(_claims_token(iss=None), id="issuer-missing"),
    pytest.param(_claims_token(exp=int(NOW.timestamp()) - 1), id="expired"),
    pytest.param(_claims_token(exp=int(NOW.timestamp())), id="expires-now"),
    pytest.param(_claims_token(exp=None), id="exp-missing"),
    pytest.param(_claims_token(azp=None), id="no-client-id"),
    pytest.param(_claims_token(sub=None), id="no-subject"),
])
async def test_a_token_failing_one_check_is_refused(kc, make):
    """Signature, algorithm, key id, typ, aud, iss, exp, azp and sub are each checked (Verify, RFC 8725)."""
    port = adapter(kc)
    assert (await port.verify_token(kc.signer.sign(token_claims()))).client_id == CREDENTIAL
    with pytest.raises(SignInRefused):
        await port.verify_token(make(kc))


def _junk() -> list[str]:
    rng = random.Random(1307)
    junk = ["", " ", ".", "..", "a.b.c", "Bearer", "dfk_x", "x" * 5000, "\x00", "ü.ü.ü", "null", "{}", "[]"]
    for _ in range(40):
        junk.append(_b64(rng.randbytes(rng.randrange(1, 200))))
        junk.append(".".join(_b64(rng.randbytes(rng.randrange(1, 60))) for _ in range(3)))
    for head, body in ((b"[]", b"{}"), (b'"x"', b"{}"), (b"{}", b"[]"), (b"{}", b"1"), (b'{"alg":"RS256","kid":"kid-1"}', b"nope"),
                       (b'{"alg":"RS256","kid":5}', b"{}"), (b'{"alg":["RS256"],"kid":"kid-1"}', b"{}")):
        junk.append(f"{_b64(head)}.{_b64(body)}.{_b64(b'sig')}")
    return junk


async def test_anything_that_is_not_a_well_formed_token_is_refused_not_crashed(kc):
    """Any string, structured or random, ends in `SignInRefused` and no other exception (Verify)."""
    port = adapter(kc)
    assert (await port.verify_token(kc.signer.sign(token_claims()))).client_id == CREDENTIAL
    for junk in _junk():
        with pytest.raises(SignInRefused):
            await port.verify_token(junk)


# --- verification: the key set --------------------------------------------------------------------

async def test_a_known_key_id_never_refetches_the_key_set(kc):
    """Control: tokens under a cached key id cost no Keycloak traffic (Verify)."""
    clock = Clock()
    port = adapter(kc, clock)
    for _ in range(3):
        await port.verify_token(kc.signer.sign(token_claims()))
        clock.now += 2 * WINDOW
        kc_token = kc.signer.sign(token_claims(exp=int(clock.now.timestamp()) + 290))
        await port.verify_token(kc_token)
    assert kc.certs_fetches() == 1


async def test_an_unknown_key_id_refetches_the_key_set_at_most_once_per_minute(kc):
    """Unknown kid: one refetch, then refusals without traffic until the minute passes; a rotated key then verifies (Verify, C1)."""
    clock = Clock()
    port = adapter(kc, clock)
    assert (await port.verify_token(kc.signer.sign(token_claims()))).client_id == CREDENTIAL
    assert kc.certs_fetches() == 1  # the cold cache's own fetch
    clock.now += dt.timedelta(seconds=61)
    for n in range(100):
        with pytest.raises(SignInRefused):
            await port.verify_token(kc.signer.sign(token_claims(exp=int(clock.now.timestamp()) + 290), kid=f"random-{n}"))
    assert kc.certs_fetches() == 2  # one refetch for a hundred random key ids
    rotated = Signer(kid="kid-2")
    kc.jwks_keys.append(rotated.jwk())
    clock.now += dt.timedelta(seconds=59)
    fresh = token_claims(exp=int(clock.now.timestamp()) + 290)
    with pytest.raises(SignInRefused):
        await port.verify_token(rotated.sign(fresh))
    assert kc.certs_fetches() == 2
    clock.now += dt.timedelta(seconds=2)
    assert (await port.verify_token(rotated.sign(fresh))).subject == SERVICE_ACCOUNT
    assert kc.certs_fetches() == 3


async def test_two_realms_never_share_cached_keys():
    """A key cached for one issuer never verifies a token for another, even under the same key id (Verify: bound to its issuer)."""
    mine, theirs = ProgramsKeycloak(Signer(), REALM), ProgramsKeycloak(Signer(), OTHER_REALM)
    try:
        mine_port, their_port = adapter(mine), adapter(theirs)
        assert (await mine_port.verify_token(mine.signer.sign(token_claims()))).client_id == CREDENTIAL
        forged = mine.signer.sign(token_claims(iss=issuer_of(OTHER_REALM)))
        with pytest.raises(SignInRefused):
            await their_port.verify_token(forged)
        theirs_ok = theirs.signer.sign(token_claims(iss=issuer_of(OTHER_REALM)))
        assert (await their_port.verify_token(theirs_ok)).client_id == CREDENTIAL  # control
        assert {s.path for s in theirs.seen if s.path.endswith("/certs")} == {f"/realms/{OTHER_REALM}/protocol/openid-connect/certs"}
        assert {s.path for s in mine.seen if s.path.endswith("/certs")} == {f"/realms/{REALM}/protocol/openid-connect/certs"}
    finally:
        for fake in (mine, theirs):
            for port in fake.opened:
                await port.close()


_OUTAGES = [
    pytest.param(httpx.ConnectError("refused"), id="refused"),
    pytest.param(httpx.ReadTimeout("timed out"), id="timeout"),
    pytest.param(500, id="http-500"),
    pytest.param(503, id="http-503"),
]


@pytest.mark.parametrize("outage", _OUTAGES)
async def test_keycloak_down_on_a_cold_cache_is_unavailable_not_refused(kc, outage):
    """No cached keys and the key set cannot be fetched: `SignInUnavailable`, so the caller can tell down from forged (Verify, C12)."""
    kc.fail["certs"] = outage
    clock = Clock()
    port = adapter(kc, clock)
    with pytest.raises(SignInUnavailable):
        await port.verify_token(kc.signer.sign(token_claims()))
    del kc.fail["certs"]
    clock.now += 2 * WINDOW  # a failed fetch spends the window (W7, next test): wait it out
    fresh = kc.signer.sign(token_claims(exp=int(clock.now.timestamp()) + 290))
    assert (await port.verify_token(fresh)).client_id == CREDENTIAL  # control: same adapter, Keycloak back


@pytest.mark.parametrize("outage", _OUTAGES)
async def test_a_failed_key_set_fetch_spends_the_minute_so_an_outage_is_not_amplified(kc, outage):
    """After a failed fetch, an unknown key id within 60 s makes no /certs request and is unavailable, not refused (the
    key may exist: a 401 would tell the client to drop a good credential); after it, Keycloak is asked again (W7)."""
    kc.fail["certs"] = outage
    clock = Clock()
    port = adapter(kc, clock)
    with pytest.raises(SignInUnavailable):
        await port.verify_token(kc.signer.sign(token_claims(), kid="first"))
    assert kc.certs_fetches() == 1
    for n in range(20):
        clock.now += dt.timedelta(seconds=2)
        with pytest.raises(SignInUnavailable):
            await port.verify_token(kc.signer.sign(token_claims(exp=int(clock.now.timestamp()) + 290), kid=f"second-{n}"))
    assert kc.certs_fetches() == 1  # twenty unknown key ids inside the window, no traffic
    clock.now += dt.timedelta(seconds=30)  # 70 s after the failure
    with pytest.raises(SignInUnavailable):  # control: the window is over, Keycloak is asked (and still down)
        await port.verify_token(kc.signer.sign(token_claims(exp=int(clock.now.timestamp()) + 290), kid="third"))
    assert kc.certs_fetches() == 2


@pytest.mark.parametrize("outage", _OUTAGES)
async def test_held_tokens_keep_verifying_while_keycloak_is_down(kc, outage):
    """Cached keys serve known key ids through an outage; an unknown id after the minute is unavailable (Verify, Keycloak down)."""
    clock = Clock()
    port = adapter(kc, clock)
    await port.verify_token(kc.signer.sign(token_claims()))
    kc.fail["certs"] = outage
    fetched = kc.certs_fetches()
    assert (await port.verify_token(kc.signer.sign(token_claims()))).client_id == CREDENTIAL
    assert kc.certs_fetches() == fetched
    clock.now += dt.timedelta(seconds=61)
    with pytest.raises(SignInUnavailable):
        await port.verify_token(kc.signer.sign(token_claims(exp=int(clock.now.timestamp()) + 290), kid="rotated"))


class _GatedCerts(httpx.AsyncBaseTransport):
    """`kc`'s transport, with each key-set fetch held until `open` is set: a fetch that is still in flight."""

    def __init__(self, kc: ProgramsKeycloak) -> None:
        self._inner = kc.transport()
        self.open = asyncio.Event()

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/certs"):
            await self.open.wait()
        return await self._inner.handle_async_request(request)


def _gated_adapter(kc: ProgramsKeycloak, clock: Clock) -> tuple[KeycloakPrograms, _GatedCerts]:
    gated = _GatedCerts(kc)
    port = KeycloakPrograms(issuer=ISSUER, audience=AUDIENCE, admin_client_id=ADMIN_CLIENT_ID,
                            admin_client_secret=ADMIN_CLIENT_SECRET, transport=gated, clock=clock)
    kc.opened.append(port)
    return port, gated


async def test_requests_arriving_during_a_key_set_fetch_wait_for_it_and_verify(kc):
    """Cold cache, five valid tokens at once: one /certs request, and every token verifies once it answers; none
    is refused because another request's fetch was still in flight."""
    port, gated = _gated_adapter(kc, Clock())
    checks = [asyncio.create_task(port.verify_token(kc.signer.sign(token_claims()))) for _ in range(5)]
    await asyncio.sleep(0)
    assert not any(c.done() for c in checks)
    gated.open.set()
    assert {r.client_id for r in await asyncio.gather(*checks)} == {CREDENTIAL}
    assert kc.certs_fetches() == 1


@pytest.mark.parametrize("outage", _OUTAGES)
async def test_requests_waiting_on_a_failed_fetch_are_unavailable_not_refused(kc, outage):
    """The fetch they waited on fails: each waiting request is unavailable (503), and no second fetch is made."""
    kc.fail["certs"] = outage
    port, gated = _gated_adapter(kc, Clock())
    checks = [asyncio.create_task(port.verify_token(kc.signer.sign(token_claims()))) for _ in range(3)]
    await asyncio.sleep(0)
    gated.open.set()
    outcomes = await asyncio.gather(*checks, return_exceptions=True)
    assert all(isinstance(o, SignInUnavailable) for o in outcomes), outcomes
    assert kc.certs_fetches() == 1


async def test_a_key_keycloak_stopped_publishing_stops_verifying_after_the_max_age(kc):
    """A key removed from the realm (rotated out, or leaked) verifies until the held set is ten minutes old; the next
    token under it fetches the set again and is refused, while a token under the current key verifies."""
    clock = Clock()
    port = adapter(kc, clock)
    old = kc.signer
    assert (await port.verify_token(old.sign(token_claims()))).client_id == CREDENTIAL
    current = Signer(kid="kid-2")
    kc.jwks_keys[:] = [current.jwk()]
    clock.now += MAX_AGE - dt.timedelta(seconds=1)
    fresh = token_claims(exp=int(clock.now.timestamp()) + 290)
    assert (await port.verify_token(old.sign(fresh))).client_id == CREDENTIAL  # still within the age
    assert kc.certs_fetches() == 1
    clock.now += dt.timedelta(seconds=1)
    fresh = token_claims(exp=int(clock.now.timestamp()) + 290)
    with pytest.raises(SignInRefused):
        await port.verify_token(old.sign(fresh))
    assert kc.certs_fetches() == 2
    assert (await port.verify_token(current.sign(fresh))).subject == SERVICE_ACCOUNT
    assert kc.certs_fetches() == 2


@pytest.mark.parametrize("outage", _OUTAGES)
async def test_held_keys_past_the_max_age_keep_verifying_while_keycloak_is_down(kc, outage):
    """Past the age with Keycloak down: the held key still verifies (an outage does not take the API down), and the
    failed fetch spends the window, so the next tokens make no request."""
    clock = Clock()
    port = adapter(kc, clock)
    await port.verify_token(kc.signer.sign(token_claims()))
    kc.fail["certs"] = outage
    clock.now += MAX_AGE
    for _ in range(3):
        fresh = token_claims(exp=int(clock.now.timestamp()) + 290)
        assert (await port.verify_token(kc.signer.sign(fresh))).client_id == CREDENTIAL
    assert kc.certs_fetches() == 2


# --- client creation ------------------------------------------------------------------------------

async def test_a_client_is_created_under_the_credential_id_for_service_accounts_only(kc):
    """id = clientId = credential id; confidential, service accounts only, 300 s tokens, audience on the access token only (Create, C22/C23/C27)."""
    service_account, secret = await adapter(kc).create_client(CREDENTIAL)
    assert (service_account, secret) == (SERVICE_ACCOUNT, "kc-generated-secret")
    [body] = kc.created()
    assert body["id"] == body["clientId"] == CREDENTIAL
    assert body["publicClient"] is False
    assert body["serviceAccountsEnabled"] is True
    assert body["standardFlowEnabled"] is False
    assert body["implicitFlowEnabled"] is False
    assert body["directAccessGrantsEnabled"] is False
    assert not body.get("redirectUris")
    assert str(body["attributes"]["access.token.lifespan"]) == "300"
    [mapper] = [m for m in body["protocolMappers"] if m["protocolMapper"] == "oidc-audience-mapper"]
    config = mapper["config"]
    assert AUDIENCE in (config.get("included.custom.audience"), config.get("included.client.audience"))
    assert str(config["access.token.claim"]).lower() == "true"
    assert str(config.get("id.token.claim", "false")).lower() == "false"


async def test_the_adapter_works_in_its_own_realm_as_its_own_admin_client(kc):
    """Every call goes to the programs realm; the admin token is the admin client's own client-credentials grant (Realm: nothing in master)."""
    port = adapter(kc)
    await port.create_client(CREDENTIAL)
    await port.client_ids()
    await port.delete_client(CREDENTIAL)
    for seen in kc.seen:
        assert seen.path.startswith((f"/realms/{REALM}/", f"/admin/realms/{REALM}/")), seen.path
    assert kc.created()
    assert kc.writes()  # control: the writes did reach the realm
    grants = [s for s in kc.seen if s.path.endswith("/token")]
    assert grants
    basic = "Basic " + base64.b64encode(f"{ADMIN_CLIENT_ID}:{ADMIN_CLIENT_SECRET}".encode()).decode()
    for grant in grants:
        assert grant.form()["grant_type"] == "client_credentials"
        assert grant.form().get("client_id") == ADMIN_CLIENT_ID or grant.headers.get("authorization") == basic
    assert all(s.headers["authorization"] == f"Bearer {ADMIN_TOKEN}" for s in kc.seen if s.path.startswith("/admin/"))


@pytest.mark.parametrize("step", ["token", "create", "service-account", "secret"])
@pytest.mark.parametrize("outage", [httpx.ConnectError("refused"), httpx.ReadTimeout("timed out"), 500, 503],
                         ids=["refused", "timeout", "http-500", "http-503"])
async def test_a_failure_while_creating_a_client_is_unavailable_and_the_adapter_deletes_nothing(kc, step, outage):
    """Any failure of the create sequence is `SignInUnavailable`; only reconciliation deletes a client (Create, D3)."""
    kc.fail[step] = outage
    with pytest.raises(SignInUnavailable):
        await adapter(kc).create_client(CREDENTIAL)
    assert [s for s in kc.seen if s.method == "DELETE"] == []
    assert (CREDENTIAL in kc.clients) == (step in ("service-account", "secret"))  # what Keycloak committed stays committed
    del kc.fail[step]
    assert (await adapter(kc).create_client(OTHER_CREDENTIAL))[1] == "kc-generated-secret"  # control: same fake, no failure


async def test_creating_a_client_for_a_taken_id_is_unavailable_and_changes_nothing(kc):
    """A 409 (a retry after a lost response) is `SignInUnavailable`, the other client untouched (Create: any failure answers 503)."""
    port = adapter(kc)
    await port.create_client(CREDENTIAL)
    before = dict(kc.clients)
    with pytest.raises(SignInUnavailable):
        await port.create_client(CREDENTIAL)
    assert kc.clients == before
    assert [s for s in kc.seen if s.method == "DELETE"] == []


# --- listing and deleting -------------------------------------------------------------------------

def _seed_foreign_clients(kc: ProgramsKeycloak) -> None:
    for client_id in (ADMIN_CLIENT_ID, AUDIENCE, *BUILT_IN_CLIENTS, "not-a-uuid", "4b1f2a3c-0000-4000-8000-0000000000"):
        kc.clients[f"internal-{client_id}"] = {"id": f"internal-{client_id}", "clientId": client_id}


async def test_listing_names_program_clients_only(kc):
    """`client_ids` is the UUID client ids; built-in clients and the API's own are never listed (Reconciliation, W1)."""
    _seed_foreign_clients(kc)
    port = adapter(kc)
    await port.create_client(CREDENTIAL)
    assert await port.client_ids() == {CREDENTIAL}
    assert kc.writes() == [s for s in kc.seen if s.method == "POST" and s.path.endswith("/clients")]  # reading changed nothing


async def test_a_client_made_by_hand_with_a_uuid_client_id_is_not_listed(kc):
    """Only a client whose internal id is its client id is ours (`create_client` makes them so): one made by hand with a
    UUID client id has an internal id of Keycloak's own, and listing it would have `delete_client` miss it on every pass
    (#1450 review)."""
    port = adapter(kc)
    await port.create_client(CREDENTIAL)
    kc.clients["kc-internal-1"] = {"id": "kc-internal-1", "clientId": OTHER_CREDENTIAL}
    assert await port.client_ids() == {CREDENTIAL}


async def test_listing_follows_the_pages_to_the_last_client(kc):
    """More program clients than one page hold are all listed (Reconciliation)."""
    _seed_foreign_clients(kc)
    minted = {str(uuid.UUID(int=n)) for n in range(1, 231)}
    for client_id in minted:
        kc.clients[client_id] = {"id": client_id, "clientId": client_id}
    assert await adapter(kc).client_ids() == minted
    assert len([s for s in kc.seen if s.method == "GET" and s.path.endswith("/clients")]) >= 2  # control: it did page


async def test_deleting_removes_that_client_by_our_id_and_an_absent_one_is_no_error(kc):
    """`delete_client` addresses the client by its internal id (= credential id); absent is fine (Reconciliation, C27)."""
    _seed_foreign_clients(kc)
    port = adapter(kc)
    await port.create_client(CREDENTIAL)
    await port.create_client(OTHER_CREDENTIAL)
    assert await port.delete_client(CREDENTIAL) is True
    assert await port.delete_client(CREDENTIAL) is False  # already gone: no error, and not a deletion
    assert [s.path for s in kc.seen if s.method == "DELETE"] == [f"/admin/realms/{REALM}/clients/{CREDENTIAL}"] * 2
    assert await port.client_ids() == {OTHER_CREDENTIAL}
    assert len(kc.clients) == 1 + 8 + 2  # the API's own clients, built-ins and look-alikes stay


@pytest.mark.parametrize("op", ["list", "delete", "token"])
@pytest.mark.parametrize("outage", [httpx.ConnectError("refused"), httpx.ReadTimeout("timed out"), 500, 503],
                         ids=["refused", "timeout", "http-500", "http-503"])
async def test_a_failing_keycloak_makes_listing_and_deleting_unavailable(kc, op, outage):
    """Reconciliation needs an answer: an error is `SignInUnavailable`, never an empty list or a silent skip (Reconciliation)."""
    port = adapter(kc)
    await port.create_client(CREDENTIAL)
    kc.fail[op] = outage
    call = (lambda p: p.delete_client(CREDENTIAL)) if op == "delete" else (lambda p: p.client_ids())
    with pytest.raises(SignInUnavailable):
        await call(adapter(kc))
    del kc.fail[op]
    await call(adapter(kc))  # control: the same call on the same fake succeeds
