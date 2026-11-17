"""#1083 piece 1: shared machinery for tests of the real server program (`defender.api_server`).

- `environment(tmp_path, dsn=..., ...)`: every setting the program reads (design FC-3), valid; `SETTING_NAMES` is
  that full set.
- `FakeKeycloak`: both realms on the back channel (and only that host), answering as the dev Keycloak was observed
  to answer (code map, 2026-11-13, rule R11), with failures at a given (realm, step, kind) (`Fail`, `FAULTS`).
  Anything it does not model, any other host included, is answered 404 and kept in `unmodelled`. It keeps each
  realm's private signing key in `signing_keys[realm]`; `program_token(...)` mints a programs-realm access token with it.
  `answers` replaces a (realm, step)'s answer with any response or transport error (a generated failure space);
  `closes` counts the clients closed over it (one per adapter).
  #1161 adds the sign-in realm's `authorization_code` grant (modelled on `keycloak-observed-q34.md`, Keycloak 26.4.0),
  with self-describing codes (`authorization_code()`, `decode_code()`; the front channel in `_signin1161` mints
  them) and the account's credential list and user record (UNOBSERVED shapes, owed the `live` check).
- `Child`: the program in a child process. `Child.real(environ)` runs the shipped command
  (`python -m defender.api_server`, real network); `Child.faked(environ, fails=...)` runs this module's entry, which
  calls `defender.api_server.run(os.environ, transport=FakeKeycloak(...))`, reports `run returned <n>` on stdout,
  holds until `release()` (or `ended()`), then exits with `n`.
  With `LOADED_ENV` set it first reports `loaded <json>`: every module the process loaded while serving (#1495).
- `seed_token_credential(dsn, seeded)`: a live `oauth_client` credential for the seeded program, for `program_token`.
- `environment` also holds the API's OpenBao settings (#1470 G4); tests that start the program give `serving`/`run` an
  `openbao_transport=ScriptedOpenBao()` (`_openbao1470`), as they give Keycloak's `transport`.
- `seed_identity(dsn)`: Ann (tenant A admin), Bob (tenant B admin), Ops (a listed administrator, one-time-code
  session) and a program of A with a live API key.

Run as `python -m defender.tests.support.api._server1083` it is the test-support entry (design, Start and stop)."""
from __future__ import annotations

import base64
import contextlib
import dataclasses
import datetime as dt
import json
import os
import secrets
import functools
import hashlib
import re
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.parse
import uuid
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path
from typing import Any

import anyio
import httpx
import jwt
from defender.tests.support.identity._seed1496 import seed_membership, seed_user

from defender.tests.support.api._openbao1470 import KV_MOUNT, WRITER_TOKEN, ScriptedOpenBao

DEFENDER = Path(__file__).resolve().parents[3]
REPO = DEFENDER.parent

A = "0b6f1c1e-3c55-4a4e-9a51-1083000000aa"
B = "0b6f1c1e-3c55-4a4e-9a51-1083000000bb"
ANN, BOB, OPS = "ann@a.example", "bob@b.example", "ops@platform.example"
SESSION_COOKIE = "__Host-defender_session"
#: The walk-through's origin: the API's own (design, Dev walk-through 1).
ORIGIN = "http://localhost:8000"
#: As observed: discovery names the front-channel host; the API reaches Keycloak on the back channel.
FRONT, BACK = "http://localhost:8080", "http://keycloak:8080"
SIGNIN_REALM, PROGRAMS_REALM = "defender", "defender-programs"
#: The audience `environment()` configures for the programs realm's access tokens.
PROGRAMS_AUDIENCE = "defender-api-programs"
REALMS = (SIGNIN_REALM, PROGRAMS_REALM)
#: The admin read each realm's probe makes (design O3 / r5 Am-9): users in the sign-in realm, clients in programs.
ADMIN_READ = {SIGNIN_REALM: "users", PROGRAMS_REALM: "clients"}
#: The admin clients `environment()` configures, as (client id, secret): the fake refuses any other at the token
#: endpoint with the observed 401, so a program that sends the wrong id, or a secret file's text unstripped, is refused.
ADMIN_CLIENTS = {SIGNIN_REALM: ("defender-api-admin", "signin-admin-secret-value"),
                 PROGRAMS_REALM: ("defender-api-programs-admin", "programs-admin-secret-value")}
#: The sign-in client `environment()` configures, as (client id, secret): the code grant authenticates with it (HTTP Basic).
SIGNIN_CLIENT = ("defender-api", "signin-client-secret-value")
#: The child's failures travel in this variable (JSON list of `Fail`); it is not a setting of the program.
FAULTS_ENV = "CF1083_KEYCLOAK_FAULTS"
#: Set, the entry also reports every module the process loaded, once `run` returned: `loaded <json list>` (#1495).
LOADED_ENV = "CF1495_REPORT_LOADED"

SETTING_NAMES = (
    "DEFENDER_DATABASE_DSN",
    "DEFENDER_API_HOST",
    "DEFENDER_API_PORT",
    "DEFENDER_API_FRONTEND_ORIGIN",
    "DEFENDER_API_ADMINISTRATORS_FILE",
    "DEFENDER_KEYCLOAK_SERVER_URL",
    "DEFENDER_KEYCLOAK_ISSUER",
    "DEFENDER_KEYCLOAK_CLIENT_ID",
    "DEFENDER_KEYCLOAK_CLIENT_SECRET_FILE",
    "DEFENDER_KEYCLOAK_ADMIN_CLIENT_ID",
    "DEFENDER_KEYCLOAK_ADMIN_CLIENT_SECRET_FILE",
    "DEFENDER_KEYCLOAK_PROGRAMS_ISSUER",
    "DEFENDER_KEYCLOAK_PROGRAMS_AUDIENCE",
    "DEFENDER_KEYCLOAK_PROGRAMS_ADMIN_CLIENT_ID",
    "DEFENDER_KEYCLOAK_PROGRAMS_ADMIN_CLIENT_SECRET_FILE",
    "DEFENDER_OPENBAO_ADDR",
    "DEFENDER_OPENBAO_KV_MOUNT",
    "DEFENDER_API_OPENBAO_TOKEN_FILE",
)
#: #1470 G4: where the API's secret store is by default in `environment`: an address nothing answers, since a test that
#: starts the program gives `serving` a `ScriptedOpenBao` (or `openbao=` the address of one listening).
OPENBAO_ADDR = "http://127.0.0.1:1"


# --- ports ------------------------------------------------------------------------------------------

def free_port() -> int:
    """A port nothing listens on right now (a small race; the program binds it itself)."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


closed_port = free_port


# --- settings ---------------------------------------------------------------------------------------

def environment(  # noqa: PLR0913 — each keyword is one setting a test varies; a settings object would hide which
        tmp_path: Path, *, dsn: str, keycloak: str = BACK, port: int | None = None,
        administrators: tuple[str, ...] = (OPS,), origin: str = ORIGIN, front: str = FRONT,
        openbao: str = OPENBAO_ADDR, kv_mount: str = KV_MOUNT, token: str = WRITER_TOKEN) -> dict[str, str]:
    """Every setting the real program reads, valid (design FC-3). Secrets are files with a trailing newline; the
    OpenBao token file holds `token` (#1470 G4). `origin` is the frontend's; the redirect URI is derived from it by
    the program (#1161 B3: no setting). `front` is the identity provider's browser-facing host, the issuers' base."""
    def secret(name: str) -> str:
        path = tmp_path / name
        path.write_text(f"{name}-value\n")
        return str(path)

    token_file = tmp_path / "openbao-token"
    token_file.write_text(f"{token}\n")
    admins = tmp_path / "administrators.yaml"
    admins.write_text("administrators:\n" + "".join(f"  - {email}\n" for email in administrators))
    environ = {
        "DEFENDER_DATABASE_DSN": dsn,
        "DEFENDER_API_HOST": "127.0.0.1",
        "DEFENDER_API_PORT": str(port if port is not None else free_port()),
        "DEFENDER_API_FRONTEND_ORIGIN": origin,
        "DEFENDER_API_ADMINISTRATORS_FILE": str(admins),
        "DEFENDER_KEYCLOAK_SERVER_URL": keycloak,
        "DEFENDER_KEYCLOAK_ISSUER": f"{front}/realms/{SIGNIN_REALM}",
        "DEFENDER_KEYCLOAK_CLIENT_ID": "defender-api",
        "DEFENDER_KEYCLOAK_CLIENT_SECRET_FILE": secret("signin-client-secret"),
        "DEFENDER_KEYCLOAK_ADMIN_CLIENT_ID": "defender-api-admin",
        "DEFENDER_KEYCLOAK_ADMIN_CLIENT_SECRET_FILE": secret("signin-admin-secret"),
        "DEFENDER_KEYCLOAK_PROGRAMS_ISSUER": f"{front}/realms/{PROGRAMS_REALM}",
        "DEFENDER_KEYCLOAK_PROGRAMS_AUDIENCE": PROGRAMS_AUDIENCE,
        "DEFENDER_KEYCLOAK_PROGRAMS_ADMIN_CLIENT_ID": "defender-api-programs-admin",
        "DEFENDER_KEYCLOAK_PROGRAMS_ADMIN_CLIENT_SECRET_FILE": secret("programs-admin-secret"),
        "DEFENDER_OPENBAO_ADDR": openbao,
        "DEFENDER_OPENBAO_KV_MOUNT": kv_mount,
        "DEFENDER_API_OPENBAO_TOKEN_FILE": str(token_file),
    }
    assert tuple(environ) == SETTING_NAMES
    return environ


# --- Keycloak at the network edge -------------------------------------------------------------------

def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


SIGNING_KID, ENCRYPTION_KID = "sig-1", "enc-1"


@functools.cache
def _realm_keys(realm: str) -> tuple[Any, Any]:
    """The realm's (signing, encryption) private RSA keys; minted once per process and shared by every fake."""
    from cryptography.hazmat.primitives.asymmetric import rsa

    return (rsa.generate_private_key(public_exponent=65537, key_size=2048),
            rsa.generate_private_key(public_exponent=65537, key_size=2048))


def _jwk(private: Any, kid: str, use: str, alg: str) -> dict[str, Any]:
    numbers = private.public_key().public_numbers()
    return {"kid": kid, "kty": "RSA", "use": use, "alg": alg,
            "n": _b64(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")), "e": "AQAB"}


#: The probe's steps (FC-6; only the first step's name, "discovery", is pinned): the discovery document, the signing
#: keys, the admin client's token request, the admin read.
STEPS = ("discovery", "keys", "token", "admin")
#: The failure kinds each step can show, each one an answer the dev Keycloak was observed to give or one HTTP
#: answers generically. `not_found` at discovery is a realm that does not exist (observed: 404 on every path of it).
#: `unreadable` is a 200 whose body is not JSON; `enc_only` and `empty` are key sets with no key to verify with
#: (observed: the realms publish one signing and one encryption key); `bad_secret` and `no_role` are observed.
STEP_KINDS: dict[str, tuple[str, ...]] = {
    "discovery": ("not_found", "server_error", "unreadable", "wrong_issuer"),
    "keys": ("not_found", "server_error", "unreadable", "enc_only", "empty"),
    "token": ("not_found", "server_error", "unreadable", "bad_secret"),
    "admin": ("not_found", "server_error", "no_role"),
}
#: Discovery that never answers: waits until the request is cancelled (the during-start signal case). Not in the
#: table, because a start that is not signalled never ends.
STALL = "stall"
#: Every failure the program must refuse start for, as `(realm, step) -> kinds`.
FAULTS: dict[tuple[str, str], tuple[str, ...]] = {
    (realm, step): kinds for realm in REALMS for step, kinds in STEP_KINDS.items()}
#: The wrong issuer discovery names (a realm the configured issuer is not).
ELSEWHERE_ISSUER = f"{FRONT}/realms/elsewhere"


@dataclasses.dataclass(frozen=True)
class Fail:
    """One failure: at `realm`'s `step`, the answer of `kind` (`STEP_KINDS`, or `STALL` at discovery)."""
    realm: str
    step: str
    kind: str

    def __post_init__(self) -> None:
        assert self.realm in REALMS, self.realm
        assert self.kind in STEP_KINDS.get(self.step, ()) or (self.step, self.kind) == ("discovery", STALL), self


ALL_FAILS = tuple(Fail(realm, step, kind) for (realm, step), kinds in FAULTS.items() for kind in kinds)


def fails_to_json(fails: Iterable[Fail]) -> str:
    return json.dumps([dataclasses.asdict(f) for f in fails])


def fails_from_json(text: str) -> tuple[Fail, ...]:
    return tuple(Fail(**raw) for raw in json.loads(text))


def realms_named(text: str) -> set[str]:
    """The realms `text` names by their own name (`defender` is also a prefix of `defender-programs` and of the
    admin client ids, which are not realms)."""
    return {realm for realm in REALMS if re.search(rf"(?<![\w-]){re.escape(realm)}(?![\w-])", text)}


# --- authorization codes ----------------------------------------------------------------------------

#: What an authorize request and the test's choices for it bind into a code (design B8): the exchange verifies them
#: from the code itself, so the front channel (the test process) and the exchange (the API's child) share no state.
CODE_FIELDS = ("sub", "nonce", "challenge", "redirect_uri", "amr", "name", "credentials", "fault")
#: A per-code fault the exchange honours: the observed `invalid_grant` "Code not valid", or a refused connection.
CODE_FAULTS = ("invalid_grant", "unavailable")


def authorization_code(  # noqa: PLR0913 — the code's bound fields, one keyword each
        *, sub: str, nonce: str, challenge: str, redirect_uri: str, amr: Iterable[str] = ("pwd",),
                       name: str = "", credentials: Iterable[str] = ("password",), fault: str | None = None,
                       session_state: str | None = None) -> str:
    """A code in Keycloak's observed shape (three dot-joined segments: here the payload, the session state, a client
    id), whose first segment carries `CODE_FIELDS` and a unique id (so two codes with equal fields differ)."""
    assert fault is None or fault in CODE_FAULTS, fault
    payload = {"sub": sub, "nonce": nonce, "challenge": challenge, "redirect_uri": redirect_uri, "amr": list(amr),
               "name": name, "credentials": list(credentials), "fault": fault, "id": str(uuid.uuid4())}
    return ".".join((_b64(json.dumps(payload).encode()), session_state or str(uuid.uuid4()), str(uuid.uuid4())))


def decode_code(code: str) -> dict[str, Any] | None:
    """The fields a code carries, or None when it is not one `authorization_code()` made."""
    try:
        first = code.split(".")[0]
        fields = json.loads(base64.urlsafe_b64decode(first + "=" * (-len(first) % 4)))
    except (ValueError, UnicodeDecodeError):
        return None
    return fields if isinstance(fields, dict) and all(k in fields for k in CODE_FIELDS) else None


def _unreadable() -> httpx.Response:
    return httpx.Response(200, content=b"<html>not what was asked for</html>", headers={"content-type": "text/html"})


class FakeKeycloak(httpx.AsyncBaseTransport):
    """Both realms, answering as observed on the dev Keycloak (code map 2026-11-13), and only on the back-channel
    host (`back`): a request to any other host is answered 404 and kept in `unmodelled`, as is anything else the
    fake does not model. Records every request in `seen` as `(method, "host:port/path")`.

    `fails` are failures at (realm, step); at most one per (realm, step). `answers[(realm, step)]` answers that step
    in place of the fake (a response, or raising a transport error). `on_stall(realm)` runs when a stalled discovery
    begins. Each realm's private signing key is `signing_keys[realm]` (published as kid `SIGNING_KID`). `closes`
    counts `aclose()` calls: an `httpx.AsyncClient` closes its transport once, so one per adapter closed.

    The sign-in realm's account administration, as the identity service's mail sender uses it
    (`KeycloakSignIn.create_account`, `send_set_password_email`), is modelled from Keycloak's admin REST API
    documentation, UNOBSERVED on the dev Keycloak (a probe would write; rule R11, owed a live check):
    `POST /admin/realms/<realm>/users` answers 201 with `Location: <server>/admin/realms/<realm>/users/<new id>`, or
    409 `{"errorMessage": "User exists with same username"}` (or `... email`) for a taken username or email;
    `GET .../users?username=<u>&exact=true` lists that account; `PUT .../users/<id>/execute-actions-email` answers
    204 (404 for an unknown id), and the mail is kept in `mails` as `(realm, id, actions)`. Only the realm whose
    admin role covers users (`ADMIN_READ`) may; the other answers 403, as for its reads.

    The sign-in realm's `authorization_code` grant (#1161 B8; observed, `keycloak-observed-q34.md`): HTTP Basic client
    authentication (`signin_client`; 401 otherwise), a code from `authorization_code()`, and `code_verifier` and
    `redirect_uri` that match the code's challenge (S256) and redirect URI. A code is single use by this fake's own
    record (`spent`): a second exchange, a wrong verifier (which burns it) and a code that is not ours are
    `invalid_grant`, with the observed texts ("Code not valid", "PKCE verification failed: Code mismatch", "Incorrect
    redirect_uri"; a wrong redirect URI does not burn the code, UNOBSERVED). A code's `fault` is honoured at
    exchange: `invalid_grant`, or a refused connection (`httpx.ConnectError`). The ID token is signed with the realm's
    key and carries `iss`, `aud`, `sub`, `nonce`, `amr` and the observed companions. A step's `fails` and `answers`
    still apply first, to the code grant as to any other token request.

    The account's side, UNOBSERVED shapes (owed the `live` check): `GET .../users/<id>/credentials` lists `credentials[id]` (a code's list is recorded
    at its exchange; default a password) as `{id, type, createdDate}`; `GET .../users/<id>` is its record (an id neither created here nor signed in at the front
    channel answers 404 on the record `GET`, `PUT` and `GET .../credentials`; only the `GET .../credentials` status is observed (the live
    check's last line); the record `GET` and `PUT` statuses and the body `{"error": "User not found"}` are UNOBSERVED and reached by no contract path) and `PUT` merges the body into it (204); read `records[id]["requiredActions"]` after a `PUT`."""

    def __init__(self, fails: Iterable[Fail] = (), *, front: str = FRONT, back: str = BACK,
                 admin_clients: Mapping[str, tuple[str, str]] = ADMIN_CLIENTS,
                 signin_client: tuple[str, str] = SIGNIN_CLIENT,
                 on_stall: Callable[[str], None] | None = None,
                 answers: Mapping[tuple[str, str], Callable[[httpx.Request], httpx.Response]] | None = None) -> None:
        self.fails = {(f.realm, f.step): f.kind for f in fails}
        self.answers = dict(answers or {})
        self.admin_clients = dict(admin_clients)
        self.signin_client = signin_client
        self.front = front
        parsed = urllib.parse.urlsplit(back)
        self.back_host, self.back_port = parsed.hostname, parsed.port
        self.on_stall = on_stall
        self.signing_keys = {realm: _realm_keys(realm)[0] for realm in REALMS}
        self.encryption_keys = {realm: _realm_keys(realm)[1] for realm in REALMS}
        self.keys = {realm: [_jwk(self.signing_keys[realm], SIGNING_KID, "sig", "RS256"),
                             _jwk(self.encryption_keys[realm], ENCRYPTION_KID, "enc", "RSA-OAEP")]
                     for realm in REALMS}
        self.seen: list[tuple[str, str]] = []
        self.unmodelled: list[tuple[str, str]] = []
        self.accounts: dict[str, dict[str, Any]] = {}  # id -> account, the sign-in realm's created accounts
        self.mails: list[tuple[str, str, list[str]]] = []
        self.spent: set[str] = set()  # the codes exchanged, whole (the grant's own single-use record)
        self.exchanges: list[str] = []  # each exchange's code, in order, whatever came of it
        self.credentials: dict[str, list[str]] = {}  # account id -> credential types
        self.records: dict[str, dict[str, Any]] = {}  # account id -> user record, for accounts not created here
        self.closes = 0

    async def aclose(self) -> None:
        self.closes += 1

    def issuer(self, realm: str) -> str:
        return f"{self.front}/realms/{realm}"

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        await request.aread()
        method, path = request.method, request.url.path
        self.seen.append((method, f"{request.url.host}:{request.url.port}{path}"))
        if (request.url.host, request.url.port) == (self.back_host, self.back_port):
            for realm in REALMS:
                if path.startswith((f"/realms/{realm}/", f"/admin/realms/{realm}/")):
                    answer = await self._answer(realm, request)
                    if answer is not None:
                        return answer
        self.unmodelled.append((method, str(request.url)))
        return httpx.Response(404)

    @staticmethod
    def _step(realm: str, request: httpx.Request) -> str | None:
        route = (request.method, request.url.path)
        return {("GET", f"/realms/{realm}/.well-known/openid-configuration"): "discovery",
                ("GET", f"/realms/{realm}/protocol/openid-connect/certs"): "keys",
                ("POST", f"/realms/{realm}/protocol/openid-connect/token"): "token",
                ("GET", f"/admin/realms/{realm}/users"): "admin",
                ("GET", f"/admin/realms/{realm}/clients"): "admin"}.get(route)

    async def _answer(self, realm: str, request: httpx.Request) -> httpx.Response | None:
        step = self._step(realm, request)
        if self.fails.get((realm, "discovery")) == "not_found":  # the realm does not exist: every path of it
            return httpx.Response(404, json={"error": "Realm does not exist"})
        if step is None:
            return self._accounts(realm, request)
        if (realm, step) in self.answers:
            return self.answers[(realm, step)](request)
        kind = self.fails.get((realm, step))
        if kind == STALL:
            if self.on_stall is not None:
                self.on_stall(realm)
            await anyio.sleep_forever()
        if kind == "not_found":
            return httpx.Response(404, json={"error": "HTTP 404 Not Found"})
        if kind == "server_error":
            return httpx.Response(503, content=b"Service Unavailable")
        if kind == "unreadable":
            return _unreadable()
        return {"discovery": self._discovery, "keys": self._keys, "token": self._token,
                "admin": self._admin}[step](realm, request, kind)

    def _discovery(self, realm: str, request: httpx.Request, kind: str | None) -> httpx.Response:
        issuer = self.issuer(realm)
        return httpx.Response(200, json={
            "issuer": ELSEWHERE_ISSUER if kind == "wrong_issuer" else issuer,
            "token_endpoint": f"{issuer}/protocol/openid-connect/token",
            "jwks_uri": f"{issuer}/protocol/openid-connect/certs"})

    def _keys(self, realm: str, request: httpx.Request, kind: str | None) -> httpx.Response:
        keys = {"enc_only": self.keys[realm][1:], "empty": []}.get(kind or "", self.keys[realm])
        return httpx.Response(200, json={"keys": keys})

    def _token(self, realm: str, request: httpx.Request, kind: str | None) -> httpx.Response | None:
        grant = urllib.parse.parse_qs(request.content.decode()).get("grant_type")
        if grant == ["authorization_code"] and realm == SIGNIN_REALM:
            return self._code_grant(realm, request)
        if grant != ["client_credentials"]:
            return None
        client = self._basic_client(request)
        if client is None or client[0] != self.admin_clients[realm][0]:  # unknown id, or no client authentication
            return httpx.Response(401, json={
                "error": "invalid_client", "error_description": "Invalid client or Invalid client credentials"})
        if kind == "bad_secret" or client != self.admin_clients[realm]:  # a known id, the wrong secret
            return httpx.Response(401, json={
                "error": "unauthorized_client", "error_description": "Invalid client or Invalid client credentials"})
        return httpx.Response(200, json={"access_token": f"admin-{realm}", "token_type": "Bearer", "expires_in": 300})

    def _code_grant(self, realm: str, request: httpx.Request) -> httpx.Response:
        form = {k: v[0] for k, v in urllib.parse.parse_qs(request.content.decode()).items()}
        client = self._basic_client(request)
        if client is None or client[0] != self.signin_client[0]:
            return httpx.Response(401, json={
                "error": "invalid_client", "error_description": "Invalid client or Invalid client credentials"})
        if client != self.signin_client:
            return httpx.Response(401, json={
                "error": "unauthorized_client", "error_description": "Invalid client or Invalid client credentials"})
        code = form.get("code", "")
        self.exchanges.append(code)
        fields = decode_code(code)
        if fields is None or code in self.spent:
            return self._invalid_grant("Code not valid")
        if fields["fault"] == "unavailable":
            raise httpx.ConnectError("connection refused", request=request)
        if fields["fault"] == "invalid_grant":
            self.spent.add(code)
            return self._invalid_grant("Code not valid")
        self.spent.add(code)  # observed: a wrong verifier burns the code
        if _b64(hashlib.sha256(form.get("code_verifier", "").encode()).digest()) != fields["challenge"]:
            return self._invalid_grant("PKCE verification failed: Code mismatch")
        if form.get("redirect_uri") != fields["redirect_uri"]:
            self.spent.discard(code)  # UNOBSERVED whether it burns
            return self._invalid_grant("Incorrect redirect_uri")
        self.credentials[fields["sub"]] = list(fields["credentials"])
        self.records.setdefault(fields["sub"], {"id": fields["sub"], "username": fields["sub"], "enabled": True,
                                                "emailVerified": True, "requiredActions": []})
        now = dt.datetime.now(dt.UTC)
        stamp = int(now.timestamp())
        session_state = code.split(".")[1] if code.count(".") == 2 else str(uuid.uuid4())
        claims = {"exp": stamp + 300, "iat": stamp, "auth_time": stamp, "jti": str(uuid.uuid4()),
                  "iss": self.issuer(realm), "aud": self.signin_client[0], "sub": fields["sub"], "typ": "ID",
                  "azp": self.signin_client[0], "nonce": fields["nonce"], "sid": session_state, "acr": "1",
                  "email_verified": True, "amr": fields["amr"], "name": fields["name"]}
        id_token = jwt.encode(claims, self.signing_keys[realm], algorithm="RS256", headers={"kid": SIGNING_KID})
        return httpx.Response(200, json={
            "access_token": "access-" + str(uuid.uuid4()), "expires_in": 300, "refresh_expires_in": 1800,
            "refresh_token": "refresh-" + str(uuid.uuid4()), "token_type": "Bearer", "id_token": id_token,
            "not-before-policy": 0, "session_state": session_state, "scope": "openid email profile"})

    @staticmethod
    def _invalid_grant(description: str) -> httpx.Response:
        return httpx.Response(400, json={"error": "invalid_grant", "error_description": description})

    def _admin(self, realm: str, request: httpx.Request, kind: str | None) -> httpx.Response:
        if request.headers.get("authorization") != f"Bearer admin-{realm}":  # an unknown (or no) bearer
            return httpx.Response(401, json={"error": "HTTP 401 Unauthorized"})
        # As observed: each admin client's role covers only its own resource; the other answers 403.
        if request.url.path.endswith(f"/{ADMIN_READ[realm]}") and kind != "no_role":
            if ADMIN_READ[realm] != "users" or "username" not in request.url.params:
                return httpx.Response(200, json=[])
            wanted = request.url.params["username"]  # the adapter searches `exact=true` (UNOBSERVED, see the class)
            return httpx.Response(200, json=[a for a in self.accounts.values() if a["username"] == wanted])
        return httpx.Response(403, json={"error": "HTTP 403 Forbidden"})

    def _accounts(self, realm: str, request: httpx.Request) -> httpx.Response | None:
        """Account create and the set-password mail (UNOBSERVED, see the class); None for anything else."""
        users = f"/admin/realms/{realm}/users"
        path = request.url.path
        person = self._person(users, path)
        if person is not None:
            return self._person_answer(realm, request, *person)
        create = (request.method, path) == ("POST", users)
        mail = request.method == "PUT" and path.startswith(f"{users}/") and path.endswith("/execute-actions-email")
        if not (create or mail):
            return None
        if request.headers.get("authorization") != f"Bearer admin-{realm}":
            return httpx.Response(401, json={"error": "HTTP 401 Unauthorized"})
        if ADMIN_READ[realm] != "users":
            return httpx.Response(403, json={"error": "HTTP 403 Forbidden"})
        if create:
            body = json.loads(request.content)
            for field in ("username", "email"):
                if any(a[field] == body[field] for a in self.accounts.values()):
                    return httpx.Response(409, json={"errorMessage": f"User exists with same {field}"})
            account_id = str(uuid.uuid4())
            self.accounts[account_id] = {"id": account_id, **body}
            return httpx.Response(201, headers={"Location": f"{request.url.scheme}://{request.url.netloc.decode()}{users}/{account_id}"})
        account_id = path.removeprefix(f"{users}/").removesuffix("/execute-actions-email")
        if account_id not in self.accounts:
            return httpx.Response(404, json={"error": "User not found"})
        self.mails.append((realm, account_id, json.loads(request.content)))
        return httpx.Response(204)

    @staticmethod
    def _person(users: str, path: str) -> tuple[str, bool] | None:
        """(account id, whether its credential list is asked) for `<users>/<id>` and `<users>/<id>/credentials`."""
        if not path.startswith(f"{users}/"):
            return None
        rest = path.removeprefix(f"{users}/")
        if rest.endswith("/credentials"):
            return urllib.parse.unquote(rest.removesuffix("/credentials")), True
        return (urllib.parse.unquote(rest), False) if rest and "/" not in rest else None

    def _person_answer(self, realm: str, request: httpx.Request, account_id: str, credentials: bool
                       ) -> httpx.Response | None:
        if (request.method, credentials) not in (("GET", True), ("GET", False), ("PUT", False)):
            return None
        if request.headers.get("authorization") != f"Bearer admin-{realm}":
            return httpx.Response(401, json={"error": "HTTP 401 Unauthorized"})
        if ADMIN_READ[realm] != "users":
            return httpx.Response(403, json={"error": "HTTP 403 Forbidden"})
        record = self.accounts.get(account_id) or self.records.get(account_id)
        if record is None:  # status observed for GET .../credentials only (live check); record GET/PUT status and body UNOBSERVED
            return httpx.Response(404, json={"error": "User not found"})
        if credentials:
            return httpx.Response(200, json=[
                {"id": str(uuid.uuid5(uuid.NAMESPACE_URL, f"{account_id}/{kind}")), "type": kind,
                 "createdDate": 1_700_000_000_000} for kind in self.credentials.get(account_id, ["password"])])
        if request.method == "GET":
            return httpx.Response(200, json=record)
        record.update(json.loads(request.content))
        return httpx.Response(204)

    @staticmethod
    def _basic_client(request: httpx.Request) -> tuple[str, str] | None:
        """The (id, secret) of HTTP basic client authentication, as the adapters send it; None if absent."""
        scheme, _, encoded = request.headers.get("authorization", "").partition(" ")
        if scheme.lower() != "basic":
            return None
        try:
            client_id, _, secret = base64.b64decode(encoded).decode().partition(":")
        except ValueError:
            return None
        return urllib.parse.unquote_plus(client_id), urllib.parse.unquote_plus(secret)


# --- the program in a child -------------------------------------------------------------------------

@dataclasses.dataclass
class Ended:
    returncode: int
    stdout: str
    stderr: str


class _Pump:
    """Reads one of the child's pipes on a thread, so a test can wait for a line while the child lives and still
    get the whole text after it ends."""

    def __init__(self, stream: Any) -> None:
        self._stream = stream
        self._lines: list[str] = []
        self._changed = threading.Condition()
        self._thread = threading.Thread(target=self._read, daemon=True)
        self._thread.start()

    def _read(self) -> None:
        for line in self._stream:
            with self._changed:
                self._lines.append(line)
                self._changed.notify_all()
        with self._changed:
            self._changed.notify_all()

    def line_starting(self, prefix: str, timeout: float) -> str | None:
        deadline = time.monotonic() + timeout
        with self._changed:
            while True:
                for line in self._lines:
                    if line.startswith(prefix):
                        return line.rstrip("\n")
                left = deadline - time.monotonic()
                if left <= 0 or not self._thread.is_alive():
                    return None
                self._changed.wait(min(left, 0.5))

    def text(self) -> str:
        self._thread.join(10)
        return "".join(self._lines)


def _die_with_parent() -> None:
    """Child-side, before exec: ask the kernel to SIGKILL this process when its parent dies. No-op off Linux."""
    try:
        import ctypes
        ctypes.CDLL(None, use_errno=True).prctl(1, signal.SIGKILL)  # PR_SET_PDEATHSIG == 1
    except Exception:  # noqa: BLE001 - harmless where unavailable
        pass


class Child:
    """The program in a child process with only `environ`'s `DEFENDER_*` settings (plus the failures).

    `ended()` waits for a program that should refuse to start (cut off after `timeout`, failing the caller's
    assertion on returncode). `ready()` waits until it answers HTTP on its port. `send_signal(sig)` and `stop(sig)` send
    `sig` to this child's PID only (never a process group, never `pkill`).

    For `Child.faked`: `stalled()` waits for a stalled discovery to begin (a start under way); `reported()` reads
    the entry's `run returned <n>` line; the entry then holds, alive, until `release()` (which `ended()` does), so
    a test can observe the database between `run`'s return and the process's exit.

    On Linux the child is killed with the parent (`PR_SET_PDEATHSIG`, SIGKILL), so a crashed test worker leaves no
    orphan. That signal follows the parent *thread*: spawn a `Child` from the main thread."""

    def __init__(self, argv: list[str], environ: Mapping[str, str], *, holds: bool = False) -> None:
        env = {k: v for k, v in os.environ.items() if not k.startswith(("DEFENDER_", FAULTS_ENV))}
        env["PYTHONPATH"] = os.pathsep.join(p for p in (str(REPO), os.environ.get("PYTHONPATH", "")) if p)
        env.update(environ)
        self.environ = dict(environ)
        self.process = subprocess.Popen(argv, cwd=str(REPO), env=env, text=True, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, preexec_fn=_die_with_parent,
                                        stdin=subprocess.PIPE if holds else subprocess.DEVNULL)
        self._out = _Pump(self.process.stdout)
        self._err = _Pump(self.process.stderr)

    @classmethod
    def real(cls, environ: Mapping[str, str]) -> Child:
        """The shipped command, `python -m defender.api_server`, on the real network."""
        return cls([sys.executable, "-m", "defender.api_server"], environ)

    @classmethod
    def faked(cls, environ: Mapping[str, str], fails: Iterable[Fail] = ()) -> Child:
        """`defender.api_server.run` over a `FakeKeycloak` with `fails`, through this module's entry."""
        return cls([sys.executable, "-m", "defender.tests.support.api._server1083"],
                   {**environ, FAULTS_ENV: fails_to_json(fails)}, holds=True)

    @property
    def base_url(self) -> str:
        return f"http://{self.environ['DEFENDER_API_HOST']}:{self.environ['DEFENDER_API_PORT']}"

    def stalled(self, timeout: float = 60) -> bool:
        """True once the fake's stalled discovery has begun: the program is mid-start, waiting on Keycloak."""
        return self._out.line_starting("stalled ", timeout) is not None

    def reported(self, timeout: float = 60) -> int | None:
        """The value the entry says `run` returned; None if it never said (killed, or `run` never returned)."""
        line = self._out.line_starting("run returned ", timeout)
        return None if line is None else int(line.rsplit(" ", 1)[1])

    def unmodelled(self, timeout: float = 60) -> list[list[str]] | None:
        """What the child's fake answered as unmodelled (printed once `run` returned); None if it never said."""
        line = self._out.line_starting("unmodelled ", timeout)
        return None if line is None else json.loads(line.removeprefix("unmodelled "))

    def release(self) -> None:
        """Let a held entry exit (idempotent)."""
        if self.process.stdin is not None and not self.process.stdin.closed:
            with contextlib.suppress(OSError):
                self.process.stdin.close()

    def ended(self, timeout: float = 90) -> Ended:
        self.release()
        try:
            self.process.wait(timeout)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
            return Ended(-9999, self._out.text(), "the program kept running when it should have ended\n"
                         + self._err.text())
        return Ended(self.process.returncode, self._out.text(), self._err.text())

    def ready(self, timeout: float = 60, path: str = "/api/openapi.json") -> bool:
        """True once `GET <path>` (the OpenAPI document; `/api/openapi.json` under #1161 B3) answers 200; False if the child exits or the time runs out first."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                return False
            try:
                if httpx.get(f"{self.base_url}{path}", timeout=2).status_code == 200:
                    return True
            except httpx.TransportError:
                pass
            time.sleep(0.2)
        return False

    def send_signal(self, sig: int = signal.SIGTERM) -> None:
        if self.process.poll() is None:
            os.kill(self.process.pid, sig)

    def stop(self, sig: int = signal.SIGTERM, timeout: float = 60) -> Ended:
        self.send_signal(sig)
        return self.ended(timeout)

    def kill(self) -> None:
        """Cleanup for a test that failed mid-way: SIGKILL this child only, if still running."""
        if self.process.poll() is None:
            self.process.kill()
        self.release()
        self.process.wait()


# --- identity seed ----------------------------------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class Seeded:
    ann_session: str
    bob_session: str
    ops_session: str
    program_id: str
    credential_id: str
    program_key: str


async def seed_identity(dsn: str) -> Seeded:
    """Ann (A) and Bob (B) as admin members with sessions; Ops, a listed administrator, with a one-time-code
    session; a program of A with a live key. Tenants A and B must already be registered."""
    from defender.identity.memory import secret_hash
    from defender.identity.postgres import PostgresIdentityRepository
    from defender.identity.service import KEY_PREFIX
    from defender.records.formats import CredentialId, TenantId

    sessions = {email: secrets.token_urlsafe(32) for email in (ANN, BOB, OPS)}
    now = dt.datetime.now(dt.UTC)  # the composed server runs on the real clock
    repo = PostgresIdentityRepository(dsn)
    try:
        users = {}
        for email, tenant in ((ANN, A), (BOB, B)):
            user = await seed_user(repo, email, created_at=now, status="active", display_name=email)
            await seed_membership(repo, user.id, TenantId(tenant), status="active", invited_by=None, created_at=now,
                                      accepted_at=now)
            await repo.add_session(sessions[email], user.id, now=now, expires_at=now + dt.timedelta(days=1))
            users[email] = user
        ops = await seed_user(repo, OPS, created_at=now, status="active", display_name="Ops", is_platform_admin=True)
        await repo.add_session(sessions[OPS], ops.id, now=now, expires_at=now + dt.timedelta(days=1), used_otp=True)
        program = await repo.add_program(TenantId(A), display_name="ci", created_by=users[ANN].id, now=now)
        credential_id = CredentialId.mint()
        key = f"{KEY_PREFIX}{credential_id}_{secrets.token_urlsafe(32)}"
        await repo.add_credential(program.id, kind="key", name="ci-key", created_by=users[ANN].id,
                                  expires_at=now + dt.timedelta(days=30), now=now, key_hash=secret_hash(key),
                                  credential_id=credential_id)
        return Seeded(sessions[ANN], sessions[BOB], sessions[OPS], str(program.id), str(credential_id), key)
    finally:
        await repo.close()


@dataclasses.dataclass(frozen=True)
class TokenCredential:
    credential_id: str
    service_account_id: str


async def seed_token_credential(dsn: str, seeded: Seeded) -> TokenCredential:
    """A live `oauth_client` credential of the seeded program, as the programs realm's client would be (a service
    account id recorded when it went live). It takes the program's second credential slot."""
    from defender.identity.postgres import PostgresIdentityRepository
    from defender.records.formats import CredentialId, ProgramId

    now = dt.datetime.now(dt.UTC)
    service_account = str(uuid.uuid4())
    repo = PostgresIdentityRepository(dsn)
    try:
        program = await repo.program(ProgramId(seeded.program_id))
        assert program is not None
        credential_id = CredentialId.mint()
        await repo.add_credential(program.id, kind="oauth_client", name="ci-token", created_by=program.created_by,
                                  expires_at=now + dt.timedelta(days=30), now=now, credential_id=credential_id)
        assert await repo.go_live(credential_id, service_account_id=service_account, now=now)
        return TokenCredential(str(credential_id), service_account)
    finally:
        await repo.close()


def program_token(keycloak: FakeKeycloak, credential: TokenCredential, *, audience: str = PROGRAMS_AUDIENCE,
                  realm: str = PROGRAMS_REALM, lifetime: dt.timedelta = dt.timedelta(minutes=5)) -> str:
    """The client-credentials access token the programs realm issues for `credential` (claims as observed, #1307
    C21/C22), signed with the fake's published key of `realm` and valid now. A wrong `audience` or `realm` makes
    the token one the server must refuse."""
    from defender.tests.identity.test_1307_keycloak_programs import token_claims
    from defender.tests.identity.test_identity_keycloak_adapter import Signer

    signer = Signer(SIGNING_KID)
    signer.key = keycloak.signing_keys[realm]
    now = dt.datetime.now(dt.UTC)
    return signer.sign(token_claims(iss=keycloak.issuer(realm), aud=[audience, "account"], azp=credential.credential_id,
                                    sub=credential.service_account_id, iat=int(now.timestamp()) - 10,
                                    exp=int((now + lifetime).timestamp())))


def person(session: str, *, write: bool = False) -> dict[str, str]:
    """A person's request headers; `write` adds the origin a cookie-authenticated write needs."""
    headers = {"Cookie": f"{SESSION_COOKIE}={session}"}
    return {**headers, "Origin": ORIGIN} if write else headers


def program(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


# --- test-support entry -----------------------------------------------------------------------------

def _main() -> int:
    """Calls `run`, reports its return on stdout, then (held until the parent releases stdin) exits with it."""
    from defender.api_server import run

    fails = fails_from_json(os.environ[FAULTS_ENV]) if FAULTS_ENV in os.environ else ()
    issuer = urllib.parse.urlsplit(os.environ.get("DEFENDER_KEYCLOAK_ISSUER", FRONT))  # the browser-facing host
    front = f"{issuer.scheme}://{issuer.netloc}"
    keycloak = FakeKeycloak(fails, front=front, on_stall=lambda realm: print(f"stalled {realm}", flush=True))
    returned = run(os.environ, transport=keycloak, openbao_transport=ScriptedOpenBao())
    if LOADED_ENV in os.environ:
        print(f"loaded {json.dumps(sorted(sys.modules))}", flush=True)
    print(f"unmodelled {json.dumps(keycloak.unmodelled)}", flush=True)
    print(f"run returned {returned}", flush=True)
    sys.stdin.readline()  # hold: the parent observes the database, then closes stdin
    return returned


if __name__ == "__main__":
    raise SystemExit(_main())
