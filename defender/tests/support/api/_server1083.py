"""#1083 piece 1: shared machinery for tests of the real server program (`defender.api_server`).

- `environment(tmp_path, dsn=..., ...)`: every setting the program reads (design FC-3), valid; `SETTING_NAMES` is
  that full set.
- `FakeKeycloak`: both realms on the back channel (and only that host), answering as the dev Keycloak was observed
  to answer (code map, 2026-11-13, rule R11), with failures at a given (realm, step, kind) (`Fail`, `FAULTS`).
  Anything it does not model, any other host included, is answered 404 and kept in `unmodelled`. It keeps each
  realm's private signing key in `signing_keys[realm]`; `program_token(...)` mints a programs-realm access token with it.
- `Child`: the program in a child process. `Child.real(environ)` runs the shipped command
  (`python -m defender.api_server`, real network); `Child.faked(environ, fails=...)` runs this module's entry, which
  calls `defender.api_server.run(os.environ, transport=FakeKeycloak(...))`, reports `run returned <n>` on stdout,
  holds until `release()` (or `ended()`), then exits with `n`.
- `seed_token_credential(dsn, seeded)`: a live `oauth_client` credential for the seeded program, for `program_token`.
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
#: The child's failures travel in this variable (JSON list of `Fail`); it is not a setting of the program.
FAULTS_ENV = "CF1083_KEYCLOAK_FAULTS"

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
    "DEFENDER_KEYCLOAK_REDIRECT_URI",
    "DEFENDER_KEYCLOAK_ADMIN_CLIENT_ID",
    "DEFENDER_KEYCLOAK_ADMIN_CLIENT_SECRET_FILE",
    "DEFENDER_KEYCLOAK_PROGRAMS_ISSUER",
    "DEFENDER_KEYCLOAK_PROGRAMS_AUDIENCE",
    "DEFENDER_KEYCLOAK_PROGRAMS_ADMIN_CLIENT_ID",
    "DEFENDER_KEYCLOAK_PROGRAMS_ADMIN_CLIENT_SECRET_FILE",
)


# --- ports ------------------------------------------------------------------------------------------

def free_port() -> int:
    """A port nothing listens on right now (a small race; the program binds it itself)."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


closed_port = free_port


# --- settings ---------------------------------------------------------------------------------------

def environment(tmp_path: Path, *, dsn: str, keycloak: str = BACK, port: int | None = None,
                administrators: tuple[str, ...] = (OPS,)) -> dict[str, str]:
    """Every setting the real program reads, valid (design FC-3). Secrets are files with a trailing newline."""
    def secret(name: str) -> str:
        path = tmp_path / name
        path.write_text(f"{name}-value\n")
        return str(path)

    admins = tmp_path / "administrators.yaml"
    admins.write_text("administrators:\n" + "".join(f"  - {email}\n" for email in administrators))
    environ = {
        "DEFENDER_DATABASE_DSN": dsn,
        "DEFENDER_API_HOST": "127.0.0.1",
        "DEFENDER_API_PORT": str(port if port is not None else free_port()),
        "DEFENDER_API_FRONTEND_ORIGIN": ORIGIN,
        "DEFENDER_API_ADMINISTRATORS_FILE": str(admins),
        "DEFENDER_KEYCLOAK_SERVER_URL": keycloak,
        "DEFENDER_KEYCLOAK_ISSUER": f"{FRONT}/realms/{SIGNIN_REALM}",
        "DEFENDER_KEYCLOAK_CLIENT_ID": "defender-api",
        "DEFENDER_KEYCLOAK_CLIENT_SECRET_FILE": secret("signin-client-secret"),
        "DEFENDER_KEYCLOAK_REDIRECT_URI": f"{ORIGIN}/auth/callback",
        "DEFENDER_KEYCLOAK_ADMIN_CLIENT_ID": "defender-api-admin",
        "DEFENDER_KEYCLOAK_ADMIN_CLIENT_SECRET_FILE": secret("signin-admin-secret"),
        "DEFENDER_KEYCLOAK_PROGRAMS_ISSUER": f"{FRONT}/realms/{PROGRAMS_REALM}",
        "DEFENDER_KEYCLOAK_PROGRAMS_AUDIENCE": PROGRAMS_AUDIENCE,
        "DEFENDER_KEYCLOAK_PROGRAMS_ADMIN_CLIENT_ID": "defender-api-programs-admin",
        "DEFENDER_KEYCLOAK_PROGRAMS_ADMIN_CLIENT_SECRET_FILE": secret("programs-admin-secret"),
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


def _unreadable() -> httpx.Response:
    return httpx.Response(200, content=b"<html>not what was asked for</html>", headers={"content-type": "text/html"})


class FakeKeycloak(httpx.AsyncBaseTransport):
    """Both realms, answering as observed on the dev Keycloak (code map 2026-11-13), and only on the back-channel
    host (`back`): a request to any other host is answered 404 and kept in `unmodelled`, as is anything else the
    fake does not model. Records every request in `seen` as `(method, "host:port/path")`.

    `fails` are failures at (realm, step); at most one per (realm, step). `on_stall(realm)` runs when a stalled
    discovery begins. Each realm's private signing key is `signing_keys[realm]` (published as kid `SIGNING_KID`)."""

    def __init__(self, fails: Iterable[Fail] = (), *, front: str = FRONT, back: str = BACK,
                 admin_clients: Mapping[str, tuple[str, str]] = ADMIN_CLIENTS,
                 on_stall: Callable[[str], None] | None = None) -> None:
        self.fails = {(f.realm, f.step): f.kind for f in fails}
        self.admin_clients = dict(admin_clients)
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
            return None
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
        if urllib.parse.parse_qs(request.content.decode()).get("grant_type") != ["client_credentials"]:
            return None
        if kind == "bad_secret" or not self._is_admin_client(realm, request):
            return httpx.Response(401, json={
                "error": "unauthorized_client", "error_description": "Invalid client or Invalid client credentials"})
        return httpx.Response(200, json={"access_token": f"admin-{realm}", "token_type": "Bearer", "expires_in": 300})

    def _admin(self, realm: str, request: httpx.Request, kind: str | None) -> httpx.Response:
        if request.headers.get("authorization") != f"Bearer admin-{realm}":  # an unknown (or no) bearer
            return httpx.Response(401, json={"error": "HTTP 401 Unauthorized"})
        # As observed: each admin client's role covers only its own resource; the other answers 403.
        if request.url.path.endswith(f"/{ADMIN_READ[realm]}") and kind != "no_role":
            return httpx.Response(200, json=[])
        return httpx.Response(403, json={"error": "HTTP 403 Forbidden"})

    def _is_admin_client(self, realm: str, request: httpx.Request) -> bool:
        """The client authenticates with HTTP basic auth, as the adapters send it."""
        scheme, _, encoded = request.headers.get("authorization", "").partition(" ")
        if scheme.lower() != "basic":
            return False
        try:
            client_id, _, secret = base64.b64decode(encoded).decode().partition(":")
        except ValueError:
            return False
        return (urllib.parse.unquote_plus(client_id), urllib.parse.unquote_plus(secret)) == self.admin_clients[realm]


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


class Child:
    """The program in a child process with only `environ`'s `DEFENDER_*` settings (plus the failures).

    `ended()` waits for a program that should refuse to start (cut off after `timeout`, failing the caller's
    assertion on returncode). `ready()` waits until it answers HTTP on its port. `send_signal(sig)` and `stop(sig)` send
    `sig` to this child's PID only (never a process group, never `pkill`).

    For `Child.faked`: `stalled()` waits for a stalled discovery to begin (a start under way); `reported()` reads
    the entry's `run returned <n>` line; the entry then holds, alive, until `release()` (which `ended()` does), so
    a test can observe the database between `run`'s return and the process's exit."""

    def __init__(self, argv: list[str], environ: Mapping[str, str], *, holds: bool = False) -> None:
        env = {k: v for k, v in os.environ.items() if not k.startswith(("DEFENDER_", FAULTS_ENV))}
        env["PYTHONPATH"] = os.pathsep.join(p for p in (str(REPO), os.environ.get("PYTHONPATH", "")) if p)
        env.update(environ)
        self.environ = dict(environ)
        self.process = subprocess.Popen(argv, cwd=str(REPO), env=env, text=True, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE,
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

    def ready(self, timeout: float = 60) -> bool:
        """True once `GET /openapi.json` answers 200; False if the child exits or the time runs out first."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                return False
            try:
                if httpx.get(f"{self.base_url}/openapi.json", timeout=2).status_code == 200:
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
            user = await repo.add_user(email, created_at=now, status="active", display_name=email)
            await repo.add_membership(user.id, TenantId(tenant), status="active", invited_by=None, created_at=now,
                                      accepted_at=now)
            await repo.add_session(sessions[email], user.id, now=now, expires_at=now + dt.timedelta(days=1))
            users[email] = user
        ops = await repo.add_user(OPS, created_at=now, status="active", display_name="Ops", is_platform_admin=True)
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
    returned = run(os.environ, transport=FakeKeycloak(fails, on_stall=lambda realm: print(f"stalled {realm}", flush=True)))
    print(f"run returned {returned}", flush=True)
    sys.stdin.readline()  # hold: the parent observes the database, then closes stdin
    return returned


if __name__ == "__main__":
    raise SystemExit(_main())
