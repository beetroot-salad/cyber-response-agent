"""#1083 piece 1: shared machinery for tests of the real server program (`defender.api_server`).

- `environment(tmp_path, dsn=..., ...)`: every setting the program reads (design FC-3), valid; `SETTING_NAMES` is
  that full set.
- `FakeKeycloak`: both realms on the back channel, answering as the dev Keycloak was observed to answer (code map,
  2026-11-13, rule R11), with per-realm faults. Anything it does not model is answered 404 and kept in `unmodelled`.
- `Child`: the program in a child process. `Child.real(environ)` runs the shipped command
  (`python -m defender.api_server`, real network); `Child.faked(environ, faults=...)` runs this module's entry, which
  only calls `defender.api_server.run(os.environ, transport=FakeKeycloak(...))`.
- `seed_identity(dsn)`: Ann (tenant A admin), Bob (tenant B admin), Ops (a listed administrator, one-time-code
  session) and a program of A with a live API key.

Run as `python -m defender.tests.support.api._server1083` it is the test-support entry (design, Start and stop)."""
from __future__ import annotations

import base64
import dataclasses
import datetime as dt
import json
import os
import secrets
import signal
import socket
import subprocess
import sys
import time
import urllib.parse
from collections.abc import Mapping
from pathlib import Path
from typing import Any

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
REALMS = (SIGNIN_REALM, PROGRAMS_REALM)
#: The admin read each realm's probe makes (design O3 / r5 Am-9): users in the sign-in realm, clients in programs.
ADMIN_READ = {SIGNIN_REALM: "users", PROGRAMS_REALM: "clients"}
#: The admin clients `environment()` configures, as (client id, secret): the fake refuses any other at the token
#: endpoint with the observed 401, so a program that sends the wrong id, or a secret file's text unstripped, is refused.
ADMIN_CLIENTS = {SIGNIN_REALM: ("defender-api-admin", "signin-admin-secret-value"),
                 PROGRAMS_REALM: ("defender-api-programs-admin", "programs-admin-secret-value")}
#: The child's fault knobs travel in this variable (JSON for `Faults`); it is not a setting of the program.
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
        "DEFENDER_KEYCLOAK_PROGRAMS_AUDIENCE": "defender-api-programs",
        "DEFENDER_KEYCLOAK_PROGRAMS_ADMIN_CLIENT_ID": "defender-api-programs-admin",
        "DEFENDER_KEYCLOAK_PROGRAMS_ADMIN_CLIENT_SECRET_FILE": secret("programs-admin-secret"),
    }
    assert tuple(environ) == SETTING_NAMES
    return environ


# --- Keycloak at the network edge -------------------------------------------------------------------

def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def published_keys() -> list[dict[str, Any]]:
    """As observed on both realms: one RS256 signing key and one RSA-OAEP encryption key."""
    from cryptography.hazmat.primitives.asymmetric import rsa

    keys = []
    for kid, use, alg in (("sig-1", "sig", "RS256"), ("enc-1", "enc", "RSA-OAEP")):
        numbers = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key().public_numbers()
        keys.append({"kid": kid, "kty": "RSA", "use": use, "alg": alg,
                     "n": _b64(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")), "e": "AQAB"})
    return keys


@dataclasses.dataclass(frozen=True)
class Faults:
    """Per-realm departures from a healthy Keycloak, each one an answer the dev Keycloak was observed to give.

    - `missing`: the realm does not exist (discovery 404, as an unknown realm answers).
    - `issuer`: discovery names this issuer instead of the realm's own.
    - `bad_secret`: the admin token request answers 401 `unauthorized_client` (as a wrong client secret does).
    - `no_role`: the admin read answers 403 `{"error":"HTTP 403 Forbidden"}` (as a service account without the
      role covering that resource does)."""
    missing: tuple[str, ...] = ()
    issuer: Mapping[str, str] = dataclasses.field(default_factory=dict)
    bad_secret: tuple[str, ...] = ()
    no_role: tuple[str, ...] = ()

    def to_json(self) -> str:
        return json.dumps(dataclasses.asdict(self))

    @classmethod
    def from_json(cls, text: str) -> Faults:
        raw = json.loads(text)
        return cls(missing=tuple(raw["missing"]), issuer=dict(raw["issuer"]), bad_secret=tuple(raw["bad_secret"]),
                   no_role=tuple(raw["no_role"]))


class FakeKeycloak(httpx.AsyncBaseTransport):
    """Both realms, answering as observed on the dev Keycloak (code map 2026-11-13). Records every request in
    `seen` as `(method, "host:port/path")`; anything unmodelled is answered 404 and kept in `unmodelled`."""

    def __init__(self, faults: Faults | None = None, *, front: str = FRONT,
                 admin_clients: Mapping[str, tuple[str, str]] = ADMIN_CLIENTS) -> None:
        self.faults = faults or Faults()
        self.admin_clients = dict(admin_clients)
        self.front = front
        self.keys = {realm: published_keys() for realm in REALMS}
        self.seen: list[tuple[str, str]] = []
        self.unmodelled: list[tuple[str, str]] = []

    def issuer(self, realm: str) -> str:
        return f"{self.front}/realms/{realm}"

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        await request.aread()
        method, path = request.method, request.url.path
        self.seen.append((method, f"{request.url.host}:{request.url.port}{path}"))
        for realm in REALMS:
            if path.startswith((f"/realms/{realm}/", f"/admin/realms/{realm}/")):
                answer = self._answer(realm, request)
                if answer is not None:
                    return answer
        self.unmodelled.append((method, str(request.url)))
        return httpx.Response(404)

    def _answer(self, realm: str, request: httpx.Request) -> httpx.Response | None:
        method, path, auth = request.method, request.url.path, request.headers.get("authorization")
        if realm in self.faults.missing:
            return httpx.Response(404, json={"error": "Realm does not exist"})
        issuer = self.issuer(realm)
        if (method, path) == ("GET", f"/realms/{realm}/.well-known/openid-configuration"):
            return httpx.Response(200, json={
                "issuer": self.faults.issuer.get(realm, issuer),
                "token_endpoint": f"{issuer}/protocol/openid-connect/token",
                "jwks_uri": f"{issuer}/protocol/openid-connect/certs"})
        if (method, path) == ("GET", f"/realms/{realm}/protocol/openid-connect/certs"):
            return httpx.Response(200, json={"keys": self.keys[realm]})
        if (method, path) == ("POST", f"/realms/{realm}/protocol/openid-connect/token") \
                and urllib.parse.parse_qs(request.content.decode()).get("grant_type") == ["client_credentials"]:
            if realm in self.faults.bad_secret or not self._is_admin_client(realm, request):
                return httpx.Response(401, json={
                    "error": "unauthorized_client",
                    "error_description": "Invalid client or Invalid client credentials"})
            return httpx.Response(200, json={"access_token": f"admin-{realm}", "token_type": "Bearer",
                                             "expires_in": 300})
        if method == "GET" and auth == f"Bearer admin-{realm}" \
                and path in (f"/admin/realms/{realm}/users", f"/admin/realms/{realm}/clients"):
            # As observed: each admin client's role covers only its own resource; the other answers 403.
            if path.endswith(f"/{ADMIN_READ[realm]}") and realm not in self.faults.no_role:
                return httpx.Response(200, json=[])
            return httpx.Response(403, json={"error": "HTTP 403 Forbidden"})
        return None

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


class Child:
    """The program in a child process with only `environ`'s `DEFENDER_*` settings (plus the fault knobs).

    `ended()` waits for a program that should refuse to start (cut off after `timeout`, failing the caller's
    assertion on returncode). `ready()` waits until it answers HTTP on its port. `stop(sig)` sends `sig` to this
    child's PID only (never a process group, never `pkill`) and waits for its exit."""

    def __init__(self, argv: list[str], environ: Mapping[str, str]) -> None:
        env = {k: v for k, v in os.environ.items() if not k.startswith(("DEFENDER_", FAULTS_ENV))}
        env["PYTHONPATH"] = os.pathsep.join(p for p in (str(REPO), os.environ.get("PYTHONPATH", "")) if p)
        env.update(environ)
        self.environ = dict(environ)
        self.process = subprocess.Popen(argv, cwd=str(REPO), env=env, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, text=True)

    @classmethod
    def real(cls, environ: Mapping[str, str]) -> Child:
        """The shipped command, `python -m defender.api_server`, on the real network."""
        return cls([sys.executable, "-m", "defender.api_server"], environ)

    @classmethod
    def faked(cls, environ: Mapping[str, str], faults: Faults | None = None) -> Child:
        """`defender.api_server.run` over a `FakeKeycloak` with `faults`, through this module's entry."""
        return cls([sys.executable, "-m", "defender.tests.support.api._server1083"],
                   {**environ, FAULTS_ENV: (faults or Faults()).to_json()})

    @property
    def base_url(self) -> str:
        return f"http://{self.environ['DEFENDER_API_HOST']}:{self.environ['DEFENDER_API_PORT']}"

    def ended(self, timeout: float = 90) -> Ended:
        try:
            out, err = self.process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.process.kill()
            out, err = self.process.communicate()
            return Ended(-9999, out, "the program kept running when it should have ended\n" + err)
        return Ended(self.process.returncode, out, err)

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

    def stop(self, sig: int = signal.SIGTERM, timeout: float = 60) -> Ended:
        if self.process.poll() is None:
            os.kill(self.process.pid, sig)
        return self.ended(timeout)

    def kill(self) -> None:
        """Cleanup for a test that failed mid-way: SIGKILL this child only, if still running."""
        if self.process.poll() is None:
            self.process.kill()
            self.process.communicate()


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


def person(session: str, *, write: bool = False) -> dict[str, str]:
    """A person's request headers; `write` adds the origin a cookie-authenticated write needs."""
    headers = {"Cookie": f"{SESSION_COOKIE}={session}"}
    return {**headers, "Origin": ORIGIN} if write else headers


def program(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


# --- test-support entry -----------------------------------------------------------------------------

def _main() -> int:
    from defender.api_server import run

    faults = Faults.from_json(os.environ[FAULTS_ENV]) if FAULTS_ENV in os.environ else Faults()
    return run(os.environ, transport=FakeKeycloak(faults))


if __name__ == "__main__":
    raise SystemExit(_main())
