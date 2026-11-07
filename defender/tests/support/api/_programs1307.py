"""#1307 test world: the #1306 `World` plus a fake programs realm (Keycloak's `defender-programs`) and a
mail fake that also records credential-expiry warnings — NO test functions. The fakes record calls and
script answers; whether a credential is usable is never the fake's decision (P-G: our row decides).

Every test-facing interface the design leaves open is fixed HERE, once (sketch forced choices):
- FC-1 the programs port is `IdentityService(..., programs=<port>)`, optional (the lifecycle builds the
  service without it, O6). Port methods: `create_client(credential_id) -> (service_account_id, secret)`
  (one call: create + read back), `delete_client(client_id)` (absent is fine), `client_ids() -> set[str]`
  (program clients only: the adapter skips its own admin/audience clients), `verify_token(token) ->
  VerifiedProgramToken(client_id, subject, expires_at)`, refusal `SignInRefused`, outage `SignInUnavailable`.
- FC-2 route payloads: `POST /programs {"display_name"}` -> `{"id", "display_name", ...}`;
  `POST /programs/{id}/credentials {"kind", "name", "expires_at"?}` -> `{"id", "kind", "name",
  "expires_at", "secret", ...}`; lists are the usual `Page` (`items`, `next_cursor`).
- FC-3 the expiry header `EXPIRY_HEADER`, an ISO-8601 UTC timestamp.
- FC-4 a program's `/me`: `{"program": {"id", ...}, "tenant": {"tenant_id"}, "credential": {"id", "expires_at"}}`.
- FC-5 the mail port gains `notify_credential_expiry(to, tenant_id, program_id, credential_id, expires_at)`;
  warnings go out in the same sender pass (`world.send_pending()`).
- FC-6 one reconciliation pass is `service.reconcile_program_clients()` (the purge, callable alone).
- FC-7 repository: `credentials_of_program(program_id)` rows carry `.id`, `.state`, `.kind`, `.key_hash`.
- FC-8 tenant audit events (`api/fakes.AuditEvent`) carry `credential_id`; identity audit log records
  carry the extra `credential_id`; actions `program.create`, `program_credential.create`, `.revoke`.
- FC-11 `User.kind` / `.created_by`, `Membership.role`; key hash = hex SHA-256 (as sessions); expiry
  over 365 days -> 422; the 14-day warning fires at exactly 14 days left, once per threshold;
  `ensure_invitation` for a program raises `DataRuleViolation`.
"""
from __future__ import annotations

import dataclasses
import datetime as _dt
import itertools
import threading
from typing import Any

from defender.api.app import create_app
from defender.api.fakes import InMemorySecrets, InMemoryStore, StubArtifactLinks, StubSystemChecker  # noqa: F401
from defender.api.ports import ApiDeps

# Production names #1307 must supply. Kept in this one block so a missing name is one ImportError.
from defender.identity import (  # noqa: F401  (re-exported for the cases)
    Bootstrap,
    IdentityService,
    SignInRefused,
    SignInUnavailable,
    VerifiedProgramToken,
)
from defender.tests.support.api._identity1306 import (
    ALERT,
    ANN,
    BOB,
    FRONTEND_ORIGIN,
    T1,
    T2,
    FakeMail,
    World,
    _WorldClient,
    BASE_URL,
)

DAY = _dt.timedelta(days=1)
KEY_PREFIX = "dfk_"
EXPIRY_HEADER = "Defender-Credential-Expires"  # FC-3
DEFAULT_LIFETIME = 90 * DAY
MAX_LIFETIME = 365 * DAY
TOKEN_LIFETIME = _dt.timedelta(seconds=300)


# --- the programs realm (FC-1) ---------------------------------------------------------------

@dataclasses.dataclass
class Client:
    client_id: str
    service_account_id: str
    secret: str


class FakeProgramsRealm:
    """Keycloak's programs realm as a recorder. Issued tokens stay verifiable after their client is
    deleted (as real signed tokens do until `exp`): only our row can stop them (O5, P-G)."""

    def __init__(self, clock: Any) -> None:
        self._clock = clock
        self._ids = itertools.count(1)
        self._lock = threading.RLock()
        self.clients: dict[str, Client] = {}
        self.created: list[str] = []
        self.deleted: list[str] = []
        #: token string -> what verification returns.
        self.tokens: dict[str, VerifiedProgramToken] = {}
        #: The next N `create_client` calls raise `SignInUnavailable` before creating anything.
        self.fail_creates = 0
        #: The next N `create_client` calls create the client, then raise (a lost response).
        self.lose_create_responses = 0
        self.closes = 0

    # --- the port --------------------------------------------------------------------------
    async def close(self) -> None:
        self.closes += 1

    async def create_client(self, credential_id: str) -> tuple[str, str]:
        with self._lock:
            self.created.append(str(credential_id))
            if self.fail_creates:
                self.fail_creates -= 1
                raise SignInUnavailable("keycloak is unavailable")
            n = next(self._ids)
            client = Client(str(credential_id), f"00000000-5a00-4000-8000-{n:012d}", f"kc-secret-{n}")
            self.clients[client.client_id] = client
            if self.lose_create_responses:
                self.lose_create_responses -= 1
                raise SignInUnavailable("the response was lost")
            return client.service_account_id, client.secret

    async def delete_client(self, client_id: str) -> None:
        with self._lock:
            self.deleted.append(str(client_id))
            self.clients.pop(str(client_id), None)

    async def client_ids(self) -> set[str]:
        with self._lock:
            return set(self.clients)

    async def verify_token(self, token: str) -> VerifiedProgramToken:
        with self._lock:
            if token not in self.tokens:
                raise SignInRefused("the token does not verify")
            return self.tokens[token]

    # --- test-side ---------------------------------------------------------------------------
    def issue(self, client_id: str) -> str:
        """A 5-minute token from the token endpoint for an existing client (client credentials grant)."""
        with self._lock:
            client = self.clients[str(client_id)]
            return self.forge(client.client_id, client.service_account_id)

    def forge(self, client_id: str, subject: str) -> str:
        """A token that verifies (realm-signed) and names `client_id` / `subject` as given."""
        with self._lock:
            token = f"eyJ.program-token-{next(self._ids)}.sig"
            self.tokens[token] = VerifiedProgramToken(
                client_id=str(client_id), subject=subject, expires_at=self._clock() + TOKEN_LIFETIME)
            return token


# --- mail (FC-5) -------------------------------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class ExpiryWarning:
    to: str
    tenant_id: str
    program_id: str
    credential_id: str
    expires_at: _dt.datetime


class ProgramsMail(FakeMail):
    def __init__(self) -> None:
        super().__init__()
        self.warnings: list[ExpiryWarning] = []

    async def notify_credential_expiry(self, to: str, tenant_id: str, program_id: str,
                                       credential_id: str, expires_at: _dt.datetime) -> None:
        with self._lock:
            self.warnings.append(ExpiryWarning(to, str(tenant_id), str(program_id), str(credential_id), expires_at))


# --- the world ---------------------------------------------------------------------------------

class ProgramsWorld(World):
    """`World` whose service also holds the fake programs realm (FC-1)."""

    def build(self, *, administrators: Any, tenants: Any) -> None:
        if not isinstance(self.mail, ProgramsMail):
            self.mail = ProgramsMail()
        if getattr(self, "realm", None) is None:
            self.realm = FakeProgramsRealm(self.clock)
        extra: dict[str, Any] = {} if self.send_interval is None else {"send_interval": self.send_interval}
        if self.send_deadline is not None:
            extra["send_deadline"] = self.send_deadline
        self.service = IdentityService(
            self.repo, signin=self.signin, mail=self.mail, clock=self.clock,
            bootstrap=Bootstrap(administrators=tuple(administrators)), programs=self.realm, **extra)
        self.app = create_app(ApiDeps(
            alerts=self.store, investigations=self.store, learning_jobs=self.store,
            lessons=self.store, systems=self.store, writes=self.store,
            secrets=InMemorySecrets(), checker=StubSystemChecker(),
            artifact_links=StubArtifactLinks(),
            identity=self.service, frontend_origin=FRONTEND_ORIGIN, tenants=self.tenants,
        ))

    def bearer(self, value: str, *, origin: str | None = None, scheme: str = "Bearer",
               raise_errors: bool = True) -> Any:
        """A program's HTTP client: `Authorization: <scheme> <value>`, no cookie, no Origin by default."""
        headers = {"Authorization": f"{scheme} {value}"}
        if origin is not None:
            headers["Origin"] = origin
        return _WorldClient(self._loop, self._asgi, base_url=BASE_URL, follow_redirects=False,
                            headers=headers, raise_server_exceptions=raise_errors)

    def credentials(self, program_id: str) -> list[Any]:
        """The program's credential rows, read from the repository (FC-7)."""
        return list(self.call(self.raw_repo.credentials_of_program, program_id))


# --- route helpers (FC-2) -----------------------------------------------------------------------

def create_program(admin: Any, tenant: str, name: str = "SOAR prod") -> dict[str, Any]:
    response = admin.post(f"/tenants/{tenant}/programs", json={"display_name": name})
    assert response.status_code == 201, response.text
    body: dict[str, Any] = response.json()
    return body


def issue(admin: Any, tenant: str, program_id: str, *, kind: str = "key", name: str = "primary",
          expires_at: _dt.datetime | None = None) -> Any:
    body: dict[str, Any] = {"kind": kind, "name": name}
    if expires_at is not None:
        body["expires_at"] = expires_at.isoformat()
    return admin.post(f"/tenants/{tenant}/programs/{program_id}/credentials", json=body)


def issue_key(admin: Any, tenant: str, program_id: str, **kw: Any) -> tuple[str, str]:
    """(credential id, the key value shown once)."""
    response = issue(admin, tenant, program_id, kind="key", **kw)
    assert response.status_code == 201, response.text
    return response.json()["id"], response.json()["secret"]


def issue_oauth(admin: Any, tenant: str, program_id: str, **kw: Any) -> str:
    """The OAuth credential's id (= its Keycloak client id)."""
    response = issue(admin, tenant, program_id, kind="oauth_client", **kw)
    assert response.status_code == 201, response.text
    return str(response.json()["id"])


def revoke(admin: Any, tenant: str, program_id: str, credential_id: str) -> Any:
    return admin.delete(f"/tenants/{tenant}/programs/{program_id}/credentials/{credential_id}")


def start_investigation(client: Any, tenant: str, request_id: str = "r1") -> Any:
    return client.post(f"/tenants/{tenant}/investigations",
                       json={"alert_id": ALERT.alert_id, "client_request_id": request_id})


def parse_time(value: str) -> _dt.datetime:
    return _dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


@dataclasses.dataclass
class Soar:
    """T1 (admin ann, one alert) with program "SOAR prod" holding one key; T2 with admin bob."""
    world: ProgramsWorld
    ann: Any
    bob: Any
    program_id: str
    key_id: str
    key: str

    def program(self) -> Any:
        return self.world.bearer(self.key)


def soar() -> Soar:
    world = ProgramsWorld(tenants={T1: [ANN], T2: [BOB]})
    world.store.add_alert(T1, ALERT)
    ann, bob = world.sign_in(ANN), world.sign_in(BOB)
    program_id = str(create_program(ann, T1)["id"])
    key_id, key = issue_key(ann, T1, program_id)
    return Soar(world, ann, bob, program_id, key_id, key)
