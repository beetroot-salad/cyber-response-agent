"""A seeded set of fakes for running the stub locally: the tenants the operator names, so
tenant scoping is visible from a browser or `curl`, and one investigation in each interesting
state in the first of them.

There is no default tenant (#1078): `serve.py` requires `--tenant`, and every tenant ID here comes
from the UUIDs it is given. The session values are predictable and public, so `serve.py` binds to
loopback by default.
"""

from __future__ import annotations

import datetime as _dt
import json
import logging
import uuid
from collections.abc import Callable, Sequence
from functools import partial

from defender.records import RUN_LAYOUT
from defender.tenancy import InMemoryTenantRepository
from defender.records.formats import AlertId, InvestigationId, LearningJobId, TenantId, TenantRefused

from defender.identity import (
    Bootstrap,
    IdentityService,
    InMemoryIdentityRepository,
    SignInRefused,
    SignInUnavailable,
    VerifiedProgramToken,
    VerifiedSignIn,
)

from .fakes import (
    InMemoryOffboarding,
    _Id,
    InMemorySecrets,
    InMemoryStore,
    StubArtifactLinks,
    StubSystemChecker,
)
from .models import Alert, Investigation, LearningJob, Lesson, SystemSettings
from .ports import ApiDeps


#: The users each tenant gets, each signed in as `<tenant>-<role>` (see `demo_sessions`).
DEMO_ROLES = ("analyst", "engineer")
#: Made-up knowledge commits the demo investigations name (the latest and an earlier one).
_DEMO_COMMITS = ("d3a0c0de" * 5, "e4a1c0de" * 5)

#: The wall clock, as a value so `demo_deps` can default to it.
UTC_NOW: Callable[[], _dt.datetime] = partial(_dt.datetime.now, _dt.UTC)


#: Where the demo's frontend is said to live; a state-changing request must carry it as `Origin`.
#: The API sends no CORS headers: as in deployment, where the proxy serves both on one origin,
#: the frontend's dev server forwards API calls, so the browser only ever sees this origin.
DEMO_FRONTEND_ORIGIN = "http://localhost:3000"
_SESSION_LIFETIME = _dt.timedelta(days=365)
_logger = logging.getLogger(__name__)


def demo_sessions(tenants: Sequence[str]) -> dict[str, str]:
    """`<tenant>-<role>` -> that user's session cookie value, one per tenant and role.
    Predictable and public: the demo has no sign-in."""
    return {f"{tenant}-{role}": f"demo-session-{tenant}-{role}" for tenant in tenants for role in DEMO_ROLES}


class _NoSignIn:
    """The demo has no sign-in provider: every sign-in call is unavailable (`/auth/login` answers 503)."""

    _WHY = "the demo has no sign-in provider; use a seeded session cookie"

    async def create_account(self, *, username: str, email: str, required_actions: frozenset[str]) -> str:
        raise SignInUnavailable(self._WHY)

    async def send_set_password_email(self, account_id: str, *, lifespan: _dt.timedelta) -> None:
        raise SignInUnavailable(self._WHY)

    async def has_otp(self, account_id: str) -> bool:
        raise SignInUnavailable(self._WHY)

    async def require_otp_setup(self, account_id: str) -> None:
        raise SignInUnavailable(self._WHY)

    async def begin_signin(self, *, state: str, nonce: str, code_challenge: str) -> str:
        raise SignInUnavailable(self._WHY)

    async def finish_signin(self, *, code: str, code_verifier: str, nonce: str) -> VerifiedSignIn:
        raise SignInUnavailable(self._WHY)

    async def close(self) -> None:
        """Nothing is open."""


class _LoggedMail:
    async def notify_invitation(self, to: str, tenant_id: str, invitation_id: str) -> None:
        _logger.info("invitation %s to %s for tenant %s (not sent: demo)", invitation_id, to, tenant_id)

    async def notify_credential_expiry(self, to: str, tenant_id: str, program_id: str, credential_id: str,
                                       expires_at: _dt.datetime) -> None:
        _logger.info("credential %s of program %s expires %s; warning to %s for tenant %s (not sent: demo)",
                     credential_id, program_id, expires_at.isoformat(), to, tenant_id)


class _DemoProgramsRealm:
    """The demo's stand-in for the programs realm: it makes a client and a secret per OAuth credential and
    keeps the clients in memory, but issues no tokens, so no OAuth credential can sign in (keys can)."""

    def __init__(self) -> None:
        self._clients: set[str] = set()

    async def create_client(self, credential_id: str) -> tuple[str, str]:
        self._clients.add(credential_id)
        return str(uuid.uuid4()), uuid.uuid4().hex

    async def delete_client(self, client_id: str) -> bool:
        if client_id not in self._clients:
            return False
        self._clients.discard(client_id)
        return True

    async def client_ids(self) -> set[str]:
        return set(self._clients)

    async def verify_token(self, token: str) -> VerifiedProgramToken:
        raise SignInRefused("the demo issues no program tokens")

    async def close(self) -> None:
        """Nothing is open."""


async def demo_deps(tenants: Sequence[str], clock: Callable[[], _dt.datetime] = UTC_NOW,
              frontend_origin: str = DEMO_FRONTEND_ORIGIN) -> ApiDeps:
    """Fakes seeded for `tenants`: the full seed in the first, one alert in each other."""
    if not tenants:
        raise ValueError("name at least one tenant")
    if len(set(tenants)) != len(tenants):
        raise ValueError(f"tenants repeat: {list(tenants)}")
    try:
        tenant_ids = [TenantId(raw) for raw in tenants]
    except TenantRefused as refused:
        raise ValueError(f"not a tenant id: {refused}") from None
    secrets = InMemorySecrets()
    store = InMemoryStore(clock)
    now = clock()
    await _seed(store, secrets, tenant_ids[0], now)
    for n, tenant in enumerate(tenant_ids[1:], start=9):
        store.add_alert(tenant, _alert(
            tenant, n, fired=now - _dt.timedelta(hours=2), title=f"An alert of {tenant}'s",
            rule="misc",
        ))
    # One store: the tenants are seeded `active` in the tenant twin, and identity reads them there.
    tenant_rows = InMemoryTenantRepository()
    people = InMemoryIdentityRepository(tenants=tenant_rows)
    for tenant in tenant_ids:
        await tenant_rows.add_tenant(tenant, created_at=now)
        for role in DEMO_ROLES:
            user = await people.add_user(f"{role}@{tenant}.example", created_at=now, status="active",
                                   display_name=role.title())
            await people.add_membership(user.id, tenant, status="active", invited_by=None,
                                  created_at=now, accepted_at=now)
            await people.add_session(demo_sessions([tenant])[f"{tenant}-{role}"], user.id, now=now,
                               expires_at=now + _SESSION_LIFETIME)
    identity = IdentityService(people, signin=_NoSignIn(), mail=_LoggedMail(), clock=clock, programs=_DemoProgramsRealm(),
                               bootstrap=Bootstrap(administrators=()),
                               session_idle_limit=_SESSION_LIFETIME)
    return ApiDeps(
        identity=identity,
        tenants=tenant_rows,
        frontend_origin=frontend_origin,
        alerts=store,
        investigations=store,
        learning_jobs=store,
        lessons=store,
        systems=store,
        writes=store,
        secrets=secrets,
        checker=StubSystemChecker(),
        artifact_links=StubArtifactLinks(),
        offboarding=InMemoryOffboarding(tenant_rows, store, clock),
    )


def demo_id(family: type[_Id], tenant: str, name: str) -> _Id:
    """The demo record `name` of `tenant`: a UUID derived from both, the same on every start."""
    return family(str(uuid.uuid5(uuid.UUID(tenant), name)))


def _alert(tenant: TenantId, n: int, *, fired: _dt.datetime, title: str, rule: str) -> Alert:
    # Ids are global, as the store's primary keys are, so each derives from its tenant.
    return Alert(
        alert_id=demo_id(AlertId, tenant, f"alert-{n:04d}"),
        vendor="demo-tickets",
        vendor_ticket_id=f"SEC-{1000 + n}",
        title=title,
        description=f"{title} (rule {rule}).",
        fired_at=fired,
        changed_at=fired + _dt.timedelta(minutes=4),
        received_at=fired + _dt.timedelta(minutes=5),
        raw=json.dumps({"summary": title, "rule": rule, "host": f"host-{n:02d}"}),
    )


async def _seed(store: InMemoryStore, secrets: InMemorySecrets, tenant: TenantId, now: _dt.datetime) -> None:
    hour = _dt.timedelta(hours=1)
    brute = store.add_alert(tenant, _alert(
        tenant, 1, fired=now - 30 * hour, title="Repeated failed logins followed by success",
        rule="auth-bruteforce",
    ))
    shell = store.add_alert(tenant, _alert(
        tenant, 2, fired=now - 3 * hour, title="Interactive shell spawned by web server",
        rule="web-shell",
    ))
    store.add_alert(tenant, _alert(
        tenant, 3, fired=now - hour, title="New admin group member",
        rule="priv-group-change",
    ))

    done = store.add_investigation(tenant, Investigation(
        investigation_id=demo_id(InvestigationId, tenant, "inv-completed"), alert_id=brute.alert_id, status="completed",
        request_key="demo-request-1", attempt=1,
        disposition="benign", cost_usd=1.84, cost_is_lower_limit=False, created_at=now - 29 * hour,
        started_at=now - 29 * hour, finished_at=now - 29 * hour + _dt.timedelta(minutes=11),
        artifacts=[RUN_LAYOUT.report.name, RUN_LAYOUT.investigation.name,
                   RUN_LAYOUT.runtime_html.name],
    ))
    running = store.add_investigation(tenant, Investigation(
        investigation_id=demo_id(InvestigationId, tenant, "inv-running"), alert_id=shell.alert_id, status="running",
        request_key="demo-request-2", attempt=1,
        cost_usd=0.0, cost_is_lower_limit=False, created_at=now - 2 * hour, started_at=now - 2 * hour,
    ))
    # Each run's knowledge record as run start writes it (#1108 P4, O-WARN): the completed run
    # read the latest approved knowledge; the running one started on the last published
    # snapshot because the newer could not be loaded.
    for investigation, record in (
        (done, {"kind": "fresh", "commit": _DEMO_COMMITS[0], "stale_kind": None, "reason": None}),
        (running, {"kind": "stale", "commit": _DEMO_COMMITS[1], "stale_kind": "transient",
                   "reason": "the issuer did not answer in time"}),
    ):
        store.add_run_knowledge(
            tenant, investigation.investigation_id, json.dumps(record),
            stamp_knowledge_source={k: record[k] for k in ("kind", "commit", "stale_kind")})
    store.add_learning_job(tenant, LearningJob(
        learning_job_id=demo_id(LearningJobId, tenant, "lj-auto"), investigation_id=done.investigation_id,
        alert_id=done.alert_id, status="completed", trigger="auto", stage="judge",
        created_at=now if done.finished_at is None else done.finished_at, finished_at=now - 20 * hour,
    ))
    store.add_lesson(tenant, Lesson(
        lesson_id=f"{tenant}-lesson-0001", title="Check the source's login history before calling it benign",
        description="A success after failures is benign only if the source has logged in before.",
        status="live",
    ))

    store.add_system(tenant, SystemSettings(
        system_id="tickets", kind="ticketing", display_name="Security ticket queue", enabled=True,
        settings={"base_url": f"https://tickets.{tenant}.example", "ready_status": "triage"},
    ))
    store.add_system(tenant, SystemSettings(
        system_id="siem", kind="siem", display_name="Event search", enabled=True,
        settings={"base_url": f"https://siem.{tenant}.example"},
    ))
    await secrets.put_credentials(
        tenant, "tickets", "static", {"api_token": "demo-secret-token-1163"})
