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
from collections.abc import Callable, Sequence
from functools import partial

from defender.records import RUN_LAYOUT
from defender.tenancy._tenant import is_valid_tenant_id
from defender.records._tenant_id import TenantId

from defender.identity import (
    Bootstrap,
    IdentityService,
    InMemoryIdentityRepository,
    SignInUnavailable,
    VerifiedSignIn,
    register_tenant,
)

from .fakes import (
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

    def create_account(self, *, username: str, email: str, required_actions: frozenset[str]) -> str:
        raise SignInUnavailable(self._WHY)

    def send_set_password_email(self, account_id: str, *, lifespan: _dt.timedelta) -> None:
        raise SignInUnavailable(self._WHY)

    def has_otp(self, account_id: str) -> bool:
        raise SignInUnavailable(self._WHY)

    def require_otp_setup(self, account_id: str) -> None:
        raise SignInUnavailable(self._WHY)

    def begin_signin(self, *, state: str, nonce: str, code_challenge: str) -> str:
        raise SignInUnavailable(self._WHY)

    def finish_signin(self, *, code: str, code_verifier: str, nonce: str) -> VerifiedSignIn:
        raise SignInUnavailable(self._WHY)


class _LoggedMail:
    def notify_invitation(self, to: str, tenant_id: str, invitation_id: str) -> None:
        _logger.info("invitation %s to %s for tenant %s (not sent: demo)", invitation_id, to, tenant_id)


def demo_deps(tenants: Sequence[str], clock: Callable[[], _dt.datetime] = UTC_NOW,
              frontend_origin: str = DEMO_FRONTEND_ORIGIN) -> ApiDeps:
    """Fakes seeded for `tenants`: the full seed in the first, one alert in each other."""
    if not tenants:
        raise ValueError("name at least one tenant")
    if len(set(tenants)) != len(tenants):
        raise ValueError(f"tenants repeat: {list(tenants)}")
    for tenant in tenants:
        if not is_valid_tenant_id(tenant):
            raise ValueError(f"not a tenant id: {tenant!r}")
    secrets = InMemorySecrets()
    store = InMemoryStore(clock)
    now = clock()
    _seed(store, secrets, tenants[0], now)
    for n, tenant in enumerate(tenants[1:], start=9):
        store.add_alert(tenant, _alert(
            tenant, n, fired=now - _dt.timedelta(hours=2), title=f"An alert of {tenant}'s",
            severity="low", rule="misc",
        ))
    people = InMemoryIdentityRepository()
    for tenant in tenants:
        register_tenant(people, TenantId(tenant))
        for role in DEMO_ROLES:
            user = people.add_user(f"{role}@{tenant}.example", created_at=now, status="active",
                                   display_name=role.title())
            people.add_membership(user.id, tenant, status="active", invited_by="system",
                                  created_at=now, accepted_at=now)
            people.add_session(demo_sessions([tenant])[f"{tenant}-{role}"], user.id, now=now,
                               expires_at=now + _SESSION_LIFETIME)
    identity = IdentityService(people, signin=_NoSignIn(), mail=_LoggedMail(), clock=clock,
                               bootstrap=Bootstrap(administrators=(), tenants={}),
                               session_idle_limit=_SESSION_LIFETIME)
    return ApiDeps(
        identity=identity,
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
    )


def _alert(tenant: str, n: int, *, fired: _dt.datetime, title: str, severity: str, rule: str) -> Alert:
    # Ids are global, as the store's primary keys will be, so each carries its tenant.
    return Alert(
        alert_id=f"{tenant}-alert-{n:04d}",
        vendor="demo-tickets",
        vendor_ticket_id=f"SEC-{1000 + n}",
        title=title,
        severity=severity,
        rule=rule,
        fired_at=fired,
        changed_at=fired + _dt.timedelta(minutes=4),
        received_at=fired + _dt.timedelta(minutes=5),
        raw={"summary": title, "rule": rule, "severity": severity, "host": f"host-{n:02d}"},
    )


def _seed(store: InMemoryStore, secrets: InMemorySecrets, tenant: str, now: _dt.datetime) -> None:
    hour = _dt.timedelta(hours=1)
    brute = store.add_alert(tenant, _alert(
        tenant, 1, fired=now - 30 * hour, title="Repeated failed logins followed by success",
        severity="high", rule="auth-bruteforce",
    ))
    shell = store.add_alert(tenant, _alert(
        tenant, 2, fired=now - 3 * hour, title="Interactive shell spawned by web server",
        severity="critical", rule="web-shell",
    ))
    store.add_alert(tenant, _alert(
        tenant, 3, fired=now - hour, title="New admin group member",
        severity="medium", rule="priv-group-change",
    ))

    done = store.add_investigation(tenant, Investigation(
        investigation_id=f"{tenant}-inv-completed", alert_id=brute.alert_id, status="completed",
        disposition="benign", cost_usd=1.84, created_at=now - 29 * hour,
        started_at=now - 29 * hour, finished_at=now - 29 * hour + _dt.timedelta(minutes=11),
        artifacts=[RUN_LAYOUT.report.name, RUN_LAYOUT.investigation.name,
                   RUN_LAYOUT.runtime_html.name],
    ))
    running = store.add_investigation(tenant, Investigation(
        investigation_id=f"{tenant}-inv-running", alert_id=shell.alert_id, status="running",
        cost_usd=0.42, created_at=now - 2 * hour, started_at=now - 2 * hour,
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
        learning_job_id=f"{tenant}-lj-auto", investigation_id=done.investigation_id,
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
    secrets.put_credentials(tenant, "tickets", {"api_token": "demo-secret"})
