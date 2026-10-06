"""A seeded set of fakes for running the stub locally: the tenants the operator names, so
tenant scoping is visible from a browser or `curl`, and one investigation in each interesting
state in the first of them.

There is no default tenant (#1078): `serve.py` requires `--tenant`, and every id here derives
from the names it is given. The tokens are predictable and public, so `serve.py` binds to
loopback by default.
"""

from __future__ import annotations

import datetime as _dt
from collections.abc import Callable, Sequence
from functools import partial

from defender._run_paths import RUN_LAYOUT
from defender._tenant import TenantId, is_valid_tenant_id

from .fakes import (
    InMemorySecrets,
    InMemoryStore,
    StubArtifactLinks,
    StubSystemChecker,
    TokenAuthenticator,
)
from .models import Alert, Investigation, LearningJob, Lesson, SystemSettings
from .ports import ApiDeps, Principal

#: The users each tenant gets; a token is `<tenant>-<role>`.
DEMO_ROLES = ("analyst", "engineer")

#: The wall clock, as a value so `demo_deps` can default to it.
UTC_NOW: Callable[[], _dt.datetime] = partial(_dt.datetime.now, _dt.UTC)


def demo_tokens(tenants: Sequence[str]) -> dict[str, Principal]:
    """bearer token -> caller, one per tenant and role."""
    return {
        f"{tenant}-{role}": Principal(tenant_id=TenantId(tenant), user_id=f"{role}@{tenant}.example")
        for tenant in tenants for role in DEMO_ROLES
    }


def demo_deps(tenants: Sequence[str], clock: Callable[[], _dt.datetime] = UTC_NOW) -> ApiDeps:
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
    return ApiDeps(
        authenticator=TokenAuthenticator(demo_tokens(tenants)),
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
    store.add_investigation(tenant, Investigation(
        investigation_id=f"{tenant}-inv-running", alert_id=shell.alert_id, status="running",
        cost_usd=0.42, created_at=now - 2 * hour, started_at=now - 2 * hour,
    ))
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
