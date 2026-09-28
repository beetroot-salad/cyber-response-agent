"""A seeded set of fakes for running the stub locally: two tenants, so tenant scoping is
visible from a browser or `curl`, and one investigation in each interesting state.

The tokens are fixed and public. `serve.py` binds to loopback by default for that reason.
"""

from __future__ import annotations

import datetime as _dt
from collections.abc import Callable
from functools import partial

from .fakes import (
    InMemoryAudit,
    InMemorySecrets,
    InMemoryStore,
    StubArtifactLinks,
    StubSystemChecker,
    TokenAuthenticator,
)
from .models import Alert, Investigation, LearningJob, Lesson, SystemPut
from .ports import ApiDeps, Principal

DEMO_TENANT = "demo"
OTHER_TENANT = "other"

#: bearer token -> caller. Two users in the demo tenant, one in the other.
DEMO_TOKENS: dict[str, Principal] = {
    "demo-analyst": Principal(tenant_id=DEMO_TENANT, user_id="analyst@demo.example"),
    "demo-engineer": Principal(tenant_id=DEMO_TENANT, user_id="engineer@demo.example"),
    "other-analyst": Principal(tenant_id=OTHER_TENANT, user_id="analyst@other.example"),
}


#: The wall clock, as a value so `demo_deps` can default to it.
UTC_NOW: Callable[[], _dt.datetime] = partial(_dt.datetime.now, _dt.UTC)


def demo_deps(clock: Callable[[], _dt.datetime] = UTC_NOW) -> ApiDeps:
    secrets = InMemorySecrets()
    store = InMemoryStore(clock, secrets)
    _seed(store, secrets, clock())
    return ApiDeps(
        authenticator=TokenAuthenticator(DEMO_TOKENS),
        alerts=store,
        investigations=store,
        learning_jobs=store,
        lessons=store,
        systems=store,
        secrets=secrets,
        checker=StubSystemChecker(),
        artifact_links=StubArtifactLinks(),
        audit=InMemoryAudit(),
        clock=clock,
    )


def _alert(n: int, *, fired: _dt.datetime, title: str, severity: str, rule: str) -> Alert:
    return Alert(
        alert_id=f"alert-{n:04d}",
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


def _seed(store: InMemoryStore, secrets: InMemorySecrets, now: _dt.datetime) -> None:
    hour = _dt.timedelta(hours=1)
    brute = store.add_alert(DEMO_TENANT, _alert(
        1, fired=now - 30 * hour, title="Repeated failed logins followed by success",
        severity="high", rule="auth-bruteforce",
    ))
    shell = store.add_alert(DEMO_TENANT, _alert(
        2, fired=now - 3 * hour, title="Interactive shell spawned by web server",
        severity="critical", rule="web-shell",
    ))
    store.add_alert(DEMO_TENANT, _alert(
        3, fired=now - hour, title="New admin group member",
        severity="medium", rule="priv-group-change",
    ))
    store.add_alert(OTHER_TENANT, _alert(
        9, fired=now - 2 * hour, title="Other tenant's alert", severity="low", rule="misc",
    ))

    done = store.add_investigation(DEMO_TENANT, Investigation(
        investigation_id="inv-demo-completed", alert_id=brute.alert_id, status="completed",
        disposition="benign", cost_usd=1.84, created_at=now - 29 * hour,
        started_at=now - 29 * hour, finished_at=now - 29 * hour + _dt.timedelta(minutes=11),
        artifacts=["report.md", "investigation.md", "runtime.html"],
    ))
    store.add_investigation(DEMO_TENANT, Investigation(
        investigation_id="inv-demo-running", alert_id=shell.alert_id, status="running",
        cost_usd=0.42, created_at=now - 2 * hour, started_at=now - 2 * hour,
    ))
    store.add_learning_job(DEMO_TENANT, LearningJob(
        learning_job_id="lj-demo-auto", investigation_id=done.investigation_id,
        alert_id=done.alert_id, status="completed", trigger="auto", stage="judge",
        created_at=done.finished_at or now, finished_at=now - 20 * hour,
    ))
    store.add_lesson(DEMO_TENANT, Lesson(
        lesson_id="lesson-0001", title="Check the source's login history before calling it benign",
        description="A success after failures is benign only if the source has logged in before.",
        status="live",
    ))

    store.put_system(DEMO_TENANT, "tickets", SystemPut(
        kind="ticketing", display_name="Security ticket queue",
        settings={"base_url": "https://tickets.demo.example", "ready_status": "triage"},
    ))
    store.put_system(DEMO_TENANT, "siem", SystemPut(
        kind="siem", display_name="Event search", settings={"base_url": "https://siem.demo.example"},
    ))
    secrets.put_credentials(DEMO_TENANT, "tickets", {"api_token": "demo-secret"})
