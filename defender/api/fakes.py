"""Rule-free stand-ins for the ports, for the demo server (`demo.py`).

They keep records per tenant and answer the obvious thing, and they enforce NONE of the data
rules `ports.py` states — no `client_request_id` replay, no one-live-investigation collapse, no
refusal to cancel, delete or learn from an investigation in the wrong state. Those rules are the
store's (#1082), which enforces them with constraints and transactions and tests them against
the ports; re-deriving them here in Python is how a second, subtly different copy of each rule
gets written. So a demo client that double-submits gets two investigations, and nothing here is
a reference for how the platform behaves.

What they do keep is the ports' shape: writes go through a transaction (`transaction`), and
the audit events written through it are kept once its block exits normally — none when it
raises. Records written before a raise are NOT undone; the demo needs no atomicity for them.

Every record is keyed by `(tenant_id, id)`, so one tenant's record can never displace
another's, and every read iterates a snapshot, so a concurrent write cannot fail it.
"""

from __future__ import annotations

import datetime as _dt
import itertools
from collections.abc import Callable
from typing import TypeVar

from pydantic import AwareDatetime

from defender._model import model

from .models import (
    Alert,
    AlertSummary,
    Investigation,
    LearningJob,
    Lesson,
    System,
    SystemCheck,
    SystemPut,
    SystemSettings,
)
from .ports import (
    AuditAction,
    NotFound,
    Principal,
    TimePosition,
    Unauthenticated,
    UnknownReference,
)

T = TypeVar("T")


def _newest_after(rows: list[T], key: Callable[[T], TimePosition], after: TimePosition | None,
                  limit: int) -> list[T]:
    """`rows` newest first by `key`, strictly after `after`, at most `limit` — the order the
    newest-first ports state."""
    ordered = sorted(rows, key=key, reverse=True)
    return [r for r in ordered if after is None or key(r) < after][:limit]


def _ids_after(rows: list[T], key: Callable[[T], str], after: str | None, limit: int) -> list[T]:
    return [r for r in sorted(rows, key=key) if after is None or key(r) > after][:limit]


class TokenAuthenticator:
    """Fixed bearer tokens, each naming one principal. A stand-in for the hosted login provider
    (#1131 "Open"); nothing about the token format is part of the contract."""

    def __init__(self, tokens: dict[str, Principal]) -> None:
        self._tokens = dict(tokens)

    def authenticate(self, bearer_token: str | None) -> Principal:
        if bearer_token is None or bearer_token not in self._tokens:
            raise Unauthenticated("missing or unknown bearer token")
        return self._tokens[bearer_token]


class _Table(dict[tuple[str, str], T]):
    """One tenant-keyed table."""

    def of(self, tenant_id: str) -> list[T]:
        return [v for (tenant, _), v in list(self.items()) if tenant == tenant_id]


@model(frozen=True)
class AuditEvent:
    """One audited action, as the demo store keeps it."""

    tenant_id: str
    user_id: str
    action: str
    target: str
    at: AwareDatetime
    detail: str = ""


class InMemoryStore:
    """The alerts, investigations, learning jobs, lessons and systems repositories, and the
    transactions writes go through, seeded by `demo.py` through the `add_*` methods (which are
    not part of any port). `audit_events` is every committed audit event, oldest first."""

    def __init__(self, clock: Callable[[], _dt.datetime]) -> None:
        self._clock = clock
        self.audit_events: list[AuditEvent] = []
        self._ids = itertools.count(1)
        self._alerts: _Table[Alert] = _Table()
        self._investigations: _Table[Investigation] = _Table()
        self._deleted: set[tuple[str, str]] = set()
        self._learning_jobs: _Table[LearningJob] = _Table()
        self._lessons: _Table[Lesson] = _Table()
        self._systems: _Table[SystemSettings] = _Table()

    def _mint(self, prefix: str) -> str:
        return f"{prefix}-{next(self._ids):06d}"

    def transaction(self, tenant_id: str, actor: str) -> _InMemoryTransaction:
        return _InMemoryTransaction(self, tenant_id, actor, self._clock)

    # --- seeding ------------------------------------------------------------------------

    def add_alert(self, tenant_id: str, alert: Alert) -> Alert:
        self._alerts[(tenant_id, alert.alert_id)] = alert
        return alert

    def add_investigation(self, tenant_id: str, investigation: Investigation) -> Investigation:
        self._investigations[(tenant_id, investigation.investigation_id)] = investigation
        return investigation

    def add_learning_job(self, tenant_id: str, job: LearningJob) -> LearningJob:
        self._learning_jobs[(tenant_id, job.learning_job_id)] = job
        return job

    def add_lesson(self, tenant_id: str, lesson: Lesson) -> Lesson:
        self._lessons[(tenant_id, lesson.lesson_id)] = lesson
        return lesson

    def add_system(self, tenant_id: str, settings: SystemSettings) -> SystemSettings:
        self._systems[(tenant_id, settings.system_id)] = settings
        return settings

    # --- AlertsRepository ---------------------------------------------------------------

    def list_alerts(
        self,
        tenant_id: str,
        *,
        fired_after: _dt.datetime | None,
        fired_before: _dt.datetime | None,
        severity: str | None,
        after: TimePosition | None,
        limit: int,
    ) -> list[AlertSummary]:
        selected = [
            a for a in self._alerts.of(tenant_id)
            if (fired_after is None or a.fired_at >= fired_after)
            and (fired_before is None or a.fired_at < fired_before)
            and (severity is None or a.severity == severity)
        ]
        page = _newest_after(selected, lambda a: (a.fired_at, a.alert_id), after, limit)
        return [AlertSummary.model_validate(a.model_dump(exclude={"raw"})) for a in page]

    def get_alert(self, tenant_id: str, alert_id: str) -> Alert | None:
        return self._alerts.get((tenant_id, alert_id))

    # --- InvestigationsRepository -------------------------------------------------------

    def create_investigation(
        self, tenant_id: str, alert_id: str, client_request_id: str
    ) -> tuple[Investigation, bool]:
        if self.get_alert(tenant_id, alert_id) is None:
            raise UnknownReference(f"no alert {alert_id!r}")
        investigation = Investigation(
            investigation_id=self._mint("inv"), alert_id=alert_id, status="queued",
            cost_usd=0.0, created_at=self._clock(),
        )
        return self.add_investigation(tenant_id, investigation), True

    def list_investigations(
        self, tenant_id: str, *, alert_id: str | None, after: TimePosition | None, limit: int
    ) -> list[Investigation]:
        found = [
            i for i in self._investigations.of(tenant_id)
            if (tenant_id, i.investigation_id) not in self._deleted
            and (alert_id is None or i.alert_id == alert_id)
        ]
        return _newest_after(found, lambda i: (i.created_at, i.investigation_id), after, limit)

    def get_investigation(self, tenant_id: str, investigation_id: str) -> Investigation | None:
        if (tenant_id, investigation_id) in self._deleted:
            return None
        return self._investigations.get((tenant_id, investigation_id))

    def _existing(self, tenant_id: str, investigation_id: str) -> Investigation:
        investigation = self.get_investigation(tenant_id, investigation_id)
        if investigation is None:
            raise NotFound(f"no investigation {investigation_id!r}")
        return investigation

    def cancel_investigation(self, tenant_id: str, investigation_id: str) -> Investigation:
        aborted = self._existing(tenant_id, investigation_id).model_copy(
            update={"status": "aborted", "finished_at": self._clock()}
        )
        return self.add_investigation(tenant_id, aborted)

    def delete_investigation(self, tenant_id: str, investigation_id: str) -> None:
        self._existing(tenant_id, investigation_id)
        self._deleted.add((tenant_id, investigation_id))

    # --- LearningJobsRepository ---------------------------------------------------------

    def create_learning_job(
        self, tenant_id: str, investigation_id: str, client_request_id: str
    ) -> tuple[LearningJob, bool]:
        investigation = self.get_investigation(tenant_id, investigation_id)
        if investigation is None:
            raise UnknownReference(f"no investigation {investigation_id!r}")
        job = LearningJob(
            learning_job_id=self._mint("lj"), investigation_id=investigation_id,
            alert_id=investigation.alert_id, status="queued", trigger="explicit",
            created_at=self._clock(),
        )
        return self.add_learning_job(tenant_id, job), True

    def list_learning_jobs(
        self, tenant_id: str, *, investigation_id: str | None, after: TimePosition | None,
        limit: int,
    ) -> list[LearningJob]:
        found = [
            j for j in self._learning_jobs.of(tenant_id)
            if investigation_id is None or j.investigation_id == investigation_id
        ]
        return _newest_after(found, lambda j: (j.created_at, j.learning_job_id), after, limit)

    def get_learning_job(self, tenant_id: str, learning_job_id: str) -> LearningJob | None:
        return self._learning_jobs.get((tenant_id, learning_job_id))

    # --- LessonsRepository --------------------------------------------------------------

    def list_lessons(self, tenant_id: str, *, after: str | None, limit: int) -> list[Lesson]:
        return _ids_after(self._lessons.of(tenant_id), lambda le: le.lesson_id, after, limit)

    # --- SystemsRepository --------------------------------------------------------------

    def list_systems(
        self, tenant_id: str, *, after: str | None, limit: int
    ) -> list[SystemSettings]:
        return _ids_after(self._systems.of(tenant_id), lambda s: s.system_id, after, limit)

    def get_system(self, tenant_id: str, system_id: str) -> SystemSettings | None:
        return self._systems.get((tenant_id, system_id))

    def put_system(
        self, tenant_id: str, system_id: str, body: SystemPut
    ) -> tuple[SystemSettings, bool]:
        created = (tenant_id, system_id) not in self._systems
        settings = self.add_system(tenant_id, SystemSettings(system_id=system_id, **body.model_dump()))
        return settings, created


class _InMemoryTransaction:
    """A write transaction on `InMemoryStore` for one tenant and actor: writes apply at once,
    audit events are kept only if the block exits normally."""

    def __init__(self, store: InMemoryStore, tenant_id: str, actor: str,
                 clock: Callable[[], _dt.datetime]) -> None:
        self._store = store
        self._clock = clock
        self._tenant_id = tenant_id
        self._actor = actor
        self._pending: list[AuditEvent] = []

    def __enter__(self) -> _InMemoryTransaction:
        return self

    def __exit__(self, exc_type: type[BaseException] | None, *_: object) -> None:
        if exc_type is None:
            self._store.audit_events.extend(self._pending)

    def create_investigation(self, alert_id: str, client_request_id: str) -> tuple[Investigation, bool]:
        return self._store.create_investigation(self._tenant_id, alert_id, client_request_id)

    def cancel_investigation(self, investigation_id: str) -> Investigation:
        return self._store.cancel_investigation(self._tenant_id, investigation_id)

    def delete_investigation(self, investigation_id: str) -> None:
        self._store.delete_investigation(self._tenant_id, investigation_id)

    def create_learning_job(self, investigation_id: str, client_request_id: str) -> tuple[LearningJob, bool]:
        return self._store.create_learning_job(self._tenant_id, investigation_id, client_request_id)

    def put_system(self, system_id: str, body: SystemPut) -> tuple[SystemSettings, bool]:
        return self._store.put_system(self._tenant_id, system_id, body)

    def audit(self, action: AuditAction, target: str, detail: str = "") -> None:
        self._pending.append(AuditEvent(
            tenant_id=self._tenant_id, user_id=self._actor, action=action, target=target,
            at=self._clock(), detail=detail,
        ))


class InMemorySecrets:
    def __init__(self) -> None:
        self._credentials: dict[tuple[str, str], dict[str, str]] = {}

    def put_credentials(self, tenant_id: str, system_id: str, credentials: dict[str, str]) -> None:
        self._credentials[(tenant_id, system_id)] = dict(credentials)

    def has_credentials(self, tenant_id: str, system_id: str) -> bool:
        return (tenant_id, system_id) in self._credentials


class StubSystemChecker:
    """Answers from configuration alone; the real check calls the system through the
    credential proxy."""

    def check(self, tenant_id: str, system: System) -> SystemCheck:
        if not system.enabled:
            return SystemCheck(ok=False, detail="the system is disabled")
        if not system.has_credentials:
            return SystemCheck(ok=False, detail="no credentials set")
        return SystemCheck(ok=True, detail="stub: configuration present; no call was made")


class StubArtifactLinks:
    """Links on a placeholder origin that serves nothing. The real links are signed and expire."""

    ORIGIN = "https://artifacts.invalid"

    def signed_url(self, tenant_id: str, investigation_id: str, key: str) -> str:
        return f"{self.ORIGIN}/{tenant_id}/{investigation_id}/{key}?signature=stub"
