"""In-memory implementations of every port, for the stub server and the API's tests.

They implement the data-layer rules the real store will enforce with constraints and
transactions (`docs/platform-design.md` §2.5, §4.1), so `tests/test_api_stub.py` is the
conformance suite a real store has to pass too. Nothing here persists, and no investigation
ever moves on its own: a created investigation stays `queued` until a test (or the demo seed)
sets its state through the `add_*` methods, which are not part of any port.
"""

from __future__ import annotations

import datetime as _dt
import itertools
from collections.abc import Callable, Iterable
from typing import Any

from .models import (
    LIVE_STATUSES,
    Alert,
    AlertSummary,
    Investigation,
    LearningJob,
    Lesson,
    System,
    SystemCheck,
    SystemPut,
)
from .ports import (
    AuditEvent,
    Conflict,
    NotFound,
    Principal,
    Unauthenticated,
    UnknownReference,
)


class TokenAuthenticator:
    """Fixed bearer tokens, each naming one principal. A stand-in for the hosted login provider
    (#1131 "Open"); nothing about the token format is part of the contract."""

    def __init__(self, tokens: dict[str, Principal]) -> None:
        self._tokens = dict(tokens)

    def authenticate(self, bearer_token: str | None) -> Principal:
        if bearer_token is None or bearer_token not in self._tokens:
            raise Unauthenticated("missing or unknown bearer token")
        return self._tokens[bearer_token]


class _Record:
    """A stored record plus the bookkeeping the wire model does not show."""

    def __init__(self, tenant_id: str, value: Any, *, client_request_id: str | None = None) -> None:
        self.tenant_id = tenant_id
        self.value = value
        self.client_request_id = client_request_id
        self.deleted = False


class InMemoryStore:
    """The alerts, investigations, learning jobs, lessons and systems repositories over one set
    of in-memory tables, since investigations and learning jobs point at alerts."""

    def __init__(self, clock: Callable[[], _dt.datetime], secrets: InMemorySecrets) -> None:
        self._clock = clock
        # `System.has_credentials` is read from the secret store, never stored beside the
        # settings, so the two cannot disagree.
        self._secrets = secrets
        self._ids = itertools.count(1)
        self._alerts: dict[str, _Record] = {}
        self._investigations: dict[str, _Record] = {}
        self._learning_jobs: dict[str, _Record] = {}
        self._lessons: list[_Record] = []
        self._systems: dict[tuple[str, str], System] = {}

    def _mint(self, prefix: str) -> str:
        return f"{prefix}-{next(self._ids):06d}"

    @staticmethod
    def _visible(record: _Record | None, tenant_id: str) -> Any:
        if record is None or record.tenant_id != tenant_id or record.deleted:
            return None
        return record.value

    # --- seeding (not part of any port) -------------------------------------------------

    def add_alert(self, tenant_id: str, alert: Alert) -> Alert:
        self._alerts[alert.alert_id] = _Record(tenant_id, alert)
        return alert

    def add_investigation(self, tenant_id: str, investigation: Investigation) -> Investigation:
        self._investigations[investigation.investigation_id] = _Record(tenant_id, investigation)
        return investigation

    def add_learning_job(self, tenant_id: str, job: LearningJob) -> LearningJob:
        self._learning_jobs[job.learning_job_id] = _Record(tenant_id, job)
        return job

    def add_lesson(self, tenant_id: str, lesson: Lesson) -> Lesson:
        self._lessons.append(_Record(tenant_id, lesson))
        return lesson

    # --- AlertsRepository ---------------------------------------------------------------

    def list_alerts(
        self,
        tenant_id: str,
        *,
        fired_after: _dt.datetime | None,
        fired_before: _dt.datetime | None,
        severity: str | None,
        limit: int,
    ) -> list[AlertSummary]:
        alerts: list[Alert] = [
            a for r in self._alerts.values() if (a := self._visible(r, tenant_id)) is not None
        ]
        selected = [
            a for a in alerts
            if (fired_after is None or a.fired_at >= fired_after)
            and (fired_before is None or a.fired_at < fired_before)
            and (severity is None or a.severity == severity)
        ]
        selected.sort(key=lambda a: a.fired_at, reverse=True)
        return [AlertSummary.model_validate(a.model_dump(exclude={"raw"})) for a in selected[:limit]]

    def get_alert(self, tenant_id: str, alert_id: str) -> Alert | None:
        return self._visible(self._alerts.get(alert_id), tenant_id)

    # --- InvestigationsRepository -------------------------------------------------------

    def _tenant_investigations(self, tenant_id: str) -> Iterable[_Record]:
        return (r for r in self._investigations.values() if r.tenant_id == tenant_id)

    def create_investigation(
        self, tenant_id: str, alert_id: str, client_request_id: str
    ) -> tuple[Investigation, bool]:
        if self.get_alert(tenant_id, alert_id) is None:
            raise UnknownReference(f"no alert {alert_id!r}")
        of_alert = [r for r in self._tenant_investigations(tenant_id) if r.value.alert_id == alert_id]
        for r in of_alert:
            if r.client_request_id == client_request_id:
                return r.value, False
        for r in of_alert:
            if r.value.status in LIVE_STATUSES:
                return r.value, False
        investigation = Investigation(
            investigation_id=self._mint("inv"),
            alert_id=alert_id,
            status="queued",
            cost_usd=0.0,
            created_at=self._clock(),
        )
        self._investigations[investigation.investigation_id] = _Record(
            tenant_id, investigation, client_request_id=client_request_id
        )
        return investigation, True

    def list_investigations(
        self, tenant_id: str, *, alert_id: str | None, limit: int
    ) -> list[Investigation]:
        found = [
            r.value for r in self._tenant_investigations(tenant_id)
            if not r.deleted and (alert_id is None or r.value.alert_id == alert_id)
        ]
        found.sort(key=lambda i: i.created_at, reverse=True)
        return found[:limit]

    def get_investigation(self, tenant_id: str, investigation_id: str) -> Investigation | None:
        return self._visible(self._investigations.get(investigation_id), tenant_id)

    def _existing_investigation(self, tenant_id: str, investigation_id: str) -> _Record:
        record = self._investigations.get(investigation_id)
        if self._visible(record, tenant_id) is None:
            raise NotFound(f"no investigation {investigation_id!r}")
        assert record is not None
        return record

    def cancel_investigation(self, tenant_id: str, investigation_id: str) -> Investigation:
        record = self._existing_investigation(tenant_id, investigation_id)
        if record.value.status not in LIVE_STATUSES:
            raise Conflict(f"investigation already ended ({record.value.status})")
        record.value = record.value.model_copy(
            update={"status": "aborted", "finished_at": self._clock()}
        )
        return record.value

    def delete_investigation(self, tenant_id: str, investigation_id: str) -> None:
        record = self._existing_investigation(tenant_id, investigation_id)
        if record.value.status in LIVE_STATUSES:
            raise Conflict("cancel a live investigation before deleting it")
        record.deleted = True

    # --- LearningJobsRepository ---------------------------------------------------------

    def create_learning_job(
        self, tenant_id: str, investigation_id: str, client_request_id: str
    ) -> tuple[LearningJob, bool]:
        investigation = self.get_investigation(tenant_id, investigation_id)
        if investigation is None:
            raise UnknownReference(f"no investigation {investigation_id!r}")
        for r in self._learning_jobs.values():
            if r.tenant_id == tenant_id and r.client_request_id == client_request_id:
                if r.value.investigation_id != investigation_id:
                    raise Conflict("client_request_id already used for another investigation")
                return r.value, False
        if investigation.status != "completed":
            raise Conflict(f"only a completed investigation can be learned from ({investigation.status})")
        job = LearningJob(
            learning_job_id=self._mint("lj"),
            investigation_id=investigation_id,
            alert_id=investigation.alert_id,
            status="queued",
            trigger="explicit",
            created_at=self._clock(),
        )
        self._learning_jobs[job.learning_job_id] = _Record(
            tenant_id, job, client_request_id=client_request_id
        )
        return job, True

    def list_learning_jobs(
        self, tenant_id: str, *, investigation_id: str | None, limit: int
    ) -> list[LearningJob]:
        found = [
            r.value for r in self._learning_jobs.values()
            if r.tenant_id == tenant_id
            and (investigation_id is None or r.value.investigation_id == investigation_id)
        ]
        found.sort(key=lambda j: j.created_at, reverse=True)
        return found[:limit]

    def get_learning_job(self, tenant_id: str, learning_job_id: str) -> LearningJob | None:
        return self._visible(self._learning_jobs.get(learning_job_id), tenant_id)

    # --- LessonsRepository --------------------------------------------------------------

    def list_lessons(self, tenant_id: str) -> list[Lesson]:
        return [r.value for r in self._lessons if r.tenant_id == tenant_id]

    # --- SystemsRepository --------------------------------------------------------------

    def _with_credentials_flag(self, tenant_id: str, system: System) -> System:
        has = self._secrets.has_credentials(tenant_id, system.system_id)
        return system.model_copy(update={"has_credentials": has})

    def list_systems(self, tenant_id: str) -> list[System]:
        return [
            self._with_credentials_flag(tenant_id, s)
            for (tenant, _), s in sorted(self._systems.items())
            if tenant == tenant_id
        ]

    def get_system(self, tenant_id: str, system_id: str) -> System | None:
        system = self._systems.get((tenant_id, system_id))
        return None if system is None else self._with_credentials_flag(tenant_id, system)

    def put_system(self, tenant_id: str, system_id: str, body: SystemPut) -> tuple[System, bool]:
        created = (tenant_id, system_id) not in self._systems
        self._systems[(tenant_id, system_id)] = System(
            system_id=system_id, has_credentials=False, **body.model_dump()
        )
        system = self.get_system(tenant_id, system_id)
        assert system is not None
        return system, created


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


class InMemoryAudit:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def record(self, event: AuditEvent) -> None:
        self.events.append(event)
