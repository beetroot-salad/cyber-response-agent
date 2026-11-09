"""Rule-free stand-ins for the ports, for the demo server (`demo.py`)."""

from __future__ import annotations

import datetime as _dt
import itertools
from collections.abc import Callable, Mapping
from typing import Any, TypeVar

from pydantic import AwareDatetime

from defender._model import model
from defender.records import formats
from defender.records.formats import AlertId, InvestigationId, LearningJobId, TenantId, UuidId

from .models import (
    Alert,
    AlertMapping,
    AlertSummary,
    Investigation,
    InvestigationKnowledge,
    LearningJob,
    Lesson,
    System,
    SystemCheck,
    SystemPut,
    SystemSettings,
)
from .ports import (
    AuditAction,
    Conflict,
    NotFound,
    Principal,
    TimePosition,
    UnknownReference,
)

T = TypeVar("T")
#: Any one id family (`demo` mints by family too).
_Id = TypeVar("_Id", bound=UuidId)


def _newest_after(rows: list[T], key: Callable[[T], TimePosition], after: TimePosition | None,
                  limit: int) -> list[T]:
    """`rows` newest first by `key`, strictly after `after`, at most `limit` — the order the
    newest-first ports state."""
    ordered = sorted(rows, key=key, reverse=True)
    return [r for r in ordered if after is None or key(r) < after][:limit]


def _ids_after(rows: list[T], key: Callable[[T], str], after: str | None, limit: int) -> list[T]:
    return [r for r in sorted(rows, key=key) if after is None or key(r) > after][:limit]


def _api_knowledge(record_text: str | None, *, stamp_names_source: bool) -> InvestigationKnowledge | None:
    """The API's `knowledge` for a run's host-held record, by the one mapping records owns."""
    mapped = formats.api_knowledge(formats.knowledge_status(record_text, stamp_names_source=stamp_names_source))
    return None if mapped is None else InvestigationKnowledge.model_validate(mapped)


class _Table(dict[tuple[str, str], T]):
    """One tenant-keyed table."""

    def of(self, tenant_id: TenantId) -> list[T]:
        return [v for (tenant, _), v in list(self.items()) if tenant == tenant_id]


@model(frozen=True)
class AuditEvent:
    """One audited action, as the demo store keeps it."""

    tenant_id: TenantId
    user_id: str
    action: str
    target: str
    at: AwareDatetime
    detail: str = ""
    credential_id: str | None = None


class InMemoryStore:
    """The alerts, investigations, learning jobs, lessons and systems repositories, and the
    transactions writes go through, seeded by `demo.py` through the `add_*` methods (which are
    not part of any port). `audit_events` is every committed audit event, oldest first."""

    def __init__(self, clock: Callable[[], _dt.datetime]) -> None:
        self._clock = clock
        self.audit_events: list[AuditEvent] = []
        self._ids = itertools.count(1)
        self._alerts: _Table[Alert] = _Table()
        self._alert_mappings: dict[TenantId, AlertMapping] = {}
        self._investigations: _Table[Investigation] = _Table()
        self._learning_jobs: _Table[LearningJob] = _Table()
        self._lessons: _Table[Lesson] = _Table()
        self._systems: _Table[SystemSettings] = _Table()

    def _mint(self, family: type[_Id]) -> _Id:
        """The next id of `family`: canonical UUID text from a counter, so ids still sort in the order
        they were minted, as the `prefix-000001` ids before #1382 did."""
        return family(f"00000000-0000-4000-8000-{next(self._ids):012x}")

    def transaction(self, tenant_id: TenantId, principal: Principal) -> _InMemoryTransaction:
        return _InMemoryTransaction(self, tenant_id, principal, self._clock)

    # --- seeding ------------------------------------------------------------------------

    def add_alert(self, tenant_id: TenantId, alert: Alert) -> Alert:
        self._alerts[(tenant_id, alert.alert_id)] = alert
        return alert

    def add_investigation(self, tenant_id: TenantId, investigation: Investigation) -> Investigation:
        self._investigations[(tenant_id, investigation.investigation_id)] = investigation
        return investigation

    def add_run_knowledge(
        self, tenant_id: TenantId, investigation_id: InvestigationId, record_text: str | None, *,
        stamp_knowledge_source: Mapping[str, Any] | None = None,
    ) -> Investigation:
        """Set an investigation's `knowledge` from its run's host-held knowledge record (its
        file's text; `None`: no record) and the run stamp's `knowledge_source` (`None`: the
        stamp has none, or there is no run), by the rule `InvestigationsRepository` states."""
        key = (tenant_id, investigation_id)
        investigation = self._investigations[key]
        knowledge = _api_knowledge(record_text, stamp_names_source=stamp_knowledge_source is not None)
        updated = investigation.model_copy(update={"knowledge": knowledge})
        self._investigations[key] = updated
        return updated

    def add_learning_job(self, tenant_id: TenantId, job: LearningJob) -> LearningJob:
        self._learning_jobs[(tenant_id, job.learning_job_id)] = job
        return job

    def add_lesson(self, tenant_id: TenantId, lesson: Lesson) -> Lesson:
        self._lessons[(tenant_id, lesson.lesson_id)] = lesson
        return lesson

    def add_system(self, tenant_id: TenantId, settings: SystemSettings) -> SystemSettings:
        self._systems[(tenant_id, settings.system_id)] = settings
        return settings

    # --- AlertsRepository ---------------------------------------------------------------

    async def list_alerts(
        self,
        tenant_id: TenantId,
        *,
        fired_after: _dt.datetime | None,
        fired_before: _dt.datetime | None,
        after: TimePosition | None,
        limit: int,
    ) -> list[AlertSummary]:
        selected = [
            a for a in self._alerts.of(tenant_id)
            if (fired_after is None or a.fired_at >= fired_after)
            and (fired_before is None or a.fired_at < fired_before)
        ]
        page = _newest_after(selected, lambda a: (a.fired_at, a.alert_id), after, limit)
        return [AlertSummary.model_validate(a.model_dump(exclude={"raw"})) for a in page]

    async def get_alert(self, tenant_id: TenantId, alert_id: AlertId) -> Alert | None:
        return self._alerts.get((tenant_id, alert_id))

    # --- InvestigationsRepository -------------------------------------------------------

    async def create_investigation(
        self, tenant_id: TenantId, alert_id: AlertId, client_request_id: str
    ) -> tuple[Investigation, bool]:
        """Always a new attempt 1 stamped with the request key: the replay rules are the store's."""
        if await self.get_alert(tenant_id, alert_id) is None:
            raise UnknownReference(f"no alert {alert_id!r}")
        investigation = Investigation(
            investigation_id=self._mint(InvestigationId), alert_id=alert_id, status="queued",
            request_key=client_request_id, attempt=1, cost_usd=0.0, created_at=self._clock(),
        )
        return self.add_investigation(tenant_id, investigation), True

    async def list_investigations(
        self, tenant_id: TenantId, *, alert_id: AlertId | None, after: TimePosition | None, limit: int
    ) -> list[Investigation]:
        found = [
            i for i in self._investigations.of(tenant_id)
            if alert_id is None or i.alert_id == alert_id
        ]
        return _newest_after(found, lambda i: (i.created_at, i.investigation_id), after, limit)

    async def get_investigation(self, tenant_id: TenantId, investigation_id: InvestigationId) -> Investigation | None:
        return self._investigations.get((tenant_id, investigation_id))

    async def _existing(self, tenant_id: TenantId, investigation_id: InvestigationId) -> Investigation:
        investigation = await self.get_investigation(tenant_id, investigation_id)
        if investigation is None:
            raise NotFound(f"no investigation {investigation_id!r}")
        return investigation

    async def cancel_investigation(self, tenant_id: TenantId, investigation_id: InvestigationId) -> Investigation:
        existing = await self._existing(tenant_id, investigation_id)
        if existing.status not in ("queued", "running"):
            raise Conflict("already ended")
        aborted = existing.model_copy(update={"status": "aborted", "failure_reason": "cancelled",
                                              "finished_at": self._clock()})
        return self.add_investigation(tenant_id, aborted)

    async def delete_investigation(self, tenant_id: TenantId, investigation_id: InvestigationId) -> None:
        existing = await self._existing(tenant_id, investigation_id)
        if existing.status in ("queued", "running"):
            raise Conflict("cannot delete an investigation that is queued or running")
        del self._investigations[(tenant_id, investigation_id)]

    # --- LearningJobsRepository ---------------------------------------------------------

    async def create_learning_job(
        self, tenant_id: TenantId, investigation_id: InvestigationId, client_request_id: str
    ) -> tuple[LearningJob, bool]:
        investigation = await self.get_investigation(tenant_id, investigation_id)
        if investigation is None:
            raise UnknownReference(f"no investigation {investigation_id!r}")
        job = LearningJob(
            learning_job_id=self._mint(LearningJobId), investigation_id=investigation_id,
            alert_id=investigation.alert_id, status="queued", trigger="explicit",
            created_at=self._clock(),
        )
        return self.add_learning_job(tenant_id, job), True

    async def list_learning_jobs(
        self, tenant_id: TenantId, *, investigation_id: InvestigationId | None, after: TimePosition | None,
        limit: int,
    ) -> list[LearningJob]:
        found = [
            j for j in self._learning_jobs.of(tenant_id)
            if investigation_id is None or j.investigation_id == investigation_id
        ]
        return _newest_after(found, lambda j: (j.created_at, j.learning_job_id), after, limit)

    async def get_learning_job(self, tenant_id: TenantId, learning_job_id: LearningJobId) -> LearningJob | None:
        return self._learning_jobs.get((tenant_id, learning_job_id))

    # --- LessonsRepository --------------------------------------------------------------

    async def list_lessons(self, tenant_id: TenantId, *, after: str | None, limit: int) -> list[Lesson]:
        return _ids_after(self._lessons.of(tenant_id), lambda le: le.lesson_id, after, limit)

    # --- SystemsRepository --------------------------------------------------------------

    async def list_systems(
        self, tenant_id: TenantId, *, after: str | None, limit: int
    ) -> list[SystemSettings]:
        return _ids_after(self._systems.of(tenant_id), lambda s: s.system_id, after, limit)

    async def get_system(self, tenant_id: TenantId, system_id: str) -> SystemSettings | None:
        return self._systems.get((tenant_id, system_id))

    async def get_alert_mapping(self, tenant_id: TenantId) -> AlertMapping | None:
        return self._alert_mappings.get(tenant_id)

    async def put_alert_mapping(self, tenant_id: TenantId, body: AlertMapping) -> tuple[AlertMapping, bool]:
        """Rule-free like the rest of the fake: the wire model has applied the path rules, and nothing here derives
        alert titles (the real store derives them when it stores an alert)."""
        created = tenant_id not in self._alert_mappings
        self._alert_mappings[tenant_id] = body
        return body, created

    async def put_system(
        self, tenant_id: TenantId, system_id: str, body: SystemPut
    ) -> tuple[SystemSettings, bool]:
        created = (tenant_id, system_id) not in self._systems
        settings = self.add_system(tenant_id, SystemSettings(system_id=system_id, **body.model_dump()))
        return settings, created


class _InMemoryTransaction:
    """A write transaction on `InMemoryStore` for one tenant and actor: writes apply at once,
    audit events are kept only if the block exits normally."""

    def __init__(self, store: InMemoryStore, tenant_id: TenantId, principal: Principal,
                 clock: Callable[[], _dt.datetime]) -> None:
        self._store = store
        self._clock = clock
        self._tenant_id = tenant_id
        self._actor = principal.user_id
        self._credential_id = principal.credential_id
        self._pending: list[AuditEvent] = []

    async def __aenter__(self) -> _InMemoryTransaction:
        return self

    async def __aexit__(self, exc_type: type[BaseException] | None, *_: object) -> None:
        if exc_type is None:
            self._store.audit_events.extend(self._pending)

    async def create_investigation(self, alert_id: AlertId, client_request_id: str) -> tuple[Investigation, bool]:
        return await self._store.create_investigation(self._tenant_id, alert_id, client_request_id)

    async def cancel_investigation(self, investigation_id: InvestigationId) -> Investigation:
        return await self._store.cancel_investigation(self._tenant_id, investigation_id)

    async def delete_investigation(self, investigation_id: InvestigationId) -> None:
        await self._store.delete_investigation(self._tenant_id, investigation_id)

    async def create_learning_job(self, investigation_id: InvestigationId, client_request_id: str) -> tuple[LearningJob, bool]:
        return await self._store.create_learning_job(self._tenant_id, investigation_id, client_request_id)

    async def put_system(self, system_id: str, body: SystemPut) -> tuple[SystemSettings, bool]:
        return await self._store.put_system(self._tenant_id, system_id, body)

    async def put_alert_mapping(self, body: AlertMapping) -> tuple[AlertMapping, bool]:
        return await self._store.put_alert_mapping(self._tenant_id, body)

    async def audit(self, action: AuditAction, target: str, detail: str = "") -> None:
        self._pending.append(AuditEvent(
            tenant_id=self._tenant_id, user_id=self._actor, action=action, target=target,
            at=self._clock(), detail=detail, credential_id=self._credential_id,
        ))


class InMemorySecrets:
    def __init__(self) -> None:
        self._credentials: dict[tuple[str, str], dict[str, str]] = {}

    async def put_credentials(
        self, tenant_id: TenantId, system_id: str, kind: str, credentials: dict[str, str],
    ) -> None:
        self._credentials[(tenant_id, system_id)] = dict(credentials)

    async def has_credentials(self, tenant_id: TenantId, system_id: str) -> bool:
        return (tenant_id, system_id) in self._credentials


class StubSystemChecker:
    """Answers from configuration alone; the real check calls the system through the
    credential proxy."""

    async def check(self, tenant_id: TenantId, system: System) -> SystemCheck:
        if not system.enabled:
            return SystemCheck(ok=False, detail="the system is disabled")
        if not system.has_credentials:
            return SystemCheck(ok=False, detail="no credentials set")
        return SystemCheck(ok=True, detail="stub: configuration present; no call was made")


class StubArtifactLinks:
    """Links on a placeholder origin that serves nothing. The real links are signed and expire."""

    ORIGIN = "https://artifacts.invalid"

    async def signed_url(self, tenant_id: TenantId, investigation_id: InvestigationId, key: str) -> str:
        return f"{self.ORIGIN}/{tenant_id}/{investigation_id}/{key}?signature=stub"
