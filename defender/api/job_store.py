"""The API's work-record ports over the job store (#1083 FC-10): one object serving the alerts, investigations, learning
jobs, alert mapping, writes and offboarding ports from a `JobStore` it does not own.

It maps the store's records to the wire models by field name (an investigation's `status` is the store's `stage`), and
hands the principal's tenant, actor and credential to the store's own calls. The store's refusals are the API's
(`ports.Conflict`, `NotFound`, `UnknownReference`) and pass through. It announces nothing: the store announces each
write once, after its commit (P2)."""

from __future__ import annotations

import datetime as _dt
from typing import Any

from defender.jobs import InvestigationRecord, JobStore, LearningJobRecord, StoredAlert
from defender.records.formats import MAPPING_KEYS, AlertId, InvestigationId, LearningJobId, TenantId, check_mapping
from defender.records.formats import AlertMapping as StoredAlertMapping
from defender.tenancy import TenantRecord

from .models import (
    Alert,
    AlertMapping,
    AlertSummary,
    Investigation,
    InvestigationKnowledge,
    LearningJob,
)
from .ports import Principal, TimePosition

_NOT_FROM_THE_STORE = {"status", "artifacts", "knowledge"}


def _alert_summary(alert: StoredAlert) -> AlertSummary:
    return AlertSummary(**{name: getattr(alert, name) for name in AlertSummary.model_fields})


def _alert(alert: StoredAlert) -> Alert:
    return Alert(raw=alert.raw.decode("utf-8"), **_alert_summary(alert).model_dump())


def _investigation(record: InvestigationRecord) -> Investigation:
    """The artifacts stay empty: no blob store holds any (#1083 N4)."""
    fields: dict[str, Any] = {
        name: getattr(record, name) for name in Investigation.model_fields if name not in _NOT_FROM_THE_STORE}
    fields["status"] = record.stage
    if record.knowledge is not None:
        fields["knowledge"] = InvestigationKnowledge.model_validate(record.knowledge)
    return Investigation(**fields)


def _learning_job(record: LearningJobRecord) -> LearningJob:
    return LearningJob(**{name: getattr(record, name) for name in LearningJob.model_fields})


def _wire_mapping(stored: StoredAlertMapping) -> AlertMapping:
    return AlertMapping(**{key: stored.path_of(key) for key in MAPPING_KEYS})


class JobStorePorts:
    def __init__(self, store: JobStore) -> None:
        self._store = store

    # --- AlertsRepository ---------------------------------------------------------------

    async def list_alerts(
        self, tenant_id: TenantId, *, fired_after: _dt.datetime | None, fired_before: _dt.datetime | None,
        after: TimePosition | None, limit: int,
    ) -> list[AlertSummary]:
        found = await self._store.list_alerts(
            tenant_id, fired_after=fired_after, fired_before=fired_before, after=after, limit=limit)
        return [_alert_summary(alert) for alert in found]

    async def get_alert(self, tenant_id: TenantId, alert_id: AlertId) -> Alert | None:
        found = await self._store.get_alert(tenant_id, alert_id)
        return None if found is None else _alert(found)

    # --- InvestigationsRepository -------------------------------------------------------

    async def list_investigations(
        self, tenant_id: TenantId, *, alert_id: AlertId | None, after: TimePosition | None, limit: int,
    ) -> list[Investigation]:
        found = await self._store.list_investigations(tenant_id, alert_id=alert_id, after=after, limit=limit)
        return [_investigation(record) for record in found]

    async def get_investigation(self, tenant_id: TenantId, investigation_id: InvestigationId) -> Investigation | None:
        found = await self._store.get_investigation(tenant_id, investigation_id)
        return None if found is None else _investigation(found)

    # --- LearningJobsRepository ---------------------------------------------------------

    async def list_learning_jobs(
        self, tenant_id: TenantId, *, investigation_id: InvestigationId | None, after: TimePosition | None,
        limit: int,
    ) -> list[LearningJob]:
        found = await self._store.list_learning_jobs(
            tenant_id, investigation_id=investigation_id, after=after, limit=limit)
        return [_learning_job(record) for record in found]

    async def get_learning_job(self, tenant_id: TenantId, learning_job_id: LearningJobId) -> LearningJob | None:
        found = await self._store.get_learning_job(tenant_id, learning_job_id)
        return None if found is None else _learning_job(found)

    # --- AlertMappingRepository ---------------------------------------------------------

    async def get_alert_mapping(self, tenant_id: TenantId) -> AlertMapping | None:
        found = await self._store.get_alert_mapping(tenant_id)
        return None if found is None else _wire_mapping(found)

    # --- Writes -------------------------------------------------------------------------

    async def create_investigation(
        self, principal: Principal, alert_id: AlertId, client_request_id: str
    ) -> tuple[Investigation, bool]:
        record, created = await self._store.create_investigation(
            principal.tenant_id, alert_id, client_request_id, actor=principal.actor_id,
            credential_id=principal.credential_id)
        return _investigation(record), created

    async def cancel_investigation(self, principal: Principal, investigation_id: InvestigationId) -> Investigation:
        record = await self._store.cancel_investigation(
            principal.tenant_id, investigation_id, actor=principal.actor_id, credential_id=principal.credential_id)
        return _investigation(record)

    async def delete_investigation(self, principal: Principal, investigation_id: InvestigationId) -> None:
        await self._store.delete_investigation(
            principal.tenant_id, investigation_id, actor=principal.actor_id, credential_id=principal.credential_id)

    async def create_learning_job(
        self, principal: Principal, investigation_id: InvestigationId, client_request_id: str
    ) -> tuple[LearningJob, bool]:
        record, created = await self._store.create_learning_job(
            principal.tenant_id, investigation_id, client_request_id, actor=principal.actor_id,
            credential_id=principal.credential_id)
        return _learning_job(record), created

    async def put_alert_mapping(self, principal: Principal, body: AlertMapping) -> tuple[AlertMapping, bool]:
        stored, created = await self._store.put_alert_mapping(
            principal.tenant_id, check_mapping(body.model_dump()), actor=principal.actor_id,
            credential_id=principal.credential_id)
        return _wire_mapping(stored), created

    # --- Offboarding --------------------------------------------------------------------

    async def offboard_tenant(self, tenant_id: TenantId, *, actor: str) -> TenantRecord:
        return await self._store.offboard_tenant(tenant_id, actor=actor)
