"""The record store: one transaction per write, taken under the tenant's row lock so one tenant's writes are serialized
across the system and case tables (O5). The judgement (all of O4 but version, staleness, lock and generation) is injected
and sees the tenant's whole after-state, read under the lock."""

from __future__ import annotations

import datetime as _dt
from collections.abc import AsyncIterator, Callable, Mapping, Sequence
from contextlib import asynccontextmanager
from typing import Any, NamedTuple

from sqlalchemy import Table, func, insert, select
from sqlalchemy.ext.asyncio import AsyncConnection

from defender.database import async_engine
from defender.kit.faults import ConfigFault
from defender.records.formats import TenantId
from defender.systems.run_tenant import not_imported_text
from defender.tenancy import parse_access
from defender.tenancy.models import (CaseRecord, CaseVersionRow, RecordsMark, SystemRecord, SystemVersionRow, TenantRecords,
                                     adapter_column)

#: The injected judgement: every reason the after-state is unusable, given the state a write replaces (None for the import).
Judge = Callable[[TenantRecords, TenantRecords | None], Sequence[str]]


class RecordRefused(Exception):
    """A write the store refuses. `faults` is every reason, each a sentence naming the system and key (never a file)."""

    def __init__(self, faults: Sequence[str]) -> None:
        self.faults = list(faults)
        super().__init__("; ".join(self.faults))


_SV: Table = SystemVersionRow.__table__  # type: ignore[assignment]
_CV: Table = CaseVersionRow.__table__  # type: ignore[assignment]
_RM: Table = RecordsMark.__table__  # type: ignore[assignment]
_TENANTS = "tenancy.tenants"


class _Latest(NamedTuple):
    """A system's newest version row (deleted or not) and the highest credential generation any of its versions had."""

    row: Any
    top_generation: int


def _version_of(last: _Latest | None) -> int:
    """The system's current version number; 0 before its first."""
    return 0 if last is None else last.row.version


class RecordStore:
    def __init__(self, dsn: str, *, clock: Callable[[], _dt.datetime], judge: Judge) -> None:
        self._engine = async_engine(dsn, max_connections=4)
        self._clock = clock
        self._judge = judge

    async def close(self) -> None:
        await self._engine.dispose()

    @asynccontextmanager
    async def _locked(self, tenant: TenantId) -> AsyncIterator[AsyncConnection]:
        """A transaction holding the tenant's row: another writer for the same tenant waits for it."""
        from sqlalchemy import text
        async with self._engine.begin() as conn:
            found = (await conn.execute(text(f"SELECT id FROM {_TENANTS} WHERE id = :t FOR UPDATE"), {"t": tenant})).first()
            if found is None:
                raise RecordRefused([f"tenant {tenant} does not exist"])
            yield conn

    # --- reads under the lock -------------------------------------------------------------------------------------

    async def _latest(self, conn: AsyncConnection, tenant: TenantId) -> dict[str, _Latest]:
        """Each system's newest version, a deleted one included, with the highest credential generation it ever had:
        all a write needs of its history, read without the versions before."""
        top = func.max(_SV.c.credential_generation).over(partition_by=_SV.c.system_id).label("top_generation")
        rows = (await conn.execute(select(_SV, top).where(_SV.c.tenant_id == tenant).distinct(_SV.c.system_id)
                                   .order_by(_SV.c.system_id, _SV.c.version.desc()))).all()
        return {row.system_id: _Latest(row, row.top_generation) for row in rows}

    async def _latest_case(self, conn: AsyncConnection, tenant: TenantId) -> Any:
        """The case record's newest version, a deleted one included; None before the first."""
        return (await conn.execute(select(_CV).where(_CV.c.tenant_id == tenant).order_by(_CV.c.version.desc())
                                   .limit(1))).first()

    async def _marked(self, conn: AsyncConnection, tenant: TenantId) -> bool:
        return (await conn.execute(select(_RM.c.tenant_id).where(_RM.c.tenant_id == tenant))).first() is not None

    async def _require_marked(self, conn: AsyncConnection, tenant: TenantId) -> None:
        """R8: a write to a tenant whose import has not run is refused, naming the import."""
        if not await self._marked(conn, tenant):
            raise RecordRefused([not_imported_text(tenant)])

    @staticmethod
    def _current(latest: Mapping[str, _Latest]) -> dict[str, SystemRecord]:
        return {s: SystemVersionRow(**{c.name: getattr(last.row, c.name) for c in _SV.c}).as_record()
                for s, last in latest.items() if not last.row.deleted}

    @staticmethod
    def _current_case(row: Any) -> CaseRecord | None:
        if row is None or row.deleted:
            return None
        return CaseRecord(version=row.version, system_id=row.system_id, comment_body=row.comment_body)

    def _refuse_if_faulty(self, after: TenantRecords, before: TenantRecords | None = None) -> None:
        """The judge sees the after-state and, for a write (not the import), the state it replaces: it judges what the
        write changes and names the part whose change broke cover (C4)."""
        faults = self._judge(after, before)
        if faults:
            raise RecordRefused(faults)

    # --- generation -------------------------------------------------------------------------------------------------

    @staticmethod
    def _generation(system: str, last: _Latest | None, access: str) -> int:
        """P5, R4, K4: the first version is 1; a re-create after a delete is the highest ever + 1; otherwise the current
        generation, one higher when the base, the CA or the auth block differs, compared as parsed values. Unchanged
        access text keeps the generation without a parse; an access, old or new, that does not parse cannot be shown to
        name the same upstream, so it takes a new generation (a new access that does not parse is the judge's
        refusal besides)."""
        if last is None:
            return 1
        top = last.top_generation
        if last.row.deleted:
            return top + 1
        if last.row.access == access:
            return top
        try:
            was, now = parse_access(last.row.access, system=system), parse_access(access, system=system)
        except ConfigFault:
            return top + 1
        return top if (was.base, was.ca, was.auth) == (now.base, now.ca, now.auth) else top + 1

    # --- writes -----------------------------------------------------------------------------------------------------

    async def put_system(self, tenant: TenantId, system: str, *, replaces: int, adapter: str | tuple[str, str],
                         enabled: bool, settings: Mapping[str, str], access: str, author: str) -> SystemRecord:
        async with self._locked(tenant) as conn:
            await self._require_marked(conn, tenant)
            latest = await self._latest(conn, tenant)
            last = latest.get(system)
            self._check_replaces(system, last, replaces)
            custom = adapter if isinstance(adapter, tuple) else None
            generation = self._generation(system, last, access)
            candidate = SystemRecord(system_id=system, version=_version_of(last) + 1, adapter_id="" if custom else str(adapter),
                                     enabled=enabled, settings=dict(settings), access=access, custom_ref=custom,
                                     credential_generation=generation)
            after = self._current(latest) | {system: candidate}
            case = self._current_case(await self._latest_case(conn, tenant))
            self._refuse_if_faulty(TenantRecords(imported=True, systems=after, case=case),
                                   TenantRecords(imported=True, systems=self._current(latest), case=case))
            await conn.execute(insert(_SV).values(
                tenant_id=tenant, system_id=system, version=candidate.version, adapter_id=adapter_column(candidate),
                enabled=enabled, settings=dict(settings), access=access, credential_generation=generation, deleted=False,
                author=author, written_at=self._clock()))
            return candidate

    @staticmethod
    def _check_replaces(system: str, last: _Latest | None, replaces: int) -> None:
        current = _version_of(last)
        if replaces != current:
            raise RecordRefused([f"system {system}: the write replaces version {replaces}, but the current version is "
                                 f"{current}"])

    async def delete_system(self, tenant: TenantId, system: str, *, replaces: int, author: str) -> None:
        async with self._locked(tenant) as conn:
            await self._require_marked(conn, tenant)
            latest = await self._latest(conn, tenant)
            found = latest.get(system)
            self._check_replaces(system, found, replaces)
            if found is None or found.row.deleted:
                raise RecordRefused([f"system {system} has no current record to delete"])
            last = found.row
            after = {k: v for k, v in self._current(latest).items() if k != system}
            case = self._current_case(await self._latest_case(conn, tenant))
            self._refuse_if_faulty(TenantRecords(imported=True, systems=after, case=case),
                                   TenantRecords(imported=True, systems=self._current(latest), case=case))
            await conn.execute(insert(_SV).values(
                tenant_id=tenant, system_id=system, version=last.version + 1, adapter_id=last.adapter_id,
                enabled=last.enabled, settings=last.settings, access=last.access,
                credential_generation=last.credential_generation, deleted=True, author=author, written_at=self._clock()))

    async def put_case(self, tenant: TenantId, *, replaces: int, system_id: str, comment_body: str, author: str) -> CaseRecord:
        async with self._locked(tenant) as conn:
            await self._require_marked(conn, tenant)
            last = await self._latest_case(conn, tenant)
            current = last.version if last is not None else 0
            if replaces != current:
                raise RecordRefused([f"case record: the write replaces version {replaces}, but the current version is {current}"])
            case = CaseRecord(version=current + 1, system_id=system_id, comment_body=comment_body)
            systems = self._current(await self._latest(conn, tenant))
            self._refuse_if_faulty(TenantRecords(imported=True, systems=systems, case=case),
                                   TenantRecords(imported=True, systems=systems, case=self._current_case(last)))
            await conn.execute(insert(_CV).values(tenant_id=tenant, version=case.version, system_id=system_id,
                                                  comment_body=comment_body, deleted=False, author=author,
                                                  written_at=self._clock()))
            return case

    async def delete_case(self, tenant: TenantId, *, replaces: int, author: str) -> None:
        async with self._locked(tenant) as conn:
            await self._require_marked(conn, tenant)
            last = await self._latest_case(conn, tenant)
            current = last.version if last is not None else 0
            if replaces != current:
                raise RecordRefused([f"case record: the write replaces version {replaces}, but the current version is {current}"])
            if last is None or last.deleted:
                raise RecordRefused(["the tenant has no case record to delete"])
            await conn.execute(insert(_CV).values(tenant_id=tenant, version=current + 1, system_id=last.system_id,
                                                  comment_body=last.comment_body, deleted=True, author=author,
                                                  written_at=self._clock()))

    async def import_tenant(self, tenant: TenantId, records: TenantRecords, *, author: str) -> None:
        """O9: every system as version 1 at generation 1, the case record, and the mark: one transaction, judged whole."""
        async with self._locked(tenant) as conn:
            if await self._marked(conn, tenant):
                raise RecordRefused([f"tenant {tenant} is already imported; nothing was written"])
            stored = {s: SystemRecord(**{**r.__dict__, "version": 1, "credential_generation": 1})
                      for s, r in records.systems.items()}
            case = None if records.case is None else CaseRecord(**{**records.case.__dict__, "version": 1})
            self._refuse_if_faulty(TenantRecords(imported=True, systems=stored, case=case))
            now = self._clock()
            for s, r in stored.items():
                await conn.execute(insert(_SV).values(
                    tenant_id=tenant, system_id=s, version=1, adapter_id=adapter_column(r), enabled=r.enabled,
                    settings=dict(r.settings), access=r.access, credential_generation=1, deleted=False, author=author,
                    written_at=now))
            if case is not None:
                await conn.execute(insert(_CV).values(tenant_id=tenant, version=1, system_id=case.system_id,
                                                      comment_body=case.comment_body, deleted=False, author=author,
                                                      written_at=now))
            await conn.execute(insert(_RM).values(tenant_id=tenant))


def open_store(dsn: str, *, clock: Callable[[], _dt.datetime]) -> RecordStore:  # lint-dup: ok — the system-records store with its judgement (#1366 W); session_store.open_store opens one case's session store, an unrelated record
    """The store with the real judgement injected (the operator command's)."""
    from defender.systems.record_judgement import judge_records
    return RecordStore(dsn, clock=clock, judge=judge_records)
