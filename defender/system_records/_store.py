"""The record store: one transaction per write, taken under the tenant's row lock so one tenant's writes are serialized
across the system and case tables (O5). The judgement (all of O4 but version, staleness, lock and generation) is injected
and sees the tenant's whole after-state, read under the lock."""

from __future__ import annotations

import datetime as _dt
from collections.abc import Callable, Mapping, Sequence
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator

from sqlalchemy import insert, select
from sqlalchemy.ext.asyncio import AsyncConnection

from defender.database import async_engine
from defender.records.formats import TenantId
from defender.tenancy import parse_access
from defender.tenancy.models import (CaseRecord, CaseVersionRow, RecordsMark, SystemRecord, SystemVersionRow, TenantRecords,
                                     adapter_column)

#: What a record store reports as the writer of a version when a caller names none.
Judge = Callable[[TenantRecords], Sequence[str]]


class RecordRefused(Exception):
    """A write the store refuses. `faults` is every reason, each a sentence naming the system and key (never a file)."""

    def __init__(self, faults: Sequence[str]) -> None:
        self.faults = list(faults)
        super().__init__("; ".join(self.faults))


_SV, _CV, _RM = SystemVersionRow.__table__, CaseVersionRow.__table__, RecordsMark.__table__
_TENANTS = "tenancy.tenants"


def _takes_before(judge: Judge) -> bool:
    """Whether `judge` accepts the replaced state as a second argument (the real judgement does; a stand-in judging the
    after-state alone does not, and is called with that alone)."""
    import inspect
    try:
        params = list(inspect.signature(judge).parameters.values())
    except (TypeError, ValueError):
        return False
    positional = [p for p in params if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)]
    return len(positional) >= 2 or any(p.kind == p.VAR_POSITIONAL for p in params)


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

    async def _history(self, conn: AsyncConnection, tenant: TenantId) -> dict[str, list[Any]]:
        rows = (await conn.execute(select(_SV).where(_SV.c.tenant_id == tenant).order_by(_SV.c.system_id, _SV.c.version))).all()
        out: dict[str, list[Any]] = {}
        for row in rows:
            out.setdefault(row.system_id, []).append(row)
        return out

    async def _case_history(self, conn: AsyncConnection, tenant: TenantId) -> list[Any]:
        return list((await conn.execute(select(_CV).where(_CV.c.tenant_id == tenant).order_by(_CV.c.version))).all())

    async def _marked(self, conn: AsyncConnection, tenant: TenantId) -> bool:
        return (await conn.execute(select(_RM.c.tenant_id).where(_RM.c.tenant_id == tenant))).first() is not None

    @staticmethod
    def _current(history: Mapping[str, list[Any]]) -> dict[str, SystemRecord]:
        return {s: SystemVersionRow(**rows[-1]._mapping).as_record() for s, rows in history.items() if not rows[-1].deleted}

    @staticmethod
    def _current_case(history: list[Any]) -> CaseRecord | None:
        if not history or history[-1].deleted:
            return None
        row = history[-1]
        return CaseRecord(version=row.version, system_id=row.system_id, comment_body=row.comment_body)

    def _refuse_if_faulty(self, after: TenantRecords, before: TenantRecords | None = None) -> None:
        """The judge sees the after-state and, for a write (not the import), the state it replaces: it judges what the
        write changes and names the part whose change broke cover (C4)."""
        faults = self._judge(after, before) if before is not None and _takes_before(self._judge) else self._judge(after)
        if faults:
            raise RecordRefused(faults)

    # --- generation -------------------------------------------------------------------------------------------------

    @staticmethod
    def _generation(system: str, rows: list[Any], access: str) -> int:
        """P5, R4, K4: the first version is 1; a re-create after a delete is the highest ever + 1; otherwise the current
        generation, one higher when the base, the CA or the auth block differs, compared as parsed values."""
        if not rows:
            return 1
        top = max(r.credential_generation for r in rows)
        if rows[-1].deleted:
            return top + 1
        was, now = parse_access(rows[-1].access, system=system), parse_access(access, system=system)
        return top if (was.base, was.ca, was.auth) == (now.base, now.ca, now.auth) else top + 1

    # --- writes -----------------------------------------------------------------------------------------------------

    async def put_system(self, tenant: TenantId, system: str, *, replaces: int, adapter: str | tuple[str, str],
                         enabled: bool, settings: Mapping[str, str], access: str, author: str) -> SystemRecord:
        async with self._locked(tenant) as conn:
            if not await self._marked(conn, tenant):
                raise RecordRefused([f"tenant {tenant} has not been imported: run `tenant.py import` first"])
            history = await self._history(conn, tenant)
            rows = history.get(system, [])
            self._check_replaces(system, rows, replaces)
            custom = adapter if isinstance(adapter, tuple) else None
            candidate = SystemRecord(system_id=system, version=len(rows) + 1, adapter_id="" if custom else str(adapter),
                                     enabled=enabled, settings=dict(settings), access=access, custom_ref=custom,
                                     credential_generation=0)
            # The judge needs the generation only to compare; access that does not parse is the judge's refusal.
            try:
                generation = self._generation(system, rows, access)
            except Exception:
                generation = rows[-1].credential_generation if rows else 1
            candidate = SystemRecord(**{**candidate.__dict__, "credential_generation": generation})
            after = self._current(history) | {system: candidate}
            case = self._current_case(await self._case_history(conn, tenant))
            self._refuse_if_faulty(TenantRecords(imported=True, systems=after, case=case),
                                   TenantRecords(imported=True, systems=self._current(history), case=case))
            await conn.execute(insert(_SV).values(
                tenant_id=tenant, system_id=system, version=candidate.version, adapter_id=adapter_column(candidate),
                enabled=enabled, settings=dict(settings), access=access, credential_generation=generation, deleted=False,
                author=author, written_at=self._clock()))
            return candidate

    @staticmethod
    def _check_replaces(system: str, rows: list[Any], replaces: int) -> None:
        current = rows[-1].version if rows else 0
        if replaces != current:
            raise RecordRefused([f"system {system}: the write replaces version {replaces}, but the current version is "
                                 f"{current}"])

    async def delete_system(self, tenant: TenantId, system: str, *, replaces: int, author: str) -> None:
        async with self._locked(tenant) as conn:
            if not await self._marked(conn, tenant):
                raise RecordRefused([f"tenant {tenant} has not been imported: run `tenant.py import` first"])
            history = await self._history(conn, tenant)
            rows = history.get(system, [])
            self._check_replaces(system, rows, replaces)
            if not rows or rows[-1].deleted:
                raise RecordRefused([f"system {system} has no current record to delete"])
            last = rows[-1]
            after = {k: v for k, v in self._current(history).items() if k != system}
            case = self._current_case(await self._case_history(conn, tenant))
            self._refuse_if_faulty(TenantRecords(imported=True, systems=after, case=case),
                                   TenantRecords(imported=True, systems=self._current(history), case=case))
            await conn.execute(insert(_SV).values(
                tenant_id=tenant, system_id=system, version=last.version + 1, adapter_id=last.adapter_id,
                enabled=last.enabled, settings=last.settings, access=last.access,
                credential_generation=last.credential_generation, deleted=True, author=author, written_at=self._clock()))

    async def put_case(self, tenant: TenantId, *, replaces: int, system_id: str, comment_body: str, author: str) -> CaseRecord:
        async with self._locked(tenant) as conn:
            if not await self._marked(conn, tenant):
                raise RecordRefused([f"tenant {tenant} has not been imported: run `tenant.py import` first"])
            history = await self._case_history(conn, tenant)
            current = history[-1].version if history else 0
            if replaces != current:
                raise RecordRefused([f"case record: the write replaces version {replaces}, but the current version is {current}"])
            case = CaseRecord(version=current + 1, system_id=system_id, comment_body=comment_body)
            systems = self._current(await self._history(conn, tenant))
            self._refuse_if_faulty(TenantRecords(imported=True, systems=systems, case=case),
                                   TenantRecords(imported=True, systems=systems, case=self._current_case(history)))
            await conn.execute(insert(_CV).values(tenant_id=tenant, version=case.version, system_id=system_id,
                                                  comment_body=comment_body, deleted=False, author=author,
                                                  written_at=self._clock()))
            return case

    async def delete_case(self, tenant: TenantId, *, replaces: int, author: str) -> None:
        async with self._locked(tenant) as conn:
            if not await self._marked(conn, tenant):
                raise RecordRefused([f"tenant {tenant} has not been imported: run `tenant.py import` first"])
            history = await self._case_history(conn, tenant)
            current = history[-1].version if history else 0
            if replaces != current:
                raise RecordRefused([f"case record: the write replaces version {replaces}, but the current version is {current}"])
            if not history or history[-1].deleted:
                raise RecordRefused(["the tenant has no case record to delete"])
            last = history[-1]
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


def open_store(dsn: str, *, clock: Callable[[], _dt.datetime]) -> RecordStore:
    """The store with the real judgement injected (the operator command's)."""
    from defender.systems.record_judgement import judge_records
    return RecordStore(dsn, clock=clock, judge=judge_records)
