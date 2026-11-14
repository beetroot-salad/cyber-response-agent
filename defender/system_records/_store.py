"""The record store: one transaction per write, taken under the tenant's row lock so one tenant's writes are serialized
across the system and case tables (#1366 O5). The judgement (all of #1366 O4 but version, staleness, lock and generation)
is injected and sees the tenant's whole after-state, read under the lock.

A record write names the version it replaces (#1470 P2): the version a read shows, 0 when a read shows none (never
written, or its newest version is a tombstone). Version numbers keep rising across a delete, so the store keeps two
facts apart: the shown version and the next version (the newest + 1). A delete of what has no current record is
`NoCurrentRecord` before any version comparison. Only an `active` tenant is written (#1470 O8: a tenant's records are
known exactly while it is active). Every refusal is a `RecordRefused` of one of five types, which the API maps to a
status by type alone."""

from __future__ import annotations

import dataclasses
import datetime as _dt
from collections.abc import AsyncIterator, Callable, Mapping, Sequence
from contextlib import asynccontextmanager
from typing import Any, NamedTuple

from sqlalchemy import Table, func, insert, select, text
from sqlalchemy.ext.asyncio import AsyncConnection

from defender.database import async_engine
from defender.kit.access import Auth
from defender.kit.faults import ConfigFault
from defender.records.formats import TenantId
from defender.system_rules import located_access
from defender.tenancy import parse_access
from defender.tenancy.models import CaseRecord, CaseVersionRow, SystemRecord, SystemVersionRow, TenantRecords, adapter_column

#: The injected judgement: every reason the after-state is unusable, given the state the write replaces.
Judge = Callable[[TenantRecords, TenantRecords], Sequence[str]]

ACTIVE = "active"


class RecordRefused(Exception):
    """A write (or a credential slot) the store refuses. `faults` is every reason, each a sentence naming the system and
    the key or part (never a file). Raised only as one of its five subclasses."""

    def __init__(self, faults: Sequence[str]) -> None:
        self.faults = list(faults)
        super().__init__("; ".join(self.faults))


class Stale(RecordRefused):
    """The write names a version other than the one a read now shows (`current_version`, 0 when a read shows none); or a
    credential slot asked for a version whose generation is not the current version's."""

    def __init__(self, what: str, *, current_version: int, named: int) -> None:
        self.current_version = current_version
        shown = f"version {current_version}" if current_version else "no current version"
        super().__init__([f"{what}: the write names version {named}, but a read now shows {shown}"])


class Judged(RecordRefused):
    """The judgement found the after-state unusable: `faults` are all its reasons, as it worded them."""


class NoSuchTenant(RecordRefused):
    """No tenant row has this id."""

    def __init__(self, tenant: object) -> None:
        super().__init__([f"tenant {tenant} does not exist"])


class TenantNotActive(RecordRefused):
    """The tenant exists but is not `active` (creating, offboarding, offboarded): its records take no write."""

    def __init__(self, tenant: object, state: str) -> None:
        self.state = state
        super().__init__([f"tenant {tenant} is {state}, not active: its records take no write"])


class NoCurrentRecord(RecordRefused):
    """The write needs a current record (a delete, a credential slot) and there is none: never written, or deleted."""

    def __init__(self, what: str) -> None:
        super().__init__([f"{what} has no current record"])


@dataclasses.dataclass(frozen=True)
class SystemWrite:
    """What `put_system` stored: the new version, whether a read showed no record before it (`created`: a create or a
    re-create after a delete), and whether it raised the credential generation (`generation_raised`: a changed base,
    CA or auth block; never on a create, whose generation no earlier set can have)."""

    record: SystemRecord
    created: bool
    generation_raised: bool


@dataclasses.dataclass(frozen=True)
class CaseWrite:
    """What `put_case` stored: the new version and whether a read showed no case record before it."""

    record: CaseRecord
    created: bool


@dataclasses.dataclass(frozen=True)
class CredentialSlot:
    """Where a credential set for a system goes (#1470 P3): the current version's credential generation and the auth
    scheme its access declaration states (`Auth.kind` is the set's kind)."""

    generation: int
    auth: Auth


_SV: Table = SystemVersionRow.__table__  # type: ignore[assignment]
_CV: Table = CaseVersionRow.__table__  # type: ignore[assignment]
_TENANTS = "tenancy.tenants"


class _Latest(NamedTuple):
    """A system's newest version row (deleted or not) and the highest credential generation any of its versions had."""

    row: Any
    top_generation: int


def _shown(row: Any) -> int:
    """The version a read shows for a newest row: its number, 0 for a tombstone or none."""
    return 0 if row is None or row.deleted else row.version


def _next(row: Any) -> int:
    """The next version number: the newest row's + 1, whether it is a tombstone or not; 1 before the first."""
    return 1 if row is None else row.version + 1


def _refuse_unless_writable(found: Any, tenant: TenantId) -> None:
    if found is None:
        raise NoSuchTenant(tenant)
    if found.state != ACTIVE:
        raise TenantNotActive(tenant, found.state)


class RecordStore:
    def __init__(self, dsn: str, *, clock: Callable[[], _dt.datetime], judge: Judge) -> None:
        self._engine = async_engine(dsn, max_connections=4)
        self._clock = clock
        self._judge = judge

    async def close(self) -> None:
        await self._engine.dispose()

    @asynccontextmanager
    async def _locked(self, tenant: TenantId) -> AsyncIterator[AsyncConnection]:
        """A transaction holding the tenant's row, which must be `active`: another writer for the same tenant waits."""
        async with self._engine.begin() as conn:
            found = (await conn.execute(text(f"SELECT state FROM {_TENANTS} WHERE id = :t FOR UPDATE"),
                                        {"t": tenant})).first()
            _refuse_unless_writable(found, tenant)
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

    @staticmethod
    def _current(latest: Mapping[str, _Latest]) -> dict[str, SystemRecord]:
        return {s: SystemVersionRow(**{c.name: getattr(last.row, c.name) for c in _SV.c}).as_record()
                for s, last in latest.items() if not last.row.deleted}

    @staticmethod
    def _current_case(row: Any) -> CaseRecord | None:
        if row is None or row.deleted:
            return None
        return CaseRecord(version=row.version, system_id=row.system_id, comment_body=row.comment_body)

    def _refuse_if_faulty(self, after: TenantRecords, before: TenantRecords) -> None:
        """The judge sees the after-state and the state it replaces: it judges what the write changes and names the part
        whose change broke cover (#1366 C4)."""
        faults = list(self._judge(after, before))
        if faults:
            raise Judged(faults)

    # --- generation -------------------------------------------------------------------------------------------------

    @staticmethod
    def _generation(system: str, last: _Latest | None, access: str) -> int:
        """#1366 P5, R4, K4: the first version is 1; a re-create after a delete is the highest ever + 1; otherwise the
        current generation, one higher when the base, the CA or the auth block differs, compared as parsed values.
        Unchanged access text keeps the generation without a parse; an access, old or new, that does not parse cannot be
        shown to name the same upstream, so it takes a new generation (a new access that does not parse is the judge's
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
                         enabled: bool, settings: Mapping[str, str], access: str, author: str) -> SystemWrite:
        """`system`'s next version, replacing the version a read shows (`replaces`, 0 for none). `author` is the acting
        member's id."""
        async with self._locked(tenant) as conn:
            latest = await self._latest(conn, tenant)
            last = latest.get(system)
            row = None if last is None else last.row
            shown = _shown(row)
            if replaces != shown:
                raise Stale(f"system {system}", current_version=shown, named=replaces)
            custom = adapter if isinstance(adapter, tuple) else None
            generation = self._generation(system, last, access)
            candidate = SystemRecord(system_id=system, version=_next(row), adapter_id="" if custom else str(adapter),
                                     enabled=enabled, settings=dict(settings), access=access, custom_ref=custom,
                                     credential_generation=generation)
            before = self._current(latest)
            case = self._current_case(await self._latest_case(conn, tenant))
            self._refuse_if_faulty(TenantRecords(systems=before | {system: candidate}, case=case),
                                   TenantRecords(systems=before, case=case))
            await conn.execute(insert(_SV).values(
                tenant_id=tenant, system_id=system, version=candidate.version, adapter_id=adapter_column(candidate),
                enabled=enabled, settings=dict(settings), access=access, credential_generation=generation, deleted=False,
                author=author, written_at=self._clock()))
            created = row is None or row.deleted
            return SystemWrite(record=candidate, created=created,
                               generation_raised=row is not None and not created and generation != row.credential_generation)

    async def delete_system(self, tenant: TenantId, system: str, *, replaces: int, author: str) -> None:
        """A tombstone over `system`'s current record (`replaces` its version)."""
        async with self._locked(tenant) as conn:
            latest = await self._latest(conn, tenant)
            found = latest.get(system)
            row = None if found is None else found.row
            if row is None or row.deleted:
                raise NoCurrentRecord(f"system {system}")
            if replaces != row.version:
                raise Stale(f"system {system}", current_version=row.version, named=replaces)
            before = self._current(latest)
            case = self._current_case(await self._latest_case(conn, tenant))
            self._refuse_if_faulty(TenantRecords(systems={k: v for k, v in before.items() if k != system}, case=case),
                                   TenantRecords(systems=before, case=case))
            await conn.execute(insert(_SV).values(
                tenant_id=tenant, system_id=system, version=_next(row), adapter_id=row.adapter_id,
                enabled=row.enabled, settings=row.settings, access=row.access,
                credential_generation=row.credential_generation, deleted=True, author=author, written_at=self._clock()))

    async def put_case(self, tenant: TenantId, *, replaces: int, system_id: str, comment_body: str,
                       author: str) -> CaseWrite:
        """The case record's next version, replacing the version a read shows (`replaces`, 0 for none)."""
        async with self._locked(tenant) as conn:
            last = await self._latest_case(conn, tenant)
            shown = _shown(last)
            if replaces != shown:
                raise Stale("the case record", current_version=shown, named=replaces)
            case = CaseRecord(version=_next(last), system_id=system_id, comment_body=comment_body)
            systems = self._current(await self._latest(conn, tenant))
            self._refuse_if_faulty(TenantRecords(systems=systems, case=case),
                                   TenantRecords(systems=systems, case=self._current_case(last)))
            await conn.execute(insert(_CV).values(tenant_id=tenant, version=case.version, system_id=system_id,
                                                  comment_body=comment_body, deleted=False, author=author,
                                                  written_at=self._clock()))
            return CaseWrite(record=case, created=shown == 0)

    async def delete_case(self, tenant: TenantId, *, replaces: int, author: str) -> None:
        """A tombstone over the current case record (`replaces` its version)."""
        async with self._locked(tenant) as conn:
            last = await self._latest_case(conn, tenant)
            if last is None or last.deleted:
                raise NoCurrentRecord("the case record")
            if replaces != last.version:
                raise Stale("the case record", current_version=last.version, named=replaces)
            systems = self._current(await self._latest(conn, tenant))
            self._refuse_if_faulty(TenantRecords(systems=systems, case=None),
                                   TenantRecords(systems=systems, case=self._current_case(last)))
            await conn.execute(insert(_CV).values(tenant_id=tenant, version=_next(last), system_id=last.system_id,
                                                  comment_body=last.comment_body, deleted=True, author=author,
                                                  written_at=self._clock()))

    # --- the credential slot (#1470 P3) -----------------------------------------------------------------------------

    async def credential_slot(self, tenant: TenantId, system: str, for_version: int) -> CredentialSlot:
        """Where a credential set prepared for `system`'s version `for_version` goes: the current version's generation
        and parsed auth scheme, accepted exactly when `for_version` is a version of this system whose generation is the
        current version's (a disabled current version counts). Version numbers are never compared. Refused as
        `NoSuchTenant`, `TenantNotActive`, `NoCurrentRecord` (never written, or deleted), `Stale` naming the current
        version (another generation, or no such version), or `Judged` when the stored access no longer parses."""
        async with self._engine.connect() as conn:
            conn = await conn.execution_options(isolation_level="REPEATABLE READ")
            async with conn.begin():
                found = (await conn.execute(text(f"SELECT state FROM {_TENANTS} WHERE id = :t"), {"t": tenant})).first()
                _refuse_unless_writable(found, tenant)
                newest = (await conn.execute(select(_SV).where(_SV.c.tenant_id == tenant, _SV.c.system_id == system)
                                             .order_by(_SV.c.version.desc()).limit(1))).first()
                if newest is None or newest.deleted:
                    raise NoCurrentRecord(f"system {system}")
                # A version outside 1..newest names no row; the column is a 32-bit integer, so a larger number is not asked.
                named = None if not 1 <= for_version <= newest.version else (await conn.execute(
                    select(_SV.c.credential_generation, _SV.c.deleted).where(
                        _SV.c.tenant_id == tenant, _SV.c.system_id == system, _SV.c.version == for_version))).first()
        if named is None or named.credential_generation != newest.credential_generation:
            raise Stale(f"system {system}", current_version=newest.version, named=for_version)
        try:
            declaration = located_access(newest.access, system=system)
        except ConfigFault as fault:
            raise Judged([str(fault)]) from None
        return CredentialSlot(generation=newest.credential_generation, auth=declaration.auth)


__all__ = ["CaseWrite", "CredentialSlot", "Judge", "Judged", "NoCurrentRecord", "NoSuchTenant", "RecordRefused",
           "RecordStore", "Stale", "SystemWrite", "TenantNotActive"]
