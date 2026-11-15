"""The API's configuration ports over the record store and the secret store (#1470): the catalog, the systems, the
case record and the credentials.

Every write goes through the record store, which judges it with the judgement run start and `tenant check` use (P1);
reads are the record store's too, so a read and a write refuse a tenant that is not active alike (r8 Am-3). Nothing here re-decides a rule owned below it (P6): versions, generations,
tombstones and tenant state are the store's, what a record must say is the judgement's, what a credential set holds is
`kit.access`'s credential schema. Their typed refusals pass through as they are; the app maps each to a status. The
secret store is the write-only OpenBao writer: whether a set exists at a generation, and the write of one. It states
each failure's outcome (stored or not, r8 Am-1); here it is only answered. A system save asks it nothing (r8 Am-2).

Each write announces its audit event after the store commits (#1083 P2). An announcement that fails answers 500 and the
write stands."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol

from defender.jobs.audit import AuditAction, announce
from defender.credential_proxy import SecretStoreFault
from defender.credential_proxy import SecretStoreRefused as _Refused
from defender.kit.access import check_credentials
from defender.records.formats import TenantId
from defender.system_records import NoCurrentRecord, RecordRefused, RecordStore, Stale
from defender.system_rules import Catalog
from defender.tenancy.record_values import SystemRecord

from .models import CaseRecord, CaseRecordPut, CatalogAdapter, SavedSystem, System, SystemPut
from .ports import CredentialsUnused, Principal, SecretStoreRefused, SecretStoreUnavailable

#: The audit marker of a credential set stored for a generation no current version uses (O9).
STORED_UNUSED = "stored for an unused generation"
#: The audit marker of a credential write whose outcome is unknown (O9).
POSSIBLY_STORED = "possibly stored"


class SecretWriter(Protocol):
    """What the API asks of the secret store (`credential_proxy.OpenBaoSecrets`, the write-only role): nothing here can
    read a value back."""

    async def put_credentials(self, tenant_id: str, system_id: str, kind: str, credentials: Mapping[str, str], *,
                              generation: int) -> None: ...

    async def has_credentials(self, tenant_id: str, system_id: str, *, generation: int) -> bool: ...


def _announce(principal: Principal, action: AuditAction, target: str, detail: str | None = None) -> None:
    announce(action, actor=principal.actor_id, tenant_id=principal.tenant_id, target=target, detail=detail,
             credential_id=principal.credential_id)


async def has_credentials(secrets: SecretWriter, tenant_id: TenantId, record: SystemRecord) -> bool:
    """Whether a set exists at `record`'s generation: the secret store's answer, or its failure as the API answers it."""
    try:
        return await secrets.has_credentials(tenant_id, record.system_id, generation=record.credential_generation)
    except _Refused as fault:
        raise SecretStoreRefused(f"the secret store refused {_whose(fault)} when asked whether {record.system_id} has "
                                 f"credentials: {fault}") from None
    except SecretStoreFault as fault:
        raise SecretStoreUnavailable(f"the secret store cannot say whether {record.system_id} has credentials: "
                                     f"{fault}") from None


def _whose(fault: _Refused) -> str:
    """What OpenBao refused: the API's token (403), or the request itself (any other 4xx: our request or the mount's
    setup). Both are ours to fix, not the caller's."""
    return "the API's login" if fault.login_refused else "the API's request"


class ConfigRecords:
    """`SystemsRepository` over the record store (reads and writes), the catalog built at start and the secret store
    (`has_credentials`, asked by reads only)."""

    def __init__(self, store: RecordStore, catalog: Catalog, secrets: SecretWriter) -> None:
        self._store, self._catalog, self._secrets = store, catalog, secrets

    # --- reads --------------------------------------------------------------------------------------------------

    async def list_adapters(self) -> list[CatalogAdapter]:
        return [CatalogAdapter(adapter_id=e.adapter_id, display_name=e.display_name, settings_keys=list(e.stored_keys),
                               sample_settings=None if e.sample_settings is None else dict(e.sample_settings), lab_example=e.example)
                for e in self._catalog.entries()]

    async def list_systems(self, tenant_id: TenantId, *, after: str | None, limit: int) -> list[SystemRecord]:
        current = (await self._store.current(tenant_id)).systems
        return [current[s] for s in sorted(current) if after is None or s > after][:limit]

    async def get_system(self, tenant_id: TenantId, system_id: str) -> SystemRecord | None:
        return (await self._store.current(tenant_id)).systems.get(system_id)

    async def served(self, tenant_id: TenantId, record: SystemRecord) -> System:
        return self._system(record, has=await has_credentials(self._secrets, tenant_id, record))

    def _system(self, record: SystemRecord, *, has: bool) -> System:
        return System(**self._saved(record).model_dump(), has_credentials=has)

    def _saved(self, record: SystemRecord) -> SavedSystem:
        named = record.custom_ref is None and record.adapter_id in self._catalog
        return SavedSystem(system_id=record.system_id, version=record.version,
                           display_name=self._catalog.entry(record.adapter_id).display_name if named else None,
                           enabled=record.enabled, settings=dict(record.settings), access=record.access)

    async def get_case_record(self, tenant_id: TenantId) -> CaseRecord | None:
        case = (await self._store.current(tenant_id)).case
        return None if case is None else CaseRecord(version=case.version, system_id=case.system_id,
                                                    comment_body=case.comment_body)

    # --- writes -------------------------------------------------------------------------------------------------

    async def put_system(self, principal: Principal, system_id: str, body: SystemPut) -> tuple[SavedSystem, bool]:
        written = await self._store.put_system(
            principal.tenant_id, system_id, replaces=body.replaces, adapter=system_id, enabled=body.enabled,
            settings=dict(body.settings), access=body.access, author=principal.actor_id)
        _announce(principal, "system.update", system_id, f"version {written.record.version}")
        return self._saved(written.record), written.created

    async def delete_system(self, principal: Principal, system_id: str, *, replaces: int) -> None:
        await self._store.delete_system(principal.tenant_id, system_id, replaces=replaces, author=principal.actor_id)
        _announce(principal, "system.delete", system_id, f"replaced version {replaces}")

    async def put_case_record(self, principal: Principal, body: CaseRecordPut) -> tuple[CaseRecord, bool]:
        written = await self._store.put_case(principal.tenant_id, replaces=body.replaces, system_id=body.system_id,
                                             comment_body=body.comment_body, author=principal.actor_id)
        case = written.record
        _announce(principal, "case_record.update", principal.tenant_id, f"version {case.version}, system {case.system_id}")
        return CaseRecord(version=case.version, system_id=case.system_id, comment_body=case.comment_body), written.created

    async def delete_case_record(self, principal: Principal, *, replaces: int) -> None:
        await self._store.delete_case(principal.tenant_id, replaces=replaces, author=principal.actor_id)
        _announce(principal, "case_record.delete", principal.tenant_id, f"replaced version {replaces}")


class ConfigCredentials:
    """`SecretStore` over the record store's credential slot (P3), the credential schema and the write-only secret
    writer. It only sequences (Flows, "Set credentials"): slot, schema, write at the slot's generation, slot again."""

    def __init__(self, store: RecordStore, secrets: SecretWriter) -> None:
        self._store, self._secrets = store, secrets

    async def put_credentials(self, principal: Principal, system_id: str, *, for_version: int,
                              credentials: dict[str, str]) -> None:
        tenant = principal.tenant_id
        slot = await self._store.credential_slot(tenant, system_id, for_version)
        check_credentials(slot.auth, credentials)
        fields = "fields: " + ", ".join(sorted(credentials))
        try:
            await self._secrets.put_credentials(tenant, system_id, slot.auth.kind, credentials,
                                                generation=slot.generation)
        except _Refused as fault:
            raise SecretStoreRefused(f"the secret store refused {_whose(fault)}; the credentials of {system_id} were "
                                     f"not stored: {fault}") from None
        except SecretStoreFault as fault:
            if fault.stored is False:
                raise SecretStoreUnavailable(f"the secret store did not take the credentials of {system_id}; they were "
                                             f"not stored: {fault}") from None
            _announce(principal, "system.credentials", system_id, f"{fields}; {POSSIBLY_STORED}")
            raise SecretStoreUnavailable(f"the secret store failed during the write of {system_id}'s credentials; they "
                                         f"are {POSSIBLY_STORED}: {fault}") from None
        # The record read again: the set's generation must still be the current version's (P3, the store's slot). Only
        # a moved generation or a deleted system shows the set unused (O7); any other refusal (the tenant, or an access
        # that no longer parses) does not, so the set is announced as stored and the refusal answered as itself (r8 Am-3).
        try:
            await self._store.credential_slot(tenant, system_id, for_version)
        except (Stale, NoCurrentRecord) as refusal:
            _announce(principal, "system.credentials", system_id, f"{fields}; {STORED_UNUSED}")
            shown = refusal.current_version if isinstance(refusal, Stale) else 0
            raise CredentialsUnused(f"the credentials of {system_id} are {STORED_UNUSED}: the record changed during "
                                    f"the write ({refusal})", current_version=shown) from None
        except RecordRefused as refusal:
            _announce(principal, "system.credentials", system_id, fields)
            refusal.add_note(f"the credentials of {system_id} were stored before this refusal")
            raise
        except Exception as failed:  # noqa: BLE001 — any failure of the re-read leaves the outcome unknown (O7)
            _announce(principal, "system.credentials", system_id, f"{fields}; {POSSIBLY_STORED}")
            raise SecretStoreUnavailable(f"the credentials of {system_id} are {POSSIBLY_STORED}: the record could not "
                                         f"be read again after the write ({type(failed).__name__})") from failed
        _announce(principal, "system.credentials", system_id, fields)
