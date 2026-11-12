"""A tenant's system and case records as plain values (#1366): what a version of each says, and what the tenant's records
say now. Kept apart from the tables (`tenancy.models`) so that a reader of records (run start, a job container handed
them by its helper) needs no database library."""
from __future__ import annotations

import dataclasses
from collections.abc import Mapping
from typing import Any


@dataclasses.dataclass(frozen=True, kw_only=True)
class SystemRecord:
    """One tenant system as a version of it stands: the adapter it names (a catalog id, or, until #1172 allows it,
    `custom_ref=(path, revision)` with an empty `adapter_id`), its prefixed settings, its access declaration's text and the
    credential generation its version carries."""

    system_id: str
    version: int
    adapter_id: str = ""
    enabled: bool = True
    settings: Mapping[str, str] = dataclasses.field(default_factory=dict)
    access: str = ""
    credential_generation: int = 1
    custom_ref: tuple[str, str] | None = None


@dataclasses.dataclass(frozen=True, kw_only=True)
class CaseRecord:
    """The tenant's case write-back record as a version of it stands."""

    version: int
    system_id: str
    comment_body: str


@dataclasses.dataclass(frozen=True, kw_only=True)
class TenantRecords:
    """What the tenant's records say now: whether its systems come from records at all (the mark), its current systems
    (a deleted one is absent, a disabled one present) and its current case record."""

    imported: bool = False
    systems: Mapping[str, SystemRecord] = dataclasses.field(default_factory=dict)
    case: CaseRecord | None = None

    def as_wire(self) -> dict[str, Any]:
        """These records as plain JSON data: how a job's host helper, which read them, hands them to its job container,
        which reads no database (#1170 A6, #1366 O6). `from_wire` reads it back."""
        return {
            "imported": self.imported,
            "systems": {sid: {"version": r.version, "adapter_id": r.adapter_id, "enabled": r.enabled,
                              "settings": dict(r.settings), "access": r.access,
                              "credential_generation": r.credential_generation,
                              "custom_ref": None if r.custom_ref is None else list(r.custom_ref)}
                        for sid, r in sorted(self.systems.items())},
            "case": None if self.case is None else {"version": self.case.version, "system_id": self.case.system_id,
                                                    "comment_body": self.case.comment_body},
        }

    @classmethod
    def handed(cls, launch: Mapping[str, Any]) -> TenantRecords:
        """Inside a job container (#1170 A6, #1366 O6): the records the job's host helper read at setup and handed over
        in the launch facts (`records`), or `ValueError` saying why they are not usable. The container reads no
        database."""
        try:
            return cls.from_wire(launch.get("records"))
        except ValueError as bad:
            raise ValueError(f"the job's host helper handed no usable tenant records: {bad}") from None

    @classmethod
    def from_wire(cls, wire: object) -> TenantRecords:
        """The records `as_wire` wrote, or `ValueError` naming the first field that is not as it wrote it."""
        def field(obj: object, key: str, kind: type | tuple[type, ...], where: str) -> Any:
            if not isinstance(obj, dict) or key not in obj:
                raise ValueError(f"{where}: no {key!r}")
            value = obj[key]
            if not isinstance(value, kind) or (kind is int and isinstance(value, bool)):
                raise ValueError(f"{where}: {key!r} is not {getattr(kind, '__name__', kind)}")
            return value

        systems: dict[str, SystemRecord] = {}
        for sid, r in field(wire, "systems", dict, "records").items():
            where = f"records: system {sid!r}"
            settings = field(r, "settings", dict, where)
            if not all(isinstance(k, str) and isinstance(v, str) for k, v in settings.items()):
                raise ValueError(f"{where}: 'settings' is not text to text")
            ref = field(r, "custom_ref", (list, type(None)), where)
            if ref is not None and (len(ref) != 2 or not all(isinstance(x, str) for x in ref)):  # noqa: PLR2004 — (path, revision)
                raise ValueError(f"{where}: 'custom_ref' is not [path, revision]")
            systems[str(sid)] = SystemRecord(
                system_id=str(sid), version=field(r, "version", int, where),
                adapter_id=field(r, "adapter_id", str, where), enabled=field(r, "enabled", bool, where),
                settings=dict(settings), access=field(r, "access", str, where),
                credential_generation=field(r, "credential_generation", int, where),
                custom_ref=None if ref is None else (ref[0], ref[1]))
        case_wire = field(wire, "case", (dict, type(None)), "records")
        case = None if case_wire is None else CaseRecord(
            version=field(case_wire, "version", int, "records: case"),
            system_id=field(case_wire, "system_id", str, "records: case"),
            comment_body=field(case_wire, "comment_body", str, "records: case"))
        return cls(imported=field(wire, "imported", bool, "records"), systems=systems, case=case)


__all__ = ["CaseRecord", "SystemRecord", "TenantRecords"]
