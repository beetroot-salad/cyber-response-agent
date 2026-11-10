"""The case system a tenant names (#1359): which adapter takes the host's comment, and whether
the tenant's records let it.

One judgement, every asker (D-17, #1366 C3): the record leg at run end (`case_verdict`, made at run
start) and `tenant check` both call `judge_case_system`, so the check cannot pass what the leg
would refuse. It reads the tenant's case record as the run read it at its start, the case
system among the tenant's systems (#1366 O1: its enabled records the catalog carries, never the
whole checkout), that system's settings judged by its adapter's own `check_settings` (through
`system_status.judge_adapter`, the run start's own rules, so a missing or crashing check is the
adapter's defect here as there), then the cover rule over its stored access declaration
(`record_judgement.case_cover_fault`, C2, the store's own rule). Every failure is a
`CaseSettingsFault` naming the record that is wrong (DC6: `the case record`, `system <s>
settings`, `system <s> access`), and nothing else escapes: every asker may call it unguarded.
"""
from __future__ import annotations

import dataclasses
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from defender.kit.faults import ConfigFault
from defender.kit.settings import RECORDS, pointer_to
from defender.kit.verbs import COMMENT_ACTION, HOST_ACTIONS, READBACK_ACTION, CaseComments
from defender.systems.run_tenant import RunTenant
from defender.systems.system_status import AdapterBroken, NotConfigured, ReasonScope, judge_adapter
from defender.systems.verbs import RegistryError, RosterRead, fresh_adapter_module
from defender.tenancy.case_ticket import (
    CASE_RECORD_REL, CaseRecordSettings, CaseTicketError)
from defender.tenancy.models import TenantRecords

#: The retired system folder a tenant may still hold; `tenant check` names the new file for it.
LEGACY_SYSTEM = "case-history"  # lint-shippable: ok — the retired system's folder name, named only to tell the operator to migrate

#: How a case-system fault names the tenant's case record (#1366 DC6: the record, not a file).
CASE_RECORD_POINTER = RECORDS.case()


class CaseSettingsFault(Exception):  # noqa: N818 — named for what it reports
    """The case system cannot take a comment because a settings file or its adapter is wrong.
    `str()` is the receipt reason: it opens with the pointer to the file at fault, never a host
    path. `adapter_refused` is set when the roster refused the adapter."""

    def __init__(self, file_pointer: str, reason: str, *, adapter_refused: bool = False) -> None:
        super().__init__(f"{file_pointer}: {reason}")
        self.file_pointer = file_pointer
        self.reason = reason
        self.adapter_refused = adapter_refused


@dataclasses.dataclass(frozen=True)
class CaseTarget:
    """A judged case system: its name, the tenant's comment template and the adapter module whose
    `add_case_comment` takes the comment."""

    system: str
    template: CaseRecordSettings
    module: Any

    @property
    def add_case_comment(self) -> Callable[..., str | None]:
        return getattr(self.module, COMMENT_ACTION)

    @property
    def read_case_comments(self) -> Callable[..., CaseComments] | None:
        """The adapter's optional read of a case's comments (#1374), or None when it has none."""
        action = getattr(self.module, READBACK_ACTION, None)
        return action if callable(action) else None


def legacy_folder_finding(settings: Path) -> str | None:
    """The finding for a tenant still holding the retired system folder for case recording, naming the
    file that replaces it; `None` when it holds none."""
    if (Path(settings) / "systems" / LEGACY_SYSTEM).exists():
        return (f"{pointer_to('systems/' + LEGACY_SYSTEM)} is retired: cases are recorded through "
                f"the system {CASE_RECORD_POINTER} names — move the comment body there and "
                "delete the folder")
    return None


def tenant_roster(record: Any, *, defender_dir: Path) -> RosterRead:
    """The tenant's systems (#1366 O1, DC7) for a caller that hands no roster: the record's
    current records (`RunTenant.records`; none on a record that carries none) over the catalog of
    `defender_dir`. Never the whole checkout. The catalog unreadable is the case record's
    `CaseSettingsFault`."""
    from defender.systems.catalog import Catalog, TenantSystems

    records = getattr(record, "records", None)
    try:
        catalog = Catalog.of_checkout(Path(defender_dir))
    except RegistryError as e:
        raise CaseSettingsFault(CASE_RECORD_POINTER,
                                f"cannot be judged: the adapters cannot be read ({e})") from None
    return TenantSystems.of(records if records is not None else TenantRecords(), catalog).roster


def _adapter_of(system: str, *, roster: RosterRead) -> Any:
    """`system`'s adapter module among the tenant's systems (`roster`, #1366 O1: never the whole
    checkout), read fresh, or the `CaseSettingsFault` naming the case record for why it cannot
    take a comment: not among the tenant's systems, a platform-served system (no adapter), an
    adapter the roster refused, one that will not load, or one without the comment action."""
    if system not in roster.adapter_files:
        if system in roster.verbs:  # a platform-served system: in every roster, with no adapter
            raise CaseSettingsFault(CASE_RECORD_POINTER,
                                    f"names the system `{system}`, which has no adapter")
        raise CaseSettingsFault(
            CASE_RECORD_POINTER,
            f"names the case system `{system}`, which is not among the tenant's systems (it has no "
            "enabled record whose adapter the catalog carries): a case system is one of them")
    if system in roster.unparsed:
        why = roster.unparsed[system]
        shown = why if any(a in why or a.replace("_", "-") in why for a in HOST_ACTIONS) \
            else "it could not be read"
        raise CaseSettingsFault(
            CASE_RECORD_POINTER,
            f"names the system `{system}`, whose adapter was refused: {shown}", adapter_refused=True)
    try:
        module = fresh_adapter_module(roster, system)
    except Exception as e:  # noqa: BLE001 — an adapter that will not import is not a usable case system
        raise CaseSettingsFault(
            CASE_RECORD_POINTER,
            f"names the system `{system}`, whose adapter could not be loaded ({type(e).__name__})",
        ) from None
    if not callable(getattr(module, COMMENT_ACTION, None)):
        raise CaseSettingsFault(
            CASE_RECORD_POINTER,
            f"names the system `{system}`, whose adapter has no `{COMMENT_ACTION}`: it cannot "
            "record a comment")
    return module


def judge_case_system(
    record: Any, *, defender_dir: Path, roster: RosterRead | None = None,
) -> CaseTarget:
    """The case system `record` names, ready to take a comment, or `CaseSettingsFault`.

    `record` is the run's tenant record (or `tenant check`'s, built from the same records): it
    carries `case_record`, `systems` and `access`, read once when the run began. `roster` is the
    tenant's systems (`tenant_roster` when none is handed). A tenant with no case record has no
    case system: that too is a fault, said so, for the callers that asked (`--update-ticket` was
    given). Order (C3): the case record, its system among the tenant's, its settings (the
    adapter's own check), then the cover of its comment route by its stored access."""
    case = record.case_record
    if case is None:
        raise CaseSettingsFault(CASE_RECORD_POINTER, "is absent: the tenant names no case system "
                                "to record the findings in")
    if isinstance(case, CaseTicketError):
        raise CaseSettingsFault(CASE_RECORD_POINTER,
                                str(case).removeprefix(f"{CASE_RECORD_POINTER} ")
                                .removeprefix(f"settings/{CASE_RECORD_REL} "))
    system = case.system
    if roster is None:
        roster = tenant_roster(record, defender_dir=defender_dir)
    module = _adapter_of(system, roster=roster)
    # The run's own reason scope, as run start's judgement uses: a crash text naming the
    # tenant's folder or the data root is shown by name, never located.
    scope = ReasonScope(tenant=record if isinstance(record, RunTenant) else None,
                        defender_dir=Path(defender_dir), adapters_root=Path(roster.root))
    cause = judge_adapter(lambda: module, tenant=record, scope=scope)
    if isinstance(cause, NotConfigured):
        settings, access = RECORDS.part(system, "settings"), RECORDS.part(system, "access")
        where = access if cause.reason.startswith(access) else settings
        raise CaseSettingsFault(where, cause.reason.removeprefix(where).lstrip(": ") or cause.reason)
    if isinstance(cause, AdapterBroken):
        raise CaseSettingsFault(CASE_RECORD_POINTER,
                                f"names the system `{system}`, whose adapter cannot be used: "
                                f"{cause.reason}", adapter_refused=True)
    _judge_cover(system, module, record)
    return CaseTarget(system=system, template=case, module=module)


def case_verdict(
    record: Any, *, defender_dir: Path, roster: RosterRead | None = None,
) -> CaseTarget | CaseSettingsFault:
    """`judge_case_system` as a value: run start judges once, over the roster the run reads, and
    hands the verdict to both the token mint and the record step, so they cannot disagree."""
    try:
        return judge_case_system(record, defender_dir=defender_dir, roster=roster)
    except CaseSettingsFault as fault:
        return fault


def _judge_cover(system: str, module: Any, record: Any) -> None:
    """The case system's stored access declaration must be usable and cover its adapter's
    comment route (#1366 C2, C5): THE cover rule the store's write and `tenant check` ask
    (`record_judgement.case_cover_fault`). A route the settings cannot build is the adapter's
    settings fault, named at the system's settings."""
    from defender.systems.record_judgement import case_cover_fault

    pointer = RECORDS.part(system, "access")
    found = record.access.get(system)
    if isinstance(found, ConfigFault):
        raise CaseSettingsFault(pointer, found.detail.removeprefix(pointer).lstrip(": "))
    if found is None:
        raise CaseSettingsFault(pointer, "is absent: a case system is reached only through the "
                                "credential proxy, at the base its access declaration names")
    settings = record.systems.get(system)
    try:
        why = case_cover_fault(module, settings if isinstance(settings, Mapping) else {}, found)
    except ConfigFault as fault:
        where = RECORDS.part(system, "settings")
        raise CaseSettingsFault(where, str(fault).removeprefix(where).lstrip(": ")) from None
    if why is not None:
        raise CaseSettingsFault(pointer, f"the case system `{system}` cannot take the comment "
                                f"{CASE_RECORD_POINTER} sends through it: {why}")


__all__ = [
    "CASE_RECORD_POINTER", "CaseSettingsFault", "CaseTarget", "LEGACY_SYSTEM",
    "case_verdict", "judge_case_system", "legacy_folder_finding", "tenant_roster",
]
