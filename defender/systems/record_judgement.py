"""The one judgement of a tenant's system and case records (#1366 O4, P2, C1-C4, K1): what makes a record usable.

All of O4 but version, staleness, the lock and the generation (those are the store's). Three callers ask it (C3):
the record store's write refusal (`system_records.open_store` injects `judge_records`), `tenant check`, and run start
(through `cover_fault`, which `case_system` asks). Every fault is one sentence naming the system and the key or part,
located by a `kit.settings.Locator` (DC6): a stored record says `system <s> settings` / `system <s> access` / `the case
record`; the import's candidate and connect's handoff pass a folder locator so the same sentence names the file.

A system record is judged by its adapter's own `check_settings` (K1), run over a tenant record built from the candidate
(`RecordTenant`), so the store and run start cannot disagree. The case record is judged by #1359's rules
(`tenancy.case_ticket.parse_case_record`), its system's comment route (C1) and the cover rule (C2).

Given `before` (the tenant's current state the write replaces), only what the write changes is judged: a record an
upgrade broke does not block a write to another one, and a refusal names the part whose change broke cover (C4). With
no `before` (the import, `check`), everything is judged."""
from __future__ import annotations

import dataclasses
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from defender._yaml import safe_dump
from defender.kit.access import AccessDeclaration, Route
from defender.kit.faults import ConfigFault
from defender.kit.settings import RECORDS, Locator, Part, SystemConfig
from defender.systems.catalog import Catalog, route_of
from defender.systems.verbs import is_platform_served
from defender.tenancy import access_pointer, parse_access
from defender.tenancy.case_ticket import CASE_RECORD_REL, CaseTicketError, parse_case_record
from defender.tenancy.models import CaseRecord, SystemRecord, TenantRecords

#: Where nothing is read from: a tenant record built for a judgement has no agent knowledge.
_NO_AGENT = Path("/nonexistent-agent-root")


# --- the tenant record an adapter's check reads ---------------------------------------------------------------------

def located_access(text: str, *, system: str, locator: Locator = RECORDS) -> AccessDeclaration:
    """`system`'s access declaration parsed from its stored `text` (K4), or the `ConfigFault` naming it by `locator`
    (`tenancy.parse_access` names the retired file; a record names itself, DC6)."""
    try:
        return parse_access(text, system=system)
    except ConfigFault as fault:
        raise ConfigFault(_relocated(str(fault), system, locator)) from None


def _relocated(text: str, system: str, locator: Locator) -> str:
    return text.replace(access_pointer(system), locator.part(system, "access"))


@dataclasses.dataclass(frozen=True)
class RecordTenant:
    """A tenant record (`kit.verbs.TenantRecord`) built from system records: what an adapter's `check_settings` reads
    (K1). `systems` are the stored settings, `access` each declaration parsed (or its located fault), `locator` how
    their faults name them."""

    systems: Mapping[str, SystemConfig | ConfigFault]
    access: Mapping[str, AccessDeclaration | ConfigFault]
    locator: Locator = RECORDS
    agent: Path = _NO_AGENT

    @classmethod
    def of(cls, records: Mapping[str, SystemRecord], *, locator: Locator = RECORDS) -> RecordTenant:
        access: dict[str, AccessDeclaration | ConfigFault] = {}
        for system, record in records.items():
            try:
                access[system] = located_access(record.access, system=system, locator=locator)
            except ConfigFault as fault:
                access[system] = fault
        return cls(systems={s: SystemConfig(r.settings) for s, r in records.items()}, access=access,
                   locator=locator)


# --- the cover rule (C2) ------------------------------------------------------------------------------------------

def _segments(path: str) -> list[str]:
    return path.split("/")


def write_covers(declared: Route, route: tuple[str, str]) -> bool:
    """C2: a declared write route covers the comment route when the method is the same, the segment count is the same,
    and each segment is a declared `*` or the same raw literal; where the route has `*`, the declared one must too."""
    method, pattern = route
    got, want = _segments(declared.path), _segments(pattern)
    return declared.method == method and len(got) == len(want) and all(
        g == "*" if w == "*" else g in ("*", w) for g, w in zip(got, want, strict=True))


def read_matches(declared: Route, route: tuple[str, str]) -> bool:
    """C2 (r5): a declared read route matches the comment route when the method and segment count are the same and each
    segment pair is equal or `*` on either side. Such a read route is refused: writes are allowed only as writes."""
    method, pattern = route
    got, want = _segments(declared.path), _segments(pattern)
    return declared.method == method and len(got) == len(want) and all(
        g == w or "*" in (g, w) for g, w in zip(got, want, strict=True))


def cover_fault(route: tuple[str, str], declaration: AccessDeclaration) -> str | None:
    """Why `declaration` does not cover the comment `route` (C2), as a clause, or None when it does. THE rule: the
    store's write, `tenant check` and run start's case verdict all ask it."""
    method, pattern = route
    matching = [r for r in declaration.reads if read_matches(r, route)]
    if matching:
        shown = ", ".join(f"{r.method} {r.path}" for r in matching)
        return (f"its read route {shown} matches its comment route {method} {pattern}: the comment is allowed only as a "
                "declared write")
    if not any(write_covers(r, route) for r in declaration.writes):
        return (f"no declared write route covers its comment route {method} {pattern} (same method and segments, `*` "
                "where the route has `*`)")
    return None


# --- the judgement ------------------------------------------------------------------------------------------------

def judge_records(after: TenantRecords, before: TenantRecords | None = None, *, catalog: Catalog | None = None,
                  locator: Locator = RECORDS) -> list[str]:
    """Every reason the tenant's records, as they would stand (`after`), are unusable: `[]` accepts (O4).

    With `before` (the current state a write replaces), only the records the write changes are judged, and the case
    record's rules only where the write touches the case record or its system; a cover refusal names the part whose
    change alone broke it (C4). With none, everything is judged. `catalog` defaults to the running checkout's."""
    adapters = _the_catalog(catalog)
    faults: list[str] = []
    broken: set[str] = set()
    old_systems = before.systems if before is not None else {}
    for system, record in sorted(after.systems.items()):
        if before is None or old_systems.get(system) != record:
            found = system_faults(record, catalog=adapters, locator=locator)
            faults += found
            if found:
                broken.add(system)
    return faults + _case_faults(after, before, catalog=adapters, locator=locator, broken=broken)


def _the_catalog(catalog: Catalog | None) -> Catalog:
    """The catalog handed in, else the running checkout's."""
    return Catalog.of_checkout() if catalog is None else catalog


def system_faults(record: SystemRecord, *, catalog: Catalog, locator: Locator = RECORDS) -> list[str]:
    """Why one system record is unusable (O3, O4, K1), each fault opening with the record's locator: a platform-served
    name, a custom reference, an adapter the catalog lacks or that differs from the system id, then its adapter's own
    settings check over a tenant record holding it (its access first, then its settings)."""
    system = record.system_id
    where = locator.system(system)
    if is_platform_served(system):
        return [f"{where}: `{system}` is a platform-served system, run by the platform itself: no record may take its "
                "name"]
    if record.custom_ref is not None:
        path, revision = record.custom_ref
        return [f"{where}: names a custom adapter ({path} at {revision}); custom adapters are refused until they are "
                "supported (#1172) — name a catalog adapter"]
    adapter = record.adapter_id
    if adapter not in catalog:
        return [f"{where}: names the adapter `{adapter}`, which the catalog does not carry (`tenant.py catalog` lists "
                "it); only a delete of this record is accepted"]
    if adapter != system:
        return [f"{where}: a catalog record's system id is its adapter id, but it names the adapter `{adapter}`"]
    fault = _settings_fault(record, catalog=catalog, locator=locator)
    return [] if fault is None else [fault]


def _settings_fault(record: SystemRecord, *, catalog: Catalog, locator: Locator) -> str | None:
    """The adapter's own `check_settings` over a tenant record holding `record` (K1), as one located sentence."""
    system = record.system_id
    try:
        module = catalog.module(record.adapter_id)
    except Exception as e:  # noqa: BLE001 — an adapter that will not import is not usable, not fatal
        return f"{locator.system(system)}: its adapter could not be loaded ({type(e).__name__})"
    check = getattr(module, "check_settings", None)
    if not callable(check):
        return f"{locator.system(system)}: its adapter declares no `check_settings`"
    try:
        check(RecordTenant.of({system: record}, locator=locator))
    except ConfigFault as fault:
        return _located(str(fault), system, locator)
    except Exception as e:  # noqa: BLE001 — a check that crashes is the adapter's defect
        return f"{locator.system(system)}: its adapter's `check_settings` raised {type(e).__name__}"
    return None


def _located(text: str, system: str, locator: Locator) -> str:
    """`text` located: as it is when it names the record (or a part of it), else opening with the record's locator."""
    text = _relocated(text, system, locator)
    if locator.system(system) in text or any(locator.part(system, p) in text for p in ("settings", "access")):
        return text
    return f"{locator.system(system)}: {text}"


def _case_text(record: CaseRecord) -> str:
    return safe_dump({"system": record.system_id, "comment": {"body": record.comment_body}}, sort_keys=False)


@dataclasses.dataclass(frozen=True)
class _CaseWrite:
    """The case record and its system as a write leaves them, and what the write changed."""

    case: CaseRecord
    record: SystemRecord | None
    old_record: SystemRecord | None
    case_changed: bool
    fresh: bool  # no state before: the import, or `check`


def _case_faults(after: TenantRecords, before: TenantRecords | None, *, catalog: Catalog, locator: Locator,
                 broken: set[str]) -> list[str]:
    """O4's case-record rules and C2's cover, where the write touches the case record or its system."""
    if after.case is None:
        return []
    system = after.case.system_id
    w = _CaseWrite(case=after.case, record=after.systems.get(system),
                   old_record=before.systems.get(system) if before is not None else None,
                   case_changed=before is None or before.case != after.case, fresh=before is None)
    if not w.case_changed and w.old_record == w.record:
        return []
    faults = _template_faults(w.case, locator) if w.case_changed else []
    record = w.record
    if record is None or not record.enabled:
        return [*faults, _absent_case_system(w, locator)]
    if system in broken:
        return faults  # the system's own fault is reported; its route cannot be judged over it
    return faults + _route_faults(w, record, catalog=catalog, locator=locator)


def _template_faults(case: CaseRecord, locator: Locator) -> list[str]:
    """#1359's rules for the case record (its template), named by the locator."""
    try:
        parse_case_record(_case_text(case))
    except CaseTicketError as bad:
        return [str(bad).replace(f"settings/{CASE_RECORD_REL}", locator.case(), 1)]
    return []


def _absent_case_system(w: _CaseWrite, locator: Locator) -> str:
    system = w.case.system_id
    if w.case_changed:
        state = "has no current record" if w.record is None else "is disabled"
        return (f"{locator.case()} names the case system `{system}`, which {state}: a case system is one of the "
                "tenant's current enabled systems")
    return (f"{locator.system(system)}: is the case system {locator.case()} names, so it cannot be deleted or "
            "disabled — delete the case record (`tenant.py delete-case`) or name another case system first")


def _route_faults(w: _CaseWrite, record: SystemRecord, *, catalog: Catalog, locator: Locator) -> list[str]:
    """C1 and C2 over the case system's record: its adapter offers a comment route, and its access covers it."""
    system, where = w.case.system_id, locator.case()
    if record.custom_ref is not None or record.adapter_id not in catalog:
        return [f"{where} names the case system `{system}`, whose adapter the catalog does not carry"] \
            if w.case_changed else []
    try:
        route = route_of(catalog.module(record.adapter_id), record.settings)
    except ConfigFault as fault:
        return [_located(str(fault), system, locator)]
    except Exception as e:  # noqa: BLE001 — an adapter that will not load cannot take a comment
        return [f"{where} names the case system `{system}`, whose adapter could not be loaded ({type(e).__name__})"]
    if route is None:
        return [f"{where} names the case system `{system}`, whose adapter offers no comment action (it declares no "
                "comment route): a case system must take the host's comment"]
    try:
        declaration = parse_access(record.access, system=system)
    except ConfigFault:
        return []  # the system's access fault is its own (reported when it changed)
    why = cover_fault(route, declaration)
    if why is None:
        return []
    if w.fresh or w.old_record is None:
        return [f"{where} names the case system `{system}`, and {locator.part(system, 'access')} does not let it take "
                f"the comment: {why}"]
    if w.case_changed:
        return [f"{where} names the case system `{system}`, which cannot take the comment: {why}"]
    return _c4_faults(system, record, w.old_record, why, catalog=catalog, locator=locator)


def _c4_faults(system: str, new: SystemRecord, old: SystemRecord, why: str, *, catalog: Catalog,
               locator: Locator) -> list[str]:
    """C4: the parts of the case system's change that break cover, each alone (recompute with the old settings and the
    new access, and the reverse); both when neither alone does."""
    parts: list[Part] = []
    if not _covers_with(new.settings, old.access, system, catalog=catalog, adapter=new.adapter_id):
        parts.append("settings")
    if not _covers_with(old.settings, new.access, system, catalog=catalog, adapter=new.adapter_id):
        parts.append("access")
    if not parts:
        parts = ["settings", "access"]
    return [f"{locator.part(system, part)}: this change leaves the case system unable to take the comment {locator.case()} "
            f"sends through it: {why}" for part in parts]


def _covers_with(settings: Mapping[str, str], access: str, system: str, *, catalog: Catalog, adapter: str) -> bool:
    try:
        route = route_of(catalog.module(adapter), settings)
        declaration = parse_access(access, system=system)
    except Exception:  # noqa: BLE001 — a part that cannot be judged does not cover
        return False
    return route is not None and cover_fault(route, declaration) is None


def judge_system(system: str, *, settings: Mapping[str, str], access: str, locator: Locator,
                 catalog: Catalog | None = None) -> list[str]:
    """One candidate system (catalog id = `system`) judged alone, with no tenant: connect's handoff (O11) passes a
    folder locator so it prints the store's own sentence naming the file."""
    record = SystemRecord(system_id=system, version=1, adapter_id=system, settings=dict(settings), access=access)
    return system_faults(record, catalog=_the_catalog(catalog), locator=locator)


def case_cover_fault(module: Any, settings: Mapping[str, str], declaration: AccessDeclaration) -> str | None:
    """Run start's question (C3, C5): why the case system's adapter `module`, over its stored `settings`, cannot take
    the comment through `declaration`, or None. A route the settings cannot build raises the adapter's `ConfigFault`."""
    route = route_of(module, settings)
    if route is None:
        return "its adapter offers no comment action (it declares no comment route)"
    return cover_fault(route, declaration)


__all__ = ["RecordTenant", "case_cover_fault", "cover_fault", "judge_records", "judge_system", "located_access",
           "read_matches", "system_faults", "write_covers"]
