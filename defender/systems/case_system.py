"""The case system a tenant names (#1359): which adapter takes the host's comment, and whether
the tenant's settings let it.

One judgement, two askers (D-17): the record leg at run end and `tenant check` on a folder both
call `judge_case_system`, so the check cannot pass what the leg would refuse. It reads the
tenant's `settings/case-record.yaml` as recorded when the run began, the case system's adapter
(from the roster the run reads), its access declaration when the system is reached through the
credential proxy, then its `check_settings` over the same record — judged by
`system_status.judge_adapter`, the run start's own rules, so a missing or crashing check is the
adapter's defect here as there. Every failure is a `CaseSettingsFault` naming the one file that is
wrong, and nothing else escapes: both askers may call it unguarded.
"""
from __future__ import annotations

import dataclasses
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from defender._paths import adapters_under
from defender.kit.access import AccessDeclaration
from defender.kit.faults import ConfigFault
from defender.kit.settings import config_pointer, pointer_to
from defender.kit.verbs import COMMENT_ACTION, HOST_ACTIONS, READBACK_ACTION, CaseComments
from defender.systems.run_tenant import RunTenant
from defender.systems.system_status import AdapterBroken, NotConfigured, ReasonScope, judge_adapter
from defender.systems.verbs import RegistryError, RosterRead, fresh_adapter_module, read_roster
from defender.tenancy.case_ticket import (
    CASE_RECORD_REL, CaseRecordSettings, CaseTicketError)

#: The retired system folder a tenant may still hold; `tenant check` names the new file for it.
LEGACY_SYSTEM = "case-history"  # lint-shippable: ok — the retired system's folder name, named only to tell the operator to migrate

CASE_RECORD_POINTER = pointer_to(CASE_RECORD_REL)


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


def _adapter_of(system: str, *, defender_dir: Path, roster: RosterRead | None) -> tuple[Any, RosterRead]:
    """`system`'s adapter module, read fresh from the checkout, or the `CaseSettingsFault` naming
    `settings/case-record.yaml` for why it cannot take a comment: no adapter, an adapter the
    roster refused, one that will not load, or one without the comment action."""
    if roster is None:
        try:
            roster = read_roster(adapters_under(Path(defender_dir)))
        except RegistryError as e:
            raise CaseSettingsFault(CASE_RECORD_POINTER,
                                    f"cannot be judged: the adapters cannot be read ({e})") from None
    if system not in roster.accepted:
        raise CaseSettingsFault(CASE_RECORD_POINTER,
                                f"names the system `{system}`, which has no adapter")
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
    return module, roster


def judge_case_system(
    record: Any, *, defender_dir: Path, roster: RosterRead | None = None,
) -> CaseTarget:
    """The case system `record` names, ready to take a comment, or `CaseSettingsFault`.

    `record` is the run's tenant record (or `tenant check`'s stand-in over a folder): it carries
    `case_record`, `systems` and `access`, read once when the run began. A tenant with no
    case-record file has no case system: that too is a fault, said so, for the callers that asked
    (`--update-ticket` was given)."""
    case = record.case_record
    if case is None:
        raise CaseSettingsFault(CASE_RECORD_POINTER, "is absent: the tenant names no case system "
                                "to record the findings in")
    if isinstance(case, CaseTicketError):
        raise CaseSettingsFault(CASE_RECORD_POINTER,
                                str(case).removeprefix(f"settings/{CASE_RECORD_REL} "))
    system = case.system
    module, roster = _adapter_of(system, defender_dir=defender_dir, roster=roster)
    if system in record.access:
        # Only a system reached through the credential proxy has an access declaration (or the
        # fault for why it has none): it must declare the comment's route. Judged before the
        # settings check, so a fault the check raises is about `config.env`, never this file.
        _judge_access(system, record.access)
    # The run's own reason scope, as run start's judgement uses: a crash text naming the
    # tenant's folder or the data root is shown by name, never located.
    scope = ReasonScope(tenant=record if isinstance(record, RunTenant) else None,
                        defender_dir=Path(defender_dir), adapters_root=Path(roster.root))
    cause = judge_adapter(lambda: module, tenant=record, scope=scope)
    if isinstance(cause, NotConfigured):
        config = config_pointer(system)
        raise CaseSettingsFault(config, cause.reason.removeprefix(f"{config}: "))
    if isinstance(cause, AdapterBroken):
        raise CaseSettingsFault(CASE_RECORD_POINTER,
                                f"names the system `{system}`, whose adapter cannot be used: "
                                f"{cause.reason}", adapter_refused=True)
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


def _judge_access(system: str, access: Mapping[str, AccessDeclaration | ConfigFault]) -> None:
    """A system reached through the credential proxy must declare its comment route: at least one
    write route in its `access.yaml` (D-16)."""
    pointer = pointer_to(f"systems/{system}/access.yaml")
    found = access.get(system)
    if isinstance(found, ConfigFault):
        raise CaseSettingsFault(pointer, found.detail.removeprefix(f"{pointer} ").lstrip(": "))
    if found is None:
        raise CaseSettingsFault(pointer, "is absent: the system is reached through the "
                                "credential proxy and declares no access")
    if not found.writes:
        raise CaseSettingsFault(pointer, "declares no write route: the host's comment has no "
                                "route to be sent on")


__all__ = [
    "CASE_RECORD_POINTER", "CaseSettingsFault", "CaseTarget", "LEGACY_SYSTEM",
    "case_verdict", "judge_case_system", "legacy_folder_finding",
]
