"""Which of a run's granted systems it can use — judged once per run, at its start (#1256)."""
from __future__ import annotations

import functools
import logging
from collections.abc import Callable, Collection, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

from defender._paths import adapters_under, name_roots, root_spellings
from defender._redaction import redact_model_visible
from defender.systems import circuit_breaker
from defender.systems.verb_dispositions import HEALTH_CHECK, gather_query_systems
from defender.systems.verb_grant import GrantError
from defender.systems.verbs import fresh_adapter_module, redact_settings_path
# The run record's fault type, through the record's own module: the import edge into
# `scripts/` stays `run_tenant`'s (#1080 O1's named pair, retired by #1172/#1121).
from defender.systems.run_tenant import ConfigFault

if TYPE_CHECKING:  # pragma: no cover — typing only
    from defender.systems._state import SystemsState
    from defender.systems.run_tenant import RunTenant
    from defender.systems.verb_dispositions import RunGrants
    from defender.systems.verbs import RosterRead

_logger = logging.getLogger(__name__)

#: How long a reason may run in what the model and the operator are shown. A reason is an
#: adapter's own fault text; a crash's can be arbitrarily long.
REASON_MAX = 400

#: How a reason names the two code trees an adapter's crash text can locate
#: (`ReasonScope.reason`): the defender tree by its name, the adapters tree by a placeholder (it
#: need not sit under the defender tree). Spelled here only — every reason passes that method.
_DEFENDER_TREE_NAME = "defender"
_ADAPTERS_TREE_NAME = "<adapters>"


@dataclass(frozen=True)
class NotConfigured:
    """The run's settings do not make the system usable; `reason` is the check's (or the escaped
    fault's) own text, host paths named rather than located."""

    reason: str


@dataclass(frozen=True)
class AdapterBroken:
    """The system's adapter could not be judged: it would not import, declares no check, or its
    check raised something other than `ConfigFault`."""

    reason: str


@dataclass(frozen=True)
class Tripped:
    """The circuit breaker counted `failures` infra failures of the system during the run."""

    failures: int


#: A cause set at run start (or by an escaped `ConfigFault`): held on the run's state.
StartCause = NotConfigured | AdapterBroken
#: Every cause a system can be down for.
Down = NotConfigured | AdapterBroken | Tripped


class NoUsableSystem(Exception):  # noqa: N818 — named for what it refuses, like `RunAborted`
    """Every granted system is down at run start, or none that is up grants gather a query verb:
    gather could query nothing (O-8). Raised before any model or adapter call; the message names
    each down system and its cause."""


# =============================================================================================
# Run start
# =============================================================================================

def granted_systems(grants: RunGrants) -> frozenset[str]:
    """The gather role defines startup scope; correlation is validated as its narrowing."""
    return grants.gather.systems


@dataclass(frozen=True)
class ReasonScope:
    """Where a run's down-cause reasons come from, so each is shown one way (`reason`): the run's
    tenant (its settings folder named by its pointer, its folder and data root by name) and the
    two code trees an adapter's own text can locate. Held on the run's state with its start
    verdict (`hold_at_start`), so a cause made later (`mark_escaped`) hides what the start
    check's did. Each part optional: the connect validator judges an adapter with no run."""

    tenant: RunTenant | None = None
    defender_dir: Path | None = None
    adapters_root: Path | None = None
    known_ids: frozenset[str] = frozenset()

    def reason(self, text: str) -> str:
        """`text` as a down system's reason, fit for the model and the operator — THE redaction
        every reason passes once, where its cause is made, so every surface that renders the
        cause (the start log lines, the O-8 refusal, MAIN's workspace view, gather's system
        index, `list_verbs`, the dispatch and call refusals) shows the same safe text. One line,
        bounded; staged names and world ids removed (`redact_model_visible`); the tenant's
        settings folder named by its pointer (`redact_settings_path`, the one settings
        redaction); and every host root named rather than located, at path boundaries
        (`_paths.name_roots`) — the tenant's folder and the data root (`Tenant.root_names`,
        their owner's) and the code trees, each by its name here. An adapter's crash text often
        carries its own file's absolute path, and a repr of the run's record the data root."""
        text = redact_model_visible(text, self.known_ids)
        named: dict[str, str] = {}
        if self.tenant is not None:
            text = redact_settings_path(text, self.tenant.settings)
            named.update(self.tenant.tenant.root_names())
        for root, name in ((self.defender_dir, _DEFENDER_TREE_NAME),
                           (self.adapters_root, _ADAPTERS_TREE_NAME)):
            if root is not None:
                named.update(root_spellings(Path(root), name))
        one_line = " ".join(name_roots(text, named).split())
        return one_line if len(one_line) <= REASON_MAX else one_line[:REASON_MAX - 1] + "…"


#: What a system whose adapter declares no settings check is down for (O-5a).
NO_CHECK = (
    "its adapter declares no `check_settings` (every adapter declares its settings check; a "
    "system needing none declares one that never raises)")


def judge_adapter(
    load: Callable[[], Any], *, tenant: RunTenant | None, scope: ReasonScope,
) -> StartCause | None:
    """THE judgement of an adapter (#1256 r4) — the start check's for each granted system, and
    the connect validator's — and the maker of the cause it finds, its reason shown through
    `scope`: `AdapterBroken` when `load()` (the adapter module) raises, when the module declares
    no callable `check_settings`, or when that check raises anything but `ConfigFault`;
    `NotConfigured` when it raises `ConfigFault`; `None` when the adapter is usable. The check
    is the declaration every adapter module makes (O-5): `check_settings(tenant)`, a pure
    function of the run's tenant record. With no `tenant` (the validator: there is no run's
    record to judge) the judgement stops at the declaration. A verb's `ConfigFault` escaping at
    call time is judged by `mark_escaped`, through the run's same scope."""
    try:
        module = load()
    except Exception as e:  # noqa: BLE001 — an adapter that will not import is broken, not fatal
        return AdapterBroken(scope.reason(
            f"its adapter could not be imported ({type(e).__name__}: {e})"))
    # Spelled literally, so a reader of the adapters (vulture's dead-code scan among them) sees
    # the name is read.
    check = getattr(module, "check_settings", None)
    if not callable(check):
        return AdapterBroken(NO_CHECK)
    if tenant is None:
        return None
    try:
        check(tenant)
    except ConfigFault as e:
        return NotConfigured(scope.reason(str(e)))
    except Exception as e:  # noqa: BLE001 — a check that crashes is the adapter's defect, not the run's
        return AdapterBroken(scope.reason(f"its `check_settings` raised {type(e).__name__}: {e}"))
    return None


@dataclass(frozen=True)
class RunSystems:
    """THE run's one judgement of its systems (#1256 r4): the roster it reads, each granted
    system down at its start with the cause (`judge_run`), and the scope its reasons are shown
    in. Made once per run — by `run.py` before the run folder exists, or by the driver when it is
    started without one — and handed inward as this one value; the run's state holds the live
    status from there (`hold_at_start`), which every surface asks when it renders."""

    roster: RosterRead
    down: Mapping[str, StartCause]
    scope: ReasonScope


def judge_run(roster: RosterRead, tenant: RunTenant, *, defender_dir: Path,
              known_ids: Collection[str] = ()) -> RunSystems:
    """@owns system_down — each granted system the run cannot use, with why: the verdict of its
    adapter's own settings check over the run's frozen record (O-1, O-5), or the reason its
    adapter cannot be judged (O-5a), each from `judge_adapter`. Every other granted system is
    up. Pure: it logs nothing and records nothing (`hold_at_start` does), so `run.py` can ask it
    before the run exists."""
    scope = ReasonScope(tenant=tenant, defender_dir=Path(defender_dir),
                        adapters_root=Path(roster.root), known_ids=frozenset(known_ids))
    down: dict[str, StartCause] = {}
    systems = granted_systems(tenant.grants)
    missing = systems - set(roster.accepted)
    if missing:
        raise GrantError(
            f"{tenant.table_pointer}: gather grants system(s) absent from the adapters roster "
            f"under {roster.root}: {', '.join(sorted(missing))}")
    for system in sorted(systems):
        cause = judge_adapter(
            functools.partial(fresh_adapter_module, roster, system), tenant=tenant, scope=scope)
        if cause is not None:
            down[system] = cause
    return RunSystems(roster=roster, down=MappingProxyType(down), scope=scope)


def hold_at_start(state: SystemsState, systems: RunSystems) -> None:
    """Hold the run's judgement on its state, before the agent's first turn: each system down
    at start with its cause, and the scope later causes' reasons are shown in. Tell the
    operator: exactly one line per down system — WARNING for one not configured (O-7), ERROR for
    a broken adapter (O-5a)."""
    with state.lock:
        state.reason_scope = systems.scope
    for system, cause in sorted(systems.down.items()):
        _mark(state, system, cause)
        line = f"system {system} is down for this run, from its start: {cause_text(cause)}"
        if isinstance(cause, AdapterBroken):
            _logger.error(line)
        else:
            _logger.warning(line)


def require_usable(grants: RunGrants, down: Mapping[str, StartCause]) -> None:
    """THE predicate of O-8, asked by `run.py` before the run exists and by the driver as it
    starts: the existing "gather can query nothing" rule (`gather_query_systems`, which the
    grant check asks of the table) asked again of the granted systems that are UP. A system up
    but granted gather nothing beyond its health check does not save the run. `NoUsableSystem`
    names each down system and its cause."""
    if gather_query_systems(grants) - set(down):
        return
    named = "; ".join(f"{system} — {cause_text(down[system])}" for system in sorted(down))
    raise NoUsableSystem(
        "no granted system is usable at run start, so gather could query nothing: no system "
        f"that is up holds a gather query verb in {grants.path} (a `{HEALTH_CHECK}` grant alone "
        f"reaches no data). Down at start: {named or 'none'}. Make one of them usable (its "
        "settings, or its adapter) before running this tenant.")


# =============================================================================================
# During the run
# =============================================================================================

def down_cause(state: SystemsState, system: str) -> Down | None:
    """THE question every gate asks: is `system` down for this run, and why? A cause held on
    the run's state (not configured, adapter broken) first; else a trip of the breaker; else
    `None` — the system is up."""
    if not system:
        return None
    held = state.system_down_cause(system)
    if held is not None:
        return held
    if circuit_breaker.is_tripped(state, system):
        return Tripped(state.breaker_failures(system))
    return None


def refusal_if_down(state: SystemsState, system: str) -> str | None:
    """What a refused dispatch or call to `system` answers, from its cause (DP4) — `None` when
    the system is up. A trip keeps the breaker's own message, its count and its causes; a system
    down for another cause names that cause and its reason, never a trip."""
    cause = down_cause(state, system)
    return None if cause is None else message_for(state, system, cause)


def message_for(state: SystemsState, system: str, cause: Down) -> str:
    """`refusal_if_down` for a cause the caller already asked `down_cause` for."""
    if isinstance(cause, Tripped):
        return circuit_breaker.down_message(state, system)
    return held_refusal(system, cause)


def held_refusal(system: str, cause: StartCause) -> str:
    """The refusal of a dispatch or call to `system`, down for `cause` (not a trip)."""
    return (
        f"[system-status] System '{system}' is DOWN for this run — {cause_text(cause)}. "
        f"Nothing more is asked of {system} in this run: a dispatch to it starts no gather (its "
        "reference skill is not loaded) and a call to it reaches no adapter. This is a "
        f"visibility gap, not a query result. Do NOT re-dispatch {system}; name the missing "
        "evidence in your analysis and in "
        "a `:T conclude` `ceiling_test` row (the entry price `inconclusive` owes), then escalate "
        "(inconclusive) if it blocks disposition."
    )


def cause_text(cause: Down) -> str:
    """The cause as every surface names it: `not configured: <reason>`,
    `adapter broken: <reason>`, or the trip's count."""
    if isinstance(cause, NotConfigured):
        return f"not configured: {cause.reason}"
    if isinstance(cause, AdapterBroken):
        return f"adapter broken: {cause.reason}"
    return f"tripped by {cause.failures} {circuit_breaker.INFRA_CAUSES}"


def mark_escaped(state: SystemsState, system: str, fault_text: str, *,
                 tenant: RunTenant | None = None, defender_dir: Path | None = None,
                 known_ids: Collection[str] = ()) -> None:
    """A verb of `system` raised `ConfigFault` at call time (O-5b): its settings check missed a
    fault its verbs can raise. The system is down as not configured from this call on — the same
    status and accounting the start check gives, reached late — and the escape is logged as the
    adapter defect it is. `fault_text` is the fault's own text: its reason is shown through the
    scope the run's start verdict holds (`hold_at_start`), the start check's own; a state no
    start held (a caller that built its own) shows it through the caller's `tenant` and
    `defender_dir`. The call is not charged to the breaker (the caller's row is written
    uncharged)."""
    with state.lock:
        held = state.reason_scope
    scope = held if held is not None else ReasonScope(
        tenant=tenant, defender_dir=defender_dir,
        adapters_root=adapters_under(defender_dir) if defender_dir is not None else None,
        known_ids=frozenset(known_ids))
    cause = NotConfigured(scope.reason(fault_text))
    _logger.error(
        f"adapter defect: a {system} verb raised ConfigFault at call time — a settings fault "
        f"its `check_settings` does not cover. {system} is down for the rest of this run as "
        f"{cause_text(cause)}")
    _mark(state, system, cause)


def down_notes(state: SystemsState, systems: Iterable[str]) -> dict[str, str]:
    """The cause of each of `systems` that is down NOW (`down_cause`): what MAIN's workspace view,
    gather's system index and the like print beside it (O-3), asked when they render — so a
    system downed after the start (an escaped config fault, a trip) is marked too."""
    notes: dict[str, str] = {}
    for system in systems:
        cause = down_cause(state, system)
        if isinstance(cause, Tripped):
            notes[system] = ("tripped: the circuit breaker stopped calls to it after repeated "
                             f"{circuit_breaker.INFRA_CAUSES}")
        elif cause is not None:
            notes[system] = cause_text(cause)
    return notes


#: No system down: the notes of a surface rendered for no run, or for a run that judged none.
NONE_DOWN: Mapping[str, str] = MappingProxyType({})


def snapshot_down(state: SystemsState) -> dict[str, dict[str, str]]:
    """The permanent down causes at the fork boundary, as JSON-shaped values.

    Reasons already passed their source run's `ReasonScope`; the scope itself belongs
    to the current run and is never copied into an arm.
    """
    with state.lock:
        return {
            system: {"kind": "not_configured" if isinstance(cause, NotConfigured)
                     else "adapter_broken", "reason": cause.reason}
            for system, cause in state.system_down.items()
        }


def restore_down(state: SystemsState, recorded: dict) -> None:
    """Inherit the source's permanent causes without losing the arm's startup verdict.

    The inherited cause came first for a system both runs found down. New startup
    failures still apply; later escaped faults use the arm's own reason scope.
    """
    inherited = down_from_snapshot(recorded)
    with state.lock:
        state.system_down.update(inherited)


def down_from_snapshot(recorded: object) -> dict[str, StartCause]:
    """Decode the fork's permanent causes, refusing an incomplete or unknown cause."""
    kinds: dict[str, Callable[[str], StartCause]] = {
        "not_configured": NotConfigured, "adapter_broken": AdapterBroken}
    inherited: dict[str, StartCause] = {}
    if not isinstance(recorded, dict):
        raise ValueError("the recorded system-down state is not an object")
    for system, entry in recorded.items():
        if (not isinstance(system, str) or not isinstance(entry, dict)
                or set(entry) != {"kind", "reason"}
                or not isinstance(entry["kind"], str) or entry["kind"] not in kinds
                or not isinstance(entry["reason"], str)):
            raise ValueError("the recorded system-down state contains an invalid cause")
        inherited[system] = kinds[entry["kind"]](entry["reason"])
    return inherited


def _mark(state: SystemsState, system: str, cause: StartCause) -> None:
    """Hold `cause` for `system` on the run's state; a system already down keeps its first
    cause (it does not come back up, and its cause does not change)."""
    with state.lock:
        state.system_down.setdefault(system, cause)


__all__ = [
    "AdapterBroken",
    "Down",
    "NONE_DOWN",
    "NO_CHECK",
    "NoUsableSystem",
    "NotConfigured",
    "ReasonScope",
    "RunSystems",
    "StartCause",
    "Tripped",
    "cause_text",
    "down_cause",
    "down_notes",
    "down_from_snapshot",
    "granted_systems",
    "held_refusal",
    "hold_at_start",
    "judge_adapter",
    "judge_run",
    "mark_escaped",
    "message_for",
    "refusal_if_down",
    "require_usable",
    "restore_down",
    "snapshot_down",
]
