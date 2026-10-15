"""Which of a run's granted systems it can use — decided once, at run start (#1256).

A system is UP or DOWN for a run, and a down system carries its cause:

  * `NotConfigured(reason)` — its adapter's settings check (`check_settings`) raised
    `ConfigFault` over the run's tenant record at start; or, later, a verb raised `ConfigFault`
    at call time — a fault the check did not cover, which is an adapter defect (DP3, O-5b).
  * `AdapterBroken(reason)` — at start, its adapter would not import, declares no check, or its
    check raised anything but `ConfigFault` (O-5a).
  * `Tripped(failures)` — the circuit breaker's count reached its limit during the run.

The first two are held on the run's `RunState` (`system_down`), written here and nowhere else;
the third is the breaker's own count. Every gate that refuses a down system — the gather
dispatch, the query tool's in-call check, lead zero, `list_verbs` — asks one question,
`down_cause`, and renders its refusal from the cause (`refusal_if_down`). A system down for a
cause that is not a trip is never charged to the breaker: no call to it runs, and the one call
that can reveal it (an escaped `ConfigFault`) is not charged (`mark_escaped`). So the breaker
counts only what can change during a run (DP2).

What makes a system usable is fixed before the agent's first turn (DP1): its settings are
frozen in the run's record, and its adapter is the roster's. `startup_check` judges it there,
once, from the adapter's own declaration (system rules live with the adapter, #1215); nothing
is inferred from call outcomes.
"""
from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from defender.learning.branch.redaction import redact_model_visible
from defender.runtime import circuit_breaker
from defender.runtime.verb_dispositions import HEALTH_CHECK, gather_query_systems
from defender.runtime.verbs import adapter_module, redact_settings_path
# The run record's fault type, through the record's own module: the import edge into
# `scripts/` stays `run_tenant`'s (#1080 O1's named pair, retired by #1172/#1121).
from defender.runtime.run_tenant import ConfigFault

if TYPE_CHECKING:  # pragma: no cover — typing only
    from defender.runtime.run_state import RunState
    from defender.runtime.run_tenant import RunTenant
    from defender.runtime.verb_dispositions import RunGrants
    from defender.runtime.verbs import RosterRead

_logger = logging.getLogger(__name__)

#: How long a reason may run in what the model and the operator are shown. A reason is an
#: adapter's own fault text; a crash's can be arbitrarily long.
REASON_MAX = 400


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
    """Every system a run's grants reach — gather's and the correlation lead's."""
    return grants.gather.systems | grants.correlation.systems


def startup_check(
    roster: RosterRead, tenant: RunTenant, *, defender_dir: Path,
) -> dict[str, StartCause]:
    """@owns system_down — each granted system the run cannot use, with why: the verdict of its
    adapter's own settings check over the run's frozen record (O-1, O-5), or the reason its
    adapter cannot be judged (O-5a). Every other granted system is up. Pure: it logs nothing and
    records nothing (`hold_at_start` does), so `run.py` can ask it before the run exists and
    the driver again when it starts.

    The adapters are `roster`'s — the tree the run reads, never an injected registry (K2). A
    granted system the roster does not hold is not judged here: a registry built over that
    roster refuses such a grant at construction (C11).

    Reasons are made fit to show before they are kept (`_shown`): the settings folder named by
    its pointer, and no host path of the data root, the defender tree or the adapters tree."""
    def shown(text: str) -> str:
        return _shown(text, tenant=tenant, defender_dir=Path(defender_dir),
                      adapters=Path(roster.root))

    down: dict[str, StartCause] = {}
    for system in sorted(granted_systems(tenant.grants) & set(roster.accepted)):
        try:
            module = adapter_module(roster, system)
        except Exception as e:  # noqa: BLE001 — an adapter that will not import is broken, not fatal
            down[system] = AdapterBroken(shown(
                f"its adapter could not be imported ({type(e).__name__}: {e})"))
            continue
        # The declaration every adapter module makes (O-5): `check_settings(tenant)`, a pure
        # function of the run's tenant record that returns None when the system is usable and
        # raises `ConfigFault` naming what is wrong otherwise. Spelled literally, so a reader of
        # the adapters (vulture's dead-code scan among them) sees the name is read.
        check = getattr(module, "check_settings", None)
        if not callable(check):
            down[system] = AdapterBroken(
                "its adapter declares no `check_settings` (every adapter declares its settings "
                "check; a system needing none declares one that never raises)")
            continue
        try:
            check(tenant)
        except ConfigFault as e:
            down[system] = NotConfigured(shown(str(e)))
        except Exception as e:  # noqa: BLE001 — a check that crashes is the adapter's defect, not the run's
            down[system] = AdapterBroken(shown(
                f"its `check_settings` raised {type(e).__name__}: {e}"))
    return down


def hold_at_start(state: RunState, down: Mapping[str, StartCause]) -> None:
    """Record the start check's verdict on the run's state, before the agent's first turn, and
    tell the operator: exactly one line per down system — WARNING for one not configured (O-7),
    ERROR for a broken adapter (O-5a)."""
    for system, cause in sorted(down.items()):
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

def down_cause(state: RunState, system: str) -> Down | None:
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


def refusal_if_down(state: RunState, system: str) -> str | None:
    """What a refused dispatch or call to `system` answers, from its cause (DP4) — `None` when
    the system is up. A trip keeps the breaker's own message, its count and its causes; a system
    down for another cause names that cause and its reason, never a trip."""
    cause = down_cause(state, system)
    return None if cause is None else message_for(state, system, cause)


def message_for(state: RunState, system: str, cause: Down) -> str:
    """`refusal_if_down` for a cause the caller already asked `down_cause` for."""
    if isinstance(cause, Tripped):
        return circuit_breaker.down_message(state, system)
    return held_refusal(system, cause)


def held_refusal(system: str, cause: StartCause) -> str:
    """The refusal of a dispatch or call to `system`, down for `cause` (not a trip)."""
    return (
        f"[system-status] System '{system}' is DOWN for this run — {cause_text(cause)}. "
        f"No dispatch or call to {system} runs in this run: this one did not, and "
        f"{system}'s reference skill was not loaded. This is a visibility gap, not a query "
        f"result. Do NOT re-dispatch {system}; name the missing evidence in your analysis and in "
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


def mark_escaped(state: RunState, system: str, fault_text: str) -> None:
    """A verb of `system` raised `ConfigFault` at call time (O-5b): its settings check missed a
    fault its verbs can raise. The system is down as not configured from this call on — the same
    status and accounting the start check gives, reached late — and the escape is logged as the
    adapter defect it is. `fault_text` is the fault as the model may read it (the caller's
    redaction); it becomes the reason every later refusal carries. The call is not charged to
    the breaker (the caller's row is written uncharged)."""
    cause = NotConfigured(" ".join(fault_text.split())[:REASON_MAX])
    _logger.error(
        f"adapter defect: a {system} verb raised ConfigFault at call time — a settings fault "
        f"its `check_settings` does not cover. {system} is down for the rest of this run as "
        f"{cause_text(cause)}")
    _mark(state, system, cause)


def down_notes(down: Mapping[str, StartCause], systems: Iterable[str]) -> dict[str, str]:
    """`cause_text` for each of `systems` that is down at start: what the workspace view and the
    gather system index print beside it (O-3)."""
    return {system: cause_text(down[system]) for system in systems if system in down}


def _mark(state: RunState, system: str, cause: StartCause) -> None:
    """Hold `cause` for `system` on the run's state; a system already down keeps its first
    cause (it does not come back up, and its cause does not change)."""
    with state.lock:
        state.system_down.setdefault(system, cause)


def _shown(text: str, *, tenant: RunTenant, defender_dir: Path, adapters: Path) -> str:
    """A reason fit for the model and the operator: one line, bounded, with the tenant's
    settings folder named by its pointer (`redact_settings_path`, the one settings redaction),
    the tenant's folder under the data root, the defender tree and the adapters tree (which
    need not sit in either — a branch estate's) named rather than located, and staged names and
    world ids removed (`redact_model_visible`). An adapter's crash text often carries its own
    file's absolute path."""
    text = redact_settings_path(redact_model_visible(text), tenant.settings)
    roots = ((tenant.tenant.dir, "<tenant folder>"), (defender_dir, "defender"),
             (adapters, "<adapters>"))
    named = {spelling: name for root, name in roots
             for spelling in (str(Path(root)), str(Path(root).resolve()))}
    # Longest first, so a root that is a prefix of the other's spelling cannot cut it in two.
    for spelling in sorted(named, key=len, reverse=True):
        text = text.replace(spelling, named[spelling])
    one_line = " ".join(text.split())
    return one_line if len(one_line) <= REASON_MAX else one_line[:REASON_MAX - 1] + "…"


__all__ = [
    "AdapterBroken",
    "Down",
    "NoUsableSystem",
    "NotConfigured",
    "StartCause",
    "Tripped",
    "cause_text",
    "down_cause",
    "down_notes",
    "granted_systems",
    "held_refusal",
    "hold_at_start",
    "mark_escaped",
    "message_for",
    "refusal_if_down",
    "require_usable",
    "startup_check",
]
