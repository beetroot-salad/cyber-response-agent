"""Harness-executed lead-0: the work the harness does before MAIN's first ORIENT turn.

It resolves the alert's ancestor documents (item 1) and dispatches one tightly-bounded
correlation gather lead (item 3), both under the reserved ids ``l-000``/``l-00c`` so the
learning loop and the review gate cite them like any model-dispatched lead. ``orient.py``
stays a pure text-assembler that formats the returned block as an ORIENT section.

  * `_spec`    — ids, statuses and field names.
  * `_capture` — issuing a call and recording it (budget gate, call ledger, `:L` row).
  * `_render`  — turning documents into the section the model reads.
  * `_items`   — ancestor resolution and correlation.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import sys
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from defender._io import read_jsonl_rows, read_text_soft
from defender.run_repository import RunPaths
from defender._untrusted import wrap_fresh
from defender.hooks.budget_enforcer import (
    DEFAULT_LIMITS,
    BudgetKill,
    read_budget,
    tail_exhausted,
    update_budget_locked,
)
from defender.hooks.record_lead import ALREADY_CLAIMED, CLAIMED, claim_lead
from defender.runtime import circuit_breaker
from defender.runtime.verb_grant import GrantError, VerbGrant
from defender.runtime.verbs import VerbContext
from ._spec import (
    ALERT_ID_FIELD,
    BUILDING_BLOCK_FIELD,
    CORRELATION_REQUEST_LIMIT,
    ELIDED,
    GROUP_ID_FIELD,
    HARNESS_PROVENANCE,
    ITEM1_GOAL,
    ITEM1_SYSTEM,
    ITEM1_WHAT_TO_SUMMARIZE,
    L0,
    L3,
    LEAD_ZERO_HEADING,
    MESSAGE_CHAR_BUDGET,
    PROVENANCE_KEY,
    RESERVED_LEAD_IDS,
    SHORTFALL,
    STATUS_EMPTY,
    STATUS_FAILED,
    STATUS_RESOLVED,
    STATUS_TRUNCATED,
    UNAVAILABLE,
    _ANY_RUN_TAG,
    _FENCE_RUN,
    correlation_grant,
    correlation_system,
)
from ._agreement import (
    CorrelationDispatch,
    CorrelationDispatchError,
    resolve_correlation_dispatch,
)
from ._capture import (
    LeadZeroResult,
    _CallLedger,
    _CaptureDeps,
    _UNMAPPED_FAULT_EXIT,
    _breaker_failures,
    _budget_account,
    _budget_gate,
    _build_deps,
    _capture_issue,
    _declare_l_finding,
    _last_row_seq,
    _record_manual_row,
    _rows_for,
    _run_sync,
    _sanitize,
)
from ._render import (
    _elide,
    _flatten_doc,
    _render_doc,
    _sort_chrono,
    _unavailable,
)
from ._items import (
    _DS_RE,
    _correlation_contract,
    _fetch_batched,
    _map_backing_index,
    _resolve_item1,
    dispatch_correlation,
)

_logger = logging.getLogger(__name__)


def prepare_correlation_lead(
    run_dir: Path, alert: dict, ancestor_block: str, status: str,
    *, dispatch: CorrelationDispatch,
) -> tuple[str, list[str]] | None:
    """The synchronous half of item 3: gate on item 1's status (RESOLVED or TRUNCATED), build
    the contract, and claim `l-00c`'s leads row before MAIN's first turn. Returns
    `(goal, what_to_summarize)` when item 3 should dispatch, else `None`.

    `dispatch.system is None` (the table grants the lead no query verb) is checked first, so a
    lead that will never run never owns a leads row. The system and template id come from
    `dispatch`, the run-start check's result. `ancestor_block` is `LeadZeroResult.text`, so the
    lead reads the same bytes MAIN reads."""
    if dispatch.system is None:
        return None
    if status not in (STATUS_RESOLVED, STATUS_TRUNCATED):
        return None
    contract = _correlation_contract(alert, ancestor_block, dispatch.template_id)
    if contract is None:
        return None
    goal, what = contract
    claimed = claim_lead({
        "run_dir": str(run_dir), "lead_id": L3, "goal": goal,
        "what_to_summarize": what, "provenance": HARNESS_PROVENANCE,
    })
    if claimed != CLAIMED:
        # A collision or a failed write: this frame owns nothing, so it does nothing.
        return None
    _declare_l_finding(run_dir, L3, "correlation lead", dispatch.system)
    return goal, what


# the wrap + section assembly

def _render_section(body: str) -> str:
    """Item 1's whole block inside one untrusted frame. The trusted heading is prepended
    separately by `render_orient_section`."""
    return wrap_fresh(body, "untrusted")


def render_orient_section(
    result: LeadZeroResult, run_dir: Path | None = None,
    *, correlation_system: str | None, grant_home: str,
) -> str:
    """The ORIENT section: a trusted heading naming the reserved ids, then item 1's untrusted
    frame unmodified.

    With `run_dir`, the heading checks the document for `L0`'s declaring row: the seed may have
    refused to write it, and "do not reuse" would then trap MAIN into an `undeclared lead`
    refusal whose only fix is writing that row. Checked on disk rather than via a flag so it
    cannot go stale. `None` (tests only) omits the check; production passes a dir even on the
    degraded arm, where the seed most likely never ran.

    `correlation_system is None` means the table grants the correlation lead no query verb, so
    `L3` will never run and the heading says so, pointing at `grant_home` (the tenant and file,
    never a host path). It has no default because it is per-run (per-tenant)."""
    heading = (
        f"{LEAD_ZERO_HEADING} (resolved by the harness before your first turn — reserved "
        f"lead ids {L0} (this resolution) and {L3} (a correlation lead dispatched off it, "
        "if any) are already claimed; do not attach new work to them"
    )
    if run_dir is not None and not _is_declared(run_dir, L0):
        heading += (
            f". NOTE: {L0}'s declaring `:L findings` row is NOT in investigation.md — the "  # lint-run-records: ok — a message naming the record for the model or operator, not a path
            f"harness could not write it. If you cite {L0}, declare it yourself in a `:L "
            f"findings` block first; that is not reuse"
        )
    if correlation_system is None:
        heading += (
            f". NOTE: {L3} was NOT dispatched on this run — the verb-disposition table "
            f"({grant_home}) grants the correlation lead no query verb (withheld, or "
            "never decided for it), so no correlation was run and none is coming"
        )
    return heading + ")\n\n" + result.text


def _is_declared(run_dir: Path, lead_id: str) -> bool:
    """Is `lead_id`'s declaring `:L findings` row on the page right now?

    Uses the real parser and the validator's definition (`_check_lead_refs`): a findings entry
    with a name. A bare `:R` reference also creates an entry, just without a name, and must not
    count, or the prompt would contradict the refusal.

    Fails open (returns True) on an unparseable document: this is prompt text, not a gate, and
    other gates already refuse such a document."""
    from defender.skills.invlang.parser import parse_dense_companion

    path = RunPaths(run_dir).investigation
    if not path.is_file():
        return False
    try:
        companion, _warnings = parse_dense_companion(path.read_text(encoding="utf-8"))  # lint-whole-read: ok — investigation.md: host writers go through validate_artifact (64 KiB cap, INVESTIGATION_FILE_MAX); box-writable in the rw run dir, bounded by the box fsize limit; per-run driver
    except Exception as e:  # noqa: BLE001 — prompt prose must not decide a run's fate
        _logger.warning(f"could not check whether {lead_id} is declared: {e!r}")
        return True
    return any(
        f.get("id") == lead_id and f.get("name")
        for f in companion.get("findings", [])
    )


# the entry point

def resolve_lead_zero(
    *, run_dir: Path, defender_dir: Path, alert_path: Path, verbs: Any,
    limits: dict = DEFAULT_LIMITS, run_id: str | None = None, tenant: Any,
    env: Mapping[str, str],
) -> LeadZeroResult:
    """Item 1's resolution, over the run's record (`tenant`, #1107) and the run's env (`env`,
    built once by the driver and handed in: nothing in this package builds or reads the
    environment itself). The tenant's alerts-index fallback reads the record's corpus-engine view."""
    run_dir = Path(run_dir)
    defender_dir = Path(defender_dir)
    resolved_run_id = run_id or run_dir.name

    if verbs is None:
        unavailable_text = _render_section(
            _unavailable("no verb registry was injected into this run"))
        return LeadZeroResult(text=unavailable_text, status=STATUS_FAILED)

    alert_text, err = read_text_soft(Path(alert_path))
    if alert_text is None:
        body = _unavailable(f"could not read the alert: {err}")
        return LeadZeroResult(text=_render_section(body), status=STATUS_FAILED)
    try:
        alert = json.loads(alert_text)
    except (ValueError, TypeError) as e:
        body = _unavailable(f"the alert is not valid JSON: {e!r}")
        return LeadZeroResult(text=_render_section(body), status=STATUS_FAILED)
    if not isinstance(alert, dict):
        body = _unavailable("the alert is not a JSON object")
        return LeadZeroResult(text=_render_section(body), status=STATUS_FAILED)

    from ..query_tool import QueryCapture

    capture = QueryCapture(verbs, "gather")

    async def _go():
        try:
            return await _resolve_item1(
                run_dir=run_dir, defender_dir=defender_dir, run_id=resolved_run_id,
                alert=alert, capture=capture, env=dict(env), limits=limits,
                tenant=tenant,
            )
        except (BudgetKill, circuit_breaker.RunAborted, asyncio.CancelledError,
                KeyboardInterrupt, GeneratorExit):
            # Control-flow signals propagate; swallowing CancelledError breaks cancellation.
            raise
        except BaseException as e:  # noqa: BLE001 — item 1's own faults degrade, never raise
            return _unavailable(f"{e!r}"), STATUS_FAILED

    body, status = _run_sync(_go())
    return LeadZeroResult(text=_render_section(body), status=status)


#: Re-exports: each name's home is the module it is imported from.

__all__ = [
    "ALERT_ID_FIELD",
    "ALREADY_CLAIMED",
    "Any",
    "BUILDING_BLOCK_FIELD",
    "BudgetKill",
    "CLAIMED",
    "CORRELATION_REQUEST_LIMIT",
    "CorrelationDispatch",
    "CorrelationDispatchError",
    "DEFAULT_LIMITS",
    "ELIDED",
    "GROUP_ID_FIELD",
    "GrantError",
    "HARNESS_PROVENANCE",
    "ITEM1_GOAL",
    "ITEM1_SYSTEM",
    "ITEM1_WHAT_TO_SUMMARIZE",
    "L0",
    "L3",
    "LEAD_ZERO_HEADING",
    "LeadZeroResult",
    "MESSAGE_CHAR_BUDGET",
    "PROVENANCE_KEY",
    "Path",
    "RESERVED_LEAD_IDS",
    "RunPaths",
    "SHORTFALL",
    "STATUS_EMPTY",
    "STATUS_FAILED",
    "STATUS_RESOLVED",
    "STATUS_TRUNCATED",
    "SimpleNamespace",
    "UNAVAILABLE",
    "VerbContext",
    "VerbGrant",
    "_ANY_RUN_TAG",
    "_CallLedger",
    "_CaptureDeps",
    "_DS_RE",
    "_FENCE_RUN",
    "_UNMAPPED_FAULT_EXIT",
    "_breaker_failures",
    "_budget_account",
    "_budget_gate",
    "_build_deps",
    "_capture_issue",
    "_correlation_contract",
    "_declare_l_finding",
    "_elide",
    "_fetch_batched",
    "_flatten_doc",
    "_is_declared",
    "_last_row_seq",
    "_map_backing_index",
    "_record_manual_row",
    "_render_doc",
    "_render_section",
    "_resolve_item1",
    "_rows_for",
    "_run_sync",
    "_sanitize",
    "_sort_chrono",
    "_unavailable",
    "asyncio",
    "circuit_breaker",
    "claim_lead",
    "correlation_grant",
    "correlation_system",
    "dataclass",
    "dispatch_correlation",
    "json",
    "prepare_correlation_lead",
    "re",
    "read_budget",
    "read_jsonl_rows",
    "read_text_soft",
    "render_orient_section",
    "resolve_correlation_dispatch",
    "replace",
    "resolve_lead_zero",
    "sys",
    "tail_exhausted",
    "update_budget_locked",
    "wrap_fresh",
]
