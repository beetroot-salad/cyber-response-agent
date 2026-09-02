"""Harness-executed lead-0.

Before MAIN's first ORIENT turn, the runtime resolves the alert's ancestor documents (item 1)
and dispatches one tightly-bounded correlation gather lead (item 3), both writing into the
run's leads/queries tables under the reserved ids ``l-000``/``l-00c`` so the learning loop and
the review gate cite them like any model-dispatched lead.

This module owns every backend call, run-dir write and dispatch those two items add;
``orient.py`` stays a pure text-assembler that calls ``resolve_lead_zero`` and formats the
returned block as one more ORIENT section.

Turn-zero leads: the work the harness does before the model's first request.

Split into four modules when this file reached 1215 lines:

  * `_spec`    — the ids, statuses and field names turn-zero work is written against.
  * `_capture` — issuing a call and recording what came back, including the budget
                    gate, the per-run call ledger, and the declaring `:L findings` row.
  * `_render`  — turning documents into the section the model actually reads.
  * `_items`   — the two items themselves: ancestor resolution, and correlation.

What stays here is the surface the driver calls: seed the lead, render the section,
resolve turn zero.
"""
from __future__ import annotations

import asyncio
import json
import re
import sys
from dataclasses import dataclass, replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from defender._io import read_jsonl_rows, read_text_soft
from defender._run_paths import RunPaths
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
from defender.runtime.verb_dispositions import DISPOSITIONS_REL
from defender.runtime.verb_grant import GrantError, VerbGrant
from defender.runtime.verbs import VerbContext
from ._spec import (
    ALERT_ID_FIELD,
    BUILDING_BLOCK_FIELD,
    CORRELATION_GRANT,
    CORRELATION_REQUEST_LIMIT,
    CORRELATION_SYSTEM,
    CORRELATION_TEMPLATE,
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


def prepare_correlation_lead(
    run_dir: Path, alert: dict, ancestor_block: str, status: str,
    *, system: str | None = CORRELATION_SYSTEM,
) -> tuple[str, list[str]] | None:
    """The SYNCHRONOUS half of item 3: gate on the resolution status (dispatches on RESOLVED
    and TRUNCATED, never on FAILED/EMPTY), build the harness-authored contract, and claim
    `l-00c`'s leads row BEFORE MAIN's first turn. Returns `(goal, what_to_summarize)` when item
    3 should actually dispatch, else `None`.

    The gate is "item 1 resolved at least one ancestor DOCUMENT" — nothing downstream turns a
    dispatch away for yielding no host/user/source-ip, which would exclude every alert source
    carrying its entities outside those three fields.

    `system` is the dispatch target the table's projection determines (`CORRELATION_SYSTEM`),
    and `None` means the verb-disposition table WITHHELD the lead's query verb (#999). That
    gate sits FIRST, before the contract and before `claim_lead`: a lead that will never run
    must not own a row in the leads table. The parameter exists so a test can state the
    withholding without planting a table into the process-wide cache.

    `ancestor_block` is item 1's rendered block as `LeadZeroResult.text` carries it — already
    sanitized, elided and wrapped — so the lead reads the same bytes MAIN reads at ORIENT."""
    if system is None:
        return None
    if status not in (STATUS_RESOLVED, STATUS_TRUNCATED):
        return None
    contract = _correlation_contract(alert, ancestor_block)
    if contract is None:
        return None
    goal, what = contract
    claimed = claim_lead({
        "run_dir": str(run_dir), "lead_id": L3, "goal": goal,
        "what_to_summarize": what, "provenance": HARNESS_PROVENANCE,
    })
    if claimed != CLAIMED:
        # Someone else already owns this id (a planted collision), or the row could not be
        # written at all — either way this frame owns nothing, so it dispatches nothing and
        # touches the id no further.
        return None
    _declare_l_finding(run_dir, L3, "correlation lead", system)
    return goal, what


# the wrap + section assembly

def _render_section(body: str) -> str:
    """`LeadZeroResult.text`: item 1's rendered block IN ITS ENTIRETY inside ONE
    `wrap_fresh(text, "untrusted")` frame — nothing outside it. The ORIENT heading is a
    separate, TRUSTED line `render_orient_section` prepends; it is not part of the entry
    point's own return value."""
    return wrap_fresh(body, "untrusted")


def render_orient_section(
    result: LeadZeroResult, run_dir: Path | None = None,
    *, correlation_system: str | None = CORRELATION_SYSTEM,
) -> str:
    """The ORIENT-time section text: the trusted heading (naming the reserved ids MAIN must not
    reuse) followed by item 1's whole untrusted frame, unmodified.

    `run_dir` is what lets the heading tell the truth about `L0`. The harness seeds that lead's
    declaring `:L findings` row before this renders, and that seed can decline to write — it
    validates the document first and refuses rather than laundering unvalidated bytes past the
    gate (#964). "Already claimed; do not reuse them" is then a TRAP, and a tight one: MAIN is
    told the id is claimed, cites it, and is refused with `undeclared lead` — for which the
    only repair is to write the very `:L findings` row it reads "do not reuse" as forbidding.
    So when the row is not on the page, say so and say what to do.

    DERIVED FROM THE DOCUMENT, not from a flag the seed sets. Same rule the repair window
    obeys: the answer is a property of the bytes on disk, so it cannot go stale, cannot
    disagree with the file, and is right about a row that went missing some other way. Passed
    `None`, the extra line is simply omitted — the heading is exactly what it was. Both
    production call sites pass a real dir, INCLUDING the degraded arm: a `BudgetKill` or
    `RunAborted` mid-resolution is the case in which the seed most likely never ran at all, so
    an arm that silently dropped the run dir would omit the escape line on precisely the runs
    that need it. `None` is for a caller that genuinely has no run dir — the tests that drive
    this function directly.

    `L3` gets no such line: it is dispatched AFTER this renders and conditionally, so an absent
    row there is the ordinary case and not a fault. Its citation is covered by the validator's
    own refusal, which names the harness-reserved case in its repair text.

    `correlation_system` is the ONE case where `L3`'s absence is not the ordinary one and is
    said: `None` means the verb-disposition table withheld the lead's query verb (#999), so
    the lead was never claimed and never will be, and the heading names the table rather than
    leaving "if any" to explain it. The parameter mirrors `prepare_correlation_lead`'s, for
    the same reason."""
    heading = (
        f"{LEAD_ZERO_HEADING} (resolved by the harness before your first turn — reserved "
        f"lead ids {L0} (this resolution) and {L3} (a correlation lead dispatched off it, "
        "if any) are already claimed; do not attach new work to them"
    )
    if run_dir is not None and not _is_declared(run_dir, L0):
        heading += (
            f". NOTE: {L0}'s declaring `:L findings` row is NOT in investigation.md — the "
            f"harness could not write it. If you cite {L0}, declare it yourself in a `:L "
            f"findings` block first; that is not reuse"
        )
    if correlation_system is None:
        heading += (
            f". NOTE: {L3} was NOT dispatched on this run — the verb-disposition table "
            f"({DISPOSITIONS_REL}) withholds the correlation lead's query verb, so no "
            "correlation was run and none is coming"
        )
    return heading + ")\n\n" + result.text


def _is_declared(run_dir: Path, lead_id: str) -> bool:
    """Is `lead_id`'s declaring `:L findings` row on the page right now?

    Answered through the real parser rather than a substring search: the id appears in prose
    and in a `:R` row's first cell too, and a heading that promised a declaration on the
    strength of either would be wrong in exactly the case it exists to catch.

    DECLARED MEANS WHAT THE VALIDATOR MEANS BY IT — a `:L findings` row carrying a NAME. The
    projector opens a lead bucket for any id it meets, so a bare `:R` reference already puts
    `{"id": lead_id}` in `findings`; keying on the id alone would answer True for exactly the
    citation `_check_lead_refs` is about to refuse as `undeclared lead`, and the heading would
    then withhold the escape line on the one document that needs it. `_check_lead_refs`
    separates the two the same way (`if isinstance(f.get("id"), str) and f.get("name")`), and
    the two readings have to agree or the prompt contradicts the refusal.

    FAILS OPEN — an unreadable or unparseable document returns True, so the extra line is
    omitted. This is prompt text, not a gate: a document nothing can parse is a fault the
    write gate and the close both refuse on their own terms, and guessing "not declared" here
    would bolt a confusing instruction onto a run whose real problem is elsewhere."""
    from defender.skills.invlang.parser import parse_dense_companion

    path = RunPaths(run_dir).investigation
    if not path.is_file():
        return False
    try:
        companion, _warnings = parse_dense_companion(path.read_text(encoding="utf-8"))
    except Exception as e:  # noqa: BLE001 — prompt prose must not decide a run's fate
        print(f"[lead_zero] could not check whether {lead_id} is declared: {e!r}")
        return True
    return any(
        f.get("id") == lead_id and f.get("name")
        for f in companion.get("findings", [])
    )


# the entry point (F1)

def resolve_lead_zero(
    *, run_dir: Path, defender_dir: Path, alert_path: Path, verbs: Any,
    limits: dict = DEFAULT_LIMITS, run_id: str | None = None,
) -> LeadZeroResult:
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

    from defender import run_common
    from ..query_tool import QueryCapture

    try:
        env = run_common.run_env(defender_dir, run_dir)
    except Exception:  # noqa: BLE001 — orientation-adjacent work must never break the run
        env = {}

    capture = QueryCapture(verbs, "gather")

    async def _go():
        try:
            return await _resolve_item1(
                run_dir=run_dir, defender_dir=defender_dir, run_id=resolved_run_id,
                alert=alert, capture=capture, env=env, limits=limits,
            )
        except (BudgetKill, circuit_breaker.RunAborted, asyncio.CancelledError,
                KeyboardInterrupt, GeneratorExit):
            # Cancellation/control-flow signals must propagate rather than degrade into a plain
            # "item 1 failed" result: swallowing `CancelledError` here breaks task cancellation
            # semantics for whatever is running this coroutine.
            raise
        except BaseException as e:  # noqa: BLE001 — item 1's own faults degrade, never raise
            return _unavailable(f"{e!r}"), STATUS_FAILED

    body, status = _run_sync(_go())
    return LeadZeroResult(text=_render_section(body), status=status)


#: Everything imported above is a RE-EXPORT: the name's real home is the module it
#: comes from. Kept because a reader already imports it from here.
__all__ = [
    "ALERT_ID_FIELD",
    "ALREADY_CLAIMED",
    "Any",
    "BUILDING_BLOCK_FIELD",
    "BudgetKill",
    "CLAIMED",
    "CORRELATION_GRANT",
    "CORRELATION_REQUEST_LIMIT",
    "CORRELATION_SYSTEM",
    "CORRELATION_TEMPLATE",
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
    "replace",
    "resolve_lead_zero",
    "sys",
    "tail_exhausted",
    "update_budget_locked",
    "wrap_fresh",
]
