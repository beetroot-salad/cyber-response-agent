"""The close tool: the only writer of a run's closing record (#1534), the row in the run's session
database that makes the close final. Every disposition but the host's own
`unresolved` passes the live write-time challenge gate before it commits (a confident one
against its conclusion, `inconclusive` against its ceiling claim).

`close_investigation` is the sync host-level close; `_tool_close_investigation` is the async
model-facing adapter. Both share `_close_investigation_async`, so the tool never nests
`asyncio.run` inside a running loop.

The tool is registered at MAIN's composition root only (a verb grant cannot express this), and
role admission is also checked host-side, so a direct call from another role is refused too.
"""

from __future__ import annotations

import asyncio
import logging
import sqlite3
from defender._model import model
from defender.records import RunPaths, closing
from defender.records import session_store
from pathlib import Path
from typing import Annotated, Any

from pydantic import Field
from pydantic_ai import RunContext
from pydantic_ai.exceptions import ModelRetry

from defender._untrusted import wrap_fresh
# The set is for the exact membership test, the ordered tuple for the argument schema.
from defender._vocab import (
    CEILING_DISPOSITION, DISPOSITION_ENUM, DISPOSITION_VALUES, HOST_ONLY_DISPOSITION,
)
from defender.records.closing import (  # noqa: F401 — re-exported: the vocabulary lives with the record
    CAUSE_CEILING_EXAMINED, CAUSE_EVIDENCE_CANNOT_DISCRIMINATE, CAUSE_NOT_REVIEWED, CAUSE_NOTHING_LEFT_TO_ASK,
    CAUSE_REVIEW_INCOMPLETE, CAUSE_STORY_SETTLED, CAUSE_TURN_BUDGET_SPENT, CAUSES, FAILURE_KINDS,
    FORCED_INCONCLUSIVE, OUTCOMES, STAGE_ERROR, STANDS, TIMEOUT, UNREADABLE,
)
from defender.hooks.budget_enforcer import BUDGET_EXEMPT_TOOLS  # noqa: F401 — re-export
from defender.skills.invlang.parser import parse_dense_companion
from defender.skills.invlang.schema import CompanionBody
from defender.skills.invlang.validate import (
    CeilingReceipt,
    RuntimeEvidenceReceipt,
    conclude_ceiling_test_rows,
    conclude_runtime_evidence_rows,
    entry_bound_refusals,
    entry_price,
)

from . import challenge_gate
from . import tools as tools_mod
from .tools import CompanionRead
from defender._agent_role import AgentRole
from .tools import AgentDeps
from defender.investigation.tools._deps import run_of

_logger = logging.getLogger(__name__)

# Two outcome vocabularies: `CLOSE_RETURNS` is what a close attempt did (the tool's return and
# the review record's `verdict`); `closing.OUTCOMES` is what a closing record can record. The
# challenged path returns before the write, so it never reaches the database. The committed
# vocabularies (outcomes, causes, failure kinds) live with the record (`records.closing`).

#: The investigation continues: nothing is committed and the discriminating material comes back.
CHALLENGED = "challenged"

CLOSE_RETURNS: tuple[str, ...] = (CHALLENGED, STANDS, FORCED_INCONCLUSIVE)

#: Dispositions never reviewed: only the host's own `unresolved`, which describes the run (cut
#: short, overruled, machinery broke) rather than claiming anything about the world.
#: `inconclusive` is reviewed, since its ceiling claim is something the review can judge.
#: Matched by value, not by `forced` (see the dispatch site).
NO_REVIEW_DISPOSITIONS: tuple[str, ...] = (HOST_ONLY_DISPOSITION,)

#: The older names of the record's vocabularies, kept for callers that still spell them.
REPORT_CAUSES = CAUSES
COMMITTED_OUTCOMES = OUTCOMES

#: The challenged attempt commits nothing, so it has no cause.
NO_CAUSE = ""


class NoSessionStore(RuntimeError):
    """A close was called on deps that carry no open session store: a wiring fault (the driver
    hands MAIN's deps the run's store), never a retryable refusal."""


@model(frozen=True)
class RecommendedLead:
    """One thing the review wants measured before the close can stand.

    `target` may name an entity, edge, lead or hypothesis (checked against
    `reply.citable_refs`), hence not `lead_id`."""

    target: str
    ask: str
    origin: str


@model(frozen=True)
class CloseResult:
    """What one close attempt did.

    `cause` is the host's own sentence and is what the closing record carries. `detail` is the
    diagnostic, which may quote a stage, so it goes on the review record, never the record."""

    outcome: str
    message: str
    material: tuple[RecommendedLead, ...]
    record_path: Path | None
    cause: str
    detail: str
    turns_used: int = 0
    failure_kind: str | None = None


def _render_challenged_message(material: tuple[RecommendedLead, ...], deps: AgentDeps) -> str:
    """The challenged arm's hand-back, which always carries at least one measurement."""
    assert material, "the challenged arm never returns without discriminating material"
    lines = [f"- {item.target}: {item.ask}" for item in material]
    # Derived from a payload-influenced role's output, so framed as untrusted with a fresh salt
    # no party (the review role included) has seen.
    framed = wrap_fresh("\n".join(lines), "untrusted")
    # "measurement", not "lead": the target may be a vertex, which is not something to run.
    return (
        f"The gate challenged this close — {len(material)} measurement(s) remain before it "
        f"can stand. Investigate further before re-closing:\n{framed}"
    )


def _record_dict(
    verdict: challenge_gate.GateVerdict, disposition: str, *, reviewed: bool,
) -> dict:
    """The numbered review record, built by one function for both bypass and reviewed sites.

    `detail` lives here, framed, rather than on the closing record: it may quote a stage, and no prompt
    reads this record verbatim. `reviewed` is written explicitly because readers cannot
    reliably infer it (a reviewed and a bypassed close can share one disposition)."""
    return {
        "verdict": verdict.outcome,
        "reviewed_disposition": disposition,
        "reviewed": reviewed,
        "detail": wrap_fresh(verdict.detail, "untrusted") if verdict.detail else "",
        "failure_kind": verdict.failure_kind,
    }


@model(frozen=True)
class _CloseFields:
    """The scalar fields `_commit` needs beyond `deps`/`disposition`/`record`, bundled so the
    function stays under the arg-count lint."""

    outcome: str
    cause: str
    detail: str
    material: tuple[RecommendedLead, ...]
    turns_used: int
    failure_kind: str | None
    #: The parse the close made for the entry price, which the record is built from; `None` for
    #: the overrule of an unreadable document, which has none.
    companion: CompanionBody | None = None


def _fields_from(
    verdict: challenge_gate.GateVerdict, *,
    material: tuple[RecommendedLead, ...] = (),
    companion: CompanionBody | None = None,
) -> _CloseFields:
    """The verdict's scalars as the commit bundle, shared by all three commit sites so a new
    field cannot be forgotten at one. The parse comes from the caller."""
    return _CloseFields(
        outcome=verdict.outcome, cause=verdict.cause, detail=verdict.detail,
        material=material, turns_used=verdict.turns_used, failure_kind=verdict.failure_kind,
        companion=companion,
    )


def _commit(
    deps: AgentDeps, disposition: str, fields: _CloseFields, record: dict, *, drafted: str,
) -> CloseResult:
    """Write the review record, then the closing record; both are attempted, and only the closing
    record's fault is raised, after both. A review-record fault is logged, never raised (#1342
    M2: terminality follows the closing record alone): raised beside a committed record, it would
    end the run as a crash after its close was final.

    `drafted` is the disposition the close was called with: the record names it when the host
    overrode it. `fields.detail` (which may quote a stage) reaches only the review record, so
    review prose stays out of the judge's prompt and the ticket bridge."""
    store = _store_of(deps)
    state = challenge_gate.ReviewState.of(deps)
    turn_for_record = state.turns + 1

    # Resolving the name can refuse a planted alias with `OSError`; treated like a write fault.
    record_path: Path | None = None
    record_error: BaseException | None = None
    try:
        record_path = RunPaths(deps.run_dir).review_record(turn_for_record)
        challenge_gate.write_review_record(run_of(deps), turn_for_record, record)
    except OSError as e:
        record_error = e

    closing_record = build_record(
        str(run_of(deps).id), disposition, fields,
        drafted=drafted if fields.outcome == FORCED_INCONCLUSIVE else None,
    )
    write_error: BaseException | None = None
    try:
        # The store's ordinary busy timeout, not the ledger's short one: a close waits out
        # another connection's write rather than failing.
        session_store.write_closing_record(store, closing_record)
    except (sqlite3.Error, session_store.StoreError) as e:
        write_error = e

    # Terminality follows the closing record alone: once it is committed the close is final,
    # even if the review record write failed, so a retry cannot re-run the gate.
    if write_error is None:
        state.closed = True
        state.disposition = disposition

    if record_error is not None:
        # Logged, never raised (#1342 r4 M2): the closing record alone decides the close.
        _logger.error(f"the review record of turn {turn_for_record} could not be written "
                      f"({record_error!r})"
                      + ("" if write_error is not None
                         else "; the closing record is committed and the close stands"))
        record_path = None
    if write_error is not None:
        raise write_error
    return CloseResult(
        outcome=fields.outcome, message=f"closed: {fields.outcome} (disposition={disposition})",
        material=fields.material, record_path=record_path, cause=fields.cause,
        detail=fields.detail, turns_used=fields.turns_used,
        failure_kind=fields.failure_kind,
    )


def _store_of(deps: AgentDeps) -> Any:
    """The run's open session store, which the driver hands MAIN's deps; none is a wiring fault."""
    store = deps.session_store
    if store is None:
        raise NoSessionStore(
            "the close was called on deps that carry no session store: the run's driver hands its "
            "open store to MAIN's deps, and a close cannot be final without it")
    return store


def build_record(run_id: str, disposition: str, fields: _CloseFields, *, drafted: str | None) -> closing.ClosingRecord:
    """The closing record of one close: the host's values, the entries and summary built from the
    close's own parse (none for the overrule of an unreadable document).

    Every model-text field is treated to its bound by the record types. The entries are kept in
    order while each column stays within its count cap and aggregate bound: for a document the
    gates passed this changes nothing; only the host's forced close, which skips the gates over a
    box-writable document, is ever cut. The build never refuses on size."""
    companion = fields.companion
    ceiling: tuple[CeilingReceipt, ...] = conclude_ceiling_test_rows(companion) if companion is not None else ()
    baselines: tuple[RuntimeEvidenceReceipt, ...] = (
        conclude_runtime_evidence_rows(companion) if companion is not None else ())
    return closing.ClosingRecord(
        run_id=run_id, disposition=disposition, outcome=fields.outcome, cause=fields.cause,
        failure_kind=fields.failure_kind, drafted_disposition=drafted,
        ceiling_test=_ceiling_entries(ceiling), runtime_evidence=_baseline_entries(baselines),
        summary=_record_summary(disposition, fields, companion),
    )


def _ceiling_entries(receipts: tuple[CeilingReceipt, ...]) -> tuple[closing.CeilingEntry, ...]:
    kept: list[closing.CeilingEntry] = []
    for receipt in receipts:
        if len(kept) == closing.CEILING_COUNT_CAP:
            break
        try:
            entry = closing.CeilingEntry(state=receipt.state, ref=receipt.ref, cap=receipt.cap, note=receipt.note)
        except ValueError as refused:
            _dropped("ceiling receipt", receipt.raw, refused)
            continue
        if closing.ceiling_lines_length((*kept, entry)) > closing.CEILING_LINES_BOUND:
            break
        kept.append(entry)
    return tuple(kept)


def _baseline_entries(receipts: tuple[RuntimeEvidenceReceipt, ...]) -> tuple[closing.BaselineEntry, ...]:
    kept: list[closing.BaselineEntry] = []
    for receipt in receipts:
        try:
            entry = closing.BaselineEntry(
                lead=receipt.resolved_by_lead, anchor_kind=receipt.anchor_kind, grounding_kind=receipt.grounding_kind,
                anchor_id=receipt.anchor_id, window_start=closing.canonical_instant(receipt.window_start),
                window_end=closing.canonical_instant(receipt.window_end), result=receipt.result,
                reasoning=receipt.reasoning)
        except ValueError as refused:
            _dropped("baseline", receipt.window, refused)
            continue
        if closing.baseline_lines_length((*kept, entry)) > closing.BASELINE_LINES_BOUND:
            break
        kept.append(entry)
    return tuple(kept)


def _dropped(what: str, row: str, refused: ValueError) -> None:
    """A row the walkers accepted that the record's own vocabulary refuses (only reachable on the
    forced close, which skips the gates that check it): dropped, never a failed build."""
    _logger.warning(f"the closing record drops a {what} its vocabulary refuses ({row!r}): {refused}")


#: The `:T conclude` rows a summary is built from, in order.
_SUMMARY_PIECES = ("summary", "detection_notes", "ceiling_rationale")


def _record_summary(disposition: str, fields: _CloseFields, companion: CompanionBody | None) -> str | None:
    """`:T conclude`'s summary, detection notes and ceiling rationale, each trimmed, the absent
    skipped, joined by one space; an `unresolved` record opens with its cause's opener. `None`
    when there is nothing to build from and the record is not `unresolved`. Treated (and cut to
    the summary bound) by the record."""
    conclude = (companion or {}).get("conclude") or {}
    pieces = [text.strip() for key in _SUMMARY_PIECES
              if isinstance(text := conclude.get(key), str) and text.strip()]
    if disposition == HOST_ONLY_DISPOSITION:
        pieces.insert(0, closing.OPENERS[(fields.cause, fields.failure_kind)])
    return " ".join(pieces) or None


async def _close_investigation_async(
    deps: AgentDeps, disposition: str, *, stages: Any, bounds: challenge_gate.Bounds,
    forced: bool = False,
) -> CloseResult:
    """The close shared by the sync host entry and the async tool."""
    if deps.role is not AgentRole.MAIN:
        raise ModelRetry(
            "close_investigation is reachable only from the investigator (main) role — "
            f"not from {deps.role.value}"
        )
    # A wiring fault, before any gate or review: a close that cannot write its record must not
    # spend a review first.
    _store_of(deps)
    # `isinstance(str)` first: an unhashable value would raise out of the set membership test.
    # The sync host entry has no pydantic validation in front of it.
    #
    # lint-vocabulary: ok — live write gate: an exact test gives the author actionable retry
    # text, while normalizing would accept a zero-width-laced value and write it into the
    # closing record.
    if not (isinstance(disposition, str) and disposition in DISPOSITION_ENUM):
        # The ordered tuple, matching the tool schema's order the model sees in the same turn.
        raise ModelRetry(
            f"disposition must be exactly one of {list(DISPOSITION_VALUES)} (got "
            f"{disposition!r}) — a typed enum, not free text"
        )
    _refuse_if_host_only_verdict_misused(disposition, forced=forced)
    # A committed close is terminal, refused before the gate so a second attempt cannot spend a
    # review or overwrite the first disposition and its review record.
    state = challenge_gate.ReviewState.of(deps)
    if state.closed:
        raise ModelRetry(
            f"this investigation is already closed — {state.disposition!r} is committed and "
            "the close is terminal. Re-closing would re-run the whole review and overwrite "
            "both the recorded disposition and the first close's own review record."
        )
    # Document gates run before any disposition branch, so no branch dodges them and no review
    # is spent on a close that will be refused. The forced close is exempt (see docstring).
    read = tools_mod.read_companion(deps)
    # An unreadable companion is decided once here, ahead of every gate:
    #   * an I/O fault is refused (retryable); overruling would let one transient fault
    #     terminally replace a settled verdict with `unresolved`.
    #   * undecodable bytes or a planted entry will not change on retry, so the model's close
    #     is overruled to `unresolved` as a review that cannot run.
    # The forced close proceeds off an empty document, since refusing it would leave no record.
    if read.text is None and not forced:
        if read.retryable:
            raise ModelRetry(
                f"close blocked: `investigation.md` could not be read ({read.refusal}). A "  # lint-run-records: ok — a message naming the record for the model or operator, not a path
                f"close is not permitted while the gate cannot look — retry."
            )
        return _overrule_unreadable_companion(deps, read, disposition)
    text = _document_or_empty(read)
    if not forced and (flagged := tools_mod.flagged_in(read)):
        raise ModelRetry(tools_mod.flagged_write_refusal(
            "close_investigation", flagged, offered_text=False,
        ))
    # The entry price, also collected at the `investigation.md` write gate. After the
    # terminal-close refusal, and before the review so an unpaid close spends none.
    companion = _refuse_if_entry_price_is_owed(text, disposition, forced=forced)
    # The close publishes against this document, so it meets the full invlang schema like
    # every other write. Deliberately after the price gate: the full validator includes rules
    # keyed on the disposition the document declares, which would otherwise shadow the more
    # specific price the model can actually pay.
    if not forced and (structure := tools_mod.committed_document_refusal(read)) is not None:
        raise ModelRetry(structure)
    # Only `unresolved` skips the review: it describes the run, not the world. Keyed on value,
    # not `forced`, because a forced close can carry a confident verdict that must be reviewed.
    if disposition in NO_REVIEW_DISPOSITIONS:
        # No review ran, so `detail` is empty. The record still carries the entries the walkers
        # accept from the parse (OD8): the forced close skipped the document gates, so the
        # builder cuts its text to the bounds rather than refusing it.
        unreviewed = challenge_gate.GateVerdict(
            outcome=STANDS, disposition=disposition, cause=CAUSE_NOT_REVIEWED, detail="",
            material=(), turns_used=0, failure_kind=None,
        )
        return _commit(
            deps, disposition, _fields_from(unreviewed, companion=companion),
            _record_dict(unreviewed, disposition, reviewed=False), drafted=disposition,
        )

    verdict = await challenge_gate.challenge_gate(
        deps, disposition, companion, stages=stages, bounds=bounds,
    )
    material = tuple(
        RecommendedLead(target=target, ask=ask, origin="review")
        for target, ask in verdict.material
    )
    record = _record_dict(verdict, disposition, reviewed=True)

    if verdict.outcome == CHALLENGED:
        turn = state.turns  # already incremented inside challenge_gate for this attempt
        record_path = RunPaths(deps.run_dir).review_record(turn)
        challenge_gate.write_review_record(run_of(deps), turn, record)
        return CloseResult(
            outcome=CHALLENGED, message=_render_challenged_message(material, deps),
            material=material, record_path=record_path, cause=verdict.cause,
            detail=verdict.detail, turns_used=verdict.turns_used,
            failure_kind=verdict.failure_kind,
        )

    # The post-review site: the ceiling receipts and baselines of the parse ride on every
    # committed disposition (OD8), an override to `unresolved` included.
    fields = _fields_from(verdict, material=material, companion=companion)
    return _commit(deps, verdict.disposition, fields, record, drafted=disposition)


def close_investigation(
    deps: AgentDeps, disposition: str, *, stages: Any, bounds: challenge_gate.Bounds | None = None,
) -> CloseResult:
    """The sync host-level close; one of the two boundaries (with `run_investigation`) that
    resolves the gate's bounds. Never call this from inside a running event loop."""
    # lint-default: ok — boundary entry point with no resolved value threaded to it; resolved
    # once and threaded inward.
    resolved = bounds if bounds is not None else challenge_gate.default_bounds()
    return asyncio.run(_close_investigation_async(deps, disposition, stages=stages, bounds=resolved))


async def _tool_close_investigation(
    deps: AgentDeps, disposition: str, *, stages: Any, bounds: challenge_gate.Bounds,
) -> str:
    result = await _close_investigation_async(deps, disposition, stages=stages, bounds=bounds)
    return result.message


def _document_or_empty(read: CompanionRead) -> str:
    """The text the close's gates judge; empty for the forced close over an unreadable
    companion (the model's close is overruled before this). Logged here because the reader
    itself runs on every request and stays silent."""
    if read.text is None:
        _logger.warning(
            f"forced close: `investigation.md` could not be read ({read.refusal}); "  # lint-run-records: ok — a message naming the record for the model or operator, not a path
            f"closing the host's own verdict off an empty document rather than dead-lettering "
            f"the run",
        )
        return ""
    return read.text


def _overrule_unreadable_companion(
    deps: AgentDeps, read: CompanionRead, disposition: str,
) -> CloseResult:
    """Commit the model's close over a companion no retry will make readable as a review that
    cannot run: the host's `unresolved`, with no parse, so no entries and the opener alone."""
    verdict = challenge_gate.review_cannot_run(
        deps, read.refusal or "investigation.md could not be read",  # lint-run-records: ok — a message naming the record for the model or operator, not a path
    )
    return _commit(
        deps, verdict.disposition, _fields_from(verdict),
        _record_dict(verdict, disposition, reviewed=True), drafted=disposition,
    )


def _refuse_if_host_only_verdict_misused(disposition: str, *, forced: bool) -> None:
    """Refuse `unresolved` from the model and `inconclusive` from the forced close.

    `unresolved` is the host's own verdict for a run that ended without a settled finding;
    the tool schema offers it (derived from the full vocabulary) but the model may not commit
    it. `inconclusive` carries an entry price a forced caller cannot pay, having no model left
    to repair with. Checked before the price gate and the review, which a refused call skips.
    """
    if disposition == HOST_ONLY_DISPOSITION and not forced:
        raise ModelRetry(
            f"disposition {HOST_ONLY_DISPOSITION!r} is recorded by the host when a run "
            "terminates without a settled finding — a gate overrule, a review that could not "
            "complete, or the close of a run cut short. Report what you could not settle as "
            "'inconclusive' instead, naming the gap; the investigating model never commits "
            f"{HOST_ONLY_DISPOSITION!r} itself."
        )
    if forced and disposition == CEILING_DISPOSITION:
        raise ModelRetry(
            "a forced close must not commit 'inconclusive' — that verdict is reserved for the "
            "investigating model's own close and now carries an entry price a forced caller "
            f"cannot pay. Use {HOST_ONLY_DISPOSITION!r} instead."
        )


def _refuse_if_entry_price_is_owed(
    text: str, disposition: str, *, forced: bool = False,
) -> CompanionBody:
    """Collect the structural price this close's disposition owes, refuse if unpaid, and return
    the parsed `investigation.md` it was read from."""
    try:
        companion, _warnings = parse_dense_companion(text)
    except Exception as exc:
        if not forced:
            raise ModelRetry(
                f"close blocked: `investigation.md` could not be parsed to check the entry "  # lint-run-records: ok — a message naming the record for the model or operator, not a path
                f"price your disposition may owe ({type(exc).__name__}: {exc}). Repair the "
                f"document — a close is not permitted while the gate cannot look."
            ) from exc
        _logger.warning(
            f"forced close: `investigation.md` could not be parsed "  # lint-run-records: ok — a message naming the record for the model or operator, not a path
            f"({type(exc).__name__}: {exc}); pricing the host's own verdict off an empty "
            f"document rather than dead-lettering the run",
        )
        companion = CompanionBody()
    try:
        price = entry_price(disposition, companion)
    except ModelRetry:
        raise
    except Exception as exc:
        raise ModelRetry(
            f"close blocked: `investigation.md` could not be priced for the entry price your "  # lint-run-records: ok — a message naming the record for the model or operator, not a path
            f"disposition may owe ({type(exc).__name__}: {exc}). Repair the document — a "
            f"close is not permitted while the gate cannot look."
        ) from exc
    if price:
        # One owed string per line: a real log can owe dozens.
        raise ModelRetry("close blocked: " + price.rationale + "\n" + "\n".join(price.owed))
    # The entry bounds, beside the price and for every disposition (OD16): the record's builder
    # then changes nothing for a model close. The forced close skips them; its builder cuts.
    if not forced and (oversized := entry_bound_refusals(companion)):
        raise ModelRetry("close blocked: the closing record's entries are over their bounds\n"
                         + "\n".join(oversized))
    return companion


#: The `disposition` argument as the model is offered it: a plain `str` with the vocabulary in
#: its JSON schema, derived from `DISPOSITION_VALUES`. (`SKILL.md` §REPORT enumerates the
#: members by hand and must be updated separately.)
#:
#: `json_schema_extra`, not a `StrEnum` or `Literal`, so pydantic does not validate it and the
#: exact test in `_close_investigation_async` stays the sole rejecter. Pydantic's own error
#: would echo an invisible character raw (`input: "beni<U+200B>gn"`) instead of our
#: repr-escaped retry text.
DispositionArg = Annotated[str, Field(json_schema_extra={"enum": list(DISPOSITION_VALUES)})]


def register_close_tool(agent, *, stages: Any, bounds: challenge_gate.Bounds) -> None:
    """Called only from MAIN's composition root, when its effective `ToolSet.close` is on."""

    # `sequential=True`: two close calls in one model response would otherwise run
    # concurrently, both pass the already-closed check (set only after the write), and the
    # second would spend a review only to be refused its record.
    @agent.tool(sequential=True)
    async def close_investigation(
        ctx: RunContext[AgentDeps], disposition: DispositionArg
    ) -> str:
        """Commit this investigation's disposition once ANALYZE has reached a confident
        finding, or once you have run out of data and the case is `inconclusive`.
        `disposition` is a closed enum whose members are in this tool's own schema, never free
        text, and the value is compared EXACTLY — a near miss is refused rather than guessed
        at, so send the keyword with nothing around it. See SKILL §REPORT for what each one
        claims and what it costs: the `detection_notes` + `entity_check` rows `false-positive`
        requires in `:T conclude`, and the planned process gap, refuted alternatives and
        `within` impact grades `unsanctioned-benign` requires. This is the ONLY way to record
        the disposition — no file write can. A confident disposition, or `inconclusive`, passes a live challenge
        gate before it commits — against the conclusion or against the ceiling claim
        respectively; if the gate is not satisfied yet, this call returns without committing
        and the investigation continues for another ANALYZE/GATHER turn."""
        return await _tool_close_investigation(ctx.deps, disposition, stages=stages, bounds=bounds)


__all__ = [
    "BUDGET_EXEMPT_TOOLS",
    "CAUSE_CEILING_EXAMINED",
    "CAUSE_EVIDENCE_CANNOT_DISCRIMINATE",
    "CAUSE_NOTHING_LEFT_TO_ASK",
    "CAUSE_NOT_REVIEWED",
    "CAUSE_REVIEW_INCOMPLETE",
    "CAUSE_STORY_SETTLED",
    "CAUSE_TURN_BUDGET_SPENT",
    "CAUSES",
    "CHALLENGED",
    "CLOSE_RETURNS",
    "COMMITTED_OUTCOMES",
    "FAILURE_KINDS",
    "FORCED_INCONCLUSIVE",
    "NO_CAUSE",
    "NO_REVIEW_DISPOSITIONS",
    "REPORT_CAUSES",
    "STAGE_ERROR",
    "STANDS",
    "TIMEOUT",
    "UNREADABLE",
    "CloseResult",
    "DispositionArg",
    "NoSessionStore",
    "RecommendedLead",
    "build_record",
    "close_investigation",
    "register_close_tool",
]
