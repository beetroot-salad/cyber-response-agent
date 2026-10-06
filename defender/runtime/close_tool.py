"""The close tool: the only writer of report.md. Every disposition but the host's own
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
from collections.abc import Callable
from defender._model import model
from defender.run_repository import RUN_LAYOUT, RunPaths
from pathlib import Path
from typing import Annotated, Any

from pydantic import Field
from pydantic_ai import RunContext
from pydantic_ai.exceptions import ModelRetry

from defender._artifact_schema import validate_artifact
from defender._untrusted import wrap_fresh
# The set is for the exact membership test, the ordered tuple for the argument schema.
from defender._vocab import (
    CEILING_DISPOSITION, DISPOSITION_ENUM, DISPOSITION_VALUES, HOST_ONLY_DISPOSITION,
)
from defender.hooks.budget_enforcer import BUDGET_EXEMPT_TOOLS  # noqa: F401 — re-export
from defender.skills.invlang.parser import parse_dense_companion
from defender.skills.invlang.schema import CompanionBody
from defender.skills.invlang.validate import (
    CeilingReceipt,
    RuntimeEvidenceReceipt,
    ceiling_note_block,
    ceiling_test_block,
    conclude_ceiling_test_rows,
    conclude_runtime_evidence_rows,
    entry_price,
    runtime_evidence_block,
)

from . import challenge_gate
from . import tools as tools_mod
from .tools import CompanionRead
from .agent_role import AgentRole
from .tools import AgentDeps

_logger = logging.getLogger(__name__)

# Two outcome vocabularies: `CLOSE_RETURNS` is what a close attempt did (the tool's return and
# the review record's `verdict`); `COMMITTED_OUTCOMES` is what report.md can record. The
# challenged path returns before the write, so it never reaches disk.

#: The investigation continues: nothing is committed and the discriminating material comes back.
CHALLENGED = "challenged"
#: The drafted disposition is committed unchanged — the gate never ran, or it ran and the
#: counter-story did not survive, or the challenger declined to argue one.
STANDS = "stands"
#: The drafted disposition is overridden to the host's own `unresolved`. (The value's name is
#: kept because fleet queries and run pages key on it.) The cause says which refusal it was.
FORCED_INCONCLUSIVE = "forced-inconclusive"

CLOSE_RETURNS: tuple[str, ...] = (CHALLENGED, STANDS, FORCED_INCONCLUSIVE)
COMMITTED_OUTCOMES: tuple[str, ...] = (STANDS, FORCED_INCONCLUSIVE)

#: Dispositions never reviewed: only the host's own `unresolved`, which describes the run (cut
#: short, overruled, machinery broke) rather than claiming anything about the world.
#: `inconclusive` is reviewed, since its ceiling claim is something the review can judge.
#: Matched by value, not by `forced` (see the dispatch site).
NO_REVIEW_DISPOSITIONS: tuple[str, ...] = (HOST_ONLY_DISPOSITION,)

# How the review failed: the typed, countable half of "why" (the cause is prose and not
# stable enough to count on). `None` whenever the review did not fail, including an override
# the evidence produced. Each member corresponds to a different response.

#: A stage was still pending at its deadline. Capacity: move the bound, or chase the
#: provider's latency.
TIMEOUT = "timeout"
#: A stage call raised, or no reviewer was bound to call. A defect, with a traceback or a
#: missing composition root to chase.
STAGE_ERROR = "error"
#: A stage answered outside its output contract: an unparseable reply, missing fields, or
#: identifiers the investigation never produced. The prompt or contract needs work.
UNREADABLE = "unreadable"

FAILURE_KINDS: tuple[str, ...] = (TIMEOUT, STAGE_ERROR, UNREADABLE)

# The cause: the only strings the frontmatter's `cause` may be. report.md goes verbatim into the
# judge LLM's prompt and out through the ticket bridge, and review stages read
# attacker-influenced data, so the host picks the cause from this closed set. Stage-derived
# diagnostics go in `CloseResult.detail` on the review record, which no prompt reads verbatim.
#
# Coarser than the conditions: where `failure_kind` already separates two conditions, the
# sentence does not separate them again.

CAUSE_NOT_REVIEWED = "the disposition was recorded without a challenge review"
CAUSE_STORY_SETTLED = (
    "the challenge review ran and left nothing about the finding unsettled"
)
#: Shared by a stage that raised or timed out, an unreadable stage reply, and unbound stages;
#: `failure_kind` and the record's `detail` tell them apart.
CAUSE_REVIEW_INCOMPLETE = "the challenge review did not complete"
CAUSE_EVIDENCE_CANNOT_DISCRIMINATE = (
    "the evidence gathered cannot discriminate what the challenge review left unsettled"
)
CAUSE_TURN_BUDGET_SPENT = (
    "the forced-turn budget was spent without settling what the challenge review raised"
)
CAUSE_NOTHING_LEFT_TO_ASK = (
    "nothing discriminating remains that the investigation was not already asked for"
)
#: A composer `holds` on an `inconclusive` close judges the ceiling claim, not a verdict, so it
#: gets its own sentence distinct from `CAUSE_STORY_SETTLED`.
CAUSE_CEILING_EXAMINED = (
    "the challenge review examined the ceiling claim and found nothing further measurable"
)

REPORT_CAUSES: tuple[str, ...] = (
    CAUSE_NOT_REVIEWED,
    CAUSE_STORY_SETTLED,
    CAUSE_REVIEW_INCOMPLETE,
    CAUSE_EVIDENCE_CANNOT_DISCRIMINATE,
    CAUSE_TURN_BUDGET_SPENT,
    CAUSE_NOTHING_LEFT_TO_ASK,
    CAUSE_CEILING_EXAMINED,
)

#: The challenged attempt commits nothing, so it has no cause.
NO_CAUSE = ""

#: The artifact validator the close is handed, defaulting to the real one. Injectable so a test
#: can prove the validator runs on every commit, not only those carrying evidence; the default
#: is the function rather than `None` so validation is never optional.
ArtifactValidator = Callable[[str, str, str | None], str | None]


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

    `cause` is the host's own sentence and is what report.md carries. `detail` is the
    diagnostic, which may quote a stage, so it goes on the review record, never report.md."""

    outcome: str
    message: str
    material: tuple[RecommendedLead, ...]
    record_path: Path | None
    cause: str
    detail: str
    turns_used: int = 0
    failure_kind: str | None = None


def render_report(  # noqa: PLR0913 — the report's full inputs; each is a host-chosen value
    disposition: str, *, outcome: str, cause: str, failure_kind: str | None = None,
    evidence: str | None = None, ceiling_test: tuple[CeilingReceipt, ...] = (),
    runtime_evidence: tuple[RuntimeEvidenceReceipt, ...] = (),
) -> str:
    """Render report.md from typed, host-chosen arguments; there is no model-supplied body.

    `disposition`, `outcome`, `failure_kind` and `cause` all come from closed vocabularies, so
    no review stage's prose reaches this file, which goes verbatim into the judge's prompt and
    out through the ticket bridge. `failure_kind` is omitted, not written empty, when the
    review did not fail, so a count can filter on its presence.

    Two companion-derived exceptions, both model-chosen structure rather than model-authored
    prose: `ceiling_test` receipts (a priced `inconclusive` close's `ref`/`state`/`cap`, ids
    already verified against the run's `:L findings`) go into the frontmatter, and
    `runtime_evidence` (the recorded baseline consultations, with a host-parsed window) goes
    into the body so a reader can see whether the alerted pattern recurs in this estate. The
    frontmatter carries nothing the host has not checked.

    Free text for the analyst (a receipt's `note`, a baseline's `result`/`reasoning`) goes in
    the body only. The whole file is still capped and may not contain `</report>`, so the write
    gate refuses the delimiter in those cells and bounds both body blocks; the bounds together
    keep the file cap unreachable by notes alone. The blocks are rendered by the price gate's
    own renderers so its byte bounds measure exactly what is written here.

    The cause is a frontmatter key only, not repeated in the body, to avoid a further egress.
    """
    kind_line = f"failure_kind: {failure_kind}\n" if failure_kind is not None else ""
    ceiling_block = ceiling_test_block(ceiling_test)
    body = f"Disposition recorded by the close gate. outcome={outcome}."
    if evidence:
        body += f" {evidence}"
    # Analyst notes go in the body, never the frontmatter.
    body += ceiling_note_block(ceiling_test)
    # One line per baseline from the receipts the projection accepted, never a second reading
    # of the companion, so a row the guard refused cannot appear. Body-only: free text.
    body += runtime_evidence_block(runtime_evidence)
    return (
        "---\n"
        f"disposition: {disposition}\n"
        f"outcome: {outcome}\n"
        f"cause: {cause}\n"
        f"{kind_line}"
        f"{ceiling_block}"
        "---\n"
        f"{body}\n"
    )


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

    `detail` lives here, framed, rather than on report.md: it may quote a stage, and no prompt
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
    #: The `:T conclude.ceiling_test` receipts a priced `inconclusive` close paid with. Set only
    #: on the reviewed site when the standing verdict is `inconclusive`.
    ceiling_test: tuple[CeilingReceipt, ...] = ()
    #: The `:R consultations` baseline rows, carried into the report body on every reviewed-site
    #: commit (including an override to `unresolved`). Empty on the bypass site, whose forced
    #: close skipped the document gate.
    runtime_evidence: tuple[RuntimeEvidenceReceipt, ...] = ()


def _fields_from(
    verdict: challenge_gate.GateVerdict, *,
    material: tuple[RecommendedLead, ...] = (),
    ceiling_test: tuple[CeilingReceipt, ...] = (),
    runtime_evidence: tuple[RuntimeEvidenceReceipt, ...] = (),
) -> _CloseFields:
    """The verdict's scalars as the commit bundle, shared by all three commit sites so a new
    field cannot be forgotten at one. Companion-derived fields come from the caller."""
    return _CloseFields(
        outcome=verdict.outcome, cause=verdict.cause, detail=verdict.detail,
        material=material, turns_used=verdict.turns_used, failure_kind=verdict.failure_kind,
        ceiling_test=ceiling_test, runtime_evidence=runtime_evidence,
    )


def _commit(  # noqa: PLR0913 — the commit's full inputs; the scalars are already bundled
    deps: AgentDeps, disposition: str, fields: _CloseFields, record: dict, *,
    validator: ArtifactValidator, evidence: str | None = None,
) -> CloseResult:
    """Write the review record, then the report; both are attempted, and any fault is raised
    only after both.

    `fields.detail` (which may quote a stage) reaches only the record, never the report, so
    review prose stays out of the judge's prompt and the ticket bridge."""
    state = challenge_gate.ReviewState.of(deps)
    turn_for_record = state.turns + 1

    # Resolving the name can refuse a planted alias with `OSError`; treated like a write fault.
    record_path: Path | None = None
    record_error: BaseException | None = None
    try:
        record_path = RunPaths(deps.run_dir).review_record(turn_for_record)
        challenge_gate.write_review_record(deps.run_dir, turn_for_record, record)
    except OSError as e:
        record_error = e

    body = render_report(
        disposition, outcome=fields.outcome, cause=fields.cause,
        failure_kind=fields.failure_kind, evidence=evidence, ceiling_test=fields.ceiling_test,
        runtime_evidence=fields.runtime_evidence,
    )
    # Every commit is validated; a refusal writes nothing and returns the validator's reason.
    schema_reason = validator(RUN_LAYOUT.report.name, body, None)
    report_error: BaseException | None = None
    if schema_reason is not None:
        report_error = ModelRetry(schema_reason)
    else:
        report_path = RunPaths(deps.run_dir).report
        try:
            from defender._io import guarded_mkdir, write_guarded

            guarded_mkdir(report_path.parent, base=Path(deps.run_dir))
            write_guarded(report_path, body, mode="replace")
        except OSError as e:
            report_error = e

    # Terminality follows the report alone: once it is on disk the close is final, even if the
    # record write failed, so a retry cannot re-run the gate and overwrite it.
    if report_error is None:
        state.closed = True
        state.disposition = disposition

    if record_error is not None or report_error is not None:
        raise record_error if record_error is not None else report_error  # type: ignore[misc]
    return CloseResult(
        outcome=fields.outcome, message=f"closed: {fields.outcome} (disposition={disposition})",
        material=fields.material, record_path=record_path, cause=fields.cause,
        detail=fields.detail, turns_used=fields.turns_used,
        failure_kind=fields.failure_kind,
    )


async def _close_investigation_async(  # noqa: PLR0913 — the close's own seams, all injected
    deps: AgentDeps, disposition: str, *, stages: Any, bounds: challenge_gate.Bounds,
    evidence: str | None = None, validator: ArtifactValidator = validate_artifact,
    forced: bool = False,
) -> CloseResult:
    """The close shared by the sync host entry and the async tool.

    `forced` marks the framework's close of a run cut short (set only by the driver's
    `_close_a_run_cut_short`). It exempts the close from the flagged-row window and the
    structure check: with no model left to repair, gating would leave the run with no
    report.md at all, which is worse than publishing off a malformed companion.

    The companion is read and parsed once, and that one body is threaded through every gate,
    so the review judges the document the price gate priced and the report carries the rows
    the review saw."""
    if deps.role is not AgentRole.MAIN:
        raise ModelRetry(
            "close_investigation is reachable only from the investigator (main) role — "
            f"not from {deps.role.value}"
        )
    # `isinstance(str)` first: an unhashable value would raise out of the set membership test.
    # The sync host entry has no pydantic validation in front of it.
    #
    # lint-vocabulary: ok — live write gate: an exact test gives the author actionable retry
    # text, while normalizing would accept a zero-width-laced value and write it into the
    # report frontmatter.
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
    # The forced close proceeds off an empty document, since refusing it would leave no report.
    if read.text is None and not forced:
        if read.retryable:
            raise ModelRetry(
                f"close blocked: `investigation.md` could not be read ({read.refusal}). A "  # lint-run-records: ok — a message naming the record for the model or operator, not a path
                f"close is not permitted while the gate cannot look — retry."
            )
        return _overrule_unreadable_companion(
            deps, read, disposition, validator=validator, evidence=evidence,
        )
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
        # No review ran, so `detail` is empty. `unresolved` carries neither companion-derived
        # field: the forced close skipped the document gate, and unchecked text the report
        # schema then refused would leave the run with no report.md.
        unreviewed = challenge_gate.GateVerdict(
            outcome=STANDS, disposition=disposition, cause=CAUSE_NOT_REVIEWED, detail="",
            material=(), turns_used=0, failure_kind=None,
        )
        return _commit(
            deps, disposition, _fields_from(unreviewed),
            _record_dict(unreviewed, disposition, reviewed=False),
            validator=validator, evidence=evidence,
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
        challenge_gate.write_review_record(deps.run_dir, turn, record)
        return CloseResult(
            outcome=CHALLENGED, message=_render_challenged_message(material, deps),
            material=material, record_path=record_path, cause=verdict.cause,
            detail=verdict.detail, turns_used=verdict.turns_used,
            failure_kind=verdict.failure_kind,
        )

    # The post-review site. `runtime_evidence` rides on every disposition. `ceiling_test` is
    # keyed on the verdict's disposition, not the argument, so it is set exactly when the
    # committed disposition is `inconclusive`.
    fields = _fields_from(
        verdict, material=material,
        ceiling_test=(
            conclude_ceiling_test_rows(companion) if verdict.disposition == CEILING_DISPOSITION else ()
        ),
        runtime_evidence=conclude_runtime_evidence_rows(companion),
    )
    return _commit(deps, verdict.disposition, fields, record, validator=validator,
                   evidence=evidence)


def close_investigation(  # noqa: PLR0913 — the close's own seams, all injected
    deps: AgentDeps, disposition: str, *, stages: Any, bounds: challenge_gate.Bounds | None = None,
    evidence: str | None = None, validator: ArtifactValidator = validate_artifact,
) -> CloseResult:
    """The sync host-level close; one of the two boundaries (with `run_investigation`) that
    resolves the gate's bounds. Never call this from inside a running event loop."""
    # lint-default: ok — boundary entry point with no resolved value threaded to it; resolved
    # once and threaded inward.
    resolved = bounds if bounds is not None else challenge_gate.default_bounds()
    return asyncio.run(_close_investigation_async(
        deps, disposition, stages=stages, bounds=resolved, evidence=evidence,
        validator=validator,
    ))


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
    deps: AgentDeps, read: CompanionRead, disposition: str, *,
    validator: ArtifactValidator, evidence: str | None,
) -> CloseResult:
    """Commit the model's close over a companion no retry will make readable as a review that
    cannot run: the host's `unresolved`, with no companion-derived fields."""
    verdict = challenge_gate.review_cannot_run(
        deps, read.refusal or "investigation.md could not be read",  # lint-run-records: ok — a message naming the record for the model or operator, not a path
    )
    return _commit(
        deps, verdict.disposition, _fields_from(verdict),
        _record_dict(verdict, disposition, reviewed=True),
        validator=validator, evidence=evidence,
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
    the parsed `investigation.md` it was read from.

    Returning the parsed body means the companion is parsed once, here, inside the guard that
    turns a parse fault into a refusal, and the review and report use exactly the rows this
    gate priced. The price is collected here as well as at the write gate because nothing else
    on the close path reads the companion. Per-disposition rules live in the owner's
    `_DISPOSITION_GATES`.

    `text` is `""` for a never-written companion, which owes every priced disposition its full
    price. A parse failure refuses (fails closed) rather than waiving the price. `forced` is
    exempt from the parse fault only, never the price: an unparseable document becomes the
    empty body, so a forced close of a priced disposition is still refused.
    """
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
    # concurrently, both pass the already-closed check (set only after the write), and both
    # commit to the same review record and report.md, keeping whichever finished last.
    @agent.tool(sequential=True)
    async def close_investigation(
        ctx: RunContext[AgentDeps], disposition: DispositionArg
    ) -> str:
        """Commit this investigation's disposition once ANALYZE has reached a confident
        finding, or once you have run out of data and the case is `inconclusive`.
        `disposition` is a closed enum whose members are in this tool's own schema, never free
        text, and the value is compared EXACTLY — a near miss is refused rather than guessed
        at, so send the keyword with nothing around it. See SKILL §REPORT for what each one
        claims, and for the `detection_notes` + `entity_check` rows `false-positive` requires
        in `:T conclude`. This is the ONLY way to record report.md — write_file/edit_file
        cannot reach it. A confident disposition, or `inconclusive`, passes a live challenge
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
    "ArtifactValidator",
    "CloseResult",
    "DispositionArg",
    "RecommendedLead",
    "close_investigation",
    "register_close_tool",
    "render_report",
]
