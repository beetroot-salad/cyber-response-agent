"""The close tool: the ONLY writer of report.md, and the seam through which a confident
disposition passes the live write-time challenge gate before it commits.

`close_investigation(deps, disposition, *, stages, bounds=None) -> CloseResult` is the SYNC
host-level close (what a test, or any synchronous host caller, drives directly).
`_tool_close_investigation` is its ASYNC model-facing adapter — the two share
`_close_investigation_async`, so `close_investigation` is never called from inside a running
event loop (it would raise) and the tool body never blocks on a nested `asyncio.run`.

`register_close_tool` registers the tool at MAIN's composition root ONLY; a verb grant cannot
express this, since verbs are data-source operations and a non-empty grant on any other role
fails policy compile. Role admission is ALSO checked host-side, in
`_close_investigation_async` itself, so the negative holds even for a direct call that never
goes through tool registration at all.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any

from pydantic import Field
from pydantic_ai import RunContext
from pydantic_ai.exceptions import ModelRetry

from defender._artifact_schema import validate_artifact
from defender._untrusted import wrap_fresh
# The vocabulary from its OWNER, not second-hand through the report schema: a module that USES
# the vocabulary imports it from the owner, so a consumer's import list never doubles as
# someone else's distribution channel. Both halves are used — the set for the exact membership
# test in `_close_investigation_async`, the ordered tuple for the argument schema below.
from defender._vocab import DISPOSITION_ENUM, DISPOSITION_VALUES
from defender.hooks.budget_enforcer import BUDGET_EXEMPT_TOOLS  # noqa: F401 — re-export, RS16
from defender.skills.invlang.validate import disposition_entry_price

from . import challenge_gate
from . import tools as tools_mod
from .agent_role import AgentRole
from .tools import AgentDeps

# THE TWO OUTCOME VOCABULARIES, deliberately not one.
#
# `CLOSE_RETURNS` answers what a close ATTEMPT did — the tool's return and the numbered review
# record's `verdict`. `COMMITTED_OUTCOMES` answers what a COMMIT recorded — report.md. The
# challenged path returns before the write, so its value is structurally incapable of reaching
# disk; spanning both sinks with one enum makes every reader carry in its head which members
# its own sink cannot hold.

#: The investigation continues: nothing is committed and the discriminating material comes back.
CHALLENGED = "challenged"
#: The drafted disposition is committed unchanged — the gate never ran, or it ran and the
#: counter-story did not survive, or the challenger declined to argue one.
STANDS = "stands"
#: The drafted CONFIDENT disposition is overridden to inconclusive. Every way the gate can
#: refuse to let a confident finding stand lands here; WHICH way is the cause's job.
FORCED_INCONCLUSIVE = "forced-inconclusive"

CLOSE_RETURNS: tuple[str, ...] = (CHALLENGED, STANDS, FORCED_INCONCLUSIVE)
COMMITTED_OUTCOMES: tuple[str, ...] = (STANDS, FORCED_INCONCLUSIVE)

# HOW THE REVIEW FAILED — the typed, countable half of "why". The cause cannot do this job: it
# is a sentence whose wording nothing promises to keep stable, and a fleet query counting
# broken reviews cannot key on prose.
#
# Absent (`None`) whenever the review did not fail. An override the EVIDENCE produced is a
# finding about the case, not a failure — fold that in and the field is set on every close,
# which makes counting by it count everything.
#
# Three members, each earning its place by a DIFFERENT RESPONSE rather than by naming a
# different condition.

#: A stage was still pending at its deadline. Capacity: move the bound, or chase the
#: provider's latency. The one member whose right response may be to do nothing.
TIMEOUT = "timeout"
#: A stage call raised, or no reviewer was bound to call. A defect, with a traceback or a
#: missing composition root to chase.
STAGE_ERROR = "error"
#: A stage ANSWERED, outside its own output contract: a reply that will not parse, rows
#: missing the fields the reader reads, or identifiers naming something the investigation
#: never produced. Nothing is down — the prompt or the contract is what needs work. An
#: unreadable reply and a hallucinated identifier are ONE member on purpose: different
#: conditions, same response.
UNREADABLE = "unreadable"

FAILURE_KINDS: tuple[str, ...] = (TIMEOUT, STAGE_ERROR, UNREADABLE)

# THE CAUSE — the close's OWN sentences, and the only strings the frontmatter's `cause` may
# be. report.md rides VERBATIM into the judge LLM's prompt and its body rides out through the
# ticket bridge's HTTP egress, and every review stage composes its reply after reading
# attacker-influenced alert data. So the cause is composed by the HOST from this closed set;
# the stage-derived diagnostic is `CloseResult.detail` and lives on the numbered review
# record, which no prompt reads verbatim.
#
# Strictly COARSER than the conditions that reach it. The rule that bounds the set is ONE
# DISTINCTION, ONE FIELD — where the typed failure kind already separates two conditions, the
# sentence must not separate them again, or the prose becomes an unversioned second copy of a
# key something counts.

CAUSE_NOT_REVIEWED = "the disposition was recorded without a challenge review"
CAUSE_STORY_SETTLED = (
    "the challenge review ran and left nothing about the finding unsettled"
)
#: THREE conditions share this one: a stage that raised or timed out, a stage reply the gate
#: cannot read or that named something the investigation never produced, and a bundle whose
#: stages are not bound. They are told apart by `failure_kind` in the same frontmatter and by
#: the record's `detail` — never by a second sentence here.
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

REPORT_CAUSES: tuple[str, ...] = (
    CAUSE_NOT_REVIEWED,
    CAUSE_STORY_SETTLED,
    CAUSE_REVIEW_INCOMPLETE,
    CAUSE_EVIDENCE_CANNOT_DISCRIMINATE,
    CAUSE_TURN_BUDGET_SPENT,
    CAUSE_NOTHING_LEFT_TO_ASK,
)

#: The challenged attempt commits nothing, so it has no cause to write. Spelled as a constant
#: rather than left as a bare literal at the one site that produces it, so "no report, no
#: cause" reads as the deliberate state it is rather than as a forgotten field.
NO_CAUSE = ""

#: The artifact validator the close is HANDED, defaulted to the real one. The seam exists
#: because the ordinary close renders its own body and passes no evidence, so nothing it
#: produces is content the schema would refuse — a test can observe that a refusal HAPPENED but
#: never that the validator RAN on the ordinary path, which is the difference between a
#: validator guarding every commit and one gated on the evidence argument. The default is the
#: FUNCTION, never `None`: with `None` the same gap survives, spelled "validate only when an
#: optional argument happens to be supplied".
ArtifactValidator = Callable[[str, str, str | None], str | None]


@dataclass(frozen=True)
class RecommendedLead:
    """One thing the review wants measured before the close can stand.

    `target` is deliberately not `lead_id`: an ask names an entity, an edge, a lead OR a
    hypothesis (`reply.citable_refs` is the set it is checked against), so a field spelled
    `lead_id` would claim a kind the contract does not guarantee."""

    target: str
    ask: str
    origin: str


@dataclass(frozen=True)
class CloseResult:
    """What one close attempt did.

    `cause` is the HOST'S OWN sentence and is what report.md carries. `detail` is the
    DIAGNOSTIC — it may quote a stage's own words and therefore never reaches report.md; it is
    kept, framed, on the numbered review record instead of being dropped."""

    outcome: str
    message: str
    material: tuple[RecommendedLead, ...]
    record_path: Path | None
    cause: str
    detail: str
    turns_used: int = 0
    failure_kind: str | None = None


def render_report(
    disposition: str, *, outcome: str, cause: str, failure_kind: str | None = None,
    evidence: str | None = None,
) -> str:
    """RS12. The body is HOST-RENDERED from typed arguments — the tool accepts no
    model-supplied body.

    All four values are chosen by the host from a closed set: the disposition is validated
    against its enum before any gate work, `outcome` and `failure_kind` are typed vocabularies,
    and `cause` is one of the close's OWN published sentences. None can carry a review stage's
    prose, which is what keeps this file — it rides verbatim into the judge's prompt and out
    through the ticket bridge — inside the 512-byte frontmatter cap and out of the raw-render
    exposure.

    `failure_kind` is OMITTED when the review did not fail rather than written empty: absence
    is the fifth state of that vocabulary, and an always-present key is one a count cannot
    filter on.

    THE CAUSE IS A FRONTMATTER KEY AND NOT ALSO A BODY SENTENCE. The judge's invocation builder
    feeds this whole file, frontmatter included, verbatim into its prompt, so the key already
    reaches a consumer; duplicating it into the body buys one further egress and a second place
    for the same sentence to be read from. The cost is the ticket bridge's closing comment,
    which carries the disposition and the outcome without the sentence explaining them.
    """
    kind_line = f"failure_kind: {failure_kind}\n" if failure_kind is not None else ""
    body = f"Disposition recorded by the close gate. outcome={outcome}."
    if evidence:
        body += f" {evidence}"
    return (
        "---\n"
        f"disposition: {disposition}\n"
        f"outcome: {outcome}\n"
        f"cause: {cause}\n"
        f"{kind_line}"
        "---\n"
        f"{body}\n"
    )


def _render_challenged_message(material: tuple[RecommendedLead, ...], deps: AgentDeps) -> str:
    """The challenged arm's hand-back, which ALWAYS carries a lead: an attempt whose
    discriminating leads were all already raised does not take this arm at all, it closes on
    what it has."""
    assert material, "the challenged arm never returns without discriminating material"
    lines = [f"- {item.target}: {item.ask}" for item in material]
    # The discriminating material is derived from a payload-influenced role's output, so it
    # returns inside an untrusted frame — with a FRESH salt, minted after this content is in
    # hand, so no party has seen the delimiter, the review role included.
    framed = wrap_fresh("\n".join(lines), "untrusted")
    # "measurement", not "lead": the ask names the entity, edge, lead or hypothesis to measure
    # and the DIMENSION to measure it on, and the investigation chooses the lead. Calling a
    # vertex a lead here tells the model a `v-` id is something it can go run.
    return (
        f"The gate challenged this close — {len(material)} measurement(s) remain before it "
        f"can stand. Investigate further before re-closing:\n{framed}"
    )


def _record_dict(verdict: challenge_gate.GateVerdict, disposition: str, deps: AgentDeps) -> dict:
    """The numbered review record. `detail` is here and NOT on report.md by decision: the
    diagnostic may quote a stage's own words, and this is the one artifact no prompt reads
    verbatim. It is framed rather than dropped, so the words survive somewhere a human can
    read them off the run."""
    return {
        "verdict": verdict.outcome,
        "reviewed_disposition": disposition,
        "detail": wrap_fresh(verdict.detail, "untrusted") if verdict.detail else "",
        "failure_kind": verdict.failure_kind,
    }


@dataclass(frozen=True)
class _CloseFields:
    """The scalar fields `_commit` needs beyond `deps`/`disposition`/`record`, bundled so the
    function stays under the arg-count lint."""

    outcome: str
    cause: str
    detail: str
    material: tuple[RecommendedLead, ...]
    turns_used: int
    failure_kind: str | None


def _commit(  # noqa: PLR0913 — the commit's full inputs; the scalars are already bundled
    deps: AgentDeps, disposition: str, fields: _CloseFields, record: dict, *,
    validator: ArtifactValidator, evidence: str | None = None,
) -> CloseResult:
    """RS19. Record FIRST, report SECOND — both attempted regardless of the other's fault, and
    any fault held until both writes have been attempted.

    The report is rendered from `fields.outcome`/`fields.cause`/`fields.failure_kind` and
    NOTHING else. `fields.detail` — the diagnostic, which may quote a stage — reaches the
    record via `_record_dict` and never this render call, which is what keeps review prose out
    of the judge's prompt and the ticket bridge's egress."""
    state = challenge_gate.ReviewState.of(deps)
    turn_for_record = state.turns + 1
    record_path = challenge_gate.review_record_path(deps.run_dir, turn_for_record)

    record_error: BaseException | None = None
    try:
        challenge_gate.write_review_record(deps.run_dir, turn_for_record, record)
    except OSError as e:
        record_error = e

    body = render_report(
        disposition, outcome=fields.outcome, cause=fields.cause,
        failure_kind=fields.failure_kind, evidence=evidence,
    )
    # EVERY commit is validated — never only the ones carrying evidence. The verdict is
    # obeyed, not merely computed: a refusal returns the validator's own reason and leaves
    # nothing on disk.
    schema_reason = validator("report.md", body, None)
    report_error: BaseException | None = None
    if schema_reason is not None:
        report_error = ModelRetry(schema_reason)
    else:
        report_path = deps.run_dir / "report.md"
        try:
            from defender._io import guarded_mkdir, write_guarded

            guarded_mkdir(report_path.parent, base=Path(deps.run_dir))
            write_guarded(report_path, body, mode="replace")
        except OSError as e:
            report_error = e

    # R4's terminality follows THE REPORT, not both writes. `report_error is None` means a
    # disposition is committed on disk; leaving `closed` False because the RECORD write failed
    # lets the model's retry sail past the already-closed refusal and re-run the whole gate on
    # top of a committed report — the exact overwrite R4 exists to prevent.
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
    """`forced` distinguishes the FRAMEWORK's close from the model's. Only the driver's
    retry-exhaustion limb sets it, and it buys exemption from the two document gates below —
    the invlang structure check and the flagged-row window. Defaulted False so every other
    caller is gated.

    Both exemptions rest on the same fact: retry exhaustion has no model left to repair with,
    so gating the forced close would dead-letter the run at persist for a MISSING report.md.
    A malformed companion is worse to publish than a well-formed one, but a run with no
    disposition at all is worse than either, and the frontmatter still records honestly which
    way the close went."""
    if deps.role is not AgentRole.MAIN:
        raise ModelRetry(
            "close_investigation is reachable only from the investigator (main) role — "
            f"not from {deps.role.value}"
        )
    # `isinstance(str)` FIRST: a non-string value (a YAML list, an int) is unhashable, so a bare
    # `value in DISPOSITION_ENUM` (a set) would raise TypeError out of the gate instead of
    # denying. The tool lane cannot reach here with one — pydantic validates the argument as
    # `str` — but the SYNC host entry has nothing in front of it, which is why the refusal lives
    # in the body.
    #
    # lint-vocabulary: ok — the WRITE-gate asymmetry: this is the LIVE close, so the author is
    # still on the other end and an exact test hands it retry text it can act on.
    # `normalized_disposition` would silently ACCEPT a zero-width-laced value and commit a close
    # no reader can tell from a clean one — and this gate's value is what the report frontmatter
    # is written FROM, so normalizing here launders the injected character past the very gate
    # that exists to deny it.
    if not (isinstance(disposition, str) and disposition in DISPOSITION_ENUM):
        # Rendered from the ORDERED TUPLE, never `sorted(DISPOSITION_ENUM)`: this refusal and
        # the tool schema are read in the SAME round trip, so a fifth member appended out of
        # alphabetical order would hand the model two orderings of one closed vocabulary while
        # it is trying to correct itself.
        raise ModelRetry(
            f"disposition must be exactly one of {list(DISPOSITION_VALUES)} (got "
            f"{disposition!r}) — a typed enum, not free text"
        )
    # R4: a COMMITTED close is terminal, and the refusal comes BEFORE the gate so a second
    # attempt cannot spend the review either. Without it a confident `malicious` can be
    # silently replaced by `inconclusive`, taking the first close's review record with it —
    # every committing arm computes its record path from the turn counter, and only the
    # NON-committing arm advances that counter.
    state = challenge_gate.ReviewState.of(deps)
    if state.closed:
        raise ModelRetry(
            f"this investigation is already closed — {state.disposition!r} is committed and "
            "the close is terminal. Re-closing would re-run the whole review and overwrite "
            "both the recorded disposition and the first close's own review record."
        )
    # TOP of the close — after the two cheap well-formedness refusals above, and before ANY
    # disposition branch. Inside a branch, `inconclusive` (which commits early, ahead of the
    # gate) could dodge the obligation entirely, and the reviewer's model calls would be spent
    # on a close that is going to be refused anyway.
    #
    # The framework's FORCED close is the one exception: retry exhaustion has no model left to
    # repair with, so gating it would dead-letter the run at persist for a MISSING report.md,
    # before investigation.md is validated at all. Every close the MODEL invokes is gated.
    if not forced:
        flagged = tools_mod.flagged_diagnostics(deps)
        if flagged:
            raise ModelRetry(tools_mod.flagged_write_refusal(
                "close_investigation", flagged, offered_text=False,
            ))
    # The dispositions carrying a structural entry price, collected here as well as at the
    # `investigation.md` write gate. AFTER the terminal-close refusal so R4's ordering holds,
    # and before the gate so a close that owes the price never spends a review.
    _refuse_if_entry_price_is_owed(deps, disposition)
    # The check the close never had (#961). Every other write verb meets the invlang schema
    # through `permission.decide_write`; the close is the verb that PUBLISHES — report.md
    # commits against this document and the review gate parses it — so it was the one path on
    # which an error-severity document reached a committed disposition. It reads through
    # `tools_mod`, beside the repair window above, so both document gates share one reader and
    # one answer to "the document could not be read at all" (H7: fail open).
    #
    # LAST of the three document gates, and the order is load-bearing. This one runs the WHOLE
    # validator, which includes rules conditioned on the disposition the DOCUMENT concludes —
    # benign gating, the false-positive entity check. Ahead of the price gate it would answer a
    # close of `false-positive` with a complaint about the `benign` the companion happens to
    # declare: true, but about a keyword the model is no longer claiming, and it would shadow
    # the specific obligation the model can actually discharge. Behind it, each refusal is the
    # most specific one the document has earned, and nothing gets past: the price gate refuses
    # what it prices, this refuses everything else. Still ahead of every disposition branch, so
    # no review is spent on a close that is going to be refused (H5's reason).
    #
    # `forced` is exempt with the flagged-row window above, for that exemption's own reason:
    # retry exhaustion has no model left to repair with.
    if not forced:
        structure = tools_mod.committed_document_refusal(deps)
        if structure is not None:
            raise ModelRetry(structure)
    if disposition == "inconclusive":
        # The gate reviews CONFIDENT closes only, so nothing was reviewed and there is no
        # stage output to diagnose — the empty detail here is the honest value, not a gap.
        record = {
            "verdict": STANDS, "reviewed_disposition": disposition, "detail": "",
            "failure_kind": None,
        }
        fields = _CloseFields(
            outcome=STANDS, cause=CAUSE_NOT_REVIEWED, detail="", material=(),
            turns_used=0, failure_kind=None,
        )
        return _commit(deps, disposition, fields, record, validator=validator, evidence=evidence)

    verdict = await challenge_gate.challenge_gate(
        deps, disposition, stages=stages, bounds=bounds,
    )
    material = tuple(
        RecommendedLead(target=target, ask=ask, origin="review")
        for target, ask in verdict.material
    )
    record = _record_dict(verdict, disposition, deps)

    if verdict.outcome == CHALLENGED:
        turn = state.turns  # already incremented inside challenge_gate for this attempt
        record_path = challenge_gate.review_record_path(deps.run_dir, turn)
        challenge_gate.write_review_record(deps.run_dir, turn, record)
        return CloseResult(
            outcome=CHALLENGED, message=_render_challenged_message(material, deps),
            material=material, record_path=record_path, cause=verdict.cause,
            detail=verdict.detail, turns_used=verdict.turns_used,
            failure_kind=verdict.failure_kind,
        )

    fields = _CloseFields(
        outcome=verdict.outcome, cause=verdict.cause, detail=verdict.detail,
        material=material, turns_used=verdict.turns_used,
        failure_kind=verdict.failure_kind,
    )
    return _commit(deps, verdict.disposition, fields, record, validator=validator,
                   evidence=evidence)


def close_investigation(  # noqa: PLR0913 — the close's own seams, all injected
    deps: AgentDeps, disposition: str, *, stages: Any, bounds: challenge_gate.Bounds | None = None,
    evidence: str | None = None, validator: ArtifactValidator = validate_artifact,
) -> CloseResult:
    """The SYNC host-level close, and one of the TWO boundaries where the gate's bounds are
    resolved (`run_investigation` is the other). Everything inward of these two takes a
    concrete `Bounds`. Never call this from inside a running event loop."""
    # lint-default: ok — DI seam owning its default at a boundary: this entry point is
    # reached directly (not through run_investigation), so it has no resolved value threaded
    # to it and must resolve one. Resolved ONCE, into a fresh name, and threaded inward.
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


def _refuse_if_entry_price_is_owed(deps: AgentDeps, disposition: str) -> None:
    """Collect the structural price this close's KEYWORD owes, and refuse if it is unpaid.

    `report.md` is written FROM the close's disposition argument and nothing else on that path
    reads the companion, so a price collected only at the `investigation.md` write gate is owed
    by the document the model chooses to write and by nothing the model calls. The dispatch
    goes through the OWNER's `_DISPOSITION_GATES` and nothing in this module is keyed on a
    disposition, so a fourth priced keyword is a row there rather than a branch here.

    Fails CLOSED on both ways the check can fail to happen: the read raises its own
    `ModelRetry` for an I/O fault (see `_read_companion_text`), and the parse is wrapped here
    because this gate parses a file it did not write — an imported run dir, a replayed fixture,
    a hand edit. Either fault would otherwise leave the close as a traceback rather than a
    refusal.
    """
    try:
        price = disposition_entry_price(
            disposition, _read_companion_text(Path(deps.run_dir) / "investigation.md")
        )
    except ModelRetry:
        raise
    except Exception as exc:
        raise ModelRetry(
            f"close blocked: `investigation.md` could not be parsed to check the entry price "
            f"your disposition may owe ({type(exc).__name__}: {exc}). Repair the document — a "
            f"close is not permitted while the gate cannot look."
        ) from exc
    if price:
        # One owed string per line: `_check_benign_open_slots` files one per unresolved slot
        # PER VERTEX, so a real log can owe dozens, and space-joined that is a wall. The write
        # gate already hands the model the same diagnostics one per line.
        raise ModelRetry("close blocked: " + price.rationale + "\n" + "\n".join(price.owed))


def _read_companion_text(path: Path) -> str:
    """The investigation log as text, or empty when it was never written.

    NEVER WRITTEN is not an error to raise here: an unwritten companion states no defect, names
    no entity check and records no alerted entity, so it owes BOTH priced keywords their whole
    price and the caller denies with the same actionable text a blank `:T conclude` earns.

    COULD NOT LOOK is a different answer. Every close reads this file, so an EACCES, an EIO or
    a run dir that is not a directory reaches this gate, and there `""` would mean "this gate
    did not run", waiving `benign`'s entire price on an I/O fault — and `false-positive` fails
    closed over an empty read where `benign` fails open, so swallowing would leave the two
    priced keywords disagreeing about what a fault means. A gate that cannot look must not
    report clean, so the fault becomes a refusal.

    Undecodable BYTES are read leniently, which is neither of those: the file IS readable, and
    replacing the bad byte leaves every readable `??` slot and unfulfilled contract still owed,
    where `""` would waive the whole price over one byte. `investigation.md` is written through
    `append_block`, which refuses an undecodable document, so this is reached only by a file
    that arrived some other way.
    """
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return ""
    except OSError as exc:
        raise ModelRetry(
            f"close blocked: `investigation.md` could not be read ({exc.strerror or exc}), so "
            f"the entry price your disposition may owe could not be checked. This is a fault "
            f"in the run dir, not something to conclude around — a close is not permitted "
            f"while the gate cannot look."
        ) from exc


#: The `disposition` argument AS THE MODEL IS OFFERED IT: a plain `str` carrying the owner's
#: vocabulary in its JSON schema. Derived from `DISPOSITION_VALUES`, so a fifth member reaches
#: the model's TOOL SCHEMA with nobody editing this file.
#:
#: That property holds for the TOOL SCHEMA ONLY. `SKILL.md` §REPORT — the runtime system
#: prompt — hand-enumerates the members with a paragraph of MEANING each, so it is not
#: derivable from a tuple of strings. A fifth member grows this schema automatically and leaves
#: that roster stale, which is a prompt change, not this one.
#:
#: `json_schema_extra`, NOT a `StrEnum` or a `Literal`, DELIBERATELY. pydantic does not validate
#: against it, so an out-of-enum value still reaches the body and the exact test in
#: `_close_investigation_async` stays the SOLE rejecter. Hand the type system the enum and
#: pydantic refuses first, which breaks three things: the host check becomes unreachable from
#: this lane, the SYNC entry is left as the only lane it still guards, and the repr-escaped
#: retry text is replaced by a framework message that echoes the invisible character RAW —
#: measured, not assumed: `input: "beni<U+200B>gn"`. The hint is for the model; the gate stays
#: ours.
DispositionArg = Annotated[str, Field(json_schema_extra={"enum": list(DISPOSITION_VALUES)})]


def register_close_tool(agent, *, stages: Any, bounds: challenge_gate.Bounds) -> None:
    """MAIN's composition root ONLY — never called for any other role's agent build, and
    only when that root's effective `ToolSet.close` is on."""

    # `sequential=True`, for the same reason `append_block`/`fix_row` carry it (tools.py):
    # two `ToolCallPart`s in ONE model response otherwise run as concurrent tasks. Here the
    # lost update is the DISPOSITION. `state.closed` is not set until `_commit` has already
    # replaced report.md, so two close calls both read it False at the R4 check, both run the
    # review gate, and both reach `_commit` — which derives `turn_for_record` from
    # `state.turns`, unchanged by either arm, so they collide on one `review_record.{turn}.json`
    # and one `write_guarded(..., mode="replace")`. The run then records whichever disposition
    # finished last while telling the model both closes succeeded, and report.md's frontmatter
    # is what the learning loop trains on.
    @agent.tool(sequential=True)
    async def close_investigation(
        ctx: RunContext[AgentDeps], disposition: DispositionArg
    ) -> str:
        """Commit this investigation's disposition once ANALYZE has reached a confident
        finding. `disposition` is a closed enum whose members are in this tool's own schema,
        never free text, and the value is compared EXACTLY — a near miss is refused rather
        than guessed at, so send the keyword with nothing around it. See SKILL §REPORT for
        what each one claims, and for the `detection_notes` + `entity_check` rows
        `false-positive` requires in `:T conclude`. This is the ONLY way to record report.md —
        write_file/edit_file cannot reach it. A confident disposition passes a live challenge
        gate before it commits; if the gate is not satisfied yet, this call returns without
        committing and the investigation continues for another ANALYZE/GATHER turn."""
        return await _tool_close_investigation(ctx.deps, disposition, stages=stages, bounds=bounds)


__all__ = [
    "BUDGET_EXEMPT_TOOLS",
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
