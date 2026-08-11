"""#774 — the close tool: the ONLY writer of report.md once R1 lands, and the seam through
which a confident disposition passes the live write-time challenge gate before it commits.

`close_investigation(deps, disposition, *, stages, bounds=None) -> CloseResult` is the SYNC
host-level close (what a test, or any synchronous host caller, drives directly).
`_tool_close_investigation` is its ASYNC model-facing adapter — the two share
`_close_investigation_async`, so `close_investigation` is never called from inside a running
event loop (it would raise) and the tool body never blocks on a nested `asyncio.run`.

`register_close_tool` registers the tool at MAIN's composition root ONLY (K14: a verb grant
cannot express this — verbs are data-source operations, and a non-empty grant on any other
role fails policy compile). Role admission is ALSO checked host-side, in
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
from defender._untrusted import wrap as _wrap
# The vocabulary from its OWNER, not through the report schema, which was only forwarding it
# here (#785's rule: a module that USES the vocabulary imports it; a module that only PASSED
# IT ON no longer names it at all). Both halves are used — the set for the exact membership
# test in `_close_investigation_async`, the ordered tuple for the argument schema below.
from defender._vocab import DISPOSITION_ENUM, DISPOSITION_VALUES
from defender.hooks.budget_enforcer import BUDGET_EXEMPT_TOOLS  # noqa: F401 — re-export, RS16
from defender.skills.invlang.validate import false_positive_entry_price

from . import challenge_gate
from .agent_role import AgentRole
from .tools import AgentDeps

# --------------------------------------------------------------------------------------
# THE TWO OUTCOME VOCABULARIES. They used to be one ten-member enum, and that conflation is
# what grew it: a single string answered three questions at once (did this commit, did the
# drafted disposition survive, and why) across two sinks that cannot hold the same members.
#
# `CLOSE_RETURNS` answers what a close ATTEMPT did — the tool's return and the numbered
# review record's `verdict`. `COMMITTED_OUTCOMES` answers what a COMMIT recorded — report.md.
# The challenged path returns before the write, so its value is structurally incapable of
# reaching disk; spanning both sinks with one enum meant every reader of either had to carry
# in its head which members its own sink could not hold.
# --------------------------------------------------------------------------------------

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

# --------------------------------------------------------------------------------------
# HOW THE REVIEW FAILED — the typed, countable half of "why", and the one vocabulary this
# collapse adds back. The cause cannot do this job: it is a sentence whose wording nothing
# promises to keep stable, and a fleet query counting broken reviews cannot key on prose.
#
# Absent (`None`) whenever the review did not fail. An override the EVIDENCE produced is a
# finding about the case, not a failure — fold that in and the field is set on every close,
# which makes counting by it count everything.
#
# Three members, each earning its place by a DIFFERENT RESPONSE rather than by naming a
# different condition — which is the bar the retired ten-member enum could not clear.
#
# #797 retired a fourth, `incoherent`. It was the COHERENCE CHECKER'S quality signal — a
# counter-story that answered inside its contract and still never settled into internal
# consistency across the grace budget — and with the challenger, the checker and the grace
# budget all gone, nothing can produce it. A vocabulary member no producer can reach is a
# bucket every fleet query counts as empty and every reader has to know is unreachable.
# --------------------------------------------------------------------------------------

#: A stage was still pending at its deadline. Capacity: move the bound, or chase the
#: provider's latency. The one member whose right response may be to do nothing.
TIMEOUT = "timeout"
#: A stage call raised, or no reviewer was bound to call. A defect, with a traceback or a
#: missing composition root to chase.
STAGE_ERROR = "error"
#: A stage ANSWERED, outside its own output contract: a reply that will not parse, rows
#: missing the fields the reader reads, or identifiers naming something the investigation
#: never produced. Nothing is down — the prompt or the contract is what needs work. An
#: unreadable reply and a hallucinated identifier are ONE member on purpose: they are
#: different conditions with the same response, and separating those is how ten arms grew.
UNREADABLE = "unreadable"

FAILURE_KINDS: tuple[str, ...] = (TIMEOUT, STAGE_ERROR, UNREADABLE)

# --------------------------------------------------------------------------------------
# THE CAUSE — the close's OWN sentences, and the only strings the frontmatter's `cause` may
# be. report.md rides VERBATIM into the judge LLM's prompt and its body rides out through the
# ticket bridge's HTTP egress, and every review stage composes its reply after reading
# attacker-influenced alert data. So the cause is composed by the HOST from this closed set;
# the stage-derived diagnostic is `CloseResult.detail` and lives on the numbered review
# record, which no prompt reads verbatim.
#
# Strictly COARSER than the conditions that reach it: one sentence per condition is the
# retired ten-member enum re-minted in longer words, one file away from where it was removed.
# The rule that actually bounds the set is ONE DISTINCTION, ONE FIELD — where the typed
# failure kind already separates two conditions, the sentence must not separate them again,
# or the report carries the same split twice and the prose becomes an unversioned second copy
# of a key something counts.
# --------------------------------------------------------------------------------------

# #797 RETIRED `CAUSE_NO_STORY` — "the challenge review ran and no alternative account was
# offered". It named the challenger's deliberate DECLINE, and a decline is a thing only a
# party that argues a counter-case can do. With no such party the sentence has no referent,
# and the three below that borrowed its "alternative account" phrasing are reworded off it:
# each still names exactly the condition it always named, in words that do not point at a
# counter-story nothing produces.

CAUSE_NOT_REVIEWED = "the disposition was recorded without a challenge review"
CAUSE_STORY_SETTLED = (
    "the challenge review ran and left nothing about the finding unsettled"
)
#: THREE conditions share this one: a stage that raised or timed out, a stage reply the gate
#: cannot read or that named something the investigation never produced, and a bundle whose
#: stages are not bound (the shape a composition root with no run dir produces). They are told
#: apart by `failure_kind`, two lines above it in the same frontmatter, and by the record's
#: `detail` — never by a second sentence here.
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
#: produces is content the schema would refuse — a test can observe that a refusal HAPPENED
#: but never that the validator RAN on the ordinary path, which is exactly the difference
#: between a validator guarding every commit and one gated on the evidence argument.
#: The default is the FUNCTION, never `None`: with `None` the same cheat survives spelled
#: "validate only when an optional argument happens to be supplied", and no behavioural
#: assertion can see that one.
ArtifactValidator = Callable[[str, str, str | None], str | None]


@dataclass(frozen=True)
class RecommendedLead:
    """One thing the review wants measured before the close can stand.

    `ask` was `requirement` — the challenger's word for an assertion its counter-story
    needed settled. #797 retired the counter-story; what a review hands back is its ask, and
    the field is renamed rather than left carrying the retired party's vocabulary.

    `target` was `lead_id`, for the same reason one layer on: #796's ask names an entity, an
    edge, a lead OR a hypothesis (`reply.citable_refs` is the set it is checked against), so
    a field spelled `lead_id` claimed a kind the contract stopped guaranteeing."""

    target: str
    ask: str
    origin: str


@dataclass(frozen=True)
class CloseResult:
    """What one close attempt did, in the three fields the collapse split `reason` into.

    `cause` is the HOST'S OWN sentence and is what report.md carries. `detail` is the
    DIAGNOSTIC — it may quote a stage's own words and therefore never reaches report.md; it
    is kept, framed, on the numbered review record instead of being dropped."""

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

    Every one of the four values is chosen by the host from a closed set: the disposition is
    validated against its enum before any gate work, `outcome` and `failure_kind` are typed
    vocabularies, and `cause` is one of the close's OWN published sentences. None of them can
    carry a review stage's prose, which is what keeps this file — it rides verbatim into the
    judge's prompt and out through the ticket bridge — inside the 512-byte frontmatter cap
    and out of the raw-render exposure.

    `failure_kind` is OMITTED when the review did not fail rather than written as an empty
    value: absence is the fifth state of that vocabulary, and a key that is always present is
    a key a count cannot filter on.

    THE CAUSE IS A FRONTMATTER KEY AND NOT ALSO A BODY SENTENCE. It was briefly both, on the
    reasoning that the collapse would otherwise reach no shipped consumer because the ticket
    bridge transmits the body alone. The first half of that is false — the judge's invocation
    builder feeds this whole file, frontmatter included, verbatim into its prompt, so the key
    already reaches a consumer. What the duplicate bought was one further egress and a second
    place for the same sentence to be read from, which is the shape that makes two readers
    disagree later. The ticket bridge's closing comment is the cost, and it is accepted: that
    comment now carries the disposition and the outcome without the sentence explaining them.
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
    """The challenged arm's hand-back, which now ALWAYS carries a lead.

    There used to be a second message here for a challenge that named nothing — the forced
    turn's tax without its probe. That state is gone: an attempt whose discriminating leads
    were all already raised does not take this arm at all, it closes on what it has. Keeping
    the message would leave production telling the model something the gate can no longer
    mean."""
    assert material, "the challenged arm never returns without discriminating material"
    lines = [f"- {item.target}: {item.ask}" for item in material]
    # O6/O7: the discriminating material is derived from a payload-influenced role's output —
    # it returns inside the SAME run-salted untrusted frame the gather subagent's return
    # already uses (`defender._untrusted.wrap`, keyed on the INVESTIGATION's own salt, never
    # the review role's own — the review role minted a fresh one and never held this one).
    framed = _wrap("\n".join(lines), "untrusted", deps.salt)
    # "measurement", not "lead": #796's ask names the entity, edge, lead or hypothesis to
    # measure and the DIMENSION to measure it on — the investigation chooses the lead. Calling
    # a vertex a lead here told the model a `v-` id was something it could go run.
    return (
        f"The gate challenged this close — {len(material)} measurement(s) remain before it "
        f"can stand. Investigate further before re-closing:\n{framed}"
    )


def _record_dict(verdict: challenge_gate.GateVerdict, disposition: str, deps: AgentDeps) -> dict:
    """The numbered review record. `detail` is here and NOT on report.md by decision: the
    diagnostic may quote a stage's own words, and this is the one artifact no prompt reads
    verbatim. It is framed rather than dropped, so the words survive somewhere a human can
    read them off the run.

    #797 dropped four keys with the stages that filled them: `direction` and
    `requirement_list` (the challenger's counter-direction and its assertions),
    `projection_response` (the projection stage's per-lead tags) and `rounds_consumed` (the
    refinement loop's counter — there is one review pass now, so the number could only ever
    be zero). `attacked_disposition` is `reviewed_disposition`: nothing attacks it any more.
    #796 adds the lens readings and the composer's prose."""
    return {
        "verdict": verdict.outcome,
        "reviewed_disposition": disposition,
        "detail": _wrap(verdict.detail, "untrusted", deps.salt) if verdict.detail else "",
        "failure_kind": verdict.failure_kind,
    }


@dataclass(frozen=True)
class _CloseFields:
    """The scalar fields `_commit` needs beyond `deps`/`disposition`/`record` — bundled so
    the function stays under the arg-count lint rather than growing an 11th parameter."""

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
    """RS19. Record FIRST, report SECOND — both attempted regardless of the other's fault,
    and any fault is held until both writes have been attempted (never silently dropping
    the second write).

    The report is rendered from `fields.outcome`/`fields.cause`/`fields.failure_kind` and
    NOTHING else. `fields.detail` — the diagnostic, which may quote a stage — reaches the
    record via `_record_dict` and never this render call, which is the whole of what keeps
    review prose out of the judge's prompt and the ticket bridge's egress."""
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
    # let the model's retry sail past the already-closed refusal and re-run the whole gate on
    # top of a committed report — the exact overwrite R4 exists to prevent, reachable through
    # a fault RS19 already says must not silently drop the other write.
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
) -> CloseResult:
    if deps.role is not AgentRole.MAIN:
        raise ModelRetry(
            "close_investigation is reachable only from the investigator (main) role — "
            f"not from {deps.role.value}"
        )
    # lint-vocabulary: ok — the same WRITE-gate asymmetry `_artifact_schema` states, one layer
    # earlier: this is the LIVE close, so the author is still on the other end of the call and an
    # exact test hands it retry text it can act on. `normalized_disposition` would silently ACCEPT
    # a zero-width-laced value and commit a close no reader can tell from a clean one — and this
    # gate's value is what the report frontmatter is later written FROM, so normalizing here would
    # launder the injected character past the very gate that exists to deny it.
    if disposition not in DISPOSITION_ENUM:
        raise ModelRetry(
            f"disposition must be exactly one of {sorted(DISPOSITION_ENUM)} (got "
            f"{disposition!r}) — a typed enum, not free text"
        )
    # R4: a COMMITTED close is terminal, and the refusal comes BEFORE the gate so a second
    # attempt cannot spend the review either. Without it the model is told its first close
    # succeeded and then allowed to succeed again with the opposite disposition — a confident
    # `malicious` was silently replaced by `inconclusive` that way, taking the first close's
    # review record with it, because every committing arm computes its record path from the
    # turn counter and only the NON-committing arm advances that counter.
    state = challenge_gate.ReviewState.of(deps)
    if state.closed:
        raise ModelRetry(
            f"this investigation is already closed — {state.disposition!r} is committed and "
            "the close is terminal. Re-closing would re-run the whole review and overwrite "
            "both the recorded disposition and the first close's own review record."
        )
    # #806: the one disposition with an entry price, collected here as well as at the
    # `investigation.md` write gate. `report.md` is written FROM this argument, and nothing else
    # on this path reads the companion — so without this the price is bypassable by concluding
    # under a cheaper keyword and passing `false-positive` to the close. Placed AFTER the
    # terminal-close refusal so R4's ordering holds, and before the gate so a close that owes
    # the price never spends a review on it.
    if disposition == "false-positive":
        owed = false_positive_entry_price(
            _read_companion_text(Path(deps.run_dir) / "investigation.md")
        )
        if owed:
            raise ModelRetry(
                "close blocked: `false-positive` says the RULE misfired, which is no evidence "
                "about the alerted entity — so it is reachable only from an `investigation.md` "
                "that states the defect and names the lead that checked the entity anyway. "
                + " ".join(owed)
            )
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


def _read_companion_text(path: Path) -> str:
    """The investigation log as text, or empty when there is none to read.

    Absence is not an error to raise here: an unwritten (or unreadable) companion states no
    defect and names no entity check, so it owes the whole price and the caller denies with the
    same actionable text a blank `:T conclude` earns. Raising instead would hand the model an
    exception where it needs an instruction.
    """
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return ""


#: The `disposition` argument AS THE MODEL IS OFFERED IT (#750): a plain `str` carrying the
#: owner's vocabulary in its JSON schema. Derived from `DISPOSITION_VALUES`, so a fifth member
#: reaches the model with nobody editing prose — #806 added `false-positive` by hand-syncing
#: every surface that spelled the members out, and this tool's docstring was one of them.
#:
#: `json_schema_extra`, NOT a `StrEnum` or a `Literal`, DELIBERATELY. pydantic does not validate
#: against it, so an out-of-enum value still reaches the body and the exact test in
#: `_close_investigation_async` stays the SOLE rejecter. Hand the type system the enum instead
#: and pydantic refuses first, which breaks three things at once: the host check becomes
#: unreachable from this lane, the SYNC entry (nothing validates a tool argument in front of
#: it) is left as the only lane the check still guards, and #722's repr-escaped retry text is
#: replaced by a framework message that echoes the invisible character RAW — measured, not
#: assumed: `input: "beni<U+200B>gn"`. The hint is for the model; the gate stays ours.
DispositionArg = Annotated[str, Field(json_schema_extra={"enum": list(DISPOSITION_VALUES)})]


def register_close_tool(agent, *, stages: Any, bounds: challenge_gate.Bounds) -> None:
    """MAIN's composition root ONLY — never called for any other role's agent build, and
    only when that root's effective `ToolSet.close` is on."""

    @agent.tool
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
    "RecommendedLead",
    "close_investigation",
    "register_close_tool",
    "render_report",
]
