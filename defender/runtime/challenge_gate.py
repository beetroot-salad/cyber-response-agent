"""The live write-time review gate's HARNESS: bounds, per-run review state, the numbered
review record, stage invocation with a real wall-clock deadline, and the trace rows.

`challenge_gate(deps, disposition, *, stages, bounds) -> GateVerdict` is the seam the close
tool drives for a CONFIDENT disposition. It never writes report.md or the review record
itself — the close tool (`close_tool.py`) owns both writes, in the record-first order RS19
pins, and is the one place a fault is held until both are attempted.

The reviewer is BLIND LENSES plus a COMPOSER. Each lens reads a projection of the
investigation that withholds the belief movement it is asked to reconstruct, and they run
concurrently because none reads another's output. The composer runs last and is the only role
that sees both the readings and the investigation's own account — it may be anchored by that
account precisely because the independent work is already banked.

The lens set is SUPPORT and its ABLATION: one reading of what the observed evidence carries,
and the same reading again with one load-bearing edge withheld. #796 shipped a third,
DISCRIMINATION, which asked instead what each lead's possible outcomes could have separated —
a question about lead DESIGN. It is retired: the gate routes on whether the disposition
holds, and a lead that discriminated nothing is a fact about a measurement already taken, so
the finding has nowhere to go. The first measured live run showed exactly that — the composer
discarded both of its findings, one of them in as many words, for 52% of the review's cost and
90% of its wall clock. What is left is a soundness check plus a sensitivity check, which is
what the two-member `holds`/`gap` finding can actually carry.

FAIL CLOSED (RS9): a stage raising, timing out, or otherwise not completing overrides the
confident finding to inconclusive — never a silently-committed close. It commits the SAME
outcome as an override the evidence produced; what separates the two is the typed
`failure_kind`, set only when the machinery is what failed. Having no reviewer at all is the
machinery failing, so it is `error` and not a finding about the case.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from defender._env import env_int
from defender._untrusted import wrap as _wrap

EXTRA_TURN_BOUND = 2

REVIEW_TIMEOUT_ENV = "DEFENDER_REVIEW_STAGE_TIMEOUT_SECONDS"

#: The review roles this gate dispatches, in the order it reports faults for. It is the ONE
#: home for that list: the trace-marking walk reads it rather than restating the names, so a
#: role added to the gate cannot arrive with a trace file the incomplete-marker never touches
#: (the shipped shape restated all three inline, and a stage renamed in one place stayed
#: spelled the old way in the other).
REVIEW_ROLES: tuple[str, ...] = ("support", "ablation", "composer")


def stage_timeout() -> int:
    """The review stages' own deadline knob — 450s default, matching the offline pipeline's
    `subagent_timeout()` default IN VALUE only. A SEPARATE env var: the two must not move
    together."""
    return env_int(REVIEW_TIMEOUT_ENV, 450)


def _retry_budget() -> int:
    # Deferred import: `driver` imports this module (for `Bounds`/`raised_request_limit`);
    # importing `driver` here at module scope would close that cycle.
    from . import driver

    return driver.DEFAULT_TOOL_RETRIES


def _shipped_base_request_limit() -> int:
    """The run's UNRAISED request ceiling, read from its one home. Same deferred import and
    same reason as `_retry_budget`."""
    from . import driver

    return driver.DEFAULT_REQUEST_LIMIT


@dataclass(frozen=True)
class Bounds:
    """RS14. Every bound is INJECTED, never hardcoded at a call site — `EXTRA_TURN_BOUND` is
    the shipped DEFAULT, not a literal restated elsewhere.

    `grace_rounds` is gone with the refinement loop it bounded (#797). There is one review
    pass per close attempt and no second ask, so there is no round budget to spend.

    `base_request_limit` is here for the same reason the cap is: the raised ceiling is
    base-plus-cap, and while the base was a module constant with no path through the entry
    point, "read FROM the cap rather than restated as a literal" could not be told apart from
    a hardcoded copy — the shipped base and a copy of it are the same number. It is also what
    lets the ceiling's THIRD reader (the message store's withhold check) be handed the same
    value the run was, rather than mirroring a stale one."""

    extra_turns: int = EXTRA_TURN_BOUND
    stage_timeout: float = field(default_factory=stage_timeout)
    base_request_limit: int = field(default_factory=_shipped_base_request_limit)

    def __post_init__(self) -> None:
        if self.extra_turns <= 0:
            raise ValueError(
                f"extra_turns must be positive (got {self.extra_turns}) — zero disables the "
                "forced turn the gate exists to force"
            )
        budget = _retry_budget()
        if self.extra_turns >= budget:
            raise ValueError(
                f"extra_turns ({self.extra_turns}) must sit strictly below the framework's "
                f"shared tool-retry budget ({budget}) — reaching it turns a stubborn model's "
                "retry into an uncaught crash instead of a forced close"
            )


def default_bounds() -> Bounds:
    """The shipped bounds. Kept as a FUNCTION though its body is now empty of arguments:
    every call site is a `# lint-default: ok` default-resolution site, and a named
    zero-argument constructor is what makes "the caller passed nothing, so use the shipped
    default" a readable line there rather than a bare `Bounds()` that looks like a literal.
    (Two are the gate's own DI boundaries — `close_investigation` and `run_investigation`;
    the third, `driver._main_extra_capabilities`, resolves the request ceiling FROM the
    shipped bounds because the honest default is derived from them.)

    It used to restate `extra_turns` and `stage_timeout`, which are exactly the dataclass's
    own defaults — so the shipped value lived in two places and only the dataclass's was
    reachable by anything else."""
    return Bounds()


def raised_request_limit(bounds: Bounds) -> int:
    """RS7. Read FROM the bounds the run was handed — both terms — never restated as a
    literal, and never half-read from a module constant the caller cannot move."""
    return bounds.base_request_limit + bounds.extra_turns


@dataclass
class ReviewState:
    """K9. The run's per-run mutable review state — lives in exactly ONE mutable container
    field on the frozen `AgentDeps` (`deps.review_state`, following the `authored_paths`
    precedent)."""

    turns: int = 0
    #: target -> how much of the record mentioned it when the ask was raised.
    #: A dict rather than a set because the overlap rule asks whether the turn already
    #: spent on a target BOUGHT anything, not merely whether the target came up before.
    raised_asks: dict = field(default_factory=dict)
    closed: bool = False
    disposition: str | None = None

    @classmethod
    def of(cls, deps: Any) -> ReviewState:
        box = deps.review_state
        if "state" not in box:
            box["state"] = cls()
        return box["state"]


# --------------------------------------------------------------------------------------
# The review record — RS11: beside the run, temp-plus-rename, keyed by run + turn.
# --------------------------------------------------------------------------------------


def review_record_path(run_dir, turn: int = 1):
    from pathlib import Path

    return Path(run_dir) / f"review_record.{turn}.json"


def write_review_record(run_dir, turn: int, record: dict) -> None:
    from defender._io import write_guarded

    write_guarded(review_record_path(run_dir, turn), json.dumps(record, indent=2), mode="replace")


# --------------------------------------------------------------------------------------
# Stage invocation: real wall-clock bound (PS1's gap closed), distinguishable timeout/error.
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class StageRequest:
    prompt: str
    salt: str
    timeout: float


@dataclass
class StageOutcome:
    text: str | None
    #: `None` when the call completed, otherwise a member of `close_tool.FAILURE_KINDS`.
    #: Deliberately NOT re-listed here: a comment enumerating a subset goes stale the next
    #: time one of them moves — which is the shape that already produced three bugs.
    failure_kind: str | None
    detail: str | None = None

    @property
    def ok(self) -> bool:
        return self.failure_kind is None


async def _call_stage(role: str, stage_fn, request: StageRequest) -> StageOutcome:
    # Deferred import, same reason and same shape as every other close_tool reference in this
    # module: close_tool imports this one at module scope. The two kinds are READ from the
    # published vocabulary rather than spelled here, so the fleet's counting key has exactly
    # one definition site.
    from .close_tool import STAGE_ERROR, TIMEOUT

    try:
        text = await asyncio.wait_for(stage_fn(request), timeout=request.timeout)
        return StageOutcome(text=text, failure_kind=None)
    except TimeoutError:
        return StageOutcome(text=None, failure_kind=TIMEOUT, detail=f"{role} timed out after {request.timeout}s")
    except Exception as e:  # noqa: BLE001 — RS9: any stage fault fails the whole review closed
        return StageOutcome(text=None, failure_kind=STAGE_ERROR, detail=f"{role} failed: {e!r}")


def _fresh_stage_request(render: Callable[[str], str], bounds: Bounds) -> StageRequest:
    """One stage call's request: its own fresh salt, and the prompt RENDERED against it.

    PR7/PR8: every stage call carries its OWN fresh salt (never the investigation's session
    salt) — the review roles never hold the delimiter of the frame their own output returns
    inside. The salt is minted BEFORE the prompt and handed to the renderer, because the frame
    the payload-derived record is inlined inside is keyed on it. Minting it after (or beside)
    the prompt left the salt with no reader at all: the review's inbound half went unframed
    while the field went on saying what it was for."""
    salt = uuid.uuid4().hex
    return StageRequest(prompt=render(salt), salt=salt, timeout=bounds.stage_timeout)


def review_trace_path(run_dir, role: str):
    """One review role's trace file. PUBLIC for the same reason `review_record_path` is: the
    run dir's readers (the runtime visualizer's § Review gate) need the shape, and a second
    site spelling `review_{role}_trace.jsonl` is a filename with two owners."""
    from pathlib import Path

    return Path(run_dir) / f"review_{role}_trace.jsonl"


def _is_row_shaped(raw_reply: str) -> bool:
    """Would any physical line of this framed reply stand in the file as a trace ROW?

    `read_jsonl_rows` — every other trace consumer — skips a line it cannot parse, which is
    what makes the raw-line path below safe for a reply of PROSE. The composer's reply is a
    JSON object by contract, and its framed form puts that object on a line of its own: a
    round-less row carrying the review's prose that every trace reader counts as gate
    metadata.

    The question is ASKED of `_io.parse_jsonl_row` — the same predicate the reader applies —
    rather than re-derived here. The two must agree exactly, because this side decides what
    goes out as a raw line on the strength of the other side skipping it; a reader that
    loosened to accept another JSON type would otherwise reintroduce the corruption from its
    own end, silently, with nothing linking the two definitions."""
    from defender._io import parse_jsonl_row

    return any(parse_jsonl_row(line) is not None for line in raw_reply.splitlines())


def _write_trace_row(
    run_dir, role: str, round_no: int, row: dict, *, raw_reply: str | None = None,
) -> None:
    """Append one trace row, JSON-metadata-only, PLUS (optionally) the stage's raw wrapped
    reply — as its own literal text line when it cannot be mistaken for a row, and inside the
    row's own JSON value when it can.

    A `wrap(...)`-framed reply carries real newline characters; folding it into a JSON
    string field would have `json.dumps` escape them to `\\n`, so the exact framed substring
    a containment test looks for would never appear literally in the file, even though the
    payload-derived text inside it would (JSON only escapes the control characters, not the
    words, so the frame's own tags survive either way). Keeping the frame as a separate raw
    line is what makes "wrapped, never bare" a checkable property of the bytes on disk — but
    only for a reply no reader can parse. A reply that IS a JSON object goes inside the value
    instead; on its own line it would corrupt the trace's row structure."""
    from defender._io import write_guarded

    payload = {"round": round_no, **row}
    inline = raw_reply is not None and _is_row_shaped(raw_reply)
    if inline:
        payload["raw_reply"] = raw_reply
    line = json.dumps(payload) + "\n"
    if raw_reply is not None and not inline:
        line += raw_reply if raw_reply.endswith("\n") else raw_reply + "\n"
    # ONE guarded append per row, not one per physical line: the two lines are a single trace
    # record, and splitting them across two `write_guarded` calls both doubled the syscalls and
    # left a window in which the metadata row was on disk without the reply it describes.
    write_guarded(review_trace_path(run_dir, role), line, mode="append")


def _mark_traces_incomplete(deps: Any, round_no: int, reason: str) -> None:
    """Every review role's trace gets the marker, so a round that ended early is not left
    reading as if it had completed. The roster comes from `REVIEW_ROLES` rather than being
    restated here — with no roles bound this writes nothing, which is the honest record of a
    gate that dispatched nothing.

    The reason rides FRAMED, on the investigation's salt, exactly as the stage replies on the
    same files do. Half of what can land here is stage-derived — a reply the reader refused
    quotes the model's own `finding`/`target`, and a stage error carries the provider's
    message — so an unframed reason puts payload-influenced text into the one artifact whose
    every other untrusted line is wrapped."""
    for role in REVIEW_ROLES:
        _write_trace_row(
            deps.run_dir, role, round_no,
            {"incomplete": True, "reason": _wrap(reason, "untrusted", deps.salt)},
        )


@dataclass
class GateVerdict:
    """One gate attempt's classification, in the three fields that replaced the single
    overloaded `reason`.

    `outcome` says what happened to the disposition (three values). `cause` is the HOST'S own
    sentence for the human reading the case — one of `close_tool.REPORT_CAUSES`, chosen here
    and never composed from a stage's reply. `detail` is the diagnostic and is the ONLY one of
    the three that may quote a stage: it names which stage broke and what it said, so it goes
    to the numbered review record and never to report.md.

    #797 dropped `counter_story`, `direction`, `requirement_list`, `projection_rows` and
    `rounds_used` with the machinery that filled them."""

    outcome: str
    disposition: str
    cause: str
    detail: str
    material: tuple[tuple[str, str], ...]  # (target, ask) pairs
    turns_used: int
    failure_kind: str | None


def _fail(role: str, outcome: StageOutcome, *, turns_used: int) -> GateVerdict:
    """Every way the review can fail to deliver: one outcome, one cause, and the typed kind
    carrying which. The kind comes from the stage outcome rather than from this function, so a
    timeout and a raise stay apart without a branch here to keep in step with the one in
    `_call_stage`.

    `turns_used` is the run's OWN count, passed in rather than written as zero. A challenged
    close comes back and reviews again, so a fault on the second pass reported a run that had
    spent no forced turn — rule 13 of `docs/review-gate-retirement.md` ("the round is a
    parameter, not a hardcoded zero"), one field over from where the round itself was fixed."""
    from .close_tool import CAUSE_REVIEW_INCOMPLETE, FORCED_INCONCLUSIVE

    return GateVerdict(
        outcome=FORCED_INCONCLUSIVE, disposition="inconclusive",
        cause=CAUSE_REVIEW_INCOMPLETE, detail=f"{role}: {outcome.detail}",
        material=(), turns_used=turns_used, failure_kind=outcome.failure_kind,
    )


async def _dispatch(
    role: str, stages: Any, render: Callable[[str], str], bounds: Bounds,
) -> StageOutcome:
    """Look the stage up, BUILD ITS REQUEST, and call it — all three inside the fault arm.

    The lookup used to sit outside `_call_stage`'s `try`, so a bundle missing an attribute
    raised past the gate, past the close tool, and into a driver that classifies five
    exception kinds and not that one. A partial bundle is a review that cannot run, which is
    the same fact as a stage that raised.

    The RENDER is here for exactly that reason too. It walks the parsed companion and
    serialises it, and it runs on a document the investigator authored out of
    attacker-influenced payloads — so it is a step that can raise, and outside this `try` it
    raised past the same three frames. A projection that cannot be built is a review that
    cannot run."""
    from .close_tool import STAGE_ERROR

    try:
        stage_fn = stages.stage(role)
        request = _fresh_stage_request(render, bounds)
    except Exception as e:  # noqa: BLE001 — an unbuildable call fails the review closed
        return StageOutcome(text=None, failure_kind=STAGE_ERROR, detail=str(e) or repr(e))
    return await _call_stage(role, stage_fn, request)


def _mentions(companion: Any, target: str) -> int:
    """How much of the record touches `target`, coarsely.

    The overlap rule's measure. Keying purely on "was this target raised before" refuses a
    second ask on the alert's own subject vertex, which most asks name — a run has three to
    eight vertices where it has many leads, so the retired lead-keyed rule collided an order
    of magnitude less often than a target-keyed one would. What the rule actually means is
    that a repeat is wasteful only when the turn it already spent bought nothing about that
    target, so that is what is measured: if the investigation recorded anything new naming it,
    the ask is fresh again.

    Deliberately a count of occurrences rather than a typed walk. A target may be a vertex, an
    edge, a lead or a hypothesis, and the shapes that can mention each differ; a typed measure
    would need an arm per kind and would silently return zero for the kind it forgot."""
    return json.dumps(companion, sort_keys=True, default=str).count(target)


def _route(
    state: ReviewState, bounds: Bounds, disposition: str, review: Any, companion: Any,
) -> GateVerdict:
    """The composer's finding, plus host state no review role can see, into one arm.

    The reviewer never picks the outcome. Whether a gap becomes `challenged` or
    `forced-inconclusive` turns on the turn count, the raised-ask state and the cap — none of
    which a review role is shown, and all of which decide what the run can still afford."""
    from .close_tool import (
        CAUSE_EVIDENCE_CANNOT_DISCRIMINATE,
        CAUSE_NOTHING_LEFT_TO_ASK,
        CAUSE_STORY_SETTLED,
        CAUSE_TURN_BUDGET_SPENT,
        CHALLENGED,
        FORCED_INCONCLUSIVE,
        NO_CAUSE,
        STANDS,
    )

    def _verdict(outcome, verdict_disposition, cause, detail, *, material=()) -> GateVerdict:
        return GateVerdict(
            outcome=outcome, disposition=verdict_disposition, cause=cause, detail=detail,
            material=material, turns_used=state.turns, failure_kind=None,
        )

    if review.holds:
        return _verdict(STANDS, disposition, CAUSE_STORY_SETTLED, review.review)

    if review.ask is None:
        # A gap with nothing measurable behind it. Forcing inconclusive costs the run
        # nothing further; spending a turn on an ask the reviewer could not name would tax
        # the investigation for a question nobody has.
        return _verdict(
            FORCED_INCONCLUSIVE, "inconclusive", CAUSE_EVIDENCE_CANNOT_DISCRIMINATE,
            review.review,
        )

    target = review.ask.target
    # Measured ONCE: the check and the watermark it writes must be the same number, and
    # `_mentions` serialises the whole companion to get it.
    mentions_now = _mentions(companion, target)
    before = state.raised_asks.get(target)
    if before is not None and mentions_now <= before:
        return _verdict(
            FORCED_INCONCLUSIVE, "inconclusive", CAUSE_NOTHING_LEFT_TO_ASK,
            f"{target} was already asked for and the turn it spent recorded nothing new "
            f"about it — {review.review}",
        )
    if state.turns >= bounds.extra_turns:
        return _verdict(
            FORCED_INCONCLUSIVE, "inconclusive", CAUSE_TURN_BUDGET_SPENT, review.review,
        )

    state.raised_asks[target] = mentions_now
    state.turns += 1
    # NO_CAUSE: this attempt commits nothing, so there is no report.md for a cause to land in.
    return _verdict(
        CHALLENGED, disposition, NO_CAUSE, review.review,
        material=((target, review.ask.prose),),
    )


async def challenge_gate(deps: Any, disposition: str, *, stages: Any, bounds: Bounds) -> GateVerdict:
    """Review one CONFIDENT disposition: the blind lenses, then the composer, then routing.

    Each lens reads a projection of the investigation that withholds the belief movement it
    is asked to reconstruct, and they run CONCURRENTLY because none of them reads another's
    output. The composer runs after all of them and is the only role that sees both the
    readings and the investigation's own account."""
    from defender._io import TEXT_READ_ERRORS, read_text_utf8

    from .close_tool import STAGE_ERROR, UNREADABLE
    from .review.projector import (
        EmptyInvestigation,
        ablation_target,
        composer_projection,
        parse_investigation,
        support_projection,
    )
    from .review.reply import Unreadable, citable_refs, read_composer_reply, read_lens_reading

    state = ReviewState.of(deps)
    # The trace's round is the review PASS this close attempt is, not a hardcoded zero: a
    # challenged close comes back and reviews again, so every row of the second pass would
    # otherwise be indistinguishable from the first's on disk.
    round_no = state.turns

    # A read AND a parse under one `try`, so the guard is the composed tuple `_io` publishes —
    # a `UnicodeDecodeError` is a `ValueError`, NOT an `OSError` (#589), and an `except OSError`
    # here let an undecodable investigation.md raise past the gate, past the close tool and
    # into a driver that classifies five exception kinds and not that one.
    unreadable_document: tuple[type[BaseException], ...] = (EmptyInvestigation, *TEXT_READ_ERRORS)
    # The ablation target is chosen under the SAME guard: it is another walk over the same
    # model-authored document, so it is another step that can raise past the gate, the close
    # tool and the driver rather than failing the review closed.
    #
    # The ablation is the SUPPORT lens again under one withheld edge — same role, same model,
    # same effort, same prompt — so its reading is a difference against the support reading
    # and not a difference between two configurations. A record with no strong belief movement
    # has nothing load-bearing to withhold; that is recorded rather than passed over, so the
    # trace says the lens did not run and why.
    try:
        companion = parse_investigation(read_text_utf8(deps.run_dir / "investigation.md"))
        ablated = ablation_target(companion)
    except unreadable_document as e:
        _mark_traces_incomplete(deps, round_no, str(e))
        return _fail("projector", StageOutcome(None, STAGE_ERROR, str(e)), turns_used=state.turns)
    except Exception as e:  # noqa: BLE001 — a projector fault is a review that cannot run
        _mark_traces_incomplete(deps, round_no, repr(e))
        return _fail("projector", StageOutcome(None, STAGE_ERROR, repr(e)), turns_used=state.turns)
    # Each lens is a RENDERER, not a rendered string: `_fresh_stage_request` mints the call's
    # own salt and the projection is framed on it, so the prompt cannot be built before the
    # salt exists.
    lenses: dict[str, Callable[[str], str]] = {
        "support": lambda salt: support_projection(companion, salt).text,
    }
    if ablated is not None:
        ablated_edge = ablated[0]
        lenses["ablation"] = (
            lambda salt: support_projection(companion, salt, without_edge=ablated_edge).text
        )
    else:
        # NO `ok` KEY. `ok` is the answer verdict of a call that was made, and every trace
        # reader — including the replay's own "the reviewer really ran" assertion — takes
        # `ok: true` as "this stage answered". A lens that was never dispatched has no verdict;
        # `skipped` alone is the honest row.
        _write_trace_row(
            deps.run_dir, "ablation", round_no,
            {"skipped": "no strong belief movement cites an edge to withhold"},
        )
    outcomes = await asyncio.gather(*(
        _dispatch(lens, stages, render, bounds) for lens, render in lenses.items()
    ))

    # EVERY dispatched lens gets its row before any of them is judged. The calls ran
    # concurrently and all of them completed; returning on the first fault mid-walk threw away
    # the replies the other lenses had already produced, so a run dir recorded a subset of the
    # calls that were made.
    for lens, outcome in zip(lenses, outcomes, strict=True):
        _write_trace_row(
            deps.run_dir, lens, round_no, {"ok": outcome.ok},
            raw_reply=_wrap(outcome.text or outcome.detail or "", "untrusted", deps.salt),
        )

    readings: dict[str, str] = {}
    for lens, outcome in zip(lenses, outcomes, strict=True):
        if not outcome.ok:
            _mark_traces_incomplete(deps, round_no, outcome.detail or "stage fault")
            return _fail(lens, outcome, turns_used=state.turns)
        try:
            readings[lens] = read_lens_reading(outcome.text)
        except Unreadable as e:
            _mark_traces_incomplete(deps, round_no, str(e))
            return _fail(lens, StageOutcome(None, UNREADABLE, str(e)), turns_used=state.turns)

    composer = await _dispatch(
        "composer", stages,
        lambda salt: composer_projection(companion, readings, salt, ablated=ablated).text,
        bounds,
    )
    _write_trace_row(
        deps.run_dir, "composer", round_no, {"ok": composer.ok},
        raw_reply=_wrap(composer.text or composer.detail or "", "untrusted", deps.salt),
    )
    if not composer.ok:
        _mark_traces_incomplete(deps, round_no, composer.detail or "stage fault")
        return _fail("composer", composer, turns_used=state.turns)
    try:
        review = read_composer_reply(composer.text, refs=citable_refs(companion))
    except Unreadable as e:
        _mark_traces_incomplete(deps, round_no, str(e))
        return _fail("composer", StageOutcome(None, UNREADABLE, str(e)), turns_used=state.turns)

    return _route(state, bounds, disposition, review, companion)


__all__ = [
    "Bounds",
    "EXTRA_TURN_BOUND",
    "GateVerdict",
    "REVIEW_ROLES",
    "ReviewState",
    "StageRequest",
    "challenge_gate",
    "default_bounds",
    "raised_request_limit",
    "review_record_path",
    "review_trace_path",
    "stage_timeout",
    "write_review_record",
]
