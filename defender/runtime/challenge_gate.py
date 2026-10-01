"""The write-time review gate's harness: bounds, per-run review state, the review record,
stage invocation with a wall-clock deadline, and the trace rows.

`challenge_gate` reviews every close except the host's own `unresolved`: a confident
disposition against its conclusion, `inconclusive` against its ceiling claim. It never writes
report.md or the review record; `close_tool.py` owns both writes.

The reviewer is blind lenses plus a composer. Each lens reads a projection that withholds the
belief movement it must reconstruct, and lenses run concurrently since none reads another's
output. The lenses are SUPPORT and its ABLATION (the same reading with one load-bearing edge
withheld): a soundness plus a sensitivity check. The composer runs last and alone sees both
the readings and the investigation's own account; its question is keyed on the disposition and
phrased so "yes" always means the close stands.

Fail closed: a stage that raises, times out, or otherwise does not complete overrides any
reviewed disposition (including `inconclusive`) to the host's `unresolved`, so an unexamined
model claim never commits as the model's claim. The typed `failure_kind` distinguishes a
machinery failure from an evidence-driven override with the same outcome.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from collections.abc import Callable
from dataclasses import field
from defender._model import model
from typing import Any

from defender._env import env_int
from defender._untrusted import wrap_fresh
from defender._vocab import CEILING_DISPOSITION, HOST_ONLY_DISPOSITION
from defender.skills.invlang.schema import CompanionBody

_logger = logging.getLogger(__name__)

EXTRA_TURN_BOUND = 2

REVIEW_TIMEOUT_ENV = "DEFENDER_REVIEW_STAGE_TIMEOUT_SECONDS"

#: The review roles this gate dispatches, in fault-report order. The trace-marking walk reads
#: this, so a new role cannot have a trace file the incomplete-marker misses.
REVIEW_ROLES: tuple[str, ...] = ("support", "ablation", "composer")


def stage_timeout() -> int:
    """The review stages' deadline (default 450s). Its own env var, independent of the offline
    pipeline's `subagent_timeout()`."""
    return env_int(REVIEW_TIMEOUT_ENV, 450)


def _retry_budget() -> int:
    # Deferred import: `driver` imports this module (for `Bounds`/`raised_request_limit`);
    # importing `driver` here at module scope would close that cycle.
    from . import driver

    return driver.DEFAULT_TOOL_RETRIES


def _shipped_base_request_limit() -> int:
    """The run's unraised request ceiling. Deferred import, as in `_retry_budget`."""
    from . import driver

    return driver.DEFAULT_REQUEST_LIMIT


@model(frozen=True)
class Bounds:
    """The review gate's injected bounds. One review pass per close attempt, so there is no
    round budget.

    `base_request_limit` is carried so the raised ceiling (base plus `extra_turns`) is read
    from the bounds the run was handed, including by the message store's withhold check."""

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
    """The shipped bounds. A named function so default-resolution call sites read as such
    rather than as a literal `Bounds()`."""
    return Bounds()


def raised_request_limit(bounds: Bounds) -> int:
    """The raised request ceiling, with both terms read from the run's bounds."""
    return bounds.base_request_limit + bounds.extra_turns


@model
class ReviewState:
    """Per-run mutable review state, held in `deps.review_state` on the frozen `AgentDeps`."""

    turns: int = 0
    #: target -> how much of the record mentioned it when the ask was raised, so the overlap
    #: rule can tell whether the turn spent on it recorded anything new.
    raised_asks: dict = field(default_factory=dict)
    closed: bool = False
    disposition: str | None = None

    @classmethod
    def of(cls, deps: Any) -> ReviewState:
        box = deps.review_state
        if "state" not in box:
            box["state"] = cls()
        return box["state"]


# The review record: beside the run, temp-plus-rename, keyed by turn. The path is owned by
# `RunPaths.review_record`.


def write_review_record(run_dir, turn: int, record: dict) -> None:
    from defender._io import write_guarded
    from defender._run_paths import RunPaths

    write_guarded(
        RunPaths(run_dir).review_record(turn), json.dumps(record, indent=2), mode="replace")


# Stage invocation: real wall-clock bound, distinguishable timeout/error.


@model(frozen=True)
class StageRequest:
    prompt: str
    salt: str
    timeout: float


@model
class StageOutcome:
    text: str | None
    #: `None` when the call completed, otherwise a member of `close_tool.FAILURE_KINDS`.
    failure_kind: str | None
    detail: str | None = None

    @property
    def ok(self) -> bool:
        return self.failure_kind is None


async def _call_stage(role: str, stage_fn, request: StageRequest) -> StageOutcome:
    # Deferred: close_tool imports this module at module scope.
    from .close_tool import STAGE_ERROR, TIMEOUT

    try:
        text = await asyncio.wait_for(stage_fn(request), timeout=request.timeout)
        return StageOutcome(text=text, failure_kind=None)
    except TimeoutError:
        return StageOutcome(text=None, failure_kind=TIMEOUT, detail=f"{role} timed out after {request.timeout}s")
    except Exception as e:  # noqa: BLE001 — any stage fault fails the whole review closed
        return StageOutcome(text=None, failure_kind=STAGE_ERROR, detail=f"{role} failed: {e!r}")


def _fresh_stage_request(render: Callable[[str], str], bounds: Bounds) -> StageRequest:
    """One stage call's request: a fresh salt and the prompt rendered against it.

    A fresh salt (never the session salt) keeps review roles from holding the delimiter of the
    frame their output returns inside. It is minted before rendering because the prompt's
    framing of the payload-derived record is keyed on it."""
    salt = uuid.uuid4().hex
    return StageRequest(prompt=render(salt), salt=salt, timeout=bounds.stage_timeout)


def _is_row_shaped(raw_reply: str) -> bool:
    """Whether any line of this framed reply would parse as a trace row.

    Trace readers skip unparseable lines, so a prose reply can go out as raw lines; a JSON
    reply (the composer's) would be read as a row. Uses the reader's own predicate
    (`_io.parse_jsonl_row`) so the two agree exactly."""
    from defender._io import parse_jsonl_row

    return any(parse_jsonl_row(line) is not None for line in raw_reply.splitlines())


def _write_trace_row(
    run_dir, role: str, round_no: int, row: dict, *, raw_reply: str | None = None,
) -> None:
    """Append one trace row, optionally followed by the stage's raw wrapped reply.

    The reply goes out as literal lines, so its framing is checkable in the bytes on disk
    (inside a JSON string the newlines would be escaped), unless it could be parsed as a row,
    in which case it goes inside the row's JSON instead."""
    from pathlib import Path

    from defender._io import guarded_mkdir, write_guarded

    payload = {"round": round_no, **row}
    inline = raw_reply is not None and _is_row_shaped(raw_reply)
    if inline:
        payload["raw_reply"] = raw_reply
    line = json.dumps(payload) + "\n"
    if raw_reply is not None and not inline:
        line += raw_reply if raw_reply.endswith("\n") else raw_reply + "\n"
    # One guarded append so the row and its reply land together. The directory is created
    # here (the `RunPaths` resolver stays pure), guarded from the run dir: the box's rw bind.
    from defender._run_paths import RunPaths

    path = RunPaths(Path(run_dir)).review_trace(role)
    guarded_mkdir(path.parent, base=Path(run_dir))
    write_guarded(path, line, mode="append")


def _mark_traces_incomplete(deps: Any, round_no: int, reason: str) -> None:
    """Mark every review role's trace incomplete, so a round that ended early does not read
    as completed.

    The reason is framed like the stage replies because it can be stage-derived (a quoted
    `finding`/`target`, a provider error message)."""
    for role in REVIEW_ROLES:
        _write_trace_row(
            deps.run_dir, role, round_no,
            {"incomplete": True, "reason": wrap_fresh(reason, "untrusted")},
        )


@model
class GateVerdict:
    """One gate attempt's classification.

    `cause` is the host's own sentence (one of `close_tool.REPORT_CAUSES`), never composed from
    a stage reply. `detail` is the only field that may quote a stage, so it goes to the review
    record and never to report.md."""

    outcome: str
    disposition: str
    cause: str
    detail: str
    material: tuple[tuple[str, str], ...]  # (target, ask) pairs
    turns_used: int
    failure_kind: str | None


def _fail(role: str, outcome: StageOutcome, *, turns_used: int) -> GateVerdict:
    """The verdict for a review that failed to deliver. The override is the same for every
    disposition; the failure kind comes from the stage outcome. `turns_used` is the run's
    count, since a challenged close reviews again."""
    from .close_tool import CAUSE_REVIEW_INCOMPLETE, FORCED_INCONCLUSIVE

    return GateVerdict(
        outcome=FORCED_INCONCLUSIVE, disposition=HOST_ONLY_DISPOSITION,
        cause=CAUSE_REVIEW_INCOMPLETE, detail=f"{role}: {outcome.detail}",
        material=(), turns_used=turns_used, failure_kind=outcome.failure_kind,
    )


def review_cannot_run(deps: Any, reason: str) -> GateVerdict:
    """The verdict for a close whose companion could not be read at all (I/O fault, planted
    non-plain entry, non-UTF-8). Reported like a projector fault: a review that cannot run.

    The trace-marker write is contained here, unlike elsewhere: this arm is reached on a fault
    in the run dir itself, where the write is likely to fail too, and an `OSError` escaping the
    tool would end the run with no report.md."""
    from .close_tool import STAGE_ERROR

    state = ReviewState.of(deps)
    try:
        _mark_traces_incomplete(deps, state.turns, reason)
    except OSError as exc:
        _logger.warning(
            f"the review-cannot-run marker could not be written ({exc!r}); the verdict "
            f"stands without its trace rows",
        )
    return _fail("companion", StageOutcome(None, STAGE_ERROR, reason), turns_used=state.turns)


async def _dispatch(
    role: str, stages: Any, render: Callable[[str], str], bounds: Bounds,
) -> StageOutcome:
    """Look the stage up, build its request, and call it, all inside the fault arm: a partial
    stage bundle or a render that raises over the model-authored companion is a review that
    cannot run, not an exception for the driver."""
    from .close_tool import STAGE_ERROR

    try:
        stage_fn = stages.stage(role)
        request = _fresh_stage_request(render, bounds)
    except Exception as e:  # noqa: BLE001 — an unbuildable call fails the review closed
        return StageOutcome(text=None, failure_kind=STAGE_ERROR, detail=str(e) or repr(e))
    return await _call_stage(role, stage_fn, request)


def _mentions(companion: Any, target: str) -> int:
    """How much of the record touches `target`, coarsely: the overlap rule's measure.

    A repeat ask is refused only if the previous turn recorded nothing new naming the target
    (asks often name the alert's own subject vertex). A raw occurrence count rather than a
    typed walk, which would need an arm per target kind and silently miss one."""
    return json.dumps(companion, sort_keys=True, default=str).count(target)


def _route(
    state: ReviewState, bounds: Bounds, disposition: str, review: Any, companion: Any,
) -> GateVerdict:
    """Route the composer's finding plus host state into one verdict.

    The reviewer never picks the outcome: challenge vs override turns on the turn count, the
    raised-ask state and the cap, none of which a review role sees. `disposition` only decides
    what a stands/challenged verdict carries and which cause a `holds` earns; the override
    arms are the same for every disposition."""
    from .close_tool import (
        CAUSE_CEILING_EXAMINED,
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
        cause = CAUSE_CEILING_EXAMINED if disposition == CEILING_DISPOSITION else CAUSE_STORY_SETTLED
        return _verdict(STANDS, disposition, cause, review.review)

    if review.ask is None:
        # A gap with no nameable ask: don't spend a turn on it.
        return _verdict(
            FORCED_INCONCLUSIVE, HOST_ONLY_DISPOSITION, CAUSE_EVIDENCE_CANNOT_DISCRIMINATE,
            review.review,
        )

    target = review.ask.target
    # Measured once: the check and the watermark must be the same number.
    mentions_now = _mentions(companion, target)
    before = state.raised_asks.get(target)
    if before is not None and mentions_now <= before:
        return _verdict(
            FORCED_INCONCLUSIVE, HOST_ONLY_DISPOSITION, CAUSE_NOTHING_LEFT_TO_ASK,
            f"{target} was already asked for and the turn it spent recorded nothing new "
            f"about it — {review.review}",
        )
    if state.turns >= bounds.extra_turns:
        return _verdict(
            FORCED_INCONCLUSIVE, HOST_ONLY_DISPOSITION, CAUSE_TURN_BUDGET_SPENT, review.review,
        )

    state.raised_asks[target] = mentions_now
    state.turns += 1
    # NO_CAUSE: this attempt commits no report.md.
    return _verdict(
        CHALLENGED, disposition, NO_CAUSE, review.review,
        material=((target, review.ask.prose),),
    )


async def challenge_gate(
    deps: Any, disposition: str, companion: CompanionBody, *, stages: Any, bounds: Bounds,
) -> GateVerdict:
    """Review one disposition (confident or `inconclusive`, never `unresolved`): the blind
    lenses concurrently, then the composer, then routing.

    `disposition` is the close's own argument; the gate never re-derives it from the
    companion. `companion` is the close's single parse of `investigation.md`, handed in rather
    than re-read so every reader on the close judges the same object."""
    from .close_tool import STAGE_ERROR, UNREADABLE
    from .review.projector import (
        EmptyInvestigation,
        ablation_target,
        composer_projection,
        require_investigation,
        support_projection,
    )
    from .review.reply import Unreadable, citable_refs, read_composer_reply, read_lens_reading

    state = ReviewState.of(deps)
    # A challenged close reviews again; the round keeps the passes apart on disk.
    round_no = state.turns

    # Guarded like the emptiness check: a walk over a model-authored document can raise. The
    # ablation is the support lens with one edge withheld (same role, model and prompt), so
    # its reading differs from support's only by that edge.
    try:
        ablated = ablation_target(require_investigation(companion))
    except EmptyInvestigation as e:
        _mark_traces_incomplete(deps, round_no, str(e))
        return _fail("projector", StageOutcome(None, STAGE_ERROR, str(e)), turns_used=state.turns)
    except Exception as e:  # noqa: BLE001 — a projector fault is a review that cannot run
        _mark_traces_incomplete(deps, round_no, repr(e))
        return _fail("projector", StageOutcome(None, STAGE_ERROR, repr(e)), turns_used=state.turns)
    # Renderers, not strings: the prompt is framed on a salt minted per call.
    lenses: dict[str, Callable[[str], str]] = {
        "support": lambda salt: support_projection(companion, salt).text,
    }
    if ablated is not None:
        ablated_edge = ablated[0]
        lenses["ablation"] = (
            lambda salt: support_projection(companion, salt, without_edge=ablated_edge).text
        )
    else:
        # No `ok` key: readers take `ok` as "this stage answered", and it was never dispatched.
        _write_trace_row(
            deps.run_dir, "ablation", round_no,
            {"skipped": "no strong belief movement cites an edge to withhold"},
        )
    outcomes = await asyncio.gather(*(
        _dispatch(lens, stages, render, bounds) for lens, render in lenses.items()
    ))

    # Record every lens's reply before judging any, so a fault doesn't drop the others'.
    for lens, outcome in zip(lenses, outcomes, strict=True):
        _write_trace_row(
            deps.run_dir, lens, round_no, {"ok": outcome.ok},
            raw_reply=wrap_fresh(outcome.text or outcome.detail or "", "untrusted"),
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
        lambda salt: composer_projection(
            companion, readings, salt, ablated=ablated, disposition=disposition,
        ).text,
        bounds,
    )
    _write_trace_row(
        deps.run_dir, "composer", round_no, {"ok": composer.ok},
        raw_reply=wrap_fresh(composer.text or composer.detail or "", "untrusted"),
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
    "stage_timeout",
    "write_review_record",
]
