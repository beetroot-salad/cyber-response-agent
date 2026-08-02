"""#774 — the live write-time challenge gate: bounds, per-run review state, the review
record, and the three-stage orchestration (`challenge_gate`) the close tool drives.

`challenge_gate(deps, disposition, *, stages, bounds) -> GateVerdict` runs the challenger,
then the coherence checker and the oracle-projection stage CONCURRENTLY (both act on the
challenger's own output), and classifies the outcome. It never writes report.md or the
review record itself — the close tool (`close_tool.py`) owns both writes, in the
record-first order RS19 pins, and is the one place a fault is held until both are attempted.
This module owns the STAGE machinery: bounds, deadlines, the discriminator rule, and the
per-run review state.

FAIL CLOSED (RS9): any of the three stage calls raising, timing out, or otherwise not
completing forces `REVIEW_FAILED` — never a silently-committed close.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from dataclasses import dataclass, field
from typing import Any

from defender._env import env_int
from defender._untrusted import wrap as _wrap
from defender.learning.core.directions import directions_for
from defender.runtime import review_roles

EXTRA_TURN_BOUND = 2
GRACE_BOUND = 1

REVIEW_TIMEOUT_ENV = "DEFENDER_REVIEW_STAGE_TIMEOUT_SECONDS"


def stage_timeout() -> int:
    """The review stages' own deadline knob — 450s default, matching the offline pipeline's
    `subagent_timeout()` default IN VALUE only. A SEPARATE env var: the two must not move
    together (`test_moving_the_generic_subagent_deadline_does_not_move_the_reviews`)."""
    return env_int(REVIEW_TIMEOUT_ENV, 450)


def _retry_budget() -> int:
    # Deferred import: `driver` imports this module (for `Bounds`/`raised_request_limit`);
    # importing `driver` here at module scope would close that cycle.
    from . import driver

    return driver.DEFAULT_TOOL_RETRIES


@dataclass(frozen=True)
class Bounds:
    """RS14. Both bounds are INJECTED, never hardcoded at a call site — `EXTRA_TURN_BOUND`/
    `GRACE_BOUND` are the shipped DEFAULTS, not literals restated elsewhere."""

    extra_turns: int = EXTRA_TURN_BOUND
    grace_rounds: int = GRACE_BOUND
    stage_timeout: float = field(default_factory=stage_timeout)

    def __post_init__(self) -> None:
        if self.extra_turns <= 0:
            raise ValueError(
                f"extra_turns must be positive (got {self.extra_turns}) — zero disables the "
                "forced turn the gate exists to force"
            )
        if self.grace_rounds <= 0:
            raise ValueError(
                f"grace_rounds must be positive (got {self.grace_rounds}) — zero disables the "
                "sole evidence-strength signal (rounds consumed)"
            )
        budget = _retry_budget()
        if self.extra_turns >= budget:
            raise ValueError(
                f"extra_turns ({self.extra_turns}) must sit strictly below the framework's "
                f"shared tool-retry budget ({budget}) — reaching it turns a stubborn model's "
                "retry into an uncaught crash instead of a forced close"
            )


def default_bounds() -> Bounds:
    return Bounds(extra_turns=EXTRA_TURN_BOUND, grace_rounds=GRACE_BOUND, stage_timeout=stage_timeout())


def raised_request_limit(bounds: Bounds) -> int:
    """RS7. Read FROM the cap, never restated as a literal."""
    from . import driver

    return driver.DEFAULT_REQUEST_LIMIT + bounds.extra_turns


@dataclass
class ReviewState:
    """K9. The run's per-run mutable review state — lives in exactly ONE mutable container
    field on the frozen `AgentDeps` (`deps.review_state`, following the `authored_paths`
    precedent)."""

    turns: int = 0
    raised_leads: set = field(default_factory=set)
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
    from defender._io import write_atomic

    write_atomic(review_record_path(run_dir, turn), json.dumps(record, indent=2))


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
    failure_kind: str | None  # None | "timeout" | "error"
    detail: str | None = None

    @property
    def ok(self) -> bool:
        return self.failure_kind is None


async def _call_stage(role: str, stage_fn, request: StageRequest) -> StageOutcome:
    try:
        text = await asyncio.wait_for(stage_fn(request), timeout=request.timeout)
        return StageOutcome(text=text, failure_kind=None)
    except TimeoutError:
        return StageOutcome(text=None, failure_kind="timeout", detail=f"{role} timed out after {request.timeout}s")
    except Exception as e:  # noqa: BLE001 — RS9: any stage fault fails the whole review closed
        return StageOutcome(text=None, failure_kind="error", detail=f"{role} failed: {e!r}")


def _trace_path(run_dir, role: str):
    from pathlib import Path

    return Path(run_dir) / f"review_{role}_trace.jsonl"


def _write_trace_row(
    run_dir, role: str, round_no: int, row: dict, *, raw_reply: str | None = None,
) -> None:
    """Append one trace row, JSON-metadata-only, PLUS (optionally) the stage's raw wrapped
    reply as its own literal text line right after — never as a JSON string VALUE.

    A `wrap(...)`-framed reply carries real newline characters; folding it into a JSON
    string field would have `json.dumps` escape them to `\\n`, so the exact framed
    substring `test_no_counter_story_prose_reaches_the_main_session` looks for would never
    appear literally in the file, even though the payload-derived text inside it would
    (JSON only escapes the control characters, not the words). Keeping the frame as a
    separate raw line is what makes "wrapped, never bare" a checkable property of the bytes
    on disk. `read_jsonl_rows` (every other trace consumer) tolerates it fine — a raw line
    that is not valid JSON is simply skipped, so the metadata rows (round/incomplete) stay
    exactly as parseable as before."""
    from defender._io import append_jsonl

    append_jsonl(_trace_path(run_dir, role), [{"round": round_no, **row}])
    if raw_reply is not None:
        path = _trace_path(run_dir, role)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(raw_reply)
            if not raw_reply.endswith("\n"):
                fh.write("\n")


def _mark_traces_incomplete(run_dir, round_no: int, reason: str) -> None:
    for role in ("challenger", "coherence_checker", "oracle"):
        _write_trace_row(run_dir, role, round_no, {"incomplete": True, "reason": reason})


# --------------------------------------------------------------------------------------
# The challenger output contract.
# --------------------------------------------------------------------------------------


class Malformed(Exception):
    pass


def _parse_challenger_reply(text: str) -> dict:
    try:
        obj = json.loads(text)
    except json.JSONDecodeError as e:
        raise Malformed(f"challenger output did not parse as JSON: {e}") from e
    if not isinstance(obj, dict):
        raise Malformed("challenger output is not a JSON object")
    if obj.get("declined"):
        if "reason" not in obj:
            raise Malformed("a declined challenger reply must carry a reason")
        return obj
    if obj.get("counter_story") is None:
        raise Malformed("challenger output has no counter_story and does not declare declined")
    requirements = obj.get("requirements")
    if not isinstance(requirements, list):
        raise Malformed("challenger output carries no requirements list")
    for item in requirements:
        if not isinstance(item, dict) or not ({"assertion", "settled_by", "if_false"} <= item.keys()):
            raise Malformed(
                f"a requirement is missing assertion/settled_by/if_false: {item!r}"
            )
    return obj


def _classify_projection(rows: list[tuple[str, str]]) -> tuple[str, list[str]]:
    """The oracle's tags folded into the discriminator rule. Returns
    `(bucket, discriminating_lead_ids)` where `bucket` is one of `evidence_silent` /
    `all_confirmed` / `discriminated`.

    `no-projection` and `empty-projection` are both "silence" (the story is not confirmed),
    but only `empty-projection` rows are ELIGIBLE discriminators — an on-topic query that
    came back empty. A `no-projection` tag means the projection mechanism did not even apply
    to that lead (off-topic), and with no confirming row anywhere either (`has-projection`
    absent), its presence signals the evidence set broadly fails to engage with the story —
    RS13's "cannot speak" reading — rather than that one particular empty-projection lead is
    a real discriminator."""
    total = len(rows)
    has = [lid for lid, tag in rows if tag == "has-projection"]
    no_projection = [lid for lid, tag in rows if tag == "no-projection"]
    empty_projection = [lid for lid, tag in rows if tag == "empty-projection"]
    if total == 0:
        return "evidence_silent", []
    if not has and no_projection:
        return "evidence_silent", []
    if not empty_projection:
        return "all_confirmed", []
    return "discriminated", empty_projection


@dataclass
class GateVerdict:
    outcome: str
    disposition: str
    reason: str
    material: tuple[tuple[str, str], ...]  # (lead_id, requirement) pairs
    turns_used: int
    rounds_used: int
    failure_kind: str | None
    counter_story: str | None
    direction: str
    requirement_list: list
    projection_rows: list


REQUIREMENT_MAX = 500


def _executed_lead_ids(run_dir) -> tuple[str, ...]:
    from pathlib import Path

    d = Path(run_dir) / "gather_raw"
    if not d.is_dir():
        return ()
    return tuple(sorted(p.name[: -len(".lead.json")] for p in d.glob("*.lead.json")))


def _fresh_stage_request(prompt: str, bounds: Bounds) -> StageRequest:
    # PR7/PR8: every stage call carries its OWN fresh salt (never the investigation's
    # session salt) — the review roles never hold the delimiter of the frame their own
    # output returns inside.
    return StageRequest(prompt=prompt, salt=uuid.uuid4().hex, timeout=bounds.stage_timeout)


async def _run_challenger_once(
    deps: Any, stages: Any, bounds: Bounds, prompt: str, round_no: int,
) -> tuple[dict | None, StageOutcome | None, str | None]:
    """One challenger call + its trace row. Returns `(reply, fail_outcome, malformed_reason)`
    — exactly one of the three is non-None/non-empty."""
    outcome = await _call_stage("challenger", stages.challenger, _fresh_stage_request(prompt, bounds))
    if not outcome.ok:
        _write_trace_row(
            deps.run_dir, "challenger", round_no, {"ok": False},
            raw_reply=_wrap(outcome.detail or "", "untrusted", deps.salt),
        )
        return None, outcome, None

    try:
        reply = _parse_challenger_reply(outcome.text or "")
    except Malformed as e:
        # A truncated/unparseable reply is not JSON-shaped by construction, so it's safe
        # to wrap and log verbatim without risking a stray parseable JSON line.
        _write_trace_row(
            deps.run_dir, "challenger", round_no, {"ok": True, "malformed": True},
            raw_reply=_wrap(outcome.text or "", "untrusted", deps.salt),
        )
        return None, None, str(e)

    # Log only the counter-story/decline-reason TEXT, wrapped — never the raw JSON reply
    # verbatim: the reply's own JSON shape would otherwise stand as its own valid,
    # round-less JSONL row once split onto its own physical line, corrupting the trace's
    # own row structure. The prose is what the containment negative is about anyway.
    story_for_trace = str(reply.get("counter_story") or reply.get("reason") or "")
    _write_trace_row(
        deps.run_dir, "challenger", round_no, {"ok": True},
        raw_reply=_wrap(story_for_trace, "untrusted", deps.salt),
    )
    return reply, None, None


async def _run_coherence_and_projection_once(
    deps: Any, stages: Any, bounds: Bounds, counter_story: str, round_no: int,
) -> tuple[StageOutcome, StageOutcome]:
    """The concurrent coherence-checker + oracle-projection pair, plus their trace rows."""
    coherence_req = _fresh_stage_request(
        review_roles.build_coherence_checker_input(counter_story), bounds,
    )
    executed_lead_ids = _executed_lead_ids(deps.run_dir)
    projection_req = _fresh_stage_request(
        review_roles.build_projection_input(deps, counter_story, executed_lead_ids), bounds,
    )
    coherence_task = _call_stage("coherence_checker", stages.coherence_checker, coherence_req)
    projection_task = _call_stage("oracle", stages.projection, projection_req)
    coherence_outcome, projection_outcome = await asyncio.gather(coherence_task, projection_task)

    # Neither stage's reply is payload-derived PROSE the containment negative targets
    # (coherence checker answers COHERENT/INCOHERENT; the oracle's tags are host-computed
    # structure) — logged as an ordinary escaped JSON field, which also sidesteps the
    # oracle's reply being valid JSON in its own right (the same hazard the challenger's
    # raw-line path avoids by never carrying the whole reply verbatim).
    _write_trace_row(
        deps.run_dir, "coherence_checker", round_no,
        {"ok": coherence_outcome.ok, "reply": coherence_outcome.text or coherence_outcome.detail},
    )
    _write_trace_row(
        deps.run_dir, "oracle", round_no,
        {"ok": projection_outcome.ok, "reply": projection_outcome.text or projection_outcome.detail},
    )
    return coherence_outcome, projection_outcome


def _finalize_verdict(
    state: ReviewState, bounds: Bounds, disposition: str, direction_name: str,
    challenger_reply: dict, projection_outcome: StageOutcome, round_no: int,
) -> GateVerdict:
    """The post-coherent classification: settled/refuted, the discriminator rule
    (evidence-silent / all-confirmed / discriminated), and the forced-turn cap."""
    from .close_tool import CHALLENGED, EVIDENCE_SILENT, FORCED_CAP, FORCED_NONDISCRIMINATING, REFUTED

    requirements = challenger_reply.get("requirements", [])
    unsettled = [r for r in requirements if r.get("settled_by") is None]
    counter_story = challenger_reply["counter_story"]

    try:
        projection_obj = json.loads(projection_outcome.text or "{}")
        rows = [(row["lead_id"], row["tag"]) for row in projection_obj.get("leads", [])]
    except (json.JSONDecodeError, KeyError, TypeError):
        rows = []

    def _verdict(outcome: str, verdict_disposition: str, reason: str, *, material=(), turns_used=0) -> GateVerdict:
        return GateVerdict(
            outcome=outcome, disposition=verdict_disposition, reason=reason,
            material=material, turns_used=turns_used, rounds_used=round_no,
            failure_kind=None, counter_story=counter_story, direction=direction_name,
            requirement_list=requirements, projection_rows=rows,
        )

    if not unsettled:
        return _verdict(
            REFUTED, disposition,
            "the counter-story's requirements are all already settled by existing evidence",
        )

    bucket, discriminating = _classify_projection(rows)

    if bucket == "evidence_silent":
        return _verdict(
            EVIDENCE_SILENT, "inconclusive", "no executed lead's evidence can speak to the counter-story",
        )
    if bucket == "all_confirmed":
        return _verdict(
            FORCED_NONDISCRIMINATING, "inconclusive",
            "every executed lead's evidence speaks to the counter-story; none is silent",
        )

    # discriminated — a real forced turn, subject to the extra-turn cap.
    if state.turns >= bounds.extra_turns:
        return _verdict(
            FORCED_CAP, "inconclusive", "the forced-turn bound is exhausted", turns_used=state.turns,
        )

    fresh = sorted(lid for lid in discriminating if lid not in state.raised_leads)
    requirement_text = (unsettled[0].get("assertion") or "")[:REQUIREMENT_MAX]
    material: tuple[tuple[str, str], ...] = ()
    if fresh:
        top = fresh[0]
        state.raised_leads.add(top)
        material = ((top, requirement_text),)
    state.turns += 1
    return _verdict(
        CHALLENGED, disposition,
        "the counter-story survived and left a discriminating lead untested",
        material=material, turns_used=state.turns,
    )


async def challenge_gate(deps: Any, disposition: str, *, stages: Any, bounds: Bounds) -> GateVerdict:
    from .close_tool import DECLINED, INCOHERENT, MALFORMED, REVIEW_FAILED

    state = ReviewState.of(deps)
    directions = directions_for(disposition)
    direction = directions[0] if directions else None
    direction_name = direction.name if direction is not None else "unknown"

    def _fail(role: str, outcome: StageOutcome) -> GateVerdict:
        return GateVerdict(
            outcome=REVIEW_FAILED, disposition="inconclusive",
            reason=f"{role}: {outcome.detail}",
            material=(), turns_used=0, rounds_used=0,
            failure_kind=outcome.failure_kind,
            counter_story=None, direction=direction_name,
            requirement_list=[], projection_rows=[],
        )

    challenger_prompt = review_roles.build_challenger_input(deps, disposition, direction)
    round_no = 0

    while True:
        reply, fail_outcome, malformed_reason = await _run_challenger_once(
            deps, stages, bounds, challenger_prompt, round_no,
        )
        if fail_outcome is not None:
            _mark_traces_incomplete(deps.run_dir, round_no, fail_outcome.detail or "stage fault")
            return _fail("challenger", fail_outcome)
        if reply is None:
            return GateVerdict(
                outcome=MALFORMED, disposition="inconclusive",
                reason=malformed_reason or "challenger output did not parse",
                material=(), turns_used=0, rounds_used=round_no,
                failure_kind=None, counter_story=None, direction=direction_name,
                requirement_list=[], projection_rows=[],
            )
        if reply.get("declined"):
            return GateVerdict(
                outcome=DECLINED, disposition=disposition,
                reason=str(reply.get("reason", "")),
                material=(), turns_used=0, rounds_used=round_no,
                failure_kind=None, counter_story=None, direction=direction_name,
                requirement_list=[], projection_rows=[],
            )

        coherence_outcome, projection_outcome = await _run_coherence_and_projection_once(
            deps, stages, bounds, reply["counter_story"], round_no,
        )
        if not coherence_outcome.ok:
            _mark_traces_incomplete(deps.run_dir, round_no, coherence_outcome.detail or "stage fault")
            return _fail("coherence_checker", coherence_outcome)
        if not projection_outcome.ok:
            _mark_traces_incomplete(deps.run_dir, round_no, projection_outcome.detail or "stage fault")
            return _fail("oracle", projection_outcome)

        coherent = "INCOHERENT" not in (coherence_outcome.text or "").upper()
        if coherent:
            return _finalize_verdict(
                state, bounds, disposition, direction_name, reply, projection_outcome, round_no,
            )
        if round_no >= bounds.grace_rounds:
            return GateVerdict(
                outcome=INCOHERENT, disposition="inconclusive",
                reason="the counter-story did not settle into internal consistency",
                material=(), turns_used=0, rounds_used=round_no,
                failure_kind=None, counter_story=None, direction=direction_name,
                requirement_list=reply.get("requirements", []), projection_rows=[],
            )
        round_no += 1
        # Refine: re-invoke the challenger for one more round.


__all__ = [
    "Bounds",
    "EXTRA_TURN_BOUND",
    "GRACE_BOUND",
    "GateVerdict",
    "ReviewState",
    "StageRequest",
    "challenge_gate",
    "default_bounds",
    "raised_request_limit",
    "review_record_path",
    "stage_timeout",
    "write_review_record",
]
