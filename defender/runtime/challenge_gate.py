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
completing overrides the confident finding to inconclusive — never a silently-committed
close. It commits the SAME outcome as an override the evidence produced; what separates the
two is the typed `failure_kind`, set only when the machinery is what failed.
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


def _shipped_base_request_limit() -> int:
    """The run's UNRAISED request ceiling, read from its one home. Same deferred import and
    same reason as `_retry_budget`."""
    from . import driver

    return driver.DEFAULT_REQUEST_LIMIT


@dataclass(frozen=True)
class Bounds:
    """RS14. Every bound is INJECTED, never hardcoded at a call site — `EXTRA_TURN_BOUND`/
    `GRACE_BOUND` are the shipped DEFAULTS, not literals restated elsewhere.

    `base_request_limit` is here for the same reason the cap is: the raised ceiling is
    base-plus-cap, and while the base was a module constant with no path through the entry
    point, "read FROM the cap rather than restated as a literal" could not be told apart from
    a hardcoded copy — the shipped base and a copy of it are the same number. It is also what
    lets the ceiling's THIRD reader (the message store's withhold check) be handed the same
    value the run was, rather than mirroring a stale one."""

    extra_turns: int = EXTRA_TURN_BOUND
    grace_rounds: int = GRACE_BOUND
    stage_timeout: float = field(default_factory=stage_timeout)
    base_request_limit: int = field(default_factory=_shipped_base_request_limit)

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
    """RS7. Read FROM the bounds the run was handed — both terms — never restated as a
    literal, and never half-read from a module constant the caller cannot move."""
    return bounds.base_request_limit + bounds.extra_turns


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
    #: Deliberately NOT re-listed here: `_call_stage` produces two of the members and
    #: `_unreadable` a third, so a comment enumerating a subset would go stale the next time
    #: one of them moves — which is the shape that already produced three bugs in this delta.
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
    from defender._io import write_guarded

    path = _trace_path(run_dir, role)
    write_guarded(path, json.dumps({"round": round_no, **row}) + "\n", mode="append")
    if raw_reply is not None:
        write_guarded(path, raw_reply if raw_reply.endswith("\n") else raw_reply + "\n", mode="append")


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


class UnreadableProjection(Exception):
    """The projection replied with something the classifier cannot read."""


def _parse_projection_reply(text: str | None) -> list[tuple[str, str]]:
    """The projection's `(lead_id, tag)` rows, or `UnreadableProjection`.

    FAIL CLOSED (R5). "Failing to complete" is not only the stage CALL breaking: a stage that
    returns something the gate cannot read has not completed either. BOTH shapes are refused
    — a reply that is not JSON at all, and well-formed JSON whose rows lack the fields the
    classifier reads, which is the likelier of the two because a confused model emits valid
    JSON. Swallowing either and reading it as zero rows records an unreadable review as a
    finding about the EVIDENCE.

    The boundary, stated so it cannot drift: the routing is on whether the output could be
    READ, never on how many rows it carried. A valid, readable, ZERO-ROW reply is a real
    finding — no executed lead touches the story — and keeps its own arm."""
    try:
        obj = json.loads(text or "")
    except (json.JSONDecodeError, TypeError) as e:
        raise UnreadableProjection(f"the reply did not parse as JSON: {e}") from e
    if not isinstance(obj, dict):
        raise UnreadableProjection("the reply is not a JSON object")
    leads = obj.get("leads")
    if not isinstance(leads, list):
        raise UnreadableProjection("the reply carries no per-lead list")
    rows: list[tuple[str, str]] = []
    for item in leads:
        if not isinstance(item, dict) or "lead_id" not in item or "tag" not in item:
            raise UnreadableProjection(f"a row lacks lead_id/tag: {item!r}")
        rows.append((str(item["lead_id"]), str(item["tag"])))
    return rows


def _direction_for(disposition: str) -> tuple[Any, str]:
    """The counter-direction the challenger argues, off the EXISTING disposition-to-direction
    map — never a second copy of the mapping written into the gate."""
    directions = directions_for(disposition)
    direction = directions[0] if directions else None
    return direction, (direction.name if direction is not None else "unknown")


def _unexecuted_leads(rows: list[tuple[str, str]], executed: tuple[str, ...]) -> list[str]:
    """The identifiers in the reply that are NOT in the executed-lead list the host sent out.

    Unbounded, an invented identifier — or one belonging to a different run — flows into the
    discriminating set and is handed to the investigator as a lead to go investigate: the
    forced turn's own economy inverted, with the gate charging the investigation for a
    hallucination."""
    known = set(executed)
    return sorted({lead_id for lead_id, _tag in rows if lead_id not in known})


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
    """One gate attempt's classification, in the three fields that replaced the single
    overloaded `reason`.

    `outcome` says what happened to the disposition (three values). `cause` is the HOST'S own
    sentence for the human reading the case — one of `close_tool.REPORT_CAUSES`, chosen here
    and never composed from a stage's reply. `detail` is the diagnostic and is the ONLY one of
    the three that may quote a stage: it names which stage broke and what it said, so it goes
    to the numbered review record and never to report.md."""

    outcome: str
    disposition: str
    cause: str
    detail: str
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


async def _run_coherence_and_projection_once(  # noqa: PLR0913 — one stage pair's full wiring
    deps: Any, stages: Any, bounds: Bounds, counter_story: str, round_no: int,
    executed_lead_ids: tuple[str, ...],
) -> tuple[StageOutcome, StageOutcome]:
    """The concurrent coherence-checker + oracle-projection pair, plus their trace rows."""
    coherence_req = _fresh_stage_request(
        review_roles.build_coherence_checker_input(counter_story), bounds,
    )
    projection_req = _fresh_stage_request(
        review_roles.build_projection_input(deps, counter_story, executed_lead_ids), bounds,
    )
    coherence_task = _call_stage("coherence_checker", stages.coherence_checker, coherence_req)
    projection_task = _call_stage("oracle", stages.projection, projection_req)
    coherence_outcome, projection_outcome = await asyncio.gather(coherence_task, projection_task)

    # BOTH replies are framed, not only the challenger's. The argument that neither of these
    # is payload-derived prose was falsified by execution: forced to carry prose, both landed
    # byte-for-byte raw on disk, and the exposure is to whoever reads the trace later — an
    # operator, a visualizer, a later model.
    #
    # The frame rides INSIDE the row's JSON value rather than on its own physical lines the
    # way the challenger's does, because the oracle's reply is valid JSON in its own right:
    # emitted as a raw line it would stand as its own round-less JSONL row and corrupt the
    # trace's row structure. `json.dumps` escapes the frame's newlines but not its delimiters,
    # so "the marker is inside the frame" stays checkable on the bytes.
    for role, outcome in (
        ("coherence_checker", coherence_outcome), ("oracle", projection_outcome),
    ):
        _write_trace_row(
            deps.run_dir, role, round_no,
            {"ok": outcome.ok,
             "reply": _wrap(outcome.text or outcome.detail or "", "untrusted", deps.salt)},
        )
    return coherence_outcome, projection_outcome


def _first_stage_fault(
    deps: Any, round_no: int, pairs: tuple[tuple[str, StageOutcome], ...],
) -> tuple[str, StageOutcome] | None:
    """The first of the concurrent pair that did not complete, its round marked incomplete —
    or `None` when both returned. RS9's fail-closed rule covers ANY stage, so the two are
    checked by one rule rather than by two hand-written branches that can drift."""
    for role, outcome in pairs:
        if not outcome.ok:
            _mark_traces_incomplete(deps.run_dir, round_no, outcome.detail or "stage fault")
            return role, outcome
    return None


def _terminal_challenger_verdict(
    reply: dict | None, malformed_reason: str | None, disposition: str,
    direction_name: str, round_no: int,
) -> GateVerdict | None:
    """The two challenger replies that end the gate before the other stages run: one that
    would not PARSE, and a deliberate DECLINE.

    They stay apart on two independent typed observables now that the outcome no longer
    spells them: a decline leaves the confident disposition STANDING and names no failure
    kind, an unparseable reply overrides it and names `unreadable`. Merging them would inflate
    the apparent incoherence rate — and note the unparseable reply is `unreadable`, NOT
    `incoherent`: the challenger's reasoning was never read, so nothing about it was judged.

    The decline's `detail` is the challenger's OWN sentence, written after reading
    attacker-influenced alert data. That is exactly why the cause beside it is a host constant
    and the detail goes only to the review record."""
    from .close_tool import (
        CAUSE_NO_STORY,
        CAUSE_REVIEW_INCOMPLETE,
        FORCED_INCONCLUSIVE,
        STANDS,
        UNREADABLE,
    )

    if reply is None:
        return GateVerdict(
            outcome=FORCED_INCONCLUSIVE, disposition="inconclusive",
            cause=CAUSE_REVIEW_INCOMPLETE,
            detail=malformed_reason or "challenger output did not parse",
            material=(), turns_used=0, rounds_used=round_no,
            failure_kind=UNREADABLE, counter_story=None, direction=direction_name,
            requirement_list=[], projection_rows=[],
        )
    if reply.get("declined"):
        return GateVerdict(
            outcome=STANDS, disposition=disposition,
            cause=CAUSE_NO_STORY, detail=str(reply.get("reason", "")),
            material=(), turns_used=0, rounds_used=round_no,
            failure_kind=None, counter_story=None, direction=direction_name,
            requirement_list=[], projection_rows=[],
        )
    return None


def _read_projection(
    deps: Any, outcome: StageOutcome, executed_lead_ids: tuple[str, ...], round_no: int,
) -> tuple[list[tuple[str, str]] | None, str]:
    """`(rows, "")` when the projection can be USED, `(None, reason)` when it cannot.

    Two ways it cannot, and both are review failures rather than findings about the evidence:
    the reply is unreadable, or it names a lead the investigation never executed. The round's
    traces are marked incomplete on either, because the round did not complete."""
    try:
        rows = _parse_projection_reply(outcome.text)
    except UnreadableProjection as e:
        detail = f"the projection returned output the gate cannot read — {e}"
        _mark_traces_incomplete(deps.run_dir, round_no, detail)
        return None, detail
    stray = _unexecuted_leads(rows, executed_lead_ids)
    if stray:
        detail = (
            "the projection named lead(s) the investigation never executed: "
            f"{', '.join(stray)}"
        )
        _mark_traces_incomplete(deps.run_dir, round_no, detail)
        return None, detail
    return rows, ""


def _finalize_verdict(  # noqa: PLR0913 — one classification's full inputs, named once
    state: ReviewState, bounds: Bounds, disposition: str, direction_name: str,
    challenger_reply: dict, rows: list[tuple[str, str]], round_no: int,
) -> GateVerdict:
    """The post-coherent classification: settled/refuted, the discriminator rule
    (evidence-silent / all-confirmed / discriminated), and the two reasons a discriminating
    attempt still spends no turn — the overlap rule and the forced-turn cap.

    `rows` arrive already READ and already bounded to the executed-lead list — an unreadable
    or out-of-list reply never reaches here, because both are review failures rather than
    findings about the evidence.

    Every arm below completed the review, so none of them names a failure kind. That absence
    is the thing that says an override came from the EVIDENCE rather than from the machinery
    breaking, now that both commit the same outcome value."""
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

    requirements = challenger_reply.get("requirements", [])
    unsettled = [r for r in requirements if r.get("settled_by") is None]
    counter_story = challenger_reply["counter_story"]

    def _verdict(  # noqa: PLR0913 — one verdict's own fields, all named at each call site
        outcome: str, verdict_disposition: str, cause: str, detail: str, *,
        material=(), turns_used=0,
    ) -> GateVerdict:
        return GateVerdict(
            outcome=outcome, disposition=verdict_disposition, cause=cause, detail=detail,
            material=material, turns_used=turns_used, rounds_used=round_no,
            failure_kind=None, counter_story=counter_story, direction=direction_name,
            requirement_list=requirements, projection_rows=rows,
        )

    if not unsettled:
        return _verdict(
            STANDS, disposition, CAUSE_STORY_SETTLED,
            "the counter-story's requirements are all already settled by existing evidence",
        )

    bucket, discriminating = _classify_projection(rows)

    # The two shapes of "the evidence cannot discriminate" share ONE cause deliberately: no
    # executed lead speaks to the story, and every executed lead speaks to it, are opposite
    # facts with the same consequence for the case, and the retired vocabulary spent two
    # members separating them for nobody. The `detail` still says which.
    if bucket == "evidence_silent":
        return _verdict(
            FORCED_INCONCLUSIVE, "inconclusive", CAUSE_EVIDENCE_CANNOT_DISCRIMINATE,
            "no executed lead's evidence can speak to the counter-story",
        )
    if bucket == "all_confirmed":
        return _verdict(
            FORCED_INCONCLUSIVE, "inconclusive", CAUSE_EVIDENCE_CANNOT_DISCRIMINATE,
            "every executed lead's evidence speaks to the counter-story; none is silent",
        )

    # Discriminated. A forced turn is spent only when it can BUY something, so the number of
    # turns a run costs is VARIABLE and the bound is a ceiling rather than a schedule. Two
    # independent reasons not to spend one, and they are different claims: the bound is about
    # how many turns a run may cost in total, the overlap rule is about whether THIS turn can
    # surface anything at all.
    fresh = sorted(lid for lid in discriminating if lid not in state.raised_leads)
    if not fresh:
        # EVERY discriminating lead was already handed back. The investigator has already been
        # asked for all of it, so this turn provably cannot surface new information: it is not
        # spent, and the gate closes on what it has. Deliberately NOT "the reply repeated" and
        # NOT "some lead repeated" — the rule is about which leads were RAISED, and a reply
        # carrying one already-raised lead alongside a genuinely new one is a turn worth
        # spending.
        #
        # This is where an ELEVENTH vocabulary member was once proposed, because the old arm
        # made a run that stopped early report its turn bound as exhausted. The cause carries
        # the claim instead, and it is a DIFFERENT sentence from the bound's: a run with turns
        # left that had nothing to ask, and a run that spent every turn it had, must not read
        # the same to whoever opens the case.
        return _verdict(
            FORCED_INCONCLUSIVE, "inconclusive", CAUSE_NOTHING_LEFT_TO_ASK,
            "every discriminating lead was already raised; a further forced turn cannot "
            "surface anything the investigator was not already asked for",
            turns_used=state.turns,
        )
    if state.turns >= bounds.extra_turns:
        return _verdict(
            FORCED_INCONCLUSIVE, "inconclusive", CAUSE_TURN_BUDGET_SPENT,
            "the forced-turn bound is exhausted", turns_used=state.turns,
        )

    top = fresh[0]
    state.raised_leads.add(top)
    material: tuple[tuple[str, str], ...] = (
        (top, (unsettled[0].get("assertion") or "")[:REQUIREMENT_MAX]),
    )
    state.turns += 1
    # NO_CAUSE, because this attempt commits nothing: there is no report.md for a cause to
    # land in. The investigation continues and the next attempt writes its own.
    return _verdict(
        CHALLENGED, disposition, NO_CAUSE,
        "the counter-story survived and left a discriminating lead untested",
        material=material, turns_used=state.turns,
    )


async def challenge_gate(deps: Any, disposition: str, *, stages: Any, bounds: Bounds) -> GateVerdict:
    from .close_tool import CAUSE_REVIEW_INCOMPLETE, FORCED_INCONCLUSIVE, INCOHERENT, UNREADABLE

    state = ReviewState.of(deps)
    direction, direction_name = _direction_for(disposition)

    def _fail(role: str, outcome: StageOutcome, round_no: int) -> GateVerdict:
        """Every way the review can fail to deliver: one outcome, one cause, and the typed
        kind carrying which. The kind comes from the stage outcome rather than from this
        function, so a timeout and a raise stay apart without a branch here to keep in step
        with the one in `_call_stage`.

        THE ROUND IS A PARAMETER AND NOT A ZERO. It used to be hardcoded here, which made this
        one function lie on every arm it serves: three of the gate's terminal sites return
        through it, and a run that had already spent a refinement before the fault persisted a
        record saying it had spent none. The counter itself was never wrong — it is right at
        its initialization, at its single increment and at both readers — so a read of those
        four places confirmed it, and the every-arm record census reads the field's presence
        rather than its arithmetic. Only a run that refines and THEN faults can see it, which
        is why it survived the whole delta green."""
        return GateVerdict(
            outcome=FORCED_INCONCLUSIVE, disposition="inconclusive",
            cause=CAUSE_REVIEW_INCOMPLETE, detail=f"{role}: {outcome.detail}",
            material=(), turns_used=0, rounds_used=round_no,
            failure_kind=outcome.failure_kind,
            counter_story=None, direction=direction_name,
            requirement_list=[], projection_rows=[],
        )

    def _unreadable(detail: str, round_no: int) -> GateVerdict:
        return _fail(
            "oracle", StageOutcome(text=None, failure_kind=UNREADABLE, detail=detail), round_no,
        )

    base_prompt = review_roles.build_challenger_input(deps, disposition, direction)
    challenger_prompt = base_prompt
    executed_lead_ids = _executed_lead_ids(deps.run_dir)
    round_no = 0

    while True:
        reply, fail_outcome, malformed_reason = await _run_challenger_once(
            deps, stages, bounds, challenger_prompt, round_no,
        )
        if fail_outcome is not None:
            _mark_traces_incomplete(deps.run_dir, round_no, fail_outcome.detail or "stage fault")
            return _fail("challenger", fail_outcome, round_no)
        ended = _terminal_challenger_verdict(
            reply, malformed_reason, disposition, direction_name, round_no,
        )
        if ended is not None:
            return ended
        assert reply is not None  # `_terminal_challenger_verdict` returned on the None arm

        coherence_outcome, projection_outcome = await _run_coherence_and_projection_once(
            deps, stages, bounds, reply["counter_story"], round_no, executed_lead_ids,
        )
        fault = _first_stage_fault(deps, round_no, (
            ("coherence_checker", coherence_outcome), ("oracle", projection_outcome),
        ))
        if fault is not None:
            faulting_role, fault_outcome = fault
            return _fail(faulting_role, fault_outcome, round_no)

        # R5: a stage that ANSWERED unusably has not completed either, and the fix is made at
        # the point both readable-empty and unreadable share, so genuine silence keeps its arm.
        rows, unusable = _read_projection(
            deps, projection_outcome, executed_lead_ids, round_no,
        )
        if rows is None:
            return _unreadable(unusable, round_no)

        coherent = "INCOHERENT" not in (coherence_outcome.text or "").upper()
        if coherent:
            return _finalize_verdict(
                state, bounds, disposition, direction_name, reply, rows, round_no,
            )
        if round_no >= bounds.grace_rounds:
            # The challenger answered INSIDE its output contract every round and the content
            # still could not be used. That is the challenger-quality signal and it is a
            # different kind from `unreadable` — a reply the gate never parsed says nothing
            # about the reasoning, and counting the two together is the inflated incoherence
            # rate this whole field exists to prevent.
            return GateVerdict(
                outcome=FORCED_INCONCLUSIVE, disposition="inconclusive",
                cause=CAUSE_REVIEW_INCOMPLETE,
                detail="the counter-story did not settle into internal consistency",
                material=(), turns_used=0, rounds_used=round_no,
                failure_kind=INCOHERENT, counter_story=None, direction=direction_name,
                requirement_list=reply.get("requirements", []), projection_rows=[],
            )
        round_no += 1
        # Refine: a SECOND ASK, carrying the story that failed and the gap the coherence
        # checker named — never the identical prompt again.
        challenger_prompt = review_roles.build_refinement_input(
            base_prompt, str(reply["counter_story"]), coherence_outcome.text or "",
        )


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
