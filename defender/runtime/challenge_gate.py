"""The live write-time review gate's HARNESS: bounds, per-run review state, the numbered
review record, stage invocation with a real wall-clock deadline, and the trace rows.

`challenge_gate(deps, disposition, *, stages, bounds) -> GateVerdict` is the seam the close
tool drives for a CONFIDENT disposition. It never writes report.md or the review record
itself — the close tool (`close_tool.py`) owns both writes, in the record-first order RS19
pins, and is the one place a fault is held until both are attempted.

THE GATE HAS NO REVIEWER RIGHT NOW. #797 retired the three stages this harness was built to
drive — the challenger, the coherence checker and the projection stage — and #796 lands the
blind lenses and the composer that replace them. Between the two, `REVIEW_ROLES` is empty and
every confident close takes the fail-closed arm below. That is the deliberate posture, not an
outage to route around: a gate that cannot review must not let a confident finding through.

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
from dataclasses import dataclass, field
from typing import Any

from defender._env import env_int

EXTRA_TURN_BOUND = 2

REVIEW_TIMEOUT_ENV = "DEFENDER_REVIEW_STAGE_TIMEOUT_SECONDS"

#: The review roles this gate dispatches, in the order it reports faults for. EMPTY between
#: #797 and #796 — the three retired stages were its only members, and #796's lenses and
#: composer are its next ones. It is the ONE home for that list: the trace-marking walk reads
#: it rather than restating the names, so a role added to the gate cannot arrive with a trace
#: file the incomplete-marker never touches (the shipped shape restated all three inline, and
#: a stage renamed in one place stayed spelled the old way in the other).
REVIEW_ROLES: tuple[str, ...] = ()

#: The fail-closed detail every confident close carries until #796 binds a reviewer. Named,
#: not inlined, so the gate's own arm and the note in `docs/review-gate-retirement.md` cannot
#: drift apart, and so a run dir's review record says WHY rather than reporting an anonymous
#: stage error.
NO_REVIEWER = (
    "no review role is bound — #797 retired the challenger, the coherence checker and the "
    "projection stage, and #796's lenses and composer are not landed yet; a confident close "
    "cannot be reviewed and therefore cannot stand"
)


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
    return Bounds(extra_turns=EXTRA_TURN_BOUND, stage_timeout=stage_timeout())


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


def _fresh_stage_request(prompt: str, bounds: Bounds) -> StageRequest:
    # PR7/PR8: every stage call carries its OWN fresh salt (never the investigation's
    # session salt) — the review roles never hold the delimiter of the frame their own
    # output returns inside.
    return StageRequest(prompt=prompt, salt=uuid.uuid4().hex, timeout=bounds.stage_timeout)


def _trace_path(run_dir, role: str):
    from pathlib import Path

    return Path(run_dir) / f"review_{role}_trace.jsonl"


def _write_trace_row(
    run_dir, role: str, round_no: int, row: dict, *, raw_reply: str | None = None,
) -> None:
    """Append one trace row, JSON-metadata-only, PLUS (optionally) the stage's raw wrapped
    reply as its own literal text line right after — never as a JSON string VALUE.

    A `wrap(...)`-framed reply carries real newline characters; folding it into a JSON
    string field would have `json.dumps` escape them to `\\n`, so the exact framed substring
    a containment test looks for would never appear literally in the file, even though the
    payload-derived text inside it would (JSON only escapes the control characters, not the
    words). Keeping the frame as a separate raw line is what makes "wrapped, never bare" a
    checkable property of the bytes on disk. `read_jsonl_rows` (every other trace consumer)
    tolerates it fine — a raw line that is not valid JSON is simply skipped, so the metadata
    rows stay exactly as parseable as before."""
    from defender._io import write_guarded

    line = json.dumps({"round": round_no, **row}) + "\n"
    if raw_reply is not None:
        line += raw_reply if raw_reply.endswith("\n") else raw_reply + "\n"
    # ONE guarded append per row, not one per physical line: the two lines are a single trace
    # record, and splitting them across two `write_guarded` calls both doubled the syscalls and
    # left a window in which the metadata row was on disk without the reply it describes.
    write_guarded(_trace_path(run_dir, role), line, mode="append")


def _mark_traces_incomplete(run_dir, round_no: int, reason: str) -> None:
    """Every review role's trace gets the marker, so a round that ended early is not left
    reading as if it had completed. The roster comes from `REVIEW_ROLES` rather than being
    restated here — with no roles bound this writes nothing, which is the honest record of a
    gate that dispatched nothing."""
    for role in REVIEW_ROLES:
        _write_trace_row(run_dir, role, round_no, {"incomplete": True, "reason": reason})


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


def _fail(role: str, outcome: StageOutcome) -> GateVerdict:
    """Every way the review can fail to deliver: one outcome, one cause, and the typed kind
    carrying which. The kind comes from the stage outcome rather than from this function, so a
    timeout and a raise stay apart without a branch here to keep in step with the one in
    `_call_stage`."""
    from .close_tool import CAUSE_REVIEW_INCOMPLETE, FORCED_INCONCLUSIVE

    return GateVerdict(
        outcome=FORCED_INCONCLUSIVE, disposition="inconclusive",
        cause=CAUSE_REVIEW_INCOMPLETE, detail=f"{role}: {outcome.detail}",
        material=(), turns_used=0, failure_kind=outcome.failure_kind,
    )


async def challenge_gate(deps: Any, disposition: str, *, stages: Any, bounds: Bounds) -> GateVerdict:
    """Review one CONFIDENT disposition. The signature is the seam #796 fills: `stages` is the
    injected `ReviewStages` bundle and `bounds` carries the deadline every stage call runs
    under.

    Both are accepted and unread while `REVIEW_ROLES` is empty. Narrowing the signature to
    what this body reads would make #796 a change to every caller — the close tool, the
    driver's two composition roots and the e2e harness's sixth injection seam — rather than a
    change to this module, which is the seam the injection exists to provide."""
    from .close_tool import STAGE_ERROR

    _mark_traces_incomplete(deps.run_dir, 0, NO_REVIEWER)
    return _fail(
        "reviewer",
        StageOutcome(text=None, failure_kind=STAGE_ERROR, detail=NO_REVIEWER),
    )


__all__ = [
    "Bounds",
    "EXTRA_TURN_BOUND",
    "GateVerdict",
    "NO_REVIEWER",
    "REVIEW_ROLES",
    "ReviewState",
    "StageRequest",
    "challenge_gate",
    "default_bounds",
    "raised_request_limit",
    "review_record_path",
    "stage_timeout",
    "write_review_record",
]
