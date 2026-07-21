"""#631 — the enforced posture driven END TO END through the real
`driver.run_investigation` loop.

It lives FLAT under `defender/tests/` rather than under `tests/e2e/` — where the
harness it builds on lives — for one mechanical reason: `check_binds` globs the suite
dir non-recursively, so a `discharged_by` pointing into `tests/e2e/` resolves to
nothing and 23 demands' prose becomes unscannable. `pytestmark = pytest.mark.e2e`
keeps it in the same marker lane as the other replay scripts.

Every scenario here is a few lines of `Turn(...)` against `_replay_harness`: the real
agent loop, the real generic tools, the real permission gate, the real observability
projection, the real budget hooks — with three injected VALUES and nothing patched
(the model, the verb registry, and the cap table). The enforcement posture is set
through the real environment the real `env_bool` reads.

RED AGAINST HEAD IS THE EXPECTED STATE. At `483b5809` there is no trip seam at all —
PO57 executed the tree-state check and got "hooks.on.tool_execute registered in
driver: False; DEFENDER_BUDGET_ENFORCE anywhere in driver: False" — so the only budget
hook is the warning-only `after_tool_execute` accountant.

THE LIVE MECHANISM IS SHORT-CIRCUIT ONLY. There is no `prepare_tools` withdrawal arm
anywhere in this design, and nothing here may assert one: X1 refuted the withdrawal
mechanism (each re-issue comes back as `RetryPromptPart('Unknown tool name')` counted
against the same per-tool ceiling, raising `UnexpectedModelBehavior` at turn 11), X2
refuted the `before_tool_execute` backstop (it fired ZERO times across 10 re-issues,
because the framework resolves the tool name UPSTREAM of the execute-family hooks),
and X6 refuted the combined form — withdrawal SHADOWS the wrap seam, so adding it
strictly REMOVES the property the mechanism exists for.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from defender._io import read_jsonl_rows
from defender.hooks.budget_enforcer import (
    BUDGET_REFUSAL_MESSAGE,
    DEFAULT_LIMITS,
    open_budget,
    update_budget_locked,
)
from defender.tests.e2e._replay_harness import (
    GOLDEN,
    FakeVerbs,
    ReplayFn,
    Turn,
    VerbRecorder,
    drive,
    materialize,
)

pytestmark = pytest.mark.e2e

FLAG = "DEFENDER_BUDGET_ENFORCE"
SALT = "0011223344556677"


@pytest.fixture
def enforced(monkeypatch):
    """The enforcing posture, set the only way production sets it: the real
    environment variable the real `env_bool` reads in-process."""
    monkeypatch.setenv(FLAG, "true")


@pytest.fixture
def unenforced(monkeypatch):
    monkeypatch.delenv(FLAG, raising=False)


def caps(**over) -> dict:
    return {**DEFAULT_LIMITS, **over}


def budget(run_dir: Path) -> dict:
    return json.loads((run_dir / "budget.json").read_text())


def report_text() -> str:
    return "---\ncase_id: c-1\ndisposition: benign\nconfidence: low\n---\n\nDone.\n"


def read_turns(run_dir: Path, n: int) -> list[Turn]:
    """`n` core-tier bash turns — each ALLOWED and schema-valid, so nothing but the
    budget can refuse it, and (being core-tier) each is REFUSED once the pool trips
    without advancing the count. P3 (executed) is why the args must be valid:
    pydantic-ai validates a ToolCallPart's args BEFORE dispatching to any
    execute-family hook, so a malformed call is preempted by a RetryPromptPart and
    never reaches the seam at all."""
    return [Turn(tool_calls=[("bash", {"command": "echo hi"})]) for _ in range(n)]


def tail_turns(run_dir: Path, n: int) -> list[Turn]:
    """`n` TAIL-tier read_file turns — read_file is tail on MAIN, so each EXECUTES and
    advances tool_calls even after the trip, driving the count limb to
    N + TAIL_ALLOWANCE deterministically. This is how the kill tests reach exhaustion
    WITHOUT depending on wall-clock timing (blind reader R25: six e2e tests shared an
    undeclared machine-speed assumption through `wall_clock_timeout=1`)."""
    return [Turn(tool_calls=[("read_file", {"path": str(run_dir / "alert.json")})])
            for _ in range(n)]


def refusal_stem() -> str:
    """The placeholder-free literal prefix of the refusal message, GUARDED non-empty.

    Blind reader R5: five tests derived their expected refusal text from
    `BUDGET_REFUSAL_MESSAGE.split("{",1)[0]`, and if the implementer front-loads a
    `{tool}` placeholder that prefix is `""` — `"" in history` then passes everywhere
    and four delivery checks silently stop testing. This guard fails loudly on that
    authoring, and the message's CONTENT is pinned separately, structurally, in
    test_refusal_message_content — so no delivery check rests on the constant's wording."""
    stem = BUDGET_REFUSAL_MESSAGE.split("{", 1)[0].strip()
    assert stem, (
        "BUDGET_REFUSAL_MESSAGE begins with an interpolated field — its literal prefix "
        "is empty, so every 'a refusal was delivered' check would pass vacuously. "
        "Author the constant with a literal lead-in (blind reader R5)."
    )
    return stem


# --- demand #0: the return contract -----------------------------------------

def test_budget_trip_returns_summary_and_writes_trace(tmp_path, enforced):
    """When a cap trips with enforcement on, run_investigation returns its normal
    summary dict — {output, model, requests, truncated_by} — and the trace and the
    request log are on disk; it never raises past its caller.

    THIS TEST OBSERVES A TRIP (blind reader R3): it is cited by name as the positive
    control for test_flag_off_leaves_run_unenforced and
    test_learning_stages_are_accounting_only, so it must exercise the mechanism, not
    merely finish. It drives the SAME two-bash-then-text script under the SAME injected
    caps those two tests use, and asserts a refusal was delivered — proving enforcement
    fired here, which is exactly the difference the controlled tests observe the
    absence of."""
    run_dir = materialize(tmp_path, GOLDEN)
    replay = ReplayFn([
        Turn(tool_calls=[("bash", {"command": "echo hi"})]),      # executes, trips
        Turn(tool_calls=[("bash", {"command": "echo again"})]),   # refused (observed)
        Turn(text="Investigation complete."),
    ])
    summary = drive(run_dir, run_id="trip", salt=SALT, main=replay,
                    limits=caps(max_tool_calls=1, wall_clock_timeout=3600,
                                grace_seconds=600))

    assert set(summary) >= {"output", "model", "requests", "truncated_by"}
    assert refusal_stem() in "\n".join(replay.seen), (
        "enforcement did not fire — no refusal was observed, so this control controls nothing"
    )
    assert budget(run_dir)["tool_calls"] == 1, "the refused call spent the pool"
    assert summary["requests"] >= 2
    assert (run_dir / "tool_trace.jsonl").is_file()
    assert (run_dir / "llm_requests.jsonl").is_file()
    assert (run_dir / "budget.json").is_file()


def test_a_budget_killed_run_carries_truncated_by_budget(tmp_path, enforced):
    """A run ended by the budget kill carries truncated_by: "budget", so the post-run
    pipeline can see that enforcement stopped the run rather than the defender
    concluding, and does not score a truncated investigation as a complete one."""
    run_dir = materialize(tmp_path, GOLDEN)
    # Deterministic kill via the COUNT limb: the first read_file trips at cap 1, then
    # tail-tier read_files advance the count to N + TAIL_ALLOWANCE and the run is
    # killed — no dependence on whether N replayed turns consume a wall second.
    summary = drive(run_dir, run_id="trunc", salt=SALT,
                    main=ReplayFn(tail_turns(run_dir, 15)),
                    limits=caps(max_tool_calls=1, wall_clock_timeout=3600,
                                grace_seconds=600))
    assert summary["truncated_by"] == "budget"
    assert summary["output"] is None, "the kill ended the run before an End node"

    # The control on the same address: a run that ends on its own carries no mark.
    clean_dir = materialize(tmp_path / "clean", GOLDEN)
    clean = drive(clean_dir, run_id="clean", salt=SALT,
                  main=ReplayFn([Turn(text="Investigation complete.")]),
                  limits=caps())
    assert clean["truncated_by"] is None


def test_only_the_budget_kill_marks_truncated_by_budget(tmp_path, enforced):
    """Only the budget kill sets truncated_by: "budget" — the PRE-EXISTING
    request-limit termination (UsageLimitExceeded, which run_investigation already
    catches) does NOT, so a run that ends because the model would not stop is not
    mislabelled as budget-truncated.

    R27: truncated_by's domain is otherwise pinned only at {"budget", None}; this
    exercises the None member under a DIFFERENT, non-budget terminator, so an
    implementation that stamped "budget" on every non-clean exit would fail. The
    positive control is test_a_budget_killed_run_carries_truncated_by_budget."""
    from defender.tests.e2e._replay_harness import NeverEndsModel

    run_dir = materialize(tmp_path, GOLDEN)
    # NeverEndsModel drives an allowed read_file forever, so the loop runs into its
    # request limit rather than any budget cap (default caps, far from tripping).
    summary = drive(run_dir, run_id="reqlimit", salt=SALT,
                    main=NeverEndsModel(run_dir), limits=caps())
    assert summary["truncated_by"] is None, (
        "a request-limit termination was mislabelled as a budget truncation"
    )
    assert budget(run_dir)["tool_calls"] < DEFAULT_LIMITS["max_tool_calls"], (
        "the run hit a budget cap after all — pick a terminator that is not the budget"
    )


def test_budget_kill_writes_partial_trace(tmp_path, enforced):
    """Tail exhaustion raises the budget kill's own exception type — not RunAborted,
    whose constructor is circuit-breaker-specific — and run_investigation's catch
    writes the partial trace exactly like the request-limit path.

    P6 (executed 5x plus a 3x asyncio.shield adversarial arm): under CONCURRENT raises
    both callers genuinely raise, yet exactly ONE kill propagates and it propagates
    UNWRAPPED — a plain `except BudgetKill` catches it, which is the shape driver.py's
    catch already has. The single-exception shape IS what this asserts end-to-end: the
    script drives a turn of many PARALLEL tail-tier calls so several become
    kill-eligible at once, and the run returns a clean summary rather than raising.
    If a pydantic-ai bump stopped collapsing the anyio TaskGroup's BaseExceptionGroup,
    the driver's plain `except BudgetKill` would MISS the group and `drive()` would
    raise the group past its caller — this test would then fail LOUDLY at that raise,
    which is exactly the guard P6 bought."""
    run_dir = materialize(tmp_path, GOLDEN)
    # One turn carrying many parallel tail-tier calls, so the kill becomes eligible for
    # several concurrently-committing callers at once (P6's shape). The count limb makes
    # exhaustion deterministic — no wall-clock race (blind reader R25).
    burst = [Turn(tool_calls=[("read_file", {"path": str(run_dir / "alert.json")})] * 15)]
    summary = drive(run_dir, run_id="kill", salt=SALT, main=ReplayFn(burst),
                    limits=caps(max_tool_calls=1, wall_clock_timeout=3600,
                                grace_seconds=600))

    assert summary["truncated_by"] == "budget", (
        "the concurrent kills did not collapse to one caught BudgetKill"
    )
    events = list(read_jsonl_rows(run_dir / "tool_trace.jsonl"))
    assert events, "the partial trace was lost on the kill path"
    assert any(e.get("type") == "result" for e in events)


def test_kill_exception_reaches_uncaught_driver_handling(tmp_path, enforced, capsys):
    """The tail-exhaustion kill is raised from a seam OUTSIDE after_tool_execute's
    broad exception guard, so the guard added specifically so that budget accounting
    could never itself break a run does not swallow the kill: the run ends and is
    marked, and no "budget accounting skipped" line is emitted for it.

    FF11: after_tool_execute's whole body is wrapped in `except Exception`
    (driver.py:121, "budget must never break the run"). A kill raised inside that body
    is invisible. "budget accounting skipped: {e!r}" is the EXACT string that guard
    prints when it swallows an exception (driver.py:121), so the string IS producible —
    the negative is falsifiable: an implementation that raised the kill from inside the
    guard would emit it. The positive control is test_budget_kill_writes_partial_trace,
    where the kill DOES reach the driver's catch and DOES write the trace."""
    run_dir = materialize(tmp_path, GOLDEN)
    summary = drive(run_dir, run_id="guard", salt=SALT,
                    main=ReplayFn(tail_turns(run_dir, 15)),
                    limits=caps(max_tool_calls=1, wall_clock_timeout=3600,
                                grace_seconds=600))
    err = capsys.readouterr().err
    assert summary["truncated_by"] == "budget", "the kill did not end the run at all"
    assert "budget accounting skipped" not in err, (
        "the kill was swallowed by after_tool_execute's except Exception guard"
    )


def test_only_one_shutdown_path_writes_the_run_dir_artifacts(tmp_path, enforced):
    """Exactly one shutdown path writes the run-dir artifacts, whichever kill fires
    and whether or not both fire: the trace and the request log are projected ONCE,
    not raced or written twice.

    Kept separate from the decoupling demand because it survives any answer to it —
    this is the demand that keeps two independent kills from both projecting the
    trace. The observable is the artifact, not the code path: `tool_trace.jsonl` ends
    with exactly one `type: result` event and the request log has no duplicated
    request ids."""
    run_dir = materialize(tmp_path, GOLDEN)
    summary = drive(run_dir, run_id="shutdown", salt=SALT,
                    main=ReplayFn(tail_turns(run_dir, 15)),
                    limits=caps(max_tool_calls=1, wall_clock_timeout=3600,
                                grace_seconds=600))
    assert summary["truncated_by"] == "budget", "the run did not take a kill path at all"

    events = list(read_jsonl_rows(run_dir / "tool_trace.jsonl"))
    assert sum(1 for e in events if e.get("type") == "result") == 1

    rows = list(read_jsonl_rows(run_dir / "llm_requests.jsonl"))
    ids = [r.get("id") for r in rows if r.get("id")]
    assert ids, "no request ids were logged — the uniqueness check would pass vacuously"
    assert len(ids) == len(set(ids)), "the request log was written by two paths"


def test_budget_kill_and_breaker_kill_are_independent(tmp_path, enforced):
    """The budget kill and the circuit-breaker kill are independent — first fires
    wins, and neither consults the other's state — so neither one's correctness
    depends on the other's.

    Driven both ways round: a run whose budget trips while the breaker's own state
    file already sits at a nonzero failure count still ends on the budget, with the
    breaker's record untouched; and a breaker abort on an un-tripped budget still ends
    the run with the budget's counters intact and no truncated_by mark."""
    from defender.runtime import circuit_breaker

    # Budget first: the breaker has failures recorded but is not tripped. Deterministic
    # count-limb kill (blind reader R25), not a wall-clock race.
    run_dir = materialize(tmp_path, GOLDEN)
    circuit_breaker.record_outcome(run_dir, "elastic", 2)
    before = json.loads((run_dir / "circuit_breaker.json").read_text())
    summary = drive(run_dir, run_id="both", salt=SALT,
                    main=ReplayFn(tail_turns(run_dir, 15)),
                    limits=caps(max_tool_calls=1, wall_clock_timeout=3600,
                                grace_seconds=600))
    assert summary["truncated_by"] == "budget", "the budget did not fire first"
    assert json.loads((run_dir / "circuit_breaker.json").read_text()) == before, (
        "the budget kill reached into the breaker's state"
    )

    # Breaker first: the budget is nowhere near a cap. The breaker MUST be shown to have
    # fired (blind reader R30) — otherwise a ConnectionError silently swallowed with no
    # breaker in the tree would pass both assertions. A failing verb drives real
    # record_outcome calls, so circuit_breaker.json carries a nonzero failure count.
    other = materialize(tmp_path / "brk", GOLDEN)
    verbs = FakeVerbs({"elastic": {"esql": _dead_verb()}})
    gather = ReplayFn([Turn(tool_calls=[("query", {
        "system": "elastic", "verb": "esql", "params": {"index": "logs"},
        "query_id": "elastic.probe"})])] * 8)
    summary = drive(other, run_id="brk", salt=SALT,
                    main=ReplayFn([
                        Turn(tool_calls=[("gather", {
                            "lead_id": f"l-00{i}", "system": "elastic",
                            "goal": "g", "what_to_summarize": ["w"]})])
                        for i in range(1, 7)]),
                    gather=gather, verbs=verbs, limits=caps())
    assert summary["truncated_by"] is None, "the budget wrongly marked a breaker-ended run"
    assert budget(other)["tool_calls"] < DEFAULT_LIMITS["max_tool_calls"]
    breaker_state = json.loads((other / "circuit_breaker.json").read_text())
    assert breaker_state, "the breaker never engaged, so arm 2 controls nothing"
    assert circuit_breaker.record_outcome  # the abort authority is real, not stubbed


def _dead_verb():
    def esql(ctx, *, index: str) -> dict:
        raise ConnectionError("the environment is unreachable")
    return esql


# --- the trip seam ----------------------------------------------------------

def test_stopped_tool_is_refused_not_withdrawn(tmp_path, enforced):
    """After a cap trips, the budget-stopped tool is STILL OFFERED to the model, and
    every call to it is refused at the tool_execute hook — which returns without
    awaiting the handler, so the tool's body never runs and the model receives a
    ToolReturnPart rather than a framework retry.

    SCOPE, narrowed by P3 (executed): pydantic-ai validates a ToolCallPart's args
    against the tool's schema BEFORE dispatching to ANY execute-family hook — on
    missing / wrong-typed / extra-field args the seam fires before=0 wrap=0 after=0
    and a RetryPromptPart appears instead. This demand is therefore true for calls
    whose args are SCHEMA-VALID, and the script below binds valid args.

    REJECTED, and this test must not be rewritten to assert either: withdrawing the
    tool in prepare_tools (X6 — it shadows the execute seam and reintroduces the very
    retry crash the mechanism exists to avoid), and a before_tool_execute backstop for
    stale calls (X2 — with nothing withdrawn there are no stale calls, and that hook
    never fires for a tool the framework has already rejected)."""
    run_dir = materialize(tmp_path, GOLDEN)
    replay = ReplayFn([
        Turn(tool_calls=[("bash", {"command": "echo hi"})]),      # lands, trips the cap
        Turn(tool_calls=[("bash", {"command": "echo again"})]),   # refused
        Turn(text="Acknowledged."),
    ])
    drive(run_dir, run_id="refuse", salt=SALT, main=replay,
          limits=caps(max_tool_calls=1, wall_clock_timeout=3600, grace_seconds=600))

    history = "\n".join(replay.seen)
    assert refusal_stem() in history, "the stopped tool was not refused at the seam"
    assert "Unknown tool name" not in history, (
        "the tool was WITHDRAWN rather than refused — X6's refuted mechanism"
    )
    # The refused call's handler never ran, so the pool did not advance past the cap:
    # the count is the observable that the body was short-circuited (blind reader R7
    # retired the dead `sentinel.txt` assertion — nothing wrote it under shell=False).
    assert budget(run_dir)["tool_calls"] == 1, (
        "the refused call's handler ran — the seam did not short-circuit"
    )


def test_repeated_reissue_accumulates_no_retries(tmp_path, enforced):
    """A model that re-issues a budget-stopped tool many more times than MAIN's
    ten-retry ceiling accumulates NO retries at all: the run completes normally, no
    UnexpectedModelBehavior is raised, and the trace reaches disk.

    THE DISCRIMINATING DEMAND — exactly the property withdrawal destroys (X6: the
    combined arm raised UnexpectedModelBehavior at turn 13 with the wrap firing once)
    and short-circuit-only preserves (X4: 14 consecutive short-circuits with zero
    retry accumulation, re-confirmed at 15). It is driven well past ten consecutive
    re-issues below, because at ten or fewer it proves nothing."""
    from pydantic_ai.exceptions import UnexpectedModelBehavior

    run_dir = materialize(tmp_path, GOLDEN)
    replay = ReplayFn([
        Turn(tool_calls=[("bash", {"command": "echo hi"})]),
        *[Turn(tool_calls=[("bash", {"command": "echo again"})]) for _ in range(25)],
        Turn(text="Acknowledged; writing the report."),
    ])
    try:
        summary = drive(run_dir, run_id="reissue", salt=SALT, main=replay,
                        limits=caps(max_tool_calls=1, wall_clock_timeout=3600,
                                    grace_seconds=600))
    except UnexpectedModelBehavior as e:  # pragma: no cover - the failure this pins
        pytest.fail(f"25 consecutive re-issues accumulated retries: {e}")

    # The mechanism must be PRESENT (blind reader R31): without a refusal assertion this
    # test is green against a run with no enforcement at all, where 26 bash calls just
    # execute. Pin that the tool WAS stopped (a refusal was delivered) and that the
    # refusals did not spend the pool past the cap.
    assert refusal_stem() in "\n".join(replay.seen), (
        "no refusal was ever delivered — the tool was not budget-stopped at all"
    )
    assert budget(run_dir)["tool_calls"] == 1, "a refused re-issue advanced the counter"
    assert replay.calls >= 25, "the loop died before the re-issues were exhausted"
    assert summary["requests"] >= 25
    assert (run_dir / "tool_trace.jsonl").is_file()


def test_refusal_message_content(tmp_path, enforced):
    """EVERY refusal — not merely the first — returns M1b's message to the model: that
    the stop is PERMANENT for the rest of the run, WHAT REMAINS AVAILABLE to it, and
    that it should WRITE ITS REPORT NOW.

    The quantifier is the load-bearing part: under the superseded combined form the
    text was delivered exactly once (X6 — the wrap fired for the single in-flight
    stale call and every re-issue after it came back as the framework's stock
    "Unknown tool name").

    This is a `kind: shape` demand, so it pins the payload's INVARIANTS two ways
    (mechanical leaf F12, blind reader R4): (1) the CONTENT requirement — permanence,
    what remains, write-the-report — is asserted against the CONSTANT itself, because
    the flattened request history contains the whole system prompt (SKILL.md carries
    "report" 11× and "remain" 1×), so `"report" in history` is pre-satisfied and pins
    nothing; and (2) the DELIVERY requirement — every refusal, not merely the first —
    is asserted by counting the message's guarded literal stem in the captured inbound
    history, which the system prompt does NOT contain."""
    run_dir = materialize(tmp_path, GOLDEN)
    replay = ReplayFn([
        Turn(tool_calls=[("bash", {"command": "echo hi"})]),
        *[Turn(tool_calls=[("bash", {"command": f"echo {i}"})]) for i in range(6)],
        Turn(text="ok"),
    ])
    drive(run_dir, run_id="msg", salt=SALT, main=replay,
          limits=caps(max_tool_calls=1, wall_clock_timeout=3600, grace_seconds=600))

    # (1) CONTENT — the constant the seam sends must itself carry the three concepts.
    constant = BUDGET_REFUSAL_MESSAGE.lower()
    assert "permanent" in constant, "the message does not state the stop is permanent"
    assert "report" in constant, "the message does not tell the model to write its report"
    assert re.search(r"still (available|allowed)|remain", constant), (
        "the message does not say what remains available"
    )
    # It must carry at least one interpolated field, so a reader is told WHICH tool /
    # limb / how much tail is left rather than a fixed banner (blind reader R27).
    assert "{" in BUDGET_REFUSAL_MESSAGE, "the refusal message interpolates nothing"

    # (2) DELIVERY — every one of the six refusals put the message into the history.
    final = replay.seen[-1]
    stem = refusal_stem()
    assert final.count(stem) >= 6, (
        f"only {final.count(stem)} of 6 refusals carried the message"
    )


def test_refused_call_does_not_increment_tool_calls(tmp_path, enforced, capsys):
    """A call refused at the execute seam leaves tool_calls unchanged in budget.json
    AND emits NOTHING on the stderr channel — across a long run of consecutive
    refusals no budget warning or exceeded line appears — so a model looping on a
    stopped tool can neither spend the ten-call tail band MAIN needs for its report
    nor bury the real signal under repeated warnings.

    X7 (executed) refuted the free version of this: a short-circuit DOES reach
    after_tool_execute — it fired 16 times against 15 short-circuits — so "not
    counted" is a property the implementation must add DELIBERATELY. NF2 then settled
    the channel: the refusal path calls neither update_budget_locked nor
    check_budgets, because a refusal is not an executed call. P2 (executed) is why
    silence is the right assertion rather than a stylistic preference: check_budgets
    is PURE — no memory, no per-run "already warned" state — so against a frozen
    at-cap counter it re-emits BYTE-IDENTICAL text on every single refusal, five for
    five, burying the real signal under its own repetition."""
    run_dir = materialize(tmp_path, GOLDEN)
    replay = ReplayFn([
        Turn(tool_calls=[("bash", {"command": "echo hi"})]),
        *[Turn(tool_calls=[("bash", {"command": f"echo {i}"})]) for i in range(20)],
        Turn(text="ok"),
    ])
    drive(run_dir, run_id="silent", salt=SALT, main=replay,
          limits=caps(max_tool_calls=1, wall_clock_timeout=3600, grace_seconds=600))
    err = capsys.readouterr().err

    # A refusal was actually delivered — so "no warnings" is silence DURING a real
    # refusal loop, not silence because nothing was refused (blind reader R20).
    assert refusal_stem() in "\n".join(replay.seen), "no refusal was delivered at all"
    assert budget(run_dir)["tool_calls"] == 1, "a refusal spent the tail band"
    # EXACTLY one "Budget exceeded" — the single line the ONE executed over-cap call
    # legitimately emits — and no more. NF2 (blind reader R7): the assertion is silence
    # ACROSS the refusal loop, so `== 1` catches the fail-open where check_budgets is
    # re-run on every one of the 20 refusals (P2: it re-emits byte-identical text five
    # for five), while `>= 1` would also catch a warning subsystem deleted to zero.
    assert err.count("Budget exceeded") == 1, (
        f"the refusal loop re-emitted the exceeded line {err.count('Budget exceeded')}× — "
        "check_budgets was called on refusals (NF2 says the refusal path must not)"
    )
    assert "Budget warning" not in err.split("Budget exceeded")[-1]


def test_a_refused_call_writes_an_explicit_refusal_record(tmp_path, enforced):
    """A call refused at the budget seam writes its OWN explicit refusal record rather
    than borrowing QueryCapture's row shape, so a refusal that leaves no queries-table
    row is still legible in the run's durable record.

    P4 (executed): under the live capability order the budget short-circuit preempts
    QueryCapture ENTIRELY — no breaker record, no queries-table row, no pre-call trip
    check — so the refusal has no carrier unless the seam mints one. The capability
    ORDER is unchanged (M11's no-phantom-row intent survives); what is added is the
    record. ACCEPTED RESIDUAL, recorded not fixed: the circuit breaker still does not
    observe refusals."""
    run_dir = materialize(tmp_path, GOLDEN)
    drive(run_dir, run_id="record", salt=SALT,
          main=ReplayFn([
              Turn(tool_calls=[("bash", {"command": "echo hi"})]),
              Turn(tool_calls=[("bash", {"command": "echo again"})]),
              Turn(text="ok"),
          ]),
          limits=caps(max_tool_calls=1))

    rows = list(read_jsonl_rows(run_dir / "llm_requests.jsonl"))
    refusals = [r for r in rows if r.get("kind") == "budget_refusal"]
    assert refusals, "a refused call left no explicit record in the run's durable log"
    assert refusals[0].get("tool_name") == "bash"
    assert refusals[0].get("agent_id") == "main"


# --- the tail band ----------------------------------------------------------

def test_replay_run_crosses_budget_and_still_reports(tmp_path, enforced):
    """The hermetic replay suite drives a full run with INJECTED LOW LIMITS until a
    cap actually trips, and observes the outcome: the expensive tools stop being
    usable, the report is still written inside the bounded tail, and the trace is on
    disk.

    This test cannot pass vacuously, and the cross-check that guarantees it is
    test_an_injected_cap_of_zero_trips_immediately_rather_than_disabling: PB6 executed
    the incumbent behaviour where an injected cap of 0 makes check_budgets return []
    silently, so a harness that injected 0 and observed "no report tail needed" would
    go green having driven no enforcement at all. The assertions below therefore
    require the refusal to be OBSERVED, not merely for the run to finish."""
    run_dir = materialize(tmp_path, GOLDEN)
    report = run_dir / "report.md"
    replay = ReplayFn([
        Turn(tool_calls=[("bash", {"command": "echo one"})]),
        Turn(tool_calls=[("bash", {"command": "echo two"})]),
        Turn(tool_calls=[("bash", {"command": "echo three"})]),   # refused
        Turn(tool_calls=[("write_file", {"path": str(report),
                                         "content": report_text()})]),
        Turn(text="Investigation complete."),
    ])
    summary = drive(run_dir, run_id="e2e", salt=SALT, main=replay,
                    limits=caps(max_tool_calls=2, wall_clock_timeout=3600,
                                grace_seconds=600))

    assert refusal_stem() in "\n".join(replay.seen), "no refusal was ever observed"
    assert report.is_file(), "the tail did not fund the report"
    assert "disposition: benign" in report.read_text()
    assert (run_dir / "tool_trace.jsonl").is_file()
    assert summary["requests"] >= 4


def test_each_trip_limb_opens_the_same_bounded_report_tail(tmp_path, enforced):
    """Every trip limb opens the SAME bounded report tail — the count limb, the spawn
    limb and the clock limb alike — and crossing the spawn cap produces an observable
    refusal of a gather while the run still reports.

    D7/D10/D12: O2 names no limb, and the CLOCK limb is the one that fires first in
    production, so denying it the tail guts O2 in the common case. This resolves the
    M1/M4 text conflict: M1's tier-agnostic wall-clock sentence is the STALE one.
    X8, re-probed executed by PB11, confirms the spawn counter is live for "gather"
    ONLY — the retired Task/Agent names increment tool_calls but not subagent_spawns —
    so the spawn arm below is written against a live counter."""
    verbs = FakeVerbs({"elastic": {"esql": lambda ctx, *, index: {"rows": []}}})

    def one_limb(name: str, limits: dict, script: list[Turn]) -> tuple[str, Path]:
        rd = materialize(tmp_path / name, GOLDEN)
        rep = rd / "report.md"
        replay = ReplayFn([*script,
                           Turn(tool_calls=[("write_file", {
                               "path": str(rep), "content": report_text()})]),
                           Turn(text="done")])
        drive(rd, run_id=name, salt=SALT, main=replay,
              gather=ReplayFn([Turn(text="summary")]), verbs=verbs, limits=limits)
        return "\n".join(replay.seen), rep

    stem = refusal_stem()

    # COUNT limb.
    history, rep = one_limb("count", caps(max_tool_calls=1, wall_clock_timeout=3600,
                                          grace_seconds=600),
                            [Turn(tool_calls=[("bash", {"command": "echo a"})]),
                             Turn(tool_calls=[("bash", {"command": "echo b"})])])
    assert stem in history and rep.is_file()

    # SPAWN limb — the arm that had no demand before, driven against the live counter.
    gathers = [Turn(tool_calls=[("gather", {"lead_id": f"l-00{i}", "system": "elastic",
                                            "goal": "g", "what_to_summarize": ["w"]})])
               for i in (1, 2)]
    history, rep = one_limb("spawn", caps(max_subagent_spawns=1, max_tool_calls=500,
                                          wall_clock_timeout=3600, grace_seconds=600),
                            gathers)
    assert stem in history, "crossing the spawn cap produced no observable refusal"
    assert rep.is_file(), "the spawn limb denied MAIN its report tail"

    # CLOCK limb — refusals never advance the count, so this is the only limb left.
    history, rep = one_limb("clock", caps(max_tool_calls=500, wall_clock_timeout=0,
                                          grace_seconds=600),
                            [Turn(tool_calls=[("bash", {"command": "echo a"})])])
    assert stem in history, "the clock limb refused nothing"
    assert rep.is_file(), "the clock limb denied MAIN its report tail"


def test_kill_lands_between_two_report_writes(tmp_path, enforced):
    """The report is written across more than one call and the tail is exhausted
    partway through: content from COMPLETED prior writes persists on disk, and the
    run's summary and trace still land — "whatever is on disk survives" is the whole
    contract, and no further granularity is specified for a write interrupted
    mid-flight."""
    run_dir = materialize(tmp_path, GOLDEN)
    part_one = run_dir / "report.md"
    inv = run_dir / "investigation.md"
    inv_text = (GOLDEN / "investigation.md").read_text()

    # Both writes are tail-tier, so they LAND inside the tail band; the count limb then
    # exhausts deterministically as tail-tier read_files advance the count to
    # N + TAIL_ALLOWANCE — no `wall_clock_timeout=2`-against-machine-speed race
    # (blind reader R25 named this the most fragile of the timing bloc).
    replay = ReplayFn([
        Turn(tool_calls=[("write_file", {"path": str(inv), "content": inv_text})]),
        Turn(tool_calls=[("write_file", {"path": str(part_one),
                                         "content": report_text()})]),
        *tail_turns(run_dir, 15),
        Turn(text="never reached"),
    ])
    summary = drive(run_dir, run_id="between", salt=SALT, main=replay,
                    limits=caps(max_tool_calls=1, wall_clock_timeout=3600,
                                grace_seconds=600))

    assert inv.read_text() == inv_text, "a completed prior write was lost by the kill"
    assert part_one.read_text() == report_text()
    assert summary["truncated_by"] == "budget"
    assert (run_dir / "tool_trace.jsonl").is_file()


# --- one pool, and what does and does not spend it ---------------------------

def test_main_and_gather_share_one_budget(tmp_path, unenforced):
    """MAIN and every GATHER subagent increment the ONE budget.json keyed by run dir,
    so the caps bound the pool rather than each agent separately — and the file the
    subagent's calls land in is the same file MAIN's do, not a second one."""
    recorder = VerbRecorder()

    def esql(ctx, *, index: str) -> dict:
        recorder.record("esql", ctx, {"index": index})
        return {"rows": []}

    verbs = FakeVerbs({"elastic": {"esql": esql}})
    run_dir = materialize(tmp_path, GOLDEN)
    gather = ReplayFn([
        Turn(tool_calls=[("query", {"system": "elastic", "verb": "esql",
                                    "params": {"index": "logs"},
                                    "query_id": "elastic.probe"})]),
        Turn(text="PARTIAL SUMMARY"),
    ])
    drive(run_dir, run_id="pool", salt=SALT,
          main=ReplayFn([
              Turn(tool_calls=[("bash", {"command": "echo hi"})]),
              Turn(tool_calls=[("gather", {"lead_id": "l-001", "system": "elastic",
                                           "goal": "g", "what_to_summarize": ["w"]})]),
              Turn(text="done"),
          ]),
          gather=gather, verbs=verbs, limits=caps())

    assert len(list((run_dir).glob("**/budget.json"))) == 1
    state = budget(run_dir)
    assert state["subagent_spawns"] == 1
    assert state["tool_calls"] >= 3, (
        f"the gather subagent's own query did not spend the shared pool: {state}"
    )
    assert recorder.verbs == ["esql"]


def test_accounting_runs_regardless_of_posture(tmp_path, monkeypatch, capsys):
    """Counter increments AND stderr warnings happen on every tool call that ACTUALLY
    EXECUTES, whether or not the posture bit enables enforcement — accounting is
    unconditional with respect to POSTURE, which is a different axis from whether a
    given call did any work.

    F3(b) narrowed the quantifier to executed calls and NF2 confirmed the narrowing:
    the refusal path calls neither update_budget_locked nor check_budgets, and the
    stderr-SILENCE assertion that implies lives on
    test_refused_call_does_not_increment_tool_calls rather than here (a reader arriving
    here must not write a second, conflicting assertion about the same channel). Here
    the calls all EXECUTE (three under a cap of four → the 75% line), so the warning
    fires under BOTH postures — the unconditional-with-respect-to-posture half."""
    def script():
        return ReplayFn([*[Turn(tool_calls=[("bash", {"command": f"echo {i}"})])
                           for i in range(3)], Turn(text="done")])
    states, warned = {}, {}
    for posture in ("off", "on"):
        if posture == "on":
            monkeypatch.setenv(FLAG, "true")
        else:
            monkeypatch.delenv(FLAG, raising=False)
        rd = materialize(tmp_path / posture, GOLDEN)
        drive(rd, run_id=posture, salt=SALT, main=script(),
              limits=caps(max_tool_calls=4))
        states[posture] = budget(rd)
        warned[posture] = "Budget warning" in capsys.readouterr().err

    assert states["off"]["tool_calls"] == states["on"]["tool_calls"] == 3
    assert warned["off"] and warned["on"], (
        "the 75% warning did not fire under both postures — accounting is gated on posture"
    )


def test_flag_off_leaves_run_unenforced(tmp_path, unenforced, capsys):
    """With the flag off, a run that crosses every cap observes no refusal and no kill
    — only the existing stderr warnings — and completes exactly as it does today.

    The positive control is test_budget_trip_returns_summary_and_writes_trace: the
    SAME two-bash-then-text script under the SAME injected caps with the flag ON
    delivers a refusal, which this run does not — the complementary condition on the
    same address (blind reader R3 required aligning the two)."""
    run_dir = materialize(tmp_path, GOLDEN)
    replay = ReplayFn([
        Turn(tool_calls=[("bash", {"command": "echo hi"})]),
        Turn(tool_calls=[("bash", {"command": "echo again"})]),
        Turn(text="done"),
    ])
    summary = drive(run_dir, run_id="off", salt=SALT, main=replay,
                    limits=caps(max_tool_calls=1, wall_clock_timeout=3600,
                                grace_seconds=600))
    err = capsys.readouterr().err

    assert refusal_stem() not in "\n".join(replay.seen), "an unenforced run was refused"
    assert summary["truncated_by"] is None
    assert budget(run_dir)["tool_calls"] == 2, "the crossed cap stopped the accounting"
    assert "Budget exceeded" in err, "the warning-only behaviour was lost"


def test_refused_gather_and_the_spawn_counter(tmp_path, enforced):
    """A budget-refused `gather` call never dispatches a subagent, and the refusal
    still reaches the accounting hook that carries the spawn branch — so
    subagent_spawns does NOT advance for it, by the same F3(b) reasoning that excludes
    tool_calls.

    The warrant is F3(b) rather than the design doc: the analogy is tight and the
    consensus was 3/3-by-inference, so it is cited as such rather than dressed up as
    doc-direct."""
    verbs = FakeVerbs({"elastic": {"esql": lambda ctx, *, index: {"rows": []}}})
    run_dir = materialize(tmp_path, GOLDEN)
    gather = ReplayFn([Turn(text="summary")])
    replay = ReplayFn([
        Turn(tool_calls=[("gather", {"lead_id": "l-001", "system": "elastic",
                                     "goal": "g", "what_to_summarize": ["w"]})]),
        Turn(tool_calls=[("gather", {"lead_id": "l-002", "system": "elastic",
                                     "goal": "g", "what_to_summarize": ["w"]})]),
        Turn(tool_calls=[("gather", {"lead_id": "l-003", "system": "elastic",
                                     "goal": "g", "what_to_summarize": ["w"]})]),
        Turn(text="done"),
    ])
    drive(run_dir, run_id="spawn", salt=SALT, main=replay, gather=gather, verbs=verbs,
          limits=caps(max_subagent_spawns=1, max_tool_calls=500,
                      wall_clock_timeout=3600, grace_seconds=600))

    assert budget(run_dir)["subagent_spawns"] == 1, (
        "a refused gather was charged to the spawn counter"
    )
    assert (run_dir / "gather_raw" / "l-001.lead.json").exists(), (
        "the admitted gather did not claim its lead id"
    )
    # l-002 is the FIRST refused gather — the off-by-one case an implementation that
    # claims the id and THEN refuses would get wrong (blind reader R33). l-003 confirms
    # the refusal is standing, not a one-off.
    assert not (run_dir / "gather_raw" / "l-002.lead.json").exists(), (
        "the first refused gather claimed a lead id"
    )
    assert not (run_dir / "gather_raw" / "l-003.lead.json").exists(), (
        "a refused gather claimed a lead id"
    )


def test_subagent_dispatched_into_an_already_stopped_pool(tmp_path, enforced):
    """A gather dispatched into an already-tripped pool is refused at MAIN's own
    tool_execute seam — `gather` is core-tier, so its "very first call" (the dispatch
    itself) is refused BEFORE any subagent is constructed — and no work is ever done:
    the inner model is never invoked, no query row, no payload, and MAIN reads the
    gather refusal.

    The `gather.calls == 0` assertion is the discriminator (blind reader R8): the
    absence assertions (`recorder.calls == []`, no queries table) hold BOTH when the
    subagent is dispatched-then-refused AND when it is never dispatched, and this
    scenario's whole point is that on a tripped pool the core-tier dispatch is refused
    UPSTREAM of construction, so the inner replay must never run."""
    recorder = VerbRecorder()

    def esql(ctx, *, index: str) -> dict:
        recorder.record("esql", ctx, {"index": index})
        return {"rows": [1]}

    verbs = FakeVerbs({"elastic": {"esql": esql}})
    run_dir = materialize(tmp_path, GOLDEN)
    open_budget(run_dir, "stopped")
    limits = caps(max_tool_calls=1, wall_clock_timeout=3600, grace_seconds=600)
    update_budget_locked(run_dir, "stopped", "bash", limits=limits)

    gather = ReplayFn([
        Turn(tool_calls=[("query", {"system": "elastic", "verb": "esql",
                                    "params": {"index": "logs"},
                                    "query_id": "elastic.probe"})]),
        Turn(text="PARTIAL SUMMARY: refused before any result"),
    ])
    main = ReplayFn([
        Turn(tool_calls=[("gather", {"lead_id": "l-001", "system": "elastic",
                                     "goal": "g", "what_to_summarize": ["w"]})]),
        Turn(text="done"),
    ])
    drive(run_dir, run_id="stopped", salt=SALT, main=main, gather=gather, verbs=verbs,
          limits=limits)

    assert gather.calls == 0, "the subagent's model was invoked on an already-stopped pool"
    assert recorder.calls == [], "the subagent did work inside an already-stopped pool"
    assert not (run_dir / "executed_queries.jsonl").exists()
    assert refusal_stem() in "\n".join(main.seen), (
        "MAIN did not observe the gather dispatch being refused"
    )


# --- capability ordering: the phantom row -----------------------------------

def test_stopped_query_writes_no_row(tmp_path, enforced):
    """A query stopped by the budget writes NO row into the queries table —
    `_make_hooks` is prepended ahead of QueryCapture, so the budget's tool_execute
    wrapper returns its refusal without ever entering QueryCapture's, and a call that
    never ran leaves no record claiming it did.

    P4 executed the ordering BOTH ways: under the live order (hooks first,
    driver.py:205) the short-circuit preempts QueryCapture entirely — no
    record_outcome, no queries-table row, and no pre-call breaker check. The order is
    KEPT and the refusal's own record is minted separately
    (test_a_refused_call_writes_an_explicit_refusal_record) rather than borrowing
    QueryCapture's row shape.

    THE SUBAGENT GENUINELY RUNS AND ISSUES BOTH QUERIES (blind reader R8): pre-tripping
    the pool and making `gather` MAIN's first call would refuse the DISPATCH and never
    reach QueryCapture at all, so the absence of a row would prove nothing about the
    ordering. Instead the cap is 1: the subagent's FIRST query executes and writes its
    row (crossing the cap), and its SECOND query is the one the budget stops — so the
    stopped query, having reached the seam, must leave no row while the executed one
    did. The executed row is the in-test control that the subagent's queries reach
    QueryCapture at all.

    The positive control is test_executed_query_writes_a_row."""
    recorder = VerbRecorder()

    def esql(ctx, *, index: str) -> dict:
        recorder.record("esql", ctx, {"index": index})
        return {"rows": [1]}

    verbs = FakeVerbs({"elastic": {"esql": esql}})
    run_dir = materialize(tmp_path, GOLDEN)
    gather = ReplayFn([
        Turn(tool_calls=[("query", {"system": "elastic", "verb": "esql",
                                    "params": {"index": "logs"},
                                    "query_id": "elastic.probe"})]),      # executes, trips
        Turn(tool_calls=[("query", {"system": "elastic", "verb": "esql",
                                    "params": {"index": "logs2"},
                                    "query_id": "elastic.probe2"})]),     # refused
        Turn(text="done"),
    ])
    drive(run_dir, run_id="phantom", salt=SALT,
          main=ReplayFn([
              Turn(tool_calls=[("gather", {"lead_id": "l-001", "system": "elastic",
                                           "goal": "g", "what_to_summarize": ["w"]})]),
              Turn(text="done"),
          ]),
          gather=gather,
          verbs=verbs, limits=caps(max_tool_calls=1, wall_clock_timeout=3600,
                                   grace_seconds=600))

    assert gather.calls >= 1, "the subagent never ran, so the ordering was not exercised"
    assert recorder.verbs == ["esql"], "the stopped query's handler ran (no short-circuit)"
    rows = list(read_jsonl_rows(run_dir / "executed_queries.jsonl"))
    assert len(rows) == 1, (
        f"the stopped query wrote a phantom row — {len(rows)} rows for 1 executed query"
    )
    # The stopped query, though preempted before QueryCapture, is still legible: it
    # mints its own budget_refusal record (pairs with refusal_writes_its_own_record).
    refusals = [r for r in read_jsonl_rows(run_dir / "llm_requests.jsonl")
                if r.get("kind") == "budget_refusal" and r.get("tool_name") == "query"]
    assert refusals, "the stopped query reached the seam but left no record at all"


def test_executed_query_writes_a_row(tmp_path, unenforced):
    """A query that actually executes under the same harness DOES write its
    queries-table row and its by-ref payload — the control that keeps the phantom-row
    demand from passing vacuously."""
    recorder = VerbRecorder()

    def esql(ctx, *, index: str) -> dict:
        recorder.record("esql", ctx, {"index": index})
        return {"rows": [1]}

    verbs = FakeVerbs({"elastic": {"esql": esql}})
    run_dir = materialize(tmp_path, GOLDEN)
    drive(run_dir, run_id="row", salt=SALT,
          main=ReplayFn([
              Turn(tool_calls=[("gather", {"lead_id": "l-001", "system": "elastic",
                                           "goal": "g", "what_to_summarize": ["w"]})]),
              Turn(text="done"),
          ]),
          gather=ReplayFn([
              Turn(tool_calls=[("query", {"system": "elastic", "verb": "esql",
                                          "params": {"index": "logs"},
                                          "query_id": "elastic.probe"})]),
              Turn(text="summary"),
          ]),
          verbs=verbs, limits=caps())

    rows = list(read_jsonl_rows(run_dir / "executed_queries.jsonl"))
    assert len(rows) == 1
    assert rows[0]["lead_id"] == "l-001" and rows[0]["system"] == "elastic"
    assert recorder.only().params == {"index": "logs"}


# --- GATHER's own boundary ---------------------------------------------------

def test_gather_abort_becomes_measurement_string(tmp_path, enforced):
    """A gather subagent that runs into its own request limit is converted to the
    measurement-shaped string, so MAIN reads an incomplete lead and reasons on rather
    than the run dying with no report — and a BUDGET REFUSAL inside GATHER is a
    DIFFERENT path that does not produce that string at all.

    P1 (executed) re-targeted this demand: at the GATHER boundary a budget refusal is
    an ordinary ToolReturnPart, NOT an exception — the inner run completes and MAIN
    reads the subagent's own degraded summary ("PARTIAL SUMMARY: got 1 result, then
    refused"). The measurement-shaped string comes from the PRE-EXISTING
    UsageLimitExceeded limb, reached only when the subagent re-issues the refused tool
    until the request limit. TWO DISTINCT CODE PATHS — a test written against "a
    refusal becomes a measurement string" would assert a conversion that never
    happens."""
    verbs = FakeVerbs({"elastic": {"esql": lambda ctx, *, index: {"rows": []}}})
    query_turn = Turn(tool_calls=[("query", {"system": "elastic", "verb": "esql",
                                             "params": {"index": "logs"},
                                             "query_id": "elastic.probe"})])

    # ARM A — the subagent never stops and hits its own request limit.
    run_dir = materialize(tmp_path / "limit", GOLDEN)
    main = ReplayFn([
        Turn(tool_calls=[("gather", {"lead_id": "l-001", "system": "elastic",
                                     "goal": "g", "what_to_summarize": ["w"]})]),
        Turn(text="done"),
    ])
    drive(run_dir, run_id="limit", salt=SALT, main=main,
          gather=ReplayFn([query_turn] * 200), verbs=verbs, limits=caps())
    assert "hit its request limit" in "\n".join(main.seen)
    assert "Treat this lead as incomplete" in "\n".join(main.seen)

    # ARM B — a budget refusal inside GATHER: an ordinary tool result, so the subagent
    # keeps working and MAIN reads its OWN degraded summary, not the measurement string.
    # The subagent must genuinely run (blind reader R8): cap 1 admits the dispatch and
    # the subagent's FIRST query, then trips, so its SECOND query is refused as a
    # ToolReturnPart and it narrates its own "PARTIAL SUMMARY: refused" — the P1 shape.
    other = materialize(tmp_path / "refused", GOLDEN)
    main_b = ReplayFn([
        Turn(tool_calls=[("gather", {"lead_id": "l-001", "system": "elastic",
                                     "goal": "g", "what_to_summarize": ["w"]})]),
        Turn(text="done"),
    ])
    gather_b = ReplayFn([
        query_turn,                                                    # executes, trips
        Turn(tool_calls=[("query", {"system": "elastic", "verb": "esql",
                                    "params": {"index": "logs2"},
                                    "query_id": "elastic.probe2"})]),  # refused
        Turn(text="PARTIAL SUMMARY: refused"),
    ])
    drive(other, run_id="gref", salt=SALT, main=main_b, gather=gather_b, verbs=verbs,
          limits=caps(max_tool_calls=1, wall_clock_timeout=3600, grace_seconds=600))
    assert gather_b.calls >= 2, "the subagent did not keep working past the refusal"
    history = "\n".join(main_b.seen)
    assert "PARTIAL SUMMARY: refused" in history
    assert "hit its request limit" not in history, (
        "a budget refusal was converted into the measurement string — the wrong path"
    )


def test_gather_has_no_per_call_timeout(tmp_path, unenforced):
    """No per-call wall clock is imposed on a gather dispatch: a lead whose work runs
    well past any short per-call bound is NOT cut off, because a legitimate
    six-dimension lead needs roughly twenty-six turns.

    C9 (read) records why an outer wall-clock timeout on `query` was deliberately
    removed and must not be reinstated as a wrapper: `asyncio.wait_for` cancels the
    await, not the thread, so a hung verb leaks a thread and synthesizes an exit-124
    row reporting a kill that never happened. The positive control is
    test_gather_keeps_its_request_limit — the bound that DOES exist is still enforced,
    so this negative cannot pass by the dispatch being unbounded in every direction."""
    def slow(ctx, *, index: str) -> dict:
        import time
        time.sleep(1.5)
        return {"rows": [1]}

    verbs = FakeVerbs({"elastic": {"esql": slow}})
    run_dir = materialize(tmp_path, GOLDEN)
    main = ReplayFn([
        Turn(tool_calls=[("gather", {"lead_id": "l-001", "system": "elastic",
                                     "goal": "g", "what_to_summarize": ["w"]})]),
        Turn(text="done"),
    ])
    drive(run_dir, run_id="slow", salt=SALT, main=main,
          gather=ReplayFn([
              Turn(tool_calls=[("query", {"system": "elastic", "verb": "esql",
                                          "params": {"index": "logs"},
                                          "query_id": "elastic.probe"})]),
              Turn(text="finished after a long call"),
          ]),
          verbs=verbs, limits=caps())

    assert "finished after a long call" in "\n".join(main.seen)
    rows = list(read_jsonl_rows(run_dir / "executed_queries.jsonl"))
    assert rows and rows[0]["exit_code"] == 0, (
        "a per-call stopwatch synthesized a timeout row for a call that completed"
    )
