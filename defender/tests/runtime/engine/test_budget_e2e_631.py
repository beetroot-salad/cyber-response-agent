"""#631 — the enforced posture driven END TO END through the real `driver.run_investigation` loop."""
from __future__ import annotations

from pathlib import Path

import pytest

from defender.tests.support.runtime.state._1255_view import model_path

from defender._io import read_jsonl_rows
from defender.records import RunPaths
from defender.hooks.budget_enforcer import (
    BUDGET_REFUSAL_MESSAGE,
    DEFAULT_LIMITS,
)
from defender.runtime.lead_zero import RESERVED_LEAD_IDS
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
    """The enforcing posture, set the only way production sets it: the real environment variable the real..."""
    monkeypatch.setenv(FLAG, "true")


@pytest.fixture
def unenforced(monkeypatch):
    monkeypatch.delenv(FLAG, raising=False)


def caps(**over) -> dict:
    return {**DEFAULT_LIMITS, **over}


def budget(summary: dict) -> dict:
    """The run's budget counters: a snapshot of the run's own `RunState`, which `drive` hands back on the summary..."""
    return summary["run_state"].budget_snapshot()


def own_rows(run_dir: Path) -> list[dict]:
    """The queries-table rows written by this test's own scripted `gather`/`query` calls — excluding lead-0's..."""
    return [r for r in read_jsonl_rows(run_dir / "executed_queries.jsonl")
            if r["lead_id"] not in RESERVED_LEAD_IDS]


def report_text() -> str:
    return "---\ncase_id: c-1\ndisposition: benign\nconfidence: low\n---\n\nDone.\n"


def tail_turns(run_dir: Path, n: int) -> list[Turn]:
    """`n` TAIL-tier read_file turns — read_file is tail on MAIN, so each EXECUTES and
    advances tool_calls even after the trip, driving the count limb to
    N + TAIL_ALLOWANCE deterministically. This is how the kill tests reach exhaustion
    WITHOUT depending on wall-clock timing (blind reader R25: six e2e tests shared an
    undeclared machine-speed assumption through `wall_clock_timeout=1`)."""
    return [Turn(tool_calls=[("read_file", {"path": model_path(RunPaths(run_dir).alert, run_dir=run_dir)})])
            for _ in range(n)]


def refusal_stem() -> str:
    """The placeholder-free literal prefix of the refusal message, GUARDED non-empty."""
    stem = BUDGET_REFUSAL_MESSAGE.split("{", 1)[0].strip()
    assert stem, (
        "BUDGET_REFUSAL_MESSAGE begins with an interpolated field — its literal prefix "
        "is empty, so every 'a refusal was delivered' check would pass vacuously. "
        "Author the constant with a literal lead-in (blind reader R5)."
    )
    return stem


def test_budget_trip_returns_summary_and_writes_trace(tmp_path, enforced):
    """When a cap trips with enforcement on, run_investigation returns its normal summary dict — {output, model,..."""
    run_dir = materialize(tmp_path, GOLDEN, run_id='trip')
    replay = ReplayFn([
        Turn(tool_calls=[("bash", {"command": "echo hi"})]),
        Turn(tool_calls=[("bash", {"command": "echo again"})]),
        Turn(text="Investigation complete."),
    ])
    summary = drive(run_dir, run_id="trip", main=replay,
                    limits=caps(max_tool_calls=1, wall_clock_timeout=3600,
                                grace_seconds=600))

    assert set(summary) >= {"output", "model", "requests", "truncated_by"}
    assert refusal_stem() in "\n".join(replay.seen), (
        "enforcement did not fire — no refusal was observed, so this control controls nothing"
    )
    assert budget(summary)["tool_calls"] == 1, "the refused call spent the pool"
    assert summary["requests"] >= 2
    assert (run_dir / "tool_trace.jsonl").is_file()
    assert RunPaths(run_dir).wire_log.is_file()
    assert budget(summary).get("run_id") == run_dir.name, "the run opened no budget of its own"


def test_a_budget_killed_run_carries_truncated_by_budget(tmp_path, enforced):
    """A run ended by the budget kill carries truncated_by: "budget", so the post-run pipeline can see that..."""
    run_dir = materialize(tmp_path, GOLDEN, run_id='trunc')
    summary = drive(run_dir, run_id="trunc",
                    main=ReplayFn(tail_turns(run_dir, 15)),
                    limits=caps(max_tool_calls=1, wall_clock_timeout=3600,
                                grace_seconds=600))
    assert summary["truncated_by"] == "budget"
    assert summary["output"] is None, "the kill ended the run before an End node"

    clean_dir = materialize(tmp_path / "clean", GOLDEN, run_id='clean')
    clean = drive(clean_dir, run_id="clean",
                  main=ReplayFn([Turn(text="Investigation complete.")]),
                  limits=caps())
    assert clean["truncated_by"] is None


def test_only_the_budget_kill_marks_truncated_by_budget(tmp_path, enforced):
    """Only the budget kill sets truncated_by: "budget" — the PRE-EXISTING request-limit termination..."""
    from defender.tests.e2e._replay_harness import NeverEndsModel

    run_dir = materialize(tmp_path, GOLDEN, run_id='reqlimit')
    summary = drive(run_dir, run_id="reqlimit",
                    main=NeverEndsModel(run_dir), limits=caps())
    assert summary["truncated_by"] == "request-limit", (
        "a request-limit termination was mislabelled as a budget truncation"
    )
    assert budget(summary)["tool_calls"] < DEFAULT_LIMITS["max_tool_calls"], (
        "the run hit a budget cap after all — pick a terminator that is not the budget"
    )


def test_budget_kill_writes_partial_trace(tmp_path, enforced):
    """Tail exhaustion raises the budget kill's own exception type — not RunAborted, whose constructor is..."""
    run_dir = materialize(tmp_path, GOLDEN, run_id='kill')
    burst = [Turn(tool_calls=[("read_file", {"path": model_path(RunPaths(run_dir).alert, run_dir=run_dir)})] * 15)]
    summary = drive(run_dir, run_id="kill", main=ReplayFn(burst),
                    limits=caps(max_tool_calls=1, wall_clock_timeout=3600,
                                grace_seconds=600))

    assert summary["truncated_by"] == "budget", (
        "the concurrent kills did not collapse to one caught BudgetKill"
    )
    events = list(read_jsonl_rows(run_dir / "tool_trace.jsonl"))
    assert events, "the partial trace was lost on the kill path"
    assert any(e.get("type") == "result" for e in events)


def test_kill_exception_reaches_uncaught_driver_handling(tmp_path, enforced, capsys):
    """The tail-exhaustion kill is raised from a seam OUTSIDE after_tool_execute's broad exception guard, so the..."""
    run_dir = materialize(tmp_path, GOLDEN, run_id='guard')
    summary = drive(run_dir, run_id="guard",
                    main=ReplayFn(tail_turns(run_dir, 15)),
                    limits=caps(max_tool_calls=1, wall_clock_timeout=3600,
                                grace_seconds=600))
    err = capsys.readouterr().err
    assert summary["truncated_by"] == "budget", "the kill did not end the run at all"
    assert "budget accounting skipped" not in err, (
        "the kill was swallowed by after_tool_execute's except Exception guard"
    )


def test_only_one_shutdown_path_writes_the_run_dir_artifacts(tmp_path, enforced):
    """Exactly one shutdown path writes the run-dir artifacts, whichever kill fires and whether or not both fire:..."""
    run_dir = materialize(tmp_path, GOLDEN, run_id='shutdown')
    summary = drive(run_dir, run_id="shutdown",
                    main=ReplayFn(tail_turns(run_dir, 15)),
                    limits=caps(max_tool_calls=1, wall_clock_timeout=3600,
                                grace_seconds=600))
    assert summary["truncated_by"] == "budget", "the run did not take a kill path at all"

    events = list(read_jsonl_rows(run_dir / "tool_trace.jsonl"))
    assert sum(1 for e in events if e.get("type") == "result") == 1

    rows = list(read_jsonl_rows(RunPaths(run_dir).wire_log))
    ids = [r.get("id") for r in rows if r.get("id")]
    assert ids, "no request ids were logged — the uniqueness check would pass vacuously"
    assert len(ids) == len(set(ids)), "the request log was written by two paths"


def test_budget_kill_and_breaker_kill_are_independent(tmp_path, enforced):
    """The budget kill and the circuit-breaker kill are independent — first fires wins, and neither consults the..."""
    run_dir = materialize(tmp_path, GOLDEN, run_id='both')
    dead = FakeVerbs({"elastic": {"esql": _dead_verb()}})
    charge = ReplayFn([Turn(tool_calls=[("query", {
        "system": "elastic", "verb": "esql", "params": {"index": "logs"},
        "query_id": "elastic.probe"})]), Turn(text="PARTIAL SUMMARY: the backend is down")])
    summary = drive(run_dir, run_id="both",
                    main=ReplayFn([
                        Turn(tool_calls=[("gather", {
                            "lead_id": "l-001", "system": "elastic",
                            "goal": "g", "what_to_summarize": ["w"]})]),
                        *tail_turns(run_dir, 15)]),
                    gather=charge, verbs=dead,
                    limits=caps(max_tool_calls=2, wall_clock_timeout=3600,
                                grace_seconds=600))
    assert charge.calls >= 1, "the charging gather never ran, so the breaker was never charged"
    assert summary["truncated_by"] == "budget", "the budget did not fire first"
    assert summary["run_state"].breaker_snapshot() == {
        "systems": {"elastic": {"failures": 1}}, "total_failures": 1}, (
        "the breaker's record is not the one in-run charge: the budget kill reached into it, "
        "or the charge never landed"
    )

    other = materialize(tmp_path / "brk", GOLDEN, run_id='brk')
    verbs = FakeVerbs({"elastic": {"esql": _dead_verb()}})
    gather = ReplayFn([Turn(tool_calls=[("query", {
        "system": "elastic", "verb": "esql", "params": {"index": "logs"},
        "query_id": "elastic.probe"})])] * 8)
    summary = drive(other, run_id="brk",
                    main=ReplayFn([
                        Turn(tool_calls=[("gather", {
                            "lead_id": f"l-00{i}", "system": "elastic",
                            "goal": "g", "what_to_summarize": ["w"]})])
                        for i in range(1, 7)]),
                    gather=gather, verbs=verbs, limits=caps())
    assert summary["truncated_by"] is None, "the budget wrongly marked a breaker-ended run"
    assert budget(summary)["tool_calls"] < DEFAULT_LIMITS["max_tool_calls"]
    engaged = summary["run_state"].breaker_snapshot()
    assert engaged["total_failures"] > 0, "the breaker never engaged, so arm 2 controls nothing"


def _dead_verb():
    def esql(ctx, *, index: str) -> dict:
        raise ConnectionError("the environment is unreachable")
    return esql


def test_stopped_tool_is_refused_not_withdrawn(tmp_path, enforced):
    """After a cap trips, the budget-stopped tool is STILL OFFERED to the model, and every call to it is refused..."""
    run_dir = materialize(tmp_path, GOLDEN, run_id='refuse')
    replay = ReplayFn([
        Turn(tool_calls=[("bash", {"command": "echo hi"})]),
        Turn(tool_calls=[("bash", {"command": "echo again"})]),
        Turn(text="Acknowledged."),
    ])
    summary = drive(run_dir, run_id="refuse", main=replay,
                    limits=caps(max_tool_calls=1, wall_clock_timeout=3600, grace_seconds=600))

    history = "\n".join(replay.seen)
    assert refusal_stem() in history, "the stopped tool was not refused at the seam"
    assert "Unknown tool name" not in history, (
        "the tool was WITHDRAWN rather than refused — X6's refuted mechanism"
    )
    assert budget(summary)["tool_calls"] == 1, (
        "the refused call's handler ran — the seam did not short-circuit"
    )


def test_repeated_reissue_accumulates_no_retries(tmp_path, enforced):
    """A model that re-issues a budget-stopped tool many more times than MAIN's ten-retry ceiling accumulates NO..."""
    from pydantic_ai.exceptions import UnexpectedModelBehavior

    run_dir = materialize(tmp_path, GOLDEN, run_id='reissue')
    replay = ReplayFn([
        Turn(tool_calls=[("bash", {"command": "echo hi"})]),
        *[Turn(tool_calls=[("bash", {"command": "echo again"})]) for _ in range(25)],
        Turn(text="Acknowledged; writing the report."),
    ])
    try:
        summary = drive(run_dir, run_id="reissue", main=replay,
                        limits=caps(max_tool_calls=1, wall_clock_timeout=3600,
                                    grace_seconds=600))
    except UnexpectedModelBehavior as e:  # pragma: no cover - the failure this pins
        pytest.fail(f"25 consecutive re-issues accumulated retries: {e}")

    assert refusal_stem() in "\n".join(replay.seen), (
        "no refusal was ever delivered — the tool was not budget-stopped at all"
    )
    assert budget(summary)["tool_calls"] == 1, "a refused re-issue advanced the counter"
    assert replay.calls >= 25, "the loop died before the re-issues were exhausted"
    assert summary["requests"] >= 25
    assert (run_dir / "tool_trace.jsonl").is_file()


def test_refused_call_does_not_increment_tool_calls(tmp_path, enforced, capsys):
    """A call refused at the execute seam leaves tool_calls unchanged in the run's budget AND emits NOTHING on..."""
    run_dir = materialize(tmp_path, GOLDEN, run_id='silent')
    replay = ReplayFn([
        Turn(tool_calls=[("bash", {"command": "echo hi"})]),
        *[Turn(tool_calls=[("bash", {"command": f"echo {i}"})]) for i in range(20)],
        Turn(text="ok"),
    ])
    summary = drive(run_dir, run_id="silent", main=replay,
                    limits=caps(max_tool_calls=1, wall_clock_timeout=3600, grace_seconds=600))
    err = capsys.readouterr().err

    assert refusal_stem() in "\n".join(replay.seen), "no refusal was delivered at all"
    assert budget(summary)["tool_calls"] == 1, "a refusal spent the tail band"
    assert err.count("Budget exceeded") == 1, (
        f"the refusal loop re-emitted the exceeded line {err.count('Budget exceeded')}× — "
        "check_budgets was called on refusals (NF2 says the refusal path must not)"
    )
    assert "Budget warning" not in err.split("Budget exceeded")[-1]


def test_a_refused_call_writes_an_explicit_refusal_record(tmp_path, enforced):
    """A call refused at the budget seam writes its OWN explicit refusal record rather than borrowing..."""
    run_dir = materialize(tmp_path, GOLDEN, run_id='record')
    drive(run_dir, run_id="record",
          main=ReplayFn([
              Turn(tool_calls=[("bash", {"command": "echo hi"})]),
              Turn(tool_calls=[("bash", {"command": "echo again"})]),
              Turn(text="ok"),
          ]),
          limits=caps(max_tool_calls=1))

    rows = list(read_jsonl_rows(RunPaths(run_dir).wire_log))
    refusals = [r for r in rows if r.get("kind") == "budget_refusal"]
    assert refusals, "a refused call left no explicit record in the run's durable log"
    assert refusals[0].get("tool_name") == "bash"
    assert refusals[0].get("agent_id") == "main"


def test_replay_run_crosses_budget_and_still_reports(tmp_path, enforced):
    """The hermetic replay suite drives a full run with INJECTED LOW LIMITS until a cap actually trips, and..."""
    # #774/R1: report.md left MAIN's write allow-list entirely (the close tool is now its
    # only writer), so the tail-tier artifact this scenario funds is investigation.md.
    run_dir = materialize(tmp_path, GOLDEN, run_id='e2e')
    inv = run_dir / "investigation.md"
    inv_text = (GOLDEN / "investigation.md").read_text()
    replay = ReplayFn([
        Turn(tool_calls=[("bash", {"command": "echo one"})]),
        Turn(tool_calls=[("bash", {"command": "echo two"})]),
        Turn(tool_calls=[("bash", {"command": "echo three"})]),
        Turn(tool_calls=[("append_block", {"text": inv_text})]),
        Turn(text="Investigation complete."),
    ])
    summary = drive(run_dir, run_id="e2e", main=replay,
                    limits=caps(max_tool_calls=2, wall_clock_timeout=3600,
                                grace_seconds=600))

    assert refusal_stem() in "\n".join(replay.seen), "no refusal was ever observed"
    assert inv.is_file(), "the tail did not fund the write"
    assert inv.read_text() == inv_text
    assert (run_dir / "tool_trace.jsonl").is_file()
    assert summary["requests"] >= 4


def test_each_trip_limb_opens_the_same_bounded_report_tail(tmp_path, enforced):
    """Every trip limb opens the SAME bounded report tail — the count limb, the spawn limb and the clock limb..."""
    verbs = FakeVerbs({"elastic": {"esql": lambda ctx, *, index: {"rows": []}}})
    inv_text = (GOLDEN / "investigation.md").read_text()

    def one_limb(name: str, limits: dict, script: list[Turn]) -> tuple[str, Path]:
        # #774/R1: report.md left MAIN's write allow-list — the tail-tier artifact this
        # scenario funds is investigation.md, whichever limb trips.
        rd = materialize(tmp_path / name, GOLDEN, run_id=name)
        rep = rd / "investigation.md"
        replay = ReplayFn([*script,
                           Turn(tool_calls=[("append_block", {"text": inv_text})]),
                           Turn(text="done")])
        drive(rd, run_id=name, main=replay,
              gather=ReplayFn([Turn(text="summary")]), verbs=verbs, limits=limits)
        return "\n".join(replay.seen), rep

    stem = refusal_stem()

    history, rep = one_limb("count", caps(max_tool_calls=1, wall_clock_timeout=3600,
                                          grace_seconds=600),
                            [Turn(tool_calls=[("bash", {"command": "echo a"})]),
                             Turn(tool_calls=[("bash", {"command": "echo b"})])])
    assert stem in history
    assert rep.is_file()

    gathers = [Turn(tool_calls=[("gather", {"lead_id": f"l-00{i}", "system": "elastic",
                                            "goal": "g", "what_to_summarize": ["w"]})])
               for i in (1, 2)]
    history, rep = one_limb("spawn", caps(max_subagent_spawns=1, max_tool_calls=500,
                                          wall_clock_timeout=3600, grace_seconds=600),
                            gathers)
    assert stem in history, "crossing the spawn cap produced no observable refusal"
    assert rep.is_file(), "the spawn limb denied MAIN its report tail"

    history, rep = one_limb("clock", caps(max_tool_calls=500, wall_clock_timeout=0,
                                          grace_seconds=600),
                            [Turn(tool_calls=[("bash", {"command": "echo a"})])])
    assert stem in history, "the clock limb refused nothing"
    assert rep.is_file(), "the clock limb denied MAIN its report tail"


def test_kill_lands_between_two_report_writes(tmp_path, enforced):
    """The run's tail-tier artifact is written across more than one call and the tail is exhausted partway..."""
    run_dir = materialize(tmp_path, GOLDEN, run_id='between')
    inv = run_dir / "investigation.md"
    inv_text = (GOLDEN / "investigation.md").read_text()
    addendum_block = "\n## ADDENDUM\n\nnoted.\n"
    expected = inv_text + addendum_block

    replay = ReplayFn([
        Turn(tool_calls=[("append_block", {"text": inv_text})]),
        Turn(tool_calls=[("append_block", {"text": addendum_block})]),
        *tail_turns(run_dir, 15),
        Turn(text="never reached"),
    ])
    summary = drive(run_dir, run_id="between", main=replay,
                    limits=caps(max_tool_calls=1, wall_clock_timeout=3600,
                                grace_seconds=600))

    assert inv.read_text() == expected, "a completed prior write was lost by the kill"
    assert summary["truncated_by"] == "budget"
    assert (run_dir / "tool_trace.jsonl").is_file()


def test_main_and_gather_share_one_budget(tmp_path, unenforced):
    """MAIN and every GATHER subagent increment the ONE budget on the run's `RunState`, so the caps bound the..."""
    recorder = VerbRecorder()

    def esql(ctx, *, index: str) -> dict:
        recorder.record("esql", ctx, {"index": index})
        return {"rows": []}

    verbs = FakeVerbs({"elastic": {"esql": esql}})
    run_dir = materialize(tmp_path, GOLDEN, run_id='pool')
    gather = ReplayFn([
        Turn(tool_calls=[("query", {"system": "elastic", "verb": "esql",
                                    "params": {"index": "logs"},
                                    "query_id": "elastic.probe"})]),
        Turn(text="PARTIAL SUMMARY"),
    ])
    summary = drive(run_dir, run_id="pool",
          main=ReplayFn([
              Turn(tool_calls=[("bash", {"command": "echo hi"})]),
              Turn(tool_calls=[("gather", {"lead_id": "l-001", "system": "elastic",
                                           "goal": "g", "what_to_summarize": ["w"]})]),
              Turn(text="done"),
          ]),
          gather=gather, verbs=verbs, limits=caps())

    assert not list(run_dir.glob("**/budget.json"))
    state = budget(summary)
    assert state["subagent_spawns"] == 2, "the pool: the correlation lead (#1222) plus the one lead"
    assert state["tool_calls"] >= 3, (
        f"the gather subagent's own query did not spend the shared pool: {state}"
    )
    assert recorder.verbs == ["esql"]


def test_accounting_runs_regardless_of_posture(tmp_path, monkeypatch, capsys):
    """Counter increments AND stderr warnings happen on every tool call that ACTUALLY EXECUTES, whether or not..."""
    def script():
        return ReplayFn([*[Turn(tool_calls=[("bash", {"command": f"echo {i}"})])
                           for i in range(3)], Turn(text="done")])
    states, warned = {}, {}
    for posture in ("off", "on"):
        if posture == "on":
            monkeypatch.setenv(FLAG, "true")
        else:
            monkeypatch.delenv(FLAG, raising=False)
        rd = materialize(tmp_path / posture, GOLDEN, run_id=posture)
        states[posture] = budget(drive(rd, run_id=posture, main=script(),
                                       limits=caps(max_tool_calls=4)))
        warned[posture] = "Budget warning" in capsys.readouterr().err

    assert states["off"]["tool_calls"] == states["on"]["tool_calls"] == 3
    _both_warned = "the 75% warning did not fire under both postures — accounting is gated on posture"
    assert warned["off"], _both_warned
    assert warned["on"], _both_warned


def test_flag_off_leaves_run_unenforced(tmp_path, unenforced, capsys):
    """With the flag off, a run that crosses every cap observes no refusal and no kill — only the existing stderr..."""
    run_dir = materialize(tmp_path, GOLDEN, run_id='off')
    replay = ReplayFn([
        Turn(tool_calls=[("bash", {"command": "echo hi"})]),
        Turn(tool_calls=[("bash", {"command": "echo again"})]),
        Turn(text="done"),
    ])
    summary = drive(run_dir, run_id="off", main=replay,
                    limits=caps(max_tool_calls=1, wall_clock_timeout=3600,
                                grace_seconds=600))
    err = capsys.readouterr().err

    assert refusal_stem() not in "\n".join(replay.seen), "an unenforced run was refused"
    assert summary["truncated_by"] is None
    assert budget(summary)["tool_calls"] == 2, "the crossed cap stopped the accounting"
    assert "Budget exceeded" in err, "the warning-only behaviour was lost"


def test_refused_gather_and_the_spawn_counter(tmp_path, enforced):
    """A budget-refused `gather` call never dispatches a subagent, and the refusal still reaches the accounting..."""
    verbs = FakeVerbs({"elastic": {"esql": lambda ctx, *, index: {"rows": []}}})
    run_dir = materialize(tmp_path, GOLDEN, run_id='spawn')
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
    summary = drive(run_dir, run_id="spawn", main=replay, gather=gather, verbs=verbs,
          limits=caps(max_subagent_spawns=2, max_tool_calls=500,  # l-00c takes the first
                      wall_clock_timeout=3600, grace_seconds=600))

    assert budget(summary)["subagent_spawns"] == 2, (  # the correlation lead plus l-001
        "a refused gather was charged to the spawn counter"
    )
    assert (run_dir / "gather_raw" / "l-001.lead.json").exists(), (
        "the admitted gather did not claim its lead id"
    )
    assert not (run_dir / "gather_raw" / "l-002.lead.json").exists(), (
        "the first refused gather claimed a lead id"
    )
    assert not (run_dir / "gather_raw" / "l-003.lead.json").exists(), (
        "a refused gather claimed a lead id"
    )


def test_subagent_dispatched_into_an_already_stopped_pool(tmp_path, enforced):
    """A gather dispatched into an already-tripped pool is refused at MAIN's own tool_execute seam — `gather` is..."""
    recorder = VerbRecorder()

    def esql(ctx, *, index: str) -> dict:
        recorder.record("esql", ctx, {"index": index})
        return {"rows": [1]}

    verbs = FakeVerbs({"elastic": {"esql": esql}})
    run_dir = materialize(tmp_path, GOLDEN, run_id='stopped')
    limits = caps(max_tool_calls=1, wall_clock_timeout=3600, grace_seconds=600)

    gather = ReplayFn([
        Turn(tool_calls=[("query", {"system": "elastic", "verb": "esql",
                                    "params": {"index": "logs"},
                                    "query_id": "elastic.probe"})]),
        Turn(text="PARTIAL SUMMARY: refused before any result"),
    ])
    # The pool is spent to its cap INSIDE the run, by MAIN's own executed bash (#1235 round 2:
    # the driver starts the run's state, so nothing seeded before `drive` can reach it).
    main = ReplayFn([
        Turn(tool_calls=[("bash", {"command": "echo spend the pool"})]),
        Turn(tool_calls=[("gather", {"lead_id": "l-001", "system": "elastic",
                                     "goal": "g", "what_to_summarize": ["w"]})]),
        Turn(text="done"),
    ])
    summary = drive(run_dir, run_id="stopped", main=main, gather=gather, verbs=verbs,
                    limits=limits)

    assert budget(summary)["tool_calls"] == 1, (
        "the pool was not at its cap when the gather was dispatched, so nothing is observed")
    assert gather.calls == 0, "the subagent's model was invoked on an already-stopped pool"
    assert recorder.calls == [], "the subagent did work inside an already-stopped pool"
    assert own_rows(run_dir) == [], (
        "the subagent wrote a queries row into an already-stopped pool"
    )
    assert refusal_stem() in "\n".join(main.seen), (
        "MAIN did not observe the gather dispatch being refused"
    )


def test_stopped_query_writes_no_row(tmp_path, enforced):
    """A query stopped by the budget writes NO row into the queries table — `_make_hooks` is prepended ahead of..."""
    recorder = VerbRecorder()

    def esql(ctx, *, index: str) -> dict:
        recorder.record("esql", ctx, {"index": index})
        return {"rows": [1]}

    verbs = FakeVerbs({"elastic": {"esql": esql}})
    run_dir = materialize(tmp_path, GOLDEN, run_id='phantom')
    gather = ReplayFn([
        Turn(tool_calls=[("query", {"system": "elastic", "verb": "esql",
                                    "params": {"index": "logs"},
                                    "query_id": "elastic.probe"})]),
        Turn(tool_calls=[("query", {"system": "elastic", "verb": "esql",
                                    "params": {"index": "logs2"},
                                    "query_id": "elastic.probe2"})]),
        Turn(text="done"),
    ])
    drive(run_dir, run_id="phantom",
          main=ReplayFn([
              Turn(tool_calls=[("gather", {"lead_id": "l-001", "system": "elastic",
                                           "goal": "g", "what_to_summarize": ["w"]})]),
              Turn(text="done"),
          ]),
          gather=gather,
          verbs=verbs, limits=caps(max_tool_calls=2, wall_clock_timeout=3600,  # l-00c spends one
                                   grace_seconds=600))

    assert gather.calls >= 1, "the subagent never ran, so the ordering was not exercised"
    assert recorder.verbs == ["esql"], "the stopped query's handler ran (no short-circuit)"
    rows = own_rows(run_dir)
    assert len(rows) == 1, (
        f"the stopped query wrote a phantom row — {len(rows)} rows for 1 executed query"
    )
    refusals = [r for r in read_jsonl_rows(RunPaths(run_dir).wire_log)
                if r.get("kind") == "budget_refusal" and r.get("tool_name") == "query"]
    assert refusals, "the stopped query reached the seam but left no record at all"


def test_executed_query_writes_a_row(tmp_path, unenforced):
    """A query that actually executes under the same harness DOES write its queries-table row and its by-ref..."""
    recorder = VerbRecorder()

    def esql(ctx, *, index: str) -> dict:
        recorder.record("esql", ctx, {"index": index})
        return {"rows": [1]}

    verbs = FakeVerbs({"elastic": {"esql": esql}})
    run_dir = materialize(tmp_path, GOLDEN, run_id='row')
    drive(run_dir, run_id="row",
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

    rows = own_rows(run_dir)
    assert len(rows) == 1
    assert rows[0]["lead_id"] == "l-001"
    assert rows[0]["system"] == "elastic"
    assert recorder.only().params == {"index": "logs"}


def test_gather_abort_becomes_measurement_string(tmp_path, enforced):
    """A gather subagent that runs into its own request limit is converted to the measurement-shaped string, so..."""
    verbs = FakeVerbs({"elastic": {"esql": lambda ctx, *, index: {"rows": []}}})
    query_turn = Turn(tool_calls=[("query", {"system": "elastic", "verb": "esql",
                                             "params": {"index": "logs"},
                                             "query_id": "elastic.probe"})])
    distinct_query_turns = [
        Turn(tool_calls=[("query", {"system": "elastic", "verb": "esql",
                                    "params": {"index": f"logs-{i}"},
                                    "query_id": "elastic.probe"})])
        for i in range(200)
    ]

    run_dir = materialize(tmp_path / "limit", GOLDEN, run_id='limit')
    main = ReplayFn([
        Turn(tool_calls=[("gather", {"lead_id": "l-001", "system": "elastic",
                                     "goal": "g", "what_to_summarize": ["w"]})]),
        Turn(text="done"),
    ])
    drive(run_dir, run_id="limit", main=main,
          gather=ReplayFn(distinct_query_turns), verbs=verbs, limits=caps())
    assert "reached its request limit" in "\n".join(main.seen)
    assert "Treat this lead as incomplete" in "\n".join(main.seen)

    other = materialize(tmp_path / "refused", GOLDEN, run_id='gref')
    main_b = ReplayFn([
        Turn(tool_calls=[("gather", {"lead_id": "l-001", "system": "elastic",
                                     "goal": "g", "what_to_summarize": ["w"]})]),
        Turn(text="done"),
    ])
    gather_b = ReplayFn([
        query_turn,
        Turn(tool_calls=[("query", {"system": "elastic", "verb": "esql",
                                    "params": {"index": "logs2"},
                                    "query_id": "elastic.probe2"})]),
        Turn(text="PARTIAL SUMMARY: refused"),
    ])
    drive(other, run_id="gref", main=main_b, gather=gather_b, verbs=verbs,
          limits=caps(max_tool_calls=2, wall_clock_timeout=3600, grace_seconds=600))  # l-00c spends one
    assert gather_b.calls >= 2, "the subagent did not keep working past the refusal"
    history = "\n".join(main_b.seen)
    assert "PARTIAL SUMMARY: refused" in history
    assert "reached its request limit" not in history, (
        "a budget refusal was converted into the measurement string — the wrong path"
    )


def test_gather_has_no_per_call_timeout(tmp_path, unenforced):
    """No per-call wall clock is imposed on a gather dispatch: a lead whose work runs well past any short..."""
    def slow(ctx, *, index: str) -> dict:
        import time
        time.sleep(1.5)
        return {"rows": [1]}

    verbs = FakeVerbs({"elastic": {"esql": slow}})
    run_dir = materialize(tmp_path, GOLDEN, run_id='slow')
    main = ReplayFn([
        Turn(tool_calls=[("gather", {"lead_id": "l-001", "system": "elastic",
                                     "goal": "g", "what_to_summarize": ["w"]})]),
        Turn(text="done"),
    ])
    drive(run_dir, run_id="slow", main=main,
          gather=ReplayFn([
              Turn(tool_calls=[("query", {"system": "elastic", "verb": "esql",
                                          "params": {"index": "logs"},
                                          "query_id": "elastic.probe"})]),
              Turn(text="finished after a long call"),
          ]),
          verbs=verbs, limits=caps())

    assert "finished after a long call" in "\n".join(main.seen)
    rows = own_rows(run_dir)
    assert rows, "the completed call wrote no queries row"
    assert rows[0]["exit_code"] == 0, (
        "a per-call stopwatch synthesized a timeout row for a call that completed"
    )
