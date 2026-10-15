"""#1235 round 3 — the holes the third adversary pass found in the round-3 suite.

Each test greens on an honest round-3 implementation and goes red under one cheating
implementation the round-3 tests let through:

  O3 — lead-0's gate reads only the monotonic delta: the wall clock ahead of the
      monotonic one (a suspend, a forward step) is spent for the hooks, fresh for lead-0.
  O3 — lead-0's gate credits only CLOSED oracle turns: an oracle turn open now holds
      the world for the hooks (`oracle_held`), not for lead-0.
  O2 — the raise keyed on MAIN only: GATHER is budget-enforced too, and its deps with
      no state must raise, not run unbudgeted.
  O2 — the raise placed after the handler: an enforced role with no state must raise
      BEFORE its first call executes ("not counted, not refused, raised"), not after the call
      reached the box.
  O6 — the boundary check placed after store setup: a mismatched state handed to a
      run whose store cannot open is a ValueError, never the store exit's summary.
  O7 — `lead_rows` still deep-copying: it hands out the stored rows themselves.
  O6 — production's path resolving a second state for lead-0: the run handed no state
      carries ONE object to lead-0's verb context and to the gather lead's.
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import replace
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from pydantic_ai import Agent  # noqa: E402
from pydantic_ai.models import override_allow_model_requests  # noqa: E402
from pydantic_ai.models.function import FunctionModel  # noqa: E402
from pydantic_ai.usage import UsageLimits  # noqa: E402

from defender.hooks.budget_enforcer import DEFAULT_LIMITS  # noqa: E402
from defender.runtime import driver, observe  # noqa: E402
from defender.runtime.agent_definition import bind, effective_tools_for  # noqa: E402
from defender.runtime.box_codec import BoxResult  # noqa: E402
from defender.runtime.driver import MAIN_DEF  # noqa: E402
from defender.runtime.providers import BuiltModel  # noqa: E402
from defender.runtime.run_state import RunState  # noqa: E402
from defender.tests import _tenants1106 as T1106  # noqa: E402
from defender.tests._fixture_uuid import fixture_uuid  # noqa: E402
from defender.tests.e2e._spec771 import DEFENDER  # noqa: E402
from defender.tests.test_959_downstream import Box  # noqa: E402
from defender.tests.test_1235_round3 import (  # noqa: E402
    _append,
    _bare_run,
    _clocked,
    _hook_kills,
    _lead_zero_kills,
)
from defender.tests.test_budget_seams_631 import ScriptedModel, _run_dir, drive_agent  # noqa: E402

LEAD = "l-001"


# ======================================================================================
# O3: lead-0's gate and the hooks agree where the wall clock leads, and while an
# oracle turn is open.
# ======================================================================================

@pytest.mark.parametrize(("wall_back", "mono_back", "credited", "open_for", "killed"), [
    pytest.param(1000, 0, 0, None, True, id="wall-clock-ahead-of-the-monotonic"),
    pytest.param(1000, 1000, 0, 990, False, id="an-oracle-turn-open-now"),
])
def test_lead_zeros_gate_agrees_with_the_hooks_on_the_rest_of_the_clock(
        tmp_path, wall_back, mono_back, credited, open_for, killed):
    """O3: "the larger of the wall-clock and monotonic deltas, less the seconds an oracle turn
    held the world" — the hooks' clock (`_budget_state_for_enforcement`: `oracle_held`, which
    counts the turn open NOW as well as the closed ones).

      * wall ahead: 1000s on the wall clock, ~0 on the monotonic one. The hooks take the larger
        and kill; a gate reading only the monotonic delta lets lead-0 issue a backend call.
      * open turn: 1000s raw, an oracle turn open for the last 990 of them. The hooks hold the
        world and let the run continue; a gate reading only `oracle_credited` (closed turns)
        kills lead-0's call.

    The upstream four-case table (`test_lead_zeros_budget_gate_agrees_with_the_hooks…`) moves
    both clocks together and credits only closed turns, so it greens either cut corner."""
    run_dir = _run_dir(tmp_path, "adv3-o3")
    state = _clocked(run_dir, wall_back=wall_back, mono_back=mono_back, credited=credited)
    if open_for is not None:
        with state.lock:
            state.oracle_opened = time.monotonic() - open_for
    hook = _hook_kills(run_dir, state)
    assert hook is killed, f"the scenario no longer exercises the hooks' clock (hook={hook})"
    assert _lead_zero_kills(state) is hook, (
        "lead-0's budget gate disagrees with the budget hooks on the run's clock: "
        f"hooks kill={hook}, lead-0 kill={not hook}")


# ======================================================================================
# O2: GATHER is enforced too.
# ======================================================================================

_LIMITS = {**DEFAULT_LIMITS, "max_tool_calls": 50, "wall_clock_timeout": 3600,
           "grace_seconds": 600}


def test_an_enforced_gather_whose_deps_carry_no_state_raises(tmp_path):
    """O2: "MAIN and GATHER are `budget_enforced` … deps with no run state raise TypeError on
    the first tool call". The upstream raise test drives MAIN only; a raise keyed on MAIN's role
    leaves an enforced gather lead running unbudgeted.

    Positive control, same def and posture: carried, the call is counted."""
    run_dir = _run_dir(tmp_path, "adv3-o2-gather")
    script = [[("read_file", {"path": str(run_dir / "alert.json")})]]
    with pytest.raises(TypeError, match="RunState"):
        drive_agent(T1106.fixture_gather_def(), run_dir, script, limits=_LIMITS, enforce=True,
                    agent_id="gather:l-001", state=None)

    carried = RunState(run_dir, "adv3-o2-gather")
    drive_agent(T1106.fixture_gather_def(), run_dir, script, limits=_LIMITS, enforce=True,
                agent_id="gather:l-001", state=carried)
    assert carried.budget_snapshot()["tool_calls"] == 1


# ======================================================================================
# O2: the raise precedes the call.
# ======================================================================================

def _drive_with_box(defn, run_dir: Path, turns, *, limits, enforce: bool, state, box):
    """`test_budget_seams_631.drive_agent`, with the box injected so the test sees whether the
    call reached it."""
    model = ScriptedModel(turns)
    logger = observe.RequestLogger(run_dir / "llm_requests.jsonl")
    defn = replace(defn, budget_enforced=enforce)
    agent: Agent = driver.build_agent_core(
        defn, deps_type=defn.deps_cls, instructions="probe", logger=logger, agent_id="main",
        make_model=lambda name, effort: BuiltModel(FunctionModel(model), None), limits=limits)
    bindable = replace(defn, tools=effective_tools_for(defn))
    deps = replace(bind(bindable, run_dir, defender_dir=DEFENDER, box=box), run_state=state)

    async def _go():
        with override_allow_model_requests(False):
            return await agent.run("go", deps=deps, usage_limits=UsageLimits(request_limit=10))

    try:
        return asyncio.run(_go())
    finally:
        logger.close()


def test_an_enforced_role_with_no_state_raises_before_its_first_call_runs(tmp_path):
    """O2: "deps with no run state raise TypeError … on the first tool call — not counted, not
    refused, raised"; the upstream test's own words: round 2 "ran an enforced role with no
    budget at all". A raise placed in the post-call accounting (the call executes, THEN the
    hook raises) satisfies `pytest.raises(TypeError)` and the untouched live count, while the
    enforced role's first call ran with no budget behind it.

    Positive control, same box and script: carried, the call reaches the box once."""
    run_dir = _run_dir(tmp_path, "adv3-o2-before")
    script = [[("bash", {"command": "echo o2"})]]
    box = Box(BoxResult(0, b"o2\n", b""))
    with pytest.raises(TypeError, match="RunState"):
        _drive_with_box(MAIN_DEF, run_dir, script, limits=_LIMITS, enforce=True, state=None,
                        box=box)
    assert box.calls == [], "an enforced role with no run state ran its call before raising"

    _drive_with_box(MAIN_DEF, run_dir, script, limits=_LIMITS, enforce=True,
                    state=RunState(run_dir, "adv3-o2-before"), box=box)
    assert len(box.calls) == 1, "the control: the carried call never reached the box"


# ======================================================================================
# O7: lead_rows hands out the stored rows, no copy.
# ======================================================================================

def test_lead_rows_hands_out_the_stored_rows_not_copies(tmp_path):
    """O7: "`RunState.lead_rows` will stop deep-copying: it returns a tuple of the stored rows
    (read-only use)"; the upstream test's docstring: "no copy of each row". Its assertions
    (a tuple, unchanged by a later append, equal to the view) green a `tuple(deepcopy(…))`.

    Two reads hand out the same row objects."""
    _run, state = _bare_run(tmp_path)
    _append(state, params={"q": "a"})
    _append(state, params={"q": "b"})
    first, second = state.lead_rows(LEAD), state.lead_rows(LEAD)
    assert all(a is b for a, b in zip(first, second, strict=True)), \
        "lead_rows copied each row on every read"


# ======================================================================================
# O6: the boundary is the boundary, on both of its branches.
# ======================================================================================

def _store_down(case_id: str, run_dir: Path):  # noqa: ARG001
    raise OSError("adv3: no store")


@pytest.mark.parametrize("other", ["folder", "run-id"])
def test_a_mismatched_state_is_refused_even_when_the_store_cannot_open(tmp_path, other):
    """O6: "when given, its run_dir/run_id must match the run's or it raises ValueError" —
    resolved "once at the boundary". The upstream mismatch test drives a run whose store opens
    and whose lead-0 makes no call, so a check placed anywhere before MAIN's agent is built
    greens it: after store setup, after lead-0, after the correlation dispatch. With the store
    down, a check placed after store setup is never reached — the run returns the store exit's
    summary over another run's state instead of refusing it.

    Positive control: the same store-down run handed its own state ends through the store exit."""
    from defender.runtime import session_store
    from defender.tests.e2e._replay_harness import GOLDEN_AB3, ReplayFn, Turn, driver_summary, materialize

    run_dir = materialize(tmp_path / "run", GOLDEN_AB3, run_id='adv3-k5')
    elsewhere = tmp_path / "elsewhere" / run_dir.name
    elsewhere.mkdir(parents=True)
    stranger = (RunState(elsewhere, run_dir.name) if other == "folder"
                else RunState(run_dir, fixture_uuid("adv3-someone-else")))
    with pytest.raises(ValueError):  # noqa: PT011 — the wording is the implementation's
        driver_summary(run_dir, run_id="adv3-k5", main=ReplayFn([Turn(text="done")]),
                       store_factory=_store_down, run_state=stranger)

    own_dir = materialize(tmp_path / "own", GOLDEN_AB3, run_id='adv3-k5-own')
    cut = driver_summary(own_dir, run_id="adv3-k5-own", main=ReplayFn([Turn(text="done")]),
                         store_factory=_store_down, run_state=RunState(own_dir, own_dir.name))
    assert cut["truncated_by"] == session_store.TRUNCATED_BY_STORE, cut


def test_production_path_carries_one_state_to_lead_zero_and_the_gather_lead(tmp_path):
    """O6, production's path (`run.py` hands no state): "resolved once at the boundary to
    `RunState(run_dir, run_id)`". `drive()` always injects a state, so every other driven test
    exercises only the injected branch; the upstream no-state test watches the gather lead's
    verb contexts alone. A run that resolves lead-0's state separately (a second
    `RunState(run_dir, run_id)` for `_opening_prompt` when handed none) splits lead-0's counts,
    rows and breaker charges off the run's — and greens that test.

    Here lead-0's item-1 calls and the gather lead's call each record the verb context they
    were handed: every one carries the same object, and it holds both leads' rows.

    Positive control: lead-0 did call (its fetch is recorded) and so did the gather lead."""
    from defender.tests.e2e import _lead_zero_808 as LZ
    from defender.tests.e2e._replay_harness import ReplayFn, Turn, driver_summary
    from defender.tests.e2e.test_query_tool_611 import DONE, q

    doc = LZ.alert_doc()
    run_dir = LZ.materialize_alert(tmp_path, doc)
    rec = LZ.VerbRecorder()
    verbs = LZ.elastic_backend(rec, LZ.answer_hits([]),
                               signal_index=doc.get("signal_index", LZ.ALERTS_INDEX))
    main = ReplayFn([
        Turn(tool_calls=[("gather", {
            "lead_id": LEAD, "system": "elastic", "goal": "measure this lead",
            "what_to_summarize": ["host inventory"]})]),
        Turn(text="Investigation complete."),
    ])
    gather = ReplayFn([q("elastic", "alerts", {"native_query": "corr:adv3-k7"}), DONE,
                       q("elastic", "query", {"native_query": "FROM adv3-k7"}), DONE])
    gather.serves_correlation = True
    summary = driver_summary(run_dir, run_id="adv3-k7", main=main, gather=gather, verbs=verbs)
    assert "run_state" not in summary

    mine = [c for c in rec.calls if c.params.get("native_query") == "FROM adv3-k7"]
    lead_zero = [c for c in rec.calls if c not in mine]
    assert mine, f"the gather lead's call was never made: {rec.verbs}"
    assert lead_zero, f"lead-0 made no call, so nothing is observed: {rec.verbs}"
    state = mine[0].ctx.run_state
    assert isinstance(state, RunState)
    assert all(c.ctx.run_state is state for c in lead_zero), \
        "lead-0's verb contexts carried a state other than the run's"
    assert state.row_count("l-00c") >= 1, "the run's state does not hold lead-0's rows"
    assert state.row_count(LEAD) == 1, "the run's state does not hold the gather lead's row"
