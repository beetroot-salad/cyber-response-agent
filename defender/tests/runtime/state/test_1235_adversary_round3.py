"""#1235 round 3 adversary holes: lead-0 gate clock agreement, enforced roles without run state
raise, stored rows are handed out uncopied, state mismatch refused."""
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
from defender.investigation import driver, observe  # noqa: E402
from defender.investigation.agent_definition import bind, effective_tools_for  # noqa: E402
from defender.execution.box_codec import BoxResult  # noqa: E402
from defender.investigation.driver import MAIN_DEF  # noqa: E402
from defender.providers import BuiltModel  # noqa: E402
from defender.investigation.run_state import RunState  # noqa: E402
from defender.tests.support.tenancy import _tenants1106 as T1106
from defender.tests.support.runtime.state._1255_view import model_path  # noqa: E402
from defender.tests.support.shared._fixture_uuid import fixture_uuid  # noqa: E402
from defender.tests.e2e._spec771 import DEFENDER  # noqa: E402
from defender.tests.sandbox.test_959_downstream import Box  # noqa: E402
from defender.tests.runtime.state.test_1235_round3 import (  # noqa: E402
    _append,
    _bare_run,
    _clocked,
    _hook_kills,
    _lead_zero_kills,
)
from defender.tests.runtime.engine.test_budget_seams_631 import ScriptedModel, _run_dir, drive_agent  # noqa: E402

LEAD = "l-001"


@pytest.mark.parametrize(("wall_back", "mono_back", "credited", "open_for", "killed"), [
    pytest.param(1000, 1000, 0, 990, False, id="an-oracle-turn-open-now"),
])
def test_lead_zeros_gate_agrees_with_the_hooks_on_the_rest_of_the_clock(
        tmp_path, wall_back, mono_back, credited, open_for, killed):
    """O3."""
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


_LIMITS = {**DEFAULT_LIMITS, "max_tool_calls": 50, "wall_clock_timeout": 3600,
           "grace_seconds": 600}


def test_an_enforced_gather_whose_deps_carry_no_state_raises(tmp_path):
    """O2."""
    run_dir = _run_dir(tmp_path, "adv3-o2-gather")
    script = [[("read_file", {"path": model_path(run_dir / "alert.json", run_dir=run_dir)})]]
    with pytest.raises(TypeError, match="RunState"):
        drive_agent(T1106.fixture_gather_def(), run_dir, script, limits=_LIMITS, enforce=True,
                    agent_id="gather:l-001", state=None)

    carried = RunState(run_dir, "adv3-o2-gather")
    drive_agent(T1106.fixture_gather_def(), run_dir, script, limits=_LIMITS, enforce=True,
                agent_id="gather:l-001", state=carried)
    assert carried.budget_snapshot()["tool_calls"] == 1


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
    """O2."""
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


def test_lead_rows_hands_out_the_stored_rows_not_copies(tmp_path):
    """O7."""
    _run, state = _bare_run(tmp_path)
    _append(state, params={"q": "a"})
    _append(state, params={"q": "b"})
    first, second = state.lead_rows(LEAD), state.lead_rows(LEAD)
    assert all(a is b for a, b in zip(first, second, strict=True)), \
        "lead_rows copied each row on every read"


def _store_down(case_id: str, run_dir: Path):  # noqa: ARG001
    raise OSError("adv3: no store")


@pytest.mark.parametrize("other", ["folder", "run-id"])
def test_a_mismatched_state_is_refused_even_when_the_store_cannot_open(tmp_path, other):
    """O6."""
    from defender.records import session_store
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
    """O6, production's path (`run.py` hands no state)."""
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
