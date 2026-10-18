"""#1235 round 3 at the unit edge: the run state is the record (a refused view write still charges
the breaker), missing state fails closed for enforced roles, lead-0 reads the run's clock."""
from __future__ import annotations

from dataclasses import replace as _with_live_run_1165
from defender.tests._spec1077 import fixture_run as _live_run_1165

from defender.tests._spec1077 import fixture_run

import asyncio
import dataclasses
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from defender.tests._1255_view import model_path

pytest.importorskip("pydantic_ai")

from defender._io import read_jsonl_rows  # noqa: E402
from defender._query_rules import BASH_SHIM_QUERY_ID  # noqa: E402
from defender.hooks.budget_enforcer import DEFAULT_LIMITS, BudgetKill  # noqa: E402
from defender.run_repository import RunPaths  # noqa: E402
from defender.runtime import circuit_breaker as cb  # noqa: E402
from defender.runtime.agent_definition import bind  # noqa: E402
from defender.runtime.box_codec import BoxResult  # noqa: E402
from defender.runtime.driver import MAIN_DEF  # noqa: E402
from defender.runtime.query_tool import QueryCapture  # noqa: E402
from defender.runtime.run_state import RunState  # noqa: E402
from defender.runtime.tools import _tool_bash  # noqa: E402
from defender.scripts.gather_tools import record_query as rq  # noqa: E402
from defender.tests import _tenants1106  # noqa: E402
from defender.tests.e2e._spec771 import DEFENDER  # noqa: E402
from defender.tests.test_959_downstream import Box, _gather_scene  # noqa: E402
from defender.tests.test_budget_seams_631 import _run_dir, drive_agent  # noqa: E402

LEAD = "l-001"
_PAYLOAD = '{"total": 1, "hits": ["web-1"]}'


def _bare_run(root: Path, name: str = "run") -> tuple[Path, RunState]:
    run_dir = root / name
    RunPaths(run_dir).gather_raw.mkdir(parents=True)
    return run_dir, RunState(run_dir, name)


def _append(state: RunState, *, params: dict, lead: str = LEAD) -> dict:
    """One executed row through the production writer."""
    return rq.append_query_row(
        state, run=fixture_run(state.run_dir), lead_id=lead, system="elastic", verb="query", query_id="elastic.probe",
        params=params, raw_command="elastic query", payload_text=_PAYLOAD, exit_code=0,
        payload_status="ok", payload_digest=rq.payload_digest(_PAYLOAD, "", 0), system_key="")


def _failures(state: RunState, system: str) -> int:
    """`system`'s charged failures, read off the breaker snapshot (the O1 cases read it this
    way so a failure there names O1, not the new accessor O7 adds)."""
    rec = state.breaker_snapshot()["systems"].get(system)
    return rec["failures"] if rec else 0


def _table_rows(run_dir: Path, lead: str = LEAD) -> list[dict]:
    return [r for r in read_jsonl_rows(RunPaths(run_dir).executed_queries)
            if r.get("lead_id") == lead]


# ======================================================================================
# O1 — a failing call is charged and recorded whether or not its view could be written.
# ======================================================================================

def _gather_deps(run_dir: Path, state: RunState):
    return dataclasses.replace(
        _with_live_run_1165(bind(_tenants1106.fixture_gather_def(), run_dir, defender_dir=DEFENDER), run=_live_run_1165(run_dir)),
        lead_id=LEAD, run_state=state)


def _record_failure(deps, *, params: dict) -> tuple[dict, str]:
    """One backend call that failed on the transport (exit 2: an infra failure the breaker
    charges), recorded through the query tool's own recorder."""
    return asyncio.run(QueryCapture(registry=None)._record(
        deps, system="elastic", verb="search", query_id="elastic.ad-hoc", params=params,
        payload=None, exit_code=2, detail="connection refused", system_key=""))


@pytest.mark.parametrize("kind", ["symlink", "directory"])
def test_a_failing_call_whose_view_write_is_refused_is_still_charged_and_recorded(
        tmp_path, kind):
    """O1 at the query tool's recorder."""
    run_dir = tmp_path / "run"
    RunPaths(run_dir).gather_raw.mkdir(parents=True)
    state = RunState(run_dir, "r3-o1")
    deps = _gather_deps(run_dir, state)
    table = RunPaths(run_dir).executed_queries
    outside = tmp_path / "outside.jsonl"
    outside.write_bytes(b"")
    if kind == "symlink":
        table.symlink_to(outside)
    else:
        table.mkdir()

    with pytest.raises(OSError):  # noqa: PT011 — the symlink and the directory refuse in their own words
        _record_failure(deps, params={"q": "a"})
    assert _failures(state, "elastic") == 1, \
        "a failing call whose view write was refused was not charged to its system"
    assert [(r["seq"], r["exit_code"], r["params"]) for r in state.lead_rows(LEAD)] == \
        [(0, 2, {"q": "a"})], "a failing call whose view write was refused left no row"
    assert outside.read_bytes() == b"", "the view write followed the planted link"

    if kind == "symlink":
        table.unlink()
    else:
        table.rmdir()
    row, _text = _record_failure(deps, params={"q": "b"})
    assert row["seq"] == 1, "the recorded row's seq was handed out again"
    assert _failures(state, "elastic") == 2
    assert [(r["seq"], r["params"]) for r in state.lead_rows(LEAD)] == \
        [(0, {"q": "a"}), (1, {"q": "b"})]
    assert [r["seq"] for r in _table_rows(run_dir)] == [1], \
        "the view holds a line other than the one write that landed"


def test_a_succeeding_call_whose_view_write_is_refused_charges_nothing(tmp_path):
    """The charge O1 keeps is the failure's, not a side effect of the refused write: a call that
    SUCCEEDED (exit 0) while the view is squatted is in the state, the write's error propagates,
    and the breaker is untouched."""
    run_dir = tmp_path / "run"
    RunPaths(run_dir).gather_raw.mkdir(parents=True)
    state = RunState(run_dir, "r3-o1-ok")
    deps = _gather_deps(run_dir, state)
    RunPaths(run_dir).executed_queries.mkdir()

    with pytest.raises(OSError):  # noqa: PT011 — the directory refuses in its own words
        asyncio.run(QueryCapture(registry=None)._record(
            deps, system="elastic", verb="search", query_id="elastic.ad-hoc", params={"q": "a"},
            payload=[{"a": 1}], exit_code=0, detail="", system_key=""))
    assert [(r["seq"], r["exit_code"]) for r in state.lead_rows(LEAD)] == [(0, 0)], \
        "a succeeding call whose view write was refused left no row"
    assert state.breaker_snapshot() == {"systems": {}, "total_failures": 0}, \
        "a succeeding call was charged because its view write failed"


# ======================================================================================
# O2 — a non-enforced role with no run state neither counts nor raises (the enforced role's
# raise is `test_1235_adversary_round2.py`'s).
# ======================================================================================

_LIMITS = {**DEFAULT_LIMITS, "max_tool_calls": 50, "wall_clock_timeout": 3600,
           "grace_seconds": 600}
_ECHO = [[("bash", {"command": "echo o2"})]]


def test_a_non_enforced_role_whose_deps_carry_no_state_neither_counts_nor_raises(tmp_path):
    """O2's other posture."""
    run_dir = _run_dir(tmp_path, "o2-open")
    result, _ = drive_agent(MAIN_DEF, run_dir, _ECHO, limits=_LIMITS, enforce=False, state=None)
    returned = [str(part.content) for message in result.all_messages()
                for part in getattr(message, "parts", ()) if part.part_kind == "tool-return"]
    assert len(returned) == 1, f"the unenforced call did not run: {returned}"
    assert "o2" in returned[0], f"the unenforced call did not run: {returned}"

    carried = RunState(run_dir, "o2-open-carried")
    drive_agent(MAIN_DEF, run_dir, _ECHO, limits=_LIMITS, enforce=False, state=carried)
    assert carried.budget_snapshot()["tool_calls"] == 1, \
        "the control: an unenforced role carrying a state did not count its call"


# ======================================================================================
# O3 — lead-0's budget gate reads the clock the budget hooks read.
# ======================================================================================

#: The tail sits at `wall_clock_timeout + grace_seconds` = 120s of investigator time.
_CLOCK_LIMITS = {**DEFAULT_LIMITS, "max_tool_calls": 100, "wall_clock_timeout": 60,
                 "grace_seconds": 60}


def _clocked(run_dir: Path, *, wall_back: float, mono_back: float, credited: float) -> RunState:
    """A run's state whose clock reads as given."""
    state = RunState(run_dir, "r3-clock")
    with state.lock:
        origin = (datetime.now(UTC) - timedelta(seconds=wall_back)).isoformat()
        state.budget["created_at"] = state.budget["started_at"] = origin
        state.started_monotonic -= mono_back
        state.oracle_credited = credited
    return state


def _lead_zero_kills(state: RunState) -> bool:
    from defender.hooks.budget_enforcer import enforcement_state, tail_exhausted
    return tail_exhausted(enforcement_state(state), _CLOCK_LIMITS)


def _hook_kills(run_dir: Path, state: RunState) -> bool:
    """The budget hooks' verdict on `state`: MAIN's enforced hook on one bash call."""
    try:
        drive_agent(MAIN_DEF, run_dir, _ECHO, limits=_CLOCK_LIMITS, enforce=True, state=state)
    except BudgetKill:
        return True
    return False


@pytest.mark.parametrize(("wall_back", "mono_back", "credited", "killed"), [
    pytest.param(0, 0, 0, False, id="fresh"),
    pytest.param(1000, 1000, 0, True, id="spent"),
    pytest.param(1000, 1000, 990, False, id="oracle-held-time-is-not-the-investigators"),
    # #1255 ("Time") RETIRES the fourth case, `wall-clock-stepped-back` (-1000, 1000, 0): it
    # pinned the monotonic delta as a source that kills a run whose wall clock reads before its
    # start. Elapsed is measured on the run clock alone now, so there is no second origin to
    # disagree with the first.
])
def test_lead_zeros_budget_gate_agrees_with_the_hooks_on_the_runs_clock(
        tmp_path, wall_back, mono_back, credited, killed):
    """O3."""
    run_dir = _run_dir(tmp_path, "o3")
    state = _clocked(run_dir, wall_back=wall_back, mono_back=mono_back, credited=credited)
    hook = _hook_kills(run_dir, state)
    assert hook is killed, f"the scenario no longer exercises the hooks' clock (hook={hook})"
    assert _lead_zero_kills(state) is hook, (
        "lead-0's budget gate disagrees with the budget hooks on the run's clock: "
        f"hooks kill={hook}, lead-0 kill={not hook}")


# ======================================================================================
# O4 — a reducer failure on deps with no run state raises; a refused write never does.
# ======================================================================================

def test_a_failed_reducer_on_gather_deps_with_no_state_raises(tmp_path):
    """O4."""
    deps, _box, payload = _gather_scene(tmp_path, BoxResult(1, b"", b"Binder Error: o4"))
    command = f"cat {model_path(payload, run_dir=deps.run_dir)} | defender-sql 'SELECT 1'"
    with pytest.raises(TypeError, match="RunState"):
        _tool_bash(dataclasses.replace(deps, run_state=None), command)

    out = _tool_bash(dataclasses.replace(deps, box=Box(BoxResult(1, b"", b"Binder Error: o4"))),
                     command)
    assert "Binder Error: o4" in out
    assert [r["query_id"] for r in deps.run_state.lead_rows(deps.lead_id)] == [BASH_SHIM_QUERY_ID]


@pytest.mark.parametrize("kind", ["symlink", "directory"])
def test_a_refused_shim_row_write_never_fails_the_command(tmp_path, kind):
    """O4's other half."""
    deps, box, payload = _gather_scene(tmp_path, BoxResult(1, b"", b"Binder Error: o4"))
    table = RunPaths(deps.run_dir).executed_queries
    outside = tmp_path / "outside.jsonl"
    outside.write_bytes(b"")
    if kind == "symlink":
        table.symlink_to(outside)
    else:
        table.mkdir()

    out = _tool_bash(deps, f"cat {model_path(payload, run_dir=deps.run_dir)} | defender-sql 'SELECT 1'")
    assert len(box.calls) == 1, "the command never reached the box, so the output is not its"
    assert "Binder Error: o4" in out, "a refused shim-row write cost the command its output"
    assert [r["query_id"] for r in deps.run_state.lead_rows(deps.lead_id)] == \
        [BASH_SHIM_QUERY_ID], "the failed reduce's row is not in the run's state"
    assert outside.read_bytes() == b"", "the shim row's write followed the planted link"


# ======================================================================================
# O5 / O7 — what round 3 deletes is gone; the state's read accessors.
# ======================================================================================


def test_lead_rows_hands_out_a_tuple_of_the_rows_as_they_stood(tmp_path):
    """`lead_rows(lead)` is a tuple of the lead's stored rows, in append order — read-only use,
    no copy of each row."""
    run_dir, state = _bare_run(tmp_path)
    assert state.lead_rows(LEAD) == ()
    _append(state, params={"q": "a"})
    before = state.lead_rows(LEAD)
    assert isinstance(before, tuple), f"lead_rows handed out a {type(before).__name__}"
    _append(state, params={"q": "b"})
    assert [r["params"] for r in before] == [{"q": "a"}], "an append reached an earlier tuple"
    after = state.lead_rows(LEAD)
    assert [r["params"] for r in after] == [{"q": "a"}, {"q": "b"}]
    assert list(after) == _table_rows(run_dir)
    assert state.lead_rows("l-404") == ()


def test_row_count_and_last_row_read_the_lead_without_listing_it(tmp_path):
    """`row_count(lead)` is how many rows the lead holds, `last_row(lead)` the latest of them
    (`None` for a lead with none) — the two reads lead-0 makes per call, counted over inherited
    and appended rows alike, per lead."""
    run_dir, state = _bare_run(tmp_path)
    assert (state.row_count(LEAD), state.last_row(LEAD)) == (0, None)

    state.inherit_rows([{"lead_id": LEAD, "seq": 0, "params": {"q": "inherited"}},
                        {"lead_id": "l-002", "seq": 0, "params": {"q": "other"}}])
    assert state.row_count(LEAD) == 1
    assert state.last_row(LEAD)["params"] == {"q": "inherited"}

    written = _append(state, params={"q": "mine"})
    assert written["seq"] == 1
    assert state.row_count(LEAD) == 2
    last = state.last_row(LEAD)
    assert (last["seq"], last["params"]) == (1, {"q": "mine"})
    assert last == _table_rows(run_dir)[-1], "the last row is not the view's last line"
    assert state.row_count("l-002") == 1
    assert (state.row_count("l-404"), state.last_row("l-404")) == (0, None)


def test_breaker_failures_counts_a_systems_charged_failures(tmp_path):
    """`breaker_failures(system)` is the failures charged to `system`."""
    _run, state = _bare_run(tmp_path)
    assert state.breaker_failures("elastic") == 0
    cb.record_outcome(state, "elastic", 2)
    cb.record_outcome(state, "elastic", 124)
    cb.record_outcome(state, "elastic", 1)
    cb.record_outcome(state, "elastic", 0)
    cb.record_outcome(state, "cmdb", 2)
    assert state.breaker_failures("elastic") == 2
    assert state.breaker_failures("cmdb") == 1
    assert state.breaker_failures("idp") == 0
    assert state.breaker_failures("elastic") == \
        state.breaker_snapshot()["systems"]["elastic"]["failures"]
