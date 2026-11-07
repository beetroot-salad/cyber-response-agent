"""#1235: the `RunState` object itself: fresh at start, sole holder of a run's live state, atomic
under its own lock, with its own oracle clock.

#1235 at the unit edge: the run state is the record (a refused view write still charges the
breaker), missing state fails closed for enforced roles, lead-0 reads the run's clock.

#1235: enforced roles without run state raise, stored rows are handed out uncopied, a
mismatched state is refused, and production's path carries one state.
"""
from __future__ import annotations

from dataclasses import replace as _with_live_run_1165
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
import asyncio
import dataclasses
from datetime import UTC, datetime, timedelta
from dataclasses import replace

import pytest

pytest.importorskip('pydantic_ai')
from pydantic_ai import Agent  # noqa: E402
from pydantic_ai.models import override_allow_model_requests  # noqa: E402
from pydantic_ai.models.function import FunctionModel  # noqa: E402
from pydantic_ai.usage import UsageLimits  # noqa: E402

from defender.tests.support.shared.contracts._spec1077 import fixture_run as _live_run_1165
from defender._io import read_jsonl_rows  # noqa: E402
from defender.hooks import budget_enforcer as be  # noqa: E402
from defender.records import RunPaths  # noqa: E402
from defender.systems import circuit_breaker as cb  # noqa: E402
from defender.investigation.run_state import RunState  # noqa: E402
from defender.investigation import record_query as rq  # noqa: E402
from defender.tests.support.shared._fixture_uuid import fixture_uuid, is_fixture_uuid_shape  # noqa: E402
from defender.tests.support.shared.contracts._spec1077 import fixture_run
from defender.tests.support.runtime.state._1255_view import model_path
from defender.knowledge._query_rules import BASH_SHIM_QUERY_ID  # noqa: E402
from defender.hooks.budget_enforcer import DEFAULT_LIMITS, BudgetKill  # noqa: E402
from defender.investigation.agent_definition import bind  # noqa: E402
from defender.execution.box_codec import BoxResult  # noqa: E402
from defender.investigation.driver import MAIN_DEF  # noqa: E402
from defender.investigation.query_tool import QueryCapture  # noqa: E402
from defender.investigation.tools import _tool_bash  # noqa: E402
from defender.tests.support.tenancy import _tenants1106
from defender.tests.e2e._spec771 import DEFENDER  # noqa: E402
from defender.tests.sandbox.test_bash_decision import Box, _gather_scene  # noqa: E402
from defender.tests.runtime.engine.test_budget_seams_631 import _run_dir, drive_agent  # noqa: E402
from defender.hooks.budget_enforcer import DEFAULT_LIMITS  # noqa: E402
from defender.investigation import driver, observe  # noqa: E402
from defender.investigation.agent_definition import bind, effective_tools_for  # noqa: E402
from defender.providers import BuiltModel  # noqa: E402
from defender.tests.support.tenancy import _tenants1106 as T1106
from defender.tests.support.shared._fixture_uuid import fixture_uuid  # noqa: E402
from defender.tests.sandbox.test_bash_decision import Box  # noqa: E402
from defender.tests.runtime.engine.test_budget_seams_631 import ScriptedModel, _run_dir, drive_agent  # noqa: E402


_BUDGET_KEYS = {"run_id", "tool_calls", "subagent_spawns", "created_at", "started_at"}


def _state_run_dir(root: Path, name: str = "run") -> Path:
    # A run folder is named by its UUID run id.
    run_dir = root / (name if is_fixture_uuid_shape(name) else fixture_uuid(name))
    RunPaths(run_dir).gather_raw.mkdir(parents=True)
    return run_dir


def _tree(root: Path) -> dict[str, bytes | None]:
    return {str(p.relative_to(root)): (p.read_bytes() if p.is_file() else None)
            for p in sorted(root.rglob("*"))}


def test_a_started_state_is_a_fresh_run_and_reads_and_writes_no_file(tmp_path):
    """`RunState(run_dir, run_id)` begins a run."""
    import json

    run_dir = _state_run_dir(tmp_path)
    (run_dir / "budget.json").write_text(json.dumps(
        {"run_id": "r", "tool_calls": 10_000, "subagent_spawns": 99,
         "created_at": "2000-01-01T00:00:00+00:00", "started_at": "2000-01-01T00:00:00+00:00"}),
        encoding="utf-8")
    (run_dir / "circuit_breaker.json").write_text(json.dumps(
        {"systems": {"elastic": {"failures": 9, "tripped_at": "2000-01-01T00:00:00+00:00"}},
         "total_failures": 4}), encoding="utf-8")
    RunPaths(run_dir).executed_queries.write_text(
        json.dumps({"lead_id": LEAD, "seq": 0, "system": "elastic", "verb": "query",
                    "params": {}}) + "\n", encoding="utf-8")
    (tmp_path / "run.oracle-held.json").write_text(
        json.dumps({"oracle_held_seconds": 1e6}), encoding="utf-8")
    before = _tree(tmp_path)
    started = datetime.now(UTC)

    state = RunState(run_dir, "r")

    assert state.run_id == "r"
    assert state.run_dir == run_dir
    budget = state.budget_snapshot()
    assert set(budget) == _BUDGET_KEYS, budget
    assert (budget["run_id"], budget["tool_calls"], budget["subagent_spawns"]) == ("r", 0, 0)
    assert budget["created_at"] == budget["started_at"]
    origin = datetime.fromisoformat(budget["created_at"])
    assert origin.tzinfo is not None, "the wall-clock origin is not timezone-aware"
    assert abs((origin - started).total_seconds()) < 5, "the origin is not the run's start"
    assert state.breaker_snapshot() == {"systems": {}, "total_failures": 0}
    assert list(state.lead_rows(LEAD)) == [], "rows on disk entered a fresh state"
    assert rq._next_seq(state, LEAD) == 0
    assert be.oracle_held(state) == 0.0, "a credit on disk entered a fresh state"
    assert cb.is_tripped(state, "elastic") is False
    assert _tree(tmp_path) == before, "starting a run's state touched the disk"

    be.count_call(state, "gather")
    cb.record_outcome(state, "elastic", 2)
    RunPaths(run_dir).executed_queries.unlink()
    assert _append(state, params={"q": "a"})["seq"] == 0
    assert (state.budget_snapshot()["tool_calls"], state.budget_snapshot()["subagent_spawns"]) \
        == (1, 1)
    assert state.breaker_snapshot()["total_failures"] == 1
    assert len(state.lead_rows(LEAD)) == 1


def test_what_the_state_hands_out_cannot_move_the_run(tmp_path):
    """Nothing a caller does to what the state hands out moves the run."""
    state = RunState(_state_run_dir(tmp_path), "r")
    cb.record_outcome(state, "elastic", 2)
    written = _append(state, params={"q": "a"})

    budget = state.budget_snapshot()
    budget["tool_calls"] = 999
    breaker = state.breaker_snapshot()
    breaker["systems"]["elastic"]["failures"] = 999
    breaker["total_failures"] = 999
    written["params"]["q"] = "edited after the write"
    written["seq"] = 99
    rows = state.lead_rows(LEAD)
    with pytest.raises((TypeError, AttributeError)):
        rows.append({"lead_id": LEAD, "seq": 1})  # type: ignore[attr-defined]

    assert state.budget_snapshot()["tool_calls"] == 0
    assert state.breaker_snapshot() == {"systems": {"elastic": {"failures": 1}},
                                        "total_failures": 1}
    assert [(r["seq"], r["params"]) for r in state.lead_rows(LEAD)] == [(0, {"q": "a"})]
    assert rq._next_seq(state, LEAD) == 1

    be.count_call(state, "bash")
    cb.record_outcome(state, "elastic", 2)
    assert state.budget_snapshot()["tool_calls"] == 1
    assert cb.is_tripped(state, "elastic") is True


def test_two_states_for_one_folder_and_one_run_id_share_nothing(tmp_path):
    """Two states started for the SAME folder and run id are two runs' states."""
    run_dir = _state_run_dir(tmp_path)
    one, two = RunState(run_dir, "same"), RunState(run_dir, "same")

    be.count_call(one, "gather")
    be.account_call(one, "bash", limits=be.DEFAULT_LIMITS, tier="core")
    cb.record_outcome(one, "elastic", 2)
    cb.record_outcome(one, "elastic", 2)
    _append(one, params={"q": "a"})
    be.oracle_turn_opened(one)
    time.sleep(0.02)
    be.oracle_turn_closed(one)

    assert (one.budget_snapshot()["tool_calls"], one.budget_snapshot()["subagent_spawns"]) \
        == (2, 1)
    assert cb.is_tripped(one, "elastic") is True
    assert len(one.lead_rows(LEAD)) == 1
    assert be.oracle_held(one) > 0.0

    assert (two.budget_snapshot()["tool_calls"], two.budget_snapshot()["subagent_spawns"]) \
        == (0, 0)
    assert cb.is_tripped(two, "elastic") is False
    assert two.breaker_snapshot() == {"systems": {}, "total_failures": 0}
    assert list(two.lead_rows(LEAD)) == []
    assert rq._next_seq(two, LEAD) == 0
    assert be.oracle_held(two) == 0.0


def test_a_row_recorded_through_deps_lands_in_the_state_the_deps_carry(tmp_path):
    """The query tool records a row into the state its deps CARRY, whatever spelling of the run
    folder the deps hold."""
    import asyncio
    from dataclasses import replace

    from defender.investigation.agent_definition import bind
    from defender.investigation.query_tool import QueryCapture
    from defender.tests.support.tenancy import _tenants1106
    from defender.tests.e2e._spec771 import DEFENDER

    real = _state_run_dir(tmp_path / "real")
    (tmp_path / "link").symlink_to(tmp_path / "real", target_is_directory=True)
    carried = RunState(tmp_path / "link" / real.name, "r-carried")
    deps = replace(_with_live_run_1165(bind(_tenants1106.fixture_gather_def(), real, defender_dir=DEFENDER), run=_live_run_1165(real)),
                   lead_id=LEAD, run_state=carried)

    asyncio.run(QueryCapture(registry=None, known_ids=frozenset())._record(
        deps, system="elastic", verb="search", query_id="elastic.ad-hoc", params={"q": "a"},
        payload=[{"a": 1}], exit_code=0, detail="", system_key=""))

    assert [r["params"] for r in carried.lead_rows(LEAD)] == [{"q": "a"}], \
        "the row did not land in the state the deps carry"
    assert list(carried.lead_rows(LEAD)) == [
        r for r in read_jsonl_rows(RunPaths(real).executed_queries) if r["lead_id"] == LEAD]
    assert list(RunState(real, "r-carried").lead_rows(LEAD)) == []


def test_concurrent_appends_to_one_lead_take_distinct_seqs_and_agree_with_the_table(tmp_path):
    """A row append is one operation under the state's lock (seq, record, payload, view line)."""
    import sys

    run_dir = _state_run_dir(tmp_path)
    state = RunState(run_dir, "r")
    old = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)
    try:
        def work(worker: int) -> None:
            for k in range(5):
                _append(state, params={"w": worker, "k": k})

        threads = [threading.Thread(target=work, args=(w,)) for w in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
    finally:
        sys.setswitchinterval(old)

    rows = list(state.lead_rows(LEAD))
    assert sorted(r["seq"] for r in rows) == list(range(40)), "two appends took one seq"
    assert [r["seq"] for r in rows] == list(range(40)), "the state's order is not the seq order"
    assert rows == read_jsonl_rows(RunPaths(run_dir).executed_queries), \
        "the state and the table disagree"


def test_every_state_has_a_clock_whose_credit_is_its_own(tmp_path):
    """The oracle clock lives in the state alone: a new state with a reused run id starts at
    zero, and nothing is written to disk."""
    run_dir = _state_run_dir(tmp_path / "runs")
    before = _tree(tmp_path)
    first = RunState(run_dir, "reused-id")
    assert be.oracle_held(first) == 0.0

    be.oracle_turn_opened(first)
    time.sleep(0.05)
    assert be.oracle_held(first) >= 0.04, "an open turn did not pause the clock"
    be.oracle_turn_closed(first)
    credited = be.oracle_held(first)
    assert credited >= 0.04, "the closed turn was not credited"
    time.sleep(0.02)
    assert be.oracle_held(first) == credited, "a closed turn kept counting"

    be.oracle_turn_opened(first)
    time.sleep(0.02)
    be.oracle_turn_closed(first)
    assert be.oracle_held(first) >= credited + 0.015, "a second turn was not added"

    second = RunState(run_dir, "reused-id")
    assert be.oracle_held(second) == 0.0, "a new run with a reused id inherited oracle credit"
    assert list(tmp_path.rglob("*.oracle-held.json")) == []
    assert _tree(tmp_path) == before, "the oracle clock wrote to disk"


LEAD = "l-001"


_PAYLOAD = '{"total": 1, "hits": ["web-1"]}'


def _bare_run(root: Path, name: str = "run") -> tuple[Path, RunState]:
    # A run folder is named by its UUID run id.
    run_dir = root / (name if is_fixture_uuid_shape(name) else fixture_uuid(name))
    RunPaths(run_dir).gather_raw.mkdir(parents=True)
    return run_dir, RunState(run_dir, run_dir.name)


def _append(state: RunState, *, params: dict) -> dict:
    """One executed row through the production writer."""
    return rq.append_query_row(
        state, run=fixture_run(state.run_dir), lead_id=LEAD, system="elastic", verb="query", query_id="elastic.probe",
        params=params, raw_command="elastic query", payload_text=_PAYLOAD, exit_code=0,
        payload_status="ok", payload_digest=rq.payload_digest(_PAYLOAD, "", 0), system_key="")


def _failures(state: RunState, system: str) -> int:
    """`system`'s charged failures, read off the breaker snapshot rather than
    `breaker_failures`, which is tested on its own below."""
    rec = state.breaker_snapshot()["systems"].get(system)
    return rec["failures"] if rec else 0


def _table_rows(run_dir: Path, lead: str = LEAD) -> list[dict]:
    return [r for r in read_jsonl_rows(RunPaths(run_dir).executed_queries)
            if r.get("lead_id") == lead]


def _gather_deps(run_dir: Path, state: RunState):
    return dataclasses.replace(
        _with_live_run_1165(bind(_tenants1106.fixture_gather_def(), run_dir, defender_dir=DEFENDER), run=_live_run_1165(run_dir)),
        lead_id=LEAD, run_state=state)


def _record_failure(deps, *, params: dict) -> tuple[dict, str]:
    """One backend call that failed on the transport (exit 2: an infra failure the breaker
    charges), recorded through the query tool's own recorder."""
    return asyncio.run(QueryCapture(registry=None, known_ids=frozenset())._record(
        deps, system="elastic", verb="search", query_id="elastic.ad-hoc", params=params,
        payload=None, exit_code=2, detail="connection refused", system_key=""))


@pytest.mark.parametrize("kind", ["symlink", "directory"])
def test_a_failing_call_whose_view_write_is_refused_is_still_charged_and_recorded(
        tmp_path, kind):
    """At the query tool's recorder, a call that failed on the transport (exit 2) while
    `executed_queries.jsonl` is squatted (a planted symlink or a directory): the view write's
    `OSError` propagates, but first the failure is charged to the system's breaker and the row
    is in the run's state."""
    run_dir = tmp_path / fixture_uuid("run")
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
    """The charge above is the failure's, not a side effect of the refused write: a call that
    succeeded (exit 0) while the view is squatted is in the state, its write error propagates,
    and the breaker is untouched."""
    run_dir = tmp_path / fixture_uuid("run")
    RunPaths(run_dir).gather_raw.mkdir(parents=True)
    state = RunState(run_dir, "r3-o1-ok")
    deps = _gather_deps(run_dir, state)
    RunPaths(run_dir).executed_queries.mkdir()

    with pytest.raises(OSError):  # noqa: PT011 — the directory refuses in its own words
        asyncio.run(QueryCapture(registry=None, known_ids=frozenset())._record(
            deps, system="elastic", verb="search", query_id="elastic.ad-hoc", params={"q": "a"},
            payload=[{"a": 1}], exit_code=0, detail="", system_key=""))
    assert [(r["seq"], r["exit_code"]) for r in state.lead_rows(LEAD)] == [(0, 0)], \
        "a succeeding call whose view write was refused left no row"
    assert state.breaker_snapshot() == {"systems": {}, "total_failures": 0}, \
        "a succeeding call was charged because its view write failed"


_LIMITS = {**DEFAULT_LIMITS, "max_tool_calls": 50, "wall_clock_timeout": 3600,
           "grace_seconds": 600}


_ECHO = [[("bash", {"command": "echo o2"})]]


def test_a_non_enforced_role_whose_deps_carry_no_state_neither_counts_nor_raises(tmp_path):
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


@pytest.mark.parametrize(("wall_back", "mono_back", "credited", "open_for", "killed"), [
    pytest.param(0, 0, 0, None, False, id="fresh"),
    pytest.param(1000, 1000, 0, None, True, id="spent"),
    pytest.param(1000, 1000, 990, None, False, id="oracle-held-time-is-not-the-investigators"),
    pytest.param(1000, 1000, 0, 990, False, id="an-oracle-turn-open-now"),
])
def test_lead_zeros_budget_gate_agrees_with_the_hooks_on_the_runs_clock(
        tmp_path, wall_back, mono_back, credited, open_for, killed):
    """Lead-0's gate and the budget hooks read one run clock, on which oracle-held time
    (credited, or a turn still open) is not the investigator's."""
    run_dir = _run_dir(tmp_path, "o3")
    state = _clocked(run_dir, wall_back=wall_back, mono_back=mono_back, credited=credited)
    if open_for is not None:
        with state.lock:
            state.oracle_opened = time.monotonic() - open_for
    hook = _hook_kills(run_dir, state)
    assert hook is killed, f"the scenario no longer exercises the hooks' clock (hook={hook})"
    assert _lead_zero_kills(state) is hook, (
        "lead-0's budget gate disagrees with the budget hooks on the run's clock: "
        f"hooks kill={hook}, lead-0 kill={not hook}")


def test_a_failed_reducer_on_gather_deps_with_no_state_raises(tmp_path):
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


def test_row_count_counts_inherited_and_appended_rows_per_lead(tmp_path):
    _run_dir, state = _bare_run(tmp_path)
    assert state.row_count(LEAD) == 0
    state.inherit_rows([{"lead_id": LEAD, "seq": 0, "params": {"q": "inherited"}},
                        {"lead_id": "l-002", "seq": 0, "params": {"q": "other"}}])
    assert state.row_count(LEAD) == 1
    assert _append(state, params={"q": "mine"})["seq"] == 1
    assert state.row_count(LEAD) == 2
    assert state.row_count("l-002") == 1
    assert state.row_count("l-404") == 0


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


def test_an_enforced_gather_whose_deps_carry_no_state_raises(tmp_path):
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
    """On production's path `run.py` hands no state; the run resolves one, and lead-0 and the
    gather lead share it."""
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
    state = mine[0].run_state
    assert isinstance(state, RunState)
    assert all(c.run_state is state for c in lead_zero), \
        "lead-0's verb contexts carried a state other than the run's"
    assert state.row_count("l-00c") >= 1, "the run's state does not hold lead-0's rows"
    assert state.row_count(LEAD) == 1, "the run's state does not hold the gather lead's row"
