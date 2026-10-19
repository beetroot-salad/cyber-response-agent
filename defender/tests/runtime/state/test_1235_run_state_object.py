"""#1235: the `RunState` object itself: fresh at start, sole holder of a run's live state, atomic
under its own lock, with its own oracle clock."""
from __future__ import annotations

from dataclasses import replace as _with_live_run_1165
from defender.tests.support.shared.contracts._spec1077 import fixture_run as _live_run_1165

from defender.tests.support.shared.contracts._spec1077 import fixture_run

import threading
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from defender._io import read_jsonl_rows  # noqa: E402
from defender.hooks import budget_enforcer as be  # noqa: E402
from defender.run_repository import RunPaths  # noqa: E402
from defender.runtime import circuit_breaker as cb  # noqa: E402
from defender.runtime.run_state import RunState  # noqa: E402
from defender.runtime import record_query as rq  # noqa: E402
from defender.tests.support.shared._fixture_uuid import fixture_uuid, is_fixture_uuid_shape  # noqa: E402

LEAD = "l-001"
_PAYLOAD = '{"total": 1, "hits": ["web-1"]}'
_BUDGET_KEYS = {"run_id", "tool_calls", "subagent_spawns", "created_at", "started_at"}


def _run_dir(root: Path, name: str = "run") -> Path:
    # #1187 (declared change 1): a run id is a canonical UUID — the folder is fixture_uuid(name)
    run_dir = root / (name if is_fixture_uuid_shape(name) else fixture_uuid(name))
    RunPaths(run_dir).gather_raw.mkdir(parents=True)
    return run_dir


def _append(state: RunState, *, params: dict, lead: str = LEAD) -> dict:
    """One executed row through the production writer."""
    return rq.append_query_row(
        state, run=fixture_run(state.run_dir), lead_id=lead, system="elastic", verb="query", query_id="elastic.probe",
        params=params, raw_command="elastic query", payload_text=_PAYLOAD, exit_code=0,
        payload_status="ok", payload_digest=rq.payload_digest(_PAYLOAD, "", 0), system_key="")


def _tree(root: Path) -> dict[str, bytes | None]:
    return {str(p.relative_to(root)): (p.read_bytes() if p.is_file() else None)
            for p in sorted(root.rglob("*"))}


def test_a_started_state_is_a_fresh_run_and_reads_and_writes_no_file(tmp_path):
    """`RunState(run_dir, run_id)` begins a run."""
    import json

    run_dir = _run_dir(tmp_path)
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
    state = RunState(_run_dir(tmp_path), "r")
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
    run_dir = _run_dir(tmp_path)
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

    from defender.runtime.agent_definition import bind
    from defender.runtime.query_tool import QueryCapture
    from defender.tests.support.tenancy import _tenants1106
    from defender.tests.e2e._spec771 import DEFENDER

    real = _run_dir(tmp_path / "real")
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

    run_dir = _run_dir(tmp_path)
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
    """R6."""
    run_dir = _run_dir(tmp_path / "runs")
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
