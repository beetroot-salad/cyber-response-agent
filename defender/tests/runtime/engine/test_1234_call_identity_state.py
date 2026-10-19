"""Call identity follows #1235's run-owned state, never the writable disk view.
"""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from defender.runtime.run_state import RunState
from defender.scripts.gather_tools.record_query import bind_call_ids, next_call_id


def test_call_ids_ignore_disk_rows_and_are_independent_between_run_states(tmp_path: Path):
    view = tmp_path / "executed_queries.jsonl"
    poisoned = '{"call_id": "world/999999"}\n'
    view.write_text(poisoned, encoding="utf-8")
    first = RunState(tmp_path, "run")
    second = RunState(tmp_path, "run")
    bind_call_ids(first, "world")
    bind_call_ids(second, "world")
    assert [next_call_id(first), next_call_id(first), next_call_id(second)] == [
        "world/0", "world/1", "world/0"]
    assert view.read_text(encoding="utf-8") == poisoned


def test_concurrent_calls_allocate_unique_ids_from_one_run_state(tmp_path: Path):
    state = RunState(tmp_path, "world")
    with ThreadPoolExecutor(max_workers=8) as pool:
        ids = list(pool.map(lambda _: next_call_id(state), range(128)))
    assert set(ids) == {f"world/{n}" for n in range(128)}
    assert list(tmp_path.iterdir()) == []
