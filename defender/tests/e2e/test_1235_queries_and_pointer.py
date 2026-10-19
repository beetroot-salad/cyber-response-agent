"""#1235, second half: the repeat guard and the rejection budget read the rows the host recorded in memory, so truncating, deleting or planting rows in executed_queries.jsonl moves neither; the run-to-case link is a sidecar beside the run folder, so a pointer planted inside the folder (or a hand-copied folder) is never followed."""
from __future__ import annotations

from defender.tests._spec1077 import fixture_run as _run_handle_1165

import json
import shutil
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from defender._io import read_jsonl_rows  # noqa: E402
from defender.run_repository import RunPaths  # noqa: E402
from defender.runtime import branch, session_store  # noqa: E402
from defender.scripts.gather_tools.record_query import REJECTION_BUDGET  # noqa: E402
from defender.tests.e2e._replay_harness import (  # noqa: E402
    GOLDEN,
    GOLDEN_AB3,
    ReplayFn,
    Turn,
    VerbRecorder,
    drive,
    materialize,
)
from defender.tests.e2e.test_query_tool_611 import DONE, elastic_ok, q  # noqa: E402

pytestmark = pytest.mark.e2e

LEAD = "l-001"
#: The in-folder name the case link had before #1235.
OLD_POINTER_NAME = "session_store_pointer.json"


class PlantingReplay(ReplayFn):
    """A scripted gather model that, when asked for turn `at` (0-based), first does `plant()` to
    the live run's queries table — in this process, after the driver opened the run."""

    def __init__(self, turns: list[Turn], *, at: int, plant) -> None:
        super().__init__(turns)
        self._at, self._plant = at, plant
        self.planted = False

    def __call__(self, messages, info):  # noqa: ANN001 — the FunctionModel callable protocol
        if self.calls == self._at:
            self._plant()
            self.planted = True
        return super().__call__(messages, info)


def _drive_lead(run_dir: Path, gather: ReplayFn, rec: VerbRecorder, *, run_id: str) -> None:
    """MAIN dispatches one elastic lead; the gather model replays `gather` against the injected
    happy-path registry (`elastic.query`, recorded in `rec`)."""
    main = ReplayFn([
        Turn(tool_calls=[("gather", {
            "lead_id": LEAD, "system": "elastic", "goal": "measure this lead",
            "what_to_summarize": ["auth events"],
        })]),
        Turn(text="Investigation complete."),
    ])
    drive(run_dir, run_id=run_id, main=main, gather=gather, verbs=elastic_ok(rec))


def _lead_lines(run_dir: Path) -> list[dict]:
    """This lead's rows as the file holds them right now (the plants' source)."""
    return [r for r in read_jsonl_rows(RunPaths(run_dir).executed_queries)
            if r.get("lead_id") == LEAD]


def _append_copies(run_dir: Path, row: dict, n: int) -> None:
    with RunPaths(run_dir).executed_queries.open("a", encoding="utf-8") as fh:  # lint-jsonl-io: ok — the plant is a raw write into the live table
        for _ in range(n):
            fh.write(json.dumps(row) + "\n")


_SAME = {"native_query": "FROM logs"}
_THREE_SAME = [q("elastic", "query", _SAME), q("elastic", "query", _SAME),
               q("elastic", "query", _SAME), DONE]


def test_three_identical_requests_trip_the_repeat_guard(tmp_path):
    """Positive control for the repeat arms: with nothing planted, the third identical request
    never reaches the backend."""
    rec = VerbRecorder()
    run_dir = materialize(tmp_path, GOLDEN_AB3)
    _drive_lead(run_dir, ReplayFn(list(_THREE_SAME)), rec, run_id="r1235-control")
    assert len(rec.calls) == 2, "the repeat guard did not refuse the third identical request"


@pytest.mark.parametrize("plant", ["truncate", "delete"])
def test_an_emptied_queries_table_does_not_reset_the_repeat_count(tmp_path, plant):
    """O1:"""
    holder: list[Path] = []

    def empty() -> None:
        table = RunPaths(holder[0]).executed_queries
        assert len(_lead_lines(holder[0])) == 2, "the plant ran before the two host rows landed"
        if plant == "truncate":
            table.write_text("", encoding="utf-8")
        else:
            table.unlink()

    rec = VerbRecorder()
    gather = PlantingReplay(list(_THREE_SAME), at=2, plant=empty)
    run_dir = materialize(tmp_path, GOLDEN_AB3)
    holder.append(run_dir)
    _drive_lead(run_dir, gather, rec, run_id="r1235-empty")

    assert gather.planted, "the plant never ran — this arm measured nothing"
    assert len(rec.calls) == 2, f"a {plant}d queries table reset the repeat count"


def test_planted_rows_do_not_fire_the_repeat_guard(tmp_path):
    """O1, the other direction:"""
    holder: list[Path] = []

    def duplicate() -> None:
        rows = _lead_lines(holder[0])
        assert len(rows) == 1, "the plant ran before the first host row landed"
        _append_copies(holder[0], rows[0], 2)

    rec = VerbRecorder()
    gather = PlantingReplay(list(_THREE_SAME), at=1, plant=duplicate)
    run_dir = materialize(tmp_path, GOLDEN_AB3)
    holder.append(run_dir)
    _drive_lead(run_dir, gather, rec, run_id="r1235-dup")

    assert gather.planted
    assert len(rec.calls) == 2, \
        "planted rows moved the repeat guard: the second request was refused (or the third ran)"


B = REJECTION_BUDGET


def _rejected(i: int) -> Turn:
    """A call the query tool's argument schema turns back (an extra argument), recorded as an
    above-guard rejection; `verb` varies per call so no two rejections repeat."""
    return Turn(tool_calls=[("query", {
        "system": "elastic", "verb": f"ghostverb{i}", "params": _SAME, "bogus_extra_arg": "x"})])


_CORRECTED = q("elastic", "query", {"native_query": "FROM corrected"})


def test_an_emptied_queries_table_does_not_refund_the_rejection_budget(tmp_path):
    """O1:"""
    holder: list[Path] = []

    def empty() -> None:
        assert len(_lead_lines(holder[0])) == B - 1, "the plant ran at the wrong point"
        RunPaths(holder[0]).executed_queries.write_text("", encoding="utf-8")

    rec = VerbRecorder()
    gather = PlantingReplay([*[_rejected(i) for i in range(B + 3)], _CORRECTED, DONE],
                            at=B - 1, plant=empty)
    run_dir = materialize(tmp_path, GOLDEN_AB3)
    holder.append(run_dir)
    _drive_lead(run_dir, gather, rec, run_id="j1235-empty")

    assert gather.planted
    assert rec.calls == [], "an emptied queries table refunded the rejection budget"


def _finished_run(root: Path, run_id: str) -> Path:
    """A real, finished run with its own case store:"""
    run_dir = materialize(root, GOLDEN, run_id=run_id)
    drive(run_dir, run_id=run_id, main=ReplayFn([Turn(text="Investigation complete.")]))
    return run_dir


def _pointer(run_dir: Path) -> dict:
    return json.loads(RunPaths(run_dir).session_pointer().read_text(encoding="utf-8"))


def test_a_pointer_planted_inside_the_folder_is_not_the_case_link(tmp_path):
    """O3:"""
    run_a = _finished_run(tmp_path / "a", "o3-a")
    run_b = _finished_run(tmp_path / "b", "o3-b")
    a_link, b_link = _pointer(run_a), _pointer(run_b)
    assert a_link["store_path"] != b_link["store_path"], "the two runs share a store"

    (run_a / OLD_POINTER_NAME).write_text(json.dumps(b_link), encoding="utf-8")

    for open_store in (branch.open_source_store, branch.source_store_if_any):
        handle = open_store(run_a, source_run=_run_handle_1165(run_a))
        try:
            assert Path(handle.path).resolve() == Path(a_link["store_path"]).resolve(), \
                f"{open_store.__name__} followed a pointer planted inside the run folder"
        finally:
            handle.connection.close()
    assert session_store.resolve_store_path(_run_handle_1165(run_a)) == Path(a_link["store_path"])
    assert session_store.resolve_session_id(_run_handle_1165(run_a)) == a_link.get("session_id")

    control = branch.open_source_store(run_b, source_run=_run_handle_1165(run_b))
    try:
        assert Path(control.path).resolve() == Path(b_link["store_path"]).resolve()
    finally:
        control.connection.close()
    assert session_store.resolve_store_path(_run_handle_1165(run_b)) == Path(b_link["store_path"])


def test_a_hand_copied_run_folder_carries_no_case_link(tmp_path):
    """O3:"""
    run_dir = _finished_run(tmp_path / "a", "o3-copied")
    copy = tmp_path / "elsewhere" / "run"
    shutil.copytree(run_dir, copy)

    assert branch.source_store_if_any(copy, source_run=_run_handle_1165(copy)) is None, \
        "a hand-copied folder opened a store through a link carried inside it"

    (copy / OLD_POINTER_NAME).write_text(json.dumps(_pointer(run_dir)), encoding="utf-8")
    with pytest.raises(branch.BranchError):
        branch.source_store_if_any(copy, source_run=_run_handle_1165(copy))

    handle = branch.source_store_if_any(run_dir, source_run=_run_handle_1165(run_dir))
    assert handle is not None, "the original run's sidecar opened no store"
    handle.connection.close()
