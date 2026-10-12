"""#1235, second half — the queries table's live reads come from memory, and the run -> case
link lives beside the run folder, not in it.

F1 (comment 6107812099, "forks decided"): the repeat guard and the rejection budget used to
re-read `executed_queries.jsonl` per call. They now read the rows the host recorded, held on the
run's one `RunState` (round 2, comment 6117481676: `state.lead_rows(lead)`), which a row enters
only after its file write succeeded and which no file is ever read into. The file is still
written, byte for byte as before: it is the model's view and the learning loop's record, and no
decision reads it back.

F2: `session_store_pointer.json` — which case database a run's messages live in — leaves the
run folder for a host-only sidecar beside it, `<run_id>.session-pointer.json` in the run's
container, like `.run-end.json`. Every reader moves with it.

What this module pins, through the real driver (`drive`) and the real readers:

  O1 (queries). While a run is live, overwriting, truncating or appending to its
     `executed_queries.jsonl` moves neither guard: the repeat guard and the rejection budget
     still fire on the rows the host recorded, and planted rows fire neither. The plant is made
     in-process from the gather model's own turn, after the driver opened the run. Each
     negative is paired with the unplanted control on the same script.
  O3. After a run the case link is the sidecar beside the folder and nothing named
     `session_store_pointer.json` is inside it; a pointer planted inside the folder naming
     ANOTHER run's real store is ignored by the branch's source-store open and by the run
     page's store resolution (positive control: the sidecar's store is the one opened, and the
     planted store is a real, openable one); a hand-copied folder carries no link and reads as
     "no session" — unless it carries the old in-folder name, which since round 2 is a run
     recorded before #1235 and is refused (`test_1235_run_state_e2e`'s R5).

Round 1 made these green; round 2 keeps every claim and moves only how the state is reached.
"""
from __future__ import annotations

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


# ======================================================================================
# O1 — the repeat guard. Three identical requests: the third is refused before it reaches the
# backend (REPEAT_THRESHOLD = 3), so the verb is asked twice.
# ======================================================================================

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
    """O1: after two identical requests, the live run's `executed_queries.jsonl` emptied (or
    deleted) does not reset the count — the third identical request is still refused before
    the backend, as in the control.

    Observed failing by: the guard re-reading the file, finding no prior occurrence, and the
    verb asked a third time."""
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
    """O1, the other direction: after the lead's first request, two more copies of its row
    appended to the live table do not count as occurrences — the second identical request
    reaches the backend and only the third is refused, as in the control.

    Observed failing by: the guard counting the planted copies and refusing the second request."""
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


# ======================================================================================
# O1 — the rejection budget. Schema-rejected calls (an extra argument), each naming a different
# verb so the repeat-rejection guard stays silent: the lead is ended at its REJECTION_BUDGET-th
# rejection, and a corrected call scripted after the rejections never runs. Scripted one short
# of the budget, the corrected call does run.
# ======================================================================================

B = REJECTION_BUDGET


def _rejected(i: int) -> Turn:
    """A call the query tool's argument schema turns back (an extra argument), recorded as an
    above-guard rejection; `verb` varies per call so no two rejections repeat."""
    return Turn(tool_calls=[("query", {
        "system": "elastic", "verb": f"ghostverb{i}", "params": _SAME, "bogus_extra_arg": "x"})])


_CORRECTED = q("elastic", "query", {"native_query": "FROM corrected"})


def test_the_rejection_budget_ends_the_lead_and_one_short_does_not(tmp_path):
    """Positive control for the rejection arms, both directions: past the budget the corrected
    call never runs; one rejection short of it, the corrected call runs."""
    over = VerbRecorder()
    run_over = materialize(tmp_path / "over", GOLDEN_AB3)
    _drive_lead(run_over, ReplayFn([*[_rejected(i) for i in range(B + 3)], _CORRECTED, DONE]),
                over, run_id="j1235-over")
    assert over.calls == [], "the rejection budget did not end the lead"

    under = VerbRecorder()
    run_under = materialize(tmp_path / "under", GOLDEN_AB3)
    _drive_lead(run_under, ReplayFn([*[_rejected(i) for i in range(B - 1)], _CORRECTED, DONE]),
                under, run_id="j1235-under")
    assert len(under.calls) == 1, "one rejection short of the budget, the corrected call did not run"


def test_an_emptied_queries_table_does_not_refund_the_rejection_budget(tmp_path):
    """O1: with the lead one rejection short of its budget, the live table emptied does not
    refund it — the next rejection still ends the lead and the corrected call never runs, as
    in the control.

    Observed failing by: the budget re-read from the emptied file, the lead running on, and the
    corrected call reaching the backend."""
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


def test_planted_rejection_rows_do_not_spend_the_rejection_budget(tmp_path):
    """O1, the other direction: after the lead's first rejection, copies of that row appended
    to the live table (enough to spend the whole budget) do not end it — scripted one short of
    the budget, the corrected call still runs, as in the control.

    Observed failing by: the planted rows counted, the lead ended early, the corrected call
    never run."""
    holder: list[Path] = []

    def spend() -> None:
        rows = _lead_lines(holder[0])
        assert len(rows) == 1, "the plant ran before the first host rejection landed"
        _append_copies(holder[0], rows[0], B)

    rec = VerbRecorder()
    gather = PlantingReplay([*[_rejected(i) for i in range(B - 1)], _CORRECTED, DONE],
                            at=1, plant=spend)
    run_dir = materialize(tmp_path, GOLDEN_AB3)
    holder.append(run_dir)
    _drive_lead(run_dir, gather, rec, run_id="j1235-spend")

    assert gather.planted
    assert len(rec.calls) == 1, "planted rejection rows spent the lead's budget"


# ======================================================================================
# O3 — the case link is a sidecar beside the run folder.
# ======================================================================================

def _finished_run(root: Path, run_id: str) -> Path:
    """A real, finished run with its own case store: one text turn through the real driver and
    the default store factory. Each root is its own container (`<root>/run`), and every root
    under the test's `tmp_path` shares one sessions directory beside them."""
    run_dir = materialize(root, GOLDEN)
    drive(run_dir, run_id=run_id, main=ReplayFn([Turn(text="Investigation complete.")]))
    return run_dir


def _pointer(run_dir: Path) -> dict:
    return json.loads(RunPaths(run_dir).session_pointer().read_text(encoding="utf-8"))


def test_the_case_link_is_a_sidecar_beside_the_run_folder(tmp_path):
    """O3: after a run, its case link is `<run_id>.session-pointer.json` in the run's container,
    naming the case and the store the run wrote; nothing named `session_store_pointer.json` (or
    the sidecar's name) is anywhere inside the run folder."""
    from defender.run_repository import SESSION_POINTER_SUFFIX

    run_dir = _finished_run(tmp_path / "a", "o3-sidecar")

    assert SESSION_POINTER_SUFFIX == ".session-pointer.json"
    sidecar = RunPaths(run_dir).session_pointer()
    assert sidecar == run_dir.parent / f"{run_dir.name}{SESSION_POINTER_SUFFIX}"
    assert sidecar.is_file(), "the run wrote no case-link sidecar"
    doc = _pointer(run_dir)
    assert set(doc) >= {"case_id", "store_path"}
    assert Path(doc["store_path"]).is_file(), "the sidecar names a store that does not exist"
    inside = [p.name for p in run_dir.rglob("*")]
    assert OLD_POINTER_NAME not in inside, "the case link is still written inside the run folder"
    assert sidecar.name not in inside


def test_a_pointer_planted_inside_the_folder_is_not_the_case_link(tmp_path):
    """O3: a `session_store_pointer.json` planted inside run A's folder, naming run B's real
    store and case, is ignored by every reader of the link — the branch's source-store open
    (`open_source_store`, `source_store_if_any`) opens A's own store, and the run page's store
    resolution (`resolve_store_path`) and session lookup (`resolve_session_id`) answer A's.

    Positive control on the same addresses: B's link opens B's store, a different, real one —
    so the plant names something a file-reading reader would really have opened.

    Observed failing by: A's readers following the planted file into B's case."""
    run_a = _finished_run(tmp_path / "a", "o3-a")
    run_b = _finished_run(tmp_path / "b", "o3-b")
    a_link, b_link = _pointer(run_a), _pointer(run_b)
    assert a_link["store_path"] != b_link["store_path"], "the two runs share a store"

    (run_a / OLD_POINTER_NAME).write_text(json.dumps(b_link), encoding="utf-8")

    for open_store in (branch.open_source_store, branch.source_store_if_any):
        handle = open_store(run_a)
        try:
            assert Path(handle.path).resolve() == Path(a_link["store_path"]).resolve(), \
                f"{open_store.__name__} followed a pointer planted inside the run folder"
        finally:
            handle.connection.close()
    assert session_store.resolve_store_path(run_a) == Path(a_link["store_path"])
    assert session_store.resolve_session_id(run_a) == a_link.get("session_id")

    control = branch.open_source_store(run_b)
    try:
        assert Path(control.path).resolve() == Path(b_link["store_path"]).resolve()
    finally:
        control.connection.close()
    assert session_store.resolve_store_path(run_b) == Path(b_link["store_path"])


def test_a_hand_copied_run_folder_carries_no_case_link(tmp_path):
    """O3: a run folder copied by hand into another container (the copy holding whatever the
    original folder held) carries no case link: the branch's source-store lookup answers "no
    session" (`None`). The same copy with the old in-folder link planted in it is a run recorded
    before #1235 (round 2): it is refused, never opened through that link. Positive control: the
    original folder, with its sidecar, opens its store.

    Observed failing by: the copy opening the original's store through a link inside the folder."""
    run_dir = _finished_run(tmp_path / "a", "o3-copied")
    copy = tmp_path / "elsewhere" / "run"
    shutil.copytree(run_dir, copy)

    assert branch.source_store_if_any(copy) is None, \
        "a hand-copied folder opened a store through a link carried inside it"

    (copy / OLD_POINTER_NAME).write_text(json.dumps(_pointer(run_dir)), encoding="utf-8")
    with pytest.raises(branch.BranchError):
        branch.source_store_if_any(copy)

    handle = branch.source_store_if_any(run_dir)
    assert handle is not None, "the original run's sidecar opened no store"
    handle.connection.close()
