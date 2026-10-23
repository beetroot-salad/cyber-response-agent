"""#869 O3/RF6/RF7/FK-2/FK-17 — reported, never silently absorbed; and the durable record.

#1108 P4 (O7, OD12 class ii): the mixed pitfalls tick runs over a batch draft
(`_curator1134.draft_lane`), adapters in a product checkout; what landed is read from the batch
branch (`agent/...`), the lane entry takes the batch (ASSUMED SEAM S-H `run_pitfalls(..., batch=)`)."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path

import json
from pathlib import Path


from defender.learning.core import drains, persist
from defender.learning.core.config import LoopPaths
from defender.learning.leads import pitfalls_curator
from defender.learning.leads.lead_extraction import LeadAuthorError
from defender.tests.support.runtime.engine._declared869 import (
    Spawn,
    agent_marker_file,
    pitfall_row,
    read_rows,
    seed_agent_files,
    seed_product,
    seed_tree,
    write,
)
from defender.tests.support.learning.curation import _curator1134 as C
from defender.tests.support.learning.curation._curator1134 import open_state
from defender.tests.support.learning.core._state1135 import curation_row, curation_run_dir
from defender.learning.core.state import PITFALLS

DECLARED = frozenset({"elastic"})


def _mixed_batch(tmp_path: Path, monkeypatch, *, name: str = "repo"):
    """The mixed tick P9 executed: two `elastic` rows, one undeclared `elastik` row, and a
    curator edit that produces a REAL commit.

    P9 moved these demands onto the mixed batch on purpose. The all-dropped control is milder
    — its sha is `None` (C37) — and cannot see the defect at all: it takes a batch that DOES
    commit something for the dropped row to inherit a sha that has nothing to do with it."""
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "2")
    product = seed_product(tmp_path, adapters=("elastic",), name=f"product-{name}")
    lane = C.draft_lane(tmp_path, lanes=C.LEAD_LANES, product=product,
                        files=seed_agent_files(markers=("elastic",), skills=("elastic",),
                                               catalog=()),
                        state_dir=tmp_path / f"state-{name}")
    paths = lane.paths
    state = open_state(paths)
    persist.append_pitfalls(
        [pitfall_row("r:l-000:0", "elastic"),
         pitfall_row("r:l-001:0", "elastic"),
         pitfall_row("r:l-002:0", "elastik")],
        state=state,
    )
    spawn = Spawn(lambda root: write(
        agent_marker_file(root, "elastic"), "# elastic\n## Common pitfalls\n- curated\n",
    ), root=lane.root)
    return lane, paths, spawn


def _run(lane, state, spawn: Spawn) -> int:
    with C.draft_trees(lane) as trees:
        return pitfalls_curator.run_pitfalls(paths=lane.paths, state=state, invoke=spawn,
                                             trees=trees, batch=lane.batch)


def test_a_dropped_row_is_never_labelled_committed(tmp_path, monkeypatch):
    lane, paths, spawn = _mixed_batch(tmp_path, monkeypatch)
    state = open_state(paths)
    _run(lane, state, spawn)

    consumed = {r["pitfall_id"]: r for r in read_rows(location_path(paths.state_root) / PITFALLS.consumed)}
    assert set(consumed) == {"r:l-000:0", "r:l-001:0", "r:l-002:0"}
    assert "agent/skills/elastic/execution.md" in lane.landed()

    dropped = consumed["r:l-002:0"]
    assert dropped["consumed_category"] != "consumed_committed"
    assert dropped.get("consumed_commit") is None

    for kept in ("r:l-000:0", "r:l-001:0"):
        assert consumed[kept]["consumed_category"] == "consumed_committed"
        assert consumed[kept]["consumed_commit"]


def test_a_dropped_row_takes_a_terminal_undeclared_category(tmp_path, monkeypatch):
    lane, paths, spawn = _mixed_batch(tmp_path, monkeypatch, name="undeclared")
    state = open_state(paths)
    _run(lane, state, spawn)

    consumed = {r["pitfall_id"]: r for r in read_rows(location_path(paths.state_root) / PITFALLS.consumed)}
    assert consumed["r:l-002:0"]["consumed_category"] == "consumed_unattributable"
    assert "consumed_commit" not in consumed["r:l-002:0"]
    assert consumed["r:l-000:0"]["consumed_category"] == "consumed_committed"

    assert persist.read_pitfalls(state) == [], "pending must go empty; the row is terminal"
    graveyard = {r.get("pitfall_id") for r in read_rows(location_path(paths.state_root) / PITFALLS.deadletter)}
    assert "r:l-002:0" in graveyard, (
        "the dropped row leaves no durable record, so nothing reaches human review"
    )
    assert "r:l-000:0" not in graveyard
    assert "agent/skills/elastic/execution.md" in lane.landed()


def test_a_membership_refusal_is_terminal_and_leaves_a_re_drivable_record(tmp_path, capsys):
    repo = seed_tree(tmp_path, adapters=("elastic",), markers=("elastic",), skills=("elastic",),
                     catalog=())
    paths = LoopPaths(repo_root=repo, state_dir=tmp_path / "state")
    state = open_state(paths)
    # A natural run where the drain rehydrates the row (#1105 PR 2): the row is its address.
    run_dir = curation_run_dir("run-x")
    (run_dir / "gather_raw").mkdir()
    write(location_path(paths.state_root) / "author-queue" / "case-1.json",
          json.dumps(curation_row("case-1", run_dir)) + "\n")

    calls: list[Path] = []

    def refusing_lane(_paths, _state, run, *, box=None, **_kw):
        calls.append(run.run_dir)
        raise LeadAuthorError(
            "lead author refused: mcpsys is not a declared system in this tree")

    capsys.readouterr()
    for _tick in range(5):
        drains._drain_lead_author_markers(paths, state, refusing_lane,
                                          accept_tenant=drains._tenant_acceptor(paths.tenant))

    assert len(calls) == 1, f"the refusal was retried: {len(calls)} invocations"
    assert not (location_path(paths.state_root) / "author-queue" / "case-1.json").exists()
    assert not list((location_path(paths.state_root) / "author-queue" / "inflight").glob("*.json"))

    failed = location_path(paths.state_root) / "author-queue" / "failed" / "case-1.json"
    assert failed.is_file()
    record = json.loads(failed.read_text())
    assert "mcpsys" in record["failed"]
    assert (record["tenant_id"], record["run_id"]) == (run_dir.parent.parent.name, run_dir.name)
    assert record["case_id"] == "case-1"
    assert "attempts" not in record, (
        "an attempts counter means the retriable class was taken, which §7 declined"
    )
