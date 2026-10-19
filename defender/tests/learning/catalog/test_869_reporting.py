"""#869 O3/RF6/RF7/FK-2/FK-17 — reported, never silently absorbed; and the durable record."""
from __future__ import annotations

import json
from pathlib import Path


from defender.learning.core import drains, persist
from defender.learning.core.config import LoopPaths
from defender.learning.leads import pitfalls_curator
from defender.learning.leads.lead_extraction import LeadAuthorError
from defender.tests.support.runtime.engine._declared869 import (
    Spawn,
    head_files,
    marker_file,
    pitfall_row,
    read_rows,
    seed_tree,
    write,
)
from defender.tests.support.learning.curation._curator1134 import open_state
from defender.tests.support.learning.curation._lead_author_1134 import lead_trees
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
    repo = seed_tree(tmp_path, adapters=("elastic",), markers=("elastic",),
                     skills=("elastic",), catalog=(), name=name)
    paths = LoopPaths(repo_root=repo, state_dir=tmp_path / f"state-{name}")
    state = open_state(paths)
    persist.append_pitfalls(
        [pitfall_row("r:l-000:0", "elastic"),
         pitfall_row("r:l-001:0", "elastic"),
         pitfall_row("r:l-002:0", "elastik")],
        state=state,
    )
    spawn = Spawn(lambda root: write(
        marker_file(root, "elastic"), "# elastic\n## Common pitfalls\n- curated\n",
    ))
    return repo, paths, spawn


def test_a_dropped_row_is_never_labelled_committed(tmp_path, monkeypatch):
    repo, paths, spawn = _mixed_batch(tmp_path, monkeypatch)
    state = open_state(paths)
    pitfalls_curator.run_pitfalls(paths=paths, state=state, invoke=spawn, trees=lead_trees(paths))

    consumed = {r["pitfall_id"]: r for r in read_rows(paths.state_root / PITFALLS.consumed)}
    assert set(consumed) == {"r:l-000:0", "r:l-001:0", "r:l-002:0"}
    assert "defender/skills/elastic/execution.md" in head_files(repo)

    dropped = consumed["r:l-002:0"]
    assert dropped["consumed_category"] != "consumed_committed"
    assert dropped.get("consumed_commit") is None

    for kept in ("r:l-000:0", "r:l-001:0"):
        assert consumed[kept]["consumed_category"] == "consumed_committed"
        assert consumed[kept]["consumed_commit"]


def test_a_dropped_row_takes_a_terminal_undeclared_category(tmp_path, monkeypatch):
    repo, paths, spawn = _mixed_batch(tmp_path, monkeypatch, name="undeclared")
    state = open_state(paths)
    pitfalls_curator.run_pitfalls(paths=paths, state=state, invoke=spawn, trees=lead_trees(paths))

    consumed = {r["pitfall_id"]: r for r in read_rows(paths.state_root / PITFALLS.consumed)}
    assert consumed["r:l-002:0"]["consumed_category"] == "consumed_unattributable"
    assert "consumed_commit" not in consumed["r:l-002:0"]
    assert consumed["r:l-000:0"]["consumed_category"] == "consumed_committed"

    assert persist.read_pitfalls(state) == [], "pending must go empty; the row is terminal"
    graveyard = {r.get("pitfall_id") for r in read_rows(paths.state_root / PITFALLS.deadletter)}
    assert "r:l-002:0" in graveyard, (
        "the dropped row leaves no durable record, so nothing reaches human review"
    )
    assert "r:l-000:0" not in graveyard
    assert repo.is_dir()


def test_a_membership_refusal_is_terminal_and_leaves_a_re_drivable_record(tmp_path, capsys):
    repo = seed_tree(tmp_path, adapters=("elastic",), markers=("elastic",), skills=("elastic",),
                     catalog=())
    paths = LoopPaths(repo_root=repo, state_dir=tmp_path / "state")
    state = open_state(paths)
    # A natural run where the drain rehydrates the row (#1105 PR 2): the row is its address.
    run_dir = curation_run_dir("run-x")
    (run_dir / "gather_raw").mkdir()
    write(paths.state_root / "author-queue" / "case-1.json",
          json.dumps(curation_row("case-1", run_dir)) + "\n")

    calls: list[Path] = []

    def refusing_lane(_paths, _state, run, *, box=None, **_kw):
        calls.append(run.run_dir)
        raise LeadAuthorError(
            "lead author refused: mcpsys is not a declared system in this tree")

    capsys.readouterr()
    for _tick in range(5):
        drains._drain_lead_author_markers(paths, state, refusing_lane,
                                          data_root=drains._data_root())

    assert len(calls) == 1, f"the refusal was retried: {len(calls)} invocations"
    assert not (paths.state_root / "author-queue" / "case-1.json").exists()
    assert not list((paths.state_root / "author-queue" / "inflight").glob("*.json"))

    failed = paths.state_root / "author-queue" / "failed" / "case-1.json"
    assert failed.is_file()
    record = json.loads(failed.read_text())
    assert "mcpsys" in record["failed"]
    assert (record["tenant_id"], record["run_id"]) == (run_dir.parent.parent.name, run_dir.name)
    assert record["case_id"] == "case-1"
    assert "attempts" not in record, (
        "an attempts counter means the retriable class was taken, which §7 declined"
    )
