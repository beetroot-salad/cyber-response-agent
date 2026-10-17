"""#869 O3/RF6/RF7/FK-2/FK-17 — reported, never silently absorbed; and the durable record."""
from __future__ import annotations

import json
from pathlib import Path


from defender.learning.core import drains, persist
from defender.learning.core.config import LoopPaths
from defender.learning.leads import pitfalls_curator
from defender.learning.leads.lead_extraction import LeadAuthorError
from defender.tests._declared869 import (
    Spawn,
    head_files,
    marker_file,
    pitfall_row,
    read_rows,
    seed_tree,
    write,
)
from defender.tests._curator1134 import open_state
from defender.tests._lead_author_1134 import lead_trees
from defender.tests._state1135 import curation_row, curation_run_dir
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
    """A dropped row is never stamped `consumed_committed`, and never carries a
    `consumed_commit` sha.

    RF7, moved onto the MIXED batch by P9 because the all-dropped case cannot see it.
    Executed at this base: with two `elastic` rows, one undeclared `elastik` row and a real
    commit, ALL THREE consumed rows carry `consumed_category: consumed_committed` and the same
    `consumed_commit` — a commit whose only content was `elastic/execution.md`. The dropped row
    is not merely mis-categorised: it carries the sha of a commit that contains NOTHING about
    it, and `_rewrite_queue` attaches that provenance precisely BECAUSE the category claims a
    commit, so fixing the category withdraws the false provenance as a side effect.

    This demand is the NEGATIVE half; `dropped_row_takes_the_undeclared_category` is the
    positive one on the same address. The two declared rows are the control here: they DO
    carry the category and the sha, so a rotation that stamped nothing would not pass.
    """
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
    """A dropped row takes the DISTINCT TERMINAL category `consumed_unattributable` and goes to
    the graveyard record for a human to act on (FK-2, §7).

    `dropped_rows_are_never_labelled_committed`'s positive control on the same address: the
    negative alone is satisfied by any label at all, including one that reads like an ordinary
    skip. Over the same mixed batch, the two declared rows carry `consumed_committed` plus the
    real sha and the dropped row carries `consumed_unattributable` (#870 F4 renamed it:
    "undeclared" was false of a systemless row and of `../evil`), no `consumed_commit`, and a
    durable record naming it.

    REJECTED, and why: reusing `consumed_skip`, which already means something else to every
    one of the twelve assertion sites C39 censused; and leaving the row queued to be re-dropped
    every tick, which is the only reading that does not bound the queue. UN-GATED rather than
    merely recommended — P9 showed `batch_ids` is computed from the RAW rows before any
    dropping, so the dropped id IS inside it, pending goes to empty, and no path leaves an
    undeclared row stuck.
    """
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
    """A membership refusal on the lead-author leg is TERMINAL on the first tick and leaves
    one durable, re-drivable record — no retriable class, no burned attempts (FK-17, §7).

    PO-K/P6 refuted the judge's provisional outright before this reached the human:
    quarantine is terminal today, and `LEAD_AUTHOR_MAX_RETRIES` (3 TOTAL attempts, not 3
    retries) governs `_LeadAuthorRetry`, a class a membership refusal never raises. Driven over
    five ticks against a real marker queue with the lane refusing on membership: the marker is
    quarantined on the FIRST tick to `author-queue/failed/<case>.json` carrying the refusal
    reason and the name, the queued marker is unlinked, the lane is invoked exactly ONCE
    across the following ticks, and no attempt counter is burned.

    REJECTED, and asserted as rejected: the retriable class, whose automatic rescue costs
    three spawns per permanently-undeclared name, is reachable today only by raising the very
    `OSError`/`SubprocessError` class `resolver_failure_is_not_swallowed_as_a_successful_tick`
    forbids on the sibling pitfalls leg, and would leave an `attempts` counter on a requeued
    spec rather than a record.

    THE DEMAND STATES THAT THE RECORD EXISTS; IT DOES NOT ASSERT THE VIEW THAT READS IT.
    Re-driving it is #870's amendment and #903's view (`test_903_queue_view.py`), neither exercised here — so
    what is pinned is that the record retains everything a re-drive needs.
    """
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
