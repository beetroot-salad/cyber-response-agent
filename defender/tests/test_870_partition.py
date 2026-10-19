"""#870 M8 — the partition follows the handoff, and what the tick tells a human."""
from __future__ import annotations

from pathlib import Path

import pytest

from defender.learning.core import drains, persist
from defender.learning.core.config import LoopPaths
from defender.learning.leads import pitfalls_curator
from defender.learning.leads.lead_extraction import LeadAuthorError
from defender.tests import _state1135
from defender.tests._declared870 import (
    REDUCER_REL,
    Spawn,
    by_surface,
    commit_all,
    consumed_by_id,
    curate_execution_md,
    curate_reducer_surface,
    edits,
    git,
    graveyard_by_id,
    head_files,
    pitfall_row,
    queue_ids,
    seed_tree,
    shim_row,
    write,
    write_reducer_surface,
)
from defender.tests._lead_author_1134 import lead_trees

ELASTIC_MD = "defender/skills/elastic/execution.md"


@pytest.fixture
def scene(tmp_path: Path, monkeypatch):
    """A committed worktree carrying the reducer surface, and a `LoopPaths` over state kept
    OUTSIDE it — a queue file inside the repo would read to the corpus-scope walk as a stray.

    The threshold is set to 1 so these demands are about the PARTITION rather than about the
    gate; FK-3's gate has its own file.
    """
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "1")
    repo = seed_tree(tmp_path, adapters=("elastic", "cmdb"), markers=("elastic",),
                     skills=("elastic",), catalog=(), non_systems=("gather",))
    write_reducer_surface(repo)
    commit_all(repo, "seed the reducer surface")
    return repo, LoopPaths(repo_root=repo, state_dir=tmp_path / "state")


def _shim_batch(paths, n: int = 3) -> list[str]:
    """N rows behind ONE reducer mistake — the l-003 shape, which is what a real reducer
    batch looks like. Appended through the production appender, into the real queue file."""
    rows = [shim_row(f"r:l-003:{i}") for i in range(n)]
    persist.append_pitfalls(rows, state=_state1135.state_for_paths(paths))
    return [r["pitfall_id"] for r in rows]


# FK-7 — a handoff is an OFFER; only a confirmed edit is curation.


def test_a_taught_reducer_row_is_consumed_not_retired(scene):
    repo, paths = scene
    ids = _shim_batch(paths)
    spawn = Spawn(curate_reducer_surface())
    head_before = git(repo, "rev-parse", "HEAD").stdout.strip()

    assert pitfalls_curator.run_pitfalls(paths=paths, invoke=spawn, trees=lead_trees(paths)) == 0
    assert by_surface(spawn.handoffs)["reducer"], "no reducer handoff, so the arm is vacuous"
    assert git(repo, "rev-parse", "HEAD").stdout.strip() != head_before, (
        "the curator's edit never reached a commit"
    )
    assert REDUCER_REL in head_files(repo), "the tick committed, but not the reducer surface"

    consumed = consumed_by_id(paths)
    assert set(consumed) == set(ids)
    for pid in ids:
        assert consumed[pid]["consumed_category"] == "consumed_committed"
        assert consumed[pid]["consumed_commit"], "a taught row carries no provenance"
    assert graveyard_by_id(paths) == {}, "a taught row reached the deadletter"
    assert queue_ids(paths) == []


def test_a_no_edit_reducer_tick_holds_its_rows(scene):
    repo, paths = scene
    ids = _shim_batch(paths)
    head_before = git(repo, "rev-parse", "HEAD").stdout.strip()
    spawn = Spawn(None)

    assert pitfalls_curator.run_pitfalls(paths=paths, invoke=spawn, trees=lead_trees(paths)) == 0
    assert by_surface(spawn.handoffs)["reducer"], "the offer was never made"

    assert queue_ids(paths) == ids, "the rows were consumed on a tick that taught nothing"
    assert consumed_by_id(paths) == {}
    assert graveyard_by_id(paths) == {}
    assert git(repo, "rev-parse", "HEAD").stdout.strip() == head_before, (
        "the tick committed something on a tick whose curator declined to edit"
    )

    # The second conjunct alone: a handoff WAS emitted, a commit DID land, and the reducer
    # literal is absent from its changed set.
    persist.append_pitfalls([pitfall_row("r:l-000:0", "elastic")], state=_state1135.state_for_paths(paths))
    taught_elsewhere = Spawn(curate_execution_md("elastic"))
    assert pitfalls_curator.run_pitfalls(paths=paths, invoke=taught_elsewhere,
                                         trees=lead_trees(paths)) == 0

    surfaces = by_surface(taught_elsewhere.handoffs)
    assert surfaces["reducer"], "the reducer entry was never offered on the mixed tick"
    assert git(repo, "rev-parse", "HEAD").stdout.strip() != head_before, (
        "nothing was committed, so this arm cannot see the second conjunct"
    )
    assert head_files(repo) == [ELASTIC_MD]
    assert REDUCER_REL not in head_files(repo)

    consumed = consumed_by_id(paths)
    assert consumed_by_id(paths).get("r:l-000:0", {}).get("consumed_category") == (
        "consumed_committed"
    ), "the system row that WAS taught must still be consumed — this arm is not a dead tick"
    for pid in ids:
        assert pid not in consumed, (
            f"{pid} was consumed on a tick that committed someone else's lesson — it now "
            f"carries a sha of a commit containing nothing about it"
        )
        assert pid not in graveyard_by_id(paths)
    assert set(queue_ids(paths)) == set(ids)


def test_an_unoffered_reducer_edit_is_refused(scene):
    repo, paths = scene
    persist.append_pitfalls([pitfall_row("r:l-000:0", "elastic")], state=_state1135.state_for_paths(paths))
    head_before = git(repo, "rev-parse", "HEAD").stdout.strip()
    overreach = Spawn(edits(curate_execution_md("elastic"), curate_reducer_surface()))

    with pytest.raises(LeadAuthorError, match="offered no reducer handoff"):
        pitfalls_curator.run_pitfalls(paths=paths, invoke=overreach, trees=lead_trees(paths))

    assert not by_surface(overreach.handoffs)["reducer"], (
        "the batch offered the reducer surface after all, so the demand is vacuous"
    )
    assert git(repo, "rev-parse", "HEAD").stdout.strip() == head_before, (
        "the unoffered reducer edit reached a commit"
    )
    # The PATH rule's verdict is untouched: the literal is still in the lane's vocabulary, and
    # what refused this tick is the offer, not the path.
    assert pitfalls_curator._pitfalls_path_rule(
        " M", REDUCER_REL, systems=frozenset({"elastic", "cmdb"}),
    ) is None

    # Positive control: one shim row makes the offer, and the identical edit now commits.
    _shim_batch(paths, n=1)
    offered = Spawn(edits(curate_execution_md("elastic"), curate_reducer_surface()))
    assert pitfalls_curator.run_pitfalls(paths=paths, invoke=offered, trees=lead_trees(paths)) == 0
    assert by_surface(offered.handoffs)["reducer"]
    assert REDUCER_REL in head_files(repo), "the offered edit was refused too"


def test_a_perpetually_declined_hold_retires_at_the_ceiling(scene, monkeypatch):
    monkeypatch.setenv("LEARNING_AUTHOR_MAX_ATTEMPTS", "3")
    repo, paths = scene
    ids = _shim_batch(paths)

    for tick in (1, 2):
        assert pitfalls_curator.run_pitfalls(paths=paths, invoke=Spawn(None),
                                             trees=lead_trees(paths)) == 0
        assert queue_ids(paths) == ids, f"the hold did not survive tick {tick}"
        assert [
            r.get(pitfalls_curator.OFFERS_DECLINED_KEY) for r in persist.read_pitfalls(_state1135.state_for_paths(paths))
        ] == [tick] * len(ids), f"the declined offer was not counted on tick {tick}"
        assert graveyard_by_id(paths) == {}, f"the row retired early, on tick {tick}"

    assert pitfalls_curator.run_pitfalls(paths=paths, invoke=Spawn(None),
                                         trees=lead_trees(paths)) == 0
    assert queue_ids(paths) == [], "the queue never drains, so the curator re-spawns forever"
    grave = graveyard_by_id(paths)
    assert set(grave) == set(ids)
    for pid in ids:
        assert grave[pid]["deadletter_reason"] == pitfalls_curator.HELD_CEILING_REASON, (
            "the retirement is filed as a fault, but the tick worked and the curator declined"
        )
    # Conserved, not merely gone: the retirement is terminal through the channel's own ledger.
    assert {
        pid: consumed_by_id(paths)[pid]["consumed_category"] for pid in ids
    } == {pid: "consumed_retired" for pid in ids}
    assert repo.is_dir()


def test_a_faulting_tick_does_not_spend_the_offer_budget(scene, monkeypatch):
    monkeypatch.setenv("LEARNING_AUTHOR_MAX_ATTEMPTS", "3")
    _repo, paths = scene
    ids = _shim_batch(paths, n=1)

    def _faulting(_paths, _state, box=None, **_kw):
        raise ImportError("the curator module vanished mid-tick")

    for tick in (1, 2):
        drains._drain_pitfalls(paths, _state1135.state_for_paths(paths), _faulting)
        assert queue_ids(paths) == ids, f"the faulting tick {tick} retired the row early"
    rows = persist.read_pitfalls(_state1135.state_for_paths(paths))
    assert [r.get("attempts") for r in rows] == [2], "the fault counter did not move"
    assert [r.get(pitfalls_curator.OFFERS_DECLINED_KEY) for r in rows] == [None], (
        "a tick that never offered the row spent its offer budget"
    )

    # The row now gets its FULL complement of declines — the third is what retires it, not the
    # first riding on two unrelated faults.
    for tick in (1, 2):
        assert pitfalls_curator.run_pitfalls(paths=paths, invoke=Spawn(None),
                                             trees=lead_trees(paths)) == 0
        assert queue_ids(paths) == ids, f"the row retired on decline {tick} of 3"
        assert [
            r.get(pitfalls_curator.OFFERS_DECLINED_KEY) for r in persist.read_pitfalls(_state1135.state_for_paths(paths))
        ] == [tick]
        assert graveyard_by_id(paths) == {}

    assert pitfalls_curator.run_pitfalls(paths=paths, invoke=Spawn(None),
                                         trees=lead_trees(paths)) == 0
    assert queue_ids(paths) == [], "the offer ceiling stopped bounding the hold"
    assert set(graveyard_by_id(paths)) == set(ids)


def test_a_reducer_only_batch_still_reaches_the_curator(scene):
    repo, paths = scene
    ids = _shim_batch(paths)
    spawn = Spawn(curate_reducer_surface())

    assert pitfalls_curator.run_pitfalls(paths=paths, invoke=spawn, trees=lead_trees(paths)) == 0
    assert spawn.calls, "the curator was never spawned for a batch that had a lesson"
    assert [e["surface"] for e in spawn.handoffs] == ["reducer"]
    assert set(consumed_by_id(paths)) == set(ids)
    assert graveyard_by_id(paths) == {}, (
        "the reducer-only batch took the `not handoffs` arm and was retired unread"
    )


def test_no_row_leaves_the_queue_without_a_record(scene):
    repo, paths = scene
    persist.append_pitfalls(
        [pitfall_row("r:l-000:0", "elastic"),
         pitfall_row("r:l-001:0", "newsys"),
         pitfall_row("r:l-002:0", "", digest="exit=1; a systemless non-shim row"),
         pitfall_row("r:l-003:0", "../evil"),
         shim_row("r:l-004:0")],
        state=_state1135.state_for_paths(paths),
    )
    every_id = {"r:l-000:0", "r:l-001:0", "r:l-002:0", "r:l-003:0", "r:l-004:0"}
    spawn = Spawn(edits(curate_execution_md("elastic"), curate_reducer_surface()))

    assert pitfalls_curator.run_pitfalls(paths=paths, invoke=spawn, trees=lead_trees(paths)) == 0

    consumed, graveyard = consumed_by_id(paths), graveyard_by_id(paths)
    assert queue_ids(paths) == []
    assert set(consumed) == every_id, "a row left the queue with no consumed record"

    committed = {i for i, r in consumed.items() if r["consumed_category"] == "consumed_committed"}
    unattributable = {
        i for i, r in consumed.items() if r["consumed_category"] == "consumed_unattributable"
    }
    assert committed | unattributable == every_id, "a third category appeared"
    assert committed == {"r:l-000:0", "r:l-004:0"}
    assert set(graveyard) == unattributable, (
        "an uncurated row left without a durable record, or a curated one gained one"
    )
    for pid in committed:
        assert consumed[pid]["consumed_commit"]
    for pid in unattributable:
        assert "consumed_commit" not in consumed[pid]


# What the commit carries, and what a human is told about it.


def test_the_commit_carries_exactly_what_the_rule_admitted(scene):
    repo, paths = scene
    _shim_batch(paths, n=1)
    persist.append_pitfalls([pitfall_row("r:l-000:0", "elastic")], state=_state1135.state_for_paths(paths))
    spawn = Spawn(edits(curate_execution_md("elastic"), curate_reducer_surface()))

    assert pitfalls_curator.run_pitfalls(paths=paths, invoke=spawn, trees=lead_trees(paths)) == 0

    message = git(repo, "log", "-1", "--pretty=%B").stdout
    named = sorted(
        line[2:].strip() for line in message.splitlines() if line.startswith("- ")
    )
    assert named == sorted([ELASTIC_MD, REDUCER_REL])
    assert sorted(head_files(repo)) == named, (
        "the commit carries paths the rule never adjudicated"
    )

    # The correction, executed: a newly-dirty non-`.md` file under the corpus refuses the
    # whole tick rather than riding it.
    persist.append_pitfalls([shim_row("r2:l-009:0", digest="exit=1; a second mistake")],
                            state=_state1135.state_for_paths(paths))
    stray = Spawn(edits(
        curate_reducer_surface("a second lesson"),
        lambda root: write(root / "defender" / "skills" / "gather" / "notes.txt", "dirt\n"),
    ))
    head_before = git(repo, "rev-parse", "HEAD").stdout.strip()
    with pytest.raises(LeadAuthorError) as exc:
        pitfalls_curator.run_pitfalls(paths=paths, invoke=stray, trees=lead_trees(paths))
    assert "outside" in str(exc.value)
    assert "notes.txt" in str(exc.value)
    assert git(repo, "rev-parse", "HEAD").stdout.strip() == head_before


# The composition frame — two ticks over one corpus tree and one queue.


def _leg(paths, spawn):
    """`_invoke_pitfalls`' shape, so the drain drives the REAL curation leg."""
    return lambda p, st, box=None, **_kw: pitfalls_curator.run_pitfalls(
        paths=p, state=st, invoke=spawn, box=box, trees=lead_trees(p))
