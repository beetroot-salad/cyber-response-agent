"""#870: the partition follows the handoff, and the commit says what it carries.

#1278: the pitfalls curator is handed a claim's items (`items=`) and fills the `outcomes` the batch's end applies (design r8
D1/D9): a taught row is reported committed (it stays in its batch until the merge), a row nothing can teach takes its own
fate at once (skipped, naming why; dead if unkeyable), and a row the curator declined is left undecided. The file queue's
consumed ledger, graveyard and `offers_declined` bump are gone (design r8 Schema "Retired files").

Retired from this file: `test_a_faulting_tick_does_not_spend_the_offer_budget` (the offer counter bumped by a tick's decline and
spared by a faulting one: nothing in the store flow writes `offers_declined` now; a faulting request tick's accounting is
`test_loop.py::test_lead_author_drain_contains_a_poison_request_and_counts_its_attempt`).

Every scene is a git-free draft of a batch over the fixture tenant (`_curator1134.draft_lane`). The
reducer surface is the tenant add-on `REDUCER_REL`, a system's page is
`agent/skills/<system>/execution.md`, and what a tick committed is read from the batch branch.
`paths.repo_root` is the product checkout, holding only the adapters.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from defender.learning.leads import pitfalls_curator
from defender.learning.leads.lead_extraction import LeadAuthorError
from defender.tests.support.learning.core._declared870 import (
    Claim,
    REDUCER_REL,
    Spawn,
    by_surface,
    curate_agent_execution_md,
    curate_reducer_surface,
    edits,
    pitfall_row,
    reducer_surface_text,
    seed_agent_files,
    seed_product,
    shim_row,
    tick as _tick,
    write,
)
from defender.tests.support.learning.curation import _curator1134 as C

ELASTIC_MD = "agent/skills/elastic/execution.md"


@pytest.fixture
def scene(tmp_path: Path, monkeypatch) -> C.DraftLane:
    """A started batch whose base carries the reducer add-on, the declared `elastic` marker and
    skill, and the `gather` non-system skill; the product checkout holds the `elastic` and `cmdb`
    adapters. Learning state lives outside the draft (a queue file in the corpus reads as a stray).
    Threshold 1 keeps these tests about the partition, not the gate (`test_870_threshold.py`).
    """
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "1")
    product = seed_product(tmp_path, adapters=("elastic", "cmdb"))
    files = {**seed_agent_files(markers=("elastic",), skills=("elastic",), catalog=(),
                                non_systems=("gather",)),
             REDUCER_REL.removeprefix("agent/"): reducer_surface_text()}
    return C.draft_lane(tmp_path, lanes=C.LEAD_LANES, files=files, product=product)


def _spawn(lane: C.DraftLane, edit=None) -> Spawn:
    """The curator spawn, its edit run against the batch draft's root (which holds `agent/`)."""
    return Spawn(edit, root=Path(lane.batch.draft_root))


def _tip_files(lane: C.DraftLane) -> list[str]:
    """What the batch branch's newest commit changed (`agent/...`); nothing before its first."""
    if lane.tip() == lane.base:
        return []
    return lane.git("show", "--name-only", "--pretty=format:", lane.tip()).stdout.split()


def _shim_batch(claim: Claim, n: int = 3) -> list[str]:
    """`n` rows behind one reducer mistake (the shape of a real reducer batch), added to the claim."""
    return claim.add(*[shim_row(f"r:l-003:{i}") for i in range(n)])


# A handoff is an offer; only a confirmed edit is curation.


def test_a_taught_reducer_row_is_reported_committed_not_retired(scene):
    """A reducer-only batch reaches the curator, and its taught rows are reported committed (they stay in the batch for the
    merge), none decided as retired."""
    lane, claim = scene, Claim()
    ids = _shim_batch(claim)
    spawn = _spawn(lane, curate_reducer_surface())
    head_before = lane.tip()

    assert _tick(lane, spawn, claim) == 0
    assert [e["surface"] for e in spawn.handoffs] == ["reducer"], (
        "the reducer-only batch never reached the curator with its one offer")
    assert lane.tip() != head_before, "the curator's edit never reached a commit"
    assert REDUCER_REL in _tip_files(lane), "the tick committed, but not the reducer surface"
    assert claim.committed == set(ids), "a taught row was not reported committed"
    assert claim.outcomes == {}, f"a taught row was decided as other than committed: {claim.outcomes}"


def test_a_no_edit_reducer_tick_holds_its_rows(scene):
    lane, claim = scene, Claim()
    ids = _shim_batch(claim)
    head_before = lane.tip()
    spawn = _spawn(lane)

    assert _tick(lane, spawn, claim) == 0
    assert by_surface(spawn.handoffs)["reducer"], "the offer was never made"

    assert claim.committed == set(), "the rows were reported committed on a tick that taught nothing"
    assert claim.outcomes == {}, "the rows were decided on a tick that taught nothing"
    assert lane.tip() == head_before, "the tick committed something on a tick whose curator declined to edit"

    # The second conjunct alone: a handoff WAS emitted, a commit DID land, and the reducer
    # literal is absent from its changed set.
    system_ids = claim.add(pitfall_row("r:l-000:0", "elastic"))
    taught_elsewhere = _spawn(lane, curate_agent_execution_md("elastic"))
    assert _tick(lane, taught_elsewhere, claim) == 0

    surfaces = by_surface(taught_elsewhere.handoffs)
    assert surfaces["reducer"], "the reducer entry was never offered on the mixed tick"
    assert lane.tip() != head_before, "nothing was committed, so this arm cannot see the second conjunct"
    assert _tip_files(lane) == [ELASTIC_MD]
    assert REDUCER_REL not in _tip_files(lane)
    assert claim.committed == set(system_ids), (
        "the system row that WAS taught must be reported committed, and no reducer row beside it — a reducer row "
        "reported committed names a commit containing nothing about it")
    assert claim.outcomes == {}


def test_an_unoffered_reducer_edit_is_refused(scene):
    lane, claim = scene, Claim()
    claim.add(pitfall_row("r:l-000:0", "elastic"))
    head_before = lane.tip()
    overreach = _spawn(lane, edits(curate_agent_execution_md("elastic"), curate_reducer_surface()))

    with pytest.raises(LeadAuthorError, match="offered no reducer handoff"):
        _tick(lane, overreach, claim)

    assert not by_surface(overreach.handoffs)["reducer"], (
        "the batch offered the reducer surface after all, so the test is vacuous"
    )
    assert lane.tip() == head_before, "the unoffered reducer edit reached a commit"
    # The PATH rule's verdict is untouched: the literal is still in the lane's vocabulary, and
    # what refused this tick is the offer, not the path.
    assert pitfalls_curator._pitfalls_path_rule(
        " M", REDUCER_REL, systems=frozenset({"elastic", "cmdb"}),
    ) is None

    # Positive control: one shim row makes the offer, and the identical edit now commits.
    _shim_batch(claim, n=1)
    offered = _spawn(lane, edits(curate_agent_execution_md("elastic"), curate_reducer_surface()))
    assert _tick(lane, offered, claim) == 0
    assert by_surface(offered.handoffs)["reducer"]
    assert REDUCER_REL in _tip_files(lane), "the offered edit was refused too"


def test_no_row_is_left_without_a_fate(scene):
    """Every row of the claim is either reported committed or decided at once (skipped, naming why); none is left undecided
    by a tick that curated. (The rows used to leave the queue with a consumed or graveyard record.)"""
    lane, claim = scene, Claim()
    claim.add(
        pitfall_row("r:l-000:0", "elastic"),
        pitfall_row("r:l-001:0", "newsys"),
        pitfall_row("r:l-002:0", "", digest="exit=1; a systemless non-shim row"),
        pitfall_row("r:l-003:0", "../evil"),
        shim_row("r:l-004:0"),
    )
    every_id = {"r:l-000:0", "r:l-001:0", "r:l-002:0", "r:l-003:0", "r:l-004:0"}
    spawn = _spawn(lane, edits(curate_agent_execution_md("elastic"), curate_reducer_surface()))

    assert _tick(lane, spawn, claim) == 0

    decided = {key for (_kind, key) in claim.outcomes}
    assert claim.committed == {"r:l-000:0", "r:l-004:0"}
    assert decided == every_id - claim.committed, "an uncurated row was left undecided, or a curated one was decided"
    assert claim.committed | decided == every_id
    assert all(o.name == "skipped" and o.reason for o in claim.outcomes.values()), "an unteachable row has no recorded reason"


# What the commit carries, and what a human is told about it.


def test_the_commit_carries_exactly_what_the_rule_admitted(scene):
    lane, claim = scene, Claim()
    _shim_batch(claim, n=1)
    claim.add(pitfall_row("r:l-000:0", "elastic"))
    spawn = _spawn(lane, edits(curate_agent_execution_md("elastic"), curate_reducer_surface()))

    assert _tick(lane, spawn, claim) == 0

    message = lane.message()
    named = sorted(
        line[2:].strip() for line in message.splitlines() if line.startswith("- ")
    )
    assert named == sorted([ELASTIC_MD, REDUCER_REL])
    assert sorted(_tip_files(lane)) == named, (
        "the commit carries paths the rule never adjudicated"
    )

    # A newly-dirty non-`.md` file under the corpus refuses the whole tick rather than riding it.
    claim.add(shim_row("r2:l-009:0", digest="exit=1; a second mistake"))
    stray = _spawn(lane, edits(
        curate_reducer_surface("a second lesson"),
        lambda root: write(root / "agent" / "skills" / "gather" / "notes.txt", "dirt\n"),
    ))
    head_before = lane.tip()
    with pytest.raises(LeadAuthorError) as exc:
        _tick(lane, stray, claim)
    assert "outside" in str(exc.value)
    assert "notes.txt" in str(exc.value)
    assert lane.tip() == head_before
