"""#870 — the threshold under normalization, and the three readers of the count it moves.

#1108 P4 (O7, OD12 class ii): every lane tick runs over a batch draft (`_curator1134.draft_lane`,
the tenant's `agent/skills` with the pitfalls add-on), adapters in a product checkout; the lane
entry takes the batch (ASSUMED SEAM S-H `run_pitfalls(..., batch=)`)."""
from __future__ import annotations


from pathlib import Path

import pytest

from defender.learning.core import drains, persist
from defender.learning.core.config import pitfalls_threshold
from defender.learning.leads import pitfalls_curator
from defender.learning.leads.lead_extraction import (
    collect_general_failures,
)
from defender.tests.support.learning.core._declared870 import (
    REDUCER_REL,
    Spawn,
    by_surface,
    curate_agent_execution_md,
    graveyard_by_id,
    pitfall_row,
    queue_ids,
    reducer_surface_text,
    seed_agent_files,
    seed_product,
    shim_lead,
    shim_row,
    silent_shim_row,
)
from defender.tests.support.learning.curation import _curator1134 as C
from defender.tests.support.learning.curation._curator1134 import open_state


@pytest.fixture
def scene(tmp_path: Path):
    """The tenant draft (elastic's marker and skill, `gather`, the reducer add-on, no catalog)
    over a product checkout declaring the elastic and cmdb adapters; `paths` the lane's
    learning paths (product-rooted, OD16)."""
    product = seed_product(tmp_path, adapters=("elastic", "cmdb"))
    files = seed_agent_files(markers=("elastic",), skills=("elastic",), catalog=(),
                             non_systems=("gather",))
    files[REDUCER_REL.removeprefix("agent/")] = reducer_surface_text()
    lane = C.draft_lane(tmp_path, lanes=C.LEAD_LANES, product=product, files=files)
    return lane, lane.paths


def _run(lane, invoke: Spawn) -> int:
    """`run_pitfalls` over the lane's draft (its held `skills/` mount and its batch)."""
    with C.draft_trees(lane) as trees:
        return pitfalls_curator.run_pitfalls(paths=lane.paths, invoke=invoke, trees=trees,
                                             batch=lane.batch)


def _tick(lane) -> Spawn:
    """One curation tick with a curator that declines to edit — so what is observed is the
    GATE (was the curator reached at all), never what the curator then did."""
    spawn = Spawn(None)
    assert _run(lane, spawn) == 0
    assert spawn.calls, "the tick gate refused the batch — the curator was never spawned"
    return spawn


# FK-3 — the arrival condition.


def test_the_threshold_gates_on_a_records_own_occurrences(scene, monkeypatch):
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "3")
    lane, paths = scene
    persist.append_pitfalls([shim_row(f"r:l-003:{i}") for i in range(3)], state=open_state(paths))

    records = persist.merge_pitfalls(persist.read_pitfalls(open_state(paths)))
    assert len(records) == 1, "the three shim rows did not merge to one record"
    assert records[0]["occurrences"] == 3
    assert len(records) < pitfalls_threshold(), (
        "the record-counting reading no longer refuses this batch, so the demand is vacuous"
    )

    assert drains._has_lead_author_work(open_state(paths)) is True, "the drain never wakes for it"
    assert by_surface(_tick(lane).handoffs)["reducer"], "the tick gate refused it"


def test_the_motivating_incident_reaches_the_curator_alone(scene, monkeypatch):
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "3")
    lane, paths = scene
    persist.append_pitfalls(
        collect_general_failures(
            [shim_lead(sql=f"SELECT unnest(data, {i})", query_index=i) for i in range(8)],
            Path("reviewer-measure-0807-b"), catalog=[],
        ),
        state=open_state(paths),
    )
    records = persist.merge_pitfalls(persist.read_pitfalls(open_state(paths)))
    assert [r["occurrences"] for r in records] == [8], "the eight reduces did not merge to one"
    assert records[0]["system"] == ""

    assert drains._has_lead_author_work(open_state(paths)) is True
    spawn = _tick(lane)
    assert [e["surface"] for e in spawn.handoffs] == ["reducer"]
    assert spawn.handoffs[0]["failures"][0]["occurrences"] == 8


def test_silent_reducer_failures_alone_do_not_open_the_lane(scene, monkeypatch):
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "3")
    lane, paths = scene
    below = [silent_shim_row(f"r:l-00{i}:0") for i in range(2)]
    persist.append_pitfalls(below, state=open_state(paths))

    records = persist.merge_pitfalls(persist.read_pitfalls(open_state(paths)))
    assert len(records) == 2, "the two silent rows did not merge to two distinct records"
    assert {r["occurrences"] for r in records} == {1}
    assert drains._has_lead_author_work(open_state(paths)) is False, "silent noise woke the drain"
    shut = Spawn(None)
    assert _run(lane, shut) == 0
    assert shut.calls == [], "silent noise alone reached the curator"
    assert queue_ids(paths) == [r["pitfall_id"] for r in below]

    # Above threshold the COUNT clears it — the pre-existing route, unchanged — while every
    # record is still worth exactly one occurrence, so FK-3's disjunct cannot be what fired.
    persist.append_pitfalls(
        [silent_shim_row(f"r:l-01{i}:0") for i in range(6)], state=open_state(paths),
    )
    records = persist.merge_pitfalls(persist.read_pitfalls(open_state(paths)))
    assert len(records) == 8
    assert max(r["occurrences"] for r in records) == 1, (
        "a content-less digest accumulated, so PO-R2's invariant no longer holds and this "
        "demand's whole ground is gone"
    )
    assert drains._has_lead_author_work(open_state(paths)) is True, (
        "the pre-existing distinct-count gate stopped opening — FK-3 adds a disjunct, it "
        "does not remove the count"
    )
    offered = Spawn(None)
    assert _run(lane, offered) == 0
    assert offered.calls, "the tick gate refused a batch its own count clears"
    assert [e["surface"] for e in offered.calls[-1]["handoffs"]] == ["reducer"]
    assert len(queue_ids(paths)) == 8, (
        "the undiagnosable batch was consumed on the tick it was merely offered — FK-7's "
        "hold is what makes this round's noisier arrival safe rather than lossy"
    )
    assert graveyard_by_id(paths) == {}


def test_the_system_lane_still_curates_at_its_own_threshold(scene, monkeypatch):
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "3")
    lane, paths = scene
    persist.append_pitfalls(
        [pitfall_row("r:l-000:0", "elastic"),
         pitfall_row("r:l-001:0", "cmdb"),
         shim_row("r:l-003:0")],
        state=open_state(paths),
    )
    records = persist.merge_pitfalls(persist.read_pitfalls(open_state(paths)))
    assert len(records) == 3, "the fixture no longer sits exactly on the count boundary"
    assert max(r["occurrences"] for r in records) == 1, (
        "some record clears the new disjunct on its own, so this says nothing about the count"
    )

    assert drains._has_lead_author_work(open_state(paths)) is True, (
        "the wake gate stopped counting the reducer record, so the system rows never even "
        "reach a tick"
    )
    spawn = Spawn(curate_agent_execution_md("elastic"))
    assert _run(lane, spawn) == 0
    assert spawn.calls, "the tick gate refused a batch that clears its own count"
    # Read shape-independently: whether the system lane still curates is a question about the
    # GATE, and it must not be answerable only through the key M6 adds.
    assert sorted(
        str(h["system"]) for h in spawn.calls[-1]["handoffs"] if h.get("system")
    ) == ["cmdb", "elastic"], "the system lane stopped curating at its own threshold"
    assert by_surface(spawn.handoffs)["reducer"], (
        "the reducer entry vanished from the mixed batch"
    )


# The other two readers of the same moved count.
