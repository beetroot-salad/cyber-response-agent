"""#870: the pitfalls threshold under normalization, as the drain's wake gate and the claim read it.

#1278: the gate is the store's claim rule (design r8 Lead-author lane: pitfall items at `LEARNING_PITFALLS_THRESHOLD`, read by
`store_tick.lane_waiting`), observed over `add_pitfall` rows in the real store with the curator tick run over a batch draft
(`_curator1134.draft_lane`, adapters in a product checkout). The tick gate that refused an under-threshold queue inside
`run_pitfalls` is gone: a tick is only made for a claim the wake gate found, so a refused batch is a lane that never wakes.

Retired from this file: nothing; the file queue's consumed ledger and graveyard assertions became "the rows stay waiting".
"""
from __future__ import annotations

from pathlib import Path

import pytest

from defender.learning.leads.lead_extraction import collect_general_failures
from defender.tests.support.learning.core._declared870 import (
    REDUCER_REL,
    Claim,
    Spawn,
    by_surface,
    curate_agent_execution_md,
    lead_wakes,
    pitfall_items,
    pitfall_row,
    queue_pitfalls,
    reducer_surface_text,
    seed_agent_files,
    seed_product,
    shim_lead,
    shim_row,
    silent_shim_row,
    tick,
)
from defender.tests.support.learning.core._store1278 import migrated_database, world  # noqa: F401 — fixtures
from defender.tests.support.learning.curation import _curator1134 as C
from defender.tests.tenancy.tenant_1108_p4.conftest import p4_tenant  # noqa: F401 — fixture `world` is built on

pytestmark = pytest.mark.postgres


@pytest.fixture
def lane(tmp_path: Path):
    """The tenant draft (elastic's marker and skill, `gather`, the reducer add-on, no catalog) over a product checkout
    declaring the elastic and cmdb adapters."""
    product = seed_product(tmp_path, adapters=("elastic", "cmdb"))
    files = seed_agent_files(markers=("elastic",), skills=("elastic",), catalog=(), non_systems=("gather",))
    files[REDUCER_REL.removeprefix("agent/")] = reducer_surface_text()
    return C.draft_lane(tmp_path, lanes=C.LEAD_LANES, product=product, files=files)


def _offer(lane, w, spawn: Spawn) -> Claim:
    """One tick over the draft, handed the store's waiting pitfalls as its claim."""
    claim = Claim()
    claim.rows = [i.payload for i in pitfall_items(w).values() if i.status == "waiting"]
    assert tick(lane, spawn, claim) == 0
    assert spawn.calls, "the curator was never spawned for the claim"
    return claim


# The arrival condition.


def test_the_threshold_gates_on_a_records_own_occurrences(world, lane, monkeypatch):  # noqa: F811 — the imported fixture
    """Three occurrences of one reducer mistake wake the lane at threshold 3, and the claim's curator is handed the one record."""
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "3")
    queue_pitfalls(world, *[shim_row(f"r:l-003:{i}") for i in range(3)])

    assert lead_wakes(world) is True, "the drain never wakes for it"
    spawn = Spawn(None)
    _offer(lane, world, spawn)
    [reducer] = by_surface(spawn.handoffs)["reducer"]
    assert reducer["failures"][0]["occurrences"] == 3


def test_the_motivating_incident_reaches_the_curator_alone(world, lane, monkeypatch):  # noqa: F811 — the imported fixture
    """Eight failed reduces of one diagnosis wake the lane at threshold 3 and reach the curator as one reducer record."""
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "3")
    queue_pitfalls(world, *collect_general_failures(
        [shim_lead(sql=f"SELECT unnest(data, {i})", query_index=i) for i in range(8)],
        Path("reviewer-measure-0807-b"), catalog=[]))

    assert lead_wakes(world) is True
    spawn = Spawn(None)
    _offer(lane, world, spawn)
    assert [e["surface"] for e in spawn.handoffs] == ["reducer"]
    assert spawn.handoffs[0]["failures"][0]["occurrences"] == 8


def test_silent_reducer_failures_alone_do_not_open_the_lane(world, lane, monkeypatch):  # noqa: F811 — the imported fixture
    """Two content-less failures are below threshold 3 and never wake the lane; six more (eight distinct records, each
    worth one occurrence) clear it by count, and the tick that is only offered them leaves them all waiting."""
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "3")
    queue_pitfalls(world, *[silent_shim_row(f"r:l-00{i}:0") for i in range(2)])
    assert lead_wakes(world) is False, "silent noise woke the drain"

    queue_pitfalls(world, *[silent_shim_row(f"r:l-01{i}:0") for i in range(6)])
    assert lead_wakes(world) is True, "the distinct-count gate no longer opens on this batch"
    offered = Spawn(None)
    claim = _offer(lane, world, offered)
    assert [e["surface"] for e in offered.calls[-1]["handoffs"]] == ["reducer"]
    assert claim.committed == set() and claim.outcomes == {}, "the undiagnosable batch was decided on the tick it was only offered"
    assert {i.status for i in pitfall_items(world).values()} == {"waiting"}
    assert len(pitfall_items(world)) == 8


def test_the_system_lane_still_curates_at_its_own_threshold(world, lane, monkeypatch):  # noqa: F811 — the imported fixture
    """One row for each of elastic, cmdb and the reducer sits exactly on threshold 3: the lane wakes and the curator is
    handed the two systems and the reducer entry."""
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "3")
    queue_pitfalls(world, pitfall_row("r:l-000:0", "elastic"), pitfall_row("r:l-001:0", "cmdb"), shim_row("r:l-003:0"))

    assert lead_wakes(world) is True, "the wake gate stopped counting the reducer record, so the system rows never reach a tick"
    spawn = Spawn(curate_agent_execution_md("elastic"))
    _offer(lane, world, spawn)
    assert sorted(str(h["system"]) for h in spawn.calls[-1]["handoffs"] if h.get("system")) == ["cmdb", "elastic"], \
        "the system lane stopped curating at its own threshold"
    assert by_surface(spawn.handoffs)["reducer"], "the reducer entry vanished from the mixed batch"
