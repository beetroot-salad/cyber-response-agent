"""Drain retire seam: an empty claim is inert.

Retired with the file queue (#1278 D1, design r8 Locks and Items: the store owns attempts, ceilings and the dead
letter; `drain.retire` and its graveyard are deleted):
- the lifetime attempt count surviving an intervening success and a fresh process, the ceiling of one retiring on the
  first failure, retirement scoped to the batch's ids (rows outside byte-identical), and a failing retirement write
  stopping the drain: all the store's claim bookkeeping, covered by
  `tests/learning/store_1278/test_items_1278.py::test_an_attempt_is_stamped_at_claim_and_forgiven_only_by_a_clean_stop`
  and `::test_crashes_to_the_ceiling_hold_the_item_for_a_person` (attempts live in the database, so another process
  sees them);
- a consumed row / graveyard row written by a live tick: the fates are the claim's `outcomes`
  (`test_773_deferral.py`, `test_drain719_guard.py` pin what a faulted claim leaves).
"""
from __future__ import annotations

from pathlib import Path

from defender.tests.support.learning.core._release1537 import outcome_dead, outcome_skipped
from defender.tests.support.learning.curation import _spec773 as S
from defender.learning.author import drain


def test_an_empty_claim_never_reaches_the_agent_and_decides_nothing(tmp_path: Path):
    """A claim of no items is rc 0: the curator is never called, no fate is written and nothing lands. The
    control (one row, a curator that faults) shows the same scene does reach the agent and returns rc 2."""
    sc = S.build_draft_scene(tmp_path, rows=[], curator=S.FakeCurator(raises=AssertionError("never called")))

    assert drain.run_batch(cfg=sc.cfg, items=[], outcomes=sc.outcomes) == 0
    assert sc.curator.calls == []
    assert sc.outcomes == {}
    assert sc.head_files() == []

    live = S.build_draft_scene(tmp_path / "live", rows=[S.finding_row("a/0", run_id="a")],
                               curator=S.FakeCurator(raises=S.author_error("so the agent is seen to run")))
    assert live.run() == 2
    assert len(live.curator.calls) == 1


def test_a_row_with_no_id_is_dead_as_malformed_naming_its_key_and_the_keyed_row_is_still_authored(tmp_path: Path):
    """An id-less row is dead at once with the cause `malformed_row` and the missing key named; the keyed row is not held back. (1537 R4)"""
    idless = {k: v for k, v in S.finding_row("x/0", run_id="x").items() if k != "finding_id"}
    sc = S.build_draft_scene(tmp_path, rows=[idless, S.finding_row("a/0", run_id="a")], curator=S.FakeCurator())
    sc.curator.writes = {"a.md": S.lesson("a/0")}

    assert sc.run() == 0
    assert sc.outcomes == {("finding", "unkeyed-0"): outcome_dead("malformed_row", "row carries no value under 'finding_id'")}
    assert sc.curator.calls, "control: the keyed row beside it reached the agent"


def test_a_world_finding_naming_no_systems_is_skipped_as_consumed_no_systems(tmp_path: Path):
    """The questioner's finding that names no systems drains unauthored, skipped with the cause `consumed_no_systems`. (1537 R4)"""
    sc = S.build_questioner_scene(tmp_path, rows=[S.world_row("w1", systems=[])], curator=S.FakeCurator())

    assert sc.run() == 0
    [(key, got)] = sc.outcomes.items()
    assert (key, got.name) == (("questioner_finding", "w1"), "skipped")
    assert got == outcome_skipped("consumed_no_systems", "consumed_no_systems: the world finding names no systems"), got
