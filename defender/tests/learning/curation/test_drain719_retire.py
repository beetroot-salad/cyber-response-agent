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
