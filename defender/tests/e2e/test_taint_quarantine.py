"""#747 — `RunTainted` is a systemic fault."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from defender.learning.core.faults import SYSTEMIC_FAULTS  # noqa: E402
from defender.box import RunTainted  # noqa: E402


# The drain cuts no worktree, so no drain tree is tainted or archived: a link or special file in
# a draft refuses its claim whole, and a claim reset never follows a box's links (both pinned in
# tenant_1108_delivery/test_changes.py). `RunTainted` stays systemic for the run dir's scrub.


def test_run_tainted_is_a_systemic_fault(tmp_path):
    """Both consequences are wanted: the stage exits 2, and no item is given a fate (a tainted tree is never one item's
    failure: the lane halts and the claim's items are returned by the store, #1278 D1 / "Fates")."""
    from types import SimpleNamespace

    from defender.learning.core import drains
    from defender.learning.core.cli import _run_stage

    assert RunTainted in SYSTEMIC_FAULTS

    def tainting_stage() -> int:
        raise RunTainted("planted link")

    assert _run_stage(tainting_stage) == 2

    # retired: `run_or_dead_letter` (the per-item dead-letter wrapper) went with the file queue; the drain's work step over a
    # claim is where a step's fault is either contained to the item or halts the lane.
    held = SimpleNamespace(items=[("pitfall", "p1", {"pitfall_id": "p1"})])

    def pitfalls_step(*_a, **_k):
        raise tainting_stage()

    outcomes: dict = {}
    with pytest.raises(RunTainted):
        drains._store_lead_work(None, lambda *_a, **_k: None, pitfalls_step,
                                box=None, batch=None, held=held, feedback=None, outcomes=outcomes)
    assert outcomes == {}, "a taint was filed as an ordinary per-item failure"

    # Control: an ordinary fault is contained to its claim's items (they wait again), so the assertion above is about the taint.
    def failing_step(*_a, **_k):
        raise RuntimeError("one claim's failure")

    outcomes = {}
    drains._store_lead_work(None, lambda *_a, **_k: None, failing_step,
                            box=None, batch=None, held=held, feedback=None, outcomes=outcomes)
    assert [o.name for o in outcomes.values()] == ["waiting"], outcomes
