"""#747 — `RunTainted` is a systemic fault."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from defender.learning.core.faults import SYSTEMIC_FAULTS, run_or_dead_letter  # noqa: E402
from defender.box import RunTainted  # noqa: E402


# The drain cuts no worktree, so no drain tree is tainted or archived: a link or special file in
# a draft refuses its claim whole, and a claim reset never follows a box's links (both pinned in
# tenant_1108_delivery/test_changes.py). `RunTainted` stays systemic for the run dir's scrub.


def test_run_tainted_is_a_systemic_fault(tmp_path):
    """Both consequences are wanted: the stage exits 2, and no item is dead-lettered."""
    from defender.learning.core.cli import _run_stage

    assert RunTainted in SYSTEMIC_FAULTS

    def tainting_stage() -> int:
        raise RunTainted("planted link")

    assert _run_stage(tainting_stage) == 2

    dead_lettered: list[Exception] = []
    with pytest.raises(RunTainted):
        run_or_dead_letter(tainting_stage, dead_lettered.append)
    assert dead_lettered == [], "a taint was filed as an ordinary per-item failure"
