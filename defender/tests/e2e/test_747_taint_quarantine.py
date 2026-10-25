"""#747 — `RunTainted` is a systemic fault. (The drain-worktree quarantine rows are retired by #1108 P4; see below.)"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from defender.learning.core.faults import SYSTEMIC_FAULTS, run_or_dead_letter  # noqa: E402
from defender.box import RunTainted  # noqa: E402


# The drain-worktree quarantine rows of #747 (the tainted tree archived as an inert tar with a
# manifest, capped by refusal, never evicting; the taint propagating with nothing pushed) are
# retired by #1108 P4 (OD12 class i): the P4 drain cuts no worktree and never scrubs its draft
# (amendment 3 C3), so no drain tree is tainted or archived. A link or special file in a draft
# refuses its claim whole (tenant_1108_delivery/test_changes.py::
# test_a_claim_holding_anything_but_in_lane_regular_files_is_refused_whole), a claim reset never
# follows a box's links (::test_a_claim_reset_resyncs_the_draft_and_never_follows_box_links).
# `RunTainted` stays systemic for the investigation run dir's scrub, below.


def test_run_tainted_is_a_systemic_fault(tmp_path):
    """d_taint_is_systemic (#747, O3 + M2) — `RunTainted` is classified with the systemic faults,
    which has two consequences and both are wanted."""
    from defender.learning.core.cli import _run_stage

    assert RunTainted in SYSTEMIC_FAULTS

    def tainting_stage() -> int:
        raise RunTainted("planted link")

    assert _run_stage(tainting_stage) == 2

    dead_lettered: list[Exception] = []
    with pytest.raises(RunTainted):
        run_or_dead_letter(tainting_stage, dead_lettered.append)
    assert dead_lettered == [], "a taint was filed as an ordinary per-item failure"
