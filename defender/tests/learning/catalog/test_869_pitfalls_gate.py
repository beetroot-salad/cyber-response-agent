"""#869 M6/U1 — the pitfalls predicate (site 1). The `SKILL.md` probe goes.

#1108 P4 (O7, OD6): handoff and gate paths are spelled `agent/skills/...`; the composed gate judges
the batch's `ChangeSet` over a git-free draft. ASSUMED SEAM (S-H): `_verify_pitfalls_state(root, *,
change_set, systems, reducer_offered, tree_for)` (the `ChangeSet` replaces `baseline_stray`/`git`).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from defender import _git
from defender.learning.core.lane_trees import DrainTrees
from defender.learning.leads import pitfalls_curator
from defender.learning.leads.lead_extraction import LeadAuthorError
from defender.learning.leads.path_validation import _is_in_scope
from defender.tests.support.learning.curation import _curator1134 as C
from defender.tests.support.runtime.engine._declared869 import (
    SKILLS_REL,
    is_system_name,
    pitfall_row,
)

DECLARED = frozenset({"elastic"})


def test_pitfalls_handoff_drops_an_undeclared_system(tmp_path):
    rows = [pitfall_row("r:0", "gather"), pitfall_row("r:1", "fakesys")]
    assert is_system_name("gather")
    assert is_system_name("fakesys")
    assert pitfalls_curator._build_pitfalls_handoffs(rows, systems=DECLARED) == []

    # And over the product tree's own names, where `gather` is the directory this issue is about
    # (a product skill that stays, O1).
    assert (_git.REPO_ROOT / SKILLS_REL / "gather" / "SKILL.md").is_file()
    assert pitfalls_curator._build_pitfalls_handoffs(
        [pitfall_row("r:2", "gather")], systems=frozenset({"elastic", "cmdb"})) == []


def test_pitfalls_handoff_keeps_a_declared_system(tmp_path):
    """#869 M6: a declared system's pitfalls are handed off at the tenant's `agent/` spelling (OD6)."""
    rows = [pitfall_row("r:0", "elastic"), pitfall_row("r:1", "gather")]
    handoffs = pitfalls_curator._build_pitfalls_handoffs(rows, systems=DECLARED)
    assert [h["system"] for h in handoffs] == ["elastic"]
    assert handoffs[0]["path"] == "agent/skills/elastic/execution.md"
    assert [f["query_id"] for f in handoffs[0]["failures"]] == ["elastic.esql"]


def test_system_name_shape_still_refuses_a_traversal(tmp_path):
    assert (_git.REPO_ROOT / "defender" / "SKILL.md").is_file()
    assert _is_in_scope("agent/skills/../SKILL.md")

    for bad in ("..", "", ".hidden", "a/b", "a\\b", "a\x00b"):
        assert is_system_name(bad) is False, bad
    for good in ("elastic", "change-mgmt", "host-state"):
        assert is_system_name(good) is True, good

    hostile = frozenset({"..", "", ".hidden", "elastic"})
    assert pitfalls_curator._build_pitfalls_handoffs(
        [pitfall_row("r:0", ".."), pitfall_row("r:1", ".hidden")], systems=hostile) == []
    assert [
        h["system"] for h in pitfalls_curator._build_pitfalls_handoffs(
            [pitfall_row("r:2", "elastic")], systems=hostile)
    ] == ["elastic"]


def test_pitfalls_path_rule_refuses_an_undeclared_directory(tmp_path):
    """#869 M6: an undeclared system's `execution.md` is refused, by the rule and the composed
    gate over the batch's claim; the batch commits nothing."""
    lane = C.draft_lane(tmp_path, lanes=C.LEAD_LANES,
                        files={"skills/elastic/execution.md": "# execution\n"})
    with pytest.raises(LeadAuthorError):
        pitfalls_curator._pitfalls_path_rule(
            "A ", "agent/skills/fakesys/execution.md", systems=DECLARED)
    assert pitfalls_curator._pitfalls_path_rule(
        "A ", "agent/skills/elastic/execution.md", systems=DECLARED) is None

    C.put(lane.skills_dir / "fakesys" / "execution.md", "# fakesys\n")
    with pytest.raises(LeadAuthorError):
        pitfalls_curator._verify_pitfalls_state(
            Path(lane.batch.draft_root), change_set=lane.batch.change_set(), systems=DECLARED,
            reducer_offered=False, tree_for=DrainTrees.open((lane.skills_dir,)).tree_for)
    assert lane.landed() == []
