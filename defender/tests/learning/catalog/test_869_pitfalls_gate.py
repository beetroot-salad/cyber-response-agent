"""#869 M6/U1 — the pitfalls predicate (site 1). The `SKILL.md` probe goes."""
from __future__ import annotations

import pytest

from defender.tests.support.learning.curation._claim1175 import claim_git
from defender import _git
from defender.learning.leads import pitfalls_curator
from defender.learning.leads.lead_extraction import LeadAuthorError
from defender.learning.leads.path_validation import _is_in_scope
from defender.tests.support.runtime.engine._declared869 import (
    SKILLS_REL,
    is_system_name,
    head_files,
    pitfall_row,
    seed_tree,
    write,
)
from defender.tests.support.learning.curation._lead_author_1134 import lane_tree_for

DECLARED = frozenset({"elastic"})


def test_pitfalls_handoff_drops_an_undeclared_system(tmp_path):
    rows = [pitfall_row("r:0", "gather"), pitfall_row("r:1", "fakesys")]
    assert is_system_name("gather")
    assert is_system_name("fakesys")
    assert pitfalls_curator._build_pitfalls_handoffs(rows, systems=DECLARED) == []

    # And over the real tree's own names, where `gather` is the directory this issue is about.
    assert (_git.REPO_ROOT / SKILLS_REL / "gather" / "SKILL.md").is_file()
    assert pitfalls_curator._build_pitfalls_handoffs(
        [pitfall_row("r:2", "gather")], systems=frozenset({"elastic", "cmdb"})) == []


def test_pitfalls_handoff_keeps_a_declared_system(tmp_path):
    rows = [pitfall_row("r:0", "elastic"), pitfall_row("r:1", "gather")]
    handoffs = pitfalls_curator._build_pitfalls_handoffs(rows, systems=DECLARED)
    assert [h["system"] for h in handoffs] == ["elastic"]
    assert handoffs[0]["path"] == "defender/skills/elastic/execution.md"
    assert [f["query_id"] for f in handoffs[0]["failures"]] == ["elastic.esql"]


def test_system_name_shape_still_refuses_a_traversal(tmp_path):
    assert (_git.REPO_ROOT / "defender" / "SKILL.md").is_file()
    assert _is_in_scope("defender/skills/../SKILL.md")

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
    repo = seed_tree(tmp_path, adapters=("elastic",), markers=("elastic",),
                     skills=("elastic",), catalog=())
    with pytest.raises(LeadAuthorError):
        pitfalls_curator._pitfalls_path_rule(
            "A ", "defender/skills/fakesys/execution.md", systems=DECLARED)
    assert pitfalls_curator._pitfalls_path_rule(
        "A ", "defender/skills/elastic/execution.md", systems=DECLARED) is None

    write(repo / SKILLS_REL / "fakesys" / "execution.md", "# fakesys\n")
    before = head_files(repo)
    with pytest.raises(LeadAuthorError):
        pitfalls_curator._verify_pitfalls_state(
            repo, baseline_stray=[], systems=DECLARED, reducer_offered=False,
            tree_for=lane_tree_for(repo), git=claim_git(repo))
    assert head_files(repo) == before
