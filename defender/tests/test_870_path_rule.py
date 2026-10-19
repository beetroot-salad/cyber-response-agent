"""#870 M7 — one literal allowance in the path rule, and everything it must not relax."""
from __future__ import annotations

import unicodedata
from pathlib import Path

import pytest

from defender.learning.leads import lead_author, pitfalls_curator
from defender.learning.leads.lead_extraction import LeadAuthorError
from defender.runtime.permission.files import build_write_allow
from defender.tests._declared870 import (
    DELETING_SHAPES,
    REDUCER_REL,
    STATUS_SHAPES,
    seed_tree,
    write,
    write_reducer_surface,
)
from defender.tests._lead_author_1134 import lane_tree_for

DECLARED = frozenset({"elastic", "cmdb"})
ELASTIC_MD = "defender/skills/elastic/execution.md"


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    tree = seed_tree(tmp_path, adapters=("elastic", "cmdb"), markers=("elastic",),
                     skills=("elastic",), catalog=(), non_systems=("gather",))
    write_reducer_surface(tree)
    return tree


def test_the_reducer_surface_cannot_be_deleted():
    for path in (REDUCER_REL, ELASTIC_MD):
        for xy in STATUS_SHAPES:
            if xy in DELETING_SHAPES:
                with pytest.raises(LeadAuthorError) as exc:
                    pitfalls_curator._pitfalls_path_rule(xy, path, systems=DECLARED)
                message = str(exc.value)
                assert "deleted" in message, (
                    f"{path} at {xy!r} was refused for the wrong reason ({message}) — the "
                    f"allowance returned early and U4 was not inherited"
                )
                assert "non-execution.md" not in message
            else:
                assert pitfalls_curator._pitfalls_path_rule(
                    xy, path, systems=DECLARED,
                ) is None, f"{path} at {xy!r} was refused as though it were a deletion"


def test_the_allowance_is_exactly_one_literal():
    refused = (
        "defender/skills/gather/SKILL.md",
        "defender/skills/gather/synthetic-reference.md",
        "defender/skills/gather/failure-modes.md",
        "defender/skills/gather/queries/elastic/x.md",
        "defender/skills/gather/defender-sql.md/x.md",
        "defender/skills/gather/sub/defender-sql.md",
        "defender/skills/gather/../gather/defender-sql.md",
        "defender/skills/gather/Defender-SQL.md",
        "defender/skills/gather/defender-sql.markdown",
    )
    for path in refused:
        with pytest.raises(LeadAuthorError):
            pitfalls_curator._pitfalls_path_rule(" M", path, systems=DECLARED)
    assert pitfalls_curator._pitfalls_path_rule(" M", REDUCER_REL, systems=DECLARED) is None


def test_the_path_rule_and_the_live_write_grant_agree_on_one_literal(repo):
    grant = build_write_allow(repo / "defender" / "skills", suffix=".md")
    combining = "defender/skills/gather/defender-sq́l.md"
    assert unicodedata.normalize("NFC", REDUCER_REL) == REDUCER_REL

    textual_variants = (
        "defender/skills/gather/DEFENDER-SQL.MD",
        "defender/skills/gather/defender-sql.MD",
        combining,
        unicodedata.normalize("NFC", combining),
        unicodedata.normalize("NFD", combining),
        REDUCER_REL + "\x00.md",
        "defender/skills/defender/skills/gather/defender-sql.md",
        REDUCER_REL + "/",
        "defender/skills/gather/./defender-sql.md",
        "defender/skills/gather/../gather/defender-sql.md",
    )
    for variant in textual_variants:
        assert variant != REDUCER_REL
        with pytest.raises(LeadAuthorError):
            pitfalls_curator._pitfalls_path_rule(" M", variant, systems=DECLARED)

    # The pair's positive control: both layers do admit the one literal, so "they agree" is
    # a statement about a file they can both see.
    assert pitfalls_curator._pitfalls_path_rule(" M", REDUCER_REL, systems=DECLARED) is None
    assert grant.fullmatch(str((repo / REDUCER_REL).resolve()))
    assert not grant.fullmatch(str(repo / (REDUCER_REL + "\x00.md"))), (
        "the grant's own [^\\x00]* is what refuses an embedded NUL"
    )

    outside = write(repo.parent / "outside" / "notes.md", "# not corpus\n")
    link = repo / REDUCER_REL
    link.unlink()
    link.symlink_to(outside)
    assert pitfalls_curator._pitfalls_path_rule(" M", REDUCER_REL, systems=DECLARED) is None
    assert not grant.fullmatch(str(link.resolve())), (
        "a symlinked literal resolves outside defender/skills and both layers admitted it"
    )


def test_the_merged_membership_gate_is_not_weakened(repo):
    assert pitfalls_curator._pitfalls_path_rule(
        "??", "defender/skills/cmdb/execution.md", systems=DECLARED,
    ) is None, "minting a declared system's first execution.md was refused"
    assert pitfalls_curator._pitfalls_path_rule(" M", ELASTIC_MD, systems=DECLARED) is None

    with pytest.raises(LeadAuthorError) as exc:
        pitfalls_curator._pitfalls_path_rule(
            " M", "defender/skills/newsys/execution.md", systems=DECLARED,
        )
    assert "undeclared system" in str(exc.value)
    assert "newsys" in str(exc.value)


def test_the_curator_still_cannot_touch_a_skill_md():
    for path in ("defender/skills/elastic/SKILL.md", "defender/skills/gather/SKILL.md"):
        for xy in (" M", "??", "A "):
            with pytest.raises(LeadAuthorError):
                pitfalls_curator._pitfalls_path_rule(xy, path, systems=DECLARED)


def test_only_the_pitfalls_lane_may_write_the_reducer_surface(repo):
    with pytest.raises(LeadAuthorError) as exc:
        lead_author._skills_path_rule(repo, " M", REDUCER_REL, systems=DECLARED,
                                      tree_for=lane_tree_for(repo))
    assert "out-of-scope" in str(exc.value)
    assert pitfalls_curator._pitfalls_path_rule(" M", REDUCER_REL, systems=DECLARED) is None

    write(repo / "defender/skills/elastic/SKILL.md", "---\nname: defender-elastic\n---\n# e\n")
    assert lead_author._skills_path_rule(
        repo, " M", "defender/skills/elastic/SKILL.md", systems=DECLARED,
        tree_for=lane_tree_for(repo),
    ) is None, "the sibling lane stopped admitting its own target"
    with pytest.raises(LeadAuthorError):
        pitfalls_curator._pitfalls_path_rule(
            " M", "defender/skills/elastic/SKILL.md", systems=DECLARED,
        )
