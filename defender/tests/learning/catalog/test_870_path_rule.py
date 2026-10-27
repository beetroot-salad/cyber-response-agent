"""#870 M7 — one literal allowance in the path rule, and everything it must not relax.

#1108 P4 (O7, OD6): paths are the batch draft's `agent/skills/...`; the literal is the tenant's
pitfalls add-on. ASSUMED (S-H): the rules keep their `(xy, path)` shape, `xy` derived from the claim."""
from __future__ import annotations

import unicodedata
from pathlib import Path

import pytest

from defender.learning.leads import lead_author, pitfalls_curator
from defender.learning.leads.lead_extraction import LeadAuthorError
from defender.investigation.permission.files import build_write_allow
from defender.learning.core.lane_trees import DrainTrees
from defender.tests.support.learning.core._declared870 import (
    DELETING_SHAPES,
    STATUS_SHAPES,
    write,
)
from defender.tests.support.tenancy._tenants1106 import FIXTURE_AGENT

DECLARED = frozenset({"elastic", "cmdb"})
#: #1108 P4 (OD6): repo-relative spellings are `agent/...`. The one reducer literal the pitfalls
#: lane may write is the tenant's add-on (carried decision, A1 path), not the product page
#: `_declared870.REDUCER_REL` still names.
REDUCER_REL = "agent/skills/gather/defender-sql.pitfalls.md"
ELASTIC_MD = "agent/skills/elastic/execution.md"


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A batch draft's shape (`<root>/agent/skills/...`, no git): the declared system's skill and
    marker, and the tenant's pitfalls add-on (the fixture's committed copy)."""
    root = tmp_path / "draft"
    skills = root / "agent" / "skills"
    write(skills / "elastic" / "SKILL.md", "---\nname: defender-elastic\n---\n# elastic\n")
    write(skills / "elastic" / "execution.md", "# execution\n")
    write(root / REDUCER_REL, (FIXTURE_AGENT / "skills" / "gather" / "defender-sql.pitfalls.md")
          .read_text(encoding="utf-8"))
    return root


def lane_tree_for(root: Path):
    """The lead lane's held `skills/` mount over the draft (open while referenced)."""
    return DrainTrees.open((root / "agent" / "skills",)).tree_for


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
        "agent/skills/gather/SKILL.md",
        "agent/skills/gather/synthetic-reference.md",
        "agent/skills/gather/failure-modes.md",
        "agent/skills/gather/queries/elastic/x.md",
        "agent/skills/gather/defender-sql.md",
        "agent/skills/gather/defender-sql.pitfalls.md/x.md",
        "agent/skills/gather/sub/defender-sql.pitfalls.md",
        "agent/skills/gather/../gather/defender-sql.pitfalls.md",
        "agent/skills/gather/Defender-SQL.pitfalls.md",
        "agent/skills/gather/defender-sql.pitfalls.markdown",
    )
    for path in refused:
        with pytest.raises(LeadAuthorError):
            pitfalls_curator._pitfalls_path_rule(" M", path, systems=DECLARED)
    assert pitfalls_curator._pitfalls_path_rule(" M", REDUCER_REL, systems=DECLARED) is None


def test_the_path_rule_and_the_live_write_grant_agree_on_one_literal(repo):
    grant = build_write_allow(repo / "agent" / "skills", suffix=".md")
    combining = "agent/skills/gather/defender-sq́l.pitfalls.md"
    assert unicodedata.normalize("NFC", REDUCER_REL) == REDUCER_REL

    textual_variants = (
        "agent/skills/gather/DEFENDER-SQL.PITFALLS.MD",
        "agent/skills/gather/defender-sql.pitfalls.MD",
        combining,
        unicodedata.normalize("NFC", combining),
        unicodedata.normalize("NFD", combining),
        REDUCER_REL + "\x00.md",
        "agent/skills/agent/skills/gather/defender-sql.pitfalls.md",
        REDUCER_REL + "/",
        "agent/skills/gather/./defender-sql.pitfalls.md",
        "agent/skills/gather/../gather/defender-sql.pitfalls.md",
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
        "a symlinked literal resolves outside agent/skills and both layers admitted it"
    )


def test_the_merged_membership_gate_is_not_weakened(repo):
    assert pitfalls_curator._pitfalls_path_rule(
        "??", "agent/skills/cmdb/execution.md", systems=DECLARED,
    ) is None, "minting a declared system's first execution.md was refused"
    assert pitfalls_curator._pitfalls_path_rule(" M", ELASTIC_MD, systems=DECLARED) is None

    with pytest.raises(LeadAuthorError) as exc:
        pitfalls_curator._pitfalls_path_rule(
            " M", "agent/skills/newsys/execution.md", systems=DECLARED,
        )
    assert "undeclared system" in str(exc.value)
    assert "newsys" in str(exc.value)


def test_the_curator_still_cannot_touch_a_skill_md():
    for path in ("agent/skills/elastic/SKILL.md", "agent/skills/gather/SKILL.md"):
        for xy in (" M", "??", "A "):
            with pytest.raises(LeadAuthorError):
                pitfalls_curator._pitfalls_path_rule(xy, path, systems=DECLARED)


def test_only_the_pitfalls_lane_may_write_the_reducer_surface(repo):
    with pytest.raises(LeadAuthorError) as exc:
        lead_author._skills_path_rule(repo, " M", REDUCER_REL, systems=DECLARED,
                                      tree_for=lane_tree_for(repo))
    assert "out-of-scope" in str(exc.value)
    assert pitfalls_curator._pitfalls_path_rule(" M", REDUCER_REL, systems=DECLARED) is None

    write(repo / "agent/skills/elastic/SKILL.md", "---\nname: defender-elastic\n---\n# e\n")
    assert lead_author._skills_path_rule(
        repo, " M", "agent/skills/elastic/SKILL.md", systems=DECLARED,
        tree_for=lane_tree_for(repo),
    ) is None, "the sibling lane stopped admitting its own target"
    with pytest.raises(LeadAuthorError):
        pitfalls_curator._pitfalls_path_rule(
            " M", "agent/skills/elastic/SKILL.md", systems=DECLARED,
        )
