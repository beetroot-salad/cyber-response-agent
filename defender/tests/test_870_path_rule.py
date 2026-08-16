"""#870 M7 — one literal allowance in the path rule, and everything it must not relax.

Every test here is one demand of `spec-flow/specs/spec_graph_870.yaml`, named after that
demand's `discharged_by` pointer and carrying its prose in its docstring. The seam contract
lives in `defender/tests/_declared870.py`.

`_pitfalls_path_rule` is the SOLE gate on the reducer surface. G13 (executed) settled that:
the curator agent's own write grant compiles to `<skills dir>/[^\\x00]*\\.md` and matches every
`.md` under `defender/skills` at any depth, including this file — so an identity disagreement
between the two layers is a BYPASS, not a defence-in-depth gap.
"""
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

DECLARED = frozenset({"elastic", "cmdb"})
ELASTIC_MD = "defender/skills/elastic/execution.md"


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    tree = seed_tree(tmp_path, adapters=("elastic", "cmdb"), markers=("elastic",),
                     skills=("elastic",), catalog=(), non_systems=("gather",))
    write_reducer_surface(tree)
    return tree


def test_the_path_rule_admits_the_reducer_surface():
    """`_pitfalls_path_rule(' M', 'defender/skills/gather/defender-sql.md', systems=<the real
    adapter set>)` returns.

    `gather` is not in that set — the set is the seven adapters (C11, searched, alphabet
    recorded) — so the literal must be matched BEFORE the membership branch, or the surface
    this round exists to open is refused by the branch that mints nothing. The shape branch is
    in front of that one and refuses it too (C7, executed: `is_system_execution_md` is False
    for this path), so the allowance has to precede both.
    """
    assert pitfalls_curator._pitfalls_path_rule(
        " M", REDUCER_REL, systems=DECLARED,
    ) is None
    assert "gather" not in DECLARED, "the fixture stopped being able to see the membership branch"


def test_the_reducer_surface_cannot_be_deleted():
    """STATUS-SHAPE CLOSURE over `xy ∈ {'M ', ' M', 'MM', 'D ', ' D', 'R ', 'RM', '??'}`
    against the reducer literal: the rule raises for every shape carrying a `D`, and admits
    every other shape as an ordinary edit.

    U4 holds on this surface exactly as it does on a declared system's `execution.md`, because
    M7's literal allowance FALLS THROUGH to the delete branch rather than returning early. The
    fall-through is observed in the REASON, not merely in the raise: at this base a `'D '` on
    this path raises the SHAPE error (C14, executed — the delete branch is `_pitfalls_path_
    rule`'s LAST and is unreachable for any path the first two branches already refused), so a
    test that only asserted "it raises" would pass against an implementation that never opened
    the lane at all.

    `path_rule_admits_the_reducer_surface` is the positive control, and the declared system's
    own `execution.md` is driven over the same alphabet here so the two surfaces are shown to
    answer the same way.

    FK-1 SCOPES THIS AS PATH SURVIVAL PLUS STATUS-SHAPE CLOSURE ONLY. The rename-ORIGIN
    discard (`_git.git_status` parses a rename record's `<origPath>` and never emits it, so a
    rename FROM a system's `execution.md` TO the reducer literal deletes that system's surface
    with no record this rule can see) is explicitly OUT OF THIS ROUND and filed as its own
    issue; this demand does not claim to catch it. The curator's live bash `rm` grant likewise
    deletes on disk in the drain worktree and is caught, if at all, only when the deletion
    rides a commit — which is exactly the branch pinned here.
    """
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
    """Every other path under `defender/skills/gather/` is still refused — `gather/SKILL.md`,
    `gather/verb-roster.md`, `gather/failure-modes.md`, `gather/queries/elastic/x.md` — and so
    is every near spelling of the allowed one.

    The allowance is ONE literal compared as a literal, not a relaxation of the shape rule
    (C7). `path_rule_admits_the_reducer_surface` is the positive control: the one path this
    refuses to refuse.
    """
    refused = (
        "defender/skills/gather/SKILL.md",
        "defender/skills/gather/verb-roster.md",
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
    """THE PATH CENSUS the doc asked for and answered in prose (FK-14), executed over one
    alphabet: case variants, a combining-mark variant and its NFC/NFD forms, an embedded NUL,
    `.`/`..` segments, a doubled prefix, a directory-shaped literal, and a symlink planted AT
    the literal.

    Two layers claim to name one file and they use different notions of identity: the offline
    rule compares the TEXT `git status` emits, and the live write grant `fullmatch`es the
    RESOLVED path (G13, executed). What this demand asserts is that they never disagree in the
    dangerous direction — the rule admits nothing but the exact literal, and no variant is
    admitted by BOTH layers while resolving outside `defender/skills`.

    The two findings it records rather than decides: `.`/`..` forms are refused by the rule and
    admitted by the grant (the rule is the stricter one, and `git status --porcelain` emits
    canonicalized paths, so the form never reaches the rule in production); and a symlink at
    the literal is admitted by the RULE (whose subject is a string) and refused by the GRANT
    (whose subject is the resolved object) — so the pair still admits nothing outside the tree.

    The literal is pure ASCII, which is itself the census's answer to the case/Unicode arm:
    there is no NFC/NFD pair and no case folding that can collide with it, only distinct
    strings the rule refuses one by one.
    """
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

    # The symlink, planted for real: the rule's subject is the string and admits it; the
    # grant's subject is the resolved object and refuses it, so the escape is not admitted by
    # both layers at once.
    outside = write(repo.parent / "outside" / "notes.md", "# not corpus\n")
    link = repo / REDUCER_REL
    link.unlink()
    link.symlink_to(outside)
    assert pitfalls_curator._pitfalls_path_rule(" M", REDUCER_REL, systems=DECLARED) is None
    assert not grant.fullmatch(str(link.resolve())), (
        "a symlinked literal resolves outside defender/skills and both layers admitted it"
    )


def test_the_merged_membership_gate_is_not_weakened(repo):
    """U2 is not weakened by the added branch: a declared system's `execution.md` is still
    admitted — minting a first one included — and an undeclared system's is still refused with
    the REGISTRY reason.

    The two behaviours #908 merged, re-asserted through the rule that now has one more branch
    in front of them. `_pitfalls_path_rule`'s branch ORDER is the contract this round changes,
    so every merged verdict downstream of the new branch is re-driven rather than assumed
    (N8: merged work is not reopened, but it is re-observed where a branch lands in front of
    it).
    """
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
    """`defender/skills/elastic/SKILL.md` and `defender/skills/gather/SKILL.md` are both
    refused, created or edited.

    N2 stands: naming or describing a system stays the lead-author's scope even though the
    curator now writes into `gather/`'s directory. `system_execution_md_unchanged` is the
    positive control — the lane still admits what it always admitted.
    """
    for path in ("defender/skills/elastic/SKILL.md", "defender/skills/gather/SKILL.md"):
        for xy in (" M", "??", "A "):
            with pytest.raises(LeadAuthorError):
                pitfalls_curator._pitfalls_path_rule(xy, path, systems=DECLARED)


def test_only_the_pitfalls_lane_may_write_the_reducer_surface(repo):
    """The lead-author lane's own commit gate still REFUSES
    `defender/skills/gather/defender-sql.md` as out of scope, so this round widens the
    committed corpus's write surface by exactly one path in exactly ONE lane.

    The census U1/U2 want, taken at the two rules that stand in front of `commit_corpus`
    rather than by reading the diff (C16/G8: `_pitfalls_path_rule` has exactly one route, and
    `_verify_corpus_scope`'s only two callers are the two lanes; C11/G20: `CATALOG_REL` is
    `defender/skills/gather/queries/`, so gather's top-level prose is outside the lead-author's
    scope entirely).

    Both lanes are driven over BOTH targets, because a parity claim asserted on one cell is
    the fail-open this rule exists for: the sibling lane must still admit its OWN targets, or
    "it refuses the reducer surface" would be true of a lane that had stopped working.
    """
    with pytest.raises(LeadAuthorError) as exc:
        lead_author._skills_path_rule(repo, " M", REDUCER_REL, systems=DECLARED)
    assert "out-of-scope" in str(exc.value)
    assert pitfalls_curator._pitfalls_path_rule(" M", REDUCER_REL, systems=DECLARED) is None

    write(repo / "defender/skills/elastic/SKILL.md", "---\nname: defender-elastic\n---\n# e\n")
    assert lead_author._skills_path_rule(
        repo, " M", "defender/skills/elastic/SKILL.md", systems=DECLARED,
    ) is None, "the sibling lane stopped admitting its own target"
    with pytest.raises(LeadAuthorError):
        pitfalls_curator._pitfalls_path_rule(
            " M", "defender/skills/elastic/SKILL.md", systems=DECLARED,
        )
