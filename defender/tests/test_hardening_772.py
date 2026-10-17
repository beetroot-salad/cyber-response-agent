"""The lead author's PERMISSION gate must not admit agent system prompts (gather/SKILL.md, invlang/SKILL.md) as writable skills paths. Probes go through the real `decide_write` / `decide_bash` with a positive control per refusal."""
from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")  # CI installs the runtime extra; skip otherwise

from defender import _git  # noqa: E402
from defender.learning.leads import lead_author, pitfalls_curator  # noqa: E402
from defender.learning.leads.lead_author_engine import LEAD_AUTHOR_DEF  # noqa: E402
from defender.learning.leads.lead_author import _membership_segment  # noqa: E402
from defender.learning.leads.lead_extraction import LeadAuthorError  # noqa: E402
from defender.learning.leads.path_validation import (  # noqa: E402
    SKILLS_REL,
    _is_draft_readme,
    _is_in_scope,
    _is_schema_md,
    _is_system_execution_md,
)
from defender.runtime import permission  # noqa: E402
from defender.runtime.agent_definition import bind  # noqa: E402
from defender.tests._repo import (  # noqa: E402
    seed_adapter_stubs,
    seed_repo,
)
from defender.tests._lead_author_1134 import lane_tree_for  # noqa: E402


#: The systems the probe trees declare. Two is the minimum that shows the lanes are an
#: alternation over a SET rather than one hardcoded name.
_SYSTEMS = ("elastic", "cmdb")


#: THE roster of directories under `defender/skills/` that are NOT systems of record — the one
#: copy, after this list had four of them (two comments, the agent's deny reason and the agent
#: prompt) and the copy at the concept's own definition point had already gone stale by a name.
#: Those now state the RULE — "a directory the tree declares no adapter for" — which is what
#: production must ask anyway, and this stays because a FIXTURE needs names to plant.
#:
#: `test_the_authored_surface_roster_is_the_shipped_one` is what keeps it honest: it asserts
#: this set against the tree, so a seventh authored directory fails here rather than silently
#: making every prose copy wrong. Two of these are agent system prompts (`gather/SKILL.md`,
#: `invlang/SKILL.md`), which is the whole of #772.
#: `judge` left in #922 with the role: its generated guidance advertised three ticket
#: verbs to any reader, and nothing could dispatch them once the role was gone.
_AUTHORED_SURFACES = ("advisory", "connect", "gather", "handbook", "invlang")


def _tree(tmp_path: Path, systems: tuple[str, ...] = _SYSTEMS) -> Path:
    """A worktree declaring `systems`, with the authored surfaces of the shipped tree beside
    them — so a probe at `gather/SKILL.md` is asking about a directory that really is there."""
    defender_dir = tmp_path / "wt" / "defender"
    for name in (*systems, *_AUTHORED_SURFACES):
        (defender_dir / "skills" / name).mkdir(parents=True, exist_ok=True)
    (defender_dir / "skills" / "gather" / "queries").mkdir(exist_ok=True)
    seed_adapter_stubs(defender_dir, systems)
    return defender_dir


def _gate(tmp_path: Path, systems: tuple[str, ...] = _SYSTEMS):
    """`(admits, defender_dir)` — `admits(rel)` runs a skills-relative path through the REAL
    write gate under a policy bound to a tree declaring `systems`."""
    defender_dir = _tree(tmp_path, systems)
    run = tmp_path / "run"
    run.mkdir(parents=True, exist_ok=True)
    deps = bind(LEAD_AUTHOR_DEF, run, defender_dir=defender_dir)

    def admits(rel: str) -> bool:
        return permission.decide_write(
            defender_dir / "skills" / rel, "body\n",
            run_dir=run, defender_dir=defender_dir, policy=deps.policy,
        ).allow

    return admits, defender_dir


# 1. The two `SKILL.md` files that are agent system prompts.

def test_the_lane_cannot_write_gathers_system_prompt(tmp_path: Path):
    """`defender/skills/gather/SKILL.md` is not a system's skill doc — it is the whole of gather's `instructions=` (`runtime/driver._gather_instructions`), loaded on every dispatch."""
    admits, _ = _gate(tmp_path)
    assert not admits("gather/SKILL.md")
    assert admits("elastic/SKILL.md")


def test_the_lane_cannot_write_the_invlang_grammar_main_is_handed(tmp_path: Path):
    """`skills/invlang/SKILL.md` is read by `runtime/orient._invlang_grammar` and inlined verbatim into MAIN's ORIENT message, under a heading that calls it *authoritative* and tells the agent not to Read the file because it is reproduced there."""
    admits, _ = _gate(tmp_path)
    assert not admits("invlang/SKILL.md")
    assert admits("cmdb/SKILL.md")


@pytest.mark.parametrize(
    "rel",
    [
        "advisory/SKILL.md",
        "handbook/SKILL.md",
        "handbook/content/design.md",
        "connect/adapter.md",
        "connect/checklist.md",
        "judge/synthetic-reference.md",
        "gather/failure-modes.md",
        "gather/synthetic-reference.md",
        "gather/defender-sql.md",
    ],
)
def test_the_other_authored_surfaces_are_not_this_lanes_to_write(tmp_path: Path, rel: str):
    """The rest of `defender/skills/` — six directories that are not systems of record."""
    admits, _ = _gate(tmp_path)
    assert not admits(rel)


# 2. The five lanes that remain — one per surface the two roles really author.

@pytest.mark.parametrize(
    "rel",
    [
        "gather/queries/elastic/auth-events.md",       # L1 established template
        "gather/queries/elastic/README.md",            # L1 a system's catalog notes
        "gather/queries/cmdb/_draft/newthing.md",      # L2 catalog draft
        "elastic/SKILL.md",                            # L3 the per-system skill doc
        "elastic/_draft/falco-na.md",                  # L4 system-skill draft
        "elastic/execution.md",                        # L5 the PITFALLS CURATOR's lane
    ],
)
def test_every_surface_the_two_roles_author_still_has_a_lane(tmp_path: Path, rel: str):
    """The positive half. One write allow serves both roles — `_pydantic_stage.build_stage_agent`
    re-derives the definition by ROLE, so the pitfalls curator spawns under this same policy —
    which is why `execution.md` is here despite the lead author's own commit gate refusing it."""
    admits, _ = _gate(tmp_path)
    assert admits(rel)


def test_the_lanes_follow_the_tree_rather_than_a_hardcoded_list(tmp_path: Path):
    """MEMBERSHIP, not a name list."""
    without, _ = _gate(tmp_path / "a")
    assert not without("ghost/SKILL.md")
    assert not without("gather/queries/ghost/x.md")

    with_ghost, _ = _gate(tmp_path / "b", (*_SYSTEMS, "ghost"))
    assert with_ghost("ghost/SKILL.md")
    assert with_ghost("gather/queries/ghost/x.md")


def test_a_tree_that_declares_no_system_is_refused_rather_than_bound_lane_less(tmp_path: Path):
    """An empty system set compiles no lane, and a writer whose `write_allow` admits nothing is a dead writer — it burns its whole request budget returning denials for the edits its own handoff just asked for."""
    defender_dir = tmp_path / "wt" / "defender"
    (defender_dir / "skills").mkdir(parents=True)
    run = tmp_path / "run"
    run.mkdir()
    with pytest.raises(LeadAuthorError, match="not a directory this process can read"):
        bind(LEAD_AUTHOR_DEF, run, defender_dir=defender_dir)

    (defender_dir / "scripts" / "adapters").mkdir(parents=True)
    with pytest.raises(ValueError, match="write scope is empty"):
        bind(LEAD_AUTHOR_DEF, run, defender_dir=defender_dir)

    seed_adapter_stubs(defender_dir, ("elastic",))
    assert bind(LEAD_AUTHOR_DEF, run, defender_dir=defender_dir).policy.write_allow


def test_the_lanes_read_the_tree_that_was_bound_not_a_sibling_of_it(tmp_path: Path):
    """The lanes resolve their systems under the BOUND `defender_dir`, never under a repo root reconstructed from it."""
    root = tmp_path / "wt"
    bound = root / "tree"                      # deliberately not named `defender`
    (bound / "skills" / "elastic").mkdir(parents=True)
    seed_adapter_stubs(bound, ("elastic",))
    decoy = root / "defender"                  # what `.parent / "defender"` would have read
    (decoy / "skills").mkdir(parents=True)
    seed_adapter_stubs(decoy, ("ghost",))

    run = tmp_path / "run"
    run.mkdir()
    pol = bind(LEAD_AUTHOR_DEF, run, defender_dir=bound).policy

    def admits(rel: str) -> bool:
        return permission.decide_write(
            bound / "skills" / rel, "body\n", run_dir=run, defender_dir=bound, policy=pol,
        ).allow

    assert admits("elastic/SKILL.md")          # the bound tree's system has its lane
    assert not admits("ghost/SKILL.md")        # the sibling's does not


# 3. The frame-injection channel, which was open — not "saved by accident".

@pytest.mark.parametrize(
    "rel",
    [
        "gather/queries/elastic/a b.md",
        "gather/queries/elastic/a\nb.md",
        "gather/queries/elastic/say\"what.md",
        "elastic/_draft/x y.md",
    ],
)
def test_a_write_only_filename_cannot_carry_a_space_or_a_newline(tmp_path: Path, rel: str):
    """Every variable segment is `grant.SEG` (a word-char class) — the read side's own alphabet — so no lane admits a name that could break a frame the way `build_scoped_write_allow`'s docstring records for #691 MD-7."""
    admits, _ = _gate(tmp_path)
    assert not admits(rel)


def test_the_porcelain_reader_does_not_quote_so_the_commit_gate_never_saw_this(tmp_path: Path):
    """#772 asserted this channel was "saved by accident:"""
    repo = seed_repo(tmp_path / "repo", add="README")
    rel = "defender/skills/gather/queries/elastic/a b.md"
    (repo / rel).parent.mkdir(parents=True)
    (repo / rel).write_text("x\n", encoding="utf-8")

    assert rel in [p for _xy, p in _git.git_status(repo)]   # RAW — no quotes, not torn
    assert rel.startswith(SKILLS_REL)          # `_verify_corpus_scope._in_corpus`, both halves
    assert rel.endswith(".md")
    assert _is_in_scope(rel)


# 4. The two gates stop disagreeing in the direction that discards a batch.

#: Representative of every shape either gate has an opinion about — the five lanes, the
#: protected surfaces at every depth they can appear, the authored surfaces, a phantom system,
#: and a hostile name.
_EVERY_SHAPE = (
    "gather/queries/elastic/auth-events.md",
    "gather/queries/elastic/README.md",
    "gather/queries/elastic/_draft/newthing.md",
    "gather/queries/elastic/_draft/README.md",
    "gather/queries/SCHEMA.md",
    # `SCHEMA.md` and `execution.md` are refused by BASENAME, not by the one depth they are
    # shipped at: `_is_schema_md` is any `SCHEMA.md` under the catalog and `_skills_path_rule`
    # refuses `execution.md` at ANY depth. Each spelling below reached a lane once.
    "gather/queries/elastic/SCHEMA.md",
    "gather/queries/elastic/_draft/SCHEMA.md",
    "gather/queries/elastic/execution.md",
    "gather/queries/elastic/_draft/execution.md",
    "elastic/_draft/execution.md",
    "gather/queries/NOTES.md",
    "gather/queries/ghost/x.md",
    "elastic/SKILL.md",
    "elastic/execution.md",
    "elastic/_draft/falco-na.md",
    "elastic/_draft/README.md",
    "elastic/notes.md",
    "gather/SKILL.md",
    "invlang/SKILL.md",
    "advisory/SKILL.md",
    "handbook/content/design.md",
    "ghost/SKILL.md",
    "gather/queries/elastic/a b.md",
)


def _commit_scopes_admit_lead_author(repo_root: Path, path: str) -> bool:
    """The LEAD AUTHOR's path rule alone — the union helper above answers for either role, and
    the point here is the one path where the two roles disagree."""
    try:
        lead_author._skills_path_rule(repo_root, "M", path, systems=frozenset(_SYSTEMS),
                                      tree_for=lane_tree_for(repo_root))
    except LeadAuthorError:
        return False
    return True


def _commit_scopes_admit(repo_root: Path, path: str) -> bool:
    """Does EITHER role's real commit-gate path rule accept `path` as a modification?"""
    for rule in (
        lambda: lead_author._skills_path_rule(
            repo_root, "M", path, systems=frozenset(_SYSTEMS), tree_for=lane_tree_for(repo_root)
        ),
        lambda: pitfalls_curator._pitfalls_path_rule(
            "M", path, systems=frozenset(_SYSTEMS)
        ),
    ):
        try:
            rule()
        except LeadAuthorError:
            continue
        return True
    return False


def test_nothing_the_write_gate_admits_is_refused_at_the_drain(tmp_path: Path):
    """The anti-drift invariant, and the second half of what #772 asked for."""
    admits, defender_dir = _gate(tmp_path)
    repo_root = defender_dir.parent
    admitted = [f"{SKILLS_REL}{rel}" for rel in _EVERY_SHAPE if admits(rel)]
    # A gate that admitted nothing would satisfy the implication vacuously.
    assert len(admitted) >= 5, admitted
    for path in admitted:
        # the lead author's commit scope, or the pitfalls curator's — one write allow serves
        # both roles, so the union is what it has to be a subset of
        assert _commit_scopes_admit(repo_root, path), path
        # the same statement in the helpers the two rules are built from, kept because they
        # name WHICH clause a regression broke
        assert _is_in_scope(path) or _is_system_execution_md(path), path
        assert not _is_schema_md(path), path
        assert not _is_draft_readme(path), path
        assert _membership_segment(path) in _SYSTEMS, path


def test_the_write_gate_refuses_the_protected_surfaces_first(tmp_path: Path):
    """`SCHEMA.md` and a `_draft/README.md` are surface declarations the commit gate calls "protected" and refuses — by discarding the batch."""
    admits, _ = _gate(tmp_path)
    assert not admits("gather/queries/SCHEMA.md")
    assert not admits("gather/queries/elastic/_draft/README.md")
    assert not admits("elastic/_draft/README.md")
    assert admits("gather/queries/elastic/_draft/real-draft.md")   # control


# 5. The `rm` lane, which had the same recoverable-vs-discard problem.

def test_rm_can_no_longer_name_an_agent_prompt(tmp_path: Path):
    """`rm defender/skills/gather/SKILL.md` used to MATCH the grant — the old pattern was `(?:/{seg})+`, unbounded in depth and indifferent to the filename — and was refused only by the commit-gate delete-prohibition, i.e."""
    defender_dir = _tree(tmp_path)
    run = tmp_path / "run"
    run.mkdir()
    pol = bind(LEAD_AUTHOR_DEF, run, defender_dir=defender_dir).policy

    def bash(cmd: str) -> bool:
        return permission.decide_bash(cmd, policy=pol).allow

    assert not bash("rm defender/skills/gather/SKILL.md")
    assert not bash(f"rm {defender_dir}/skills/gather/SKILL.md")
    assert not bash("rm defender/skills/elastic/SKILL.md")
    assert not bash("rm defender/skills/gather/queries/elastic/auth-events.md")
    assert not bash("rm defender/skills/elastic/_draft/x y.md")     # the SEG narrowing, on rm too
    # controls: the two draft lanes the prompt does point it at
    assert bash("rm defender/skills/elastic/_draft/falco-na.md")
    assert bash("rm defender/skills/gather/queries/elastic/_draft/newthing.md")
    assert bash(f"rm {defender_dir}/skills/elastic/_draft/falco-na.md")
