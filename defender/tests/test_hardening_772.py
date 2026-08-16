"""#772 — the lead author's PERMISSION gate stops admitting agent system prompts.

The defect: `LEAD_AUTHOR_DEF`'s write allow was one `build_write_allow(<skills>, ".md")`
pattern — `<skills>/[^\\x00]*\\.md`, every `.md` at every depth under `defender/skills/`. That
subtree holds the per-system skill docs this lane exists to curate, but it also holds
`gather/SKILL.md`, which IS the gather subagent's entire `instructions=`, and
`invlang/SKILL.md`, which is inlined verbatim into MAIN's ORIENT message. The lane's own inputs
(`goal_text`, `params`, `executed_query`) are lifted from a completed run, so they are model
output downstream of attacker-controlled telemetry.

#869 closed the COMMIT-gate half of this — `_skills_path_rule` now refuses any skills path
whose `_membership_segment` names a system `declared_systems` does not, and
`tests/test_869_commit_gate.py` is where that lives. What it did not touch is the permission
gate, so until this change the agent could still WRITE those files and only lost the batch at
the drain. That difference is the whole subject of this suite: a write-gate refusal is one
denied tool call the agent recovers from, while a commit-gate refusal discards every other
edit in the batch with it.

Each section pins the correction and carries the positive control that keeps it from being
satisfied by a policy that simply denies everything.

The probes go through the REAL `decide_write` / `decide_bash` rather than reading the compiled
patterns, because the pattern is not the gate: `decide_write` fullmatches against the RESOLVED
operand, and resolution is half of what makes the lanes a subtree rather than a string prefix.
"""
from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")  # CI installs the runtime extra; skip otherwise

from defender import _git  # noqa: E402
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


#: The systems the probe trees declare. Two is the minimum that shows the lanes are an
#: alternation over a SET rather than one hardcoded name.
_SYSTEMS = ("elastic", "cmdb")


def _tree(tmp_path: Path, systems: tuple[str, ...] = _SYSTEMS) -> Path:
    """A worktree declaring `systems`, with the authored surfaces of the shipped tree beside
    them — so a probe at `gather/SKILL.md` is asking about a directory that really is there."""
    defender_dir = tmp_path / "wt" / "defender"
    for name in (*systems, "gather", "invlang", "handbook", "connect", "advisory", "judge"):
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


# =========================================================================== #
# 1. The two `SKILL.md` files that are agent system prompts.
# =========================================================================== #

def test_the_lane_cannot_write_gathers_system_prompt(tmp_path: Path):
    """`defender/skills/gather/SKILL.md` is not a system's skill doc — it is the whole of
    gather's `instructions=` (`runtime/driver._gather_instructions`), loaded on every dispatch.
    Gather is the agent that reads raw attacker payloads, and this lane's inputs are lifted from
    the run those payloads produced, so a writable prompt there is a persistent injection loop:
    rewritten by the lane, committed by the drain, read by every later run.

    The positive control is a real system's skill doc — the same filename, one directory over.
    """
    admits, _ = _gate(tmp_path)
    assert not admits("gather/SKILL.md")
    assert admits("elastic/SKILL.md")


def test_the_lane_cannot_write_the_invlang_grammar_main_is_handed(tmp_path: Path):
    """`skills/invlang/SKILL.md` is read by `runtime/orient._invlang_grammar` and inlined
    verbatim into MAIN's ORIENT message, under a heading that calls it *authoritative* and tells
    the agent not to Read the file because it is reproduced there. Same loop as gather's, one
    role up."""
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
        "judge/verb-roster.md",
        "gather/failure-modes.md",
        "gather/verb-roster.md",
        "gather/defender-sql.md",
    ],
)
def test_the_other_authored_surfaces_are_not_this_lanes_to_write(tmp_path: Path, rel: str):
    """The rest of `defender/skills/` — six directories that are not systems of record. None of
    these is an agent prompt, but every one of them was writable, and each was also OUT of the
    commit gate's scope, so a single stray write cost the whole batch at the drain.

    `handbook/content/design.md` and `connect/checklist.md` carry the second half of the old
    tail: it was unbounded in DEPTH as well as in directory."""
    admits, _ = _gate(tmp_path)
    assert not admits(rel)


# =========================================================================== #
# 2. The five lanes that remain — one per surface the two roles really author.
# =========================================================================== #

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
    """MEMBERSHIP, not a name list. `ghost` is refused in a tree that declares no adapter for it
    and admitted in one that does — the same directory name, the same two paths, decided by
    `_scaffold_rules.VerbResolver.is_system`, which is also what the commit gate reads.

    This is the property a hardcoded `EDITABLE_SKILL_DIRS` frozenset could not have: it would
    answer identically about both trees, and drift the first time `connect` scaffolds a system.
    """
    without, _ = _gate(tmp_path / "a")
    assert not without("ghost/SKILL.md")
    assert not without("gather/queries/ghost/x.md")

    with_ghost, _ = _gate(tmp_path / "b", (*_SYSTEMS, "ghost"))
    assert with_ghost("ghost/SKILL.md")
    assert with_ghost("gather/queries/ghost/x.md")


def test_a_tree_that_declares_no_system_is_refused_rather_than_bound_lane_less(tmp_path: Path):
    """An empty system set compiles no lane, and a writer whose `write_allow` admits nothing is
    a dead writer — it burns its whole request budget returning denials for the edits its own
    handoff just asked for. Refused at bind, where the tree is nameable, rather than one frame
    down. The positive control: one stub adapter and the same bind succeeds.

    Two refusals, kept distinguishable because they are different facts about the tree — the
    disjunctive reading #869 gives its resolver, applied at this seam:

    * the adapters directory is not there at all, so the SOURCE is unresolvable and
      `adapter_declared_systems` raises `LeadAuthorError`. That is the useful class here: it is
      a member of the drain's `RETIRE_SET`, so a broken worktree quarantines one batch instead
      of halting the drain;
    * the directory resolves and declares nothing, which is a statement about the tree rather
      than about reading it, and is this module's own `ValueError`.
    """
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


# =========================================================================== #
# 3. The frame-injection channel, which was open — not "saved by accident".
# =========================================================================== #

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
    """Every variable segment is `grant.SEG` (`[\\w.@=+-]+`) — the read side's own alphabet — so
    no lane admits a name that could break a frame the way `build_scoped_write_allow`'s docstring
    records for #691 MD-7. The old `[^\\x00]*` tail admitted all of these.

    Gather's dispatch prompt prints template paths, so the channel had a live reader."""
    admits, _ = _gate(tmp_path)
    assert not admits(rel)


def test_an_ordinary_kebab_name_still_lands(tmp_path: Path):
    """The control for the narrowing above: the catalog's real naming convention is kebab-case,
    and `-`, `.` and `_` are all inside SEG. A narrowing that also refused these would have been
    measured as a fix while breaking the lane."""
    admits, _ = _gate(tmp_path)
    assert admits("gather/queries/elastic/sshd-auth-history.md")
    assert admits("gather/queries/elastic/doc_fetch.v2.md")


def test_the_porcelain_reader_does_not_quote_so_the_commit_gate_never_saw_this(tmp_path: Path):
    """#772 asserted this channel was "saved by accident: git porcelain quotes such a path, so
    the `startswith(SKILLS_REL)` check fails and the commit aborts." It is not. `_git.git_status`
    runs `git status --porcelain -z`, and `-z` disables quoting outright — so the path comes back
    RAW, `_verify_corpus_scope`'s `startswith`/`endswith` test accepts it, and `_is_in_scope`
    calls it in scope.

    Pinned because the belief is load-bearing in the wrong direction: a future reader who
    re-derives "git quoting protects us" would conclude the SEG narrowing above is redundant and
    widen the tail back out. The write gate is the only thing closing this."""
    repo = seed_repo(tmp_path / "repo", add="README")
    rel = "defender/skills/gather/queries/elastic/a b.md"
    (repo / rel).parent.mkdir(parents=True)
    (repo / rel).write_text("x\n", encoding="utf-8")

    assert rel in [p for _xy, p in _git.git_status(repo)]   # RAW — no quotes, not torn
    assert rel.startswith(SKILLS_REL)          # `_verify_corpus_scope._in_corpus`, both halves
    assert rel.endswith(".md")
    assert _is_in_scope(rel)


# =========================================================================== #
# 4. The two gates stop disagreeing in the direction that discards a batch.
# =========================================================================== #

#: Representative of every shape either gate has an opinion about — the five lanes, the
#: protected surfaces, the authored surfaces, a phantom system, and a hostile name.
_EVERY_SHAPE = (
    "gather/queries/elastic/auth-events.md",
    "gather/queries/elastic/README.md",
    "gather/queries/elastic/_draft/newthing.md",
    "gather/queries/elastic/_draft/README.md",
    "gather/queries/SCHEMA.md",
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


def test_nothing_the_write_gate_admits_is_refused_at_the_drain(tmp_path: Path):
    """The anti-drift invariant, and the second half of what #772 asked for.

    A refusal at the WRITE gate is one denied tool call the agent can recover from. A refusal at
    the COMMIT gate raises `LeadAuthorError` out of the drain and discards the whole batch —
    every other edit in it included. So the write allow must be a SUBSET of the union of the two
    roles' commit scopes, and this asserts exactly that implication over every shape either gate
    has an opinion about. It is not a re-spelling of the lanes: the two are now separate
    spellings sharing only the system set, and this is what keeps them from drifting apart in
    the expensive direction.

    Note the implication is one-way on purpose. The write gate is STRICTER for
    `queries/SCHEMA.md`, `queries/NOTES.md` and `_draft/README.md` — all in scope for the commit
    gate, two of them protected surfaces it refuses anyway — and that is the safe direction.

    The membership clause is the one that binds the two halves of this issue together: #869's
    `_membership_segment(path) in systems` is what the commit gate refuses `gather/SKILL.md`
    by, and the lanes are compiled off the same declared set, so the two answers cannot part
    without this failing.
    """
    admits, _ = _gate(tmp_path)
    admitted = [f"{SKILLS_REL}{rel}" for rel in _EVERY_SHAPE if admits(rel)]
    # A gate that admitted nothing would satisfy the implication vacuously.
    assert len(admitted) >= 5, admitted
    for path in admitted:
        # the lead author's commit scope, or the pitfalls curator's — one write allow serves
        # both roles, so the union is what it has to be a subset of
        assert _is_in_scope(path) or _is_system_execution_md(path), path
        assert not _is_schema_md(path), path
        assert not _is_draft_readme(path), path
        assert _membership_segment(path) in _SYSTEMS, path


def test_the_write_gate_refuses_the_protected_surfaces_first(tmp_path: Path):
    """`SCHEMA.md` and a `_draft/README.md` are surface declarations the commit gate calls
    "protected" and refuses — by discarding the batch. No lane reaches them now, so the same
    refusal arrives as a recoverable denial instead. `SCHEMA.md` needs no exclusion of its own:
    it sits at the catalog ROOT, one segment above where any lane starts."""
    admits, _ = _gate(tmp_path)
    assert not admits("gather/queries/SCHEMA.md")
    assert not admits("gather/queries/elastic/_draft/README.md")
    assert not admits("elastic/_draft/README.md")
    assert admits("gather/queries/elastic/_draft/real-draft.md")   # control


# =========================================================================== #
# 6. The `rm` lane, which had the same recoverable-vs-discard problem.
# =========================================================================== #

def test_rm_can_no_longer_name_an_agent_prompt(tmp_path: Path):
    """`rm defender/skills/gather/SKILL.md` used to MATCH the grant — the old pattern was
    `(?:/{seg})+`, unbounded in depth and indifferent to the filename — and was refused only by
    the commit-gate delete-prohibition, i.e. by discarding the batch. `lead_author.md` has always
    said `rm` may target drafts and nothing else; the grant now says the same thing.

    Both spellings, because the agent issues repo-relative paths and the matcher accepts the
    absolute worktree one too."""
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
