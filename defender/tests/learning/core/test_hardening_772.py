"""The lead author's PERMISSION gate must not admit agent system prompts (gather/SKILL.md, invlang/SKILL.md) as writable skills paths. Probes go through the real `decide_write` / `decide_bash` with a positive control per refusal.

#1108 P4 (O7, OD6): the lane writes a batch draft's `agent/skills/`; the product prompts stay in the
product tree. ASSUMED SEAM (S-H): the lead author's write lanes compile under
`RunScope(tenant_agent=<draft agent/>)` (`bind(LEAD_AUTHOR_DEF, run, defender_dir=<product>,
scope=...)`), its systems the product's adapters (plus the draft's markers)."""
from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")  # CI installs the runtime extra; skip otherwise

from defender.learning.leads import lead_author, pitfalls_curator  # noqa: E402
from defender.learning.leads.lead_author_engine import LEAD_AUTHOR_DEF  # noqa: E402
from defender.learning.leads.lead_author import _membership_segment  # noqa: E402
from defender.learning.leads.lead_extraction import LeadAuthorError  # noqa: E402
from defender.learning.core.lane_trees import DrainTrees  # noqa: E402
from defender.learning.leads.path_validation import (  # noqa: E402
    _is_draft_readme,
    _is_in_scope,
    _is_schema_md,
    _is_system_execution_md,
)
from defender.investigation import permission  # noqa: E402
from defender.investigation.agent_definition import RunScope, bind  # noqa: E402
from defender.tests.support.shared.contracts._repo import seed_adapter_stubs  # noqa: E402

#: The draft's repo-relative skills spelling after P4 (OD6).
SKILLS_REL = "agent/skills/"


def lane_tree_for(root: Path):
    """The lead lane's held `skills/` mount over the draft at `root` (open while referenced)."""
    return DrainTrees.open((root / "agent" / "skills",)).tree_for


#: The systems the probe trees declare. Two is the minimum that shows the lanes are an
#: alternation over a SET rather than one hardcoded name.
_SYSTEMS = ("elastic", "cmdb")


_AUTHORED_SURFACES = ("advisory", "connect", "gather", "handbook", "invlang")


def _tree(tmp_path: Path, systems: tuple[str, ...] = _SYSTEMS) -> tuple[Path, Path]:
    """`(product defender dir, draft agent root)`: the product checkout declares `systems` by
    adapter and keeps the authored surfaces; the draft holds each system's folder beside the
    authored surfaces' names — so a probe at `gather/SKILL.md` asks about a folder that is there."""
    defender_dir = tmp_path / "wt" / "defender"
    for name in _AUTHORED_SURFACES:
        (defender_dir / "skills" / name).mkdir(parents=True, exist_ok=True)
    seed_adapter_stubs(defender_dir, systems)
    agent = tmp_path / "draft" / "agent"
    for name in (*systems, *_AUTHORED_SURFACES):
        (agent / "skills" / name).mkdir(parents=True, exist_ok=True)
    (agent / "skills" / "gather" / "queries").mkdir(exist_ok=True)
    return defender_dir, agent


def _bind(run: Path, defender_dir: Path, agent: Path):
    return bind(LEAD_AUTHOR_DEF, run, defender_dir=defender_dir,
                scope=RunScope(tenant_agent=agent))


def _gate(tmp_path: Path, systems: tuple[str, ...] = _SYSTEMS):
    """`(admits, draft root)` — `admits(rel)` runs a skills-relative path of the draft through
    the REAL write gate under a policy bound to a product tree declaring `systems`.
    `admits.product(rel)` asks the same of the product tree's own `skills/`."""
    defender_dir, agent = _tree(tmp_path, systems)
    run = tmp_path / "run"
    run.mkdir(parents=True, exist_ok=True)
    deps = _bind(run, defender_dir, agent)

    def decide(path: Path) -> bool:
        return permission.decide_write(
            path, "body\n", run_dir=run, defender_dir=defender_dir, policy=deps.policy,
        ).allow

    def admits(rel: str) -> bool:
        return decide(agent / "skills" / rel)

    admits.product = lambda rel: decide(defender_dir / "skills" / rel)  # type: ignore[attr-defined]
    return admits, agent.parent


# 1. The two `SKILL.md` files that are agent system prompts.

def test_the_lane_cannot_write_gathers_system_prompt(tmp_path: Path):
    """`defender/skills/gather/SKILL.md` is not a system's skill doc — it is the whole of gather's `instructions=` (`investigation/driver._gather_instructions`), loaded on every dispatch."""
    admits, _ = _gate(tmp_path)
    assert not admits("gather/SKILL.md")
    assert not admits.product("gather/SKILL.md")
    assert admits("elastic/SKILL.md")


def test_the_lane_cannot_write_the_invlang_grammar_main_is_handed(tmp_path: Path):
    """`skills/invlang/SKILL.md` is read by `investigation/orient._invlang_grammar` and inlined verbatim into MAIN's ORIENT message, under a heading that calls it *authoritative* and tells the agent not to Read the file because it is reproduced there."""
    admits, _ = _gate(tmp_path)
    assert not admits("invlang/SKILL.md")
    assert not admits.product("invlang/SKILL.md")
    assert admits("cmdb/SKILL.md")


@pytest.mark.parametrize("rel", [
    "advisory/SKILL.md",
    "handbook/SKILL.md",
    "handbook/content/design.md",
    "connect/adapter.md",
    "connect/checklist.md",
    "judge/synthetic-reference.md",
    "gather/failure-modes.md",
    "gather/synthetic-reference.md",
    "gather/defender-sql.md",
    "gather/queries/elastic/a b.md",
    "gather/queries/elastic/a\nb.md",
    "gather/queries/elastic/say\"what.md",
    "elastic/_draft/x y.md",
])
def test_non_lane_surfaces_and_malformed_filenames_are_not_writable(tmp_path: Path, rel: str):
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
    agent = tmp_path / "draft" / "agent"
    (agent / "skills").mkdir(parents=True)
    run = tmp_path / "run"
    run.mkdir()
    with pytest.raises(LeadAuthorError, match="not a directory this process can read"):
        _bind(run, defender_dir, agent)

    (defender_dir / "integrations").mkdir(parents=True)
    with pytest.raises(ValueError, match="write scope is empty"):
        _bind(run, defender_dir, agent)

    seed_adapter_stubs(defender_dir, ("elastic",))
    assert _bind(run, defender_dir, agent).policy.write_allow


def test_the_lanes_read_the_tree_that_was_bound_not_a_sibling_of_it(tmp_path: Path):
    """The lanes resolve their systems under the BOUND `defender_dir`, never under a repo root reconstructed from it."""
    root = tmp_path / "wt"
    bound = root / "tree"                      # deliberately not named `defender`
    bound.mkdir(parents=True)
    seed_adapter_stubs(bound, ("elastic",))
    decoy = root / "defender"                  # what `.parent / "defender"` would have read
    (decoy / "skills").mkdir(parents=True)
    seed_adapter_stubs(decoy, ("ghost",))
    agent = tmp_path / "draft" / "agent"
    for name in ("elastic", "ghost"):
        (agent / "skills" / name).mkdir(parents=True)

    run = tmp_path / "run"
    run.mkdir()
    pol = _bind(run, bound, agent).policy

    def admits(rel: str) -> bool:
        return permission.decide_write(
            agent / "skills" / rel, "body\n", run_dir=run, defender_dir=bound, policy=pol,
        ).allow

    assert admits("elastic/SKILL.md")          # the bound tree's system has its lane
    assert not admits("ghost/SKILL.md")        # the sibling's does not


# 3. The frame-injection channel. #1108 P4 OD12(i): `test_the_porcelain_reader_does_not_quote_so_
# the_commit_gate_never_saw_this` pinned how `git status --porcelain` spells a spaced name in the
# worktree. A claim is now the draft read by name off the filesystem (`ChangeSet`), never
# porcelain: P3 tenant_1108_delivery/test_change_set_fuzz.py::test_derivation_keeps_its_invariant_on_random_box_output;
# the write-gate half stays above (`gather/queries/elastic/a b.md` is not writable).


# 4. The two gates stop disagreeing in the direction that discards a batch.

_EVERY_SHAPE = (
    "gather/queries/elastic/auth-events.md",
    "gather/queries/elastic/README.md",
    "gather/queries/elastic/_draft/newthing.md",
    "gather/queries/elastic/_draft/README.md",
    "gather/queries/SCHEMA.md",
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
    admits, repo_root = _gate(tmp_path)
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
    defender_dir, agent = _tree(tmp_path)
    run = tmp_path / "run"
    run.mkdir()
    pol = _bind(run, defender_dir, agent).policy

    def bash(cmd: str) -> bool:
        # The drain box's cwd is the draft's `agent/` (P3 `Batch.box_request`).
        return permission.decide_bash(
            cmd, policy=pol, run_dir=run, cwd_anchor=agent,
        ).allow

    assert not bash("rm skills/gather/SKILL.md")
    assert not bash(f"rm {agent}/skills/gather/SKILL.md")
    assert not bash(f"rm {defender_dir}/skills/gather/SKILL.md")
    assert not bash("rm skills/elastic/SKILL.md")
    assert not bash("rm skills/gather/queries/elastic/auth-events.md")
    assert not bash("rm skills/elastic/_draft/x y.md")     # the SEG narrowing, on rm too
    # controls: the two draft lanes the prompt does point it at
    assert bash("rm skills/elastic/_draft/falco-na.md")
    assert bash("rm skills/gather/queries/elastic/_draft/newthing.md")
    assert bash(f"rm {agent}/skills/elastic/_draft/falco-na.md")
