"""Executable spec (written BEFORE the code) for design #551 — make bind/compile_policy
the SOLE production policy seam for all 7 roles (AgentDefinition consolidation step three).
The demand list, structure, and gate live in `spec_graph_551.yaml` beside this file.

#545/#546 shipped `bind` as the production deps+policy seam. #551 finishes the job:

  - `resolve_roots` + `bind` gain a unified `defender_dir` param and DROP the `repo_root`
    kwarg (lead-author threads its worktree via `defender_dir=<wt>/defender`); bind threads
    it into BOTH the policy anchor (`resolve_roots`) AND the deps field (`_for_run`) so the
    two tree anchors are ONE tree — a split bricks every worktree read/write.
  - `compile_policy` grows a `write_shapes` positional (write twin of `read_shapes`): the
    per-writer write scope becomes data, and `_lead_author_policy` is deleted (its worktree
    `defender/skills/**.md` write scope + scoped `rm`-of-drafts grant now come from
    `compile_policy` via `write_shapes`).
  - the actor-confine and lead-author-tree fail-louds become generic DATA bits
    (`requires_confine` / `requires_explicit_tree` on AgentDefinition) — no `if role is X`
    branch remains in bind; bind additionally HARDENS its root inputs (relative/degenerate
    roots + a lead-author main-checkout tree are UNBUILDABLE).
  - the writers (`tools._tool_write_file`/`_tool_edit_file`) pass `deps.run_dir`/
    `deps.defender_dir` to `decide_write`, activating the dormant write⊆read guard.
  - the parallel factory path retires: `_ORACLE_POLICY`/`_VERIFY_POLICY`/`_lead_author_policy`
    go; `policy_for`/`main_policy`/`gather_policy` survive only as bind aliases (the alias now
    carries `reader_read_shapes`, flipping a non-`.md` corpus read allow→deny — hole H4).

The 4 resolved design decisions this suite is authored against:
  Q1 KEEP-AS-HELPERS: `_judge_policy`/`_actor_policy` stay as `compile_policy._bash_allow`'s
     pattern source; only their `for_scope` front doors are deleted. decide_bash is identical.
  Q2 FULL DATA-DRIVE: bind gains `defender_dir` + drops `repo_root`; a `requires_explicit_tree`
     data bit (True on LEAD_AUTHOR_DEF) raises generically when such a role gets no non-PATHS
     tree; the actor's `requires_confine` bit (True on ACTOR_DEF) is checked generically.
  Q3 ASSERT: compile_policy RAISES on write=True⊗empty write_shapes OR write=False⊗non-empty.
  Q4 HARDEN: bind validates root inputs (absolute, non-degenerate); a lead-author main-checkout
     tree (== PATHS) is UNBUILDABLE.

RED@HEAD-for-the-right-reason contract: every symbol imported here EXISTS at HEAD, so the
module IMPORTS cleanly and no test fails at collection. New-behaviour tests fail at RUNTIME —
`bind(..., defender_dir=)` / `resolve_roots(..., defender_dir=)` TypeError (repo_root/3-arg
today), `compile_policy(..., write_shapes, ...)` TypeError (4-arg today), `*.write_shapes` /
`*.requires_confine` / `*.requires_explicit_tree` AttributeError, and behaviour assertions on
the not-yet-wired write⊆read guard / the not-yet-anchoring policy_for alias / the not-yet-
hardened root validation. Every ad-hoc `AgentDefinition(...)` is built INSIDE a test body
(a module-level construct with a new field would be a COLLECTION error, which the gate rejects).
GREEN@HEAD characterization (must pass at HEAD and STAY green): the read↔cat filename + symlink
parity, the write⊆read guard called DIRECTLY with roots, the deny-all stages, the actor-confine
positive controls, the corpus-traversal guard. Each test marks its expected HEAD state inline.

Prose-only demands (recorded here, NOT tested — no `form: test` in the spec_graph):
  - r5_requires_confine_default_documented (form: waiver, hole H5): `requires_confine` /
    `requires_explicit_tree` default False, so a NEW confined/worktree role that forgets the
    bit is silently built open. The design KEEPS the permissive default, shifting safety onto
    the def author + build_registry review; the risk is accepted, not gated.
There are NO `form: clause` demands in this spec.

Hermetic: every test calls bind / compile_policy / resolve_roots / decide_* / the tool seams
directly. No network, no key, no fault-injection fakes (the entry points are pure functions).
"""
from __future__ import annotations

import os
import re
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")  # CI installs the runtime extra; skip otherwise

from pydantic_ai.exceptions import ModelRetry  # noqa: E402

from defender._paths import PATHS  # noqa: E402
from defender.hooks._cmd_segments import NON_ADAPTER_SHIMS  # noqa: E402
from defender.learning.core import config  # noqa: E402
from defender.learning.author.verify_forward.engine import VerifierDeps  # noqa: E402
from defender.learning.leads.lead_author_engine import LeadAuthorDeps  # noqa: E402
from defender.learning.pipeline.actor_engine import ActorDeps  # noqa: E402
from defender.learning.pipeline.judge.engine_pydantic import JudgeDeps  # noqa: E402
from defender.learning.pipeline.oracle_engine import OracleDeps  # noqa: E402
from defender.runtime import permission  # noqa: E402
from defender.runtime.agent_role import AgentRole  # noqa: E402
from defender.runtime.permission import files  # noqa: E402
from defender.runtime.permission.policies._common import (  # noqa: E402
    READER_VIEWERS,
    reader_patterns_for,
)
from defender.runtime.permission.policy import AgentPolicy  # noqa: E402
from defender.runtime.tools import AgentDeps, GatherDeps, _tool_write_file  # noqa: E402

from defender.runtime.agent_definition import (  # noqa: E402
    AgentDefinition,
    BashGrammar,
    RunScope,
    ToolSet,
    bind,
    compile_policy,
    resolve_roots,
)
from defender.runtime.agents import (  # noqa: E402
    ACTOR_DEF,
    CORPUS_AUTHOR_DEF,
    GATHER_DEF,
    JUDGE_DEF,
    LEAD_AUTHOR_DEF,
    MAIN_DEF,
    ORACLE_DEF,
    VERIFY_DEF,
)

_DEFENDER = PATHS.defender_dir

# Real repo-relative script/confine paths (mirrors test_bind_wiring_545.py) — the actor's
# _script_pattern does script.resolve().relative_to(REPO_ROOT), so synthetic paths raise.
_ENV_RETRIEVE = config.LESSONS_ENV_RETRIEVE_SCRIPT
_ACTOR_INDEX = config.LESSONS_ACTOR_INDEX_SCRIPT
_ACTOR_DIR = config.LESSONS_ACTOR_DIR
_ENV_DIR = config.LESSONS_ENVIRONMENT_DIR

# Probe files (need not exist — the gate is textual/root-based):
#   corpus .md under lessons  → both the bash cat lane AND decide_read admit (reader agent)
#   non-.md under skills      → the bash cat lane REJECTS; a reader's decide_read must too
_CORPUS_MD = _DEFENDER / "lessons" / "_probe_551.md"
_NON_MD = _DEFENDER / "skills" / "gather" / "run.py"   # a non-.md path under the corpus


def _policy9(p) -> tuple:
    """The 9 LEGACY AgentPolicy fields as a comparable tuple (bash_allow / write_allow
    Patterns → their source strings). INCLUDES write_allow, EXCLUDES the additive
    read_shapes (tested separately / folded into `_policy_full`)."""
    return (
        tuple(pat.pattern for pat in p.bash_allow),
        p.jq_operand_gated, p.adapters, p.adapter_sql_pipe, p.raw_reads,
        tuple(str(r) for r in p.read_roots),
        tuple(str(r) for r in p.read_confine),
        tuple(pat.pattern for pat in p.write_allow),
        p.deny_reason,
    )


def _policy_full(p) -> tuple:
    """`_policy9` plus the read_shapes filename grammar — the projection that proves the
    defender_dir==PATHS threading is behaviour-preserving over EVERY field a caller reads."""
    return _policy9(p) + (tuple(pat.pattern for pat in p.read_shapes),)


def _actor_scope() -> RunScope:
    return RunScope(scripts=(_ENV_RETRIEVE, _ACTOR_INDEX), read_confine=(_ACTOR_DIR, _ENV_DIR))


def _reader_toolset() -> ToolSet:
    """A main/gather-shaped reader ToolSet — the full declared viewer/shim set, so a compiled
    lane equals the kept `policy_for` API."""
    return ToolSet(
        read=True,
        bash=BashGrammar(viewers=READER_VIEWERS, shims=tuple(NON_ADAPTER_SHIMS)),
    )


# ============================================================================
# D0 — the return-value contract (resolve FIRST)
# ============================================================================

def test_d0_bind_return_contract(tmp_path):
    """d0_bind_return_contract: bind(defn, run_dir, *, scope, salt, defender_dir=None) returns
    the role's AgentDeps subtype whose .policy is an AgentPolicy, .run_id == run_dir.name,
    .salt is the passed salt verbatim, and .defender_dir is the SAME tree threaded in (never
    PATHS when a worktree tree is passed). NO separate repo_root kwarg."""
    # RED@HEAD: bind's signature has `repo_root`, not `defender_dir` → TypeError.
    run = tmp_path / "run-xyz"
    wt = tmp_path / "wt" / "defender"
    deps = bind(MAIN_DEF, run, scope=RunScope(), salt="a" * 32, defender_dir=wt)
    assert isinstance(deps, AgentDeps)
    assert isinstance(deps.policy, permission.AgentPolicy)
    assert deps.run_id == run.name
    assert deps.salt == "a" * 32
    assert deps.defender_dir == wt          # the threaded tree, NOT PATHS


# ============================================================================
# D1 — all seven roles obtain deps via bind
# ============================================================================

def test_d1_judge_via_bind(tmp_path):
    """d1_judge_via_bind: bind(JUDGE_DEF, scope=RunScope(add_dirs, ticket_cli)) yields a
    jq_operand_gated + raw_reads policy whose read_roots == add_dirs and whose bash lane
    carries the pinned --require-closed ticket read."""
    # GREEN@HEAD: judge binds off scope alone (no defender_dir); stays green post-#551.
    run = tmp_path / "run"
    cmp = tmp_path / "cmp"
    tcli = tmp_path / "ticket_cli.py"
    jdeps = bind(JUDGE_DEF, run, scope=RunScope(add_dirs=(cmp,), ticket_cli=("python3", tcli)))
    assert isinstance(jdeps, JudgeDeps)
    jpol = jdeps.policy
    assert jpol.jq_operand_gated
    assert jpol.raw_reads
    assert jpol.read_roots == (cmp,)
    # bash-jq lane: a jq operand inside the comparison root is admitted, outside denied.
    assert permission.decide_bash(f"jq '.' {cmp}/a.json", policy=jpol, run_dir=run, defender_dir=_DEFENDER).allow
    assert not permission.decide_bash("jq '.' /etc/passwd", policy=jpol, run_dir=run, defender_dir=_DEFENDER).allow
    # the benign --require-closed ticket read (required flag enforced).
    assert permission.decide_bash(f"python3 {tcli} list-tickets --require-closed", policy=jpol, run_dir=run, defender_dir=_DEFENDER).allow
    assert not permission.decide_bash(f"python3 {tcli} list-tickets", policy=jpol, run_dir=run, defender_dir=_DEFENDER).allow


def test_d1_actor_via_bind(tmp_path):
    """d1_actor_via_bind: bind(ACTOR_DEF, scope=RunScope(scripts, read_confine)) yields a policy
    with one python3-<script> bash pattern per pinned script, read_confine == the confine, raw_reads False."""
    # GREEN@HEAD: actor binds off scope alone; stays green post-#551.
    run = tmp_path / "run"
    scope = _actor_scope()
    apol = bind(ACTOR_DEF, run, scope=scope).policy
    assert apol.read_confine == scope.read_confine
    assert not apol.raw_reads
    assert len(apol.bash_allow) == len(scope.scripts)
    assert permission.decide_bash(f"python3 {_ENV_RETRIEVE} --tags", policy=apol, run_dir=run, defender_dir=_DEFENDER).allow
    assert not permission.decide_bash("cat /etc/passwd", policy=apol, run_dir=run, defender_dir=_DEFENDER).allow


def test_d1_oracle_via_bind(tmp_path):
    """d1_oracle_via_bind (survival): bind(ORACLE_DEF, run_dir) yields a deny-all policy — the
    tool-free predictor's gate survives the factory retirement."""
    # GREEN@HEAD: bind(ORACLE_DEF) already compiles a deny-all policy over ORACLE_DEF's empty ToolSet.
    run = tmp_path / "run"
    opol = bind(ORACLE_DEF, run).policy
    assert isinstance(bind(ORACLE_DEF, run), OracleDeps)
    assert not permission.decide_bash("ls", policy=opol, run_dir=run, defender_dir=_DEFENDER).allow
    assert not permission.decide_write(run / "x.md", "c", policy=opol).allow


def test_d1_verifier_via_bind(tmp_path):
    """d1_verifier_via_bind (survival): bind(VERIFY_DEF, source_run_dir) yields deny-all."""
    # GREEN@HEAD: same deny-all-via-empty-ToolSet path as the oracle.
    run = tmp_path / "source-run"
    vpol = bind(VERIFY_DEF, run).policy
    assert isinstance(bind(VERIFY_DEF, run), VerifierDeps)
    assert not permission.decide_bash("ls", policy=vpol, run_dir=run, defender_dir=_DEFENDER).allow
    assert not permission.decide_write(run / "x.md", "c", policy=vpol).allow


def test_d1_lead_author_via_bind(tmp_path):
    """d1_lead_author_via_bind (survival): bind(LEAD_AUTHOR_DEF, run_dir, defender_dir=<wt>/defender)
    flows through resolve_roots→compile_policy (no early-return); the worktree write scope + rm grant
    (formerly `_lead_author_policy`, now compile_policy via write_shapes) both reproduce."""
    # RED@HEAD: bind takes `repo_root`, not `defender_dir` → TypeError (the early-return path).
    run = tmp_path / "run"
    wtd = tmp_path / "wt" / "defender"
    skills = wtd / "skills"
    deps = bind(LEAD_AUTHOR_DEF, run, defender_dir=wtd)
    assert isinstance(deps, LeadAuthorDeps)
    pol = deps.policy
    # write scope: the worktree skills .md corpus.
    assert permission.decide_write(skills / "gather" / "x.md", "c", policy=pol).allow
    # rm-of-drafts grant.
    assert permission.decide_bash(f"rm {skills}/gather/_draft/x.md", policy=pol, run_dir=run, defender_dir=wtd).allow


def test_d1_stages_mint_fresh_salt(tmp_path):
    """d1_stages_mint_fresh_salt: salt=None mints a fresh 32-hex uuid4 (two binds differ); a
    carried salt threads verbatim; MAIN carries the run's persisted salt."""
    # GREEN@HEAD: the salt seam shipped with #545; the fold must keep it.
    run = tmp_path / "run"
    d1 = bind(ORACLE_DEF, run)
    d2 = bind(ORACLE_DEF, run)
    assert re.fullmatch(r"[0-9a-f]{32}", d1.salt)
    assert d1.salt != d2.salt
    assert bind(ORACLE_DEF, run, salt="feed" * 8).salt == "feed" * 8
    assert bind(MAIN_DEF, run, salt="beef" * 8).salt == "beef" * 8


def test_d1_base_for_run_spine_survives(tmp_path):
    """d1_base_for_run_spine_survives (survival): the BASE AgentDeps._for_run spine bind calls
    is CONSERVED — an over-eager subtraction that deletes it would break bind itself."""
    # GREEN@HEAD (conservation guard): bind routes through _for_run (run_id + minted salt prove it).
    run = tmp_path / "run-abc"
    deps = bind(ORACLE_DEF, run)
    assert deps.run_id == run.name                 # _for_run sets run_id = run_dir.name
    assert re.fullmatch(r"[0-9a-f]{32}", deps.salt)  # _for_run minted the salt
    assert hasattr(AgentDeps, "_for_run")            # the base spine survives


def test_d1_no_factory_in_stage_modules():
    """d1_no_factory_in_stage_modules: grep for `for_scope(` / `for_run(` (the five stage front
    doors) returns nothing in the five stage modules — every production deps site obtains AgentDeps
    via bind, not a co-located factory."""
    # RED@HEAD: the front doors (ActorDeps.for_scope / OracleDeps.for_run / …) still exist + are called.
    base = PATHS.repo_root / "defender" / "learning"
    modules = {
        "judge": base / "pipeline" / "judge" / "engine_pydantic.py",
        "actor": base / "pipeline" / "actor_engine.py",
        "oracle": base / "pipeline" / "oracle_engine.py",
        "verifier": base / "author" / "verify_forward" / "engine.py",
        "lead_author": base / "leads" / "lead_author_engine.py",
    }
    for name, path in modules.items():
        src = path.read_text()
        assert "for_scope(" not in src, f"{name} still has a for_scope front door"
        assert "for_run(" not in src, f"{name} still has a for_run/_for_run front door"


# ============================================================================
# D2 — write scope as data (write_shapes; lead-author fork removed)
# ============================================================================

def test_d2_write_shapes_field(tmp_path):
    """d2_write_shapes_field (seam): compile_policy takes write_shapes — per-run (run_dir,
    defender_dir)->patterns builders resolved into write_allow (exactly like read_shapes); a
    read-only stage's empty write_shapes ⇒ empty write_allow."""
    # RED@HEAD: compile_policy is 4-arg (tools, read_shapes, roots, deny_reason) → TypeError.
    run = tmp_path / "run"
    roots = resolve_roots(run, (), RunScope())
    main_shape = lambda rd, dfn: (permission.build_write_allow(rd),)  # noqa: E731
    pol = compile_policy(_reader_toolset_write(), (), (main_shape,), roots, "d")
    assert permission.decide_write(run / "x.md", "c", policy=pol).allow          # resolved into write_allow
    assert not permission.decide_write(tmp_path / "y.md", "c", policy=pol).allow  # outside the shape
    ro = compile_policy(_reader_toolset(), (), (), roots, "d")                    # write=False + empty
    assert ro.write_allow == ()


def _reader_toolset_write() -> ToolSet:
    """A writer ToolSet (read + bash + write) for the write_shapes compile_policy tests."""
    return ToolSet(read=True, bash=BashGrammar(), write=True)


def test_d2_main_write_shape_anchors_run_dir(tmp_path):
    """d2_main_write_shape_anchors_run_dir (domain-outcome): MAIN's write shape anchors run_dir —
    decide_write admits run_dir/x.md and DENIES defender_dir/skills/x.md (a defender_dir-anchored
    shape would let MAIN author the corpus)."""
    # GREEN@HEAD: MAIN's run-dir write scope must survive the read_shapes→write_shapes migration.
    run = tmp_path / "run"
    pol = bind(MAIN_DEF, run).policy
    assert permission.decide_write(run / "x.md", "c", policy=pol).allow              # positive control
    assert not permission.decide_write(_DEFENDER / "skills" / "x.md", "c", policy=pol).allow


def test_d2_lead_author_write_shape_anchors_skills(tmp_path):
    """d2_lead_author_write_shape_anchors_skills (domain-outcome): LEAD_AUTHOR's write shape uses
    roots.DEFENDER_DIR/skills suffix .md — decide_write admits <wt>/defender/skills/gather/x.md but
    DENIES run_dir/x.md (wrong root) and skills/x.txt (wrong suffix)."""
    # RED@HEAD: bind(LEAD_AUTHOR_DEF, …, defender_dir=) → TypeError (repo_root today).
    run = tmp_path / "run"
    wtd = tmp_path / "wt" / "defender"
    skills = wtd / "skills"
    pol = bind(LEAD_AUTHOR_DEF, run, defender_dir=wtd).policy
    assert permission.decide_write(skills / "gather" / "x.md", "c", policy=pol).allow   # positive control (.md)
    assert not permission.decide_write(run / "x.md", "c", policy=pol).allow             # wrong root
    assert not permission.decide_write(skills / "gather" / "x.txt", "c", policy=pol).allow  # wrong suffix


def test_d2_write_shape_resolves_symlinked_root(tmp_path):
    """d2_write_shape_resolves_symlinked_root (parity): under a symlinked base, decide_write of a
    real-path target is admitted — the write shape anchors on RESOLVED roots (the write twin of
    reader_read_shapes' #546 .resolve()); a shape that forgot resolve() bricks every write."""
    # GREEN@HEAD: build_write_allow already resolve()s its root; the migration must keep it.
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "linkrun"
    os.symlink(real, link)
    pol = bind(MAIN_DEF, link).policy
    assert permission.decide_write(link / "x.md", "c", policy=pol).allow  # link/x.md resolves to real/x.md


def test_d2_main_lead_shapes_no_cross_contamination(tmp_path):
    """d2_main_lead_shapes_no_cross_contamination (negative): MAIN's suffix-less run-dir shape admits
    any basename under run_dir; LEAD's .md skills shape admits only skills/**.md — neither def's shape
    widens into the other's root/suffix (positive control: each admits its own sanctioned write)."""
    # RED@HEAD: the LEAD half needs bind(LEAD_AUTHOR_DEF, defender_dir=) → TypeError.
    run = tmp_path / "run"
    wtd = tmp_path / "wt" / "defender"
    skills = wtd / "skills"
    main_pol = bind(MAIN_DEF, run).policy
    lead_pol = bind(LEAD_AUTHOR_DEF, run, defender_dir=wtd).policy

    assert permission.decide_write(run / "scratch.bin", "c", policy=main_pol).allow      # MAIN: any basename
    assert not permission.decide_write(skills / "x.md", "c", policy=main_pol).allow      # MAIN doesn't widen into skills
    assert permission.decide_write(skills / "gather" / "x.md", "c", policy=lead_pol).allow  # LEAD: sanctioned .md
    assert not permission.decide_write(run / "x.md", "c", policy=lead_pol).allow         # LEAD doesn't widen into run_dir


def test_d2_lead_author_rm_scope(tmp_path):
    """d2_lead_author_rm_scope (negative): the bound lead-author's decide_bash admits `rm
    <wt>/defender/skills/<draft>` (positive control) but DENIES a bare/general `rm -rf /`, an `rm`
    outside the skills subtree, and `rm defender/skills/../../x` (textual `..`, no symlink follow)."""
    # RED@HEAD: bind(LEAD_AUTHOR_DEF, defender_dir=) → TypeError.
    run = tmp_path / "run"
    wtd = tmp_path / "wt" / "defender"
    skills = wtd / "skills"
    pol = bind(LEAD_AUTHOR_DEF, run, defender_dir=wtd).policy

    def _bash(cmd: str) -> bool:
        return permission.decide_bash(cmd, policy=pol, run_dir=run, defender_dir=wtd).allow

    assert _bash(f"rm {skills}/gather/_draft/x.md")   # positive control (scoped rm)
    assert not _bash("rm -rf /")                       # not a general rm
    assert not _bash(f"rm {run}/report.md")            # not outside the skills subtree
    assert not _bash("rm defender/skills/../../x")     # textual `..` rejected


def test_d2_lead_author_early_return_removed(tmp_path):
    """d2_lead_author_early_return_removed (survival): the LEAD_AUTHOR early-return in bind is gone;
    bind(LEAD_AUTHOR_DEF, run_dir, defender_dir=<wt>) reaches the _deps_class(LEAD_AUTHOR) tail and
    returns LeadAuthorDeps via the uniform spine."""
    # RED@HEAD: bind has no defender_dir kwarg (early-return path takes repo_root) → TypeError.
    run = tmp_path / "run"
    wtd = tmp_path / "wt" / "defender"
    deps = bind(LEAD_AUTHOR_DEF, run, defender_dir=wtd)
    assert isinstance(deps, LeadAuthorDeps)
    assert deps.run_id == run.name           # the uniform _for_run tail ran


def test_d2_deps_class_maps_every_bindable_role(tmp_path):
    """d2_deps_class_all_roles (migrated from test_bind_wiring_545): bind maps every BINDABLE role
    to its AgentDeps subtype — none silently mismapped. The one role bind does NOT build is
    CORPUS_AUTHOR (the #556 curator port): like the lead author it is a per-spawn writer, but its
    policy needs the worktree `corpus_dir` + `verifier_scripts` that bind's RunScope cannot carry
    (compiling it here would root its write_allow at run_dir), so it is constructed only via
    `CuratorDeps.for_run` and bind(CORPUS_AUTHOR_DEF) FAILS LOUD rather than mint a wrong policy."""
    cases = [
        (bind(MAIN_DEF, tmp_path), AgentDeps),
        (bind(GATHER_DEF, tmp_path), GatherDeps),
        (bind(JUDGE_DEF, tmp_path), JudgeDeps),
        (bind(ACTOR_DEF, tmp_path, scope=RunScope(read_confine=(tmp_path / "env",))), ActorDeps),
        (bind(ORACLE_DEF, tmp_path), OracleDeps),
        (bind(VERIFY_DEF, tmp_path), VerifierDeps),
        (bind(LEAD_AUTHOR_DEF, tmp_path / "run", defender_dir=tmp_path / "wt" / "defender"),
         LeadAuthorDeps),
    ]
    # 8 roles total: the 7 bindable ones above + CORPUS_AUTHOR (for_run-only, asserted below).
    assert len({role for role in AgentRole}) == 8
    for deps, expected in cases:
        assert type(deps) is expected, f"{deps.role} → {type(deps).__name__}, want {expected.__name__}"
    with pytest.raises((ValueError, TypeError)):
        bind(CORPUS_AUTHOR_DEF, tmp_path)


# ============================================================================
# D3 — defender_dir threaded through resolve_roots AND _for_run (deps)
# ============================================================================

def test_d3_resolve_roots_defender_dir_param(tmp_path):
    """d3_resolve_roots_defender_dir_param (seam): resolve_roots takes defender_dir (default
    PATHS.defender_dir) — ResolvedRoots.defender_dir is the passed value, no longer hardcoded."""
    run = tmp_path / "run"
    wtd = tmp_path / "wt" / "defender"
    assert resolve_roots(run, (), RunScope()).defender_dir == _DEFENDER   # positive control (default)
    # RED@HEAD: resolve_roots is 3-arg → TypeError on the defender_dir kwarg.
    assert resolve_roots(run, (), RunScope(), defender_dir=wtd).defender_dir == wtd


def test_d3_bind_threads_defender_dir_into_deps_field(tmp_path):
    """d3_bind_threads_defender_dir_into_deps_field (parity): bind(MAIN_DEF, run, defender_dir=wt)
    threads the tree into BOTH the deps field (deps.defender_dir == wt, NOT PATHS) AND the policy
    anchor (a wt corpus read is admitted when the gate is called with the same wt)."""
    # RED@HEAD: bind has no defender_dir kwarg → TypeError.
    run = tmp_path / "run"
    wtd = tmp_path / "wt" / "defender"
    deps = bind(MAIN_DEF, run, defender_dir=wtd)
    assert deps.defender_dir == wtd
    # deps.defender_dir and the policy's read anchor are ONE tree → a wt corpus read admits.
    assert permission.decide_read(wtd / "lessons" / "a.md", run_dir=run, defender_dir=deps.defender_dir, policy=deps.policy).allow


def test_d3_partial_thread_bricks_worktree_reads(tmp_path):
    """d3_partial_thread_bricks_worktree_reads (negative): a policy anchored on tree A while
    decide_read/decide_bash are called with defender_dir=tree B (A != B, the split) DENIES every
    corpus read on BOTH surfaces — the total functional brick the canonical-PATHS suite can't
    exhibit; positive control: one consistent tree admits the corpus read."""
    # RED@HEAD: constructing the split requires bind(defender_dir=tree_a) → TypeError.
    run = tmp_path / "run"
    tree_a = tmp_path / "a" / "defender"
    tree_b = tmp_path / "b" / "defender"
    pol_a = bind(MAIN_DEF, run, defender_dir=tree_a).policy   # anchored on A
    probe_b = tree_b / "lessons" / "x.md"
    # split: policy anchored on A, gate called with B → deny on both surfaces.
    assert not permission.decide_read(probe_b, run_dir=run, defender_dir=tree_b, policy=pol_a).allow
    assert not permission.decide_bash(f"cat {probe_b}", policy=pol_a, run_dir=run, defender_dir=tree_b).allow
    # positive control: one consistent tree admits.
    pol_b = bind(MAIN_DEF, run, defender_dir=tree_b).policy
    assert permission.decide_read(probe_b, run_dir=run, defender_dir=tree_b, policy=pol_b).allow
    assert permission.decide_bash(f"cat {probe_b}", policy=pol_b, run_dir=run, defender_dir=tree_b).allow


def test_d3_lead_author_worktree_anchor(tmp_path):
    """d3_lead_author_worktree_anchor (behavior): bind(LEAD_AUTHOR_DEF, run, defender_dir=wt/defender)
    yields deps.defender_dir == wt/defender AND the policy's write_allow anchors on wt/defender."""
    # RED@HEAD: bind(LEAD_AUTHOR_DEF, defender_dir=) → TypeError (repo_root today).
    run = tmp_path / "run"
    wtd = tmp_path / "wt" / "defender"
    deps = bind(LEAD_AUTHOR_DEF, run, defender_dir=wtd)
    assert deps.defender_dir == wtd
    assert permission.decide_write(wtd / "skills" / "x.md", "c", policy=deps.policy).allow
    assert not permission.decide_write(_DEFENDER / "skills" / "x.md", "c", policy=deps.policy).allow


def test_d3_main_gather_non_paths_defender_dir(tmp_path):
    """d3_main_gather_non_paths_defender_dir (domain-outcome): bind(MAIN_DEF/GATHER_DEF, run,
    defender_dir=<non-PATHS worktree>) anchors the policy's read/bash surface on the passed tree,
    not PATHS."""
    # RED@HEAD: bind has no defender_dir kwarg → TypeError.
    run = tmp_path / "run"
    wtd = tmp_path / "wt" / "defender"
    probe = wtd / "lessons" / "a.md"
    for defn in (MAIN_DEF, GATHER_DEF):
        deps = bind(defn, run, defender_dir=wtd)
        assert permission.decide_read(probe, run_dir=run, defender_dir=wtd, policy=deps.policy).allow
        assert permission.decide_bash(f"cat {probe}", policy=deps.policy, run_dir=run, defender_dir=wtd).allow


def test_d3_paths_equal_behavior_preserving(tmp_path):
    """d3_paths_equal_behavior_preserving (domain-outcome, positive control): with defender_dir ==
    PATHS.defender_dir the compiled policy is IDENTICAL to today's — the threading is behaviour-
    preserving for every current caller."""
    # RED@HEAD: bind(MAIN_DEF, defender_dir=…) → TypeError; post-#551 both calls are equal.
    run = tmp_path / "run"
    threaded = bind(MAIN_DEF, run, defender_dir=_DEFENDER).policy
    default = bind(MAIN_DEF, run).policy
    assert _policy_full(threaded) == _policy_full(default)


def test_d3_main_driver_threads_param_into_bind():
    """d3_main_driver_threads_param_into_bind (behavior): run_investigation threads its defender_dir
    param into the bind(MAIN_DEF, …) call (so prompt tree == gate tree), not only into
    build_agent/_user_prompt while bind anchors PATHS."""
    # RED@HEAD: the driver's bind(MAIN_DEF, run_dir, salt=salt) call has no defender_dir today.
    src = (PATHS.repo_root / "defender" / "runtime" / "driver.py").read_text()
    assert re.search(r"bind\(\s*MAIN_DEF[^)]*defender_dir\s*=", src), \
        "run_investigation must thread defender_dir into bind(MAIN_DEF, …)"


def test_d3_gather_threads_not_restamps():
    """d3_gather_threads_not_restamps (parity): the GATHER dispatch builds deps as
    bind(GATHER_DEF, deps.run_dir, salt=deps.salt, defender_dir=deps.defender_dir) and DROPS the
    replace(defender_dir=…) restamp — policy anchor and deps field are one tree (no restamp split),
    and the PARENT run's salt is threaded in (a fresh uuid4 would split the run's ONE untrusted-data
    trust token and fail the injection defence open — the #546 footgun)."""
    # RED@HEAD: bind(GATHER_DEF, …) has no defender_dir kwarg; the tree rides a replace() restamp.
    src = (PATHS.repo_root / "defender" / "runtime" / "tools_gather.py").read_text()
    assert re.search(r"bind\(\s*GATHER_DEF[^)]*defender_dir\s*=", src), \
        "the gather dispatch must thread defender_dir into bind(GATHER_DEF, …)"
    # Salt-not-split (the #546 injection-defense footgun): the bind(GATHER_DEF, …) call must carry
    # the parent run's salt (salt=deps.salt), never let bind mint a fresh uuid4 for the subagent.
    assert re.search(r"bind\(\s*GATHER_DEF[^)]*salt\s*=\s*deps\.salt", src), \
        "the gather dispatch must thread the parent run's salt (salt=deps.salt) into " \
        "bind(GATHER_DEF, …) — a fresh uuid4 would split the run's untrusted-data trust token"
    assert "defender_dir=deps.defender_dir, lead_id=" not in src, \
        "the replace(defender_dir=…) restamp must be dropped (bind anchors the tree)"


def test_d3_corpus_traversal_guard_survives(tmp_path):
    """d3_corpus_traversal_guard_survives (survival): resolve_roots still RAISES ValueError on a
    '..'/absolute corpus name after _resolve_corpus_dir stops hardcoding PATHS — the traversal
    defence is on the NAME, independent of which tree it anchors."""
    # GREEN@HEAD: the guard exists today; the defender_dir thread must not weaken it.
    run = tmp_path / "run"
    with pytest.raises(ValueError, match="clean relative name"):
        resolve_roots(run, ("../evil",), RunScope())
    with pytest.raises(ValueError, match="clean relative name"):
        resolve_roots(run, ("/abs",), RunScope())
    assert resolve_roots(run, ("lessons",), RunScope()).corpus_roots  # positive control (clean name)


# ============================================================================
# D4 — actor confine + lead-author tree preconditions as data
# ============================================================================

def test_d4_requires_confine_data(tmp_path):
    """d4_requires_confine_data (seam): the actor's empty-read_confine fail-loud is a
    requires_confine bool on AgentDefinition (True on ACTOR_DEF, False on MAIN_DEF)."""
    # RED@HEAD: AgentDefinition has no requires_confine field → AttributeError.
    assert ACTOR_DEF.requires_confine is True
    assert MAIN_DEF.requires_confine is False


def test_d4_actor_empty_confine_raises(tmp_path):
    """d4_actor_empty_confine_raises (negative): bind(ACTOR_DEF, run_dir) with the default empty
    read_confine RAISES — no unconfined ActorDeps is ever constructed (the #512 gray-box leak,
    safe-by-construction); positive control: a non-empty confine SUCCEEDS."""
    # GREEN@HEAD: the fail-loud exists today; it must SURVIVE the altitude change to a data bit.
    run = tmp_path / "run"
    with pytest.raises(ValueError, match="read_confine"):
        bind(ACTOR_DEF, run)                              # empty confine
    assert isinstance(bind(ACTOR_DEF, run, scope=_actor_scope()), ActorDeps)  # positive control


def test_d4_actor_with_confine_no_widen(tmp_path):
    """d4_actor_with_confine_no_widen (behavior, positive control): bind(ACTOR_DEF, scope=<confine>)
    succeeds; policy.read_confine == the confine and the resolved read roots do NOT include the whole
    defender_dir (the confine REPLACES the base)."""
    # GREEN@HEAD.
    run = tmp_path / "run"
    scope = _actor_scope()
    deps = bind(ACTOR_DEF, run, scope=scope)
    assert deps.policy.read_confine == scope.read_confine
    roots = files._resolved_read_roots(deps.policy, run, _DEFENDER)
    assert _DEFENDER.resolve() not in roots


def test_d4_main_empty_confine_ok(tmp_path):
    """d4_main_empty_confine_ok (behavior, positive control): bind(MAIN_DEF, run_dir) with the default
    empty confine SUCCEEDS — requires_confine is False for main; main legitimately reads defender_dir."""
    # GREEN@HEAD.
    run = tmp_path / "run"
    deps = bind(MAIN_DEF, run)
    assert deps.policy.read_confine == ()
    assert permission.decide_read(_CORPUS_MD, run_dir=run, defender_dir=_DEFENDER, policy=deps.policy).allow


def test_d4_no_role_branch_in_bind(tmp_path):
    """d4_no_role_branch_in_bind (negative): NO `if defn.role is AgentRole.X` branch remains — BOTH
    preconditions are data: a synthetic NON-actor def with requires_confine=True + empty confine raises,
    and a synthetic def with requires_explicit_tree=True + no defender_dir raises, each via the generic
    data check (not a role-identity branch)."""
    # RED@HEAD: requires_confine / requires_explicit_tree are new AgentDefinition fields → TypeError.
    run = tmp_path / "run"
    confine_def = AgentDefinition(
        role=AgentRole.ORACLE, model=lambda: "m", effort=None, requires_confine=True,
    )
    with pytest.raises((ValueError, TypeError)):
        bind(confine_def, run)                            # empty confine + generic data check
    tree_def = AgentDefinition(
        role=AgentRole.ORACLE, model=lambda: "m", effort=None, requires_explicit_tree=True,
    )
    with pytest.raises((ValueError, TypeError)):
        bind(tree_def, run)                               # no defender_dir + generic data check


def test_d4_lead_author_no_tree_raises(tmp_path):
    """d4_lead_author_no_tree_raises (negative): after the early-return is deleted, bind(LEAD_AUTHOR_DEF,
    run_dir) with NO defender_dir RAISES via the requires_explicit_tree data bit — never a silent
    PATHS/run_dir fallback authoring the MAIN checkout; positive control: an explicit worktree tree succeeds."""
    run = tmp_path / "run"
    wtd = tmp_path / "wt" / "defender"
    with pytest.raises((ValueError, TypeError)):
        bind(LEAD_AUTHOR_DEF, run)                        # no tree — raises today (repo_root) + post-#551 (data bit)
    # RED@HEAD: the positive control uses the new defender_dir kwarg → TypeError.
    assert isinstance(bind(LEAD_AUTHOR_DEF, run, defender_dir=wtd), LeadAuthorDeps)


# ============================================================================
# D5 — the parallel factory path retires
# ============================================================================

def test_d5_oracle_verify_denyall_via_compile_policy(tmp_path):
    """d5_oracle_verify_denyall_via_compile_policy (survival): the _ORACLE_POLICY/_VERIFY_POLICY
    production constructors are gone; bind(ORACLE_DEF)/bind(VERIFY_DEF) still yield deny-all policies
    via compile_policy over an empty ToolSet."""
    # GREEN@HEAD: bind already compiles both from their empty ToolSets; stays green.
    run = tmp_path / "run"
    for defn in (ORACLE_DEF, VERIFY_DEF):
        pol = bind(defn, run).policy
        assert pol.bash_allow == ()
        assert pol.write_allow == ()
        assert not permission.decide_bash("cat x", policy=pol, run_dir=run, defender_dir=_DEFENDER).allow
        assert not permission.decide_write(run / "x.md", "c", policy=pol).allow


def test_d5_judge_actor_bash_lane_preserved(tmp_path):
    """d5_judge_actor_bash_lane_preserved (survival): the judge jq lane (jq_operand_gated, operands
    confined to the read roots) and the actor python3-<script> lane are UNCHANGED by the factory
    retirement — _judge_policy/_actor_policy stay as compile_policy._bash_allow's pattern helpers."""
    # GREEN@HEAD: decide_bash for judge/actor is identical after #551.
    run = tmp_path / "run"
    cmp = tmp_path / "cmp"
    jpol = bind(JUDGE_DEF, run, scope=RunScope(add_dirs=(cmp,))).policy
    assert jpol.jq_operand_gated
    assert permission.decide_bash(f"jq '.' {cmp}/a.json", policy=jpol, run_dir=run, defender_dir=_DEFENDER).allow
    assert not permission.decide_bash("jq '.' /etc/shadow", policy=jpol, run_dir=run, defender_dir=_DEFENDER).allow

    apol = bind(ACTOR_DEF, run, scope=_actor_scope()).policy
    assert permission.decide_bash(f"python3 {_ACTOR_INDEX} --q x", policy=apol, run_dir=run, defender_dir=_DEFENDER).allow
    assert not permission.decide_bash("grep secret /etc/passwd", policy=apol, run_dir=run, defender_dir=_DEFENDER).allow


def test_d5_actor_read_confine_not_leaked_from_builder(tmp_path):
    """d5_actor_read_confine_not_leaked_from_builder (negative): the bound actor's policy.read_confine
    == scope.read_confine, NOT the read_confine=() compile_policy passes to the actor bash-pattern
    builder — conflating them collapses the actor to an empty confine (the whole defender_dir, the
    #512 leak); positive control: the confine is the named corpus."""
    # GREEN@HEAD.
    run = tmp_path / "run"
    scope = _actor_scope()
    apol = bind(ACTOR_DEF, run, scope=scope).policy
    assert apol.read_confine == scope.read_confine   # NOT the builder's read_confine=()
    assert apol.read_confine != ()
    # the confine is honoured on the read tool: a file in it is readable, one outside is not.
    assert permission.decide_read(_ACTOR_DIR / "x.md", run_dir=run, defender_dir=_DEFENDER, policy=apol).allow
    assert not permission.decide_read(_DEFENDER / "skills" / "gather" / "SKILL.md", run_dir=run, defender_dir=_DEFENDER, policy=apol).allow


def test_d5_policy_for_is_bind_alias(tmp_path):
    """d5_policy_for_is_bind_alias (survival): policy_for survives only as a bind alias — its returned
    policy now carries reader_read_shapes (old main_policy set read_shapes=()), so a non-.md corpus
    read via policy_for('main') flips allow→deny to MATCH bind(MAIN_DEF) (hole H4)."""
    # RED@HEAD: policy_for('main') dispatches to main_policy (read_shapes=()) → the .py is admitted.
    run = tmp_path / "run"
    ppol = permission.policy_for("main", run_dir=run, defender_dir=_DEFENDER)
    assert not permission.decide_read(_NON_MD, run_dir=run, defender_dir=_DEFENDER, policy=ppol).allow
    # positive control: the bound reader already denies the non-.md corpus file (the target behaviour).
    bpol = bind(MAIN_DEF, run).policy
    assert not permission.decide_read(_NON_MD, run_dir=run, defender_dir=_DEFENDER, policy=bpol).allow


def test_d5_reader_patterns_for_kept(tmp_path):
    """d5_reader_patterns_for_kept (survival): the parametrized reader_patterns_for STAYS (the
    compile_policy._bash_allow caller) so every bound main/gather reader lane is unchanged."""
    # GREEN@HEAD.
    assert callable(reader_patterns_for)
    run = tmp_path / "run"
    pol = bind(MAIN_DEF, run).policy
    assert permission.decide_bash(f"cat {_CORPUS_MD}", policy=pol, run_dir=run, defender_dir=_DEFENDER).allow
    assert not permission.decide_bash("cat /etc/passwd", policy=pol, run_dir=run, defender_dir=_DEFENDER).allow


# ============================================================================
# D6 — wire the write ⊆ read guard
# ============================================================================

def test_d6_writers_pass_roots(tmp_path):
    """d6_writers_pass_roots (seam): both writer call sites (tools.py write_file/edit_file) call
    decide_write with run_dir=deps.run_dir and defender_dir=deps.defender_dir, activating the
    write⊆read guard — driving _tool_write_file with an escaping write_allow is DENIED (today it
    is allowed, the guard being dormant)."""
    run = tmp_path / "run"
    run.mkdir()
    dfn = tmp_path / "dfn"
    dfn.mkdir()
    escape = tmp_path / "escape"                          # outside run + dfn (the read surface)
    escape_pol = AgentPolicy(
        write_allow=(permission.build_write_allow(escape, suffix=".md"),), deny_reason="d",
    )
    deps = AgentDeps(run_dir=run, defender_dir=dfn, run_id="r", salt="s", policy=escape_pol)
    # RED@HEAD: _tool_write_file calls decide_write WITHOUT roots → the guard is dormant → allowed.
    with pytest.raises(ModelRetry):
        _tool_write_file(deps, str(escape / "x.md"), "content")
    # both call sites must pass the tree — a source check covers edit_file (whose read gate already
    # denies the escape, so the wiring is not behaviourally separable there).
    tools_src = (PATHS.repo_root / "defender" / "runtime" / "tools.py").read_text()
    calls = re.findall(r"decide_write\(.*?policy=deps\.policy", tools_src, re.DOTALL)
    assert len(calls) == 2
    assert all("defender_dir=deps.defender_dir" in c for c in calls)


def test_d6_guard_denies_escape(tmp_path):
    """d6_guard_denies_escape (negative): with both roots supplied, decide_write DENIES a target
    matching write_allow but resolving OUTSIDE the read surface (an escaping write_allow) — the
    guard's reason to exist; the paired positive control is d6_guard_noop_for_real_writers."""
    # GREEN@HEAD: the guard lives in decide_write; it just needs roots (dormant at the tool call sites).
    run = tmp_path / "run"
    dfn = tmp_path / "dfn"
    escape = tmp_path / "escape"
    pol = AgentPolicy(write_allow=(permission.build_write_allow(escape, suffix=".md"),), deny_reason="d")
    tgt = escape / "x.md"
    assert not permission.decide_write(tgt, "c", run_dir=run, defender_dir=dfn, policy=pol).allow  # roots → guard denies
    assert permission.decide_write(tgt, "c", policy=pol).allow                                     # no roots → dormant (allow)


def test_d6_guard_noop_for_real_writers(tmp_path):
    """d6_guard_noop_for_real_writers (behavior, positive control): with both roots supplied, a MAIN
    write under run_dir and a LEAD_AUTHOR write under <wt>/defender/skills/x.md are STILL allowed —
    the guard is a no-op for every real writer (D6 behaviour-preserving)."""
    # GREEN@HEAD.
    run = tmp_path / "run"
    wtd = tmp_path / "wt" / "defender"
    skills = wtd / "skills"
    main_pol = bind(MAIN_DEF, run).policy
    assert permission.decide_write(run / "report.md", "c", run_dir=run, defender_dir=_DEFENDER, policy=main_pol).allow
    lead_pol = AgentPolicy(write_allow=(permission.build_write_allow(skills, suffix=".md"),), deny_reason="d")
    assert permission.decide_write(skills / "gather" / "x.md", "c", run_dir=run, defender_dir=wtd, policy=lead_pol).allow


def test_d6_guard_needs_worktree_defender_dir(tmp_path):
    """d6_guard_needs_worktree_defender_dir (parity, D6 × the deps/policy split): the write⊆read guard
    admits <wt>/skills/x.md ONLY when deps.defender_dir is the worktree tree the write_allow anchors
    on; if deps=PATHS (the split) the legit lead-author write DENIES — the split is observable on WRITES."""
    # RED@HEAD: the lead-author policy anchored on a worktree needs bind(defender_dir=) → TypeError.
    run = tmp_path / "run"
    wtd = tmp_path / "wt" / "defender"
    target = wtd / "skills" / "gather" / "x.md"
    pol = bind(LEAD_AUTHOR_DEF, run, defender_dir=wtd).policy
    # consistent tree → admitted.
    assert permission.decide_write(target, "c", run_dir=run, defender_dir=wtd, policy=pol).allow
    # the split (deps tree = PATHS while write_allow anchors on wt) → the legit write DENIES.
    assert not permission.decide_write(target, "c", run_dir=run, defender_dir=_DEFENDER, policy=pol).allow


# ============================================================================
# R3 — read↔bash filename + symlink parity
# ============================================================================

def test_r3_read_bash_filename_parity(tmp_path):
    """r3_read_bash_filename_parity (parity): for a reader agent, decide_read and the bash cat lane
    agree on the SAME probe files — a corpus .md admitted by both, a non-.md corpus file denied by
    both (the read_shapes filter == the cat operand grammar)."""
    # GREEN@HEAD.
    run = tmp_path / "run"
    pol = bind(MAIN_DEF, run).policy
    for probe in (_CORPUS_MD, _NON_MD):
        read_ok = permission.decide_read(probe, run_dir=run, defender_dir=_DEFENDER, policy=pol).allow
        bash_ok = permission.decide_bash(f"cat {probe}", policy=pol, run_dir=run, defender_dir=_DEFENDER).allow
        assert read_ok == bash_ok, f"read-tool vs bash disagree on {probe}: read={read_ok} bash={bash_ok}"


def test_r3_symlinked_base_admits(tmp_path):
    """r3_symlinked_base_admits (parity): under a SYMLINKED run base (link->real), decide_read of a
    run-dir file is ADMITTED (resolves through the link) and agrees with the bash cat lane — the #546
    fixture the #545 suite lacked (all its fixtures were canonical)."""
    # GREEN@HEAD: reader_read_shapes anchors on the RESOLVED run base (#546); the fold must keep it.
    real = tmp_path / "real"
    real.mkdir()
    (real / "scratch.md").write_text("x")
    link = tmp_path / "linkrun"
    os.symlink(real, link)
    pol = bind(MAIN_DEF, link).policy
    probe = link / "scratch.md"
    read_ok = permission.decide_read(probe, run_dir=link, defender_dir=_DEFENDER, policy=pol).allow
    bash_ok = permission.decide_bash(f"cat {probe}", policy=pol, run_dir=link, defender_dir=_DEFENDER).allow
    assert read_ok      # decide_read resolves through the link
    assert bash_ok      # the bash cat lane agrees


def test_r3_symlink_pointing_out_denies(tmp_path):
    """r3_symlink_pointing_out_denies (negative): a symlink INSIDE the roots pointing OUT: decide_read
    DENIES (resolves outside); the bash cat lane denies a textual `..` traversal too (no-follow) —
    each surface blocks its own escape vector; positive control r3_symlinked_base_admits."""
    # GREEN@HEAD.
    run = tmp_path / "run"
    run.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret").write_text("x")
    evil = run / "evil"
    os.symlink(outside / "secret", evil)
    pol = bind(MAIN_DEF, run).policy
    assert not permission.decide_read(evil, run_dir=run, defender_dir=_DEFENDER, policy=pol).allow  # resolves out
    assert not permission.decide_bash(f"cat {run}/../outside/secret", policy=pol, run_dir=run, defender_dir=_DEFENDER).allow  # textual `..`


# ============================================================================
# R2 — per-pair isolation
# ============================================================================

def test_r2_resolve_roots_per_pair_distinct(tmp_path):
    """r2_resolve_roots_per_pair_distinct (uniqueness): two different (run_dir, defender_dir) pairs
    resolve to DISTINCT anchors — one run's confine never appears in another's policy, and no
    corpus-only cache-key bleed across defender_dir values (the #497/#534 hazard)."""
    run_a, run_b = tmp_path / "a", tmp_path / "b"
    # run-dir distinctness (GREEN today via bind's per-run resolve).
    da = bind(ACTOR_DEF, run_a, scope=RunScope(scripts=(_ENV_RETRIEVE,), read_confine=(run_a / "corpus",)))
    db = bind(ACTOR_DEF, run_b, scope=RunScope(scripts=(_ENV_RETRIEVE,), read_confine=(run_b / "corpus",)))
    assert da.policy.read_confine != db.policy.read_confine
    assert (run_a / "corpus") not in db.policy.read_confine
    # RED@HEAD: no corpus-only cache bleed across defender_dir values — resolve_roots(defender_dir=) TypeError.
    tree_a = tmp_path / "ta" / "defender"
    tree_b = tmp_path / "tb" / "defender"
    ra = resolve_roots(run_a, ("lessons",), RunScope(), defender_dir=tree_a)
    rb = resolve_roots(run_a, ("lessons",), RunScope(), defender_dir=tree_b)
    assert ra.corpus_roots == (tree_a / "lessons",)
    assert ra.corpus_roots != rb.corpus_roots


# ============================================================================
# R5 — safe-by-construction: compile_policy write co-constraint
# ============================================================================

def test_r5_tools_write_write_shapes_agree(tmp_path):
    """r5_tools_write_write_shapes_agree (negative, Q3 assert): compile_policy RAISES on an
    inconsistent AgentDefinition — write=True with empty write_shapes (a writer with no scope →
    would deny all writes) OR write=False with a non-empty write_shape (dead scope). Positive
    control: write=True+non-empty and write=False+empty both compile clean."""
    # RED@HEAD: compile_policy is 4-arg (no write_shapes) → the 5-arg call TypeErrors before it can validate.
    run = tmp_path / "run"
    roots = resolve_roots(run, (), RunScope())
    main_shape = lambda rd, dfn: (permission.build_write_allow(rd),)  # noqa: E731
    with pytest.raises((ValueError, TypeError)):
        compile_policy(_reader_toolset_write(), (), (), roots, "d")           # write=True ⊗ empty → raise
    with pytest.raises((ValueError, TypeError)):
        compile_policy(_reader_toolset(), (), (main_shape,), roots, "d")      # write=False ⊗ non-empty → raise
    # positive controls compile clean.
    compile_policy(_reader_toolset_write(), (), (main_shape,), roots, "d")    # write=True + non-empty
    compile_policy(_reader_toolset(), (), (), roots, "d")                     # write=False + empty


# ============================================================================
# D7 — bind input-validation seam (Q4 harden)
# ============================================================================

def test_d7_bind_validates_roots(tmp_path):
    """d7_bind_validates_roots (seam): bind validates its root inputs — a relative or empty-string
    root RAISES rather than silently anchoring CWD (the _require_read_root-style shape check
    policy_for already applies); positive control: an absolute run_dir succeeds."""
    assert isinstance(bind(MAIN_DEF, tmp_path / "run"), AgentDeps)  # positive control (absolute)
    # RED@HEAD: bind passes a relative run_dir straight to resolve_roots (anchors CWD); no validation.
    with pytest.raises((ValueError, TypeError)):
        bind(MAIN_DEF, Path("relative/run"))


def test_d7_bind_rejects_degenerate_confine(tmp_path):
    """d7_bind_rejects_degenerate_confine (negative): bind(ACTOR_DEF, scope=RunScope(read_confine=
    (Path(''),), …)) RAISES — the emptiness guard alone passes it (Path('') resolves to CWD, the actor
    reads the repo root); the root-validity check rejects it. Positive control: a real absolute confine
    succeeds."""
    run = tmp_path / "run"
    assert isinstance(bind(ACTOR_DEF, run, scope=_actor_scope()), ActorDeps)  # positive control
    # RED@HEAD: a non-empty tuple of Path('') passes the emptiness guard and is NOT root-validated today.
    with pytest.raises((ValueError, TypeError)):
        bind(ACTOR_DEF, run, scope=RunScope(read_confine=(Path(""),), scripts=(_ENV_RETRIEVE,)))


def test_d7_lead_author_main_tree_unbuildable(tmp_path):
    """d7_lead_author_main_tree_unbuildable (negative): bind(LEAD_AUTHOR_DEF, run, defender_dir=
    PATHS.defender_dir) RAISES — a requires_explicit_tree role must be given an explicit NON-PATHS
    worktree tree, so the main-checkout-authoring state is UNBUILDABLE (not merely well-behaved when
    configured right). Positive control: an explicit worktree tree (!= PATHS) succeeds."""
    # RED@HEAD: bind has no defender_dir kwarg → TypeError (the #551 ValueError can't yet fire).
    run = tmp_path / "run"
    wtd = tmp_path / "wt" / "defender"
    with pytest.raises((ValueError, TypeError)):
        bind(LEAD_AUTHOR_DEF, run, defender_dir=_DEFENDER)      # main-checkout tree — UNBUILDABLE
    assert isinstance(bind(LEAD_AUTHOR_DEF, run, defender_dir=wtd), LeadAuthorDeps)  # positive control
