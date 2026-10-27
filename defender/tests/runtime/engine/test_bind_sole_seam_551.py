"""bind/compile_policy as the sole policy seam: bind contract, write shapes, defender_dir threading, guards, symlink parity."""
from __future__ import annotations

from defender.agents import LEAD_AUTHOR_DEF, MAIN_DEF  # noqa: E402

import os
import re
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")  # CI installs the runtime extra; skip otherwise

from pydantic_ai.exceptions import ModelRetry  # noqa: E402

from defender._paths import PATHS  # noqa: E402
from defender.learning.leads.lead_author_engine import LeadAuthorDeps  # noqa: E402
from defender.investigation import permission  # noqa: E402
from defender._agent_role import AgentRole  # noqa: E402
from defender.investigation.permission.grant import Grant  # noqa: E402
from defender.investigation.permission.policies._common import reader_grants  # noqa: E402
from defender.investigation.permission.policy import AgentPolicy  # noqa: E402
from defender.investigation.tools import AgentDeps, _tool_write_file  # noqa: E402

from defender.tests.support.shared.contracts._repo import seed_adapter_stubs  # noqa: E402
from defender.tests.support.tenancy import _tenants1106 as T1106
from defender.investigation.agent_definition import (  # noqa: E402
    AgentDefinition,
    ResolvedRoots,
    RunScope,
    ToolSet,
    bind,
    compile_policy,
    compile_policy_for,
    read_allow_of,
    resolve_roots,
)

_DEFENDER = PATHS.defender_dir


_VALID_REPORT = "---\ndisposition: benign\n---\nok\n"

# Real repo-relative script/confine paths (mirrors test_bind_wiring_545.py) — the actor's
# _script_pattern does script.resolve().relative_to(REPO_ROOT), so synthetic paths raise.

_CORPUS_MD = _DEFENDER / "lessons" / "_probe_551.md"
_NON_MD = _DEFENDER / "skills" / "gather" / "run.py"   # a non-.md path under the corpus


def _grant(g: Grant) -> tuple:
    """One `Grant` as a comparable tuple — the shape (program + argv pattern), the scope (its anchored..."""
    return (
        g.program, g.pattern.pattern, tuple(s.pattern for s in g.scope), g.route, g.pins_path,
    )


def _policy_full(p) -> tuple:
    """EVERY AgentPolicy field as a comparable tuple (#575's fields — the capability bits and the second read..."""
    return (
        tuple(_grant(g) for g in p.bash_allow),
        tuple(pat.pattern for pat in p.read_allow),
        tuple(str(r) for r in p.read_roots),
        tuple(str(r) for r in p.read_confine),
        tuple(pat.pattern for pat in p.write_allow),
        p.deny_reason,
    )


def _reader_bash_shapes(roots: ResolvedRoots) -> tuple[Grant, ...]:
    """The production main-shaped reader grant builder (`_common.reader_grants`) — so a def compiled here carries..."""
    return reader_grants(roots.run_dir, roots.defender_dir, raw=False)


def _reader_def(*, write=False, write_shapes=()) -> AgentDefinition:
    """An ad-hoc main-shaped AgentDefinition for the `compile_policy` seam tests. Built INSIDE the helper (never..."""
    return AgentDefinition(
        role=AgentRole.MAIN,
        model=lambda: "m",
        effort=None,
        tools=ToolSet(read=True, bash=True, write=write),
        bash_shapes=(_reader_bash_shapes,),
        write_shapes=write_shapes,
        deps_cls=AgentDeps,
    )


def _main_write_shape(roots: ResolvedRoots) -> tuple:
    """MAIN's write scope builder shape: `(ResolvedRoots) -> patterns` (#575 — one arg, the resolved roots, not..."""
    return (permission.build_write_allow(roots.run_dir),)


# D0 — the return-value contract (resolve FIRST)

def test_d0_bind_return_contract(tmp_path):
    """d0_bind_return_contract: bind(defn, run_dir, *, scope, salt, defender_dir=None) returns the role's..."""
    # RED@HEAD: bind's signature has `repo_root`, not `defender_dir` → TypeError.
    run = tmp_path / "run-xyz"
    wt = tmp_path / "wt" / "defender"
    deps = bind(MAIN_DEF, run, scope=RunScope(), defender_dir=wt)
    assert isinstance(deps, AgentDeps)
    assert isinstance(deps.policy, permission.AgentPolicy)
    assert deps.run_id == run.name
    assert not hasattr(deps, "salt")   # #875: bind hands out no delimiter
    assert deps.defender_dir == wt          # the threaded tree, NOT PATHS


# D1 — all seven roles obtain deps via bind


def _lead_wtd(tmp_path):
    """A worktree tree the lead author can actually bind against."""
    wtd = tmp_path / "wt" / "defender"
    (wtd / "skills" / "gather" / "queries" / "elastic").mkdir(parents=True, exist_ok=True)
    (wtd / "skills" / "elastic" / "_draft").mkdir(parents=True, exist_ok=True)
    seed_adapter_stubs(wtd, ("elastic",))
    return wtd


def test_d1_lead_author_via_bind(tmp_path):
    """d1_lead_author_via_bind (survival): bind(LEAD_AUTHOR_DEF, run_dir, defender_dir=<wt>/defender) flows..."""
    # RED@HEAD: bind takes `repo_root`, not `defender_dir` → TypeError (the early-return path).
    run = tmp_path / "run"
    wtd = _lead_wtd(tmp_path)
    skills = wtd / "skills"
    deps = bind(LEAD_AUTHOR_DEF, run, defender_dir=wtd)
    assert isinstance(deps, LeadAuthorDeps)
    pol = deps.policy
    # write scope: the worktree skills .md corpus.
    assert permission.decide_write(
        skills / "elastic" / "SKILL.md", "c", run_dir=run, defender_dir=wtd, policy=pol).allow
    # rm-of-drafts grant.
    assert permission.decide_bash(f"rm {skills}/elastic/_draft/x.md", policy=pol, run_dir=run, defender_dir=wtd).allow


# D2 — write scope as data (write_shapes; lead-author fork removed)

def test_d2_write_shapes_field(tmp_path):
    """d2_write_shapes_field (seam): the def carries `write_shapes` — per-run (ResolvedRoots)-> patterns builders..."""
    # #575: compile_policy is `(defn, roots)` — the ToolSet/read_shapes/deny_reason positionals
    # folded back onto the definition they always belonged to.
    run = tmp_path / "run"
    roots = resolve_roots(run, (), RunScope())
    pol = compile_policy(_reader_def(write=True, write_shapes=(_main_write_shape,)), roots)
    assert permission.decide_write(                                              # resolved into write_allow
        run / "x.md", "c", run_dir=run, defender_dir=_DEFENDER, policy=pol).allow
    assert not permission.decide_write(                                          # outside the shape
        tmp_path / "y.md", "c", run_dir=run, defender_dir=_DEFENDER, policy=pol).allow
    ro = compile_policy(_reader_def(), roots)                                     # write=False + empty
    assert ro.write_allow == ()


def test_d2_main_write_shape_anchors_run_dir(tmp_path):
    """d2_main_write_shape_anchors_run_dir (domain-outcome): MAIN's write shape anchors run_dir — decide_write..."""
    run = tmp_path / "run"
    pol = bind(MAIN_DEF, run).policy
    assert permission.decide_write(                                                   # positive control
        run / "investigation.md", "", run_dir=run, defender_dir=_DEFENDER, policy=pol).allow
    assert not permission.decide_write(
        _DEFENDER / "skills" / "investigation.md", "",
        run_dir=run, defender_dir=_DEFENDER, policy=pol).allow
    assert not permission.decide_write(                                    # R1: report.md is refused too
        run / "report.md", _VALID_REPORT, run_dir=run, defender_dir=_DEFENDER, policy=pol).allow


def test_d2_lead_author_write_shape_anchors_skills(tmp_path):
    """d2_lead_author_write_shape_anchors_skills (domain-outcome): LEAD_AUTHOR's write shape uses..."""
    # RED@HEAD: bind(LEAD_AUTHOR_DEF, …, defender_dir=) → TypeError (repo_root today).
    run = tmp_path / "run"
    wtd = _lead_wtd(tmp_path)
    skills = wtd / "skills"
    pol = bind(LEAD_AUTHOR_DEF, run, defender_dir=wtd).policy
    assert permission.decide_write(                                                     # positive control (.md)
        skills / "elastic" / "SKILL.md", "c", run_dir=run, defender_dir=wtd, policy=pol).allow
    assert not permission.decide_write(                                                 # wrong root
        run / "x.md", "c", run_dir=run, defender_dir=wtd, policy=pol).allow
    assert not permission.decide_write(                                                 # wrong suffix
        skills / "elastic" / "SKILL.txt", "c", run_dir=run, defender_dir=wtd, policy=pol).allow


def test_d2_write_shape_resolves_symlinked_root(tmp_path):
    """d2_write_shape_resolves_symlinked_root (parity): under a symlinked base, decide_write of a real-path..."""
    # GREEN@HEAD: build_write_allow already resolve()s its root; the migration must keep it.
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "linkrun"
    os.symlink(real, link)
    pol = bind(MAIN_DEF, link).policy
    assert permission.decide_write(
        link / "investigation.md", "", run_dir=link, defender_dir=_DEFENDER, policy=pol).allow


def test_d2_main_lead_shapes_no_cross_contamination(tmp_path):
    """d2_main_lead_shapes_no_cross_contamination (negative): MAIN's run-dir shape admits its sanctioned run-dir..."""
    # RED@HEAD: the LEAD half needs bind(LEAD_AUTHOR_DEF, defender_dir=) → TypeError.
    run = tmp_path / "run"
    wtd = _lead_wtd(tmp_path)
    skills = wtd / "skills"
    main_pol = bind(MAIN_DEF, run).policy
    lead_pol = bind(LEAD_AUTHOR_DEF, run, defender_dir=wtd).policy

    assert permission.decide_write(                                                     # MAIN: sanctioned run-dir artifact
        run / "investigation.md", "", run_dir=run, defender_dir=_DEFENDER, policy=main_pol).allow
    assert not permission.decide_write(                                                 # MAIN doesn't widen into skills
        skills / "investigation.md", "", run_dir=run, defender_dir=wtd, policy=main_pol).allow
    assert not permission.decide_write(                                                 # R1: report.md refused too
        run / "report.md", _VALID_REPORT, run_dir=run, defender_dir=_DEFENDER, policy=main_pol).allow
    assert permission.decide_write(                                                     # LEAD: sanctioned .md
        skills / "elastic" / "SKILL.md", "c", run_dir=run, defender_dir=wtd, policy=lead_pol).allow
    assert not permission.decide_write(                                                 # LEAD doesn't widen into run_dir
        run / "x.md", "c", run_dir=run, defender_dir=wtd, policy=lead_pol).allow


def test_d2_lead_author_rm_scope(tmp_path):
    """d2_lead_author_rm_scope (negative): the bound lead-author's decide_bash admits `rm..."""
    # RED@HEAD: bind(LEAD_AUTHOR_DEF, defender_dir=) → TypeError.
    run = tmp_path / "run"
    wtd = _lead_wtd(tmp_path)
    skills = wtd / "skills"
    pol = bind(LEAD_AUTHOR_DEF, run, defender_dir=wtd).policy

    def _bash(cmd: str) -> bool:
        return permission.decide_bash(cmd, policy=pol, run_dir=run, defender_dir=wtd).allow

    assert _bash(f"rm {skills}/elastic/_draft/x.md")   # positive control (scoped rm)
    assert not _bash("rm -rf /")                       # not a general rm
    assert not _bash(f"rm {run}/report.md")            # not outside the skills subtree
    assert not _bash("rm defender/skills/../../x")     # textual `..` rejected


# D3 — defender_dir threaded through resolve_roots AND _for_run (deps)

def test_d3_resolve_roots_defender_dir_param(tmp_path):
    """d3_resolve_roots_defender_dir_param (seam): resolve_roots takes defender_dir (default PATHS.defender_dir)..."""
    run = tmp_path / "run"
    wtd = tmp_path / "wt" / "defender"
    assert resolve_roots(run, (), RunScope()).defender_dir == _DEFENDER   # positive control (default)
    # RED@HEAD: resolve_roots is 3-arg → TypeError on the defender_dir kwarg.
    assert resolve_roots(run, (), RunScope(), defender_dir=wtd).defender_dir == wtd


def test_d3_bind_threads_defender_dir_into_deps_field(tmp_path):
    """d3_bind_threads_defender_dir_into_deps_field (parity): bind(MAIN_DEF, run, defender_dir=wt) threads the..."""
    # RED@HEAD: bind has no defender_dir kwarg → TypeError.
    run = tmp_path / "run"
    wtd = tmp_path / "wt" / "defender"
    deps = bind(MAIN_DEF, run, defender_dir=wtd)
    assert deps.defender_dir == wtd
    # deps.defender_dir and the policy's read anchor are ONE tree → a wt corpus read admits.
    assert permission.decide_read(wtd / "lessons" / "a.md", run_dir=run, defender_dir=deps.defender_dir, policy=deps.policy).allow


def test_d3_partial_thread_bricks_worktree_reads(tmp_path):
    """d3_partial_thread_bricks_worktree_reads (negative): a policy anchored on tree A while..."""
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
    """d3_lead_author_worktree_anchor (behavior): bind(LEAD_AUTHOR_DEF, run, defender_dir=wt/defender) yields..."""
    # RED@HEAD: bind(LEAD_AUTHOR_DEF, defender_dir=) → TypeError (repo_root today).
    run = tmp_path / "run"
    wtd = _lead_wtd(tmp_path)
    deps = bind(LEAD_AUTHOR_DEF, run, defender_dir=wtd)
    assert deps.defender_dir == wtd
    assert permission.decide_write(
        wtd / "skills" / "elastic" / "SKILL.md", "c",
        run_dir=run, defender_dir=wtd, policy=deps.policy).allow
    assert not permission.decide_write(
        _DEFENDER / "skills" / "elastic" / "SKILL.md", "c",
        run_dir=run, defender_dir=wtd, policy=deps.policy).allow


def test_d3_main_gather_non_paths_defender_dir(tmp_path):
    """d3_main_gather_non_paths_defender_dir (domain-outcome): bind(MAIN_DEF/GATHER_DEF, run,..."""
    # RED@HEAD: bind has no defender_dir kwarg → TypeError.
    run = tmp_path / "run"
    wtd = tmp_path / "wt" / "defender"
    probe = wtd / "lessons" / "a.md"
    for defn in (MAIN_DEF, T1106.fixture_gather_def()):
        deps = bind(defn, run, defender_dir=wtd)
        assert permission.decide_read(probe, run_dir=run, defender_dir=wtd, policy=deps.policy).allow
        assert permission.decide_bash(f"cat {probe}", policy=deps.policy, run_dir=run, defender_dir=wtd).allow


def test_d3_corpus_traversal_guard_survives(tmp_path):
    """d3_corpus_traversal_guard_survives (survival): resolve_roots still RAISES ValueError on a '..'/absolute..."""
    # GREEN@HEAD: the guard exists today; the defender_dir thread must not weaken it.
    run = tmp_path / "run"
    with pytest.raises(ValueError, match="clean relative path segment"):
        resolve_roots(run, ("../evil",), RunScope())
    with pytest.raises(ValueError, match="clean relative path segment"):
        resolve_roots(run, ("/abs",), RunScope())
    assert resolve_roots(run, ("lessons",), RunScope()).corpus_roots  # positive control (clean name)


# D4 — actor confine + lead-author tree preconditions as data


def test_d4_main_empty_confine_ok(tmp_path):
    """d4_main_empty_confine_ok (behavior, positive control): bind(MAIN_DEF, run_dir) with the default empty..."""
    # GREEN@HEAD.
    run = tmp_path / "run"
    deps = bind(MAIN_DEF, run)
    assert deps.policy.read_confine == ()
    assert permission.decide_read(_CORPUS_MD, run_dir=run, defender_dir=_DEFENDER, policy=deps.policy).allow


def test_d4_lead_author_no_tree_raises(tmp_path):
    """d4_lead_author_no_tree_raises (negative): after the early-return is deleted, bind(LEAD_AUTHOR_DEF,..."""
    run = tmp_path / "run"
    wtd = _lead_wtd(tmp_path)
    with pytest.raises((ValueError, TypeError), match="explicit NON-PATHS defender_dir"):
        bind(LEAD_AUTHOR_DEF, run)                        # no tree — raises today (repo_root) + post-#551 (data bit)
    # RED@HEAD: the positive control uses the new defender_dir kwarg → TypeError.
    assert isinstance(bind(LEAD_AUTHOR_DEF, run, defender_dir=wtd), LeadAuthorDeps)


# D5 — the parallel factory path retires


def test_d5_compile_policy_for_read_shapes(tmp_path):
    """d5_compile_policy_for_read_shapes (survival): `compile_policy_for` (the policy-only half of `bind`)..."""
    run = tmp_path / "run"
    ppol = compile_policy_for(MAIN_DEF, run_dir=run, defender_dir=_DEFENDER)
    assert not permission.decide_read(_NON_MD, run_dir=run, defender_dir=_DEFENDER, policy=ppol).allow
    # positive control: the bound reader already denies the non-.md corpus file (the target behaviour).
    bpol = bind(MAIN_DEF, run).policy
    assert not permission.decide_read(_NON_MD, run_dir=run, defender_dir=_DEFENDER, policy=bpol).allow


def test_d5_reader_patterns_for_kept(tmp_path):
    """d5_reader_patterns_for_kept (survival; the builder is `_common.reader_grants` since #575 — the demand id..."""
    # GREEN@HEAD.
    assert callable(reader_grants)
    run = tmp_path / "run"
    pol = bind(MAIN_DEF, run).policy
    assert permission.decide_bash(f"cat {_CORPUS_MD}", policy=pol, run_dir=run, defender_dir=_DEFENDER).allow
    assert not permission.decide_bash("cat /etc/passwd", policy=pol, run_dir=run, defender_dir=_DEFENDER).allow


# D6 — wire the write ⊆ read guard

def test_d6_writers_pass_roots(tmp_path):
    """d6_writers_pass_roots (seam): both writer call sites (tools.py write_file/edit_file) call decide_write..."""
    run = tmp_path / "run"
    run.mkdir()
    dfn = tmp_path / "dfn"
    dfn.mkdir()
    escape = tmp_path / "escape"                          # outside run + dfn (the read surface)
    escape_pol = AgentPolicy(
        write_allow=(permission.build_write_allow(escape, suffix=".md"),), deny_reason="d",
    )
    deps = AgentDeps(
        run_dir=run, defender_dir=dfn, run_id="r", policy=escape_pol,
        cwd_anchor=run,
    )
    # RED@#551-HEAD: _tool_write_file called decide_write WITHOUT roots → guard dormant → allowed.
    with pytest.raises(ModelRetry):
        _tool_write_file(deps, str(escape / "x.md"), "content")
    runtime = PATHS.repo_root / "defender" / "investigation" / "tools"
    tools_src = "\n".join(
        (runtime / name).read_text() for name in ("_files.py", "_document.py")
    )
    calls = re.findall(r"decide_write\(.*?policy=deps\.policy", tools_src, re.DOTALL)
    assert len(calls) == 4, "a decide_write call site appeared or vanished — check the roots"
    assert all("defender_dir=deps.defender_dir" in c for c in calls)


def test_d6_guard_denies_escape(tmp_path):
    """d6_guard_denies_escape (negative): decide_write DENIES a target matching write_allow but resolving OUTSIDE..."""
    # GREEN@HEAD: the guard lives in decide_write.
    run = tmp_path / "run"
    dfn = tmp_path / "dfn"
    escape = tmp_path / "escape"
    pol = AgentPolicy(write_allow=(permission.build_write_allow(escape, suffix=".md"),), deny_reason="d")
    tgt = escape / "x.md"
    assert not permission.decide_write(tgt, "c", run_dir=run, defender_dir=dfn, policy=pol).allow


def test_d6_guard_noop_for_real_writers(tmp_path):
    """d6_guard_noop_for_real_writers (behavior, positive control): with both roots supplied, a MAIN write under..."""
    # GREEN@HEAD.
    run = tmp_path / "run"
    wtd = _lead_wtd(tmp_path)
    skills = wtd / "skills"
    main_pol = bind(MAIN_DEF, run).policy
    assert permission.decide_write(run / "investigation.md", "", run_dir=run, defender_dir=_DEFENDER, policy=main_pol).allow
    assert not permission.decide_write(run / "report.md", _VALID_REPORT, run_dir=run, defender_dir=_DEFENDER, policy=main_pol).allow
    lead_pol = AgentPolicy(write_allow=(permission.build_write_allow(skills, suffix=".md"),), deny_reason="d")
    assert permission.decide_write(skills / "elastic" / "SKILL.md", "c", run_dir=run, defender_dir=wtd, policy=lead_pol).allow


def test_d6_guard_needs_worktree_defender_dir(tmp_path):
    """d6_guard_needs_worktree_defender_dir (parity, D6 × the deps/policy split): the write⊆read guard admits..."""
    # RED@HEAD: the lead-author policy anchored on a worktree needs bind(defender_dir=) → TypeError.
    run = tmp_path / "run"
    wtd = _lead_wtd(tmp_path)
    target = wtd / "skills" / "elastic" / "SKILL.md"
    pol = bind(LEAD_AUTHOR_DEF, run, defender_dir=wtd).policy
    # consistent tree → admitted.
    assert permission.decide_write(target, "c", run_dir=run, defender_dir=wtd, policy=pol).allow
    # the split (deps tree = PATHS while write_allow anchors on wt) → the legit write DENIES.
    assert not permission.decide_write(target, "c", run_dir=run, defender_dir=_DEFENDER, policy=pol).allow


# R3 — read↔bash filename + symlink parity

def test_r3_read_bash_filename_parity(tmp_path):
    """r3_read_bash_filename_parity (parity): for a reader agent, decide_read and the bash cat lane agree on the..."""
    # GREEN@HEAD.
    run = tmp_path / "run"
    pol = bind(MAIN_DEF, run).policy
    assert pol.read_allow is read_allow_of(pol.bash_allow)   # one object, not two grammars
    for probe in (_CORPUS_MD, _NON_MD):
        read_ok = permission.decide_read(probe, run_dir=run, defender_dir=_DEFENDER, policy=pol).allow
        bash_ok = permission.decide_bash(f"cat {probe}", policy=pol, run_dir=run, defender_dir=_DEFENDER).allow
        assert read_ok == bash_ok, f"read-tool vs bash disagree on {probe}: read={read_ok} bash={bash_ok}"


def test_r3_symlinked_base_admits(tmp_path):
    """r3_symlinked_base_admits (parity): under a SYMLINKED run base (link->real), decide_read of a run-dir file..."""
    # GREEN@HEAD: the reader's shapes anchor on the RESOLVED run base (#546 — `_common.read_shapes`
    # resolve()s its roots, and #575 resolves the OPERAND too); the fold must keep it.
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
    """r3_symlink_pointing_out_denies (negative): a symlink INSIDE the roots pointing OUT: decide_read DENIES..."""
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


# R2 — per-pair isolation


# R5 — safe-by-construction: compile_policy write co-constraint

def test_r5_tools_write_write_shapes_agree(tmp_path):
    """r5_tools_write_write_shapes_agree (negative, Q3 assert): compile_policy RAISES on an inconsistent..."""
    run = tmp_path / "run"
    roots = resolve_roots(run, (), RunScope())
    with pytest.raises((ValueError, TypeError)):
        compile_policy(_reader_def(write=True), roots)                              # write=True ⊗ empty
    with pytest.raises((ValueError, TypeError)):
        compile_policy(_reader_def(write_shapes=(_main_write_shape,)), roots)       # write=False ⊗ non-empty
    # positive controls compile clean.
    compile_policy(_reader_def(write=True, write_shapes=(_main_write_shape,)), roots)
    compile_policy(_reader_def(), roots)


# D7 — bind input-validation seam (Q4 harden)

def test_d7_bind_validates_roots(tmp_path):
    """d7_bind_validates_roots (seam): bind validates its root inputs — a relative or empty-string root RAISES..."""
    assert isinstance(bind(MAIN_DEF, tmp_path / "run"), AgentDeps)  # positive control (absolute)
    # RED@HEAD: bind passes a relative run_dir straight to resolve_roots (anchors CWD); no validation.
    with pytest.raises((ValueError, TypeError)):
        bind(MAIN_DEF, Path("relative/run"))


def test_d7_lead_author_main_tree_unbuildable(tmp_path):
    """d7_lead_author_main_tree_unbuildable (negative): bind(LEAD_AUTHOR_DEF, run, defender_dir=..."""
    # RED@HEAD: bind has no defender_dir kwarg → TypeError (the #551 ValueError can't yet fire).
    run = tmp_path / "run"
    wtd = _lead_wtd(tmp_path)
    with pytest.raises((ValueError, TypeError), match="explicit NON-PATHS defender_dir"):
        bind(LEAD_AUTHOR_DEF, run, defender_dir=_DEFENDER)      # main-checkout tree — UNBUILDABLE
    assert isinstance(bind(LEAD_AUTHOR_DEF, run, defender_dir=wtd), LeadAuthorDeps)  # positive control


