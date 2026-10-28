"""bind/compile_policy as the sole policy seam: bind contract, write shapes, defender_dir threading, guards, symlink parity.

`bind` threads one `defender_dir` into both the policy anchor and the deps field: a split between
them bricks every worktree read and write."""
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

# Probe paths under the real defender tree, where MAIN's corpus scope anchors (they need not exist).

_CORPUS_MD = _DEFENDER / "lessons" / "_probe_551.md"
_NON_MD = _DEFENDER / "skills" / "gather" / "run.py"   # a non-.md path under the corpus


def _reader_bash_shapes(roots: ResolvedRoots) -> tuple[Grant, ...]:
    """The production main-shaped reader grant builder (`_common.reader_grants`), so a def compiled
    here carries the real reader lane."""
    return reader_grants(roots.run_dir, roots.defender_dir, raw=False)


def _reader_def(*, write=False, write_shapes=()) -> AgentDefinition:
    """An ad-hoc main-shaped AgentDefinition for the `compile_policy` seam tests."""
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
    """MAIN's write scope builder: `(ResolvedRoots) -> patterns`."""
    return (permission.build_write_allow(roots.run_dir),)


# D0 — bind's return contract

def test_d0_bind_return_contract(tmp_path):
    """`bind` returns the role's deps carrying an `AgentPolicy`, the run's id and the threaded
    `defender_dir` (never PATHS when a worktree is passed), and no salt."""
    run = tmp_path / "run-xyz"
    wt = tmp_path / "wt" / "defender"
    deps = bind(MAIN_DEF, run, scope=RunScope(), defender_dir=wt)
    assert isinstance(deps, AgentDeps)
    assert isinstance(deps.policy, permission.AgentPolicy)
    assert deps.run_id == run.name
    assert not hasattr(deps, "salt")   # #875: bind hands out no delimiter
    assert deps.defender_dir == wt          # the threaded tree, NOT PATHS


def _lead_wtd(tmp_path):
    """A worktree tree the lead author can bind against: its write lanes and `rm` grant are compiled
    per system the tree declares an adapter for, so it seeds `elastic`, the system probes spell."""
    wtd = tmp_path / "wt" / "defender"
    (wtd / "skills" / "gather" / "queries" / "elastic").mkdir(parents=True, exist_ok=True)
    (wtd / "skills" / "elastic" / "_draft").mkdir(parents=True, exist_ok=True)
    seed_adapter_stubs(wtd, ("elastic",))
    return wtd


# D2 — write scope as data (`write_shapes`)

def test_d2_write_shapes_field(tmp_path):
    """A def's `write_shapes` builders resolve into `write_allow` (inside admitted, outside denied);
    a read-only def's `write_allow` is empty."""
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
    """MAIN's write shape anchors run_dir: investigation.md there is admitted, the corpus and
    report.md are not."""
    run = tmp_path / "run"
    pol = bind(MAIN_DEF, run).policy
    assert permission.decide_write(                                                   # positive control
        run / "investigation.md", "", run_dir=run, defender_dir=_DEFENDER, policy=pol).allow
    assert not permission.decide_write(
        _DEFENDER / "skills" / "investigation.md", "",
        run_dir=run, defender_dir=_DEFENDER, policy=pol).allow
    assert not permission.decide_write(                                    # report.md is refused too
        run / "report.md", _VALID_REPORT, run_dir=run, defender_dir=_DEFENDER, policy=pol).allow


def test_d2_lead_author_write_shape_anchors_skills(tmp_path):
    """LEAD_AUTHOR's write shape is `.md` under the worktree's skills: run_dir and a non-`.md`
    suffix are denied."""
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
    """Under a symlinked run base, a write through the link is admitted: the write shape anchors on
    resolved roots."""
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "linkrun"
    os.symlink(real, link)
    pol = bind(MAIN_DEF, link).policy
    assert permission.decide_write(
        link / "investigation.md", "", run_dir=link, defender_dir=_DEFENDER, policy=pol).allow


def test_d2_main_lead_shapes_no_cross_contamination(tmp_path):
    """MAIN's run-dir shape and LEAD's skills `.md` shape each admit their own sanctioned write and
    neither widens into the other's root."""
    run = tmp_path / "run"
    wtd = _lead_wtd(tmp_path)
    skills = wtd / "skills"
    main_pol = bind(MAIN_DEF, run).policy
    lead_pol = bind(LEAD_AUTHOR_DEF, run, defender_dir=wtd).policy

    assert permission.decide_write(                                                     # MAIN: sanctioned run-dir artifact
        run / "investigation.md", "", run_dir=run, defender_dir=_DEFENDER, policy=main_pol).allow
    assert not permission.decide_write(                                                 # MAIN doesn't widen into skills
        skills / "investigation.md", "", run_dir=run, defender_dir=wtd, policy=main_pol).allow
    assert not permission.decide_write(                                                 # report.md refused too
        run / "report.md", _VALID_REPORT, run_dir=run, defender_dir=_DEFENDER, policy=main_pol).allow
    assert permission.decide_write(                                                     # LEAD: sanctioned .md
        skills / "elastic" / "SKILL.md", "c", run_dir=run, defender_dir=wtd, policy=lead_pol).allow
    assert not permission.decide_write(                                                 # LEAD doesn't widen into run_dir
        run / "x.md", "c", run_dir=run, defender_dir=wtd, policy=lead_pol).allow


def test_d2_lead_author_rm_scope(tmp_path):
    """The lead author's `rm` admits only drafts under the worktree skills: not `rm -rf /`, not
    outside the subtree, not a textual `..`."""
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


# D3 — `defender_dir` threaded into the policy anchor and the deps alike

def test_d3_resolve_roots_defender_dir_param(tmp_path):
    """`resolve_roots` takes `defender_dir` (default PATHS) and returns it on `ResolvedRoots`."""
    run = tmp_path / "run"
    wtd = tmp_path / "wt" / "defender"
    assert resolve_roots(run, (), RunScope()).defender_dir == _DEFENDER   # positive control (default)
    assert resolve_roots(run, (), RunScope(), defender_dir=wtd).defender_dir == wtd


def test_d3_bind_threads_defender_dir_into_deps_field(tmp_path):
    """`bind(MAIN_DEF, run, defender_dir=wt)` threads the tree into both the deps field and the
    policy anchor, so a worktree corpus read is admitted."""
    run = tmp_path / "run"
    wtd = tmp_path / "wt" / "defender"
    deps = bind(MAIN_DEF, run, defender_dir=wtd)
    assert deps.defender_dir == wtd
    assert permission.decide_read(wtd / "lessons" / "a.md", run_dir=run, defender_dir=deps.defender_dir, policy=deps.policy).allow


def test_d3_partial_thread_bricks_worktree_reads(tmp_path):
    """A policy anchored on tree A but queried with tree B denies every corpus read on both
    surfaces; one consistent tree admits."""
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
    """The lead author's deps and write scope anchor on its worktree tree, not the main checkout."""
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
    """MAIN and gather bound with a worktree `defender_dir` anchor their read and bash surfaces on
    that tree."""
    run = tmp_path / "run"
    wtd = tmp_path / "wt" / "defender"
    probe = wtd / "lessons" / "a.md"
    for defn in (MAIN_DEF, T1106.fixture_gather_def()):
        deps = bind(defn, run, defender_dir=wtd)
        assert permission.decide_read(probe, run_dir=run, defender_dir=wtd, policy=deps.policy).allow
        assert permission.decide_bash(f"cat {probe}", policy=deps.policy, run_dir=run, defender_dir=wtd).allow


# D4 — the confine and explicit-tree preconditions


def test_d4_main_empty_confine_ok(tmp_path):
    """MAIN binds with an empty confine and reads the corpus: `requires_confine` is off for main."""
    run = tmp_path / "run"
    deps = bind(MAIN_DEF, run)
    assert deps.policy.read_confine == ()
    assert permission.decide_read(_CORPUS_MD, run_dir=run, defender_dir=_DEFENDER, policy=deps.policy).allow


def test_d4_lead_author_no_tree_raises(tmp_path):
    """Binding the lead author with no `defender_dir` raises (`requires_explicit_tree`) instead of
    falling back to the main checkout; an explicit worktree binds."""
    run = tmp_path / "run"
    wtd = _lead_wtd(tmp_path)
    with pytest.raises((ValueError, TypeError), match="explicit NON-PATHS defender_dir"):
        bind(LEAD_AUTHOR_DEF, run)                        # no tree
    assert isinstance(bind(LEAD_AUTHOR_DEF, run, defender_dir=wtd), LeadAuthorDeps)


# D5 — the reader lane through `compile_policy_for`


def test_d5_compile_policy_for_read_shapes(tmp_path):
    """`compile_policy_for` (the policy-only half of `bind`) carries the reader's read shapes, so a
    non-`.md` corpus read is denied there as through `bind`."""
    run = tmp_path / "run"
    ppol = compile_policy_for(MAIN_DEF, run_dir=run, defender_dir=_DEFENDER)
    assert not permission.decide_read(_NON_MD, run_dir=run, defender_dir=_DEFENDER, policy=ppol).allow
    # The bound reader denies the non-.md corpus file too.
    bpol = bind(MAIN_DEF, run).policy
    assert not permission.decide_read(_NON_MD, run_dir=run, defender_dir=_DEFENDER, policy=bpol).allow


def test_d5_reader_patterns_for_kept(tmp_path):
    """The shared reader builder (`_common.reader_grants`) backs the bound lane: a corpus `cat` is
    admitted, `/etc/passwd` denied."""
    assert callable(reader_grants)
    run = tmp_path / "run"
    pol = bind(MAIN_DEF, run).policy
    assert permission.decide_bash(f"cat {_CORPUS_MD}", policy=pol, run_dir=run, defender_dir=_DEFENDER).allow
    assert not permission.decide_bash("cat /etc/passwd", policy=pol, run_dir=run, defender_dir=_DEFENDER).allow


# D6 — the write ⊆ read guard

def test_d6_writers_pass_roots(tmp_path):
    """Every writer call site passes the deps' roots to `decide_write`, so an escaping `write_allow`
    is denied through `_tool_write_file`."""
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
    """`decide_write` denies a target that matches `write_allow` but lies outside the read surface."""
    run = tmp_path / "run"
    dfn = tmp_path / "dfn"
    escape = tmp_path / "escape"
    pol = AgentPolicy(write_allow=(permission.build_write_allow(escape, suffix=".md"),), deny_reason="d")
    tgt = escape / "x.md"
    assert not permission.decide_write(tgt, "c", run_dir=run, defender_dir=dfn, policy=pol).allow


def test_d6_guard_noop_for_real_writers(tmp_path):
    """The guard is a no-op for real writers: MAIN's run-dir write and a lead-author skills write stay
    allowed."""
    run = tmp_path / "run"
    wtd = _lead_wtd(tmp_path)
    skills = wtd / "skills"
    main_pol = bind(MAIN_DEF, run).policy
    assert permission.decide_write(run / "investigation.md", "", run_dir=run, defender_dir=_DEFENDER, policy=main_pol).allow
    assert not permission.decide_write(run / "report.md", _VALID_REPORT, run_dir=run, defender_dir=_DEFENDER, policy=main_pol).allow
    lead_pol = AgentPolicy(write_allow=(permission.build_write_allow(skills, suffix=".md"),), deny_reason="d")
    assert permission.decide_write(skills / "elastic" / "SKILL.md", "c", run_dir=run, defender_dir=wtd, policy=lead_pol).allow


def test_d6_guard_needs_worktree_defender_dir(tmp_path):
    """The guard admits a lead-author skills write only when the deps tree is the worktree its
    `write_allow` anchors on; the PATHS split denies it."""
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
    """`decide_read` and the bash `cat` lane agree on corpus probes (`.md` admitted, non-`.md` denied)."""
    run = tmp_path / "run"
    pol = bind(MAIN_DEF, run).policy
    assert pol.read_allow is read_allow_of(pol.bash_allow)   # one object, not two grammars
    for probe in (_CORPUS_MD, _NON_MD):
        read_ok = permission.decide_read(probe, run_dir=run, defender_dir=_DEFENDER, policy=pol).allow
        bash_ok = permission.decide_bash(f"cat {probe}", policy=pol, run_dir=run, defender_dir=_DEFENDER).allow
        assert read_ok == bash_ok, f"read-tool vs bash disagree on {probe}: read={read_ok} bash={bash_ok}"


def test_r3_symlinked_base_admits(tmp_path):
    """Under a symlinked run base, a run-dir file is admitted by `decide_read` and the `cat` lane
    alike: the reader's shapes anchor on the resolved base, and the operand is resolved too."""
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
    """A symlink inside the roots pointing out is denied by `decide_read`; the `cat` lane denies a
    textual `..`."""
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


# R5 — `compile_policy`'s write co-constraint

def test_r5_tools_write_write_shapes_agree(tmp_path):
    """`compile_policy` raises on `write=True` with no write shapes or `write=False` with some;
    consistent defs compile."""
    run = tmp_path / "run"
    roots = resolve_roots(run, (), RunScope())
    with pytest.raises((ValueError, TypeError)):
        compile_policy(_reader_def(write=True), roots)                              # write=True ⊗ empty
    with pytest.raises((ValueError, TypeError)):
        compile_policy(_reader_def(write_shapes=(_main_write_shape,)), roots)       # write=False ⊗ non-empty
    # positive controls compile clean.
    compile_policy(_reader_def(write=True, write_shapes=(_main_write_shape,)), roots)
    compile_policy(_reader_def(), roots)


# D7 — bind's input validation

def test_d7_bind_validates_roots(tmp_path):
    """`bind` refuses a relative run_dir instead of silently anchoring on CWD."""
    assert isinstance(bind(MAIN_DEF, tmp_path / "run"), AgentDeps)  # positive control (absolute)
    with pytest.raises((ValueError, TypeError)):
        bind(MAIN_DEF, Path("relative/run"))


def test_d7_lead_author_main_tree_unbuildable(tmp_path):
    """Binding the lead author to the main checkout's tree raises: an explicit-tree role needs a
    non-PATHS worktree."""
    run = tmp_path / "run"
    wtd = _lead_wtd(tmp_path)
    with pytest.raises((ValueError, TypeError), match="explicit NON-PATHS defender_dir"):
        bind(LEAD_AUTHOR_DEF, run, defender_dir=_DEFENDER)      # main-checkout tree — UNBUILDABLE
    assert isinstance(bind(LEAD_AUTHOR_DEF, run, defender_dir=wtd), LeadAuthorDeps)  # positive control


