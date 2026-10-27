"""Per-agent read confinement across both read surfaces (decide_read and decide_bash)."""
from __future__ import annotations

import os

import pytest

pytest.importorskip("pydantic_ai")

from defender.agents import MAIN_DEF  # noqa: E402
from defender.learning.core import config  # noqa: E402
from defender.investigation import permission  # noqa: E402
from defender.investigation.agent_definition import (  # noqa: E402
    compile_policy_for,
    read_allow_of,
)
from defender.investigation.permission import AgentPolicy  # noqa: E402
from defender.tests.support.tenancy import _tenants1106 as T1106

_DEFENDER = config.REPO_ROOT / "defender"

_CONFINE_A = _DEFENDER / "lessons"
_CONFINE_B = _DEFENDER / "skills"
#: A real file OUTSIDE both, for the refusal side. It was the deleted judge's rubric; any file
#: the confine does not cover carries the same demand, and this one ships.
_OUTSIDE = _DEFENDER / "SKILL.md"

#: A two-directory confine and a one-directory confine. The two shapes are what the gate has to
#: tell apart; which legs happened to bind them is not what these tests are about.
_MALICIOUS_CONFINE = (_CONFINE_A, _CONFINE_B)
_BENIGN_CONFINE = (_CONFINE_B,)


def _policy(*, read_confine=(), bash_allow=(), read_roots=()):
    """An AgentPolicy for gate tests."""
    return AgentPolicy(
        read_roots=read_roots, read_confine=read_confine, bash_allow=bash_allow,
    )


@pytest.mark.parametrize("path", [_CONFINE_A / "T1078.md", _CONFINE_B / "svc-monitoring.md"])
def test_malicious_reads_within_confine_allowed(tmp_path, path):
    """read under either directory of the two-directory confine -> allow."""
    pol = _policy(read_confine=_MALICIOUS_CONFINE)
    assert permission.decide_read(path, run_dir=tmp_path, defender_dir=_DEFENDER, policy=pol).allow, path


@pytest.mark.parametrize("path", [
    _OUTSIDE,
    _DEFENDER / "SKILL.md",
    _DEFENDER / "learning" / "pipeline" / "judge" / "benign.md",
])
def test_malicious_reads_outside_confine_denied(tmp_path, path):
    """read under defender_dir but OUTSIDE the confine (rubric, SKILL.md) -> deny. The regression #510 dropped."""
    pol = _policy(read_confine=_MALICIOUS_CONFINE)
    assert not permission.decide_read(path, run_dir=tmp_path, defender_dir=_DEFENDER, policy=pol).allow, path


def test_benign_confined_to_environment(tmp_path):
    """one-directory confine: its directory allowed; the other directory AND a file outside both denied — the gray-box split."""
    pol = _policy(read_confine=_BENIGN_CONFINE)
    assert permission.decide_read(_CONFINE_B / "x.md", run_dir=tmp_path, defender_dir=_DEFENDER, policy=pol).allow
    assert not permission.decide_read(_CONFINE_A / "x.md", run_dir=tmp_path, defender_dir=_DEFENDER, policy=pol).allow
    assert not permission.decide_read(_OUTSIDE, run_dir=tmp_path, defender_dir=_DEFENDER, policy=pol).allow


def test_confine_replaces_defender_dir_but_run_dir_stays(tmp_path):
    """confine REPLACES the defender_dir base; run_dir remains a root (own artifacts still readable)."""
    pol = _policy(read_confine=_MALICIOUS_CONFINE)
    assert permission.decide_read(tmp_path / "actor_out.json", run_dir=tmp_path, defender_dir=_DEFENDER, policy=pol).allow
    assert not permission.decide_read(_DEFENDER / "SKILL.md", run_dir=tmp_path, defender_dir=_DEFENDER, policy=pol).allow


def test_confine_root_dir_itself_allowed(tmp_path):
    """the confine root DIRECTORY itself resolves within-root -> allow (a pattern-search needs the dir
    readable; a plain read of a dir is the tool's not-a-file concern, not the gate's)."""
    pol = _policy(read_confine=_MALICIOUS_CONFINE)
    assert permission.decide_read(_CONFINE_A, run_dir=tmp_path, defender_dir=_DEFENDER, policy=pol).allow


def test_nonexistent_in_confine_path_allowed(tmp_path):
    """decide_read decides on the PATH, not existence: an in-confine path that does not exist -> allow
    (the tool then raises 'file not found')."""
    pol = _policy(read_confine=_MALICIOUS_CONFINE)
    p = _CONFINE_A / "does-not-exist.md"
    assert permission.decide_read(p, run_dir=tmp_path, defender_dir=_DEFENDER, policy=pol).allow


def test_traversal_out_of_confine_denied(tmp_path):
    """a `..` traversal from an in-confine dir up to the rubric -> deny (resolve() collapses `..`
    before the containment check)."""
    pol = _policy(read_confine=_MALICIOUS_CONFINE)
    escape = _CONFINE_B / ".." / "learning" / "pipeline" / "judge" / "malicious.md"
    assert not permission.decide_read(escape, run_dir=tmp_path, defender_dir=_DEFENDER, policy=pol).allow


@pytest.mark.parametrize("name", [".env", "credentials.txt", "ground_truth.yaml", "cases.json"])
def test_denylist_still_fires_inside_confine(tmp_path, name):
    """a secret/ground-truth file landing INSIDE a confine root is still denied by the global denylist."""
    pol = _policy(read_confine=_MALICIOUS_CONFINE)
    assert not permission.decide_read(_CONFINE_B / name, run_dir=tmp_path, defender_dir=_DEFENDER, policy=pol).allow


def test_confined_actor_cannot_reach_gather_raw(tmp_path):
    """the actor cannot read a gather_raw payload — pinned as CONTAINMENT, not as the deleted"""
    pol = _policy(read_confine=_MALICIOUS_CONFINE)
    investigation_raw = tmp_path / "investigation-run" / "gather_raw" / "l-001" / "0.json"
    assert not permission.decide_read(
        investigation_raw, run_dir=tmp_path / "learning-run", defender_dir=_DEFENDER, policy=pol).allow
    assert permission.decide_read(
        tmp_path / "learning-run" / "story.md", run_dir=tmp_path / "learning-run",
        defender_dir=_DEFENDER, policy=pol).allow


def _tmp_tree(tmp_path):
    """A tmp defender-like tree: a confine dir + an out-of-confine 'rubric'. Returns (defender_dir, confine, rubric)."""
    dfn = tmp_path / "defender"
    conf = dfn / "confined-corpus"
    conf.mkdir(parents=True)
    (conf / "ok.md").write_text("lesson\n")
    judge = dfn / "judge"
    judge.mkdir()
    rubric = judge / "malicious.md"
    rubric.write_text("SURVIVED-CRITERIA\n")
    return dfn, conf, rubric


def test_symlink_inside_confine_to_out_of_confine_denied(tmp_path):
    """a symlink placed INSIDE the confine pointing at an out-of-confine file -> deny (resolve() follows the
    link, then the containment check fails). The classic confine-escape."""
    dfn, conf, rubric = _tmp_tree(tmp_path)
    link = conf / "sneaky.md"
    os.symlink(rubric, link)
    pol = _policy(read_confine=(conf,))
    assert not permission.decide_read(link, run_dir=tmp_path / "run", defender_dir=dfn, policy=pol).allow


def test_resolve_error_fails_closed(tmp_path):
    """a circular symlink makes resolve() raise; the gate must FAIL CLOSED (deny), never propagate the error."""
    dfn, conf, _ = _tmp_tree(tmp_path)
    a, b = conf / "a", conf / "b"
    os.symlink(a, b)
    os.symlink(b, a)
    pol = _policy(read_confine=(conf,))
    assert not permission.decide_read(a, run_dir=tmp_path / "run", defender_dir=dfn, policy=pol).allow


@pytest.mark.parametrize("cmd", [
    "cat defender/confined-a/x.md",
    "grep foo defender/confined-b/y.md",
    "head -5 defender/confined-a/x.md",
    "tail -5 defender/confined-a/x.md",
    "ls defender/confined-a",
])
def test_actor_all_generic_readers_denied(cmd):
    assert not permission.decide_bash(cmd, policy=_policy(bash_allow=())).allow, cmd


def test_reduction_is_per_policy_not_global(tmp_path):
    """the reader reduction is per-policy, NOT a global removal: an actor policy with empty"""
    run, dfn = tmp_path / "run", tmp_path / "defender"
    run.mkdir()
    dfn.mkdir()
    main = compile_policy_for(MAIN_DEF, run_dir=run, defender_dir=dfn)
    inv = run / "investigation.md"
    assert not permission.decide_bash(
        f"cat {inv}", policy=_policy(bash_allow=()), run_dir=run, defender_dir=dfn,
    ).allow
    assert permission.decide_bash(
        f"cat {inv}", policy=main, run_dir=run, defender_dir=dfn).allow
    assert permission.decide_bash(
        f"cat {inv} | grep foo", policy=main, run_dir=run, defender_dir=dfn).allow


@pytest.mark.parametrize("cmd", [
    'cat {r} | defender-sql \\\n  "SELECT 1"',
    'cat {r} | defender-sql "SELECT 1\nFROM data"',
])
def test_multiline_command_is_denied_with_a_reason_that_says_why(tmp_path, cmd):
    """`bash_exec.parse` lexes each PHYSICAL LINE on its own (an unquoted newline is a"""
    raw = tmp_path / "gather_raw" / "l-002" / "0.json"
    run = tmp_path / "run"
    dfn = tmp_path / "tree" / "defender"
    dfn.mkdir(parents=True, exist_ok=True)
    pol = compile_policy_for(MAIN_DEF, run_dir=run, defender_dir=dfn)
    decision = permission.decide_bash(
        cmd.format(r=raw), policy=pol, run_dir=run, defender_dir=dfn)
    assert not decision.allow
    assert decision.reason == permission.bash.UNTOKENIZABLE_REASON
    assert "SINGLE line" in decision.reason


def test_main_cat_scope_is_the_read_surface(tmp_path):
    """MAIN keeps a viewer lane, and its `cat` grant's SCOPE is the run dir + corpus over the RESOLVED"""
    run, dfn = tmp_path / "run", tmp_path / "defender"
    run.mkdir()
    dfn.mkdir()
    main = compile_policy_for(MAIN_DEF, run_dir=run, defender_dir=dfn)
    assert main.bash_allow
    assert main.read_allow is read_allow_of(main.bash_allow)
    assert permission.decide_bash(
        f"cat {run}/investigation.md", policy=main, run_dir=run, defender_dir=dfn).allow
    assert not permission.decide_bash(
        "cat /tmp/x", policy=main, run_dir=run, defender_dir=dfn).allow


def test_gather_stream_plumbing_anchored(tmp_path):
    """GATHER's compute lane still works over IN-SCOPE payloads — cat {run}/… | defender-sql,"""
    run, dfn = tmp_path / "run", tmp_path / "defender"
    run.mkdir()
    dfn.mkdir()
    gather = compile_policy_for(T1106.fixture_gather_def(), run_dir=run, defender_dir=dfn)

    def bash(cmd):
        return permission.decide_bash(cmd, policy=gather, run_dir=run, defender_dir=dfn)

    raw = f"{run}/gather_raw/l-001/0.json"
    assert bash(f"cat {raw} | defender-sql 'SELECT count(*) FROM data'").allow
    assert not bash("defender-elastic query 'x'").allow
    assert bash(f"cat {raw} | wc -c").allow
    assert not bash("cat /tmp/p.json | wc -c").allow
    assert not bash(f"cat {run}/gather_raw/evil.json").allow
