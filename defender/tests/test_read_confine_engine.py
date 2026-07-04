"""Executable spec (engine + tool layer) for #512 slice 2 — pydantic-guarded.

Pins the parts that need the pydantic runtime:
  - the actor/judge policy BUILDERS wire the new confinement fields
    (_actor_policy(scripts, read_confine); _judge_policy -> bash_readers=('jq',)),
  - the read tool _tool_read_file(deps, path, pattern=None) routes through the confined policy,
    folds search via `pattern`, and honours the return contract (deny -> ModelRetry, no existence
    oracle, no-match -> empty, in-confine-missing -> 'file not found').

RED until the implement phase lands the builders' new behaviour and read_file(pattern=). The pure
gate spec (decide_read / decide_bash) is in test_read_confine.py.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from pydantic_ai import ModelRetry  # noqa: E402

from defender.learning.core import config  # noqa: E402
from defender.learning.pipeline import actor_engine  # noqa: E402
from defender.learning.pipeline.actor_engine import ActorDeps  # noqa: E402
from defender.runtime import permission, tools  # noqa: E402
from defender.runtime.permission import AgentPolicy  # noqa: E402

_DEFENDER = config.REPO_ROOT / "defender"
_ACTOR_DIR = config.LESSONS_ACTOR_DIR
_ENV_DIR = config.LESSONS_ENVIRONMENT_DIR
_RUBRIC = _DEFENDER / "learning" / "pipeline" / "judge" / "malicious.md"
_ENV_RETRIEVE = config.LESSONS_ENV_RETRIEVE_SCRIPT
_ACTOR_INDEX = config.LESSONS_ACTOR_INDEX_SCRIPT


# ============================================================================
# builder wiring: _actor_policy carries the confine + zero readers
# ============================================================================

def test_actor_policy_malicious_wires_confine_and_no_readers():
    """_actor_policy for the malicious leg -> read_confine == {lessons-actor, lessons-environment},
    bash_readers == () (zero generic bash readers), and still gray-box (raw_reads False, no adapters)."""
    pol = actor_engine._actor_policy((_ENV_RETRIEVE, _ACTOR_INDEX), read_confine=(_ACTOR_DIR, _ENV_DIR))
    assert set(pol.read_confine) == {_ACTOR_DIR, _ENV_DIR}
    assert pol.bash_readers == ()
    assert pol.raw_reads is False and pol.adapters is False


def test_benign_actor_policy_env_only():
    """_actor_policy for the benign leg -> read_confine == {lessons-environment} only; no bash readers."""
    pol = actor_engine._actor_policy((_ENV_RETRIEVE,), read_confine=(_ENV_DIR,))
    assert set(pol.read_confine) == {_ENV_DIR}
    assert pol.bash_readers == ()


def test_actor_policy_confine_denies_rubric_via_gate(tmp_path):
    """the malicious actor policy, THROUGH decide_read, denies the judge rubric and allows a lesson —
    the builder actually closes the gray-box hole."""
    pol = actor_engine._actor_policy((_ENV_RETRIEVE, _ACTOR_INDEX), read_confine=(_ACTOR_DIR, _ENV_DIR))
    assert not permission.decide_read(_RUBRIC, run_dir=tmp_path, defender_dir=_DEFENDER, policy=pol).allow
    assert permission.decide_read(_ACTOR_DIR / "x.md", run_dir=tmp_path, defender_dir=_DEFENDER, policy=pol).allow


def test_actor_policy_still_runs_pinned_scripts_but_no_reader(tmp_path):
    """confinement does not disturb the pinned-script matchers: both lesson scripts still run for the
    malicious leg; a bash reader of the rubric is still denied."""
    pol = actor_engine._actor_policy((_ENV_RETRIEVE, _ACTOR_INDEX), read_confine=(_ACTOR_DIR, _ENV_DIR))
    assert permission.decide_bash(f"python3 {_ENV_RETRIEVE} --alert-rule-ids 5712", policy=pol).allow
    assert permission.decide_bash(f"python3 {_ACTOR_INDEX} --techniques T1078", policy=pol).allow
    assert not permission.decide_bash(f"cat {_RUBRIC}", policy=pol).allow


def test_benign_actor_pins_env_script_only():
    """the benign leg keeps only the env-retrieve matcher; the tradecraft index stays malicious-only and
    the benign leg has no jq either."""
    pol = actor_engine._actor_policy((_ENV_RETRIEVE,), read_confine=(_ENV_DIR,))
    assert permission.decide_bash(f"python3 {_ENV_RETRIEVE} --alert-rule-ids 5712", policy=pol).allow
    assert not permission.decide_bash(f"python3 {_ACTOR_INDEX} --techniques T1078", policy=pol).allow
    assert not permission.decide_bash("jq . anything", policy=pol).allow


def test_judge_policy_is_jq_only():
    """_judge_policy -> bash_readers == ('jq',): jq retained, cat/grep/head/tail/ls dropped."""
    from defender.learning.pipeline.judge import engine_pydantic
    pol = engine_pydantic._judge_policy(read_roots=(), ticket_cli=None)
    assert pol.bash_readers == ("jq",)


# ============================================================================
# read tool: routing + pattern fold + return contract
# ============================================================================

def _tree(tmp_path):
    """tmp tree: a confine dir with a real lesson file + an out-of-confine rubric. Returns
    (deps, confine_dir, in_confine_file, rubric)."""
    dfn = tmp_path / "defender"
    conf = dfn / "lessons-environment"
    conf.mkdir(parents=True)
    lesson = conf / "ok.md"
    lesson.write_text("alpha\nbeta\ngamma\n")
    judge = dfn / "judge"
    judge.mkdir()
    rubric = judge / "malicious.md"
    rubric.write_text("SURVIVED-CRITERIA\n")
    run = tmp_path / "run"
    run.mkdir()
    pol = AgentPolicy(read_confine=(conf,), bash_readers=(), raw_reads=False,
                      adapters=False, adapter_sql_pipe=False, read_roots=())
    deps = ActorDeps(run_dir=run, defender_dir=dfn, run_id="r", salt="s", policy=pol)
    return deps, conf, lesson, rubric


def test_tool_allows_in_confine_read(tmp_path):
    """read_file of an in-confine file -> returns its text."""
    deps, conf, lesson, rubric = _tree(tmp_path)
    assert "beta" in tools._tool_read_file(deps, str(lesson))


def test_tool_denial_gives_no_existence_oracle(tmp_path):
    """a denied EXISTING file and a denied ABSENT file both raise the POLICY denial (never the tool's
    'file not found') — the deny path runs before any existence check, so it leaks nothing."""
    deps, conf, lesson, rubric = _tree(tmp_path)
    with pytest.raises(ModelRetry) as e_exists:
        tools._tool_read_file(deps, str(rubric))                       # denied, exists
    with pytest.raises(ModelRetry) as e_absent:
        tools._tool_read_file(deps, str(rubric.parent / "nope.md"))    # denied, absent
    assert "not found" not in str(e_exists.value).lower()
    assert "not found" not in str(e_absent.value).lower()
    # rejected: 404 'file not found' for a denied path (an existence oracle)


def test_tool_in_confine_missing_is_file_not_found(tmp_path):
    """an in-confine but nonexistent path passes the gate, then the tool raises 'file not found' —
    distinct from a policy denial."""
    deps, conf, lesson, rubric = _tree(tmp_path)
    with pytest.raises(ModelRetry) as e:
        tools._tool_read_file(deps, str(conf / "missing.md"))
    assert "not found" in str(e.value).lower()


def test_tool_pattern_search_returns_matches_only(tmp_path):
    """read_file(in-confine file, pattern='bet') -> the matching line(s), not the whole file (grep folded in)."""
    deps, conf, lesson, rubric = _tree(tmp_path)
    out = tools._tool_read_file(deps, str(lesson), pattern="bet")
    assert "beta" in out and "alpha" not in out


def test_tool_pattern_no_match_returns_empty_not_error(tmp_path):
    """read_file(in-confine file, pattern='zzz') -> empty result, NOT ModelRetry (no-match is a valid outcome)."""
    deps, conf, lesson, rubric = _tree(tmp_path)
    assert tools._tool_read_file(deps, str(lesson), pattern="zzz").strip() == ""
    # rejected: raise/err on zero matches


def test_tool_pattern_over_denied_path_raises(tmp_path):
    """search does not widen the read surface: read_file(rubric, pattern='SURVIVED') -> ModelRetry
    (the confine gates the path BEFORE any search)."""
    deps, conf, lesson, rubric = _tree(tmp_path)
    with pytest.raises(ModelRetry):
        tools._tool_read_file(deps, str(rubric), pattern="SURVIVED")
