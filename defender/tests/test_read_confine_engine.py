"""Executable spec (engine + tool layer) for #512 slice 2 — pydantic-guarded.

Pins the parts that need the pydantic runtime:
  - the actor's policy is compiled through the REAL seam and wires the confinement fields + one
    pinned-script GRANT per script (#575: the per-agent builders `_actor_policy`/`_judge_policy`
    are gone — each agent hangs its own `bash_shapes` builder on its own def, and the policy comes
    off `compile_policy_for`, the same call production makes),
  - the read tool _tool_read_file(deps, path, pattern=None) routes through the confined policy,
    folds search via `pattern`, and honours the return contract (deny -> ModelRetry, no existence
    oracle, no-match -> empty, in-confine-missing -> 'file not found').

The pure gate spec (decide_read / decide_bash) is in test_read_confine.py.
"""
from __future__ import annotations

import pytest

pytest.importorskip("pydantic_ai")

from pydantic_ai import ModelRetry  # noqa: E402

from defender.learning.core import config  # noqa: E402
from defender.learning.pipeline.actor_engine import ACTOR_DEF, ActorDeps  # noqa: E402
from defender.runtime import permission, tools  # noqa: E402
from defender.runtime.agent_definition import RunScope, compile_policy_for  # noqa: E402
from defender.runtime.permission import AgentPolicy  # noqa: E402
from defender.runtime.permission.grant import PROGRAMS, Route  # noqa: E402

_DEFENDER = config.REPO_ROOT / "defender"
_ACTOR_DIR = config.LESSONS_ACTOR_DIR
_ENV_DIR = config.LESSONS_ENVIRONMENT_DIR
_RUBRIC = _DEFENDER / "learning" / "pipeline" / "judge" / "malicious.md"
_ENV_RETRIEVE = config.LESSONS_ENV_RETRIEVE_SCRIPT
_ACTOR_INDEX = config.LESSONS_ACTOR_INDEX_SCRIPT


def _actor_policy(scripts, *, read_confine, run_dir=None):
    """The actor's policy off the REAL seam (#575) — `compile_policy_for(ACTOR_DEF, …)`, exactly
    what production binds. The pinned scripts and the gray-box confine ride the `RunScope`, which
    is where the per-invocation inputs a static def cannot carry have always lived; the def's own
    `bash_shapes` builder turns the scripts into one `pins_path` grant each."""
    return compile_policy_for(
        ACTOR_DEF,
        run_dir if run_dir is not None else _DEFENDER / "learning" / "runs",
        scope=RunScope(scripts=tuple(scripts), read_confine=tuple(read_confine)),
        defender_dir=_DEFENDER,
    )




def test_actor_policy_malicious_wires_confine_and_no_readers():
    """_actor_policy for the malicious leg -> read_confine == {lessons-actor, lessons-environment},
    `bash_allow` is JUST the two pinned-script patterns (no viewer/jq surface), and still gray-box
    (raw_reads False, no adapters)."""
    pol = _actor_policy((_ENV_RETRIEVE, _ACTOR_INDEX), read_confine=(_ACTOR_DIR, _ENV_DIR))
    assert set(pol.read_confine) == {_ACTOR_DIR, _ENV_DIR}
    assert len(pol.bash_allow) == 2
    assert not any(g.program == "cat" for g in pol.bash_allow)
    assert pol.read_allow == ()
    assert all(g.route is Route.PLAIN for g in pol.bash_allow)
    assert all(g.pins_path and g.program == "python3" for g in pol.bash_allow)


def test_benign_actor_policy_env_only():
    """_actor_policy for the benign leg -> read_confine == {lessons-environment} only; a single
    pinned-script pattern (env-retrieve), no viewer/jq surface."""
    pol = _actor_policy((_ENV_RETRIEVE,), read_confine=(_ENV_DIR,))
    assert set(pol.read_confine) == {_ENV_DIR}
    assert len(pol.bash_allow) == 1


def test_actor_policy_confine_denies_rubric_via_gate(tmp_path):
    """the malicious actor policy, THROUGH decide_read, denies the judge rubric and allows a lesson —
    the builder actually closes the gray-box hole."""
    pol = _actor_policy((_ENV_RETRIEVE, _ACTOR_INDEX), read_confine=(_ACTOR_DIR, _ENV_DIR))
    assert not permission.decide_read(_RUBRIC, run_dir=tmp_path, defender_dir=_DEFENDER, policy=pol).allow
    assert permission.decide_read(_ACTOR_DIR / "x.md", run_dir=tmp_path, defender_dir=_DEFENDER, policy=pol).allow


def test_actor_policy_still_runs_pinned_scripts_but_no_reader(tmp_path):
    """confinement does not disturb the pinned-script patterns: both lesson scripts still run for the
    malicious leg; a bash reader of the rubric is still denied."""
    pol = _actor_policy((_ENV_RETRIEVE, _ACTOR_INDEX), read_confine=(_ACTOR_DIR, _ENV_DIR))
    assert permission.decide_bash(f"python3 {_ENV_RETRIEVE} --alert-rule-ids 5712", policy=pol).allow
    assert permission.decide_bash(f"python3 {_ACTOR_INDEX} --techniques T1078", policy=pol).allow
    assert not permission.decide_bash(f"cat {_RUBRIC}", policy=pol).allow


def test_benign_actor_pins_env_script_only():
    """the benign leg keeps only the env-retrieve matcher; the tradecraft index stays malicious-only and
    the benign leg has no jq either."""
    pol = _actor_policy((_ENV_RETRIEVE,), read_confine=(_ENV_DIR,))
    assert permission.decide_bash(f"python3 {_ENV_RETRIEVE} --alert-rule-ids 5712", policy=pol).allow
    assert not permission.decide_bash(f"python3 {_ACTOR_INDEX} --techniques T1078", policy=pol).allow
    assert not permission.decide_bash("jq . anything", policy=pol).allow


def test_judge_policy_is_cat_and_sql_only(tmp_path):
    """The judge's lane is `cat` + `defender-sql` and NOTHING else — grep/head/tail/jq/ls and the
    inert `echo`/`true` are not on it (the judge does not inherit the reader lane's shim set).

    The two bits this used to assert are gone (#575) and are now the same fact stated as
    structure: `operand_gated` → the judge's `cat` grant carries a SCOPE and `PROGRAMS["cat"]` is
    a real extractor, so its operands are scope-checked at resolve() time like every other opener;
    `raw_reads` → the gather_raw payloads reach it through that scope (they live under the
    INVESTIGATION run dir, which arrives as a `read_root`), not through a capability bit that
    could be declared True while the lane denied it."""
    from defender.learning.pipeline.judge.engine_pydantic import JUDGE_DEF
    cmp_dir = tmp_path / "cmp"
    cmp_dir.mkdir()
    pol = compile_policy_for(
        JUDGE_DEF, tmp_path / "run", scope=RunScope(add_dirs=(cmp_dir,)), defender_dir=_DEFENDER,
    )
    assert {g.program for g in pol.bash_allow} == {"cat", "defender-sql"}
    cat = next(g for g in pol.bash_allow if g.program == "cat")
    assert cat.scope
    assert PROGRAMS["cat"] is not permission.OPENS_NOTHING
    for denied in ("jq '.'", "grep x y", "head x", "tail x", "ls .", "echo hi", "true"):
        assert not any(g.pattern.fullmatch(denied) for g in pol.bash_allow), denied
    raw = cmp_dir / "gather_raw" / "l-001" / "0.json"
    raw.parent.mkdir(parents=True)
    raw.write_text("{}\n")
    assert permission.decide_bash(
        f"cat {raw}", policy=pol, run_dir=tmp_path / "run", defender_dir=_DEFENDER,
    ).allow



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
    pol = AgentPolicy(read_confine=(conf,), bash_allow=(), read_roots=())
    deps = ActorDeps(
        run_dir=run, defender_dir=dfn, run_id="r", salt="s", policy=pol, cwd_anchor=run,
    )
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
        tools._tool_read_file(deps, str(rubric))
    with pytest.raises(ModelRetry) as e_absent:
        tools._tool_read_file(deps, str(rubric.parent / "nope.md"))
    assert "not found" not in str(e_exists.value).lower()
    assert "not found" not in str(e_absent.value).lower()


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
    assert "beta" in out
    assert "alpha" not in out


def test_tool_pattern_no_match_returns_empty_not_error(tmp_path):
    """read_file(in-confine file, pattern='zzz') -> empty result, NOT ModelRetry (no-match is a valid outcome)."""
    deps, conf, lesson, rubric = _tree(tmp_path)
    assert tools._tool_read_file(deps, str(lesson), pattern="zzz").strip() == ""


def test_tool_pattern_over_denied_path_raises(tmp_path):
    """search does not widen the read surface: read_file(rubric, pattern='SURVIVED') -> ModelRetry
    (the confine gates the path BEFORE any search)."""
    deps, conf, lesson, rubric = _tree(tmp_path)
    with pytest.raises(ModelRetry):
        tools._tool_read_file(deps, str(rubric), pattern="SURVIVED")
