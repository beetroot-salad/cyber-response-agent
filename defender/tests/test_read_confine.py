"""Executable spec for #512 slice 2 — per-agent read confinement across BOTH read surfaces.

WRITTEN BEFORE THE IMPLEMENTATION: this is the spec the code is coded against, RED until the
implement phase lands —

  - AgentPolicy.read_confine: tuple[Path, ...] = ()        # REPLACES the defender_dir read base when non-empty
  - AgentPolicy.bash_readers: tuple[str, ...] | None = None # per-policy bash reader set; None -> today's global viewers
  - decide_read: honour read_confine; FAIL CLOSED on a resolve() error
  - decide_bash(command, *, policy, run_dir=None, defender_dir=None): per-policy bash_readers +
    a jq file-arg path-gate (every file-loading arg validated against the policy's roots)

These are pure unit tests (no pydantic, no model, no API key) — they drive permission.decide_read /
decide_bash directly, constructing the AgentPolicy under test. Builder wiring (_actor_policy / _judge_policy)
and the read-tool return contract live in test_read_confine_engine.py.

Locked design (this slice): malicious actor confined to {lessons-actor, lessons-environment} with NO bash
readers; benign actor to {lessons-environment} with NO bash readers; judge keeps ONLY jq (path-gated to its
roots); main/gather byte-for-byte unchanged. See issue #512.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from defender.learning.core import config
from defender.runtime import permission
from defender.runtime.permission import AgentPolicy

_DEFENDER = config.REPO_ROOT / "defender"
_ACTOR_DIR = config.LESSONS_ACTOR_DIR
_ENV_DIR = config.LESSONS_ENVIRONMENT_DIR
_RUBRIC = _DEFENDER / "learning" / "pipeline" / "judge" / "malicious.md"  # the judge's grading rubric — gray-box target
_ENV_RETRIEVE = config.LESSONS_ENV_RETRIEVE_SCRIPT
_ACTOR_INDEX = config.LESSONS_ACTOR_INDEX_SCRIPT

_MALICIOUS_CONFINE = (_ACTOR_DIR, _ENV_DIR)
_BENIGN_CONFINE = (_ENV_DIR,)


def _policy(*, read_confine=(), bash_readers=(), raw_reads=False, read_roots=()):
    """An AgentPolicy for gate tests. Defaults model a confined, reader-less actor leg
    (bash_readers=() -> no generic bash readers). Override per case."""
    return AgentPolicy(
        adapters=False, adapter_sql_pipe=False, raw_reads=raw_reads,
        read_roots=read_roots, read_confine=read_confine, bash_readers=bash_readers,
    )


# ============================================================================
# A. decide_read — confine semantics (pure paths; decide_read does not stat)
# ============================================================================

@pytest.mark.parametrize("path", [_ACTOR_DIR / "T1078.md", _ENV_DIR / "svc-monitoring.md"])
def test_malicious_reads_within_confine_allowed(tmp_path, path):
    """read under lessons-actor / lessons-environment (malicious confine) -> allow."""
    pol = _policy(read_confine=_MALICIOUS_CONFINE)
    assert permission.decide_read(path, run_dir=tmp_path, defender_dir=_DEFENDER, policy=pol).allow, path


@pytest.mark.parametrize("path", [
    _RUBRIC,                                                             # the judge rubric — the FN-metric target
    _DEFENDER / "SKILL.md",                                             # under defender_dir but outside the confine
    _DEFENDER / "learning" / "pipeline" / "judge" / "benign.md",
])
def test_malicious_reads_outside_confine_denied(tmp_path, path):
    """read under defender_dir but OUTSIDE the confine (rubric, SKILL.md) -> deny. The regression #510 dropped."""
    pol = _policy(read_confine=_MALICIOUS_CONFINE)
    assert not permission.decide_read(path, run_dir=tmp_path, defender_dir=_DEFENDER, policy=pol).allow, path


def test_benign_confined_to_environment(tmp_path):
    """benign leg: lessons-environment allowed; lessons-actor (tradecraft) AND rubric denied — the gray-box split."""
    pol = _policy(read_confine=_BENIGN_CONFINE)
    assert permission.decide_read(_ENV_DIR / "x.md", run_dir=tmp_path, defender_dir=_DEFENDER, policy=pol).allow
    assert not permission.decide_read(_ACTOR_DIR / "x.md", run_dir=tmp_path, defender_dir=_DEFENDER, policy=pol).allow
    assert not permission.decide_read(_RUBRIC, run_dir=tmp_path, defender_dir=_DEFENDER, policy=pol).allow


def test_confine_replaces_defender_dir_but_run_dir_stays(tmp_path):
    """confine REPLACES the defender_dir base; run_dir remains a root (own artifacts still readable)."""
    pol = _policy(read_confine=_MALICIOUS_CONFINE)
    assert permission.decide_read(tmp_path / "actor_out.json", run_dir=tmp_path, defender_dir=_DEFENDER, policy=pol).allow
    assert not permission.decide_read(_DEFENDER / "SKILL.md", run_dir=tmp_path, defender_dir=_DEFENDER, policy=pol).allow
    # rejected: confine ADDS to {run_dir, defender_dir} (additive like read_roots -> would not close the hole)


def test_empty_confine_is_legacy_defender_dir_base(tmp_path):
    """read_confine=() -> roots are exactly {run_dir, defender_dir}; a defender_dir read is allowed
    (byte-for-byte with today's main/gather/judge). The field is inert when empty."""
    pol = _policy(read_confine=(), bash_readers=None)
    assert permission.decide_read(_DEFENDER / "SKILL.md", run_dir=tmp_path, defender_dir=_DEFENDER, policy=pol).allow
    # rejected: empty confine means "lock to run_dir only" (would break every existing decide_read row)


def test_confine_root_dir_itself_allowed(tmp_path):
    """the confine root DIRECTORY itself resolves within-root -> allow (a pattern-search needs the dir
    readable; a plain read of a dir is the tool's not-a-file concern, not the gate's)."""
    pol = _policy(read_confine=_MALICIOUS_CONFINE)
    assert permission.decide_read(_ACTOR_DIR, run_dir=tmp_path, defender_dir=_DEFENDER, policy=pol).allow
    # rejected: deny the bare root dir (would block search-root validation)


def test_nonexistent_in_confine_path_allowed(tmp_path):
    """decide_read decides on the PATH, not existence: an in-confine path that does not exist -> allow
    (the tool then raises 'file not found')."""
    pol = _policy(read_confine=_MALICIOUS_CONFINE)
    p = _ACTOR_DIR / "does-not-exist.md"
    assert permission.decide_read(p, run_dir=tmp_path, defender_dir=_DEFENDER, policy=pol).allow
    # rejected: decide_read stats and 404s/denies a nonexistent in-confine path


def test_traversal_out_of_confine_denied(tmp_path):
    """a `..` traversal from an in-confine dir up to the rubric -> deny (resolve() collapses `..`
    before the containment check)."""
    pol = _policy(read_confine=_MALICIOUS_CONFINE)
    escape = _ENV_DIR / ".." / "learning" / "pipeline" / "judge" / "malicious.md"
    assert not permission.decide_read(escape, run_dir=tmp_path, defender_dir=_DEFENDER, policy=pol).allow


@pytest.mark.parametrize("name", [".env", "credentials.txt", "ground_truth.yaml", "cases.json"])
def test_denylist_still_fires_inside_confine(tmp_path, name):
    """a secret/ground-truth file landing INSIDE a confine root is still denied by the global denylist."""
    pol = _policy(read_confine=_MALICIOUS_CONFINE)
    assert not permission.decide_read(_ENV_DIR / name, run_dir=tmp_path, defender_dir=_DEFENDER, policy=pol).allow


def test_gather_raw_clamp_still_denies_confined_actor(tmp_path):
    """the actor (raw_reads=False) is still clamped off gather_raw after the confine change; gather_raw is
    not in the confine anyway (independent AND-condition, order only changes the message)."""
    pol = _policy(read_confine=_MALICIOUS_CONFINE, raw_reads=False)
    raw = tmp_path / "gather_raw" / "l-001" / "0.json"
    assert not permission.decide_read(raw, run_dir=tmp_path, defender_dir=_DEFENDER, policy=pol).allow


# ---- A(fs). resolve()-based escapes: symlink + fail-closed (tmp fs, no pydantic) ----

def _tmp_tree(tmp_path):
    """A tmp defender-like tree: a confine dir + an out-of-confine 'rubric'. Returns (defender_dir, confine, rubric)."""
    dfn = tmp_path / "defender"
    conf = dfn / "lessons-environment"
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
    os.symlink(b, a)  # cycle -> OSError from resolve()
    pol = _policy(read_confine=(conf,))
    assert not permission.decide_read(a, run_dir=tmp_path / "run", defender_dir=dfn, policy=pol).allow
    # rejected: let the OSError propagate (a blocking gate must not raise)


# ============================================================================
# B. decide_bash — actor reader surface (bash_readers=())
# ============================================================================

@pytest.mark.parametrize("cmd", [
    "cat defender/lessons-actor/x.md",
    "grep foo defender/lessons-environment/y.md",
    "head -5 defender/lessons-actor/x.md",
    "tail -5 defender/lessons-actor/x.md",
    "ls defender/lessons-actor",
    "jq . defender/lessons-actor/x.md",
])
def test_actor_all_generic_readers_denied(cmd):
    """a confined actor (bash_readers=()) is denied EVERY generic bash reader — reads go through the tool.
    Even an IN-confine path is denied here: bash is simply not a read path for the actor."""
    assert not permission.decide_bash(cmd, policy=_policy(bash_readers=())).allow, cmd


def test_reduction_is_per_policy_not_global():
    """bash_readers=None reproduces today's global viewer set (cat/grep allowed). The reader reduction is
    per-policy (actor/judge), NOT a global removal — main/gather are unaffected."""
    glob = _policy(bash_readers=None)
    assert permission.decide_bash("cat /tmp/x", policy=glob).allow
    assert permission.decide_bash("grep foo /tmp/x", policy=glob).allow


# ============================================================================
# C. decide_bash — judge jq gate (bash_readers=('jq',), path-gated to roots)
#    NOTE: judge is UNCONFINED this slice (read_confine=()), so its roots are
#    {run_dir, defender_dir}. The jq gate protects against reads OUTSIDE those
#    (e.g. /etc/passwd), not against the rubric (which is in-roots until judge
#    confinement lands in a later slice).
# ============================================================================

def _judge_gate(cmd, run_dir, *, read_roots=()):
    pol = _policy(bash_readers=("jq",), raw_reads=True, read_roots=read_roots)
    return permission.decide_bash(cmd, policy=pol, run_dir=run_dir, defender_dir=_DEFENDER)


def test_judge_jq_in_roots_operand_allowed(tmp_path):
    """jq with a file operand under run_dir (gather_raw) -> allow. The refute primitive keeps working;
    raw_reads=True skips the gather_raw clamp."""
    raw = tmp_path / "gather_raw" / "l-002" / "0.json"
    assert _judge_gate(f"jq '[.[]|select(.user==\"x\")]|length' {raw}", tmp_path).allow


def test_judge_jq_out_of_roots_operand_denied(tmp_path):
    """jq with a file operand outside the judge's roots -> deny (jq retained but path-gated)."""
    assert not _judge_gate("jq . /etc/passwd", tmp_path).allow


def test_judge_jq_slurpfile_out_of_roots_denied(tmp_path):
    """the flag-injection escape: --slurpfile loads an out-of-roots file while the trailing operand looks
    clean -> deny. EVERY file-loading arg is validated, not just the last token."""
    raw = tmp_path / "gather_raw" / "l-002" / "0.json"
    assert not _judge_gate(f"jq --slurpfile s /etc/passwd '.' {raw}", tmp_path).allow


def test_judge_jq_rawfile_out_of_roots_denied(tmp_path):
    """--rawfile is a second file-loading flag — same gate -> deny on an out-of-roots target."""
    raw = tmp_path / "gather_raw" / "l-002" / "0.json"
    assert not _judge_gate(f"jq --rawfile r /etc/shadow '.' {raw}", tmp_path).allow


def test_judge_bare_stdin_jq_allowed(tmp_path):
    """jq with NO file operand (reads stdin) -> allow: inert, nothing to path-gate."""
    assert _judge_gate("jq '.'", tmp_path).allow
    # rejected: deny any jq lacking an in-roots file operand (would break stdin/pipe jq)


def test_judge_multi_stage_jq_denied(tmp_path):
    """multi-stage jq (pipe / compound) -> deny: only single-stage jq survives, else a downstream head/cat
    re-opens the reader surface via the global fall-through."""
    raw = tmp_path / "gather_raw" / "l-002" / "0.json"
    assert not _judge_gate(f"jq '.' {raw} | head", tmp_path).allow
    assert not _judge_gate(f"cat {raw} | jq '.'", tmp_path).allow


@pytest.mark.parametrize("tmpl", ["cat {r}", "grep x {r}", "head {r}", "tail {r}", "ls ."])
def test_judge_non_jq_readers_denied(tmp_path, tmpl):
    """for the judge, cat/grep/head/tail/ls are denied (subsumed by the read tool's read+search);
    only jq survives as a bash reader."""
    raw = tmp_path / "gather_raw" / "l-002" / "0.json"
    assert not _judge_gate(tmpl.format(r=raw), tmp_path).allow
    # rejected: judge keeps grep for gather_raw text scans (folded into read_file(pattern=))


def test_judge_jq_multiple_operands_one_out_of_roots_denied(tmp_path):
    """multiple file operands, one outside roots -> deny (validate EVERY file-shaped arg, not just one)."""
    raw = tmp_path / "gather_raw" / "l-002" / "0.json"
    assert not _judge_gate(f"jq -s '.' {raw} /etc/passwd", tmp_path).allow


def test_judge_jq_comparison_dir_via_read_roots_allowed(tmp_path):
    """jq of a file under the judge's read_roots (its comparison dir) -> allow (read_roots still widen)."""
    comp = tmp_path / "comparison"
    assert _judge_gate(f"jq '.' {comp / 'x.json'}", tmp_path, read_roots=(comp,)).allow


# ============================================================================
# D. regression — main/gather byte-for-byte unchanged
# ============================================================================

def test_main_global_viewers_unchanged():
    """MAIN declares no per-policy reader set (bash_readers is None) and keeps the full viewer set —
    cat/grep still allowed. The reader reduction does not touch main."""
    main = permission.policy_for("main")
    assert main.bash_readers is None
    assert permission.decide_bash("cat /tmp/x", policy=main).allow
    assert permission.decide_bash("grep foo /tmp/x", policy=main).allow


def test_gather_stream_plumbing_unchanged():
    """GATHER's compute lane is untouched: cat|defender-sql and adapter|defender-sql and on-disk jq still
    allowed — for gather cat/jq are stream plumbing, not reads to fold away (deferred slice)."""
    gather = permission.policy_for("gather")
    assert permission.decide_bash("cat /tmp/p.json | defender-sql 'SELECT count(*) FROM data'", policy=gather).allow
    assert permission.decide_bash("defender-elastic query 'x' --raw", policy=gather).allow
    assert permission.decide_bash("jq '.hits|length' /tmp/p.json", policy=gather).allow


def test_empty_confine_preserves_existing_decide_read_rows(tmp_path):
    """the confine field is inert for main: corpus allow, outside deny, gather_raw clamp — all unchanged."""
    run = tmp_path / "run"
    (run / "gather_raw" / "l").mkdir(parents=True)
    dfn = tmp_path / "defender"
    (dfn / "skills").mkdir(parents=True)
    main = permission.policy_for("main")
    assert permission.decide_read(dfn / "SKILL.md", run_dir=run, defender_dir=dfn, policy=main).allow
    assert not permission.decide_read(Path("/etc/passwd"), run_dir=run, defender_dir=dfn, policy=main).allow
    assert not permission.decide_read(run / "gather_raw" / "l" / "0.json", run_dir=run, defender_dir=dfn, policy=main).allow
