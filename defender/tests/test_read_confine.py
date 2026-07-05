"""Spec for #512 slice 2 — per-agent read confinement across BOTH read surfaces.

The permission surface under test (#512 slice 2 + the #522 regex-allowlist refactor):

  - AgentPolicy.read_confine: tuple[Path, ...] = ()        # REPLACES the defender_dir read base when non-empty
  - AgentPolicy.bash_allow: tuple[re.Pattern, ...] = ()    # per-agent anchored regexes over the tokenized argv
  - AgentPolicy.jq_operand_gated: bool = False             # jq file operands must resolve within the read roots
  - decide_read: honour read_confine; FAIL CLOSED on a resolve() error
  - decide_bash(command, *, policy, run_dir=None, defender_dir=None): a command is allowed iff EVERY stage
    matches some `bash_allow` pattern; a `jq` stage is additionally path-gated when `jq_operand_gated`.

These are pure unit tests (no pydantic, no model, no API key) — they drive permission.decide_read /
decide_bash directly, constructing the AgentPolicy under test. Builder wiring (_actor_policy / _judge_policy)
and the read-tool return contract live in test_read_confine_engine.py.

Locked design: malicious actor confined to {lessons-actor, lessons-environment} with NO bash readers
(empty `bash_allow`); benign actor to {lessons-environment} likewise; judge keeps ONLY jq (path-gated to
its roots via `jq_operand_gated`); main/gather keep the full viewer allowlist. See issues #512 / #522.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

import pytest

from defender.learning.core import config
from defender.runtime import permission
from defender.runtime.permission import AgentPolicy
from defender.runtime.permission.policies._common import viewer_patterns

_DEFENDER = config.REPO_ROOT / "defender"
_ACTOR_DIR = config.LESSONS_ACTOR_DIR
_ENV_DIR = config.LESSONS_ENVIRONMENT_DIR
_RUBRIC = _DEFENDER / "learning" / "pipeline" / "judge" / "malicious.md"  # the judge's grading rubric — gray-box target
_ENV_RETRIEVE = config.LESSONS_ENV_RETRIEVE_SCRIPT
_ACTOR_INDEX = config.LESSONS_ACTOR_INDEX_SCRIPT

_MALICIOUS_CONFINE = (_ACTOR_DIR, _ENV_DIR)
_BENIGN_CONFINE = (_ENV_DIR,)

# The judge's jq shape (any jq invocation; operands path-gated separately) and the
# main/gather global viewer allowlist — mirrors of the production policies.
_JQ = re.compile(r"^jq(?: .*)?$")
_VIEWERS = viewer_patterns()


def _policy(*, read_confine=(), bash_allow=(), jq_operand_gated=False, raw_reads=False, read_roots=()):
    """An AgentPolicy for gate tests. Defaults model a confined, reader-less actor leg
    (empty `bash_allow` -> no bash readers at all). Override per case."""
    return AgentPolicy(
        adapters=False, adapter_sql_pipe=False, raw_reads=raw_reads,
        read_roots=read_roots, read_confine=read_confine,
        bash_allow=bash_allow, jq_operand_gated=jq_operand_gated,
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
    pol = _policy(read_confine=())
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
# B. decide_bash — actor reader surface (empty bash_allow)
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
    """a confined actor (empty `bash_allow`) is denied EVERY generic bash reader — reads go through the tool.
    Even an IN-confine path is denied here: bash is simply not a read path for the actor."""
    assert not permission.decide_bash(cmd, policy=_policy(bash_allow=())).allow, cmd


def test_reduction_is_per_policy_not_global():
    """the global viewer allowlist (main/gather's `bash_allow`) still permits cat/grep. The reader reduction
    is per-policy (actor/judge carry a narrower `bash_allow`), NOT a global removal — main/gather unaffected."""
    glob = _policy(bash_allow=_VIEWERS)
    assert permission.decide_bash("cat /tmp/x", policy=glob).allow
    assert permission.decide_bash("grep foo /tmp/x", policy=glob).allow


# ============================================================================
# C. decide_bash — judge jq gate (bash_allow=(jq,), jq_operand_gated -> path-gated)
#    NOTE: judge is UNCONFINED this slice (read_confine=()), so its roots are
#    {run_dir, defender_dir}. The jq gate protects against reads OUTSIDE those
#    (e.g. /etc/passwd), not against the rubric (which is in-roots until judge
#    confinement lands in a later slice).
# ============================================================================

def _judge_gate(cmd, run_dir, *, read_roots=()):
    pol = _policy(bash_allow=(_JQ,), jq_operand_gated=True, raw_reads=True, read_roots=read_roots)
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


def test_judge_pipe_with_non_jq_stage_denied(tmp_path):
    """a pipe whose downstream/upstream stage is NOT jq -> deny: EVERY stage must match the judge's
    (jq-only) `bash_allow`, so head/cat match no pattern and the whole command is denied. (This
    replaces the old single-stage restriction: a jq|jq pipe is now allowed — see the next test.)"""
    raw = tmp_path / "gather_raw" / "l-002" / "0.json"
    assert not _judge_gate(f"jq '.' {raw} | head", tmp_path).allow
    assert not _judge_gate(f"cat {raw} | jq '.'", tmp_path).allow


def test_judge_jq_pipe_all_stages_gated(tmp_path):
    """a jq|jq pipe is allowed (both stages match `bash_allow`), but EVERY jq stage's operands are still
    path-gated: an out-of-roots operand on ANY stage denies the whole command."""
    raw = tmp_path / "gather_raw" / "l-002" / "0.json"
    assert _judge_gate(f"jq '.' {raw} | jq '.a'", tmp_path).allow
    assert not _judge_gate(f"jq '.' {raw} | jq '.' /etc/passwd", tmp_path).allow


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


@pytest.mark.parametrize("cmd", [
    "jq -nf /etc/passwd",      # -n + -f bundled: jq opens /etc/passwd as its `-f` filter program
    "jq -Rf /etc/passwd",      # -R + -f
    "jq -sf /etc/passwd",      # -s + -f
    "jq -L/etc/ssh '.'",       # attached -L<dir>: an out-of-roots module search path
])
def test_judge_jq_bundled_arg_flag_denied(tmp_path, cmd):
    """a SHORT bundle carrying an arg-taking flag (`-nf FILE`, `-L<dir>`) -> deny. jq bundles short options
    and lets a trailing `-f`/`-L` consume the next token / an attached value, opening a file the per-token
    parser would otherwise miss (and jq echoes a compile error's source line to stderr). The gate FAILS
    CLOSED on such a bundle rather than leave its file un-gated."""
    assert not _judge_gate(cmd, tmp_path).allow, cmd


@pytest.mark.parametrize("name", ["cases.json", "ground_truth.yaml", ".env", "credentials.txt"])
def test_judge_jq_denylisted_file_in_roots_denied(tmp_path, name):
    """a denylisted secret / ground-truth file that resolves INSIDE the judge's roots is denied in the bash
    jq lane too — parity with decide_read, so the judge can't `jq` the held-out answer key / a captured .env
    that read_file refuses. A non-denylisted sibling in the same dir stays allowed (it's the name, not the dir)."""
    assert not _judge_gate(f"jq '.' {tmp_path / name}", tmp_path).allow, name
    assert _judge_gate(f"jq '.' {tmp_path / 'payload.json'}", tmp_path).allow  # sibling, not denied


def test_judge_jq_comparison_dir_via_read_roots_allowed(tmp_path):
    """jq of a file under the judge's read_roots (its comparison dir) -> allow (read_roots still widen)."""
    comp = tmp_path / "comparison"
    assert _judge_gate(f"jq '.' {comp / 'x.json'}", tmp_path, read_roots=(comp,)).allow


# ============================================================================
# D. regression — main/gather byte-for-byte unchanged
# ============================================================================

def test_main_global_viewers_unchanged():
    """MAIN keeps the full viewer allowlist (`bash_allow` = viewers, not operand-gated) — cat/grep
    still allowed. The per-agent reader reduction does not touch main."""
    main = permission.policy_for("main")
    assert main.bash_allow
    assert not main.jq_operand_gated
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
