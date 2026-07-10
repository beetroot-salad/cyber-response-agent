"""Spec for #512 slice 2 — per-agent read confinement across BOTH read surfaces.

The permission surface under test (#512 slice 2 + the #522 regex-allowlist refactor):

  - AgentPolicy.read_confine: tuple[Path, ...] = ()        # REPLACES the defender_dir read base when non-empty
  - AgentPolicy.bash_allow: tuple[re.Pattern, ...] = ()    # per-agent anchored regexes over the tokenized argv
  - AgentPolicy.operand_gated: bool = False                # a file-opening stage's operands must resolve within the read roots
  - decide_read: honour read_confine; FAIL CLOSED on a resolve() error
  - decide_bash(command, *, policy, run_dir=None, defender_dir=None): a command is allowed iff EVERY stage
    matches some `bash_allow` pattern; a `cat` stage is additionally path-gated when `operand_gated`.

These are pure unit tests (no pydantic, no model, no API key) — they drive permission.decide_read /
decide_bash directly, constructing the AgentPolicy under test. Builder wiring (_actor_policy / _judge_policy)
and the read-tool return contract live in test_read_confine_engine.py.

Locked design: malicious actor confined to {lessons-actor, lessons-environment} with NO bash readers
(empty `bash_allow`); benign actor to {lessons-environment} likewise; judge keeps ONLY `cat` (operands
path-gated to its roots via `operand_gated`) piped into the sandboxed `defender-sql`; main/gather keep the
full viewer allowlist. See issues #512 / #522.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")  # CI installs the runtime extra; skip otherwise

from defender.learning.core import config  # noqa: E402
from defender.runtime import permission  # noqa: E402
from defender.runtime.agent_definition import compile_policy_for  # noqa: E402
from defender.runtime.driver import GATHER_DEF, MAIN_DEF  # noqa: E402
from defender.runtime.permission import AgentPolicy  # noqa: E402

_DEFENDER = config.REPO_ROOT / "defender"
_ACTOR_DIR = config.LESSONS_ACTOR_DIR
_ENV_DIR = config.LESSONS_ENVIRONMENT_DIR
_RUBRIC = _DEFENDER / "learning" / "pipeline" / "judge" / "malicious.md"  # the judge's grading rubric — gray-box target
_ENV_RETRIEVE = config.LESSONS_ENV_RETRIEVE_SCRIPT
_ACTOR_INDEX = config.LESSONS_ACTOR_INDEX_SCRIPT

_MALICIOUS_CONFINE = (_ACTOR_DIR, _ENV_DIR)
_BENIGN_CONFINE = (_ENV_DIR,)

# The judge's two shapes, IMPORTED from their authoritative source rather than re-typed:
# `cat` (operands UNANCHORED here and path-gated separately at resolve() time) and the
# argument-inert `defender-sql`. A hand-copied regex would keep passing against the OLD
# grammar after the real one is tightened. The main/gather viewer allowlist is PER-RUN +
# anchored (#535), so it is built via `compile_policy_for(<DEF>, run_dir=…, defender_dir=…)`
# in the tests below rather than a module const.
from defender.learning.pipeline.judge.engine_pydantic import (  # noqa: E402
    _CAT_PATTERN as _CAT,
    _SQL_PATTERN as _SQL,
)


def _policy(*, read_confine=(), bash_allow=(), operand_gated=False, raw_reads=False, read_roots=()):
    """An AgentPolicy for gate tests. Defaults model a confined, reader-less actor leg
    (empty `bash_allow` -> no bash readers at all). Override per case."""
    return AgentPolicy(
        adapters=False, adapter_sql_pipe=False, raw_reads=raw_reads,
        read_roots=read_roots, read_confine=read_confine,
        bash_allow=bash_allow, operand_gated=operand_gated,
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


def test_reduction_is_per_policy_not_global(tmp_path):
    """the reader reduction is per-policy, NOT a global removal: an actor policy with empty
    `bash_allow` denies every bash reader, while main's (now anchored — #535) viewer allowlist still
    permits an IN-ROOT cat/grep. The narrowing lives in the policy, not the gate. (Out-of-root now
    denies for main too — the anchoring is comprehensively pinned in test_read_confine_bash.py.)"""
    run, dfn = tmp_path / "run", tmp_path / "defender"
    run.mkdir()
    dfn.mkdir()
    main = compile_policy_for(MAIN_DEF, run_dir=run, defender_dir=dfn)
    inv = run / "investigation.md"
    assert not permission.decide_bash(f"cat {inv}", policy=_policy(bash_allow=())).allow   # actor: no bash reader
    assert permission.decide_bash(f"cat {inv}", policy=main).allow                          # main: in-root ok
    assert permission.decide_bash(f"grep foo {inv}", policy=main).allow


# ============================================================================
# C. decide_bash — judge operand gate
#    (bash_allow=(cat, defender-sql), operand_gated -> cat's operands path-gated)
#    NOTE: judge is UNCONFINED this slice (read_confine=()), so its roots are
#    {run_dir, defender_dir, *read_roots}. The operand gate protects against reads
#    OUTSIDE those (e.g. /etc/passwd), not against the rubric (which is in-roots
#    until judge confinement lands in a later slice).
#
#    `cat` OPENS files, so its operands are resolve()-gated. `defender-sql` opens
#    none — stdin only, one argv (the SQL), DuckDB sealed before that SQL runs — so
#    it is argument-inert and deliberately NOT operand-gated.
# ============================================================================

def _judge_gate(cmd, run_dir, *, read_roots=()):
    pol = _policy(bash_allow=(_CAT, _SQL), operand_gated=True, raw_reads=True, read_roots=read_roots)
    return permission.decide_bash(cmd, policy=pol, run_dir=run_dir, defender_dir=_DEFENDER)


def test_judge_cat_sql_pipe_in_roots_allowed(tmp_path):
    """the refute primitive: `cat <payload> | defender-sql '<SQL>'` with the operand under run_dir
    -> allow. raw_reads=True skips the gather_raw clamp."""
    raw = tmp_path / "gather_raw" / "l-002" / "0.json"
    sql = "SELECT count(*) FROM (SELECT unnest(hits) h FROM data) WHERE h.user = 'x'"
    assert _judge_gate(f'cat {raw} | defender-sql "{sql}"', tmp_path).allow


def test_judge_gather_raw_outside_run_dir_via_read_roots_allowed(tmp_path):
    """THE production topology, and the reason the judge is operand-gated rather than
    textually anchored: `gather_raw` lives under the INVESTIGATION run dir while the judge's
    run_dir is the LEARNING run dir, so it arrives only as a `read_root`. The anchored reader
    grammars (`policies._common._file_operand`) cannot see read_roots; `read_allowed_path` can."""
    investigation, learning = tmp_path / "inv", tmp_path / "learn"
    raw = investigation / "gather_raw"
    sql = "SELECT total, returned, truncated FROM data"
    assert _judge_gate(
        f'cat {raw / "l-002" / "0.json"} | defender-sql "{sql}"', learning, read_roots=(raw,),
    ).allow
    # ...and a sibling of that read_root is still out of bounds
    assert not _judge_gate(
        f'cat {investigation / "secrets" / "x.json"}', learning, read_roots=(raw,),
    ).allow


def test_judge_cat_out_of_roots_operand_denied(tmp_path):
    """cat with a file operand outside the judge's roots -> deny (cat retained but path-gated)."""
    assert not _judge_gate("cat /etc/passwd", tmp_path).allow
    assert not _judge_gate("cat /etc/passwd | defender-sql 'SELECT 1'", tmp_path).allow


def test_judge_bare_stdin_sql_allowed(tmp_path):
    """`defender-sql` with no producer reads stdin -> allow: it opens no file, nothing to path-gate."""
    assert _judge_gate("defender-sql 'SELECT 1'", tmp_path).allow


def test_judge_sql_argv_is_not_operand_gated(tmp_path):
    """`defender-sql`'s single argv is SQL, not a path — it must never be resolved against the read
    roots. A query whose TEXT looks like an out-of-roots path is still allowed: the sealed DuckDB
    (enable_external_access=false + lock_configuration=true) bounds it, not this gate."""
    assert _judge_gate("defender-sql 'SELECT * FROM data /etc/passwd'", tmp_path).allow
    assert _judge_gate("defender-sql '/etc/shadow'", tmp_path).allow


def test_judge_stdin_cat_mid_pipe_allowed(tmp_path):
    """a `cat` naming no file (a downstream pipe stage) is inert: no operand to gate, so it must not
    be denied for lack of one."""
    raw = tmp_path / "gather_raw" / "l-002" / "0.json"
    assert _judge_gate(f"cat {raw} | cat | defender-sql 'SELECT 1'", tmp_path).allow


def test_judge_cat_operand_with_embedded_nul_fails_closed(tmp_path):
    """`shlex` happily tokenizes a NUL into an operand, but `Path.resolve()` raises
    `ValueError` on one — an exception class the fail-closed `except` used to miss, so
    the gate RAISED out of `decide_bash` instead of denying. Every gate that resolves a
    hostile operand must deny, never raise (`files._RESOLVE_ERRORS`)."""
    assert not _judge_gate("cat /etc/pass\x00wd", tmp_path).allow
    assert not _judge_gate("cat /etc/pass\x00wd | defender-sql 'SELECT 1'", tmp_path).allow


def test_judge_relative_operand_denied(tmp_path):
    """The judge's payloads reach it as ABSOLUTE `read_roots`, so a relative operand names
    nothing inside them and is denied. The prompts must not teach one either — that side is
    pinned by `test_every_command_the_prompt_teaches_passes_the_judges_own_gate`."""
    assert not _judge_gate("cat gather_raw/l-002/0.json", tmp_path).allow


def test_judge_relative_operand_gated_against_the_executors_cwd(monkeypatch, tmp_path):
    """A relative operand must be judged against `defender_dir.parent` — the cwd
    `tools._tool_bash` gives the executor — NOT the ambient process cwd. Otherwise the
    gate validates one file while `cat` opens another: the validator/executor differential
    `bash_exec` exists to close, and which `tools._resolve_operand` already closed for the
    file tools.

    `run_dir` is deliberately a directory the ambient cwd is NOT inside, so a relative
    operand cannot land in-roots by accident — that is what makes the two resolutions
    distinguishable."""
    run = tmp_path / "run"
    neutral = tmp_path / "neutral"
    neutral.mkdir(parents=True)
    # repo-relative, and really inside `defender_dir` when resolved from the executor's cwd
    inside, escape = "defender/CLAUDE.md", "defender/../../../../../etc/passwd"

    verdicts = []
    for cwd in (neutral, tmp_path):
        monkeypatch.chdir(cwd)
        verdicts.append((
            _judge_gate(f"cat {inside}", run).allow,
            _judge_gate(f"cat {escape}", run).allow,
        ))
    # in-roots relative operand ALLOWED, `..` escape DENIED — from any ambient cwd
    assert verdicts == [(True, False)] * 2, f"verdict moved with the ambient cwd: {verdicts}"


@pytest.mark.parametrize("cmd", [
    'cat {r} | defender-sql \\\n  "SELECT 1"',          # `\`-continuation: dangling escape
    'cat {r} | defender-sql "SELECT 1\nFROM data"',      # newline inside a quoted argument
])
def test_multiline_command_is_denied_with_a_reason_that_says_why(tmp_path, cmd):
    """`bash_exec.parse` lexes each PHYSICAL LINE on its own (an unquoted newline is a
    command separator), so it does not model bash's line-JOINING: both shapes leave line 1
    unbalanced and fail closed. That is deliberate — but the deny must SAY so. The generic
    `policy.deny_reason` reads as "this program is forbidden", which sends the model
    hunting for another one when its command was fine and only its line breaks were not."""
    raw = tmp_path / "gather_raw" / "l-002" / "0.json"
    decision = _judge_gate(cmd.format(r=raw), tmp_path)
    assert not decision.allow
    assert decision.reason == permission.bash.UNTOKENIZABLE_REASON
    assert "SINGLE line" in decision.reason


def test_judge_pipe_with_unapproved_stage_denied(tmp_path):
    """a pipe with a stage outside the judge's (cat, defender-sql) `bash_allow` -> deny: EVERY stage
    must match, so `head`/`jq` match no pattern and the whole command is denied."""
    raw = tmp_path / "gather_raw" / "l-002" / "0.json"
    assert not _judge_gate(f"cat {raw} | head", tmp_path).allow
    assert not _judge_gate(f"cat {raw} | jq '.'", tmp_path).allow


def test_judge_pipe_all_cat_stages_gated(tmp_path):
    """a cat|cat pipe matches `bash_allow` twice, but EVERY cat stage's operands are still
    path-gated: an out-of-roots operand on ANY stage denies the whole command."""
    raw = tmp_path / "gather_raw" / "l-002" / "0.json"
    assert _judge_gate(f"cat {raw} | cat {raw}", tmp_path).allow
    assert not _judge_gate(f"cat {raw} | cat /etc/passwd", tmp_path).allow


@pytest.mark.parametrize("tmpl", ["grep x {r}", "head {r}", "tail {r}", "ls .", "jq . {r}", "echo hi"])
def test_judge_other_readers_denied(tmp_path, tmpl):
    """for the judge, grep/head/tail/ls/jq are denied (subsumed by the read tool's read+search), and
    the inert `echo`/`true` viewers are NOT inherited — only cat + defender-sql survive as bash."""
    raw = tmp_path / "gather_raw" / "l-002" / "0.json"
    assert not _judge_gate(tmpl.format(r=raw), tmp_path).allow
    # rejected: judge keeps grep for gather_raw text scans (folded into read_file(pattern=))


def test_judge_cat_multiple_operands_one_out_of_roots_denied(tmp_path):
    """multiple file operands, one outside roots -> deny (validate EVERY operand, not just one)."""
    raw = tmp_path / "gather_raw" / "l-002" / "0.json"
    assert not _judge_gate(f"cat {raw} /etc/passwd", tmp_path).allow


def test_judge_cat_operand_after_double_dash_still_gated(tmp_path):
    """`--` ends options, so a flag-shaped token after it is an OPERAND cat opens — and it is gated
    like any other. The gate must not mistake it for a flag and wave it through."""
    assert not _judge_gate("cat -- /etc/passwd", tmp_path).allow
    assert _judge_gate(f"cat -n -- {tmp_path / 'payload.json'}", tmp_path).allow


@pytest.mark.parametrize("cmd", [
    "cat -f /etc/passwd",       # `-f` is not a cat flag at all -> don't guess, fail closed
    "cat -nf /etc/passwd",      # a bundle carrying an unknown letter
    "cat --files0-from=/etc/passwd",  # a real coreutils flag, but `wc`'s — not `cat`'s
    "cat -L/etc/ssh x",         # attached-value shape
])
def test_judge_cat_unknown_flag_denied(tmp_path, cmd):
    """any `-`-prefixed token that is not a known boolean bundle -> deny. `cat` has no arg-taking
    flag, so a token shaped like one means the stage grammar and the operand extractor disagree —
    and a disagreement between them is exactly the fail-open class this gate exists to prevent."""
    assert not _judge_gate(cmd, tmp_path).allow, cmd


@pytest.mark.parametrize("name", ["cases.json", "ground_truth.yaml", ".env", "credentials.txt"])
def test_judge_cat_denylisted_file_in_roots_denied(tmp_path, name):
    """a denylisted secret / ground-truth file that resolves INSIDE the judge's roots is denied in the
    bash lane too — parity with decide_read, so the judge can't `cat` the held-out answer key / a
    captured .env that read_file refuses. A non-denylisted sibling stays allowed (it's the name, not the dir)."""
    assert not _judge_gate(f"cat {tmp_path / name}", tmp_path).allow, name
    assert not _judge_gate(f"cat {tmp_path / name} | defender-sql 'SELECT 1'", tmp_path).allow, name
    assert _judge_gate(f"cat {tmp_path / 'payload.json'}", tmp_path).allow  # sibling, not denied


def test_judge_cat_traversal_denied(tmp_path):
    """a `..` escape out of an in-roots prefix -> deny. The operand gate resolve()s before matching,
    so the traversal collapses and lands outside the roots."""
    raw = tmp_path / "gather_raw"
    assert not _judge_gate(f"cat {raw}/../../../etc/passwd", tmp_path).allow


def test_judge_cat_comparison_dir_via_read_roots_allowed(tmp_path):
    """cat of a file under the judge's read_roots (its comparison dir) -> allow (read_roots widen)."""
    comp = tmp_path / "comparison"
    assert _judge_gate(f"cat {comp / 'x.md'}", tmp_path, read_roots=(comp,)).allow


# ============================================================================
# D. main/gather — the bash reader lane is now PER-RUN + anchored (#535)
#    (superseding this file's earlier "byte-for-byte unchanged" regression: the
#    anchored allow/deny matrix is comprehensively owned by test_read_confine_bash.py;
#    these pin the compile_policy_for wiring + that decide_read is unaffected.)
# ============================================================================

def test_gather_multiline_esql_denies_with_the_lexing_reason_not_the_adapter_one(tmp_path):
    """The case that motivates a dedicated reason, and it is NOT the judge's.

    ES|QL is line-oriented and the query templates render it as multi-line blocks, so
    gather must flatten it into one shell argument on every call. When it doesn't, the
    command is a perfectly legal standalone adapter invocation whose only defect is a
    newline inside its quoted query. Before the split-out reason, the gate answered with
    `GATHER_FALLTHROUGH_DENY_REASON` — "gather may only run a data-source adapter as a
    standalone command" — i.e. it blamed adapter policy for a tokenizer failure, telling
    the model the exact opposite of what it needed to know."""
    run = tmp_path / "run"
    dfn = _DEFENDER
    pol = compile_policy_for(GATHER_DEF, run_dir=run, defender_dir=dfn)
    multi = 'defender-elastic esql \'FROM logs-*\n| WHERE host == "db-1"\n| STATS n = count(*)\''
    flat = 'defender-elastic esql \'FROM logs-* | WHERE host == "db-1" | STATS n = count(*)\''

    denied = permission.decide_bash(multi, policy=pol, run_dir=run, defender_dir=dfn)
    assert not denied.allow
    assert denied.reason == permission.UNTOKENIZABLE_REASON
    assert denied.reason != pol.deny_reason  # not the misleading adapter-policy text
    # the same query on one line is a normal, allowed standalone adapter call
    assert permission.decide_bash(flat, policy=pol, run_dir=run, defender_dir=dfn).allow


def test_main_viewers_now_anchored(tmp_path):
    """#535: MAIN keeps a viewer allowlist, but its operands are now ANCHORED to the run dir +
    corpus — an IN-ROOT cat is allowed, an out-of-root cat is denied (was: any operand allowed).
    Not jq-operand-gated (jq is stdin-compute-only). Full matrix: test_read_confine_bash.py."""
    run, dfn = tmp_path / "run", tmp_path / "defender"
    run.mkdir()
    dfn.mkdir()
    main = compile_policy_for(MAIN_DEF, run_dir=run, defender_dir=dfn)
    assert main.bash_allow
    assert not main.operand_gated
    assert permission.decide_bash(f"cat {run}/investigation.md", policy=main).allow
    assert not permission.decide_bash("cat /tmp/x", policy=main).allow


def test_gather_stream_plumbing_anchored(tmp_path):
    """#535: GATHER's compute lane still works over IN-ROOT payloads — cat {run}/… | defender-sql,
    the standalone adapter, cat {run}/… | jq — but jq is stdin-only and an out-of-root /tmp operand
    is now denied (the demonstrated bypass this slice closes)."""
    run, dfn = tmp_path / "run", tmp_path / "defender"
    run.mkdir()
    dfn.mkdir()
    gather = compile_policy_for(GATHER_DEF, run_dir=run, defender_dir=dfn)
    raw = f"{run}/gather_raw/l/0.json"
    assert permission.decide_bash(
        f"cat {raw} | defender-sql 'SELECT count(*) FROM data'", policy=gather).allow
    assert permission.decide_bash("defender-elastic query 'x' --raw", policy=gather).allow
    assert permission.decide_bash(f"cat {raw} | jq '.hits|length'", policy=gather).allow
    assert not permission.decide_bash("jq '.hits|length' /tmp/p.json", policy=gather).allow


def test_empty_confine_preserves_existing_decide_read_rows(tmp_path):
    """the confine field is inert for main: decide_read still allows the corpus, denies outside, and
    clamps gather_raw. The corpus-readable probe is a tight-corpus `.md` (`skills/**.md`) — since
    #551 `compile_policy_for(MAIN_DEF)` carries the read↔bash `read_shapes`
    filter, so a bare `SKILL.md` directly under defender_dir (outside lessons/skills/examples) is
    now denied on the read tool exactly as the bash cat lane denies it (#545/#546 parity)."""
    run = tmp_path / "run"
    (run / "gather_raw" / "l").mkdir(parents=True)
    dfn = tmp_path / "defender"
    (dfn / "skills" / "elastic").mkdir(parents=True)
    main = compile_policy_for(MAIN_DEF, run_dir=run, defender_dir=dfn)
    assert permission.decide_read(dfn / "skills" / "elastic" / "SKILL.md", run_dir=run, defender_dir=dfn, policy=main).allow
    assert not permission.decide_read(dfn / "SKILL.md", run_dir=run, defender_dir=dfn, policy=main).allow  # non-tight corpus → denied (read_shapes)
    assert not permission.decide_read(Path("/etc/passwd"), run_dir=run, defender_dir=dfn, policy=main).allow
    assert not permission.decide_read(run / "gather_raw" / "l" / "0.json", run_dir=run, defender_dir=dfn, policy=main).allow
