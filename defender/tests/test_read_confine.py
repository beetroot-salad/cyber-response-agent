"""Spec for #512 slice 2 — per-agent read confinement across BOTH read surfaces.

The permission surface under test (#512 slice 2, as rebuilt on #575's one containment model):

  - AgentPolicy.read_confine: tuple[Path, ...] = ()   # REPLACES the defender_dir read base when non-empty
  - AgentPolicy.bash_allow: tuple[Grant, ...] = ()    # per-agent SHAPE (program+flags+arity) + SCOPE (resolved-path regexes)
  - decide_read: honour read_confine; FAIL CLOSED on a resolve() error
  - decide_bash(command, *, policy, run_dir=None, defender_dir=None): a command is allowed iff EVERY
    stage is claimed by a grant's shape AND everything `PROGRAMS[grant.program]` says it opens
    RESOLVES into that grant's scope.

What #575 changed under this spec, and why these tests still hold:

  - `operand_gated` is DELETED. It was the judge's special case — "this agent's `cat` operands are
    resolve()-gated rather than textually anchored" — and it is now the GENERAL rule: every `cat`
    grant, on every lane, resolves its operands and matches them against that grant's scope. The
    judge's lane is no longer exceptional, so it no longer needs a bit; the tests that pinned the
    behavior are unchanged, only the way the policy is built (`compile_policy_for(CORPUS_AUTHOR_DEF, …)`,
    the real seam, instead of two hand-imported regexes).
  - `raw_reads` is DELETED. Containment is positive enumeration now: an agent reaches gather_raw iff
    its grants carry that shape. For a confined actor the payload is not merely un-granted, it is not
    even under a read ROOT — which is the honest statement of the property the bit used to make.
  - the judge's `_CAT_PATTERN`/`_SQL_PATTERN` are gone; its lane is `_judge_bash_shapes`, reached
    through `compile_policy_for`. Building the policy from the REAL seam (never a hand-copied regex)
    is the point: a copy keeps passing against the old grammar after the real one is tightened.

These are pure unit tests (no model, no API key) — they drive permission.decide_read / decide_bash
directly. Builder wiring and the read-tool return contract live in test_read_confine_engine.py.

Locked design: malicious actor confined to {lessons-actor, lessons-environment} with NO bash readers
(empty `bash_allow`); benign actor to {lessons-environment} likewise; judge keeps ONLY `cat` (scoped
to its read roots) piped into the sandboxed `defender-sql`; main/gather keep the viewer lane. See
issues #512 / #522 / #575.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from defender.agents import GATHER_DEF, MAIN_DEF  # noqa: E402
from defender.learning.core import config  # noqa: E402
from defender.runtime import permission  # noqa: E402
from defender.runtime.agent_definition import (  # noqa: E402
    compile_policy_for,
    read_allow_of,
)
from defender.runtime.permission import AgentPolicy  # noqa: E402

_DEFENDER = config.REPO_ROOT / "defender"

#: A FAMILY OF DEMANDS LEFT THIS FILE WITH #922, recorded rather than deleted in silence.
#:
#: `test_judge_cat_*` (18 cases) drove the learning-side bash lane: `cat` over a run dir and
#: `cat <payload> | defender-sql '<SQL>'`, compiled off the pipeline judge's real seam. That
#: role is deleted and NO surviving role has that lane — the curator, the one learning role
#: that still holds `cat`, is granted it over its own corpus only and has no `defender-sql` at
#: all, which is its design rather than an oversight. Re-pointing the cases onto it would have
#: asserted grants nothing holds.
#:
#: What still witnesses the gate here: the MAIN and GATHER families below, which are runtime
#: roles and unaffected. What is no longer witnessed anywhere: the denylist and traversal
#: refusals AS THEY APPLY TO A LEARNING ROLE'S bash. Restore them when a learning role is next
#: granted a shell lane — that grant is the change that needs them, not this one.
#: TWO REAL DIRECTORIES UNDER `defender/`, used as confine members. They were the actor legs'
#: two lesson corpora until #922 deleted those legs; what the gate tests below need of them is
#: only that they exist, differ, and sit inside the defender dir — the property under test is
#: the CONFINE's, not any role's. Named for what they are here rather than for a role that no
#: longer binds them, so a reader is not sent looking for a leg that is gone.
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
    """An AgentPolicy for gate tests. Defaults model a confined, reader-less actor leg
    (empty `bash_allow` -> no bash readers at all). Override per case. `read_allow` stays empty:
    an agent with no `cat` grant has no path SHAPES, so `decide_read` is root-only for it —
    bounded by its confine/roots, which is exactly the actor's design."""
    return AgentPolicy(
        read_roots=read_roots, read_confine=read_confine, bash_allow=bash_allow,
    )



@pytest.mark.parametrize("path", [_CONFINE_A / "T1078.md", _CONFINE_B / "svc-monitoring.md"])
def test_malicious_reads_within_confine_allowed(tmp_path, path):
    """read under lessons-actor / lessons-environment (malicious confine) -> allow."""
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
    """benign leg: lessons-environment allowed; lessons-actor (tradecraft) AND rubric denied — the gray-box split."""
    pol = _policy(read_confine=_BENIGN_CONFINE)
    assert permission.decide_read(_CONFINE_B / "x.md", run_dir=tmp_path, defender_dir=_DEFENDER, policy=pol).allow
    assert not permission.decide_read(_CONFINE_A / "x.md", run_dir=tmp_path, defender_dir=_DEFENDER, policy=pol).allow
    assert not permission.decide_read(_OUTSIDE, run_dir=tmp_path, defender_dir=_DEFENDER, policy=pol).allow


def test_confine_replaces_defender_dir_but_run_dir_stays(tmp_path):
    """confine REPLACES the defender_dir base; run_dir remains a root (own artifacts still readable)."""
    pol = _policy(read_confine=_MALICIOUS_CONFINE)
    assert permission.decide_read(tmp_path / "actor_out.json", run_dir=tmp_path, defender_dir=_DEFENDER, policy=pol).allow
    assert not permission.decide_read(_DEFENDER / "SKILL.md", run_dir=tmp_path, defender_dir=_DEFENDER, policy=pol).allow


def test_empty_confine_is_legacy_defender_dir_base(tmp_path):
    """read_confine=() -> roots are exactly {run_dir, defender_dir}; a defender_dir read is allowed
    (byte-for-byte with today's judge, whose read_allow carries no corpus SHAPE filter). The field is
    inert when empty."""
    pol = _policy(read_confine=())
    assert permission.decide_read(_DEFENDER / "SKILL.md", run_dir=tmp_path, defender_dir=_DEFENDER, policy=pol).allow


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
    """the actor cannot read a gather_raw payload — pinned as CONTAINMENT, not as the deleted
    `raw_reads` bit (#575: the per-agent capability bits are gone; an agent reaches a path iff its
    grants/roots carry it). The payloads live under the INVESTIGATION run dir, which is not a root of
    the actor's policy at all: neither its confine (the two lesson corpora) nor its run dir (the
    LEARNING run dir) contains them, so the read denies at the roots gate.
    Positive control: the actor's own run-dir artifact IS readable — the deny is the payload's
    location, not a dead policy."""
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
    os.symlink(b, a)
    pol = _policy(read_confine=(conf,))
    assert not permission.decide_read(a, run_dir=tmp_path / "run", defender_dir=dfn, policy=pol).allow



@pytest.mark.parametrize("cmd", [
    "cat defender/lessons-actor/x.md",
    "grep foo defender/lessons-environment/y.md",
    "head -5 defender/lessons-actor/x.md",
    "tail -5 defender/lessons-actor/x.md",
    "ls defender/lessons-actor",
])
def test_actor_all_generic_readers_denied(cmd):
    """a confined actor (empty `bash_allow`) is denied EVERY generic bash reader — reads go through the tool.
    Even an IN-confine path is denied here: bash is simply not a read path for the actor. (Deny-by-default
    is the mechanism: with no grant, no stage is ever claimed.)"""
    assert not permission.decide_bash(cmd, policy=_policy(bash_allow=())).allow, cmd


def test_reduction_is_per_policy_not_global(tmp_path):
    """the reader reduction is per-policy, NOT a global removal: an actor policy with empty
    `bash_allow` denies every bash reader, while main's grants still permit an IN-SCOPE `cat` and the
    stdin-only viewers behind it. The narrowing lives in the policy, not the gate. (#575: `grep foo
    {file}` is dead for main too — grep lost its file operand — so the surviving reduction shape is
    `cat {file} | grep foo`; the full matrix is in test_read_confine_bash.py.)"""
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
    """`bash_exec.parse` lexes each PHYSICAL LINE on its own (an unquoted newline is a
    command separator), so it does not model bash's line-JOINING: both shapes leave line 1
    unbalanced and fail closed. That is deliberate — but the deny must SAY so. The generic
    `policy.deny_reason` reads as "this program is forbidden", which sends the model
    hunting for another one when its command was fine and only its line breaks were not."""
    # ANY compiled policy answers this: the refusal happens in the LEXER, before a program or
    # a path is looked at, so the demand is policy-independent. It used to ride on the deleted
    # judge's gate purely because that helper was to hand; MAIN's is the one that ships.
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





















def test_gather_multiline_command_denies_with_the_lexing_reason_not_a_policy_one(tmp_path):
    """The case that motivates a dedicated reason, and it is NOT the judge's.

    SQL/ES|QL is line-oriented and the query templates render it as multi-line blocks, so gather
    must flatten it into one shell argument on every call. When it doesn't, the command may be an
    otherwise-allowed invocation whose only defect is a newline inside its quoted query — and a
    POLICY reason ("reach a data source with the `query` tool", "adapters are not runnable from
    bash") would blame policy for a tokenizer failure, telling the model the exact opposite of what
    it needed to know. So a lexing failure must be diagnosed BEFORE any classification of the
    command's shape.

    #611: the motivating command used to be a standalone `defender-elastic esql …` (which was
    allowed when flat). That form is now unreachable from bash, so the probe is gather's surviving
    multi-line-prone command — a `cat <payload> | defender-sql '<SQL>'` aggregation — plus an
    adapter-shaped multi-liner, which must ALSO lex-deny rather than get the adapter reason (the
    over-tightening this test exists to catch would now hand back `ADAPTER_RETIRED_REASON`)."""
    run = tmp_path / "run"
    dfn = _DEFENDER
    pol = compile_policy_for(GATHER_DEF, run_dir=run, defender_dir=dfn)
    raw = f"{run}/gather_raw/l-001/0.json"
    multi = f"cat {raw} | defender-sql 'SELECT host,\ncount(*)\nFROM data GROUP BY host'"
    flat = f"cat {raw} | defender-sql 'SELECT host, count(*) FROM data GROUP BY host'"

    denied = permission.decide_bash(multi, policy=pol, run_dir=run, defender_dir=dfn)
    assert not denied.allow
    assert denied.reason == permission.UNTOKENIZABLE_REASON
    assert denied.reason != pol.deny_reason
    assert permission.decide_bash(flat, policy=pol, run_dir=run, defender_dir=dfn).allow

    adapter_multi = 'defender-elastic esql \'FROM logs-*\n| WHERE host == "db-1"\''
    d = permission.decide_bash(adapter_multi, policy=pol, run_dir=run, defender_dir=dfn)
    assert not d.allow
    assert d.reason == permission.UNTOKENIZABLE_REASON
    assert d.reason != permission.ADAPTER_RETIRED_REASON


def test_main_cat_scope_is_the_read_surface(tmp_path):
    """MAIN keeps a viewer lane, and its `cat` grant's SCOPE is the run dir + corpus over the RESOLVED
    path — an in-scope cat is allowed, an out-of-scope cat is denied (pre-#535: any operand allowed).
    `operand_gated` is gone: every cat grant is scope-checked, so there is no bit to assert. What
    replaces it is the identity that made the bit unnecessary — `read_allow` IS the cat grant's scope
    OBJECT, so the read tool and the bash lane cannot drift. Full matrix: test_read_confine_bash.py."""
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
    """GATHER's compute lane still works over IN-SCOPE payloads — cat {run}/… | defender-sql,
    cat {run}/… | jq — but jq is stdin-only and an out-of-scope /tmp operand is denied (the bypass
    #535 closed, now enforced against the RESOLVED path). Note the payload path must match the
    machine-tight gather_raw shape (`gather_raw/l-<digits>/<seq>.json`).

    #611: the standalone adapter left this lane (it is the `query` tool's job now), so the plumbing
    pinned here is what REMAINS — local computation over a payload already on disk — and the adapter
    is asserted DENIED, which is the same anchoring statement with the verdict flipped."""
    run, dfn = tmp_path / "run", tmp_path / "defender"
    run.mkdir()
    dfn.mkdir()
    gather = compile_policy_for(GATHER_DEF, run_dir=run, defender_dir=dfn)

    def bash(cmd):
        return permission.decide_bash(cmd, policy=gather, run_dir=run, defender_dir=dfn)

    raw = f"{run}/gather_raw/l-001/0.json"
    assert bash(f"cat {raw} | defender-sql 'SELECT count(*) FROM data'").allow
    assert not bash("defender-elastic query 'x'").allow
    assert bash(f"cat {raw} | wc -c").allow
    assert not bash("cat /tmp/p.json | wc -c").allow
    assert not bash(f"cat {run}/gather_raw/evil.json").allow


def test_empty_confine_preserves_existing_decide_read_rows(tmp_path):
    """the confine field is inert for main: decide_read still allows the corpus, denies outside, and
    denies the raw payload. The corpus-readable probe is a tight-corpus `.md` (`skills/**.md`) — the
    policy's `read_allow` IS the cat grant's scope (#575), so a bare `SKILL.md` directly under
    defender_dir (outside lessons/skills/examples) is denied on the read tool exactly as the bash cat
    lane denies it (#545/#546 parity, now by construction)."""
    run = tmp_path / "run"
    (run / "gather_raw" / "l-001").mkdir(parents=True)
    dfn = tmp_path / "defender"
    (dfn / "skills" / "elastic").mkdir(parents=True)
    main = compile_policy_for(MAIN_DEF, run_dir=run, defender_dir=dfn)
    assert permission.decide_read(dfn / "skills" / "elastic" / "SKILL.md", run_dir=run, defender_dir=dfn, policy=main).allow
    assert not permission.decide_read(dfn / "SKILL.md", run_dir=run, defender_dir=dfn, policy=main).allow
    assert not permission.decide_read(Path("/etc/passwd"), run_dir=run, defender_dir=dfn, policy=main).allow
    assert not permission.decide_read(run / "gather_raw" / "l-001" / "0.json", run_dir=run, defender_dir=dfn, policy=main).allow
