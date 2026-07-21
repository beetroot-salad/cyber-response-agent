"""#535/#575 — the gather+main bash reader lane confines file operands to {run_dir, corpus}.

Spec for the confined-read migration, rewritten onto #575's one containment model.

  - #535 moved gather/main from a program-only bash allowlist (`^cat(?: .*)?$`, ANY operand) to a
    per-run regex allowlist whose file operands were ANCHORED to the run dir + corpus, closing a
    demonstrated bypass (`decide_bash("cat /etc/passwd", policy=…GATHER…).allow` was True).
  - #575 replaced the ANCHOR with a `Grant`: a SHAPE (program + flags + arity, no paths) plus a
    SCOPE (anchored regexes over the **RESOLVED** path of everything the program opens). The
    confinement property is the same; it is now enforced against the path the OS will open rather
    than the text the model typed. Three consequences run through this file:

      1. `grep`/`head`/`tail`/`wc`/`jq` LOST their file operand — they are stdin-only pipe stages.
         `grep -n s {run}/x.md` DENIES; `cat {run}/x.md | grep -n s` ALLOWS. Same capability, one
         extra `cat |`, and `cat` becomes the SOLE opener (one extractor, one scope check).
      2. `ls` and `cd` are GONE from the lane entirely. `ls`'s anchored DIR operand was the other
         path-opening slot, and dropping it leaves the whole surface with NO recursive-descent
         primitive: to reach a path you must NAME it, and a named path is a resolved path is a
         scope check.
      3. the symlink RESIDUAL this file used to document as un-closable IS NOW CLOSED (§H): the
         lane resolve()s, so an in-shape symlink pointing out of the run dir lands outside every
         scope and denies.

Entry points under test:
  - `compile_policy_for(<DEF>, run_dir, *, defender_dir)` — the policy-only half of `bind`; RAISES
    on a missing run_dir / degenerate root (safe-by-construction: no unconfined fallback).
  - `decide_bash(command, *, policy, run_dir, defender_dir) -> BashDecision`
    (.allow / .reason; since #611 there are no `.adapter_argv` / `.sql_pipe` routing fields — a
    data source is reached through the `query` tool, not from bash). `defender_dir` is load-bearing
    now: a RELATIVE operand is rebased on the executor's cwd (`defender_dir.parent`) before it
    resolves.

The gate RESOLVES operands (it still never stats them — `resolve(strict=False)`), so the roots here
are real tmp dirs and commands interpolate their ABSOLUTE paths.
"""
from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("pydantic_ai")  # CI installs the runtime extra; skip otherwise

from defender.agents import GATHER_DEF, MAIN_DEF  # noqa: E402
from defender.runtime import permission  # noqa: E402
from defender.runtime.agent_definition import compile_policy_for  # noqa: E402


# --------------------------------------------------------------------------- #
# Fixtures: a per-run run dir + corpus, and the two per-run policies built off  #
# them. The dirs are real because both surfaces resolve() their operands.       #
# --------------------------------------------------------------------------- #
@pytest.fixture
def env(tmp_path):
    run = tmp_path / "run"
    (run / "gather_raw" / "l-001").mkdir(parents=True)
    (run / "gather_summaries").mkdir()
    dfn = tmp_path / "defender"
    (dfn / "lessons").mkdir(parents=True)
    (dfn / "skills" / "elastic").mkdir(parents=True)
    (dfn / "skills" / "gather" / "queries" / "elastic").mkdir(parents=True)
    (dfn / "examples").mkdir()
    (dfn / "fixtures" / "held-out" / "m01").mkdir(parents=True)
    main = compile_policy_for(MAIN_DEF, run_dir=run, defender_dir=dfn)
    gather = compile_policy_for(GATHER_DEF, run_dir=run, defender_dir=dfn)
    return SimpleNamespace(run=run, dfn=dfn, main=main, gather=gather)


def _bash(env, cmd, which="gather"):
    pol = env.gather if which == "gather" else env.main
    return permission.decide_bash(cmd, policy=pol, run_dir=env.run, defender_dir=env.dfn)


def _read(env, path, which="gather"):
    pol = env.gather if which == "gather" else env.main
    return permission.decide_read(Path(path), run_dir=env.run, defender_dir=env.dfn, policy=pol)


# ===========================================================================  #
# A. Safe-by-construction: the compile seam cannot build an unconfined policy    #
# ===========================================================================  #

def test_compile_policy_for_requires_run_dir():
    """compile_policy_for(GATHER_DEF) with NO run_dir RAISES → the confined reader policy can't
    be built in an unconfined state (run_dir is a required positional, no silent fallback)."""
    # rejected: return a permissive default policy (re-opens the cat /etc/passwd bypass)
    with pytest.raises((TypeError, ValueError)):
        compile_policy_for(GATHER_DEF)


def test_compile_policy_for_rejects_degenerate_roots(tmp_path):
    """An empty-string / '/' root — run_dir OR an explicit defender_dir — must RAISE, not anchor
    the grant scopes to the CWD / filesystem root (which would allow reading anything). The shared
    `require_anchor_root` guard rejects both.

    (Unlike the retired `policy_for`, `compile_policy_for`'s `defender_dir` legitimately DEFAULTS
    to the PATHS checkout when omitted — a real confined tree, not unconfined — so an OMITTED
    defender_dir is allowed; only a degenerate EXPLICIT root is rejected.)"""
    # rejected: accept '' or '/' and produce a root-anchored (=everything) policy
    for bad in ("", "/"):
        with pytest.raises((TypeError, ValueError)):
            compile_policy_for(GATHER_DEF, run_dir=Path(bad), defender_dir=tmp_path)
        with pytest.raises((TypeError, ValueError)):
            compile_policy_for(MAIN_DEF, run_dir=tmp_path, defender_dir=Path(bad))


# ===========================================================================  #
# B. In-scope reads ALLOW (positive controls — the reads real runs actually make)#
# ===========================================================================  #

def test_cat_run_investigation_allowed(env):
    """cat {RUN}/investigation.md → ALLOW: the agent's own case log, absolute, under the run dir."""
    assert _bash(env, f"cat {env.run}/investigation.md", "main").allow
    assert _bash(env, f"cat {env.run}/investigation.md", "gather").allow


def test_cat_run_gather_summary_allowed(env):
    """cat {RUN}/gather_summaries/l-001.md → ALLOW: the per-lead summary (built inline at
    tools_gather.py, NOT a RunPaths prop — the scope must still cover it).

    Read on the MAIN lane on purpose: the summary is main's sanctioned view of a lead's data
    (the raw payload is gather's), and it is a shape main's grants carry."""
    assert _bash(env, f"cat {env.run}/gather_summaries/l-001.md", "main").allow


def test_cat_run_executed_queries_allowed(env):
    """cat {RUN}/executed_queries.jsonl → ALLOW: a run-dir artifact (RunPaths.executed_queries)."""
    assert _bash(env, f"cat {env.run}/executed_queries.jsonl", "main").allow


def test_tail_wc_grep_over_investigation_allowed_as_pipe_stages(env):
    """The real read/format shapes from run traces, in their #575 form: the viewers have NO file
    slot, so `cat` opens the file and the reduction happens on STDIN. The FILE forms of the same
    three commands are the deny half of the c1 ledger (test_viewer_file_operand_denied below);
    these are the surviving capability — identical, one extra `cat |`."""
    for cmd in (f"cat {env.run}/investigation.md | tail -5",
                f"cat {env.run}/investigation.md | wc -l",
                f'cat {env.run}/investigation.md | grep -n "T resolutions"'):
        assert _bash(env, cmd, "main").allow, cmd


def test_cat_corpus_lesson_allowed(env):
    """cat {DFN}/lessons/<slug>.md → ALLOW: a lessons-corpus read (absolute, .md under lessons/)."""
    assert _bash(env, f"cat {env.dfn}/lessons/auth-log-scope.md", "main").allow


def test_cat_multi_lesson_allowed(env):
    """cat {DFN}/lessons/a.md {DFN}/lessons/b.md 2>/dev/null → ALLOW: the real multi-file lesson cat
    (multiple in-scope operands + benign stderr discard). EVERY operand is resolved and scope-checked,
    not just the first."""
    cmd = (f"cat {env.dfn}/lessons/a.md {env.dfn}/lessons/b.md 2>/dev/null")
    assert _bash(env, cmd, "main").allow


def test_cat_corpus_skill_and_query_template_allowed(env):
    """cat {DFN}/skills/<sys>/SKILL.md and a query template → ALLOW: enumerated corpus .md shapes."""
    assert _bash(env, f"cat {env.dfn}/skills/elastic/SKILL.md", "gather").allow
    assert _bash(env, f"cat {env.dfn}/skills/gather/queries/elastic/x.md", "gather").allow


def test_gather_reads_its_own_gather_raw_absolute(env):
    """cat {RUN}/gather_raw/l-001/1.json → ALLOW for gather: the machine-tight payload shape
    (`gather_raw/l-<digits>/<seq>.json`) is in GATHER's grants — and in nobody else's."""
    assert _bash(env, f"cat {env.run}/gather_raw/l-001/1.json", "gather").allow


# ===========================================================================  #
# C. Out-of-scope reads DENY (guarded negatives, each with a positive control)  #
# ===========================================================================  #

def test_cat_etc_passwd_denied_both(env):
    """cat /etc/passwd → DENY (both agents): the demonstrated bypass #535 closed.
    Positive control: cat {RUN}/investigation.md (same program, in-scope) is allowed."""
    assert not _bash(env, "cat /etc/passwd", "gather").allow
    assert not _bash(env, "cat /etc/passwd", "main").allow
    assert _bash(env, f"cat {env.run}/investigation.md", "gather").allow  # positive control


def test_out_of_scope_file_denied_through_a_pipe(env):
    """The out-of-root read cannot be laundered through the pipe lane either: `cat /etc/passwd |
    grep root` DENIES on the cat stage's SCOPE (grep opens nothing, so it is not what saves us).
    Positive control: the same pipe over an in-scope file is allowed."""
    assert not _bash(env, "cat /etc/passwd | grep root", "gather").allow
    assert _bash(env, f"cat {env.run}/investigation.md | grep root", "gather").allow


def test_cat_traversal_out_of_prefix_denied(env):
    """cat {RUN}/../outside.txt → DENY: `..` collapses at resolve() and the result lands outside
    every scope shape. (#535 rejected `..` TEXTUALLY because the lane did not resolve; #575 resolves,
    so the traversal is closed by the same check that closes symlinks — one mechanism, not two.)
    Positive control: cat {RUN}/report.md (no traversal) is allowed."""
    assert not _bash(env, f"cat {env.run}/../outside.txt", "gather").allow
    assert _bash(env, f"cat {env.run}/report.md", "gather").allow  # positive control


def test_cat_in_prefix_traversal_escape_denied(env):
    """cat {RUN}/gather_raw/../../../etc/passwd → DENY: starts with the run-dir prefix (would pass a
    naive startswith) but the `..` segments tunnel out — resolve() collapses them to /etc/passwd."""
    assert not _bash(env, f"cat {env.run}/gather_raw/../../../etc/passwd", "gather").allow


def test_second_operand_escape_denied(env):
    """cat {RUN}/investigation.md /etc/passwd → DENY: the FIRST operand is in-scope but the SECOND
    escapes — every operand the extractor reports is scope-checked, not just the first.
    Positive control: cat {RUN}/investigation.md {RUN}/report.md (both in-scope) is allowed."""
    assert not _bash(env, f"cat {env.run}/investigation.md /etc/passwd", "gather").allow
    assert _bash(env, f"cat {env.run}/investigation.md {env.run}/report.md", "gather").allow


def test_corpus_lookalike_sibling_denied(env):
    """cat {DFN}-evil/x.md → DENY: a sibling dir sharing the corpus PREFIX but not under it must
    not match — `under()` closes the root with a `/` boundary, so the anchor is a path boundary,
    not a string prefix."""
    assert not _bash(env, f"cat {env.dfn}-evil/x.md", "gather").allow


# ===========================================================================  #
# D. File-opening FLAGS — the escape a clean trailing operand hides             #
#    (`OPENS_NOTHING` is a CLAIM the SHAPE must earn: the gate skips the scope   #
#     check for those programs, so any flag that opens a file is a fail-open)    #
# ===========================================================================  #

def test_grep_dash_f_patternfile_escapes(env):
    """grep -f /etc/passwd → DENY: `-f` opens the out-of-root PATTERN file. grep is `OPENS_NOTHING`,
    so NOTHING scope-checks that file — the shape's positive flag allowlist is the only thing
    standing between it and the read, which is why `-f` is not in it.
    Positive control: the flagless stdin form is allowed."""
    # rejected: gate only the trailing operand (misses -f's file) — and there IS no trailing operand now
    assert not _bash(env, f"grep -f /etc/passwd {env.run}/investigation.md", "gather").allow
    assert not _bash(env, "grep -f /etc/passwd x", "gather").allow
    assert _bash(env, f"cat {env.run}/investigation.md | grep root", "gather").allow  # positive control


def test_grep_dash_e_promotes_positional_to_file(env):
    """grep -e root /etc/shadow → DENY: `-e` fills the pattern slot so /etc/shadow becomes a FILE
    operand. Doubly denied now (grep has no file slot at all, and `-e` is an arg-taker excluded from
    the flag allowlist) — the belt and the suspenders are both pinned."""
    # rejected: model grep as always pattern+files positionally (ignores -e)
    assert not _bash(env, "grep -e root /etc/shadow", "gather").allow


def test_grep_recursive_denied(env):
    """grep -r/-R → DENY: recursion walks a dir (and follows symlinks out of root), reading files no
    operand ever named — the one primitive that reaches a subtree WITHOUT naming it, which is exactly
    what positive-enumeration containment must not hand back (an in-root dir operand on purpose: a
    `grep -r secret /etc` would deny on the operand no matter what the flag class does, so it cannot
    see a regression that admits `r`/`R`).
    Positive control: the same search as a stdin stage is allowed."""
    # rejected: allow -r/-R over an in-root dir (recursive walk / symlink follow escapes containment)
    assert not _bash(env, f"grep -r secret {env.run}/gather_raw", "gather").allow
    assert not _bash(env, f"grep -R secret {env.run}/gather_raw", "gather").allow
    assert not _bash(env, "grep -r secret /etc", "gather").allow
    assert _bash(env, f"cat {env.run}/investigation.md | grep secret", "gather").allow  # control


def test_grep_recursive_single_operand_denied(env):
    """grep -r <pattern> → DENY. The SINGLE-operand form: `-r` is (correctly) excluded from the flag
    class, but without the `(?!-)` guard on the free-text PATTERN slot it is RE-ABSORBED there — the
    argv matches and runs as `grep -r <pattern>` = `-r` flag + pattern + NO operand, which walks the
    CWD (the repo root), reading every file under it including denylisted ones (#579). Positive
    control: a real leading-dash-free pattern on the stdin lane."""
    # rejected: `VALUE = r"[^ ]+"` (a leading-dash pattern slot re-absorbs the rejected -r)
    for which in ("main", "gather"):
        assert not _bash(env, f"grep -r {env.run}/investigation.md", which).allow, which
        assert not _bash(env, f"grep -R {env.run}/investigation.md", which).allow, which
        assert not _bash(env, f"grep -rn {env.run}/investigation.md", which).allow, which
        assert not _bash(env, "grep -r secret", which).allow, which
        assert _bash(env, f"cat {env.run}/investigation.md | grep -n secret", which).allow, which


def test_tail_head_have_no_file_slot_and_no_arg_taking_flag(env):
    """tail/head keep their COUNT flags (`-n`/`-c`, fused `-5`) and lose their file operand (#575).

    Pre-#575 the operand was ANCHORED, and `-n`'s arg-consumption was safe only because the token it
    ate still had to match the anchored operand slot. With no file slot at all, the argument is
    simply not there to smuggle: `tail -n /etc/passwd` denies because /etc/passwd matches no slot in
    the shape, not because of an anchor that can be edited away. `-f`/`-F` (follow) stay DENIED for a
    liveness reason — a follow never returns, so the stage burns the executor's whole timeout budget
    — and `-s SECS` is out as an arg-taker.
    Positive controls: the count forms on the stdin lane, which is where they now live."""
    for which in ("main", "gather"):
        assert not _bash(env, "tail -n /etc/passwd", which).allow, which
        assert not _bash(env, "head -c /etc/shadow", which).allow, which
        assert not _bash(env, f"tail -5 {env.run}/investigation.md", which).allow, which  # file slot: gone
        assert not _bash(env, f"tail -f {env.run}/investigation.md", which).allow, which
        assert not _bash(env, f"tail -F {env.run}/investigation.md", which).allow, which
        assert not _bash(env, f"tail -s 5 {env.run}/investigation.md", which).allow, which
        inv = f"cat {env.run}/investigation.md"
        assert _bash(env, f"{inv} | tail -5", which).allow, which        # control
        assert _bash(env, f"{inv} | head -5", which).allow, which        # control
        assert _bash(env, f"{inv} | tail -n 20", which).allow, which     # control
        assert _bash(env, f"{inv} | head -c 100", which).allow, which    # control


# The c1 ledger — viewers lose their file-operand slot, the `cat … |` form still allows —
# is pinned once, on a fully in-scope path, at
# test_grant_gate_575.py::test_c1_file_operand_viewers_lose_their_file_slot. The copy that
# lived here was byte-identical to it (same four parameter pairs, same operand, same
# main/gather loop) against an equivalent `env`, so it could not fail alone.


def test_grep_free_text_pattern_is_not_a_path(env):
    """cat {RUN}/investigation.md | grep "/home/x/.ssh/authorized_keys" → ALLOW: the path-LOOKING
    token is the search PATTERN, not a file. Only what a program OPENS is scope-checked (`cat`'s
    operands), so a token that merely looks like an out-of-root path — even one carrying a denylisted
    `.ssh` component — must not be denied. The real trace shape, and the honest statement of what
    "resolve the operand" buys over "scan the command text"."""
    # rejected: deny because a token looks like an out-of-root path (over-anchors the pattern)
    assert _bash(env, f'cat {env.run}/investigation.md | grep "/home/x/.ssh/authorized_keys"', "main").allow


def test_wc_files0_from_escapes(env):
    """wc --files0-from=/etc/passwd → DENY: it opens the named file AND every path inside it, a
    two-hop out-of-root read. `wc` is `OPENS_NOTHING`, so the shape's flag allowlist (short boolean
    bundles only — no `--long` option anywhere) is the sole thing that denies it."""
    # rejected: leave --files0-from ungated
    assert not _bash(env, "wc --files0-from=/etc/passwd", "gather").allow
    assert not _bash(env, f"cat {env.run}/report.md | wc --files0-from=/etc/passwd", "gather").allow





def test_stdin_consuming_viewers_in_pipe_allowed(env):
    """`<in-scope cat | shim> | grep/wc/head/tail/cat` → ALLOW: a downstream viewer reads STDIN and
    names no file operand, so `cat`'s operand grammar must be OPTIONAL (a bare `cat` / `cat -` in a
    pipe is inert) and the viewers' shapes must admit a flags-only argv. These are the in-scope
    read/filter idioms every run uses; they are ALL of the viewers' capability now."""
    # rejected: require >=1 operand on cat (denying every stdin-consuming pipe stage)
    for cmd in (f"cat {env.run}/investigation.md | grep -n resolved",
                f"cat {env.run}/investigation.md | tail -50 | grep err",
                f"cat {env.run}/investigation.md | grep foo | head -5",
                f"cat {env.run}/investigation.md | wc -l",
                "defender-lessons --tags | grep auth",
                "defender-lessons --tags | wc -l",
                f"cat {env.run}/investigation.md | cat -",
                f"cat {env.run}/investigation.md | tail -5"):
        assert _bash(env, cmd, "gather").allow, cmd
        assert _bash(env, cmd, "main").allow, cmd


def test_stdin_viewer_second_stage_still_gated(env):
    """A downstream stage cannot smuggle a file back in: `… | grep foo /etc/passwd` and
    `… | wc -l /etc/passwd` DENY at the SHAPE (the viewers have no file slot — an in-scope path
    would deny there too), and `… | cat /etc/passwd` DENIES at the SCOPE (cat does have a slot, and
    every stage is scope-checked against the grant that claimed IT)."""
    assert not _bash(env, f"cat {env.run}/investigation.md | grep foo /etc/passwd", "gather").allow
    assert not _bash(env, f"cat {env.run}/investigation.md | cat /etc/passwd", "gather").allow
    assert not _bash(env, f"cat {env.run}/investigation.md | wc -l /etc/passwd", "gather").allow


# ===========================================================================  #
# E. Cross-surface PARITY: the read tool and the bash lane share ONE object     #
# ===========================================================================  #

def test_read_allow_is_the_cat_grants_scope(env):
    """The parity MECHANISM, not just its symptom: `policy.read_allow` IS the `cat` grant's `scope` —
    the same tuple OBJECT (#575), so the read tool admits exactly the paths `cat` does and there is
    nothing to keep in sync. #545's two grammars (one for each surface, built from one source) drifted;
    one object cannot. The rows below are the symptom."""
    for pol in (env.main, env.gather):
        (cat_grant,) = [g for g in pol.bash_allow if g.program == "cat"]
        assert pol.read_allow is cat_grant.scope


def test_parity_out_of_root(env):
    """/etc/passwd: decide_read DENIES and decide_bash("cat …") DENIES — the two read surfaces agree.
    Positive control: {RUN}/investigation.md is allowed on BOTH."""
    assert not _read(env, "/etc/passwd", "gather").allow
    assert not _bash(env, "cat /etc/passwd", "gather").allow
    assert _read(env, f"{env.run}/investigation.md", "gather").allow          # positive control
    assert _bash(env, f"cat {env.run}/investigation.md", "gather").allow      # positive control


def test_parity_ground_truth_inside_corpus(env):
    """{DFN}/fixtures/held-out/m01/ground_truth.yaml lives INSIDE defender_dir; decide_read denies it
    and the bash lane must too. (Doubly denied: it is outside the tight corpus `.md` shape AND its
    basename hits the denylist — the shape half is what the `.md`-named probe below removes.)
    Positive control: a lessons .md is allowed on both."""
    gt = f"{env.dfn}/fixtures/held-out/m01/ground_truth.yaml"
    assert not _read(env, gt, "gather").allow
    assert not _bash(env, f"cat {gt}", "gather").allow
    assert _bash(env, f"cat {env.dfn}/lessons/ok.md", "gather").allow  # positive control


def test_parity_captured_env_in_run_dir(env):
    """A captured .env at the top of the run dir: it is IN-SHAPE (`under(run, SEG)` admits any
    run-dir file), so the secret denylist is the ONLY thing that can deny it — and it denies on BOTH
    surfaces. An in-scope operand is necessary, not sufficient."""
    dotenv = f"{env.run}/.env"
    assert not _read(env, dotenv, "gather").allow
    assert not _bash(env, f"cat {dotenv}", "gather").allow


def test_parity_ssh_dir_component(env):
    """The denylist's path-COMPONENT axis (`.ssh`), probed where only it can decide: `{DFN}/lessons/
    .ssh/key.md` matches the tight corpus `.md` shape (`.ssh` is a legal path segment), so the shape
    gate admits it and the component denylist is what denies it — on both surfaces. A `{RUN}/.ssh/…`
    probe would deny at the SHAPE (the run-dir shape is one segment deep) and prove nothing about the
    denylist. Positive control: the same shape with no denied component is allowed on both."""
    p = f"{env.dfn}/lessons/.ssh/key.md"
    assert not _read(env, p, "gather").allow
    assert not _bash(env, f"cat {p}", "gather").allow
    assert _read(env, f"{env.dfn}/lessons/auth/key.md", "gather").allow      # positive control
    assert _bash(env, f"cat {env.dfn}/lessons/auth/key.md", "gather").allow  # positive control


def test_parity_corpus_non_listed_denied_on_both_lanes(env):
    """Read↔bash PARITY on a non-listed corpus file (#545/#546): a corpus file NOT under the tight
    lessons/skills/examples/**.md grammar ({DFN}/docs/x.md) is DENIED on BOTH the read tool and the
    bash cat lane. The pre-#546 'read broad, bash tight' asymmetry is CLOSED — and since #575 it is
    closed BY CONSTRUCTION (one object), not by two grammars that agree today. Positive control: a
    tight-corpus lessons/**.md is allowed on both."""
    docs = f"{env.dfn}/docs/learning-loop.md"
    assert not _read(env, docs, "gather").allow
    assert not _bash(env, f"cat {docs}", "gather").allow
    ok = f"{env.dfn}/lessons/notes.md"
    assert _read(env, ok, "gather").allow
    assert _bash(env, f"cat {ok}", "gather").allow


def test_corpus_md_named_secret_denied(env):
    """A `.md`-named secret UNDER a corpus subdir — `{DFN}/lessons/credentials.md` — passes the corpus
    `.md` SHAPE gate, so the basename-substring denylist is the ONLY thing that can deny it. Unlike
    the `ground_truth.yaml`/`.env` cases (which the shape gate denies first), this exercises the
    basename axis in isolation on BOTH surfaces.
    Positive control: `{DFN}/lessons/notes.md` (same subdir, benign name) is allowed on both."""
    # rejected: drop the basename-substring axis (a `credentials.md`/`.env.md` in-corpus leaks)
    for secret in (f"{env.dfn}/lessons/credentials.md",
                   f"{env.dfn}/skills/elastic/ground_truth.md",
                   f"{env.dfn}/lessons/x.env.md"):
        assert not _bash(env, f"cat {secret}", "gather").allow, secret
        assert not _read(env, secret, "gather").allow, secret
    assert _bash(env, f"cat {env.dfn}/lessons/notes.md", "gather").allow  # positive control


@pytest.mark.parametrize("axis", ["substring", "dir"])
def test_denylist_parity_bash_matches_decide_read(env, axis):
    """For every configured denylist entry, an OTHERWISE-IN-SCOPE operand carrying it denies on BOTH
    the bash lane and decide_read. Both probes are chosen to be in-shape (a run-dir file at depth 1;
    a corpus `.md` under a denied dir component) so the denylist — not the enumeration — is what
    decides. Iterating the LIVE denylist (not a hardcoded sample) is what keeps a new entry in
    bash_policy.json honored on both surfaces: since #575 both call the same `files.denylisted`, and
    this pins that they still do."""
    from defender.runtime import bash_policy
    if axis == "substring":
        for sub in bash_policy.read_deny_substrings():
            p = f"{env.run}/{sub}xyz"                     # denied substring in an in-shape basename
            assert not _bash(env, f"cat {p}", "gather").allow, p
            assert not _read(env, p, "gather").allow, p
    else:
        for d in bash_policy.read_deny_dirs():
            p = f"{env.dfn}/lessons/{d}/inner.md"         # denied dir as an in-shape path component
            assert not _bash(env, f"cat {p}", "gather").allow, p
            assert not _read(env, p, "gather").allow, p


def test_empty_denylist_cannot_brick_the_reader_lane(env, monkeypatch):
    """The empty-denylist footgun, closed BY CONSTRUCTION. Pre-#575 the denylist was compiled INTO the
    reader regexes as a negative lookahead, so an emptied `read_deny` config produced an empty `(?:)`
    alternation that matches everywhere and flipped the lookahead to DENY every operand — a config
    change that silently bricks the lane. Now the denylist is a resolve()-time SUBTRACTION
    (`files.denylisted`) and no path shape carries a lookahead at all, so emptying it can subtract
    nothing and brick nothing.

    Asserted both ways: structurally (no scope/read shape contains `(?!`) and end-to-end (with the
    denylist emptied, an in-scope read still ALLOWs — and the `.env` it used to deny is now admitted,
    which is what proves the emptied config is the thing being exercised)."""
    from defender.runtime import bash_policy
    for pol in (env.main, env.gather):
        for shape in [s for g in pol.bash_allow for s in g.scope] + list(pol.read_allow):
            assert "(?!" not in shape.pattern, shape.pattern
    monkeypatch.setattr(bash_policy, "read_deny_substrings", lambda: ())  # lint-monkeypatch: ok — force the degenerate empty-denylist config
    monkeypatch.setattr(bash_policy, "read_deny_dirs", lambda: ())  # lint-monkeypatch: ok — force the degenerate empty-denylist config
    assert _bash(env, f"cat {env.run}/investigation.md", "gather").allow   # not bricked
    assert _bash(env, f"cat {env.run}/.env", "gather").allow               # the axis really is empty


# ===========================================================================  #
# F. gather_raw: POSITIVE ENUMERATION replaces the raw clamp                    #
# ===========================================================================  #

def test_raw_payload_is_gathers_shape_and_not_mains(env):
    """cat {RUN}/gather_raw/l-001/1.json: DENY for main, ALLOW for gather — same program, same
    extractor, same resolved operand. Main is not "clamped off" gather_raw by a `RAW_MARKER in cmd`
    substring scan (deleted): the gather_raw SHAPE is simply not in main's grants, so it never had
    the address. The read tool agrees (it enforces the same object) and keeps the gather_raw-specific
    deny REASON, which the e2e deny-tail asserts as a substring."""
    raw = f"{env.run}/gather_raw/l-001/1.json"
    assert not _bash(env, f"cat {raw}", "main").allow
    assert _bash(env, f"cat {raw}", "gather").allow
    d_read = _read(env, raw, "main")
    assert not d_read.allow
    assert "gather_raw" in (d_read.reason or "")


def test_gather_raw_as_a_grep_pattern_is_not_a_read(env):
    """cat {RUN}/report.md | grep gather_raw (main) → ALLOW. It DENIED before #575: the raw clamp was
    a substring scan over the unparsed command TEXT, so it over-fired whenever `gather_raw` appeared
    as a grep PATTERN rather than a path. Containment is now decided by what the command OPENS (an
    in-scope report.md; grep opens nothing), so text that merely mentions the word decides nothing.
    Positive control — the property that must NOT regress: main still cannot open the payload."""
    assert _bash(env, f"cat {env.run}/report.md | grep gather_raw", "main").allow
    assert not _bash(env, f"cat {env.run}/gather_raw/l-001/1.json", "main").allow


def test_no_recursive_descent_primitive_on_any_lane(env):
    """The invariant that made the old clamp complete rather than lucky, KEPT after the clamp died:
    the lane has NO recursive-descent primitive, so a subtree cannot be reached without NAMING a path
    — and a named path is a resolved path is a scope check. `ls -R` (ls is gone entirely) and
    `grep -r/-R` (excluded from the flag class) deny on BOTH agents.
    Without this, positive enumeration would be bypassable: `ls -R {run}` would walk into gather_raw/
    and list the whole payload tree for main, naming nothing."""
    for which in ("main", "gather"):
        for cmd in (f"ls -R {env.run}", f"ls -lR {env.run}", f"grep -r x {env.run}",
                    f"grep -R x {env.run}", f"find {env.run} -name '*.json'"):
            assert not _bash(env, cmd, which).allow, f"{which}: {cmd}"


def test_ls_and_cd_are_gone_from_the_lane(env):
    """`ls` and `cd` — in ANY form — DENY for main and gather (#575 behavior change #2), and no grant
    names them. `ls DIR` was the other path-opening slot (a bash-lane-only recon primitive with no
    decide_read counterpart); removing the program is what removes the whole `-I`/`-w`-consumes-the-
    operand-and-falls-back-to-the-CWD bug class (#579) rather than enumerating 37 safe flags to hold
    it back. `cd` fell with it: the executor's cwd is fixed, so a relative operand always resolves
    against one known dir.
    Positive controls: the surviving programs still run — including the shim `cd` used to prefix."""
    for which in ("main", "gather"):
        assert "ls" not in {g.program for g in (env.main if which == "main" else env.gather).bash_allow}
        for cmd in ("ls", f"ls {env.run}", f"ls -la {env.run}", f"ls {env.run}/gather_raw",
                    "ls /etc", f"cd {env.run}", f"cd {env.dfn} && defender-lessons --tags"):
            assert not _bash(env, cmd, which).allow, f"{which}: {cmd}"
        assert _bash(env, "defender-lessons --tags", which).allow, which          # control
        assert _bash(env, f"cat {env.run}/investigation.md", which).allow, which  # control


# ===========================================================================  #
# G. Relative operands: rebased on the EXECUTOR's cwd, then resolved            #
# ===========================================================================  #

def test_relative_operand_is_rebased_not_guessed(env):
    """A relative operand is rebased on the cwd `tools._tool_bash` hands the executor, before it
    resolves (#575). Pre-#535 the convention was "absolute only" because a pure regex anchor
    cannot resolve a relative path; resolving one against the EXECUTOR's cwd is not a widening
    but a correctness fix: without it the gate validates one file while `cat` opens another.

    Since #540 that cwd is the RUN DIR (the box's rw bind), so the rebase now lands INSIDE the
    run rather than at the repo root. `gather_raw/l-001/1.json` therefore names gather's own
    payload and ALLOWs — the same file the absolute control names, which is the property that
    matters: one spelling, one file, gate and executor agreeing.

    The repo-relative corpus spelling now DENIES, and that is not a capability loss: an
    absolute operand bypasses every anchor, and `defender-lessons` emits absolute paths, so
    the corpus is still reachable by the spelling the agent is actually handed. A `..` escape
    still DENIES — the rebase is a resolution rule, not a widening."""
    rel = _bash(env, "cat gather_raw/l-001/1.json", "gather")
    absolute = _bash(env, f"cat {env.run}/gather_raw/l-001/1.json", "gather")
    assert rel.allow
    assert absolute.allow                                                         # absolute control
    assert not _bash(env, "cat defender/lessons/x.md", "gather").allow            # no longer the repo root
    assert not _bash(env, "cat ../../etc/passwd", "gather").allow                 # rebase is not a widening


def test_relative_after_cd_still_denied(env):
    """cd {RUN} && cat gather_raw/l-001/1.json → DENY, now for two independent reasons: `cd` is not a
    granted program at all, and the executor's cwd is FIXED — a relative operand is rebased on
    `defender_dir.parent` no matter what the model believes the cwd to be. There is no state a
    command can set that moves where an operand resolves."""
    assert not _bash(env, f"cd {env.run} && cat gather_raw/l-001/1.json", "gather").allow


# ===========================================================================  #
# H. Symlinks: the residual this file used to DOCUMENT is now CLOSED            #
# ===========================================================================  #

def test_ln_symlink_creation_denied(env):
    """ln -s /etc/passwd {RUN}/x → DENY (both): `ln` is in no grant (and not in `PROGRAMS`), so the
    agent cannot CREATE a symlink. Defense in depth — no longer the load-bearing half."""
    assert not _bash(env, f"ln -s /etc/passwd {env.run}/x", "gather").allow
    assert not _bash(env, f"ln -s /etc/passwd {env.run}/x", "main").allow


def test_preexisting_symlink_out_of_root_denied(env):
    """THE RESIDUAL, CLOSED (#575 behavior change #4). This file used to carry a NOTE saying a
    PRE-EXISTING symlink at an in-shape path could not be caught by the bash lane — the anchored
    regex judged the operand's literal TEXT, so `{RUN}/gather_raw/l-001/9.json -> /etc/passwd` read
    as in-root, and containment rested on a side invariant (no sanctioned writer creates a link) plus
    the OS sandbox. The lane resolve()s now: the link collapses to /etc/passwd, which no scope shape
    admits, and it DENIES — a check, not an invariant.

    Positive control: a symlink to an IN-ROOT, in-shape target ALLOWs. The deny is for the ESCAPE,
    not for being a symlink; containment is where a path RESOLVES and nothing else."""
    escape = env.run / "gather_raw" / "l-001" / "9.json"
    os.symlink("/etc/passwd", escape)
    assert not _bash(env, f"cat {escape}", "gather").allow
    assert not _read(env, escape, "gather").allow          # ...and the read tool agrees

    (env.run / "gather_raw" / "l-001" / "0.json").write_text("{}\n")
    inside = env.run / "gather_raw" / "l-001" / "1.json"
    os.symlink(env.run / "gather_raw" / "l-001" / "0.json", inside)
    assert _bash(env, f"cat {inside}", "gather").allow     # positive control


def test_symlink_loop_fails_closed(env):
    """A symlink LOOP makes `resolve()` raise `RuntimeError` — the gate must DENY, never propagate
    (a raise out of decide_bash is a 500 in the driver, not a deny the model can retry)."""
    a = env.run / "gather_raw" / "l-001" / "2.json"
    b = env.run / "gather_raw" / "l-001" / "3.json"
    os.symlink(b, a)
    os.symlink(a, b)
    assert not _bash(env, f"cat {a}", "gather").allow      # must not raise


# ===========================================================================  #
# I. Writes stay on write_file/edit_file; bash redirect-writes deny             #
# ===========================================================================  #

def test_bash_redirect_write_denied(env):
    """cat ... >> {RUN}/investigation.md and echo x > {RUN}/f → DENY: the executor fails closed on
    write redirects (`>`/`>>`). Substitute: the write_file/edit_file tool (invlang-validated)."""
    # rejected: allow the redirect (would bypass the invlang write gate)
    assert not _bash(env, f"echo x >> {env.run}/investigation.md", "main").allow
    assert not _bash(env, f"echo x > {env.run}/f.txt", "gather").allow


def test_write_report_still_allowed(env):
    """decide_write({RUN}/report.md) → ALLOW: the sanctioned main-loop write path is unchanged
    (regression). Main declares its run-dir subtree as its write_allow."""
    pol = permission.AgentPolicy(write_allow=(permission.build_write_allow(env.run),))
    assert permission.decide_write(
        env.run / "report.md", "---\ndisposition: benign\n---\nConcise analysis.\n",
        run_dir=env.run, defender_dir=env.dfn, policy=pol,
    ).allow


def test_write_investigation_invalid_invlang_denied(env):
    """decide_write({RUN}/investigation.md, <invalid invlang>) → DENY: the invlang gate is unchanged
    (the run-dir write_allow admits the path, then invlang denies the content)."""
    pol = permission.AgentPolicy(write_allow=(permission.build_write_allow(env.run),))
    d = permission.decide_write(
        env.run / "investigation.md", "```yaml\nfoo: bar\n```\n",
        run_dir=env.run, defender_dir=env.dfn, policy=pol,
    )
    assert not d.allow


# ===========================================================================  #
# J. #611 — the adapter lane is gone; the local-compute lane over payloads       #
#    already on disk survives, and an adapter denies on BOTH lanes.              #
# ===========================================================================  #

def test_standalone_adapter_denied_for_gather(env):
    """#611 FLIP: `defender-elastic query 'x'` used to be ALLOW for gather (its payload captured
    transparently). A data source is now reached through the `query` tool, so the adapter is
    unreachable from bash — the standalone form DENIES for gather, and the decision carries no
    routing fields for a capture layer that no longer exists."""
    d = _bash(env, "defender-elastic query 'x'", "gather")
    assert not d.allow
    assert d.reason == permission.ADAPTER_RETIRED_REASON
    assert not hasattr(d, "adapter_argv")
    assert not hasattr(d, "sql_pipe")


def test_adapter_sql_pipe_denied_split_became_tool_then_bash(env):
    """#611 FLIP: `defender-elastic … | defender-sql …` was the sanctioned capture+aggregate pipe.
    It is now two steps — `query(…)` produces the payload, then `cat <payload> | defender-sql …`
    aggregates it — so the single-command pipe DENIES for gather (its adapter stage is unreachable),
    on the adapter reason. Main never got the adapter and still doesn't."""
    cmd = "defender-elastic query 'x' | defender-sql 'SELECT user, count(*) c FROM data GROUP BY user'"
    d = _bash(env, cmd, "gather")
    assert not d.allow
    assert d.reason == permission.ADAPTER_RETIRED_REASON
    assert not _bash(env, cmd, "main").allow


def test_cat_payload_into_defender_sql_allowed(env):
    """cat {RUN}/gather_raw/l-001/1.json | defender-sql 'SELECT …' → ALLOW for gather: an in-scope
    payload streamed into the sandboxed aggregator (cat scope-checked, defender-sql opens nothing).
    This is the SURVIVING half of the retired capture+aggregate pipe — the `defender-sql` step of
    the new tool-then-bash flow."""
    cmd = f"cat {env.run}/gather_raw/l-001/1.json | defender-sql 'SELECT count(*) FROM data'"
    assert _bash(env, cmd, "gather").allow


def test_adapter_jq_pipe_denied(env):
    """defender-elastic … | jq '.x' → DENY. This was denied because adapter|jq was not the
    sanctioned adapter pipe; post-#611 it denies because the adapter stage is unreachable from bash
    at all. Either way a live adapter's payload never flows into an arbitrary reader stage."""
    d = _bash(env, "defender-elastic query 'x' | jq '.x'", "gather")
    assert not d.allow
    assert d.reason == permission.ADAPTER_RETIRED_REASON


def test_adapter_denied_for_main(env):
    """A data-source adapter is denied for the main loop — unchanged in verdict. Since #611 the
    reason is the shared `ADAPTER_RETIRED_REASON` (it names the `query` tool); it is prompt surface
    the e2e deny-tail asserts as a substring, so it is pinned here too."""
    d = _bash(env, "defender-elastic query 'x'", "main")
    assert not d.allow
    assert d.reason == permission.ADAPTER_RETIRED_REASON


# ===========================================================================  #
# K. Degenerate inputs                                                          #
# ===========================================================================  #

def test_empty_command_allowed(env):
    """An empty / whitespace-only command is a no-op → ALLOW (unchanged current behavior; nothing is
    read)."""
    assert _bash(env, "", "gather").allow
    assert _bash(env, "   ", "main").allow


def test_arbitrary_shell_still_denied(env):
    """curl / rm / python3 → DENY for both agents (regression floor — the grant list is
    deny-by-default, and `curl` is not even in `PROGRAMS`, so no policy could grant it without
    failing loud at compile)."""
    for cmd in ("curl http://evil", "rm -rf /tmp/x", "python3 -c 'x'"):
        assert not _bash(env, cmd, "gather").allow, cmd
        assert not _bash(env, cmd, "main").allow, cmd
