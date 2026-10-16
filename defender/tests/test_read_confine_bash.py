"""The gather/main bash reader lane confines file operands to {run_dir, corpus} by resolved path."""
from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("pydantic_ai")  # CI installs the runtime extra; skip otherwise

from defender.agents import MAIN_DEF  # noqa: E402
from defender.tests import _tenants1106  # noqa: E402
from defender.runtime import permission  # noqa: E402
from defender.runtime.agent_definition import compile_policy_for  # noqa: E402


# Fixtures: a per-run run dir + corpus, and the two per-run policies built off  #
# them. The dirs are real because both surfaces resolve() their operands.       #
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
    gather = compile_policy_for(
        _tenants1106.fixture_gather_def(), run_dir=run, defender_dir=dfn)
    return SimpleNamespace(run=run, dfn=dfn, main=main, gather=gather)


def _bash(env, cmd, which="gather"):
    pol = env.gather if which == "gather" else env.main
    return permission.decide_bash(cmd, policy=pol, run_dir=env.run, defender_dir=env.dfn)


def _read(env, path, which="gather"):
    pol = env.gather if which == "gather" else env.main
    return permission.decide_read(Path(path), run_dir=env.run, defender_dir=env.dfn, policy=pol)


# A. Safe-by-construction: the compile seam cannot build an unconfined policy    #

def test_compile_policy_for_requires_run_dir():
    """compile_policy_for(GATHER_DEF) with NO run_dir RAISES → the confined reader policy can't
    be built in an unconfined state (run_dir is a required positional, no silent fallback)."""
    # rejected: return a permissive default policy (re-opens the cat /etc/passwd bypass)
    gather_def = _tenants1106.fixture_gather_def()
    with pytest.raises((TypeError, ValueError)):
        compile_policy_for(gather_def)


def test_compile_policy_for_rejects_degenerate_roots(tmp_path):
    """An empty-string / '/' root — run_dir OR an explicit defender_dir — must RAISE, not anchor"""
    # rejected: accept '' or '/' and produce a root-anchored (=everything) policy
    gather_def = _tenants1106.fixture_gather_def()
    for bad in ("", "/"):
        with pytest.raises((TypeError, ValueError)):
            compile_policy_for(gather_def, run_dir=Path(bad), defender_dir=tmp_path)
        with pytest.raises((TypeError, ValueError)):
            compile_policy_for(MAIN_DEF, run_dir=tmp_path, defender_dir=Path(bad))


# B. In-scope reads ALLOW (positive controls — the reads real runs actually make)#

# The positive controls: the reads real runs actually make. A confinement gate that denies
# everything is trivially "secure", so each of these is a capability the lane must keep.
@pytest.mark.parametrize(("case", "cmd", "lane"), [
    # the agent's own case log, absolute, under the run dir — readable on BOTH lanes
    ("run-investigation-main", "cat {run}/investigation.md", "main"),
    ("run-investigation-gather", "cat {run}/investigation.md", "gather"),

    # the per-lead summary, built inline at tools_gather.py and NOT a RunPaths prop — the
    # scope must still cover it. Read on the MAIN lane on purpose: the summary is main's
    # sanctioned view of a lead's data (the raw payload is gather's).
    ("run-gather-summary-on-main", "cat {run}/gather_summaries/l-001.md", "main"),

    # a plain run-dir artifact (RunPaths.executed_queries)
    ("run-executed-queries", "cat {run}/executed_queries.jsonl", "main"),

    # The real read/format shapes from run traces, in their #575 form: the viewers have NO
    # file slot, so `cat` opens the file and the reduction happens on STDIN. The FILE forms of
    # these same three commands are the deny half of the c1 ledger
    # (test_viewer_file_operand_denied below); these are the surviving capability — identical,
    # one extra `cat |`.
    ("investigation-piped-to-tail", "cat {run}/investigation.md | tail -5", "main"),
    ("investigation-piped-to-wc", "cat {run}/investigation.md | wc -l", "main"),
    ("investigation-piped-to-grep",
     'cat {run}/investigation.md | grep -n "T resolutions"', "main"),

    # a lessons-corpus read (absolute, .md under lessons/)
    ("corpus-lesson", "cat {dfn}/lessons/auth-log-scope.md", "main"),

    # the real multi-file lesson cat: multiple in-scope operands + a benign stderr discard.
    # EVERY operand is resolved and scope-checked, not just the first.
    ("corpus-multi-lesson", "cat {dfn}/lessons/a.md {dfn}/lessons/b.md 2>/dev/null", "main"),

    # the enumerated corpus .md shapes
    ("corpus-system-skill", "cat {dfn}/skills/elastic/SKILL.md", "gather"),
    ("corpus-query-template", "cat {dfn}/skills/gather/queries/elastic/x.md", "gather"),

    # the machine-tight payload shape (`gather_raw/l-<digits>/<seq>.json`) is in GATHER's
    # grants — and in nobody else's
    ("gather-raw-absolute-on-gather", "cat {run}/gather_raw/l-001/1.json", "gather"),
], ids=lambda v: v if isinstance(v, str) and len(v) < 40 and "/" not in v else "")
def test_an_in_scope_read_is_allowed(env, case, cmd, lane):
    """The capability half of the ledger: the run-dir artifacts and corpus documents each lane
    is actually granted stay readable — absolute, piped, multi-operand and all."""
    assert _bash(env, cmd.format(run=env.run, dfn=env.dfn), lane).allow


# C. Out-of-scope reads DENY (guarded negatives, each with a positive control)  #

# Each row is one out-of-scope read plus, where one exists, the in-scope read that proves the
# deny came from the SCOPE check and not from the program being unsupported. Without that
# control, a gate that denied `cat` outright would pass every row here.
@pytest.mark.parametrize(("case", "denied", "control", "lane"), [
    # The demonstrated bypass #535 closed, on both lanes.
    ("etc-passwd-gather", "cat /etc/passwd", "cat {run}/investigation.md", "gather"),
    ("etc-passwd-main", "cat /etc/passwd", None, "main"),

    # The out-of-root read cannot be laundered through the PIPE lane either: this denies on
    # the cat stage's scope (grep opens nothing, so grep is not what saves us).
    ("through-a-pipe", "cat /etc/passwd | grep root",
     "cat {run}/investigation.md | grep root", "gather"),

    # `..` collapses at resolve() and the result lands outside every scope shape. (#535
    # rejected `..` TEXTUALLY because the lane did not resolve; #575 resolves, so the
    # traversal is closed by the same check that closes symlinks — one mechanism, not two.)
    ("traversal-out-of-prefix", "cat {run}/../outside.txt", "cat {run}/report.md", "gather"),

    # Starts WITH the run-dir prefix — it would pass a naive startswith — but the `..`
    # segments tunnel out, and resolve() collapses them to /etc/passwd.
    ("in-prefix-traversal-escape", "cat {run}/gather_raw/../../../etc/passwd", None, "gather"),

    # The FIRST operand is in-scope and the SECOND escapes: every operand the extractor
    # reports is scope-checked, not just the first. The control is the same command with both
    # operands in scope.
    ("second-operand-escape", "cat {run}/investigation.md /etc/passwd",
     "cat {run}/investigation.md {run}/report.md", "gather"),

    # A sibling dir sharing the corpus PREFIX but not under it must not match — `under()`
    # closes the root with a `/` boundary, so the anchor is a path boundary, not a string
    # prefix.
    ("corpus-lookalike-sibling", "cat {dfn}-evil/x.md", None, "gather"),
], ids=lambda v: v if isinstance(v, str) and len(v) < 40 and "/" not in v else "")
def test_an_out_of_scope_read_is_denied(env, case, denied, control, lane):
    """A read that resolves outside every scope shape is denied — spelled directly, hidden
    behind a pipe stage, tunnelled through `..`, banked behind an in-scope first operand, or
    aimed at a sibling that merely shares the corpus prefix."""
    fmt = {"run": env.run, "dfn": env.dfn}
    assert not _bash(env, denied.format(**fmt), lane).allow
    if control is not None:
        assert _bash(env, control.format(**fmt), lane).allow, "positive control"


# D. File-opening FLAGS — the escape a clean trailing operand hides             #
#    (`OPENS_NOTHING` is a CLAIM the SHAPE must earn: the gate skips the scope   #
#     check for those programs, so any flag that opens a file is a fail-open)    #

def test_grep_dash_f_patternfile_escapes(env):
    """grep -f /etc/passwd → DENY: `-f` opens the out-of-root PATTERN file."""
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
    """grep -r/-R → DENY: recursion walks a dir (and follows symlinks out of root), reading files no"""
    # rejected: allow -r/-R over an in-root dir (recursive walk / symlink follow escapes containment)
    assert not _bash(env, f"grep -r secret {env.run}/gather_raw", "gather").allow
    assert not _bash(env, f"grep -R secret {env.run}/gather_raw", "gather").allow
    assert not _bash(env, "grep -r secret /etc", "gather").allow
    assert _bash(env, f"cat {env.run}/investigation.md | grep secret", "gather").allow  # control


def test_grep_recursive_single_operand_denied(env):
    """grep -r <pattern> → DENY."""
    # rejected: `VALUE = r"[^ ]+"` (a leading-dash pattern slot re-absorbs the rejected -r)
    for which in ("main", "gather"):
        assert not _bash(env, f"grep -r {env.run}/investigation.md", which).allow, which
        assert not _bash(env, f"grep -R {env.run}/investigation.md", which).allow, which
        assert not _bash(env, f"grep -rn {env.run}/investigation.md", which).allow, which
        assert not _bash(env, "grep -r secret", which).allow, which
        assert _bash(env, f"cat {env.run}/investigation.md | grep -n secret", which).allow, which


def test_tail_head_have_no_file_slot_and_no_arg_taking_flag(env):
    """tail/head keep their COUNT flags (`-n`/`-c`, fused `-5`) and lose their file operand (#575)."""
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
    """cat {RUN}/investigation.md | grep "/home/x/.ssh/authorized_keys" → ALLOW: the path-LOOKING token is the search PATTERN, not a file."""
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
    """`<in-scope cat | shim> | grep/wc/head/tail/cat` → ALLOW: a downstream viewer reads STDIN and"""
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
    """A downstream stage cannot smuggle a file back in: `… | grep foo /etc/passwd` and"""
    assert not _bash(env, f"cat {env.run}/investigation.md | grep foo /etc/passwd", "gather").allow
    assert not _bash(env, f"cat {env.run}/investigation.md | cat /etc/passwd", "gather").allow
    assert not _bash(env, f"cat {env.run}/investigation.md | wc -l /etc/passwd", "gather").allow


# E. Cross-surface PARITY: the read tool and the bash lane share ONE object     #

def test_read_allow_is_the_cat_grants_scope(env):
    """The parity MECHANISM, not just its symptom: `policy.read_allow` IS the `cat` grant's `scope` —"""
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


def test_parity_ssh_dir_component(env):
    """The denylist's path-COMPONENT axis (`.ssh`), probed where only it can decide: `{DFN}/lessons/"""
    p = f"{env.dfn}/lessons/.ssh/key.md"
    assert not _read(env, p, "gather").allow
    assert not _bash(env, f"cat {p}", "gather").allow
    assert _read(env, f"{env.dfn}/lessons/auth/key.md", "gather").allow      # positive control
    assert _bash(env, f"cat {env.dfn}/lessons/auth/key.md", "gather").allow  # positive control


def test_parity_corpus_non_listed_denied_on_both_lanes(env):
    """Read↔bash PARITY on a non-listed corpus file (#545/#546): a corpus file NOT under the tight"""
    docs = f"{env.dfn}/docs/learning-loop.md"
    assert not _read(env, docs, "gather").allow
    assert not _bash(env, f"cat {docs}", "gather").allow
    ok = f"{env.dfn}/lessons/notes.md"
    assert _read(env, ok, "gather").allow
    assert _bash(env, f"cat {ok}", "gather").allow


def test_corpus_md_named_secret_denied(env):
    """A `.md`-named secret UNDER a corpus subdir — `{DFN}/lessons/credentials.md` — passes the corpus"""
    # rejected: drop the basename-substring axis (a `credentials.md`/`.env.md` in-corpus leaks)
    for secret in (f"{env.dfn}/lessons/credentials.md",
                   f"{env.dfn}/skills/elastic/ground_truth.md",
                   f"{env.dfn}/lessons/x.env.md"):
        assert not _bash(env, f"cat {secret}", "gather").allow, secret
        assert not _read(env, secret, "gather").allow, secret
    assert _bash(env, f"cat {env.dfn}/lessons/notes.md", "gather").allow  # positive control


@pytest.mark.parametrize("axis", ["substring", "dir"])
def test_denylist_parity_bash_matches_decide_read(env, axis):
    """For every configured denylist entry, an OTHERWISE-IN-SCOPE operand carrying it denies on BOTH the bash lane and decide_read."""
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
    """The empty-denylist footgun, closed BY CONSTRUCTION."""
    from defender.runtime import bash_policy
    for pol in (env.main, env.gather):
        for shape in [s for g in pol.bash_allow for s in g.scope] + list(pol.read_allow):
            assert "(?!" not in shape.pattern, shape.pattern
    monkeypatch.setattr(bash_policy, "read_deny_substrings", lambda: ())  # lint-monkeypatch: ok — force the degenerate empty-denylist config
    monkeypatch.setattr(bash_policy, "read_deny_dirs", lambda: ())  # lint-monkeypatch: ok — force the degenerate empty-denylist config
    assert _bash(env, f"cat {env.run}/investigation.md", "gather").allow   # not bricked
    assert _bash(env, f"cat {env.run}/.env", "gather").allow               # the axis really is empty


# F. gather_raw: POSITIVE ENUMERATION replaces the raw clamp                    #

def test_raw_payload_is_gathers_shape_and_not_mains(env):
    """cat {RUN}/gather_raw/l-001/1.json: DENY for main, ALLOW for gather — same program, same extractor, same resolved operand."""
    raw = f"{env.run}/gather_raw/l-001/1.json"
    assert not _bash(env, f"cat {raw}", "main").allow
    assert _bash(env, f"cat {raw}", "gather").allow
    d_read = _read(env, raw, "main")
    assert not d_read.allow
    assert "gather_raw" in (d_read.reason or "")


def test_gather_raw_as_a_grep_pattern_is_not_a_read(env):
    """cat {RUN}/report.md | grep gather_raw (main) → ALLOW."""
    assert _bash(env, f"cat {env.run}/report.md | grep gather_raw", "main").allow
    assert not _bash(env, f"cat {env.run}/gather_raw/l-001/1.json", "main").allow


def test_no_recursive_descent_primitive_on_any_lane(env):
    """The invariant that made the old clamp complete rather than lucky, KEPT after the clamp died:"""
    for which in ("main", "gather"):
        for cmd in (f"ls -R {env.run}", f"ls -lR {env.run}", f"grep -r x {env.run}",
                    f"grep -R x {env.run}", f"find {env.run} -name '*.json'"):
            assert not _bash(env, cmd, which).allow, f"{which}: {cmd}"


# G. Relative operands: rebased on the EXECUTOR's cwd, then resolved            #

def test_relative_operand_is_rebased_not_guessed(env):
    """A relative operand is rebased on the cwd `tools._tool_bash` hands the executor, before it resolves (#575)."""
    rel = _bash(env, "cat gather_raw/l-001/1.json", "gather")
    absolute = _bash(env, f"cat {env.run}/gather_raw/l-001/1.json", "gather")
    assert rel.allow
    assert absolute.allow                                                         # absolute control
    assert not _bash(env, "cat defender/lessons/x.md", "gather").allow            # no longer the repo root
    assert not _bash(env, "cat ../../etc/passwd", "gather").allow                 # rebase is not a widening


def test_relative_after_cd_still_denied(env):
    """cd {RUN} && cat gather_raw/l-001/1.json → DENY, now for two independent reasons: `cd` is not a"""
    assert not _bash(env, f"cd {env.run} && cat gather_raw/l-001/1.json", "gather").allow


# H. Symlinks: the residual this file used to DOCUMENT is now CLOSED            #

def test_ln_symlink_creation_denied(env):
    """ln -s /etc/passwd {RUN}/x → DENY (both): `ln` is in no grant (and not in `PROGRAMS`), so the
    agent cannot CREATE a symlink. Defense in depth — no longer the load-bearing half."""
    assert not _bash(env, f"ln -s /etc/passwd {env.run}/x", "gather").allow
    assert not _bash(env, f"ln -s /etc/passwd {env.run}/x", "main").allow


def test_preexisting_symlink_out_of_root_denied(env):
    """THE RESIDUAL, CLOSED (#575 behavior change #4)."""
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


# I. Writes stay on write_file/edit_file; bash redirect-writes deny             #

def test_bash_redirect_write_denied(env):
    """cat ... >> {RUN}/investigation.md and echo x > {RUN}/f → DENY: the executor fails closed on
    write redirects (`>`/`>>`). Substitute: the write_file/edit_file tool (invlang-validated)."""
    # rejected: allow the redirect (would bypass the invlang write gate)
    assert not _bash(env, f"echo x >> {env.run}/investigation.md", "main").allow
    assert not _bash(env, f"echo x > {env.run}/f.txt", "gather").allow


# J. #611 — the adapter lane is gone; the local-compute lane over payloads       #
#    already on disk survives, and an adapter denies on BOTH lanes.              #

def test_cat_payload_into_defender_sql_allowed(env):
    """cat {RUN}/gather_raw/l-001/1.json | defender-sql 'SELECT …' → ALLOW for gather: an in-scope"""
    cmd = f"cat {env.run}/gather_raw/l-001/1.json | defender-sql 'SELECT count(*) FROM data'"
    assert _bash(env, cmd, "gather").allow


# K. Degenerate inputs                                                          #

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
