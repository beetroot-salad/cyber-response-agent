"""The gather/main bash reader lane confines file operands to {run_dir, corpus} by resolved path.

The corpus is the tenant's (lessons, system skills, query catalog) under the run's agent root
(`<T>/run-knowledge/<run_id>/agent/`, threaded as `RunScope(tenant_agent=...)`), never under
`defender_dir`. `env.agent` is that run copy, built from made-up content."""
from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("pydantic_ai")  # CI installs the runtime extra; skip otherwise

from defender.agents import MAIN_DEF  # noqa: E402
from defender.tests.support.tenancy import _tenants1106
from defender.investigation import permission  # noqa: E402
from defender.investigation.agent_definition import RunScope, compile_policy_for  # noqa: E402


# Fixtures: a per-run run dir + corpus, and the two per-run policies built off  #
# them. The dirs are real because both surfaces resolve() their operands.       #
@pytest.fixture
def env(tmp_path):
    run = tmp_path / "run"
    (run / "gather_raw" / "l-001").mkdir(parents=True)
    (run / "gather_summaries").mkdir()
    dfn = tmp_path / "defender"
    # Checkout-side corpus folders, only as the place a stale reader would look: none of them is
    # a corpus root.
    (dfn / "lessons").mkdir(parents=True)
    (dfn / "skills" / "elastic").mkdir(parents=True)
    (dfn / "skills" / "gather" / "queries" / "elastic").mkdir(parents=True)
    (dfn / "examples").mkdir()
    (dfn / "fixtures" / "held-out" / "m01").mkdir(parents=True)
    # This run's copy of its tenant's knowledge (`<T>/run-knowledge/<run>/`).
    agent = tmp_path / "tenant" / "run-knowledge" / "run-1" / "agent"
    (agent / "lessons").mkdir(parents=True)
    (agent / "skills" / "cmdb").mkdir(parents=True)
    (agent / "skills" / "gather" / "queries" / "cmdb").mkdir(parents=True)
    # Another tenant's run copy under the same data root: never a root of this run.
    other = tmp_path / "other-tenant" / "run-knowledge" / "run-2" / "agent"
    (other / "lessons").mkdir(parents=True)
    scope = RunScope(tenant_agent=agent)
    main = compile_policy_for(MAIN_DEF, run_dir=run, defender_dir=dfn, scope=scope)
    gather = compile_policy_for(
        _tenants1106.fixture_gather_def(), run_dir=run, defender_dir=dfn, scope=scope)
    return SimpleNamespace(run=run, dfn=dfn, agent=agent, other=other, main=main, gather=gather)


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
    """An empty-string or '/' root (run_dir or an explicit defender_dir) raises instead of anchoring
    the grant scopes at the CWD or the filesystem root."""
    # rejected: accept '' or '/' and produce a root-anchored (=everything) policy
    gather_def = _tenants1106.fixture_gather_def()
    for bad in ("", "/"):
        with pytest.raises((TypeError, ValueError)):
            compile_policy_for(gather_def, run_dir=Path(bad), defender_dir=tmp_path)
        with pytest.raises((TypeError, ValueError)):
            compile_policy_for(MAIN_DEF, run_dir=tmp_path, defender_dir=Path(bad))


# B. In-scope reads ALLOW (positive controls — the reads real runs actually make)#

# A gate that denies everything is trivially "secure", so each row is a capability the lane
# must keep.
@pytest.mark.parametrize(("case", "cmd", "lane"), [
    # the agent's own case log, absolute, under the run dir — readable on BOTH lanes
    ("run-investigation-main", "cat {run}/investigation.md", "main"),
    ("run-investigation-gather", "cat {run}/investigation.md", "gather"),

    ("run-gather-summary-on-main", "cat {run}/gather_summaries/l-001.md", "main"),

    # a plain run-dir artifact (RunPaths.executed_queries)
    ("run-executed-queries", "cat {run}/executed_queries.jsonl", "main"),

    ("investigation-piped-to-tail", "cat {run}/investigation.md | tail -5", "main"),
    ("investigation-piped-to-wc", "cat {run}/investigation.md | wc -l", "main"),
    ("investigation-piped-to-grep",
     'cat {run}/investigation.md | grep -n "T resolutions"', "main"),

    # a lessons-corpus read (absolute, .md under the run copy's lessons/)
    ("corpus-lesson", "cat {agent}/lessons/auth-log-scope.md", "main"),

    # the real multi-file lesson cat: multiple in-scope operands + a benign stderr discard.
    # EVERY operand is resolved and scope-checked, not just the first.
    ("corpus-multi-lesson", "cat {agent}/lessons/a.md {agent}/lessons/b.md 2>/dev/null", "main"),

    # the enumerated corpus .md shapes
    ("corpus-system-skill", "cat {agent}/skills/cmdb/SKILL.md", "gather"),
    ("corpus-query-template", "cat {agent}/skills/gather/queries/cmdb/x.md", "gather"),

    # the machine-tight payload shape (`gather_raw/l-<digits>/<seq>.json`) is in GATHER's
    # grants — and in nobody else's
    ("gather-raw-absolute-on-gather", "cat {run}/gather_raw/l-001/1.json", "gather"),
    # an in-scope payload streamed into the sandboxed aggregator (`defender-sql` opens nothing)
    ("payload-into-defender-sql",
     "cat {run}/gather_raw/l-001/1.json | defender-sql 'SELECT count(*) FROM data'", "gather"),
    # a path-looking token is grep's PATTERN, not a file operand
    ("grep-pattern-looks-like-a-path",
     'cat {run}/investigation.md | grep "/home/x/.ssh/authorized_keys"', "main"),
    # text that merely names gather_raw decides nothing: only what a command opens counts
    ("gather-raw-as-a-grep-pattern", "cat {run}/report.md | grep gather_raw", "main"),
], ids=lambda v: v if isinstance(v, str) and len(v) < 40 and "/" not in v else "")
def test_an_in_scope_read_is_allowed(env, case, cmd, lane):
    """The capability half of the ledger: the run-dir artifacts and corpus documents each lane
    is actually granted stay readable — absolute, piped, multi-operand and all."""
    assert _bash(env, cmd.format(run=env.run, dfn=env.dfn, agent=env.agent), lane).allow


@pytest.mark.parametrize("lane", ["main", "gather"])
@pytest.mark.parametrize("rel", ["lessons/x.md", "skills/elastic/SKILL.md",
                                 "skills/gather/queries/elastic/x.md"])
def test_o2_the_checkout_corpus_shapes_are_no_corpus_root_after_p4(env, lane, rel):
    """A lesson, system skill or query template under `defender_dir` is refused on both read
    surfaces, as is another tenant's run copy; the same shape under the run's own agent root is
    admitted (positive control)."""
    stale, own, foreign = env.dfn / rel, env.agent / rel, env.other / rel
    assert _bash(env, f"cat {own}", lane).allow, "positive control: the run copy's corpus"
    assert _read(env, own, lane).allow, "positive control: the run copy's corpus"
    assert not _bash(env, f"cat {stale}", lane).allow, "the checkout's corpus is still a root"
    assert not _read(env, stale, lane).allow, "the checkout's corpus is still a root"
    assert not _bash(env, f"cat {foreign}", lane).allow, "another tenant's run copy is readable"
    assert not _read(env, foreign, lane).allow, "another tenant's run copy is readable"


# C. Out-of-scope reads DENY (guarded negatives, each with a positive control)  #

@pytest.mark.parametrize(("case", "denied", "control", "lane"), [
    # The demonstrated bypass #535 closed, on both lanes.
    ("etc-passwd-gather", "cat /etc/passwd", "cat {run}/investigation.md", "gather"),
    ("etc-passwd-main", "cat /etc/passwd", None, "main"),

    # The out-of-root read cannot be laundered through the PIPE lane either: this denies on
    # the cat stage's scope (grep opens nothing, so grep is not what saves us).
    ("through-a-pipe", "cat /etc/passwd | grep root",
     "cat {run}/investigation.md | grep root", "gather"),

    ("traversal-out-of-prefix", "cat {run}/../outside.txt", "cat {run}/report.md", "gather"),

    # Starts WITH the run-dir prefix — it would pass a naive startswith — but the `..`
    # segments tunnel out, and resolve() collapses them to /etc/passwd.
    ("in-prefix-traversal-escape", "cat {run}/gather_raw/../../../etc/passwd", None, "gather"),

    ("second-operand-escape", "cat {run}/investigation.md /etc/passwd",
     "cat {run}/investigation.md {run}/report.md", "gather"),

    ("corpus-lookalike-sibling", "cat {dfn}-evil/x.md", None, "gather"),
    ("agent-lookalike-sibling", "cat {agent}-evil/lessons/x.md",
     "cat {agent}/lessons/x.md", "gather"),

    # A downstream stage cannot smuggle a file back in: the viewers deny at the shape (they have
    # no file slot), `cat` at the scope.
    ("grep-second-stage-file", "cat {run}/investigation.md | grep foo /etc/passwd", None, "gather"),
    ("cat-second-stage-file", "cat {run}/investigation.md | cat /etc/passwd", None, "gather"),
    ("wc-second-stage-file", "cat {run}/investigation.md | wc -l /etc/passwd", None, "gather"),
], ids=lambda v: v if isinstance(v, str) and len(v) < 40 and "/" not in v else "")
def test_an_out_of_scope_read_is_denied(env, case, denied, control, lane):
    fmt = {"run": env.run, "dfn": env.dfn, "agent": env.agent}
    assert not _bash(env, denied.format(**fmt), lane).allow
    if control is not None:
        assert _bash(env, control.format(**fmt), lane).allow, "positive control"


def test_grep_dash_f_patternfile_escapes(env):
    """grep -f /etc/passwd → DENY: `-f` opens the out-of-root PATTERN file."""
    # rejected: gating only the trailing operand (misses -f's file)
    assert not _bash(env, f"grep -f /etc/passwd {env.run}/investigation.md", "gather").allow
    assert not _bash(env, "grep -f /etc/passwd x", "gather").allow
    assert _bash(env, f"cat {env.run}/investigation.md | grep root", "gather").allow  # positive control


def test_grep_dash_e_promotes_positional_to_file(env):
    # rejected: model grep as always pattern+files positionally (ignores -e)
    assert not _bash(env, "grep -e root /etc/shadow", "gather").allow


def test_grep_recursive_denied(env):
    """`grep -r`/`-R` is denied: recursion reads files no operand named (and follows symlinks out of
    root). The dir operand is in-root on purpose, so only the flag can deny it."""
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
    """tail/head keep their count flags (`-n`/`-c`, fused `-5`) but take no file operand; `-f`/`-F`
    stay denied (a follow never returns and burns the executor's timeout), as does `-s SECS`."""
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


def test_wc_files0_from_escapes(env):
    # rejected: leave --files0-from ungated
    assert not _bash(env, "wc --files0-from=/etc/passwd", "gather").allow
    assert not _bash(env, f"cat {env.run}/report.md | wc --files0-from=/etc/passwd", "gather").allow


def test_stdin_consuming_viewers_in_pipe_allowed(env):
    """An in-scope `cat` (or a shim) piped into grep/wc/head/tail/`cat -` is allowed on both lanes: a
    downstream viewer reads stdin and names no file."""
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


# E. Cross-surface PARITY: the read tool and the bash lane share ONE object     #

def test_read_allow_is_the_cat_grants_scope(env):
    """`policy.read_allow` IS the `cat` grant's scope object on both lanes, so the read tool admits
    exactly what `cat` does."""
    for pol in (env.main, env.gather):
        (cat_grant,) = [g for g in pol.bash_allow if g.program == "cat"]
        assert pol.read_allow is cat_grant.scope


def test_parity_corpus_non_listed_denied_on_both_lanes(env):
    """A file outside the corpus grammar (`{dfn}/docs/…`) is denied on both the read tool and the
    `cat` lane; a lessons `.md` is admitted on both."""
    docs = f"{env.dfn}/docs/learning-loop.md"
    assert not _read(env, docs, "gather").allow
    assert not _bash(env, f"cat {docs}", "gather").allow
    ok = f"{env.agent}/lessons/notes.md"
    assert _read(env, ok, "gather").allow
    assert _bash(env, f"cat {ok}", "gather").allow


def test_corpus_md_named_secret_denied(env):
    """A `.md`-named secret under a corpus dir passes the corpus shape, so the basename denylist
    alone must deny it, on both surfaces."""
    # rejected: drop the basename-substring axis (a `credentials.md`/`.env.md` in-corpus leaks)
    for secret in (f"{env.agent}/lessons/credentials.md",
                   f"{env.agent}/skills/cmdb/ground_truth.md",
                   f"{env.agent}/lessons/x.env.md"):
        assert not _bash(env, f"cat {secret}", "gather").allow, secret
        assert not _read(env, secret, "gather").allow, secret
    assert _bash(env, f"cat {env.agent}/lessons/notes.md", "gather").allow  # positive control


@pytest.mark.parametrize("axis", ["substring", "dir"])
def test_denylist_parity_bash_matches_decide_read(env, axis):
    """For every configured denylist entry, an OTHERWISE-IN-SCOPE operand carrying it denies on BOTH the bash lane and decide_read."""
    from defender.investigation import bash_policy
    if axis == "substring":
        for sub in bash_policy.read_deny_substrings():
            p = f"{env.run}/{sub}xyz"                     # denied substring in an in-shape basename
            assert not _bash(env, f"cat {p}", "gather").allow, p
            assert not _read(env, p, "gather").allow, p
    else:
        for d in bash_policy.read_deny_dirs():
            p = f"{env.agent}/lessons/{d}/inner.md"       # denied dir as an in-shape path component
            assert not _bash(env, f"cat {p}", "gather").allow, p
            assert not _read(env, p, "gather").allow, p


def test_empty_denylist_cannot_brick_the_reader_lane(env, monkeypatch):
    """An emptied denylist cannot brick the reader lane: it is a resolve-time subtraction, not a
    lookahead in the shapes (none contains `(?!`), and emptied it admits the `.env` it denied."""
    from defender.investigation import bash_policy
    for pol in (env.main, env.gather):
        for shape in [s for g in pol.bash_allow for s in g.scope] + list(pol.read_allow):
            assert "(?!" not in shape.pattern, shape.pattern
    monkeypatch.setattr(bash_policy, "read_deny_substrings", lambda: ())  # lint-monkeypatch: ok — force the degenerate empty-denylist config
    monkeypatch.setattr(bash_policy, "read_deny_dirs", lambda: ())  # lint-monkeypatch: ok — force the degenerate empty-denylist config
    assert _bash(env, f"cat {env.run}/investigation.md", "gather").allow   # not bricked
    assert _bash(env, f"cat {env.run}/.env", "gather").allow               # the axis really is empty


# F. gather_raw is reached by positive enumeration only                         #

def test_raw_payload_is_gathers_shape_and_not_mains(env):
    """cat {RUN}/gather_raw/l-001/1.json: DENY for main, ALLOW for gather — same program, same extractor, same resolved operand."""
    raw = f"{env.run}/gather_raw/l-001/1.json"
    assert not _bash(env, f"cat {raw}", "main").allow
    assert _bash(env, f"cat {raw}", "gather").allow
    d_read = _read(env, raw, "main")
    assert not d_read.allow
    assert "gather_raw" in (d_read.reason or "")


def test_no_recursive_descent_primitive_on_any_lane(env):
    """No lane has a recursive-descent primitive (`ls -R`, `grep -r`, `find`), so a subtree such as
    gather_raw cannot be reached without naming, and so scope-checking, a path."""
    for which in ("main", "gather"):
        for cmd in (f"ls -R {env.run}", f"ls -lR {env.run}", f"grep -r x {env.run}",
                    f"grep -R x {env.run}", f"find {env.run} -name '*.json'"):
            assert not _bash(env, cmd, which).allow, f"{which}: {cmd}"


# G. Relative operands: rebased on the EXECUTOR's cwd, then resolved            #

def test_relative_operand_is_rebased_not_guessed(env):
    """A relative operand is rebased on the cwd `tools._tool_bash` hands the executor (the run dir)
    before it resolves, so gate and executor judge the same file."""
    rel = _bash(env, "cat gather_raw/l-001/1.json", "gather")
    absolute = _bash(env, f"cat {env.run}/gather_raw/l-001/1.json", "gather")
    assert rel.allow
    assert absolute.allow                                                         # absolute control
    assert not _bash(env, "cat defender/lessons/x.md", "gather").allow            # rebased on the run dir
    assert not _bash(env, "cat ../../etc/passwd", "gather").allow                 # rebase is not a widening


def test_relative_after_cd_still_denied(env):
    """`cd {run} && cat <relative>` is denied: `cd` is not a granted program, and the executor's cwd
    is fixed anyway."""
    assert not _bash(env, f"cd {env.run} && cat gather_raw/l-001/1.json", "gather").allow


# H. Symlinks: containment is where a path resolves                             #

def test_ln_symlink_creation_denied(env):
    """`ln -s` is denied on both lanes: `ln` is in no grant, so the agent cannot create a symlink
    (defense in depth; resolving operands is what contains one)."""
    assert not _bash(env, f"ln -s /etc/passwd {env.run}/x", "gather").allow
    assert not _bash(env, f"ln -s /etc/passwd {env.run}/x", "main").allow


def test_preexisting_symlink_out_of_root_denied(env):
    """A pre-existing in-shape symlink pointing out of root is denied on both surfaces because the
    operand is resolved; a link to an in-root target is allowed (positive control)."""
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


# I. Bash redirect writes deny; writes go through the write tools               #

def test_bash_redirect_write_denied(env):
    """`>`/`>>` write redirects are denied: writes go through the validated write tools, never bash."""
    # rejected: allow the redirect (would bypass the invlang write gate)
    assert not _bash(env, f"echo x >> {env.run}/investigation.md", "main").allow
    assert not _bash(env, f"echo x > {env.run}/f.txt", "gather").allow


# K. Degenerate inputs                                                          #

def test_empty_command_allowed(env):
    """An empty / whitespace-only command is a no-op → ALLOW (unchanged current behavior; nothing is
    read)."""
    assert _bash(env, "", "gather").allow
    assert _bash(env, "   ", "main").allow


def test_arbitrary_shell_still_denied(env):
    for cmd in ("curl http://evil", "rm -rf /tmp/x", "python3 -c 'x'"):
        assert not _bash(env, cmd, "gather").allow, cmd
        assert not _bash(env, cmd, "main").allow, cmd
