"""Executable spec (written BEFORE the code) for #575 — one containment model: `Grant`.

The spec is `.spec/resolved-demands.md` (post-human-resolution); every demand there is
exactly one test here, and each test's docstring carries its demand id (a1, b7, …) so the
spec-coverage graph can join to it.

THE CHANGE, in one line: a command is allowed iff it matches a grant's **shape** (program +
flags + arity, NO paths) AND everything `PROGRAMS[argv[0]]` says it opens **resolves** into
that grant's **scope** (an anchored regex over the RESOLVED path). Shape and scope are
separate and neither is interpolated into the other.

RED@HEAD, deliberately. `Grant` / `PROGRAMS` / `OPENS_NOTHING` / `Route` / `under` /
`AgentPolicy.read_allow` / `AgentDefinition.bash_shapes` / `defender.agents` / the
`defender-policy` CLI do not exist at base `09e0a93c`, so this module fails at IMPORT.
That ImportError IS the expected red — it is the spec, not a bug.

The API surface this suite pins (the implementation must satisfy these names):
  - `defender.runtime.permission` re-exports `Grant`, `Route`, `PROGRAMS`, `OPENS_NOTHING`,
    `under` beside the existing `decide_bash` / `decide_read` / `AgentPolicy`.
  - `Grant(program=<str>, pattern=<re.Pattern>, scope=(), route=Route.PLAIN, pins_path=False)`
    — `program` is a FIELD because `compile_policy` must fail loud when a grant *names* a
    program absent from `PROGRAMS`, and because `defender-policy show` prints per-program lines.
  - `AgentPolicy.read_allow: tuple[re.Pattern, ...]` — the read surface's shape tuple, the SAME
    OBJECT the `cat` grant's `scope` carries (read↔bash parity by construction; `read_shapes`
    and `raw_reads` are deleted).
  - `AgentDefinition.bash_shapes: (ResolvedRoots) -> tuple[Grant, ...]` — the per-role builder
    each engine module hangs on its OWN def (task 5), so `runtime/` imports no `learning/` private.
  - the registry lives at `defender.agents` (out of `runtime/`), and the audit CLI is the shim
    `<defender_dir>/bin/defender-policy` (`show` / `explain`).

Entry points driven: `permission.decide_bash`, `permission.decide_read`,
`permission.is_untrusted_read`, `agent_definition.compile_policy_for` / `bind`, the curator's
`CuratorDeps.for_run`, and the `defender-policy` CLI over subprocess. No monkeypatch (CI
ratchets new sites); every seam is a real one.

`resolve()` genuinely touches the filesystem now (that is the point — symlinks collapse there),
so the symlink demands (a5/a6/a7/a8/a10) build real trees with real `os.symlink`.
"""
from __future__ import annotations

import ast
import dataclasses
import json
import os
import re
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("pydantic_ai")  # CI installs the runtime extra; skip otherwise

from defender._paths import PATHS  # noqa: E402
from defender.agents import (  # noqa: E402
    ACTOR_DEF,
    AGENTS,
    CORPUS_AUTHOR_DEF,
    GATHER_DEF,
    JUDGE_DEF,
    LEAD_AUTHOR_DEF,
    MAIN_DEF,
    ORACLE_DEF,
    VERIFY_DEF,
)
from defender.hooks._cmd_segments import NON_ADAPTER_SHIMS  # noqa: E402
from defender.learning.author.curator_engine import CuratorDeps  # noqa: E402
from defender.learning.core import config  # noqa: E402
from defender.runtime import permission, tools  # noqa: E402
from defender.runtime.agent_definition import (  # noqa: E402
    RunScope,
    bind,
    compile_policy_for,
)
from defender.runtime.permission import (  # noqa: E402
    OPENS_NOTHING,
    PROGRAMS,
    Grant,
    Route,
    under,
)

_DEFENDER = PATHS.defender_dir
_POLICY_CLI = _DEFENDER / "bin" / "defender-policy"

# Real repo scripts — the actor's pinned-script pattern does
# `script.resolve().relative_to(REPO_ROOT)`, so a synthetic path raises.
_ENV_RETRIEVE = config.LESSONS_ENV_RETRIEVE_SCRIPT
_ACTOR_INDEX = config.LESSONS_ACTOR_INDEX_SCRIPT
_ACTOR_DIR = config.LESSONS_ACTOR_DIR
_ENV_DIR = config.LESSONS_ENVIRONMENT_DIR


# --------------------------------------------------------------------------- #
# Fixtures — real dirs + real files (resolve() touches the fs now).            #
# The two reader policies come off the REAL compile seam (compile_policy_for,  #
# not bind: no discarded salt/deps), the four stage policies off bind.         #
# --------------------------------------------------------------------------- #
@pytest.fixture
def env(tmp_path):
    run = tmp_path / "run"
    (run / "gather_raw" / "l-001").mkdir(parents=True)
    (run / "gather_raw" / "l-002").mkdir(parents=True)
    (run / "gather_summaries").mkdir()
    for rel in ("investigation.md", "report.md", "alert.json", "executed_queries.jsonl",
                "gather_summaries/l-001.md", "gather_raw/l-001/0.json",
                "gather_raw/l-001.lead.json"):
        (run / rel).write_text("{}\n")
    dfn = tmp_path / "defender"
    (dfn / "lessons").mkdir(parents=True)
    (dfn / "skills" / "elastic").mkdir(parents=True)
    (dfn / "docs").mkdir()
    (dfn / "examples").mkdir()
    (dfn / "fixtures" / "held-out" / "m01").mkdir(parents=True)
    for rel in ("lessons/x.md", "lessons/notes.md", "lessons/a.md", "lessons/.env.md",
                "docs/x.md", "skills/elastic/SKILL.md",
                "fixtures/held-out/m01/ground_truth.yaml"):
        (dfn / rel).write_text("x\n")
    main = compile_policy_for(MAIN_DEF, run_dir=run, defender_dir=dfn)
    gather = compile_policy_for(GATHER_DEF, run_dir=run, defender_dir=dfn)
    return SimpleNamespace(run=run, dfn=dfn, main=main, gather=gather, tmp=tmp_path)


def _bash(env, cmd, which="gather"):
    pol = getattr(env, which) if isinstance(which, str) else which
    return permission.decide_bash(cmd, policy=pol, run_dir=env.run, defender_dir=env.dfn)


def _read(env, path, which="gather"):
    pol = getattr(env, which) if isinstance(which, str) else which
    return permission.decide_read(Path(path), run_dir=env.run, defender_dir=env.dfn, policy=pol)


def _judge(env, *, ticket_cli=None):
    """The judge's policy via the real bind seam (adversarial when ticket_cli is None)."""
    cmp_dir = env.tmp / "cmp"
    cmp_dir.mkdir(exist_ok=True)
    scope = RunScope(add_dirs=(cmp_dir,), ticket_cli=ticket_cli)
    return bind(JUDGE_DEF, env.run, scope=scope, defender_dir=env.dfn).policy


def _ticket_cli(env) -> tuple[str, Path]:
    cli = env.dfn / "scripts" / "case_history" / "case_ticket.py"
    cli.parent.mkdir(parents=True, exist_ok=True)
    cli.write_text("#\n")
    return ("python3", cli)


def _actor(env):
    return bind(
        ACTOR_DEF, env.run,
        scope=RunScope(scripts=(_ENV_RETRIEVE, _ACTOR_INDEX),
                       read_confine=(_ACTOR_DIR, _ENV_DIR)),
        defender_dir=env.dfn,
    ).policy


def _lead_author(env):
    """The lead author binds against a WORKTREE tree (requires_explicit_tree)."""
    return bind(LEAD_AUTHOR_DEF, env.run, defender_dir=env.dfn).policy


def _curator(env):
    """The curator is the one denylist-free lane; it is `bindable=False`, so its policy comes
    off its own real front door (`CuratorDeps.for_run`), never `bind`."""
    corpus = env.dfn / "lessons"
    deps = CuratorDeps.for_run(
        env.run, env.dfn.parent, corpus,
        check=lambda *a, **k: "GOOD", runs_dir=env.tmp / "runs", pending=env.tmp / "pending",
        queued_ids=frozenset(), run_verify=lambda *a, **k: "GOOD",
    )
    return deps.policy


def _all_policies(env) -> dict[str, permission.AgentPolicy]:
    """Every agent's compiled policy, through each role's REAL seam. The audit demands (a2/a4/
    b3/b8/g1) sweep this."""
    tc = _ticket_cli(env)
    return {
        "main": env.main,
        "gather": env.gather,
        "judge": _judge(env, ticket_cli=tc),
        "actor": _actor(env),
        "oracle": compile_policy_for(ORACLE_DEF, run_dir=env.run, defender_dir=env.dfn),
        "verify": compile_policy_for(VERIFY_DEF, run_dir=env.run, defender_dir=env.dfn),
        "lead_author": _lead_author(env),
        "corpus_author": _curator(env),
    }


def _opens_nothing_grants(policy) -> tuple[Grant, ...]:
    return tuple(g for g in policy.bash_allow
                 if not g.pins_path and PROGRAMS.get(g.program) is OPENS_NOTHING)


def _cat_grant(policy) -> Grant:
    (g,) = [g for g in policy.bash_allow if g.program == "cat"]
    return g


# ===========================================================================  #
# §A — The containment model                                                   #
# ===========================================================================  #

def test_a1_shape_and_scope_both_required(env):
    """a1: a command is ALLOWED only if it matches a grant's `pattern` AND every operand
    `PROGRAMS[argv[0]]` extracts resolves into that grant's `scope`. Both halves are load-bearing:
    an in-scope operand under an ungranted SHAPE denies, and a granted shape with an out-of-scope
    operand denies. Only shape ∧ scope allows."""
    inv = f"{env.run}/investigation.md"
    assert _bash(env, f"cat {inv}", "main").allow                      # shape ∧ scope
    assert not _bash(env, "cat /etc/passwd", "main").allow             # shape, ✗scope
    assert not _bash(env, f"strings {inv}", "main").allow              # ✗shape, scope
    assert not _bash(env, f"nl -ba {inv}", "main").allow               # ✗shape (untabled program)


def test_a2_no_unmarked_grant_pattern_embeds_a_path(env):
    """a2 (negative): NO UNMARKED grant's `pattern` embeds a path. Sweep every compiled Grant of
    all 8 defs: a pattern carrying a literal/escaped run_dir, defender_dir, script or ticket-CLI
    path MUST carry `pins_path=True` (the R1 exemption). Positive control: the three exempt grants
    (actor python3-script, lead-author/curator rm, judge ticket-CLI) DO embed a path — so the audit
    can tell the two classes apart — and the SCOPE patterns DO carry the anchored roots (that is
    where a path belongs)."""
    pols = _all_policies(env)
    roots = (str(env.run), str(env.dfn), str(PATHS.repo_root))
    exempt_seen = 0
    for name, pol in pols.items():
        for g in pol.bash_allow:
            src = g.pattern.pattern
            if g.pins_path:
                exempt_seen += 1
                assert "/" in src, f"{name}: a pins_path grant that pins no path: {src}"
                continue
            assert "/" not in src, f"{name}: unmarked grant embeds a path: {src}"
            for root in roots:
                assert root not in src, f"{name}: unmarked grant embeds {root}: {src}"
    assert exempt_seen >= 3          # actor script, lead-author/curator rm, judge ticket
    # positive control: the anchored roots live in the SCOPE, not the shape
    cat_scope = " ".join(s.pattern for s in _cat_grant(pols["main"]).scope)
    assert str(env.run) in cat_scope or re.escape(str(env.run)) in cat_scope


def test_a3_under_fullmatches_the_resolved_path(env):
    """a3: `under(root, tail)` fullmatches the RESOLVED path — it is an allowlist entry over what
    `resolve()` returns, not over what the model typed. A same-file spelling that only resolve()
    can normalize (a symlinked root, a `.` segment) matches only AFTER resolution."""
    real = env.tmp / "real"
    real.mkdir()
    (real / "a.md").write_text("x\n")
    link = env.tmp / "link"
    os.symlink(real, link)
    pat = under(real.resolve(), r"a\.md")
    typed = link / "a.md"
    assert pat.fullmatch(str(typed.resolve()))     # resolved → matches
    assert not pat.fullmatch(str(typed))           # as typed → does not (containment MUST resolve)
    assert not pat.fullmatch(str(real / "b.md"))   # tail is a tight shape, not a subtree wildcard


def test_a4_path_shapes_are_tight_never_any_char_star(env):
    """a4 (negative): no path shape uses `[^\\x00]*` — that class admits spaces and newlines, so an
    approved path would not be a safe token downstream. Machine-generated paths get machine-tight
    grammars (`gather_raw/l-\\d+/\\d+\\.json`), pinned behaviorally: gather's own payload path
    ALLOWs, a free-form name at the same depth DENIES."""
    for name, pol in _all_policies(env).items():
        shapes = [s for g in pol.bash_allow for s in g.scope] + list(pol.read_allow)
        for s in shapes:
            assert "[^\\x00]*" not in s.pattern, f"{name}: loose path shape {s.pattern}"
    assert _bash(env, f"cat {env.run}/gather_raw/l-001/0.json", "gather").allow      # tight, real
    assert not _bash(env, f"cat {env.run}/gather_raw/l-001/evil.sh", "gather").allow  # not the shape
    assert not _bash(env, f"cat {env.run}/gather_raw/evil.json", "gather").allow      # wrong depth


def test_a5_symlink_escaping_the_root_denied(env):
    """a5 (negative, symlink): an IN-SHAPE path that is a symlink out of the root — `{run}/gather_raw/
    l-001/9.json` → /etc/passwd — DENIES for gather: resolve() collapses it to /etc/passwd, which no
    scope entry admits. (The path is in-shape on purpose; an out-of-shape `{run}/evil.json` would
    deny at the shape gate and never exercise resolve().) This is the hole the textual lane could not
    close at HEAD (`_common.py`'s no-symlink-writer side invariant).
    Positive control: the real `{run}/gather_raw/l-001/0.json` under the SAME grant ALLOWs."""
    evil = env.run / "gather_raw" / "l-001" / "9.json"
    os.symlink("/etc/passwd", evil)
    assert not _bash(env, f"cat {evil}", "gather").allow
    assert _bash(env, f"cat {env.run}/gather_raw/l-001/0.json", "gather").allow  # positive control


def test_a6_symlink_to_an_in_root_target_allowed(env):
    """a6: a symlink `{run}/gather_raw/l-001/1.json` → another IN-ROOT, in-shape file ALLOWs —
    a5 denies for the ESCAPE, not because symlinks are banned. Containment is where the path
    RESOLVES, nothing else."""
    link = env.run / "gather_raw" / "l-001" / "1.json"
    os.symlink(env.run / "gather_raw" / "l-001" / "0.json", link)
    assert _bash(env, f"cat {link}", "gather").allow


def test_a7_symlink_loop_fails_closed(env):
    """a7: a symlink LOOP makes `Path.resolve(strict=False)` raise `RuntimeError` (the one thing it
    does raise). It is in `_RESOLVE_ERRORS` → DENY, and no exception escapes decide_bash."""
    a = env.run / "gather_raw" / "l-002" / "0.json"
    b = env.run / "gather_raw" / "l-002" / "1.json"
    os.symlink(b, a)
    os.symlink(a, b)
    d = _bash(env, f"cat {a}", "gather")      # must not raise
    assert not d.allow


def test_a8_missing_and_broken_symlinks_are_judged_by_shape(env):
    """a8: `resolve(strict=False)` does NOT raise on a missing path or a broken symlink — it
    resolves lexically / through the link. So the verdict is by SHAPE of the RESOLVED path, never by
    existence: a not-yet-written `{run}/gather_raw/l-003/0.json` still ALLOWs for gather, and a
    broken link whose (missing) target is in-shape ALLOWs, while a broken link whose target escapes
    DENIES. (A gate that denied on non-existence would break every write-then-read flow.)"""
    (env.run / "gather_raw" / "l-003").mkdir()
    assert _bash(env, f"cat {env.run}/gather_raw/l-003/0.json", "gather").allow   # missing, in-shape
    ok = env.run / "gather_raw" / "l-003" / "1.json"
    os.symlink(env.run / "gather_raw" / "l-003" / "7.json", ok)                   # broken, in-shape
    assert _bash(env, f"cat {ok}", "gather").allow
    bad = env.run / "gather_raw" / "l-003" / "2.json"
    os.symlink("/etc/nope-does-not-exist", bad)                                   # broken, escapes
    assert not _bash(env, f"cat {bad}", "gather").allow


def test_a9_embedded_nul_operand_denies_without_raising(env):
    """a9: an embedded-NUL operand makes `Path.resolve()` raise `ValueError`, which is in
    `_RESOLVE_ERRORS` → DENY. The tool must not propagate it (a raise out of decide_bash is a
    500 in the driver, not a deny the model can retry)."""
    d = _bash(env, f"cat {env.run}/inv\x00.md", "main")   # must not raise
    assert not d.allow


def test_a10_scope_anchors_on_the_resolved_root(env):
    """a10: the scope anchors on the RESOLVED root. A run_dir reached through a symlink (the real
    shape of a symlinked `$DEFENDER_RUNS_BASE`) still ALLOWs `cat {run}/investigation.md`: the
    operand resolves to the real path, so the scope must be built from the resolved root too.
    Compile the scope from the UNRESOLVED root and every in-root read denies — the inverse failure
    of the resolution-semantics comment at `_common.py:250-259`."""
    real_base = env.tmp / "real-base"
    (real_base / "r1").mkdir(parents=True)
    (real_base / "r1" / "investigation.md").write_text("x\n")
    link_base = env.tmp / "runs"
    os.symlink(real_base, link_base)
    run = link_base / "r1"
    pol = compile_policy_for(MAIN_DEF, run_dir=run, defender_dir=env.dfn)
    d = permission.decide_bash(f"cat {run}/investigation.md", policy=pol,
                               run_dir=run, defender_dir=env.dfn)
    assert d.allow


def test_a11_relative_operand_is_rebased_on_the_executor_cwd(env):
    """a11: a RELATIVE operand is rebased on the executor's REAL cwd before resolve. Drop the
    rebase and the gate and the executor name different files: the gate would resolve against
    the ambient process cwd while bash opens from the executor's.

    Since #540 that cwd is the RUN DIR, not the repo root — it is the box's rw bind, the one
    directory that names the same thing inside the container and out, and it no longer anchors
    a relative operand one `..` from the repo's `.env`/`.ssh`. So `investigation.md` names the
    run's own artifact and ALLOWs, while the repo-relative corpus spelling now DENIEs: nothing
    hands MAIN that spelling any more, because `defender-lessons` emits ABSOLUTE paths (an
    absolute operand bypasses every anchor, which is how the lessons lane still works).

    Positive control: a relative path that escapes the run dir still DENIES — the rebase is a
    resolution rule, not a widening."""
    assert _bash(env, "cat investigation.md", "main").allow
    assert not _bash(env, "cat defender/lessons/x.md", "main").allow
    assert not _bash(env, "cat ../../etc/passwd", "main").allow


def test_a12_every_pipe_stage_is_gated(env):
    """a12: EVERY stage of a pipeline is gated, not just the first: `cat {run}/x.md | cat /etc/passwd`
    DENIES — the second stage's operand is scope-checked too. Positive control: the same pipe with
    both operands in scope ALLOWs."""
    inv = f"{env.run}/investigation.md"
    assert not _bash(env, f"cat {inv} | cat /etc/passwd", "main").allow
    assert _bash(env, f"cat {inv} | cat {env.run}/report.md", "main").allow  # positive control


# ===========================================================================  #
# §B — PROGRAMS, and the OPENS_NOTHING obligation                              #
# ===========================================================================  #

def test_b1_cat_is_the_sole_opener_in_the_program_table(env):
    """b1: `PROGRAMS["cat"]` is the real extractor (argv → file operands | None); EVERY other
    program any agent grants is `OPENS_NOTHING`. What a program opens is a fact about the PROGRAM,
    so it lives in one global table keyed by name — never duplicated onto grants, where two agents
    could represent a disagreement about what `cat` does."""
    assert PROGRAMS["cat"] is not OPENS_NOTHING
    assert PROGRAMS["cat"](["cat", "-n", "/x/a.md", "/x/b.md"]) == ["/x/a.md", "/x/b.md"]
    for name, pol in _all_policies(env).items():
        for g in pol.bash_allow:
            if g.program != "cat":
                assert PROGRAMS[g.program] is OPENS_NOTHING, f"{name}: {g.program} opens something"


def test_b2_compile_policy_raises_on_an_untabled_program(env):
    """b2: `compile_policy` RAISES when a grant names a program absent from `PROGRAMS`. Fail LOUD at
    compile — never fail-open at the first decide, which is what today's
    `_OPERAND_GATED_PROGRAMS.get(...) is None → True` pass-through (`bash.py:282-284`) does: an
    untabled program is silently ungated. Positive control: the same def with a TABLED program
    compiles."""
    def bad(_roots):
        return (Grant(program="strings", pattern=re.compile(r"^strings(?: [^ ]+)*$")),)

    def good(_roots):
        return (Grant(program="cat", pattern=re.compile(r"^cat(?: [^ ]+)*$")),)

    bad_def = dataclasses.replace(MAIN_DEF, bash_shapes=(bad,))
    with pytest.raises((KeyError, ValueError, TypeError)):
        compile_policy_for(bad_def, run_dir=env.run, defender_dir=env.dfn)
    ok_def = dataclasses.replace(MAIN_DEF, bash_shapes=(good,))
    assert compile_policy_for(ok_def, run_dir=env.run, defender_dir=env.dfn).bash_allow


def test_b3_every_registered_agents_policy_passes_the_table_check(env):
    """b3: EVERY AgentPolicy in the registry passes the program-table validation — INCLUDING
    CORPUS_AUTHOR's, which is built directly by `_corpus_author_policy` (via `CuratorDeps.for_run`)
    and never calls `compile_policy` today. It is the one denylist-free lane, so an untabled
    (=ungated) program there is the worst place for the fail-open to hide."""
    pols = _all_policies(env)
    assert len(AGENTS) == 8                              # the sweep below covers every role
    assert CORPUS_AUTHOR_DEF in AGENTS.values()
    assert "corpus_author" in pols                       # …including the un-bindable one
    for name, pol in pols.items():
        for g in pol.bash_allow:
            assert g.program in PROGRAMS, f"{name}: untabled program {g.program!r}"


@pytest.mark.parametrize("tok", ["-z", "-q", "--color", "--show-all", "-w", "-1", "--", "-nz"])
def test_b4_cat_extractor_fails_closed_on_unknown_dash_tokens(env, tok):
    """b4 (domain-outcome): `_cat_input_files` returns None → DENY for EVERY unrecognized
    `-`-prefixed token (the fail-closed rule that made `cat` the safe opener). `--` is in the list
    for a different reason — see b5: it ends options, so what follows is an OPERAND, and
    `cat -- /etc/passwd` must still be scope-checked."""
    inv = f"{env.run}/investigation.md"
    if tok == "--":
        assert not _bash(env, f"cat {tok} /etc/passwd", "main").allow
    else:
        assert not _bash(env, f"cat {tok} {inv}", "main").allow


def test_b4_cat_known_boolean_bundles_extract_the_operands(env):
    """b4 positive control: the known boolean bundles (`-n`, `-A`, `-vET`) are admitted and the file
    operands are extracted + scope-checked correctly — cat's whole short-flag set (`-A -b -e -E -n
    -s -t -T -u -v`) consumes NO argument, which is why it can have an extractor at all."""
    inv = f"{env.run}/investigation.md"
    for flags in ("-n", "-A", "-vET", "-n -s"):
        assert _bash(env, f"cat {flags} {inv}", "main").allow, flags
        assert not _bash(env, f"cat {flags} /etc/passwd", "main").allow, flags


def test_b5_cat_double_dash_operand_still_scope_checked(env):
    """b5 (domain-outcome): `cat -- /etc/passwd` → DENY. Post-`--` tokens ARE appended as file
    operands (`bash.py:243-245`), so they get scope-checked like any other. (An enumerator read this
    backwards and proposed a fail-open; pin it.)
    Positive control: `cat -- {run}/investigation.md` ALLOWs — `--` is not itself a denial."""
    assert not _bash(env, "cat -- /etc/passwd", "main").allow
    assert _bash(env, f"cat -- {env.run}/investigation.md", "main").allow


def test_b6_bare_dash_is_stdin_not_an_operand(env):
    """b6 (domain-outcome): a bare `-` is STDIN, not a file operand — the extractor drops it — so the
    stdin-pipe shape `cat {run}/x.md | cat -` still ALLOWs."""
    assert _bash(env, f"cat {env.run}/investigation.md | cat -", "main").allow


_FILE_OPENING_FLAGS = [
    "wc --files0-from=/etc/passwd",
    "grep --file=/etc/passwd x",
    "grep -f /etc/passwd x",
    "grep --exclude-from=/etc/passwd x",
    "grep -e x /etc/passwd",
    "grep -r x",
    "grep -R x",
    "tail -f /etc/passwd",
    "head -c 100 /etc/passwd",
]


@pytest.mark.parametrize("cmd", _FILE_OPENING_FLAGS)
@pytest.mark.parametrize("which", ["main", "gather"])
def test_b7_opens_nothing_shapes_admit_no_file_opening_flag(env, which, cmd):
    """b7 (negative, THE PRIME FAIL-OPEN): `OPENS_NOTHING` is a CLAIM, not a check — the gate skips
    the scope check for those programs entirely, so the SHAPE regex must earn it by admitting no
    file-opening / arg-consuming flag. Every one of these opens a file (or, for `-r`/`-R`, walks the
    CWD with no operand at all) and must DENY for main AND gather. If one lands, the operand it
    opens is never scope-checked — the gate is wide open on that program."""
    assert not _bash(env, cmd, which).allow


@pytest.mark.parametrize("stage", ["grep -n s", "wc -l", "head -5", "tail -3"])
def test_b7_stdin_forms_still_allowed(env, stage):
    """b7 positive control: the STDIN forms of the same programs still ALLOW — the migration takes
    away their file slot, not the programs. `cat {run}/x.md | grep -n s` is the substitute for
    every file-operand viewer form c1 removes; if these denied, the change would have cost real
    capability."""
    for which in ("main", "gather"):
        assert _bash(env, f"cat {env.run}/report.md | {stage}", which).allow, which


def test_b8_opens_nothing_shapes_admit_no_long_option_or_dash_positional(env):
    """b8 (negative, structural): over EVERY `OPENS_NOTHING` grant of every agent — its pattern
    admits no `--` long option and no `-`-prefixed positional. Today both are CONVENTIONS
    (`gnu_flags.bundle()` emits single-dash bundles only; the `(?!-)` free-text close from #579).
    A convention a future grammar author can silently drop is not a security property — this makes
    them ENFORCED, so the b7 list can never be reopened one flag at a time."""
    probes = ("--evil", "--evil=/etc/passwd", "--files0-from=/etc/passwd", "-ZZ9")
    checked = 0
    for name, pol in _all_policies(env).items():
        for g in _opens_nothing_grants(pol):
            checked += 1
            for probe in probes:
                for argv in (f"{g.program} {probe}", f"{g.program} x {probe}",
                             f"{g.program} {probe} x"):
                    assert not g.pattern.fullmatch(argv), f"{name}/{g.program}: admits {argv!r}"
    assert checked >= 5   # grep/head/tail/wc/jq at minimum — never iterate an empty set

    # Positive control: the SAME patterns still admit their legitimate short-bundle forms.
    # Without this the test passes for a grammar that admits nothing at all.
    admits = {
        "grep": "grep -n secret", "head": "head -5", "tail": "tail -3",
        "wc": "wc -l",
    }
    main_pol = _all_policies(env)["main"]
    for g in _opens_nothing_grants(main_pol):
        if g.program in admits:
            assert g.pattern.fullmatch(admits[g.program]), (
                f"{g.program}: rejects its own legitimate stdin form {admits[g.program]!r} — "
                "the b8 exclusions have over-tightened the lane into uselessness"
            )


# ===========================================================================  #
# §C — The lane after the change (the behavior-change ledger — BOTH sides)     #
# ===========================================================================  #

@pytest.mark.parametrize(("file_form", "pipe_form"), [
    ("grep -n secret {p}", "cat {p} | grep -n secret"),
    ("head -5 {p}", "cat {p} | head -5"),
    ("tail -3 {p}", "cat {p} | tail -3"),
    ("wc -l {p}", "cat {p} | wc -l"),
])
def test_c1_file_operand_viewers_lose_their_file_slot(env, file_form, pipe_form):
    """c1 (domain-outcome, behavior change #1 — BOTH sides pinned): grep/head/tail/wc/jq lose their
    file-operand slot and become stdin-only pipe stages. The file form DENIES (it ALLOWed at HEAD —
    this is the documented change), the `cat … |` form ALLOWs. Identical capability, one extra
    `cat |`; and with no file slot, those programs open nothing and need no anchor at all."""
    p = f"{env.run}/investigation.md"
    for which in ("main", "gather"):
        assert not _bash(env, file_form.format(p=p), which).allow, f"{which}: {file_form}"
        assert _bash(env, pipe_form.format(p=p), which).allow, f"{which}: {pipe_form}"


def test_c2_ls_and_cd_are_deleted_from_the_lane(env):
    """c2 (negative, behavior change #2): `ls` and `cd` — in ANY form — DENY for main and gather.
    `ls`'s anchored DIR operand was the other path-opening slot, and a fixed cwd is what makes the
    `-I`/`-r`-falls-back-to-the-CWD bug class (#579) structurally impossible.
    Positive control: the surviving programs still ALLOW."""
    for which in ("main", "gather"):
        for cmd in ("ls", f"ls {env.run}", f"ls -la {env.run}", f"ls {env.run}/gather_raw",
                    f"cd {env.run}", f"cd {env.dfn} && defender-lessons --tags"):
            assert not _bash(env, cmd, which).allow, f"{which}: {cmd}"
        assert _bash(env, f"cat {env.run}/investigation.md", which).allow, which    # control
        assert _bash(env, "defender-lessons --tags", which).allow, which            # control


def test_c3_main_has_no_recursive_descent_primitive(env):
    """c3 (negative): main has NO recursive-descent primitive — `ls -R {run}` and `grep -r x {run}`
    DENY. This is the property that made the (now-deleted) textual raw clamp complete rather than
    lucky (`_common.py:117-122`): recursion is the one primitive that reaches a subtree WITHOUT
    naming it. Positive-enumeration containment must not hand it back."""
    for cmd in (f"ls -R {env.run}", f"ls -lR {env.run}", f"grep -r x {env.run}",
                f"grep -R x {env.run}"):
        assert not _bash(env, cmd, "main").allow, cmd
        assert not _bash(env, cmd, "gather").allow, cmd


def test_c4_shipped_query_template_command_survives(env):
    """c4 (survival): the LITERAL command from the shipped query template
    (`skills/gather/queries/host-state/container-identity-and-uid.md:28`) still ALLOWs for gather.
    A shipped template the gate denies is a documented dead command — the worst kind, because the
    agent is TOLD to run it."""
    payload = f"{env.run}/gather_raw/l-001/0.json"
    cmd = f"""cat {payload} | defender-sql "SELECT * FROM data WHERE uid = '1000'" """
    assert _bash(env, cmd, "gather").allow


def test_c5_raw_marker_substring_scan_is_gone(env):
    """c5 (behavior change #3): the `RAW_MARKER in cmd` substring scan is DELETED.
    `cat {run}/report.md | grep gather_raw` → ALLOW for main: it opens report.md (in scope) and
    nothing touches gather_raw — `gather_raw` is a grep PATTERN here, not a path. At HEAD this
    DENIES (verified). Containment is now positive enumeration over the RESOLVED operand, so a
    substring of the command text decides nothing.
    Positive control (the property that must NOT regress): main still cannot read the payload —
    see d1/d2."""
    assert _bash(env, f"cat {env.run}/report.md | grep gather_raw", "main").allow
    assert not _bash(env, f"cat {env.run}/gather_raw/l-001/0.json", "main").allow


def test_c6_curator_lane_loses_its_file_operands_and_ls(env):
    """c6 (survival, curator behavior change #4): the curator's private viewer copy folds onto the
    same lane. `grep -l 'source_signature:.*x' {dfn}/lessons/a.md` DENIES (file operand gone) while
    `cat {dfn}/lessons/a.md | grep -l 'source_signature:.*x'` ALLOWs; `ls {dfn}/lessons/` DENIES —
    the #574 corpus manifest replaces the listing. This is the one denylist-free lane, so the
    anchored operand was its sole containment; resolve()+scope replaces it."""
    cur = _curator(env)
    a = f"{env.dfn}/lessons/a.md"
    assert not _bash(env, f"grep -l 'source_signature:.*x' {a}", cur).allow
    assert _bash(env, f"cat {a} | grep -l 'source_signature:.*x'", cur).allow
    assert not _bash(env, f"ls {env.dfn}/lessons/", cur).allow
    assert not _bash(env, f"ls {env.dfn}/lessons", cur).allow


# ===========================================================================  #
# §D — gather_raw, positive enumeration, and the read surface                  #
# ===========================================================================  #

def test_d1_gather_raw_bash_allow_for_gather_deny_for_main(env):
    """d1 (domain-outcome): `cat {run}/gather_raw/l-001/0.json` → ALLOW for gather, DENY for main —
    on the bash lane. Same shape, same extractor, same operand: it resolves, and the GATHER_RAW
    shape is simply NOT IN MAIN'S LIST. Main is not "denied gather_raw" by a clamp; it never had it.
    The layout is the real one (`gather_raw/{lead_id}/{seq}.json`)."""
    raw = f"cat {env.run}/gather_raw/l-001/0.json"
    assert _bash(env, raw, "gather").allow
    assert not _bash(env, raw, "main").allow


def test_d2_decide_read_denies_main_gather_raw_with_the_e2e_reason(env):
    """d2 (behavior): `decide_read(main, {run}/gather_raw/l-001/0.json)` → DENY. `raw_reads` is
    deleted, so `files.py:173`'s clamp is gone — the DENY must now come from the READ-SIDE positive
    enumeration (the gather_raw shape is not in main's `read_allow`). The e2e deny-tail asserts the
    REASON substring, so the message must still name gather_raw
    (`tests/e2e/test_replay_skeleton.py:152-179` — do NOT relax that assertion).
    Positive control: gather reads the same payload, and main reads the summary."""
    raw = f"{env.run}/gather_raw/l-001/0.json"
    d = _read(env, raw, "main")
    assert not d.allow
    assert "must not read gather_raw" in (d.reason or "")
    assert _read(env, raw, "gather").allow                                     # positive control
    assert _read(env, f"{env.run}/gather_summaries/l-001.md", "main").allow    # positive control


def test_d3_gather_raw_stays_untrusted_read(env):
    """d3 (negative): `is_untrusted_read({run}/gather_raw/l-001/0.json)` is True — the payload read is
    still SALT-TAG WRAPPED. Deleting `RAW_MARKER` is a deletion of the CLAMP, not of the trust
    boundary: gather_raw is the primary attacker-influenced channel, and untagging it fails the
    prompt-injection defense OPEN (the model can no longer tell data from instructions).
    Positive control: `{run}/investigation.md` (the agent's own log) is NOT untrusted, and
    `alert.json` (the other attacker-influenced input) still IS."""
    assert permission.is_untrusted_read(env.run / "gather_raw" / "l-001" / "0.json")
    assert permission.is_untrusted_read(env.run / "gather_raw" / "l-001.lead.json")
    assert permission.is_untrusted_read(env.run / "alert.json")
    assert not permission.is_untrusted_read(env.run / "investigation.md")
    assert not permission.is_untrusted_read(env.run / "gather_summaries" / "l-001.md")


def test_d4_read_and_bash_scopes_are_the_same_objects(env):
    """d4 (parity): read↔bash parity is STRUCTURAL, not maintained. For MAIN and GATHER the shape
    tuple `decide_read` enforces IS — identity, not equality-by-luck — the tuple the `cat` grant's
    `scope` carries. That is what makes `read_shapes` / `reader_read_shapes` deletable: there is
    one object, so the two surfaces cannot drift.
    FALSIFICATION (the guard against a vacuous identity check): a policy whose read scope and cat
    scope are different objects must FAIL this same harness."""
    def same_objects(pol) -> bool:
        return pol.read_allow is _cat_grant(pol).scope

    assert same_objects(env.main)
    assert same_objects(env.gather)
    forged = dataclasses.replace(
        env.main,
        read_allow=tuple(env.main.read_allow),   # equal by value, a DIFFERENT object
    )
    assert not same_objects(forged)              # the harness can fail → it is not vacuous


_MATRIX_PATHS = [
    "{run}/investigation.md",
    "{run}/report.md",
    "{run}/alert.json",
    "{run}/executed_queries.jsonl",
    "{run}/gather_summaries/l-001.md",
    "{run}/gather_raw/l-001/0.json",
    "{run}/gather_raw/l-001.lead.json",
    "{dfn}/lessons/x.md",
    "{dfn}/docs/x.md",
    "{dfn}/fixtures/held-out/m01/ground_truth.yaml",
    "/etc/passwd",
]


@pytest.mark.parametrize("which", ["main", "gather"])
@pytest.mark.parametrize("tmpl", _MATRIX_PATHS)
def test_d5_read_bash_allow_matrix_agrees(env, which, tmpl):
    """d5 (parity, parametrized — the ALLOW-MATRIX): for each (agent, path),
    `decide_read(path).allow == decide_bash(f"cat {path}").allow`. The corpus spans every artifact a
    real run touches plus the two denied classes (the held-out ground truth inside defender_dir, and
    an out-of-root path). This is the whole point of sharing the shape objects: if the two surfaces
    can disagree on ANY of these, `read_allow` and the cat grant's scope have drifted."""
    p = tmpl.format(run=env.run, dfn=env.dfn)
    assert _read(env, p, which).allow == _bash(env, f"cat {p}", which).allow, p


def test_d6_denylist_still_applies_inside_scope(env):
    """d6: the secret denylist still applies INSIDE the scope — being in-shape is necessary, not
    sufficient. `{dfn}/lessons/.env.md` matches the corpus `.md` shape and `{run}/x/.ssh/id_rsa` sits
    under the run root, and both DENY on BOTH surfaces (basename substring + path-component axes).
    Positive control: `{dfn}/lessons/notes.md` — same dir, benign name — ALLOWs on both."""
    for secret in (f"{env.dfn}/lessons/.env.md", f"{env.run}/x/.ssh/id_rsa"):
        assert not _bash(env, f"cat {secret}", "main").allow, secret
        assert not _read(env, secret, "main").allow, secret
    ok = f"{env.dfn}/lessons/notes.md"
    assert _bash(env, f"cat {ok}", "main").allow
    assert _read(env, ok, "main").allow


# ===========================================================================  #
# §E — The exempt (`pins_path`) grants                                         #
# ===========================================================================  #

def test_e1_judge_ticket_grant_still_requires_require_closed(env):
    """e1 (negative — THE JUDGE'S SECURITY PROPERTY): `<py> <ticket-cli> get-ticket case-1` with NO
    `--require-closed` → DENY. `--require-closed` is what stops the benign judge grading against the
    live, in-flight ticket (the answer key). A boolean-flag allowlist makes every flag OPTIONAL, so
    a mechanical migration of `_ticket_pattern` into a flag grammar drops the requirement SILENTLY —
    which is exactly why this grant is `pins_path` (kept verbatim, lookahead included).
    Positive control: the same CLI WITH `--require-closed` ALLOWs."""
    py, cli = _ticket_cli(env)
    pol = _judge(env, ticket_cli=(py, cli))
    assert not _bash(env, f"{py} {cli} get-ticket case-1", pol).allow
    assert _bash(env, f"{py} {cli} list-tickets --require-closed", pol).allow   # positive control
    assert _bash(env, f"{py} {cli} get-ticket case-1 --require-closed", pol).allow


def test_e2_adversarial_judge_has_no_ticket_grant(env):
    """e2: the adversarial judge (`RunScope(ticket_cli=None)`) carries NO ticket grant at all — even
    the well-formed `… list-tickets --require-closed` DENIES. The case store is unreachable by
    construction, not by flag."""
    py, cli = _ticket_cli(env)
    pol = _judge(env, ticket_cli=None)
    assert not _bash(env, f"{py} {cli} list-tickets --require-closed", pol).allow
    assert not any(g.program.endswith("case_ticket.py") for g in pol.bash_allow)


def test_e3_require_closed_cannot_be_smuggled_in_a_quoted_operand(env):
    """e3: `--require-closed` cannot be smuggled inside a QUOTED operand:
    `<py> <cli> get-ticket "x --require-closed"` → DENY. The `_TOKEN_SPACE` NUL sentinel replaces
    each token's own spaces, so every real space in the joined argv is a true token boundary and the
    lookahead can only be satisfied by a whole token."""
    py, cli = _ticket_cli(env)
    pol = _judge(env, ticket_cli=(py, cli))
    assert not _bash(env, f'{py} {cli} get-ticket "x --require-closed"', pol).allow


def test_e4_actor_script_and_lead_author_rm_survive(env):
    """e4: the other two exempt grants still work and still contain. The actor's pinned
    `python3 <script>` ALLOWs while `python3 /etc/evil.py` DENIES; the lead author's
    `rm {skills}/<name>.md` ALLOWs while `rm {skills}/../../etc/passwd` DENIES (rm unlinks the LINK,
    not the target — resolve() is the wrong operand model for it, which is why it stays a pattern)."""
    actor = _actor(env)
    assert _bash(env, f"python3 {_ENV_RETRIEVE} --tags", actor).allow
    assert not _bash(env, "python3 /etc/evil.py", actor).allow
    la = _lead_author(env)
    assert _bash(env, f"rm {env.dfn}/skills/_draft/x.md", la).allow
    assert not _bash(env, f"rm {env.dfn}/skills/../../etc/passwd", la).allow


# ===========================================================================  #
# §F — Routing, Decision, and layering                                         #
# ===========================================================================  #

def test_f1_bash_decision_carries_the_single_parse_and_no_adapter_route(env):
    """f1 (demand #0): `BashDecision` carries `pipelines` (the #456 single parse
    `bash_exec.run_parsed` consumes) and `grants` (the claiming grants). Since #611 it carries NO
    adapter routing payload — `adapter_argv` / `sql_pipe` are gone with the capture-from-bash layer
    that read them, and `Route` has ONE member (`PLAIN`), so no grant on any lane carries an adapter
    route. `Grant.route` still TAGS reader-lane grants; there is simply one tag left."""
    d = _bash(env, f"cat {env.run}/investigation.md", "main")
    assert d.allow
    assert d.pipelines
    assert not hasattr(d, "adapter_argv")
    assert not hasattr(d, "sql_pipe")
    # the adapter is unreachable from gather's bash lane; it denies for the query-tool reason
    a = _bash(env, "defender-elastic query 'x'", "gather")
    assert not a.allow
    assert a.reason == permission.ADAPTER_RETIRED_REASON
    # every grant on every lane is PLAIN — the capture routes were the capability, and it moved
    assert {g.route for g in env.gather.bash_allow} == {Route.PLAIN}
    assert list(Route) == [Route.PLAIN]
    assert _cat_grant(env.gather).route is Route.PLAIN


def test_f2_reader_lane_claims_before_adapter_classification(env):
    """f2: adapter classification stays STRUCTURAL and runs AFTER the reader lane returns None —
    the ORDER, not just the verdict. An adapter-SHAPED command that a grant claims is decided by the
    grant: the judge's ticket read is `python3 <cli> …` (adapter-shaped), and the judge has no
    adapter capability — yet it ALLOWs, and is NOT diverted to the adapter deny. Reverse the order
    and the judge loses its case-history read outright."""
    py, cli = _ticket_cli(env)
    pol = _judge(env, ticket_cli=(py, cli))
    d = _bash(env, f"{py} {cli} list-tickets --require-closed", pol)
    assert d.allow
    # claimed by the grant, so it did NOT fall through to the adapter deny
    assert d.reason != permission.ADAPTER_RETIRED_REASON
    assert not hasattr(d, "adapter_argv")
    assert not hasattr(d, "sql_pipe")


@pytest.mark.parametrize(("cmd", "reason_substr"), [
    ("defender-elastic query foo", "not runnable from bash"),
    ("curl http://example.invalid/x", "only the defender-* shims"),
])
def test_f3_adapter_deny_reasons_survive(env, cmd, reason_substr):
    """f3 (parametrized): the two SPECIFIC deny reasons survive the rebuild — the e2e deny-tail
    asserts them as SUBSTRINGS (`test_replay_skeleton.py`), and they are prompt surface. Since #611
    the adapter reason points at the `query` TOOL (the surface that DOES work), not at "dispatch
    gather / run a standalone adapter" — a reason naming a dead route teaches a dead command. The
    curl case still gets the generic fall-through naming the shims. A generic reason for the adapter
    case is an e2e break AND a worse agent."""
    d = _bash(env, cmd, "main")
    assert not d.allow
    assert reason_substr in (d.reason or "")


def test_f4_adapter_sql_pipe_is_now_tool_then_bash_and_nothing_else(env):
    """f4 FLIP: the sanctioned `defender-elastic query X | defender-sql '<SQL>'` capture+aggregate
    pipe is GONE (#611). Its adapter stage is unreachable from bash — the whole pipe DENIES for
    gather with the query-tool reason — because a data source is reached through the `query` tool.
    What survives is the aggregation HALF as a separate bash step over a payload already on disk:
    `cat <ABSOLUTE payload> | defender-sql '<SQL>'` ALLOWs. `… | head` still denies (an arbitrary
    reader stage is not `defender-sql`), and main reaches no payload."""
    old = "defender-elastic query 'x' | defender-sql 'SELECT count(*) FROM data'"
    d = _bash(env, old, "gather")
    assert not d.allow
    assert d.reason == permission.ADAPTER_RETIRED_REASON
    # the surviving aggregation step, over an in-scope payload
    new = f"cat {env.run}/gather_raw/l-001/0.json | defender-sql 'SELECT count(*) FROM data'"
    assert _bash(env, new, "gather").allow
    # `adapter | head` — the old "output only into defender-sql, never an arbitrary reader" case —
    # denies for the adapter reason now (the adapter stage is unreachable, whatever is downstream).
    assert not _bash(env, "defender-elastic query 'x' | head -5", "gather").allow
    assert not _bash(env, old, "main").allow
    assert not _bash(env, new, "main").allow


def test_f5_runtime_imports_no_learning_private_and_enumerates_no_agent(env):
    """f5 (negative, layering): an AST walk over `defender/runtime/**` finds NO import of a
    `defender.learning.*` name beginning with `_` — function-body/lazy imports COUNT (today
    `_bash_allow` lazily imports `_judge_policy`/`_actor_policy`/`_rm_skills_pattern` at
    `agent_definition.py:275,278,285`), and nothing under `runtime/` enumerates agents (the registry
    moves out to `defender/agents.py`). Each engine hangs its OWN `bash_shapes` builder on its OWN
    def, which inverts the dependency.
    Positive control: the relocated `defender/agents.py` DOES import the 6 `*_DEF`s — proof the scan
    SEES such an import when one is present (a scan that finds nothing because it looks in the wrong
    place is the failure mode this control kills)."""
    runtime_dir = _DEFENDER / "runtime"
    offenders = []
    for py in sorted(runtime_dir.rglob("*.py")):
        tree = ast.parse(py.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and (node.module or "").startswith("defender.learning"):
                for alias in node.names:
                    if alias.name.startswith("_") or (node.module or "").split(".")[-1].startswith("_"):
                        offenders.append(f"{py.name}: from {node.module} import {alias.name}")
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.startswith("defender.learning") and "._" in alias.name:
                        offenders.append(f"{py.name}: import {alias.name}")
    assert offenders == [], offenders
    assert not (runtime_dir / "agents.py").exists()      # the registry left runtime/
    # positive control: the scan's shape DOES see the relocated registry's def imports
    reg = ast.parse((_DEFENDER / "agents.py").read_text())
    imported = {a.name for n in ast.walk(reg) if isinstance(n, ast.ImportFrom) for a in n.names}
    assert {"JUDGE_DEF", "ACTOR_DEF", "ORACLE_DEF", "VERIFY_DEF", "LEAD_AUTHOR_DEF",
            "CORPUS_AUTHOR_DEF"} <= imported


# ===========================================================================  #
# §G — Prompt surface (a dead program named in a prompt teaches a dead command)#
# ===========================================================================  #

# Words that appear inside backticks / slash-groups in the deny reasons but are NOT program
# names (paths, English). NEVER a program name — a dead PROGRAM must not be excusable here,
# which is the whole point of not grepping for a hardcoded dead-name list.
_NON_PROGRAM_WORDS = frozenset({
    "defender", "lessons", "skills", "examples", "docs", "read", "write", "edit", "file",
    "only", "the", "and", "or", "with", "shims", "viewers", "tool", "tools", "bash", "run",
    "stdin", "pipe", "path", "paths", "dir", "md", "json", "sql", "yaml",
    # #611: `query` is the name of the TOOL the adapter/gather deny reasons point at, not a bash
    # program — naming it is the CORRECT prompt surface (the whole point of #611), the mirror of
    # "read"/"write"/"tool" above. It is deliberately NOT runnable from any bash lane.
    "query",
})
_PROGRAMISH = re.compile(r"(?<![\w/.-])([a-z][a-z0-9-]{1,15}(?:/[a-z][a-z0-9-]{1,15})+)(?![\w/.-])")
_BACKTICKED = re.compile(r"`([a-z][a-z0-9-]{1,15})`")


def _named_programs(text: str) -> set[str]:
    """Program-LOOKING words in a prompt-surface string: the members of a slash-group
    (`jq/ls/cat`) and bare backticked words (`` `ls` ``), minus the English/path vocabulary."""
    words: set[str] = set()
    for group in _PROGRAMISH.findall(text):
        words |= set(group.split("/"))
    words |= set(_BACKTICKED.findall(text))
    return {w for w in words if w not in _NON_PROGRAM_WORDS}


def test_g1_no_deny_reason_or_hint_names_a_program_the_agent_cannot_run(env):
    """g1 (negative): NO `deny_reason` and no `_overflow_filter_hint` output names a program the
    agent cannot run. A deny reason is PROMPT SURFACE: a reason naming a dead program teaches a dead
    command, and the agent burns turns on it. Catches `policies/main.py:18` + `policies/gather.py:22`
    (which name the DELETED `ls`) and `bash.py:70` (which tells gather to "filter the persisted
    payload FILE with jq/grep" — after both lose their file slot).
    Derived from the LIVE lane, never a hardcoded dead-name list: it must keep working after the
    next deletion."""
    seen = 0
    for name, pol in _all_policies(env).items():
        granted = {g.program for g in pol.bash_allow}
        text = (pol.deny_reason or "") + "\n" + tools._overflow_filter_hint(
            f"{env.run}/gather_raw/l-001/0.json", pol)
        for prog in _named_programs(text):
            seen += 1
            assert prog in granted, f"{name}: names {prog!r}, which its own lane denies"

    # Positive controls. Without these the test is VACUOUS: it passes for an extractor that
    # finds no programs at all, and for a reason set that has been emptied to dodge it.
    assert seen >= 3, (
        "_named_programs found no program names in ANY deny reason or overflow hint — "
        "the extractor is blind, so this test proves nothing"
    )
    # (a) the extractor demonstrably FINDS a program that IS on the lane,
    assert "cat" in _named_programs("only the read-only viewers (cat/grep) are permitted")
    # (b) and it demonstrably CATCHES a reason naming a program the lane denies.
    assert "ls" in _named_programs("only the read-only viewers (jq/ls/cat) are permitted")
    assert "ls" not in {g.program for g in _all_policies(env)["main"].bash_allow}


def test_g2_overflow_hint_reaches_the_right_branch_through_the_real_seam(env):
    """g2: `_overflow_filter_hint` still reaches the `jq` branch for main/gather (`cat <path> | jq
    '<filter>'`), the `defender-sql` branch for the judge, and the read-tool fold for the rest.
    `tools._lane_admits` (`tools.py:58-62`) probes with `p.fullmatch(probe)` over `policy.bash_allow`
    — an AttributeError IN PRODUCTION once that tuple holds `Grant`s (a Grant has no `.fullmatch`).
    It must go through the REAL decide seam, so the hint can never disagree with the gate."""
    path = f"{env.run}/gather_raw/l-001/0.json"
    for which in ("main", "gather"):
        hint = tools._overflow_filter_hint(path, getattr(env, which))
        assert f"cat {path} | defender-sql" in hint, which
        assert "jq" not in hint, which
    jhint = tools._overflow_filter_hint(path, _judge(env, ticket_cli=_ticket_cli(env)))
    assert "defender-sql" in jhint
    assert "jq" not in jhint
    ahint = tools._overflow_filter_hint(path, _actor(env), read_tool="read_file")
    assert "read_file" in ahint
    assert "pattern=" in ahint


# ===========================================================================  #
# §H — Lifecycle                                                               #
# ===========================================================================  #

def _projection(pol) -> tuple:
    """A comparable projection of a policy (Patterns → their source strings)."""
    return (
        tuple((g.program, g.pattern.pattern, tuple(s.pattern for s in g.scope), g.route,
               g.pins_path) for g in pol.bash_allow),
        tuple(s.pattern for s in pol.read_allow),
        tuple(s.pattern for s in pol.write_allow),
        tuple(str(r) for r in pol.read_roots),
        pol.deny_reason,
    )


def test_h1_compile_policy_for_is_idempotent(env):
    """h1: compiling the same (def, roots) twice yields an EQUAL policy — the compile is a pure
    projection of declared data, with no accumulated or cached state leaking between calls
    (`tools_gather.py:325` binds GATHER_DEF once per DISPATCH, many times per run)."""
    for defn in (MAIN_DEF, GATHER_DEF):
        a = compile_policy_for(defn, run_dir=env.run, defender_dir=env.dfn)
        b = compile_policy_for(defn, run_dir=env.run, defender_dir=env.dfn)
        assert _projection(a) == _projection(b)


def test_h2_no_cross_run_bleed(env):
    """h2: two runs with DIFFERENT run_dirs in ONE process produce policies whose scopes anchor on
    their OWN run_dir. The #497/#534 hazard is real here — `reader_patterns_for` is
    `@lru_cache(maxsize=1)` today while `resolve_roots` is deliberately UNCACHED — and a cache keyed
    on anything but the run would hand run B's agent a scope anchored on run A's dir: it could read
    another investigation's payloads, and could not read its own."""
    run_b = env.tmp / "run-b"
    (run_b / "gather_raw" / "l-001").mkdir(parents=True)
    (run_b / "investigation.md").write_text("x\n")
    pol_b = compile_policy_for(MAIN_DEF, run_dir=run_b, defender_dir=env.dfn)
    a_inv, b_inv = f"{env.run}/investigation.md", f"{run_b}/investigation.md"
    ok_a = permission.decide_bash(f"cat {a_inv}", policy=env.main,
                                  run_dir=env.run, defender_dir=env.dfn)
    ok_b = permission.decide_bash(f"cat {b_inv}", policy=pol_b,
                                  run_dir=run_b, defender_dir=env.dfn)
    cross = permission.decide_bash(f"cat {a_inv}", policy=pol_b,
                                   run_dir=run_b, defender_dir=env.dfn)
    assert ok_a.allow
    assert ok_b.allow
    assert not cross.allow


def test_h3_denylist_contributes_no_regex_lookahead(env):
    """h3: the empty-denylist footgun cannot brick the lane, BY CONSTRUCTION. At HEAD the denylist is
    baked into the reader regexes as a negative lookahead, so an empty axis would produce an empty
    `(?:)` alternation that matches everywhere and flips the lookahead to deny EVERY operand
    (`test_empty_denylist_does_not_brick_reader_lane` guards it). After the rebuild the denylist is
    applied at resolve() time (`files._denylisted`), not compiled into a shape: no path shape carries
    a lookahead at all, so emptying the config can subtract nothing.
    Positive controls: a denylisted in-scope path still DENIES (the denylist is still ENFORCED — see
    d6), and an ordinary in-scope read still ALLOWs (the lane is not bricked)."""
    for name, pol in _all_policies(env).items():
        for s in [s for g in pol.bash_allow for s in g.scope] + list(pol.read_allow):
            assert "(?!" not in s.pattern, f"{name}: path shape carries a lookahead: {s.pattern}"
    assert not _bash(env, f"cat {env.dfn}/lessons/.env.md", "main").allow   # still enforced
    assert _bash(env, f"cat {env.run}/investigation.md", "main").allow      # not bricked


# ===========================================================================  #
# §I — The audit CLI                                                          #
# ===========================================================================  #

def _cli(*args, cwd=None) -> subprocess.CompletedProcess:
    return subprocess.run(  # noqa: S603 — the pinned in-repo shim, fixed argv
        [str(_POLICY_CLI), *args], capture_output=True, text=True, timeout=60, cwd=cwd,
    )


def test_i1_policy_show_prints_grants_and_never_a_misleading_empty_scope(env):
    """i1: `defender-policy show <agent> --run-dir X` prints each agent's read / write / bash grants
    with their scopes. The reason "how did this resolve?" takes effort today is that there is NO
    tool — everyone hand-rolls a `bind(MAIN_DEF, …)` probe. An EXEMPT (`pins_path`) grant must report
    its PATTERN as the containment, never a misleading `scope: []` — an empty scope on an exempt
    grant reads as "unconfined" when the pattern IS the confinement."""
    p = _cli("show", "main", "--run-dir", str(env.run))
    assert p.returncode == 0, p.stderr
    out = p.stdout
    for word in ("cat", "read", "write", "bash"):
        assert word in out
    assert str(env.run) in out                      # the scopes are the RESOLVED roots
    assert "ls" not in _named_programs(out)         # a deleted program is not advertised
    j = _cli("show", "judge", "--run-dir", str(env.run))
    assert j.returncode == 0, j.stderr
    for line in j.stdout.splitlines():
        if "--require-closed" in line:              # the exempt ticket grant's line
            assert "scope: []" not in line
            break
    else:
        pytest.fail("defender-policy show judge did not report the exempt ticket grant's pattern")


@pytest.mark.parametrize("cmd", [
    "cat {run}/investigation.md",
    "cat {run}/gather_raw/l-001/0.json",
    "cat /etc/passwd",
    "grep -n secret {run}/investigation.md",
    "cat {run}/report.md | grep -n secret",
    "defender-elastic query foo",
    "ls {run}",
])
@pytest.mark.parametrize("which", ["main", "gather"])
def test_i2_policy_explain_is_a_second_consumer_not_a_second_implementation(env, which, cmd):
    """i2 (differential): over a corpus of (agent, command), `defender-policy explain` reports the
    SAME verdict AND the same matched-grant / deny-reason as `decide_bash`. The CLI is a second
    CONSUMER of the gate, never a second implementation — an audit tool that models the gate
    separately is worse than none: it certifies a policy nobody runs."""
    c = cmd.format(run=env.run, dfn=env.dfn)
    p = _cli("explain", which, c, "--run-dir", str(env.run), "--defender-dir", str(env.dfn),
             "--json")
    assert p.returncode == 0, p.stderr
    got = json.loads(p.stdout)
    d = _bash(env, c, which)
    assert got["allow"] == d.allow, c
    if d.allow:
        assert got["grant"], c                       # which grant matched
    else:
        assert got["reason"] == (d.reason or ""), c  # the SAME deny reason the model sees


def test_i3_defender_policy_is_not_a_shim_any_agent_can_run(env):
    """i3 (negative): `defender-policy` is NOT in `NON_ADAPTER_SHIMS` and DENIES on every agent lane.
    Adding it to `hooks/_cmd_segments.py:56` would hand every agent free policy introspection via
    `_shim_names` — a read of its own gate, which is a map of what to attack (and, for the judge, of
    exactly which grants stand between it and the answer key).
    Positive control: the shims that ARE sanctioned still run."""
    assert "defender-policy" not in NON_ADAPTER_SHIMS
    for name, pol in _all_policies(env).items():
        assert not _bash(env, f"defender-policy show main --run-dir {env.run}", pol).allow, name
    assert _bash(env, "defender-lessons --tags", "main").allow      # positive control


# ─────────────────────────────────────────────────────────────────────────────
# §F (cont.) — R1's obligation: the outbound channel to the executor.
#
# The gate parses ONCE and the executor runs `decision.pipelines` (#456,
# tools.py:301 hands `list(decision.pipelines or ())` straight to run_parsed).
# Nothing today asserts that what the executor RECEIVES is what the gate GATED —
# and that gap IS the validator/executor parser differential the no-shell lane
# (#379) exists to close. R1 computed this; no lens volunteered it.
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "cmd",
    [
        "cat {run}/investigation.md",
        "cat {run}/investigation.md | grep -n secret",
        "cat {run}/report.md | wc -l",
        "defender-lessons --tags",
    ],
)
def test_f6_executed_argv_is_the_gated_argv(env, cmd):
    """f6 — the argv EXECUTED is the argv GATED.

    `decision.pipelines` (what tools.py hands run_parsed) must be exactly the
    decomposition `bash_exec.parse` produces for the same command — so the
    executor never re-parses the raw string and no parser differential can
    reopen. Compared as argv structure, not object identity."""
    from defender.hooks._cmd_segments import unwrap
    from defender.runtime import bash_exec

    resolved = cmd.format(run=env.run)
    decision = _bash(env, resolved, "main")
    assert decision.allow, resolved

    gated = [[list(st.argv) for st in pl.stages] for pl in (decision.pipelines or ())]
    executed = [[list(st.argv) for st in pl.stages] for pl in bash_exec.parse(unwrap(resolved))]
    assert gated == executed, (
        f"the gate approved {gated!r} but the executor would run {executed!r} — "
        "a validator/executor parser differential"
    )


def test_f6_denied_command_carries_no_executable_pipeline(env):
    """f6 (positive control) — a DENIED command hands the executor nothing.

    Proves the observation channel can see the difference: an allowed command
    carries a non-empty `pipelines`, a denied one carries nothing to run."""
    denied = _bash(env, "cat /etc/passwd", "main")
    assert not denied.allow
    assert not denied.pipelines


# ─────────────────────────────────────────────────────────────────────────────
# §H (cont.) — h4: the PATHS-relocation hazard (#562).
#
# `check_actors` surfaced this: `harness_lead.py` and `replay_actor.py` re-exec
# as subprocesses and RELOCATE the tree anchor onto whatever tree they run in.
# LEAD_AUTHOR_DEF is `requires_explicit_tree=True` and is bound with a WORKTREE
# `defender_dir`. If a grant's scope/pattern is compiled from the module-level
# `PATHS` constant instead of the threaded `defender_dir`, a worktree run gets
# grants anchored on the MAIN CHECKOUT — it would delete the wrong tree's files.
# ─────────────────────────────────────────────────────────────────────────────


def test_h4_grants_anchor_on_the_threaded_tree_not_module_paths(tmp_path):
    """h4 — grants anchor on the defender_dir THREADED IN, never on import-time PATHS.

    Bind the lead author against a worktree tree: its `rm` grant must admit that
    worktree's skills dir and DENY the main checkout's. The two trees differ, so a
    policy compiled from `PATHS` (the main checkout) fails this outright."""
    worktree = tmp_path / "wt" / "defender"
    (worktree / "skills").mkdir(parents=True)
    run = tmp_path / "learn-run"
    run.mkdir()

    deps = bind(LEAD_AUTHOR_DEF, run, defender_dir=worktree)
    pol = deps.policy

    def verdict(cmd: str) -> bool:
        return permission.decide_bash(
            cmd, policy=pol, run_dir=run, defender_dir=worktree
        ).allow

    assert worktree.resolve() != PATHS.defender_dir.resolve(), "fixture must differ from PATHS"

    # the tree it was BOUND to
    assert verdict(f"rm {worktree}/skills/stale.md")
    # the tree PATHS points at — the main checkout. A PATHS-anchored grant would allow this.
    assert not verdict(f"rm {PATHS.defender_dir}/skills/stale.md"), (
        "the lead author's rm grant is anchored on the import-time PATHS constant, "
        "not on the defender_dir it was bound with — a worktree run would rm the main checkout"
    )
