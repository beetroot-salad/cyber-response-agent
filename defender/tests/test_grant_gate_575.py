"""One containment model, `Grant`: a command is allowed iff it matches a grant's shape AND every path the program opens resolves into the grant's scope. Drives `permission.decide_bash` / `decide_read` / `compile_policy_for` and the `defender-policy` CLI over real symlink trees."""
from __future__ import annotations

import dataclasses
import functools
import json
import os
import re
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("pydantic_ai")

from defender._paths import PATHS  # noqa: E402
from defender.agents import (  # noqa: E402
    COMPOSER_DEF,
    LEAD_AUTHOR_DEF,
    MAIN_DEF,
    QUESTIONER_DEF,
    SUPPORT_DEF,
)
from defender.learning.author.curator_engine import (  # noqa: E402
    CuratorDeps,
)
from defender.runtime import permission  # noqa: E402
from defender.runtime.agent_definition import (  # noqa: E402
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
from defender.tests import _tenants1106 as T1106  # noqa: E402
from defender.tests._repo import seed_adapter_stubs  # noqa: E402

_DEFENDER = PATHS.defender_dir
_POLICY_CLI = _DEFENDER / "bin" / "defender-policy"


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
    seed_adapter_stubs(dfn, ("elastic",))
    main = compile_policy_for(MAIN_DEF, run_dir=run, defender_dir=dfn)
    return _Env(run=run, dfn=dfn, main=main, tmp=tmp_path)


class _Env(SimpleNamespace):
    """The planted tree and its compiled policies. Gather's is compiled LAZILY and with a RUN's
    grant (#1106 M4: `GATHER_DEF` carries no table grant; the driver binds gather with the run's
    tenant's), so a test about main alone does not depend on the tenant folder."""

    @functools.cached_property
    def gather(self) -> permission.AgentPolicy:
        return compile_policy_for(T1106.fixture_gather_def(), run_dir=self.run,
                                  defender_dir=self.dfn)


def _bash(env, cmd, which="gather"):
    pol = getattr(env, which) if isinstance(which, str) else which
    return permission.decide_bash(cmd, policy=pol, run_dir=env.run, defender_dir=env.dfn)


def _read(env, path, which="gather"):
    pol = getattr(env, which) if isinstance(which, str) else which
    return permission.decide_read(Path(path), run_dir=env.run, defender_dir=env.dfn, policy=pol)


def _lead_author(env):
    """The lead author binds against a WORKTREE tree (requires_explicit_tree)."""
    return bind(LEAD_AUTHOR_DEF, env.run, defender_dir=env.dfn).policy


def _curator(env):
    """The curator is the one denylist-free lane; it is `bindable=False`, so its policy comes
    off its own real front door (`CuratorDeps.for_run`), never `bind`."""
    corpus = env.dfn / "lessons"
    deps = CuratorDeps.for_run(env.run, env.dfn.parent, corpus, box=None)
    return deps.policy


def _all_policies(env) -> dict[str, permission.AgentPolicy]:
    """Every agent's compiled policy, through each role's REAL seam. The audit demands (a2/a4/
    b3/b8/g1) sweep this."""
    from defender.agents import JUDGE_DEF, ORACLE_CHECK_DEF, ORACLE_DEF

    return {
        "main": env.main,
        "gather": env.gather,
        # Keyed by the ROLE VALUE: b3 asserts this dict covers the registry, and it can only do
        # that if the keys are the roster's own names.
        "lead_author": _lead_author(env),
        "corpus_author": _curator(env),
        "support": compile_policy_for(SUPPORT_DEF, run_dir=env.run, defender_dir=env.dfn),
        "composer": compile_policy_for(COMPOSER_DEF, run_dir=env.run, defender_dir=env.dfn),
        "questioner": compile_policy_for(QUESTIONER_DEF, run_dir=env.run, defender_dir=env.dfn),
        "judge": compile_policy_for(JUDGE_DEF, run_dir=env.run, defender_dir=env.dfn),
        # #1224's live oracle and its verifier: two more deny-all roles, each its own key, so
        # each is a compiled policy (and a deny_reason) the audit must look at.
        "oracle": compile_policy_for(ORACLE_DEF, run_dir=env.run, defender_dir=env.dfn),
        "oracle_check": compile_policy_for(ORACLE_CHECK_DEF, run_dir=env.run,
                                           defender_dir=env.dfn),
    }


def _opens_nothing_grants(policy) -> tuple[Grant, ...]:
    return tuple(g for g in policy.bash_allow
                 if not g.pins_path and PROGRAMS.get(g.program) is OPENS_NOTHING)


def _cat_grant(policy) -> Grant:
    (g,) = [g for g in policy.bash_allow if g.program == "cat"]
    return g


def test_a1_shape_and_scope_both_required(env):
    """a1: a command is ALLOWED only if it matches a grant's `pattern` AND every operand `PROGRAMS[argv[0]]` extracts resolves into that grant's `scope`."""
    inv = f"{env.run}/investigation.md"
    assert _bash(env, f"cat {inv}", "main").allow
    assert not _bash(env, "cat /etc/passwd", "main").allow
    assert not _bash(env, f"strings {inv}", "main").allow
    assert not _bash(env, f"nl -ba {inv}", "main").allow


def test_a3_under_fullmatches_the_resolved_path(env):
    real = env.tmp / "real"
    real.mkdir()
    (real / "a.md").write_text("x\n")
    link = env.tmp / "link"
    os.symlink(real, link)
    pat = under(real.resolve(), r"a\.md")
    typed = link / "a.md"
    assert pat.fullmatch(str(typed.resolve()))
    assert not pat.fullmatch(str(typed))
    assert not pat.fullmatch(str(real / "b.md"))


def test_a5_symlink_escaping_the_root_denied(env):
    """a5 (negative, symlink):"""
    evil = env.run / "gather_raw" / "l-001" / "9.json"
    os.symlink("/etc/passwd", evil)
    assert not _bash(env, f"cat {evil}", "gather").allow
    assert _bash(env, f"cat {env.run}/gather_raw/l-001/0.json", "gather").allow


def test_a6_symlink_to_an_in_root_target_allowed(env):
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
    d = _bash(env, f"cat {a}", "gather")
    assert not d.allow


def test_a8_missing_and_broken_symlinks_are_judged_by_shape(env):
    """a8: `resolve(strict=False)` does NOT raise on a missing path or a broken symlink — it resolves lexically / through the link."""
    (env.run / "gather_raw" / "l-003").mkdir()
    assert _bash(env, f"cat {env.run}/gather_raw/l-003/0.json", "gather").allow
    ok = env.run / "gather_raw" / "l-003" / "1.json"
    os.symlink(env.run / "gather_raw" / "l-003" / "7.json", ok)
    assert _bash(env, f"cat {ok}", "gather").allow
    bad = env.run / "gather_raw" / "l-003" / "2.json"
    os.symlink("/etc/nope-does-not-exist", bad)
    assert not _bash(env, f"cat {bad}", "gather").allow


def test_a9_embedded_nul_operand_denies_without_raising(env):
    d = _bash(env, f"cat {env.run}/inv\x00.md", "main")
    assert not d.allow


def test_a10_scope_anchors_on_the_resolved_root(env):
    """a10: the scope anchors on the RESOLVED root."""
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
    """a11: a RELATIVE operand is rebased on the executor's REAL cwd before resolve."""
    assert _bash(env, "cat investigation.md", "main").allow
    assert not _bash(env, "cat defender/lessons/x.md", "main").allow
    assert not _bash(env, "cat ../../etc/passwd", "main").allow


def test_a12_every_pipe_stage_is_gated(env):
    inv = f"{env.run}/investigation.md"
    assert not _bash(env, f"cat {inv} | cat /etc/passwd", "main").allow
    assert _bash(env, f"cat {inv} | cat {env.run}/report.md", "main").allow


def test_b2_compile_policy_raises_on_an_untabled_program(env):
    """b2: `compile_policy` RAISES when a grant names a program absent from `PROGRAMS`."""
    def bad(_roots):
        return (Grant(program="strings", pattern=re.compile(r"^strings(?: [^ ]+)*$")),)

    def good(_roots):
        return (Grant(program="cat", pattern=re.compile(r"^cat(?: [^ ]+)*$")),)

    bad_def = dataclasses.replace(MAIN_DEF, bash_shapes=(bad,))
    with pytest.raises((KeyError, ValueError, TypeError)):
        compile_policy_for(bad_def, run_dir=env.run, defender_dir=env.dfn)
    ok_def = dataclasses.replace(MAIN_DEF, bash_shapes=(good,))
    assert compile_policy_for(ok_def, run_dir=env.run, defender_dir=env.dfn).bash_allow


@pytest.mark.parametrize("tok", ["-z", "-q", "--color", "--show-all", "-w", "-1", "--", "-nz"])
def test_b4_cat_extractor_fails_closed_on_unknown_dash_tokens(env, tok):
    """b4 (domain-outcome): `_cat_input_files` returns None → DENY for EVERY unrecognized `-`-prefixed token (the fail-closed rule that made `cat` the safe opener)."""
    inv = f"{env.run}/investigation.md"
    if tok == "--":
        assert not _bash(env, f"cat {tok} /etc/passwd", "main").allow
    else:
        assert not _bash(env, f"cat {tok} {inv}", "main").allow


def test_b4_cat_known_boolean_bundles_extract_the_operands(env):
    inv = f"{env.run}/investigation.md"
    for flags in ("-n", "-A", "-vET", "-n -s"):
        assert _bash(env, f"cat {flags} {inv}", "main").allow, flags
        assert not _bash(env, f"cat {flags} /etc/passwd", "main").allow, flags


def test_b5_cat_double_dash_operand_still_scope_checked(env):
    """b5 (domain-outcome): `cat -- /etc/passwd` → DENY."""
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
    """b7 (negative, THE PRIME FAIL-OPEN):"""
    assert not _bash(env, cmd, which).allow


def test_b8_opens_nothing_shapes_admit_no_long_option_or_dash_positional(env):
    """b8 (negative, structural):"""
    probes = ("--evil", "--evil=/etc/passwd", "--files0-from=/etc/passwd", "-ZZ9")
    checked = 0
    for name, pol in _all_policies(env).items():
        for g in _opens_nothing_grants(pol):
            checked += 1
            for probe in probes:
                for argv in (f"{g.program} {probe}", f"{g.program} x {probe}",
                             f"{g.program} {probe} x"):
                    assert not g.pattern.fullmatch(argv), f"{name}/{g.program}: admits {argv!r}"
    assert checked >= 5

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


@pytest.mark.parametrize(("file_form", "pipe_form"), [
    ("grep -n secret {p}", "cat {p} | grep -n secret"),
    ("head -5 {p}", "cat {p} | head -5"),
    ("tail -3 {p}", "cat {p} | tail -3"),
    ("wc -l {p}", "cat {p} | wc -l"),
])
def test_c1_file_operand_viewers_lose_their_file_slot(env, file_form, pipe_form):
    """c1 (domain-outcome, behavior change #1 — BOTH sides pinned):"""
    p = f"{env.run}/investigation.md"
    for which in ("main", "gather"):
        assert not _bash(env, file_form.format(p=p), which).allow, f"{which}: {file_form}"
        assert _bash(env, pipe_form.format(p=p), which).allow, f"{which}: {pipe_form}"


def test_d1_gather_raw_bash_allow_for_gather_deny_for_main(env):
    """d1 (domain-outcome): `cat {run}/gather_raw/l-001/0.json` → ALLOW for gather, DENY for main — on the bash lane."""
    raw = f"cat {env.run}/gather_raw/l-001/0.json"
    assert _bash(env, raw, "gather").allow
    assert not _bash(env, raw, "main").allow


def test_d2_decide_read_denies_main_gather_raw_with_the_e2e_reason(env):
    """d2 (behavior): `decide_read(main, {run}/gather_raw/l-001/0.json)` → DENY."""
    raw = f"{env.run}/gather_raw/l-001/0.json"
    d = _read(env, raw, "main")
    assert not d.allow
    assert "must not read gather_raw" in (d.reason or "")
    assert _read(env, raw, "gather").allow
    assert _read(env, f"{env.run}/gather_summaries/l-001.md", "main").allow


def test_d3_gather_raw_stays_untrusted_read(env):
    """d3 (negative): `is_untrusted_read({run}/gather_raw/l-001/0.json)` is True — the payload read is still SALT-TAG WRAPPED."""
    assert permission.is_untrusted_read(env.run / "gather_raw" / "l-001" / "0.json")
    assert permission.is_untrusted_read(env.run / "gather_raw" / "l-001.lead.json")
    assert permission.is_untrusted_read(env.run / "alert.json")
    assert not permission.is_untrusted_read(env.run / "investigation.md")
    assert not permission.is_untrusted_read(env.run / "gather_summaries" / "l-001.md")


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
    """d5 (parity, parametrized — the ALLOW-MATRIX):"""
    p = tmpl.format(run=env.run, dfn=env.dfn)
    assert _read(env, p, which).allow == _bash(env, f"cat {p}", which).allow, p


def test_d6_denylist_still_applies_inside_scope(env):
    """d6: the secret denylist still applies INSIDE the scope — being in-shape is necessary, not sufficient."""
    for secret in (f"{env.dfn}/lessons/.env.md", f"{env.run}/x/.ssh/id_rsa"):
        assert not _bash(env, f"cat {secret}", "main").allow, secret
        assert not _read(env, secret, "main").allow, secret
    ok = f"{env.dfn}/lessons/notes.md"
    assert _bash(env, f"cat {ok}", "main").allow
    assert _read(env, ok, "main").allow


def test_f1_bash_decision_carries_the_single_parse_and_no_adapter_route(env):
    """f1 (demand #0): `BashDecision` carries `pipelines` (the #456 single parse `bash_exec.run_parsed` consumes) and `grants` (the claiming grants)."""
    d = _bash(env, f"cat {env.run}/investigation.md", "main")
    assert d.allow
    assert d.pipelines
    assert not hasattr(d, "adapter_argv")
    assert not hasattr(d, "sql_pipe")
    a = _bash(env, "defender-elastic query 'x'", "gather")
    assert not a.allow
    assert a.reason == permission.ADAPTER_RETIRED_REASON
    assert {g.route for g in env.gather.bash_allow} == {Route.PLAIN}
    assert list(Route) == [Route.PLAIN]
    assert _cat_grant(env.gather).route is Route.PLAIN


@pytest.mark.parametrize(("cmd", "reason_substr"), [
    ("defender-elastic query foo", "not runnable from bash"),
    ("curl http://example.invalid/x", "only the defender-* shims"),
])
def test_f3_adapter_deny_reasons_survive(env, cmd, reason_substr):
    """f3 (parametrized): the two SPECIFIC deny reasons survive the rebuild — the e2e deny-tail asserts them as SUBSTRINGS (`test_replay_skeleton.py`), and they are prompt surface."""
    d = _bash(env, cmd, "main")
    assert not d.allow
    assert reason_substr in (d.reason or "")


_NON_PROGRAM_WORDS = frozenset({
    "defender", "lessons", "skills", "examples", "docs", "read", "write", "edit", "file",
    "only", "the", "and", "or", "with", "shims", "viewers", "tool", "tools", "bash", "run",
    "stdin", "pipe", "path", "paths", "dir", "md", "json", "sql", "yaml",
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
    for defn in (MAIN_DEF, T1106.fixture_gather_def()):
        a = compile_policy_for(defn, run_dir=env.run, defender_dir=env.dfn)
        b = compile_policy_for(defn, run_dir=env.run, defender_dir=env.dfn)
        assert _projection(a) == _projection(b)


def test_h2_no_cross_run_bleed(env):
    """h2: two runs with DIFFERENT run_dirs in ONE process produce policies whose scopes anchor on their OWN run_dir."""
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


def _cli(*args, cwd=None) -> subprocess.CompletedProcess:
    return subprocess.run(  # noqa: S603 — the pinned in-repo shim, fixed argv
        [str(_POLICY_CLI), *args], capture_output=True, text=True, timeout=60, cwd=cwd,
    )


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
def test_i2_policy_explain_is_a_second_consumer_not_a_second_implementation(env, which, cmd, capsys):
    """i2 (differential): over a corpus of (agent, command), `defender-policy explain` reports the SAME verdict AND the same matched-grant / deny-reason as `decide_bash`."""
    from defender.scripts import policy_cli

    c = cmd.format(run=env.run, dfn=env.dfn)
    tenant = (("--tenant", T1106.fixture_tenant().id) if which == "gather" else ())
    # The CLI's `main` in-process: the differential is about what `explain` decides, and a
    # fresh interpreter per (agent, command) pair only re-paid the import. i1 drives the shim.
    rc = policy_cli.main(["explain", which, c, "--run-dir", str(env.run),
                          "--defender-dir", str(env.dfn), *tenant, "--json"])
    out = capsys.readouterr()
    assert rc == 0, out.err
    got = json.loads(out.out)
    d = _bash(env, c, which)
    assert got["allow"] == d.allow, c
    if d.allow:
        assert got["grant"], c
    else:
        assert got["reason"] == (d.reason or ""), c


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
    """f6 — the argv EXECUTED is the argv GATED."""
    from defender.runtime import bash_exec

    resolved = cmd.format(run=env.run)
    decision = _bash(env, resolved, "main")
    assert decision.allow, resolved

    gated = [[list(st.argv) for st in pl.stages] for pl in (decision.pipelines or ())]
    # `parse` takes the raw command text directly (#959 D1/C3) — no standalone wrapper step to
    # apply first any more.
    executed = [[list(st.argv) for st in pl.stages] for pl in bash_exec.parse(resolved)]
    assert gated == executed, (
        f"the gate approved {gated!r} but the executor would run {executed!r} — "
        "a validator/executor parser differential"
    )


def test_f6_denied_command_carries_no_executable_pipeline(env):
    """f6 (positive control) — a DENIED command hands the executor nothing."""
    denied = _bash(env, "cat /etc/passwd", "main")
    assert not denied.allow
    assert not denied.pipelines


def test_h4_grants_anchor_on_the_threaded_tree_not_module_paths(tmp_path):
    """h4 — grants anchor on the defender_dir THREADED IN, never on import-time PATHS."""
    worktree = tmp_path / "wt" / "defender"
    (worktree / "skills").mkdir(parents=True)
    seed_adapter_stubs(worktree, ("elastic",))
    run = tmp_path / "learn-run"
    run.mkdir()

    deps = bind(LEAD_AUTHOR_DEF, run, defender_dir=worktree)
    pol = deps.policy

    def verdict(cmd: str) -> bool:
        return permission.decide_bash(
            cmd, policy=pol, run_dir=run, defender_dir=worktree
        ).allow

    assert worktree.resolve() != PATHS.defender_dir.resolve(), "fixture must differ from PATHS"

    assert verdict(f"rm {worktree}/skills/elastic/_draft/stale.md")
    assert not verdict(f"rm {PATHS.defender_dir}/skills/elastic/_draft/stale.md"), (
        "the lead author's rm grant is anchored on the import-time PATHS constant, "
        "not on the defender_dir it was bound with — a worktree run would rm the main checkout"
    )
