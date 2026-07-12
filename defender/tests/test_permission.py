"""Pure unit tests for the runtime permission gate (runtime/permission/).

No model call, no API key — these run in CI. They assert the in-process gate makes the same
allow/deny decisions as the four Claude Code PreToolUse hooks it ports, so functionality
parity is checked for free.

Since #575 the gate speaks ONE containment model: an `AgentPolicy.bash_allow` is a tuple of
`Grant`s, each a SHAPE (program + flags + arity, no paths) plus a SCOPE (anchored regexes over
the **RESOLVED** path of everything `PROGRAMS[grant.program]` says the program opens). `cat` is
the sole opener; `grep`/`head`/`tail`/`wc`/`jq` are stdin-only pipe stages; `ls`/`cd` are gone
from every lane. The capability BITS this file used to construct policies with
(`adapters` / `adapter_sql_pipe` / `raw_reads` / `operand_gated`) are deleted — each is now a
fact the grant list carries directly, so the tests below construct grants instead of bits. The
model itself is specced in `test_grant_gate_575.py`; this file keeps the shim/adapter/unwrap/
redirect/write coverage it always had, ported onto the new API.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")  # CI installs the runtime extra; skip otherwise

# The workspace root is on sys.path via pytest's `pythonpath = [".."]`, so
# `defender.*` namespace imports resolve. The agent registry moved OUT of `runtime/`
# to `defender.agents` (#575), which imports `pydantic_ai` transitively — hence the guard.
from defender.agents import GATHER_DEF, MAIN_DEF  # noqa: E402
from defender.runtime import permission  # noqa: E402
from defender.runtime.agent_definition import compile_policy_for  # noqa: E402
from defender.runtime.permission.grant import PathShapes, under  # noqa: E402

# The gate is policy-driven (it keys on an AgentPolicy, not a role). The runtime-agent reader
# policy is compiled PER-RUN — `compile_policy_for(<DEF>, run_dir, defender_dir=…)` bakes the
# RESOLVED roots into every grant's SCOPE and RAISES without them (safe-by-construction). These
# synthetic absolute roots anchor the lane; `decide_bash` resolves an operand but never stats it,
# so they need not exist. The per-run anchored-read behavior is specced in test_read_confine_bash.py;
# here the bash tests exercise shim/adapter/unwrap/redirect shapes against the same policies.
_RUN = Path("/run")
_DFN = Path("/dfn")
MAIN = compile_policy_for(MAIN_DEF, run_dir=_RUN, defender_dir=_DFN)
GATHER = compile_policy_for(GATHER_DEF, run_dir=_RUN, defender_dir=_DFN)


def _bash(cmd, policy):
    """Every decide_bash call threads the run roots: a `cat` operand is RESOLVED against the
    executor's cwd (`defender_dir.parent`) before its scope check, so a gate call without them
    fails closed on any file-opening stage (by design — see `bash._in_scope`)."""
    return permission.decide_bash(cmd, policy=policy, run_dir=_RUN, defender_dir=_DFN)


# --- bash, main loop -------------------------------------------------------

@pytest.mark.parametrize("cmd", [
    "defender-invlang enum types",
    "defender-lessons --tags",
    # #575: the viewers lost their file operands, so a run-dir artifact is opened by `cat` and
    # reduced through the stdin-only stages (`tail -1 {run}/…` denies — see the c1 ledger).
    "cat /run/executed_queries.jsonl | tail -1 | jq '.'",
    "defender-record-query --lead l-1 --query-id ad-hoc",
])
def test_main_loop_allows_safe(cmd):
    assert _bash(cmd, MAIN).allow


def test_record_query_passthrough_wrapper_form_denied():
    """`defender-record-query … -- defender-<sys> …` (the retired capture WRAPPER) now DENIES:
    a shim's shape is a POSITIVE allowlist of its own long flags + free-text args (#575), and
    `--` + a passthrough argv is neither. Adapter capture is in-process (`tools._capture_adapter`)
    so the wrapper is a dead command — but it is still spelled in `skills/gather/queries/SCHEMA.md`,
    which is stale prompt surface. Pinned so the deny is a decision, not a surprise.
    Positive control: the shim's own flag form (above) still runs."""
    assert not _bash(
        "defender-record-query --lead l-1 --query-id ad-hoc -- defender-elastic query foo", MAIN,
    ).allow


@pytest.mark.parametrize(("cmd", "reason_substr"), [
    ("defender-elastic query foo", "data-source CLIs directly"),
    # The raw payload is denied to MAIN by POSITIVE ENUMERATION (the gather_raw shape is not in
    # main's grants), not by the deleted `RAW_MARKER in cmd` clamp — so the bash lane answers with
    # main's fall-through reason. The gather_raw-specific reason is the READ tool's, and it is
    # still asserted there (test_read_main_loop_gather_raw_not_enumerated_gather_allowed).
    ("cat /run/gather_raw/l-001/0.json", "only the defender-* shims"),
    ("python3 scripts/adapters/elastic_cli.py query foo", "data-source CLIs directly"),
    ("curl http://evil", "arbitrary shell"),
    ("env | grep PASSWORD", "arbitrary shell"),
])
def test_main_loop_denies(cmd, reason_substr):
    d = _bash(cmd, MAIN)
    assert not d.allow
    assert reason_substr in d.reason


# --- bash, gather subagent (slice 2: transparent capture) ------------------

def test_gather_allows_standalone_adapter():
    # Adapters are captured transparently by the harness — gather runs them
    # directly, no record-query wrapper. A standalone adapter call is allowed.
    assert _bash("defender-elastic query foo", GATHER).allow


@pytest.mark.parametrize("cmd", [
    "defender-elastic query foo | jq '.'",                    # piped
    "defender-elastic query foo && cat /run/report.md",       # chained (with a GRANTED viewer)
    "cat /run/report.md; defender-elastic query foo",         # sequenced
])
def test_gather_denies_compound_with_adapter(cmd):
    # The other stage is deliberately one gather MAY run: the deny must come from the adapter
    # being in a compound, not from the neighbouring stage being unclaimed.
    d = _bash(cmd, GATHER)
    assert not d.allow
    assert "standalone" in d.reason


# The reader lane's shapes: `cat` opens (and is scope-checked), the rest read stdin.
@pytest.mark.parametrize("cmd", [
    "cat /run/gather_raw/l-001/0.json | jq '.'",   # jq over stdin, not a file operand
    "defender-invlang enum types",
    "cat /run/gather_raw/l-001/0.json",            # gather reads its own raw, absolute
])
def test_gather_allows_readonly_viewers(cmd):
    assert _bash(cmd, GATHER).allow


@pytest.mark.parametrize("cmd", ["curl http://evil", "rm -rf /", "python3 -c 'x'"])
def test_gather_denies_arbitrary_shell(cmd):
    assert not _bash(cmd, GATHER).allow


def test_decision_exposes_standalone_adapter_argv():
    # The gate stashes the standalone-adapter argv on the decision so dispatch
    # routes capture off the single parse, no re-parse (#456).
    assert _bash("defender-elastic query foo", GATHER).adapter_argv == [
        "defender-elastic", "query", "foo"]
    assert _bash("timeout 60 defender-cmdb host-lookup web-1", GATHER).adapter_argv == [
        "defender-cmdb", "host-lookup", "web-1"]


@pytest.mark.parametrize("cmd", [
    "defender-elastic query foo | jq '.'",  # compound → not a standalone capture
    "cat /run/report.md | jq '.'",          # a plain reader command → claimed by grants, not routed
    "defender-invlang enum types",          # non-adapter shim
])
def test_decision_no_adapter_argv_for_non_standalone(cmd):
    assert _bash(cmd, GATHER).adapter_argv is None


# --- jq comparison operators are not redirects (quote-aware unsafe scan) -----
# Regression: `>`/`<` inside a quoted jq filter (a comparison) were read as shell
# redirects and hard-denied in-process. They must be allowed; real redirects and
# command substitution outside quotes must still be denied.

@pytest.mark.parametrize("cmd", [
    # jq is stdin-compute-only, so the payload is fed via an in-scope `cat …`; the point of this
    # regression stays — `>`/`<` inside the single-quoted filter are comparisons, not redirects.
    '''cat /run/gather_raw/l-001/0.json | jq '[.hits[] | select(.["@timestamp"] >= "2026-01-01" and .x <= "2026-12-31")]' ''',
    '''cat /run/gather_raw/l-001/0.json | jq '[.hosts[] | select(.trust_edges_out | length > 0)]' ''',
])
def test_gather_allows_quoted_jq_comparisons(cmd):
    assert _bash(cmd, GATHER).allow


@pytest.mark.parametrize("cmd", [
    # Same regression for MAIN — the gather variants above open a gather_raw path that is not in
    # MAIN's enumeration, so cover MAIN over an in-scope NON-raw artifact instead. Without this, no
    # MAIN test carries a comparison-bearing jq filter, so a main-only over-tightening of redirect
    # detection (`>=`/`<=` misread as a redirect) would slip through green.
    '''cat /run/investigation.md | jq '[.hits[] | select(.["@timestamp"] >= "2026-01-01" and .x <= "2026-12-31")]' ''',
    '''cat /run/investigation.md | jq '[.hosts[] | select(.trust_edges_out | length > 0)]' ''',
])
def test_main_allows_quoted_jq_comparisons(cmd):
    assert _bash(cmd, MAIN).allow


@pytest.mark.parametrize("cmd", [
    # Each head is a command the lane OTHERWISE ALLOWS (an in-scope `cat`), so the deny can only
    # come from the redirect / substitution guard — a viewer with a file operand would now deny at
    # the shape gate and the guard would never be exercised.
    "cat /run/report.md > /tmp/out",         # real stdout redirect outside quotes
    "cat /run/report.md 1> /tmp/out",        # explicit fd redirect
    "cat /run/report.md >> /tmp/out",        # append redirect
    "cat $(cat injected)",                   # command substitution outside quotes
    'cat "$(rm -rf /)"',                     # substitution live inside double quotes
    # Fused shell-operator tokens shlex emits as a single token that is neither a
    # recognized separator (|/||/&&/;) nor a `<>&`-only redirect — a redirect-only
    # check missed these, so a file write / a second ungated command slipped through.
    "cat /run/report.md >| /tmp/out",        # >| force-clobber stdout redirect
    "cat secret >| /tmp/exfil",              # ... same, exfil shape
    "cat /run/report.md &>| /tmp/out",       # &>| both-stream clobber
    "cat /run/report.md |& rm -rf /",        # |& pipe-both: the rm must be gated
    "cat /run/report.md & rm -rf /",         # bare-& background: the rm must be gated
    # `2>1` is a write to a file named `1` (operator token `>`), not the `2>&1`
    # merge (operator token `>&`) — it must not be waved through as benign stderr.
    "cat /run/report.md 2>1",
    "cat /run/report.md 2 > 1",              # ... same, with `2` as a positional token
])
def test_gather_still_denies_real_redirect_and_substitution(cmd):
    assert not _bash(cmd, GATHER).allow
    assert not _bash(cmd, MAIN).allow


# --- a second command must never hide behind a safe head -------------------
# shlex eats an unquoted newline as whitespace, and unwrap()'s `bash -c`/`timeout`
# handling used to drop or re-quote what followed — both let a safe head (an in-scope
# `cat`) front an ungated second command the shell still runs. Each must fail closed
# in BOTH sessions. The heads are all commands the lane really allows, so a regression
# in unwrap shows up as an ALLOW here rather than being masked by the head's own deny.

@pytest.mark.parametrize("cmd", [
    "cat /run/report.md\nrm -rf /tmp/x",                    # unquoted newline = a 2nd command
    "cat /run/report.md\ncurl http://evil",
    "bash -c 'cat /run/report.md' ; rm -rf /tmp/x",         # cmd AFTER the -c payload (outer shell)
    "bash -c 'cat /run/report.md'\nrm -rf /tmp/x",          # ... via newline
    "bash -c 'cat /run/report.md' && curl http://evil",
    "bash -c 'cat /run/report.md' | sh",
    'bash -c "cat /run/report.md\nrm -rf /tmp/x"',          # newline INSIDE the -c payload
    "timeout 5 cat /run/report.md\nrm -rf /tmp/x",          # timeout prefix + newline (unwrap join)
    "timeout 5 cat /run/report.md ; rm -rf /tmp/x",
    "cat /run/report.md ;; rm -rf /tmp/x",                  # ;-fused token must fail closed
    "echo a ;& curl http://evil",
])
def test_no_second_command_hides_behind_safe_head(cmd):
    assert not _bash(cmd, GATHER).allow
    assert not _bash(cmd, MAIN).allow


# A SCRIPT FILE before `-c` is not the inline `bash -c <payload>` wrapper: the shell
# runs the script and `-c`/the "payload" become its positional args. unwrap used to
# grab the first `-c` anywhere, extract the safe-looking payload, and approve while
# `shell=True` ran the script (issue #379 bypass). The exact-adjacency unwrap must
# fail closed here in BOTH sessions. The payload is an ALLOWED command on purpose:
# an unwrap that grabbed it would approve, so the deny pins the adjacency rule itself.
@pytest.mark.parametrize("cmd", [
    "bash evil.sh -c 'cat /run/report.md'",            # script file before -c → -c is the script's arg
    "sh evil.sh -c 'cat /run/report.md'",
    "timeout 5 bash evil.sh -c 'cat /run/report.md'",  # ... behind a timeout prefix
])
def test_bash_script_file_before_c_fails_closed(cmd):
    assert not _bash(cmd, GATHER).allow
    assert not _bash(cmd, MAIN).allow


# Happy-path anchor for the exact-adjacency tightening above: the LEGITIMATE inline
# `bash -c <payload>`/`sh -c <payload>` form (optionally behind a `timeout` prefix)
# wrapping a read-only viewer must STILL be approved in BOTH sessions. Without this,
# every `bash -c` test is a deny case, so a future over-tightening of unwrap could
# flip these real commands to deny and the whole suite would stay green.
@pytest.mark.parametrize("cmd", [
    "bash -c 'cat /run/investigation.md'",
    "sh -c 'cat /run/investigation.md'",
    "timeout 5 bash -c 'cat /run/investigation.md'",         # ... behind a timeout prefix
    "bash -c 'cat /run/investigation.md | jq .'",            # a pipeline payload must not be re-quoted
])
def test_inline_bash_c_viewer_still_allowed(cmd):
    assert _bash(cmd, GATHER).allow
    assert _bash(cmd, MAIN).allow


@pytest.mark.parametrize("cmd", [
    # a `timeout` prefix in front of a legit pipeline must STILL be approved — the
    # unwrap fix must not quote the `|` or otherwise break the pipeline.
    "timeout 30 cat /run/investigation.md | jq '.'",
    "timeout 5 cat /run/investigation.md",
])
def test_timeout_prefix_keeps_legit_pipeline(cmd):
    assert _bash(cmd, MAIN).allow
    assert _bash(cmd, GATHER).allow


@pytest.mark.parametrize("cmd", [
    # A quote spanning a newline is unparseable → the shared executor decomposition
    # (bash_exec.parse) raises, so the gate fails CLOSED, not mistaking it for an
    # adapter (its head "starts with defender-") and routing it to the capture path.
    "defender-elastic query 'unterminated\nrest'",
    "cat /run/report.md | jq '.a\n.b'",
])
def test_unparseable_quote_spanning_newline_fails_closed(cmd):
    d = _bash(cmd, GATHER)
    assert not d.allow
    assert not _bash(cmd, MAIN).allow
    assert d.adapter_argv is None  # not routed to capture


# --- read: deny-by-default allowlist over {run_dir, defender_dir} -----------

def _read_roots(tmp_path):
    """A run dir + a defender corpus dir for the read allowlist (both real dirs so
    `resolve()` has something to anchor)."""
    run = tmp_path / "run"
    (run / "gather_raw" / "l-001").mkdir(parents=True)
    dfn = tmp_path / "defender"
    (dfn / "skills" / "elastic").mkdir(parents=True)
    (dfn / "lessons").mkdir(parents=True)
    return run, dfn


def test_read_allows_in_root_corpus_and_run(tmp_path):
    # The reads past runs actually make: alert/investigation/run artifacts under the run dir;
    # tight-corpus `.md` under the defender corpus. Built with a MAIN policy compiled on these
    # roots (`compile_policy_for` bakes them into the `cat` grant's scope, which IS the policy's
    # `read_allow` — so the policy must anchor on the SAME roots the gate is called with; a
    # mismatched anchor denies every read). A run-dir file is admitted regardless of name; a
    # corpus read must be a tight `.md` under lessons/skills/examples.
    run, dfn = _read_roots(tmp_path)
    main = compile_policy_for(MAIN_DEF, run_dir=run, defender_dir=dfn)
    for p in (run / "alert.json", run / "investigation.md", run / "executed_queries.jsonl",
              dfn / "skills" / "elastic" / "SKILL.md"):
        assert permission.decide_read(
            p, run_dir=run, defender_dir=dfn, policy=main).allow, p
    # a bare SKILL.md directly under defender_dir (outside lessons/skills/examples) is NOT a tight
    # corpus `.md`, so the read_allow shapes deny it — parity with the bash cat lane.
    assert not permission.decide_read(
        dfn / "SKILL.md", run_dir=run, defender_dir=dfn, policy=main).allow


@pytest.mark.parametrize("path", [
    "/workspace/.env",                               # the secret-grope the policy targets
    "/etc/passwd",
    "/home/user/.ssh/id_rsa",
    "/workspace/docs/playground-elastic-stack.md",   # real env doc, but out of corpus
    "fixtures/held-out/cases.json",                  # relative → resolves outside roots
])
def test_read_denies_outside_roots(tmp_path, path):
    # Deny-by-default: a read outside {run_dir, defender_dir} fails closed regardless
    # of filename — the structural close for the cat-.env / basename / case gaps.
    run, dfn = _read_roots(tmp_path)
    main = compile_policy_for(MAIN_DEF, run_dir=run, defender_dir=dfn)
    assert not permission.decide_read(
        Path(path), run_dir=run, defender_dir=dfn, policy=main).allow, path


def test_read_traversal_escape_denied(tmp_path):
    # resolve() collapses `..`, so a path whose prefix is in-root but which escapes
    # the root fails the allowlist.
    run, dfn = _read_roots(tmp_path)
    main = compile_policy_for(MAIN_DEF, run_dir=run, defender_dir=dfn)
    assert not permission.decide_read(
        run / ".." / "outside.txt", run_dir=run, defender_dir=dfn, policy=main).allow


@pytest.mark.parametrize("name", [".env", "credentials.txt", "ground_truth.yaml", "cases.json"])
def test_read_denylist_is_belt_and_suspenders_inside_a_root(tmp_path, name):
    # A secret that lands INSIDE an allowed root AND inside the agent's own shapes (a captured
    # .env at the top of the run dir, the eval cases.json) is still denied by the declarative
    # denylist on top. The path is IN-SHAPE on purpose — a run-dir file at depth 1 matches
    # `under(run, SEG)` — so the denylist is the only thing that can deny it (an out-of-shape
    # probe would deny at the enumeration and prove nothing about the denylist).
    run, dfn = _read_roots(tmp_path)
    main = compile_policy_for(MAIN_DEF, run_dir=run, defender_dir=dfn)
    assert not permission.decide_read(
        run / name, run_dir=run, defender_dir=dfn, policy=main).allow, name
    assert permission.decide_read(          # positive control: same root, benign name
        run / "report.md", run_dir=run, defender_dir=dfn, policy=main).allow


def test_read_ssh_dir_component_denied_inside_a_shape(tmp_path):
    # The denylist's OTHER axis: a denied path COMPONENT (`.ssh`). The probe sits inside the tight
    # corpus `.md` shape (`lessons/<dir>/<name>.md` — `.ssh` is a legal segment), so the shape gate
    # admits it and only the component denylist can deny it.
    run, dfn = _read_roots(tmp_path)
    main = compile_policy_for(MAIN_DEF, run_dir=run, defender_dir=dfn)
    assert not permission.decide_read(
        dfn / "lessons" / ".ssh" / "id_rsa.md", run_dir=run, defender_dir=dfn, policy=main).allow
    assert permission.decide_read(          # positive control: same shape, no denied component
        dfn / "lessons" / "auth" / "scope.md", run_dir=run, defender_dir=dfn, policy=main).allow


def test_read_main_loop_gather_raw_not_enumerated_gather_allowed(tmp_path):
    # gather_raw is inside the run dir, but the gather_raw SHAPE is simply not in main's
    # `read_allow` (which IS its `cat` grant's scope) — positive enumeration, not the deleted
    # `raw_reads` clamp bit. The gather subagent's grants DO carry that shape, so it reads its own
    # payload. The gather_raw-specific deny REASON is prompt surface the e2e deny-tail asserts as a
    # substring, so it is pinned here too.
    run, dfn = _read_roots(tmp_path)
    main = compile_policy_for(MAIN_DEF, run_dir=run, defender_dir=dfn)
    gather = compile_policy_for(GATHER_DEF, run_dir=run, defender_dir=dfn)
    raw = run / "gather_raw" / "l-001" / "0.json"
    d = permission.decide_read(raw, run_dir=run, defender_dir=dfn, policy=main)
    assert not d.allow
    assert "must not read gather_raw" in d.reason
    assert permission.decide_read(raw, run_dir=run, defender_dir=dfn, policy=gather).allow


def test_alert_is_untrusted():
    assert permission.is_untrusted_read(Path("/tmp/defender-runs/x/alert.json"))
    assert not permission.is_untrusted_read(Path("/tmp/defender-runs/x/report.md"))


# --- write -----------------------------------------------------------------
# decide_write is a flat, deny-by-default allowlist (the write twin of bash_allow):
# the RESOLVED path must fullmatch a `policy.write_allow` pattern. There is NO implicit
# run_dir base — every writer declares its paths (main: its run-dir subtree; the lead
# author: defender/skills/**.md). Empty write_allow → the agent may write nothing.
# `build_write_allow(root, suffix=…)` is the shared subtree-pattern builder.

def _run_dir_pol(run_dir):
    """A main-style policy: its one declared write surface is the run-dir subtree."""
    return permission.AgentPolicy(write_allow=(permission.build_write_allow(run_dir),))


def _skills_pol(skills):
    """A lead-author-style policy: defender/skills/**.md only."""
    return permission.AgentPolicy(write_allow=(permission.build_write_allow(skills, suffix=".md"),))


def test_write_outside_run_dir_denied(tmp_path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    d = permission.decide_write(tmp_path / "evil.txt", "x", policy=_run_dir_pol(run_dir))
    assert not d.allow


def test_write_report_allowed(tmp_path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    d = permission.decide_write(run_dir / "report.md", "disposition: benign\n", policy=_run_dir_pol(run_dir))
    assert d.allow


def test_write_investigation_invalid_invlang_denied(tmp_path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    # A ```yaml fence is rejected by the invlang surface check (Rule 0).
    bad = "```yaml\nfoo: bar\n```\n"
    d = permission.decide_write(run_dir / "investigation.md", bad, policy=_run_dir_pol(run_dir))
    assert not d.allow
    assert "invlang validation" in d.reason


def test_decide_write_requires_policy(tmp_path):
    """decide_write requires an explicit policy — omitting it is a TypeError (the write allowlist
    lives on the policy, so no caller silently gets a default write scope). Mirrors decide_read."""
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    with pytest.raises(TypeError):
        permission.decide_write(run_dir / "x.md", "b\n")  # no policy=


def test_write_allow_admits_declared_denies_sibling(tmp_path):
    """write_allow is a flat list of the paths an agent may author: a skills .md under the declared
    subtree is allowed (positive control — real, would-be-committed content); a sibling under
    defender/ but OUTSIDE the allowlist (lessons) is denied on the same policy (guarded negative)."""
    skills = tmp_path / "defender" / "skills"
    (skills / "elastic").mkdir(parents=True)
    (tmp_path / "defender" / "lessons").mkdir(parents=True)
    pol = _skills_pol(skills)
    assert permission.decide_write(skills / "elastic" / "x.md", "b\n", policy=pol).allow
    assert not permission.decide_write(tmp_path / "defender" / "lessons" / "z.md", "b\n", policy=pol).allow


def test_write_allow_md_only_denies_non_md(tmp_path):
    """the lead-author allowlist is .md-only (the corpus), so a .py under the SAME skills subtree
    (the invlang/connect code that also lives there) is DENIED — the tightening #3 asked for: the
    write gate refuses corpus-code writes up front, not just at the loop's late .md-only scope gate."""
    skills = tmp_path / "defender" / "skills"
    (skills / "invlang").mkdir(parents=True)
    pol = _skills_pol(skills)
    assert permission.decide_write(skills / "elastic.md", "b\n", policy=pol).allow
    assert not permission.decide_write(skills / "invlang" / "validate.py", "evil\n", policy=pol).allow
    # rejected: allow any file under skills — that lets the writer clobber invlang/connect .py code,
    #           caught only late by the loop's .md-only scope gate (after the worktree carries it)


def test_write_allow_no_implicit_run_dir(tmp_path):
    """the flat allowlist REPLACES the old run-dir base (no implicit run_dir): a writer that declares
    only a skills subtree may NOT write run_dir. This is the #3 fix — the lead author (run_dir=source
    case dir) and pitfalls curator (run_dir=PENDING_DIR) no longer get a blanket run-dir write grant.
    Positive control: the declared skills path IS allowed."""
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    skills = tmp_path / "defender" / "skills"
    skills.mkdir(parents=True)
    pol = _skills_pol(skills)
    assert not permission.decide_write(run_dir / "report.md", "x\n", policy=pol).allow
    assert permission.decide_write(skills / "x.md", "b\n", policy=pol).allow


def test_write_allow_traversal_escape_denied(tmp_path):
    """a `..` escape out of the declared subtree is denied after resolve() collapses it (the pattern
    matches the RESOLVED path, so `skills/../lessons/z.md` lands outside the allowlist)."""
    skills = tmp_path / "defender" / "skills"
    skills.mkdir(parents=True)
    (tmp_path / "defender" / "lessons").mkdir(parents=True)
    pol = _skills_pol(skills)
    escape = skills / ".." / "lessons" / "z.md"
    assert not permission.decide_write(escape, "b\n", policy=pol).allow


def test_write_empty_allow_denies_all(tmp_path):
    """empty write_allow (every read-only / predictor stage: gather/judge/actor/oracle/verify) → the
    agent may write NOTHING, deny-by-default. Even a run_dir path is denied — a non-writer that
    somehow reached the write gate is refused, not silently granted its run dir."""
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    pol = permission.AgentPolicy()  # write_allow=()
    assert not permission.decide_write(run_dir / "report.md", "x\n", policy=pol).allow
    # rejected: an implicit run_dir base — it silently granted every agent (incl. read-only
    #           predictors) run-dir writes; deny-by-default forces each writer to declare its paths


def test_write_allow_investigation_validation_still_fires(tmp_path):
    """investigation.md invlang validation is keyed on the filename, so it still fires for a write
    admitted via write_allow. Positive control: a plain .md alongside it is allowed (the validation
    is filename-scoped, not a blanket .md check)."""
    skills = tmp_path / "defender" / "skills"
    skills.mkdir(parents=True)
    pol = _skills_pol(skills)
    d = permission.decide_write(skills / "investigation.md", "```yaml\nfoo: bar\n```\n", policy=pol)
    assert not d.allow
    assert "invlang validation" in d.reason
    assert permission.decide_write(skills / "note.md", "plain text\n", policy=pol).allow


# --- gather subagent: compute + adapter surface ---

def test_gather_drops_find():
    # `find` was dropped from the allowlist (#379): template discovery is Read/Grep
    # now (gather SKILL §2), and find was the one tool needing arg-level deny rules
    # (-exec/-delete, sensitive-path locator). It now fails closed in both lanes — and
    # since #575 it is not even in `PROGRAMS`, so no policy could grant it without
    # failing loud at compile.
    for cmd in ("find /workspace -type d -name gather",
                "find skills/gather/queries -name '*.md'"):
        assert not _bash(cmd, GATHER).allow, cmd
        assert not _bash(cmd, MAIN).allow, cmd


def test_gather_keeps_compute_and_adapter():
    # Compute is the adapter (native ES|QL) + defender-sql/jq over an IN-SCOPE payload streamed via
    # `cat {RUN}/…`; jq is stdin-compute-only and an out-of-scope /tmp operand denies.
    for cmd in ("defender-elastic query 'x'",
                "cat /run/gather_raw/l-001/1.json | defender-sql 'SELECT count(*) FROM data'",
                "cat /run/gather_raw/l-001/1.json | jq '.hits|length'"):
        assert _bash(cmd, GATHER).allow, cmd


def test_gather_allows_adapter_sql_pipe():
    # The sanctioned aggregation pipe (#379): an adapter's payload piped
    # straight into the sandboxed defender-sql. Allowed in gather only — the
    # adapter stage is captured, defender-sql is a local transform over its payload.
    cmd = ("defender-elastic query 'x' | "
           "defender-sql 'SELECT user, count(*) c FROM data GROUP BY user'")
    d = _bash(cmd, GATHER)
    assert d.allow
    # The split is exposed on the decision for the bash tool to route capture +
    # aggregation off the single parse.
    pipe = d.sql_pipe
    assert pipe is not None
    adapter_av, sql_av = pipe
    assert adapter_av == ["defender-elastic", "query", "x"]
    assert sql_av[0] == "defender-sql"
    # adapter_argv must NOT claim it (it's a pipe, not a standalone capture).
    assert d.adapter_argv is None
    # Main loop never gets the adapter, pipe or not.
    assert not _bash(cmd, MAIN).allow
    # A non-sql consumer downstream of an adapter stays denied (not the exception).
    assert not _bash("defender-elastic query 'x' | cat", GATHER).allow


@pytest.mark.parametrize("sep", [";", "&&", "||"])
def test_gather_denies_adapter_sql_sequence_not_pipe(sep):
    # ONLY the single `|` pipe is the sanctioned aggregation shape. A `;`/`&&`/`||`
    # SEQUENCE of `adapter` then `defender-sql` is a separate-pipelines compound
    # (the shell would sequence/short-circuit them — with `||`, run defender-sql only
    # on adapter FAILURE), not a pipe; it must be denied, and neither routing seam may
    # claim it (else the harness would silently stream the payload as if it were `|`).
    cmd = f"defender-elastic query 'x' {sep} defender-sql 'SELECT 1'"
    d = _bash(cmd, GATHER)
    assert not d.allow, cmd
    assert "standalone" in d.reason
    assert d.sql_pipe is None
    assert d.adapter_argv is None
    assert not _bash(cmd, MAIN).allow


@pytest.mark.parametrize("cmd", [
    # An adapter query whose value contains a `$(`/backtick substring is a LITERAL
    # query payload, not shell — the adapter runs shell=False (no expansion). It was
    # over-denied when the substitution guard was applied to the adapter stage; a
    # standalone adapter must be allowed and routed to capture so its argv reaches the
    # data source verbatim (e.g. hunting command-line telemetry for injection IOCs).
    "defender-elastic query 'process.command_line:*$(*'",
    "defender-elastic query 'cmd:`id`'",
])
def test_gather_allows_adapter_query_with_inert_shell_metachars(cmd):
    d = _bash(cmd, GATHER)
    assert d.allow, cmd
    argv = d.adapter_argv
    assert argv is not None, cmd
    assert argv[0] == "defender-elastic", cmd
    # The metachar survives verbatim in the captured argv (one shlex-resolved token).
    assert any("$(" in t or "`" in t for t in argv), cmd
    # The defense-in-depth guard is still enforced for a non-adapter VIEWER stage: the shape
    # below IS claimed by the `cat` grant (a single free-text operand), so only the guard denies it.
    assert not _bash('cat "$(rm -rf /)"', GATHER).allow


def test_gather_drops_residual_reduce_by_hand_tools():
    # sort/uniq/datamash/cut/comm/join/tr/paste/nl were dropped from the allowlist
    # (residual download-and-reduce era, superseded by native ES|QL/defender-sql).
    for cmd in ("datamash mean 1", "cat /run/report.md | uniq -c", "cut -d, -f1 /tmp/p",
                "join /tmp/a /tmp/b", "nl /tmp/p", "cat /run/report.md | sort",
                "sort -o /tmp/p f"):
        assert not _bash(cmd, GATHER).allow, cmd


# --- command_shape: pure classifiers over parsed pipelines (#456) ----------
# The classification half, shared between the gate and dispatch. It operates on
# the parsed bash_exec.Pipeline structure (no parsing of its own); the gate parses
# once and routes off these, so a command is decomposed exactly once per tool call.

from defender.runtime import bash_exec  # noqa: E402 — grouped with its test section
from defender.runtime.permission import command_shape  # noqa: E402


def _shape(cmd):
    from defender.hooks._cmd_segments import unwrap
    return bash_exec.parse(unwrap(cmd))


def test_command_shape_is_adapter_stage():
    assert command_shape.is_adapter_stage(["defender-elastic", "query", "x"])
    assert command_shape.is_adapter_stage(["python3", "scripts/adapters/elastic_cli.py", "q"])
    assert not command_shape.is_adapter_stage(["defender-invlang", "enum"])  # non-adapter shim
    assert not command_shape.is_adapter_stage(["jq", ".x"])
    assert not command_shape.is_adapter_stage([])
    # adapter name as an ARGUMENT, not the command, is not an adapter stage
    assert not command_shape.is_adapter_stage(["which", "defender-elastic"])


def test_command_shape_standalone_and_split():
    standalone = _shape("defender-elastic query foo")
    assert command_shape.standalone_adapter_argv(standalone) == [
        "defender-elastic", "query", "foo"]
    assert command_shape.adapter_sql_split(standalone) is None

    pipe = _shape("defender-elastic query x | defender-sql 'SELECT 1'")
    assert command_shape.standalone_adapter_argv(pipe) is None
    split = command_shape.adapter_sql_split(pipe)
    assert split == (["defender-elastic", "query", "x"], ["defender-sql", "SELECT 1"])

    # a `;` SEQUENCE is two pipelines, never the sanctioned single-`|` pipe
    seq = _shape("defender-elastic query x ; defender-sql 'SELECT 1'")
    assert command_shape.adapter_sql_split(seq) is None
    # a non-sql consumer downstream is not the sanctioned split
    assert command_shape.adapter_sql_split(_shape("defender-elastic query x | cat")) is None


# --- AgentPolicy primitive: read_roots + hand-built grants ------------------
# The generic mechanism the judge is the first consumer of: an agent brings its
# capability as DATA (an AgentPolicy carrying Grants). These test the primitive itself
# with a synthetic policy; the judge's own policy + ticket grant are tested with the
# judge module.

from defender.runtime.permission import AgentPolicy, Grant  # noqa: E402


def test_policy_read_roots_extend_the_allowlist(tmp_path):
    # A read under a declared extra root is allowed; the SAME path is denied under a
    # policy without it. This is how the judge reaches its comparison dir (which
    # lives under learning_run_dir, outside {run_dir, defender_dir}).
    run, dfn = _read_roots(tmp_path)
    main = compile_policy_for(MAIN_DEF, run_dir=run, defender_dir=dfn)
    extra = tmp_path / "learning_run" / "comparison"
    extra.mkdir(parents=True)
    target = extra / "l-001.md"
    with_root = AgentPolicy(read_roots=(extra,))
    assert permission.decide_read(target, run_dir=run, defender_dir=dfn, policy=with_root).allow
    assert not permission.decide_read(target, run_dir=run, defender_dir=dfn, policy=main).allow


def test_policy_read_roots_still_subject_to_denylist(tmp_path):
    # HIGH-SEVERITY: widening read_roots must NOT defeat the ground-truth/secret
    # denylist — a held-out ground_truth.yaml sitting in a declared extra root is
    # still denied, so a judge granted its comparison/gather dirs can never read the
    # label it is being measured against. (An empty `read_allow` applies no shape filter,
    # so the denylist is the ONLY thing standing between this policy and the file.)
    run, dfn = _read_roots(tmp_path)
    extra = tmp_path / "learning_run"
    extra.mkdir(parents=True)
    pol = AgentPolicy(read_roots=(extra,))
    assert not permission.decide_read(
        extra / "ground_truth.yaml", run_dir=run, defender_dir=dfn, policy=pol).allow
    assert not permission.decide_read(
        extra / ".env", run_dir=run, defender_dir=dfn, policy=pol).allow
    assert permission.decide_read(          # positive control: the root really is granted
        extra / "l-001.md", run_dir=run, defender_dir=dfn, policy=pol).allow


# A pinned-command grant: exactly `python3 <…>/elastic_cli.py …` (adapter-SHAPED, the mirror of
# the judge's ticket read / the actor's lesson scripts). `pins_path=True` — the operand IS the
# program, so the path lives in the PATTERN and the grant opens nothing the gate must resolve
# (`PROGRAMS["python3"] is OPENS_NOTHING`).
_PY_CLI = Grant(
    program="python3",
    pattern=re.compile(r"^python3 scripts/adapters/elastic_cli\.py .*$"),
    pins_path=True,
)


def test_policy_bash_allow_claims_before_adapter_classification():
    # `python3 <…>/elastic_cli.py …` is adapter-shaped, so adapter classification would
    # deny it for a no-adapter policy. The `bash_allow` reader lane runs FIRST and can
    # claim it — exactly how the judge's ticket read (python3 <ticket_cli>) is allowed.
    cmd = "python3 scripts/adapters/elastic_cli.py query foo"
    no_allow = AgentPolicy(deny_reason="nope")
    assert not _bash(cmd, no_allow).allow  # adapter-denied
    with_allow = AgentPolicy(bash_allow=(_PY_CLI,), deny_reason="nope")
    assert _bash(cmd, with_allow).allow


def test_policy_bash_allow_non_match_falls_through_to_deny():
    # A command matching no `bash_allow` grant does not widen anything — a non-adapter,
    # non-matching command fails closed.
    pol = AgentPolicy(bash_allow=(_PY_CLI,), deny_reason="nope")
    assert not _bash("rm -rf /tmp/x", pol).allow


def test_policy_untabled_program_fails_loud():
    # The replacement for the old `_OPERAND_GATED_PROGRAMS.get(argv[0]) is None → True`
    # pass-through, which left an untabled program silently UNGATED: a grant naming a program
    # absent from `PROGRAMS` now raises at policy construction, not at the first decide.
    with pytest.raises(ValueError, match="untabled"):
        AgentPolicy(bash_allow=(Grant(program="strings", pattern=re.compile(r"^strings .*$")),))


def test_policy_scope_not_shape_breadth_is_containment():
    # SECURITY: the old lane had a raw-read CLAMP that ran BEFORE the allowlist, so an
    # over-permissive pattern could not rescue a gather_raw command. The clamp is deleted (#575);
    # what replaces it is that a grant's SHAPE never decides containment — its SCOPE does. Here the
    # shape claims EVERY `cat` command, and the scope admits only the run dir's own top-level files:
    # the gather_raw payload (and /etc/passwd) still deny, because the operand is RESOLVED and
    # matched against the scope after the shape claims the stage.
    claim_all = AgentPolicy(bash_allow=(Grant(
        program="cat",
        pattern=re.compile(r"^cat .*$"),
        scope=PathShapes([under(_RUN, r"[\w.@=+-]+")]),
    ),))
    assert not _bash("cat /run/gather_raw/l-001/0.json", claim_all).allow
    assert not _bash("cat /etc/passwd", claim_all).allow
    assert _bash("cat /run/report.md", claim_all).allow  # positive control: in scope
