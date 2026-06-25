"""Pure unit tests for the runtime permission gate (runtime/permission.py).

No model call, no API key — these run in CI. They assert the in-process gate
makes the same allow/deny decisions as the four Claude Code PreToolUse hooks it
ports, so functionality parity is checked for free.
"""
from __future__ import annotations

from pathlib import Path

import pytest

# The workspace root is on sys.path via pytest's `pythonpath = [".."]`, so
# `defender.*` namespace imports resolve.
from defender.runtime import permission
from defender.runtime.agent_role import AgentRole


# --- bash, main loop -------------------------------------------------------

@pytest.mark.parametrize("cmd", [
    "defender-invlang enum types",
    "defender-lessons --tags",
    "tail -1 executed_queries.jsonl | jq '.'",
    "ls -la",
    "defender-record-query --lead l-1 --query-id ad-hoc -- defender-elastic query foo",
])
def test_main_loop_allows_safe(cmd):
    assert permission.decide_bash(cmd, role=AgentRole.MAIN).allow


@pytest.mark.parametrize(("cmd", "reason_substr"), [
    ("defender-elastic query foo --raw", "data-source CLIs directly"),
    ("cat gather_raw/l-001/0.json", "must not read gather_raw"),
    ("python3 scripts/adapters/elastic_cli.py query foo", "data-source CLIs directly"),
    ("curl http://evil", "arbitrary shell"),
    ("env | grep PASSWORD", "arbitrary shell"),
])
def test_main_loop_denies(cmd, reason_substr):
    d = permission.decide_bash(cmd, role=AgentRole.MAIN)
    assert not d.allow
    assert reason_substr in d.reason


# --- bash, gather subagent (slice 2: transparent capture) ------------------

def test_gather_allows_standalone_adapter():
    # Adapters are captured transparently by the harness — gather runs them
    # directly, no record-query wrapper. A standalone adapter call is allowed.
    assert permission.decide_bash(
        "defender-elastic query foo --raw", role=AgentRole.GATHER).allow


@pytest.mark.parametrize("cmd", [
    "defender-elastic query foo --raw | jq '.'",   # piped
    "defender-elastic query foo && ls",            # chained
    "ls; defender-elastic query foo",              # sequenced
])
def test_gather_denies_compound_with_adapter(cmd):
    d = permission.decide_bash(cmd, role=AgentRole.GATHER)
    assert not d.allow
    assert "standalone" in d.reason


@pytest.mark.parametrize("cmd", [
    "jq '.' gather_raw/l-001/0.json",
    "defender-invlang enum types",
    "cat gather_raw/l-001/0.json",
])
def test_gather_allows_readonly_viewers(cmd):
    assert permission.decide_bash(cmd, role=AgentRole.GATHER).allow


@pytest.mark.parametrize("cmd", ["curl http://evil", "rm -rf /", "python3 -c 'x'"])
def test_gather_denies_arbitrary_shell(cmd):
    assert not permission.decide_bash(cmd, role=AgentRole.GATHER).allow


def test_adapter_argv_extracts_standalone():
    assert permission.adapter_argv("defender-elastic query foo --raw") == [
        "defender-elastic", "query", "foo", "--raw"]
    assert permission.adapter_argv("timeout 60 defender-cmdb host-lookup web-1") == [
        "defender-cmdb", "host-lookup", "web-1"]


@pytest.mark.parametrize("cmd", [
    "defender-elastic query foo | jq '.'",  # compound → not captured here
    "jq '.' x.json",                        # not an adapter
    "defender-invlang enum types",          # non-adapter shim
])
def test_adapter_argv_none_for_non_standalone_adapter(cmd):
    assert permission.adapter_argv(cmd) is None


# --- jq comparison operators are not redirects (quote-aware unsafe scan) -----
# Regression: `>`/`<` inside a quoted jq filter (a comparison) were read as shell
# redirects and hard-denied in-process. They must be allowed; real redirects and
# command substitution outside quotes must still be denied.

@pytest.mark.parametrize("cmd", [
    # plain jq with comparisons (single-quoted filter, double-quoted literals)
    '''jq '[.hits[] | select(.["@timestamp"] >= "2026-01-01" and .x <= "2026-12-31")]' f.json''',
    '''jq '[.hosts[] | select(.trust_edges_out | length > 0)]' f.json''',
])
def test_gather_allows_quoted_jq_comparisons(cmd):
    assert permission.decide_bash(cmd, role=AgentRole.GATHER).allow
    assert permission.decide_bash(cmd, role=AgentRole.MAIN).allow


@pytest.mark.parametrize("cmd", [
    "jq '.x' f.json > /tmp/out",            # real stdout redirect outside quotes
    "cat f.json 1> /tmp/out",               # explicit fd redirect
    "jq '.x' f.json >> /tmp/out",           # append redirect
    "jq '.x' $(cat injected)",              # command substitution outside quotes
    'jq ".x" "$(rm -rf /)"',                # substitution live inside double quotes
    # Fused shell-operator tokens shlex emits as a single token that is neither a
    # recognized separator (|/||/&&/;) nor a `<>&`-only redirect — a redirect-only
    # check missed these, so a file write / a second ungated command slipped through.
    "jq '.x' f.json >| /tmp/out",           # >| force-clobber stdout redirect
    "cat secret >| /tmp/exfil",             # ... same, exfil shape
    "jq '.x' f.json &>| /tmp/out",          # &>| both-stream clobber
    "jq '.x' f.json |& rm -rf /",           # |& pipe-both: the rm must be gated
    "jq '.x' f.json & rm -rf /",            # bare-& background: the rm must be gated
    # `2>1` is a write to a file named `1` (operator token `>`), not the `2>&1`
    # merge (operator token `>&`) — it must not be waved through as benign stderr.
    "jq '.x' f.json 2>1",
    "jq '.x' f.json 2 > 1",                 # ... same, with `2` as a positional token
])
def test_gather_still_denies_real_redirect_and_substitution(cmd):
    assert not permission.decide_bash(cmd, role=AgentRole.GATHER).allow
    assert not permission.decide_bash(cmd, role=AgentRole.MAIN).allow


# --- a second command must never hide behind a safe head -------------------
# shlex eats an unquoted newline as whitespace, and unwrap()'s `bash -c`/`timeout`
# handling used to drop or re-quote what followed — both let a safe head (`jq`,
# `cat`) front an ungated second command the shell still runs. Each must fail closed
# in BOTH sessions.

@pytest.mark.parametrize("cmd", [
    "jq '.x' f.json\nrm -rf /tmp/x",            # unquoted newline = a 2nd command
    "cat f.json\ncurl http://evil",
    "bash -c 'jq .x f' ; rm -rf /tmp/x",        # cmd AFTER the -c payload (outer shell)
    "bash -c 'jq .x f'\nrm -rf /tmp/x",         # ... via newline
    "bash -c 'jq .x f' && curl http://evil",
    "bash -c 'jq .x f' | sh",
    'bash -c "jq .x f\nrm -rf /tmp/x"',         # newline INSIDE the -c payload
    "timeout 5 jq .x f\nrm -rf /tmp/x",         # timeout prefix + newline (unwrap join)
    "timeout 5 jq .x f ; rm -rf /tmp/x",
    "ls ;; rm -rf /tmp/x",                       # ;-fused token must fail closed
    "echo a ;& curl http://evil",
])
def test_no_second_command_hides_behind_safe_head(cmd):
    assert not permission.decide_bash(cmd, role=AgentRole.GATHER).allow
    assert not permission.decide_bash(cmd, role=AgentRole.MAIN).allow


# A SCRIPT FILE before `-c` is not the inline `bash -c <payload>` wrapper: the shell
# runs the script and `-c`/the "payload" become its positional args. unwrap used to
# grab the first `-c` anywhere, extract the safe-looking payload, and approve while
# `shell=True` ran the script (issue #379 bypass). The exact-adjacency unwrap must
# fail closed here in BOTH sessions.
@pytest.mark.parametrize("cmd", [
    "bash evil.sh -c 'jq .'",            # script file before -c → -c is the script's arg
    "sh evil.sh -c 'jq .'",
    "timeout 5 bash evil.sh -c 'jq .'",  # ... behind a timeout prefix
])
def test_bash_script_file_before_c_fails_closed(cmd):
    assert not permission.decide_bash(cmd, role=AgentRole.GATHER).allow
    assert not permission.decide_bash(cmd, role=AgentRole.MAIN).allow


# Happy-path anchor for the exact-adjacency tightening above: the LEGITIMATE inline
# `bash -c <payload>`/`sh -c <payload>` form (optionally behind a `timeout` prefix)
# wrapping a read-only viewer must STILL be approved in BOTH sessions. Without this,
# every `bash -c` test is a deny case, so a future over-tightening of unwrap could
# flip these real commands to deny and the whole suite would stay green.
@pytest.mark.parametrize("cmd", [
    "bash -c 'jq .x f.json'",
    "sh -c 'jq .x f.json'",
    "timeout 5 bash -c 'jq .x f.json'",   # ... behind a timeout prefix
    "bash -c 'tail -1 f.json | jq .'",    # a pipeline payload must not be re-quoted
])
def test_inline_bash_c_viewer_still_allowed(cmd):
    assert permission.decide_bash(cmd, role=AgentRole.GATHER).allow
    assert permission.decide_bash(cmd, role=AgentRole.MAIN).allow


@pytest.mark.parametrize("cmd", [
    # a `timeout` prefix in front of a legit pipeline must STILL be approved — the
    # unwrap fix must not quote the `|` or otherwise break the pipeline.
    "timeout 30 tail -1 f.json | jq '.'",
    "timeout 5 jq '.x' f.json",
])
def test_timeout_prefix_keeps_legit_pipeline(cmd):
    assert permission.decide_bash(cmd, role=AgentRole.MAIN).allow
    assert permission.decide_bash(cmd, role=AgentRole.GATHER).allow


@pytest.mark.parametrize("cmd", [
    # A quote spanning a newline is unparseable → the shared executor decomposition
    # (bash_exec.stage_argvs) raises, so _decompose returns None. It must fail
    # CLOSED, not be mistaken for an adapter (its head "starts with defender-") and
    # routed to the capture path.
    "defender-elastic query 'unterminated\nrest'",
    "jq '.a\n.b' f.json",
])
def test_unparseable_quote_spanning_newline_fails_closed(cmd):
    assert not permission.decide_bash(cmd, role=AgentRole.GATHER).allow
    assert not permission.decide_bash(cmd, role=AgentRole.MAIN).allow
    assert permission.adapter_argv(cmd) is None  # not routed to capture


# --- read: deny-by-default allowlist over {run_dir, defender_dir} -----------

def _read_roots(tmp_path):
    """A run dir + a defender corpus dir for the read allowlist (both real dirs so
    `resolve()` has something to anchor)."""
    run = tmp_path / "run"
    (run / "gather_raw" / "l-001").mkdir(parents=True)
    dfn = tmp_path / "defender"
    (dfn / "skills" / "elastic").mkdir(parents=True)
    return run, dfn


def test_read_allows_in_root_corpus_and_run(tmp_path):
    # The reads past runs actually make: alert/investigation/run artifacts under the
    # run dir; SKILLs/lessons/scripts/SKILL.md under the defender corpus.
    run, dfn = _read_roots(tmp_path)
    for p in (run / "alert.json", run / "investigation.md", run / "executed_queries.jsonl",
              dfn / "SKILL.md", dfn / "skills" / "elastic" / "SKILL.md"):
        assert permission.decide_read(
            p, run_dir=run, defender_dir=dfn, role=AgentRole.MAIN).allow, p


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
    assert not permission.decide_read(
        Path(path), run_dir=run, defender_dir=dfn, role=AgentRole.MAIN).allow, path


def test_read_traversal_escape_denied(tmp_path):
    # resolve() collapses `..`, so a path whose prefix is in-root but which escapes
    # the root fails the allowlist.
    run, dfn = _read_roots(tmp_path)
    assert not permission.decide_read(
        run / ".." / "outside.txt", run_dir=run, defender_dir=dfn, role=AgentRole.MAIN).allow


@pytest.mark.parametrize("name", [".env", "credentials.txt", "ground_truth.yaml", "cases.json"])
def test_read_denylist_is_belt_and_suspenders_inside_a_root(tmp_path, name):
    # A secret that lands INSIDE an allowed root (a captured .env in the run dir, the
    # eval cases.json) is still denied by the declarative denylist on top.
    run, dfn = _read_roots(tmp_path)
    assert not permission.decide_read(
        run / name, run_dir=run, defender_dir=dfn, role=AgentRole.MAIN).allow, name


def test_read_ssh_dir_inside_root_denied(tmp_path):
    run, dfn = _read_roots(tmp_path)
    assert not permission.decide_read(
        dfn / ".ssh" / "id_rsa", run_dir=run, defender_dir=dfn, role=AgentRole.MAIN).allow


def test_read_main_loop_gather_raw_clamped_gather_allowed(tmp_path):
    # gather_raw is inside the run dir (allowlist-permitted), but the main loop is
    # clamped off the raw payload (it consumes the summary); the gather subagent
    # reads its own gather_raw to verify its result.
    run, dfn = _read_roots(tmp_path)
    raw = run / "gather_raw" / "l-001" / "0.json"
    assert not permission.decide_read(raw, run_dir=run, defender_dir=dfn, role=AgentRole.MAIN).allow
    assert permission.decide_read(raw, run_dir=run, defender_dir=dfn, role=AgentRole.GATHER).allow


def test_alert_is_untrusted():
    assert permission.is_untrusted_read(Path("/tmp/defender-runs/x/alert.json"))
    assert not permission.is_untrusted_read(Path("/tmp/defender-runs/x/report.md"))


# --- write -----------------------------------------------------------------

def test_write_outside_run_dir_denied(tmp_path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    d = permission.decide_write(tmp_path / "evil.txt", "x", run_dir=run_dir)
    assert not d.allow


def test_write_report_allowed(tmp_path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    d = permission.decide_write(run_dir / "report.md", "disposition: benign\n", run_dir=run_dir)
    assert d.allow


def test_write_investigation_invalid_invlang_denied(tmp_path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    # A ```yaml fence is rejected by the invlang surface check (Rule 0).
    bad = "```yaml\nfoo: bar\n```\n"
    d = permission.decide_write(run_dir / "investigation.md", bad, run_dir=run_dir)
    assert not d.allow
    assert "invlang validation" in d.reason


# --- gather subagent: compute + adapter surface ---

def test_gather_drops_find():
    # `find` was dropped from the allowlist (#379): template discovery is Read/Grep
    # now (gather SKILL §2), and find was the one tool needing arg-level deny rules
    # (-exec/-delete, sensitive-path locator). It now fails closed in both lanes.
    for cmd in ("find /workspace -type d -name gather",
                "find skills/gather/queries -name '*.md'"):
        assert not permission.decide_bash(cmd, role=AgentRole.GATHER).allow, cmd
        assert not permission.decide_bash(cmd, role=AgentRole.MAIN).allow, cmd


def test_gather_keeps_compute_and_adapter():
    # Compute is jq on-disk + the adapter (native ES|QL / defender-sql aggregation);
    # the residual reduce-by-hand coreutils set (datamash/uniq/cut/…) was removed.
    for cmd in ("jq '.hits|length' /tmp/p.json",
                "jq '[.hits[].user]|group_by(.)|map(length)' /tmp/p.json",
                "defender-elastic query 'x' --raw",
                "cat /tmp/p.json | defender-sql 'SELECT count(*) FROM data'"):
        assert permission.decide_bash(
            cmd, role=AgentRole.GATHER,
        ).allow, cmd


def test_gather_allows_adapter_sql_pipe():
    # The sanctioned aggregation pipe (#379): an adapter producing `--raw` piped
    # straight into the sandboxed defender-sql. Allowed in gather only — the
    # adapter stage is captured, defender-sql is a local transform over its payload.
    cmd = ("defender-elastic query 'x' --raw | "
           "defender-sql 'SELECT user, count(*) c FROM data GROUP BY user'")
    assert permission.decide_bash(cmd, role=AgentRole.GATHER).allow
    # The split is exposed for the bash tool to route capture + aggregation.
    pipe = permission.adapter_sql_pipe(cmd)
    assert pipe is not None
    adapter_av, sql_av = pipe
    assert adapter_av == ["defender-elastic", "query", "x", "--raw"]
    assert sql_av[0] == "defender-sql"
    # adapter_argv must NOT claim it (it's a pipe, not a standalone capture).
    assert permission.adapter_argv(cmd) is None
    # Main loop never gets the adapter, pipe or not.
    assert not permission.decide_bash(cmd, role=AgentRole.MAIN).allow
    # A non-sql consumer downstream of an adapter stays denied (not the exception).
    assert not permission.decide_bash(
        "defender-elastic query 'x' --raw | cat", role=AgentRole.GATHER).allow


@pytest.mark.parametrize("sep", [";", "&&", "||"])
def test_gather_denies_adapter_sql_sequence_not_pipe(sep):
    # ONLY the single `|` pipe is the sanctioned aggregation shape. A `;`/`&&`/`||`
    # SEQUENCE of `adapter --raw` then `defender-sql` is a separate-pipelines compound
    # (the shell would sequence/short-circuit them — with `||`, run defender-sql only
    # on adapter FAILURE), not a pipe; it must be denied, and neither routing seam may
    # claim it (else the harness would silently stream the payload as if it were `|`).
    cmd = f"defender-elastic query 'x' --raw {sep} defender-sql 'SELECT 1'"
    d = permission.decide_bash(cmd, role=AgentRole.GATHER)
    assert not d.allow, cmd
    assert "standalone" in d.reason
    assert permission.adapter_sql_pipe(cmd) is None
    assert permission.adapter_argv(cmd) is None
    assert not permission.decide_bash(cmd, role=AgentRole.MAIN).allow


@pytest.mark.parametrize("cmd", [
    # An adapter query whose value contains a `$(`/backtick substring is a LITERAL
    # query payload, not shell — the adapter runs shell=False (no expansion). It was
    # over-denied when the substitution guard was applied to the adapter stage; a
    # standalone adapter must be allowed and routed to capture so its argv reaches the
    # data source verbatim (e.g. hunting command-line telemetry for injection IOCs).
    "defender-elastic query 'process.command_line:*$(*' --raw",
    "defender-elastic query 'cmd:`id`' --raw",
])
def test_gather_allows_adapter_query_with_inert_shell_metachars(cmd):
    assert permission.decide_bash(cmd, role=AgentRole.GATHER).allow, cmd
    argv = permission.adapter_argv(cmd)
    assert argv is not None, cmd
    assert argv[0] == "defender-elastic", cmd
    # The metachar survives verbatim in the captured argv (one shlex-resolved token).
    assert any("$(" in t or "`" in t for t in argv), cmd
    # The defense-in-depth guard is still enforced for a non-adapter VIEWER stage.
    assert not permission.decide_bash('jq ".x" "$(rm -rf /)"', role=AgentRole.GATHER).allow


def test_gather_drops_residual_reduce_by_hand_tools():
    # sort/uniq/datamash/cut/comm/join/tr/paste/nl were dropped from the allowlist
    # (residual download-and-reduce era, superseded by native ES|QL/defender-sql).
    for cmd in ("datamash mean 1", "jq -r .x f | uniq -c", "cut -d, -f1 /tmp/p",
                "join /tmp/a /tmp/b", "nl /tmp/p", "jq -r .x f | sort",
                "sort -o /tmp/p f"):
        assert not permission.decide_bash(
            cmd, role=AgentRole.GATHER,
        ).allow, cmd
