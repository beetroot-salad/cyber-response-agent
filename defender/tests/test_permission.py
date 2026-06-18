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


# --- bash, main loop -------------------------------------------------------

@pytest.mark.parametrize("cmd", [
    "defender-invlang enum types",
    "defender-lessons --tags",
    "tail -1 executed_queries.jsonl | jq '.'",
    "ls -la",
    "defender-record-query --lead l-1 --query-id ad-hoc -- defender-elastic query foo",
])
def test_main_loop_allows_safe(cmd):
    assert permission.decide_bash(cmd, is_main_session=True).allow


@pytest.mark.parametrize("cmd,reason_substr", [
    ("defender-elastic query foo --raw", "data-source CLIs directly"),
    ("cat gather_raw/l-001/0.json", "must not read gather_raw"),
    ("python3 scripts/tools/elastic_cli.py query foo", "data-source CLIs directly"),
    ("curl http://evil", "arbitrary shell"),
    ("env | grep PASSWORD", "arbitrary shell"),
])
def test_main_loop_denies(cmd, reason_substr):
    d = permission.decide_bash(cmd, is_main_session=True)
    assert not d.allow
    assert reason_substr in d.reason


# --- bash, gather subagent (slice 2: transparent capture) ------------------

def test_gather_allows_standalone_adapter():
    # Adapters are captured transparently by the harness — gather runs them
    # directly, no record-query wrapper. A standalone adapter call is allowed.
    assert permission.decide_bash(
        "defender-elastic query foo --raw", is_main_session=False).allow


@pytest.mark.parametrize("cmd", [
    "defender-elastic query foo --raw | jq '.'",   # piped
    "defender-elastic query foo && ls",            # chained
    "ls; defender-elastic query foo",              # sequenced
])
def test_gather_denies_compound_with_adapter(cmd):
    d = permission.decide_bash(cmd, is_main_session=False)
    assert not d.allow
    assert "standalone" in d.reason


@pytest.mark.parametrize("cmd", [
    "jq '.' gather_raw/l-001/0.json",
    "defender-invlang enum types",
    "cat gather_raw/l-001/0.json",
])
def test_gather_allows_readonly_viewers(cmd):
    assert permission.decide_bash(cmd, is_main_session=False).allow


@pytest.mark.parametrize("cmd", ["curl http://evil", "rm -rf /", "python3 -c 'x'"])
def test_gather_denies_arbitrary_shell(cmd):
    assert not permission.decide_bash(cmd, is_main_session=False).allow


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
    # record-summary with the jq payload single-quoted ...
    '''defender-record-summary --lead l-1 --label x -- 'jq "[.h[] | select(.n > 0)]" f.json' ''',
    # ... and double-quoted with escaped inner quotes (the form gather emits)
    '''defender-record-summary --lead l-1 --label x -- "jq '[.hits[] | select(.\\"@timestamp\\" >= \\"2026-05-25T12:53:35Z\\")]' f.json"''',
])
def test_gather_allows_quoted_jq_comparisons(cmd):
    assert permission.decide_bash(cmd, is_main_session=False).allow
    assert permission.decide_bash(cmd, is_main_session=True).allow


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
    assert not permission.decide_bash(cmd, is_main_session=False).allow
    assert not permission.decide_bash(cmd, is_main_session=True).allow


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
    assert not permission.decide_bash(cmd, is_main_session=False).allow
    assert not permission.decide_bash(cmd, is_main_session=True).allow


@pytest.mark.parametrize("cmd", [
    # a `timeout` prefix in front of a legit pipeline must STILL be approved — the
    # unwrap fix must not quote the `|` or otherwise break the pipeline.
    "timeout 30 tail -1 f.json | jq '.'",
    "timeout 5 jq '.x' f.json",
])
def test_timeout_prefix_keeps_legit_pipeline(cmd):
    assert permission.decide_bash(cmd, is_main_session=True).allow
    assert permission.decide_bash(cmd, is_main_session=False).allow


@pytest.mark.parametrize("cmd", [
    # A quote spanning a newline is unparseable → split_segments hands back one
    # opaque token. It must fail CLOSED, not be mistaken for an adapter (its head
    # "starts with defender-") and routed to the capture path.
    "defender-elastic query 'unterminated\nrest'",
    "jq '.a\n.b' f.json",
])
def test_unparseable_quote_spanning_newline_fails_closed(cmd):
    assert not permission.decide_bash(cmd, is_main_session=False).allow
    assert not permission.decide_bash(cmd, is_main_session=True).allow
    assert permission.adapter_argv(cmd) is None  # not routed to capture


# --- read ------------------------------------------------------------------

@pytest.mark.parametrize("path", [
    "/workspace/playground-v2/.env",
    "/home/user/.ssh/id_rsa",
    "/run/x/ground_truth.yaml",
    "fixtures/held-out/cases.json",
])
def test_read_denies_secrets_and_groundtruth(path):
    assert not permission.decide_read(Path(path), is_main_session=True).allow


def test_read_denies_main_loop_gather_raw():
    assert not permission.decide_read(
        Path("/tmp/defender-runs/x/gather_raw/l-001/0.json"), is_main_session=True).allow


def test_read_allows_alert_and_skill():
    assert permission.decide_read(Path("/tmp/defender-runs/x/alert.json"), is_main_session=True).allow
    assert permission.decide_read(Path("/workspace/defender/SKILL.md"), is_main_session=True).allow


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
