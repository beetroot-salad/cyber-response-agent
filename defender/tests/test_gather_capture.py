"""Pure unit tests for the gather capture core + lead claim (no model, CI).

`record_query.capture()` is the harness capability behind gather's data-source
access (the in-process replacement for the `defender-record-query` wrapper): run
an adapter, persist its payload, append the queries-table row. `record_lead.
claim_lead()` is the atomic lead-id claim the `gather` dispatch tool calls.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

# The workspace root is on sys.path via pytest's `pythonpath = [".."]`, so
# `defender.*` namespace imports resolve.
from defender.scripts.gather_tools.record_query import capture
from defender.hooks.record_lead import claim_lead

# A defender dir whose `.venv` carries duckdb — needed only by the adapter→
# defender-sql pipe test, which runs the real shim. Prefer this checkout's defender
# dir (CI bootstraps its venv); fall back to the canonical /workspace install.
_DEFENDER_DIR = next(
    (d for d in (Path(__file__).resolve().parents[1], Path("/workspace/defender"))
     if (d / ".venv/bin/python3").exists()),
    None,
)

# A stub adapter named like an adapter CLI so derive_system → "elastic".
# argv[1] selects the mode (ok / empty / error).
_STUB = """#!/usr/bin/env python3
import sys
mode = sys.argv[1] if len(sys.argv) > 1 else "ok"
if mode == "error":
    sys.stderr.write("connection refused\\n"); sys.exit(2)
if mode == "empty":
    sys.exit(0)
sys.stdout.write('{"hits": [{"id": 1}, {"id": 2}]}')
"""


@pytest.fixture
def stub(tmp_path):
    p = tmp_path / "elastic_cli.py"
    p.write_text(_STUB)
    return p


def _argv(stub, mode):
    return [sys.executable, str(stub), mode]


def test_capture_ok_writes_row_and_payload(tmp_path, stub):
    passthrough, stderr, record = capture(tmp_path, "l-001", _argv(stub, "ok"))

    # The queries-table row carries the full schema the lead-author reads.
    assert record["lead_id"] == "l-001"
    assert record["seq"] == 0
    assert record["system"] == "elastic"
    assert record["verb"] == "ok"
    assert record["query_id"] == "elastic.ok"      # derived {system}.{verb}
    assert record["params"] == {}
    assert "elastic_cli.py" in record["raw_command"]
    assert record["payload_path"] == "gather_raw/l-001/0.json"
    assert record["exit_code"] == 0
    assert record["payload_status"] == "ok"
    assert record["payload_digest"]

    # The payload is persisted by-ref, verbatim; the row is appended to the table.
    payload = (tmp_path / record["payload_path"]).read_text()
    assert json.loads(payload) == {"hits": [{"id": 1}, {"id": 2}]}
    rows = (tmp_path / "executed_queries.jsonl").read_text().splitlines()
    assert len(rows) == 1
    assert json.loads(rows[0])["seq"] == 0
    # The in-context passthrough is a field-shape SAMPLE of the record list (so
    # the raw dump never re-enters the subagent's context); the full payload is
    # persisted verbatim on disk (asserted above).
    assert "FIELD-SHAPE sample" in passthrough
    assert "2 records" in passthrough
    assert "sample[0]" in passthrough
    assert payload not in passthrough


def test_capture_seq_is_monotonic_per_lead(tmp_path, stub):
    capture(tmp_path, "l-001", _argv(stub, "ok"))
    _, _, r2 = capture(tmp_path, "l-001", _argv(stub, "ok"))
    assert r2["seq"] == 1
    assert r2["payload_path"] == "gather_raw/l-001/1.json"
    # A different lead sequences independently.
    _, _, r_other = capture(tmp_path, "l-002", _argv(stub, "ok"))
    assert r_other["seq"] == 0


def test_capture_error_status(tmp_path, stub):
    _, stderr, record = capture(tmp_path, "l-001", _argv(stub, "error"))
    assert record["exit_code"] == 2
    assert record["payload_status"] == "error"
    assert "connection refused" in stderr
    # A failed query still appends a row (so seq stays monotonic).
    assert (tmp_path / "executed_queries.jsonl").read_text().strip()


def test_capture_empty_status(tmp_path, stub):
    _, _, record = capture(tmp_path, "l-001", _argv(stub, "empty"))
    assert record["exit_code"] == 0
    assert record["payload_status"] == "empty"


def test_capture_rejects_bad_lead(tmp_path, stub):
    with pytest.raises(ValueError, match="invalid lead id"):
        capture(tmp_path, "../escape", _argv(stub, "ok"))


@pytest.mark.parametrize(
    "bad_qid",
    [
        "elastic.../../../../tmp/PWNED",   # `/` separators → traversal
        "elastic.sub/dir",                 # bare `/`
        "elastic.up..down",                # parent-ref token
        "../../etc/passwd",                # absolute-ish escape, no dot
        "elastic.bad\\seg",                # backslash separator
    ],
)
def test_capture_rejects_traversal_query_id(tmp_path, stub, bad_qid):
    # A model-coined --query-id with path-traversal characters is rejected at the
    # boundary so it can never reach lead_author.synthesize_drafts' path build,
    # and no queries-table row is written.
    with pytest.raises(ValueError, match="path-traversal"):
        capture(tmp_path, "l-001", _argv(stub, "ok"), query_id=bad_qid)
    assert not (tmp_path / "executed_queries.jsonl").exists()


def test_capture_accepts_normal_coined_query_id(tmp_path, stub):
    # A normally-coined `{system}.{kebab}` id passes through untouched.
    _, _, record = capture(
        tmp_path, "l-001", _argv(stub, "ok"), query_id="elastic.sshd-auth-baseline-7d"
    )
    assert record["query_id"] == "elastic.sshd-auth-baseline-7d"


def test_capture_rejects_undetectable_system(tmp_path):
    # No defender-<system> shim / <system>_cli.py token → system can't be derived.
    with pytest.raises(ValueError, match="system could not be derived"):
        capture(tmp_path, "l-001", ["echo", "hi"])


@pytest.mark.skipif(_DEFENDER_DIR is None, reason="needs a defender .venv with duckdb")
def test_capture_adapter_sql_pipe_aggregates(tmp_path, stub):
    # The sanctioned `adapter --raw | defender-sql '<SQL>'` pipe (#379): the bash
    # tool captures the adapter payload, then aggregates it through the real
    # defender-sql shim. The adapter query is audited (queries row + by-ref
    # payload); the SQL runs over the FULL payload, not the truncated passthrough.
    pytest.importorskip("duckdb")  # the shim's interpreter needs duckdb (runtime extra)
    from defender.runtime import tools
    from defender.runtime.agent_definition import compile_policy_for
    from defender.runtime.driver import GATHER_DEF

    deps = tools.GatherDeps(
        run_dir=tmp_path, defender_dir=_DEFENDER_DIR, run_id="r", salt="s",
        lead_id="l-001",
        # gather policy is per-run since #535 (no static default) — build it from the run's roots.
        policy=compile_policy_for(GATHER_DEF, run_dir=tmp_path, defender_dir=_DEFENDER_DIR),
    )
    out = tools._capture_adapter_sql(
        deps, _argv(stub, "ok"), ["defender-sql", "SELECT len(hits) AS n FROM data"],
    )
    # The adapter query is recorded (audited) and its payload persisted by-ref.
    rows = (tmp_path / "executed_queries.jsonl").read_text().splitlines()
    assert len(rows) == 1
    assert json.loads(rows[0])["system"] == "elastic"
    assert (tmp_path / "gather_raw" / "l-001" / "0.json").exists()
    # defender-sql aggregated the full 2-record payload.
    body = out.split("--- stdout ---\n", 1)[1].split("\n[record_query]")[0].strip()
    assert json.loads(body) == [{"n": 2}]


def test_claim_lead_claims_then_rejects_reuse(tmp_path):
    dispatch = {
        "run_dir": str(tmp_path), "lead_id": "l-001",
        "goal": "did the IP resolve?", "what_to_summarize": ["a", "b"],
    }
    assert claim_lead(dispatch) == 0
    sidecar = tmp_path / "gather_raw" / "l-001.lead.json"
    assert json.loads(sidecar.read_text()) == {
        "goal": "did the IP resolve?", "what_to_summarize": ["a", "b"]}
    # A reused id is rejected (the gather tool maps this to ModelRetry).
    assert claim_lead(dispatch) == 2
