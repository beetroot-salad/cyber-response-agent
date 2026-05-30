"""Tests for the gather capture wrapper (defender/scripts/tools/gather_exec.py).

Pins the deterministic-capture contract: argv → faithful record (the fix for
the cmdb.get-host mislabel), per-lead canonical addressing (the fix for
filename-drift silent drops), and transparent passthrough.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

_GE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "tools" / "gather_exec.py"
_spec = importlib.util.spec_from_file_location("gather_exec", _GE_PATH)
ge = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ge)


# --- parse_invocation: subcommand CLIs (verb == measurement == query_id) ---

def test_parse_cmdb_get_host():
    p = ge.parse_invocation(["python3", "/x/cmdb_cli.py", "get-host", "web-1", "--raw"])
    assert p["system"] == "cmdb"
    assert p["verb"] == "get-host"
    assert p["query_id"] == "cmdb.get-host"
    assert p["params"] == {"name": "web-1"}
    assert p["body"] is None


def test_parse_host_state_underscore_to_dash_and_two_positionals():
    p = ge.parse_invocation(["/x/host_state_cli.py", "fim-checksum", "db-1", "/etc/passwd", "--raw"])
    assert p["system"] == "host-state"
    assert p["query_id"] == "host-state.fim-checksum"
    assert p["params"] == {"host": "db-1", "path": "/etc/passwd"}


def test_parse_identity_can_access_two_named_positionals():
    p = ge.parse_invocation(["identity_cli.py", "can-access", "dev.dana", "db-1"])
    assert p["params"] == {"user": "dev.dana", "host": "db-1"}


def test_parse_value_flags():
    p = ge.parse_invocation(["change_mgmt_cli.py", "active-changes", "--host", "web-1", "--at", "2026-05-30T00:00:00Z"])
    assert p["query_id"] == "change-mgmt.active-changes"
    assert p["params"] == {"host": "web-1", "at": "2026-05-30T00:00:00Z"}


# --- parse_invocation: query-string CLI (body distinguishes the template) ---

def test_parse_elastic_query_captures_body():
    p = ge.parse_invocation(["elastic_cli.py", "query", 'process.name:"sshd"', "--limit", "20", "--raw"])
    assert p["query_id"] == "elastic.query"
    assert p["body"] == 'process.name:"sshd"'
    assert p["params"] == {"limit": "20"}


def test_parse_unknown_cli_does_not_raise():
    p = ge.parse_invocation(["python3", "-c", "print(1)"])
    assert p["system"] == "unknown"
    assert p["query_id"] == "unknown"


# --- payload_status ---

def test_payload_status():
    assert ge.payload_status(0, '{"a":1}') == "ok"
    assert ge.payload_status(0, "   \n") == "empty"
    assert ge.payload_status(3, "anything") == "error"


# --- end-to-end main(): real subprocess, addressing, passthrough, exit ---

def _fake_cli(tmp_path: Path, name: str, stdout: str, exit_code: int = 0) -> Path:
    cli = tmp_path / name
    cli.write_text(
        "import sys\n"
        f"sys.stdout.write({stdout!r})\n"
        f"sys.exit({exit_code})\n"
    )
    return cli


def test_main_writes_payload_record_and_passes_through(tmp_path, capsys):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    cli = _fake_cli(tmp_path, "cmdb_cli.py", '{"name":"web-1","role":"web"}')

    rc = ge.main(["--run-dir", str(run_dir), "--lead", "l-003", "--",
                  sys.executable, str(cli), "get-host", "web-1", "--raw"])

    assert rc == 0
    payload = run_dir / "gather_raw" / "l-003" / "0.json"
    assert payload.is_file()
    assert json.loads(payload.read_text())["name"] == "web-1"

    rows = [json.loads(l) for l in (run_dir / "executed_queries.jsonl").read_text().splitlines()]
    assert len(rows) == 1
    r = rows[0]
    assert r["lead"] == "l-003" and r["seq"] == 0
    assert r["system"] == "cmdb" and r["query_id"] == "cmdb.get-host"
    assert r["params"] == {"name": "web-1"}
    assert r["payload_path"] == "gather_raw/l-003/0.json"
    assert r["payload_status"] == "ok"
    # passthrough: the CLI's stdout reaches the wrapper's stdout
    assert '"name":"web-1"' in capsys.readouterr().out


def test_main_per_lead_seq_increments(tmp_path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    cli = _fake_cli(tmp_path, "host_state_cli.py", "uid=1003\n")
    base = ["--run-dir", str(run_dir), "--lead", "l-002", "--", sys.executable, str(cli)]
    ge.main(base + ["proc-tree", "db-1"])
    ge.main(base + ["passwd", "db-1"])
    rows = [json.loads(l) for l in (run_dir / "executed_queries.jsonl").read_text().splitlines()]
    assert [r["seq"] for r in rows] == [0, 1]
    assert (run_dir / "gather_raw" / "l-002" / "0.json").is_file()
    assert (run_dir / "gather_raw" / "l-002" / "1.json").is_file()


def test_main_query_id_override_for_query_string_cli(tmp_path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    cli = _fake_cli(tmp_path, "elastic_cli.py", '{"hits":[]}')
    ge.main(["--run-dir", str(run_dir), "--lead", "0",
             "--query-id", "elastic.container-network-tool-cadence", "--",
             sys.executable, str(cli), "query", 'falco.rule:"x"', "--raw"])
    row = json.loads((run_dir / "executed_queries.jsonl").read_text().splitlines()[0])
    # subagent-chosen template id wins over the derived elastic.query
    assert row["query_id"] == "elastic.container-network-tool-cadence"
    assert row["body"] == 'falco.rule:"x"'


def test_main_propagates_nonzero_exit_and_error_status(tmp_path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    cli = _fake_cli(tmp_path, "cmdb_cli.py", "", exit_code=3)
    rc = ge.main(["--run-dir", str(run_dir), "--lead", "l-1", "--",
                  sys.executable, str(cli), "get-host", "nope"])
    assert rc == 3
    row = json.loads((run_dir / "executed_queries.jsonl").read_text().splitlines()[0])
    assert row["exit_code"] == 3 and row["payload_status"] == "error"
