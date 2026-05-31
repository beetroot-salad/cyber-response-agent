"""Tests for the gather capture wrapper (defender/scripts/tools/gather_exec.py).

Pins the deterministic-capture contract: system + query_id come verbatim from
the dispatch (`--system`/`--query-id`, so the wrapper stays portable across any
system CLI roster — no hardcoded system/verb tables), params are parsed
generically from argv, per-lead canonical addressing fixes the filename-drift
silent drop, and the inner command passes straight through.
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


# --- parse_params: generic, no per-system tables ---

def test_parse_params_single_positional_and_boolean_flag():
    p = ge.parse_params(["python3", "/x/cmdb_cli.py", "host-lookup", "web-1", "--raw"])
    assert p == {"arg0": "web-1", "raw": True}


def test_parse_params_two_positionals():
    p = ge.parse_params(["/x/host_query.py", "fim-checksum", "db-1", "/etc/passwd", "--raw"])
    assert p == {"arg0": "db-1", "arg1": "/etc/passwd", "raw": True}


def test_parse_params_value_flags():
    p = ge.parse_params(
        ["wazuh_cli.py", "query", "--query", "rule.id:5503", "--limit", "20", "--raw"]
    )
    assert p == {"query": "rule.id:5503", "limit": "20", "raw": True}


def test_parse_params_short_flag_with_value():
    # `-q` is a real wazuh_cli short form for --query; it must capture its value,
    # not get dropped as a bare positional.
    p = ge.parse_params(["wazuh_cli.py", "query", "-q", "rule.id:5503", "--raw"])
    assert p == {"q": "rule.id:5503", "raw": True}


def test_parse_params_unknown_shape_does_not_raise():
    # No `.py` script token — still yields a dict rather than raising.
    assert isinstance(ge.parse_params(["python3", "-c", "print(1)"]), dict)


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

    rc = ge.main(["--run-dir", str(run_dir), "--lead", "3",
                  "--system", "stub-cmdb", "--query-id", "stub-cmdb.host-lookup", "--",
                  sys.executable, str(cli), "host-lookup", "web-1", "--raw"])

    assert rc == 0
    payload = run_dir / "gather_raw" / "3" / "0.json"
    assert payload.is_file()
    assert json.loads(payload.read_text())["name"] == "web-1"

    rows = [json.loads(ln) for ln in (run_dir / "executed_queries.jsonl").read_text().splitlines()]
    assert len(rows) == 1
    r = rows[0]
    assert r["lead"] == "3" and r["seq"] == 0
    assert r["system"] == "stub-cmdb" and r["query_id"] == "stub-cmdb.host-lookup"
    assert r["verb"] == "host-lookup"
    assert r["params"] == {"arg0": "web-1", "raw": True}
    assert r["payload_path"] == "gather_raw/3/0.json"
    assert r["payload_status"] == "ok"
    # passthrough: the CLI's stdout reaches the wrapper's stdout
    assert '"name":"web-1"' in capsys.readouterr().out


def test_main_records_system_and_query_id_verbatim(tmp_path):
    # The CLI filename ("host_query.py") does NOT match the catalog system
    # ("host-query"); the wrapper must trust --system / --query-id rather than
    # derive from argv. This pins the portability fix.
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    cli = _fake_cli(tmp_path, "host_query.py", "uid=1003\n")
    ge.main(["--run-dir", str(run_dir), "--lead", "0",
             "--system", "host-query", "--query-id", "host-query.proc-tree", "--",
             sys.executable, str(cli), "proc-tree", "db-1"])
    row = json.loads((run_dir / "executed_queries.jsonl").read_text().splitlines()[0])
    assert row["system"] == "host-query"
    assert row["query_id"] == "host-query.proc-tree"
    assert row["verb"] == "proc-tree"


def test_main_per_lead_seq_increments(tmp_path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    cli = _fake_cli(tmp_path, "host_query.py", "uid=1003\n")
    ge.main(["--run-dir", str(run_dir), "--lead", "2",
             "--system", "host-query", "--query-id", "host-query.proc-tree", "--",
             sys.executable, str(cli), "proc-tree", "db-1"])
    ge.main(["--run-dir", str(run_dir), "--lead", "2",
             "--system", "host-query", "--query-id", "host-query.passwd", "--",
             sys.executable, str(cli), "passwd", "db-1"])
    rows = [json.loads(ln) for ln in (run_dir / "executed_queries.jsonl").read_text().splitlines()]
    assert [r["seq"] for r in rows] == [0, 1]
    assert (run_dir / "gather_raw" / "2" / "0.json").is_file()
    assert (run_dir / "gather_raw" / "2" / "1.json").is_file()


def test_main_adhoc_query_id(tmp_path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    cli = _fake_cli(tmp_path, "wazuh_cli.py", '{"hits":[]}')
    ge.main(["--run-dir", str(run_dir), "--lead", "0",
             "--system", "wazuh", "--query-id", "ad-hoc", "--",
             sys.executable, str(cli), "query", "--query", 'rule.id:5503', "--raw"])
    row = json.loads((run_dir / "executed_queries.jsonl").read_text().splitlines()[0])
    assert row["query_id"] == "ad-hoc"
    assert row["params"] == {"query": "rule.id:5503", "raw": True}


def test_main_requires_system_and_query_id(tmp_path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    cli = _fake_cli(tmp_path, "cmdb_cli.py", "{}")
    # Missing --system/--query-id → usage error (exit 2), nothing executed.
    rc = ge.main(["--run-dir", str(run_dir), "--lead", "0", "--",
                  sys.executable, str(cli), "host-lookup", "web-1"])
    assert rc == 2
    assert not (run_dir / "executed_queries.jsonl").exists()


def test_main_propagates_nonzero_exit_and_error_status(tmp_path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    cli = _fake_cli(tmp_path, "cmdb_cli.py", "", exit_code=3)
    rc = ge.main(["--run-dir", str(run_dir), "--lead", "1",
                  "--system", "stub-cmdb", "--query-id", "stub-cmdb.host-lookup", "--",
                  sys.executable, str(cli), "host-lookup", "nope"])
    assert rc == 3
    row = json.loads((run_dir / "executed_queries.jsonl").read_text().splitlines()[0])
    assert row["exit_code"] == 3 and row["payload_status"] == "error"


# --- size-safety: oversized pass-through is truncated, payload still persisted ---

def _big_hits_payload(n: int) -> str:
    return json.dumps({"hits": [{"i": i, "message": f"event {i}", "pad": "x" * 50} for i in range(n)]})


def test_build_truncated_view_samples_records(tmp_path):
    payload = _big_hits_payload(200)
    view = ge.build_truncated_view(payload, "gather_raw/0/0.json", tmp_path)
    assert "200 records" in view
    assert view.count("sample[") == ge.PASSTHROUGH_SAMPLE_COUNT
    assert "jq" in view
    assert str(tmp_path / "gather_raw/0/0.json") in view


def test_build_truncated_view_non_json_falls_back_to_chars(tmp_path):
    view = ge.build_truncated_view("x" * 5000, "gather_raw/0/0.json", tmp_path)
    assert "bytes — pass-through truncated" in view
    assert "sample[" not in view


def test_main_truncates_oversized_passthrough_but_persists_full(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(ge, "PASSTHROUGH_MAX_BYTES", 500)
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    big = _big_hits_payload(100)
    assert len(big) > 500
    cli = _fake_cli(tmp_path, "elastic_cli.py", big)
    rc = ge.main(["--run-dir", str(run_dir), "--lead", "0",
                  "--system", "elastic", "--query-id", "elastic.q", "--",
                  sys.executable, str(cli), "query", "--raw"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "pass-through truncated" in out
    assert "100 records" in out
    # Full payload is persisted on disk regardless of the capped view.
    persisted = (run_dir / "gather_raw" / "0" / "0.json").read_text()
    assert persisted == big


def test_main_passes_small_payload_through_verbatim(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(ge, "PASSTHROUGH_MAX_BYTES", 65536)
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    cli = _fake_cli(tmp_path, "elastic_cli.py", '{"hits":[{"i":1}]}')
    rc = ge.main(["--run-dir", str(run_dir), "--lead", "0",
                  "--system", "elastic", "--query-id", "elastic.q", "--",
                  sys.executable, str(cli), "query", "--raw"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "pass-through truncated" not in out
    assert '{"hits":[{"i":1}]}' in out
