"""Tests for the defender-sql aggregation shim (scripts/tools/sql_cli.py).

Pins two contracts:

1. **Aggregation.** A JSON `--raw` envelope or NDJSON piped on stdin is
   exposed as the table `data` with `read_json_auto` inference, so the
   caller's SQL (structs, `unnest`, GROUP BY) computes the answer — the
   tier-2 fallback for a source with no native aggregation.
2. **Sandbox.** The caller's SQL runs after the connection is sealed, so it
   cannot read files (including the held-out ground-truth the read-deny
   protects), write files, or re-enable access. This is what lets the shim
   be auto-approved for the gather subagent, which handles untrusted data.

Skipped when duckdb isn't installed (it lives in the `runtime` extra, not
`dev`/CI), mirroring the live/llm markers.
"""
from __future__ import annotations

import importlib.util
import io
import json
from pathlib import Path

import pytest

pytest.importorskip("duckdb")

_SQL_PATH = Path(__file__).resolve().parents[1] / "scripts" / "tools" / "sql_cli.py"
_spec = importlib.util.spec_from_file_location("sql_cli", _SQL_PATH)
sql_cli = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sql_cli)


def _run(monkeypatch, capsys, payload: str, query: str) -> tuple[int, str]:
    monkeypatch.setattr("sys.stdin", io.StringIO(payload))
    code = sql_cli._run(query)
    return code, capsys.readouterr().out


_ENVELOPE = json.dumps({
    "system": "example", "endpoint": "/events", "args": {"q": "status:failed"},
    "result": {"hits": [
        {"user": "root", "src_ip": "203.0.113.4"},
        {"user": "root", "src_ip": "203.0.113.4"},
        {"user": "root", "src_ip": "203.0.113.9"},
        {"user": "sre.alice", "src_ip": "10.0.0.5"},
    ]},
})


# --- aggregation ----------------------------------------------------------


def test_aggregates_over_raw_envelope(monkeypatch, capsys):
    code, out = _run(
        monkeypatch, capsys, _ENVELOPE,
        "SELECT h.user AS user, count(*) c, count(DISTINCT h.src_ip) ips "
        "FROM (SELECT unnest(result.hits) h FROM data) GROUP BY user ORDER BY c DESC",
    )
    assert code == sql_cli.EXIT_OK
    assert json.loads(out) == [
        {"user": "root", "c": 3, "ips": 2},
        {"user": "sre.alice", "c": 1, "ips": 1},
    ]


def test_aggregates_ndjson(monkeypatch, capsys):
    code, out = _run(
        monkeypatch, capsys, '{"u":"a"}\n{"u":"b"}\n{"u":"a"}\n',
        "SELECT u, count(*) c FROM data GROUP BY u ORDER BY u",
    )
    assert code == sql_cli.EXIT_OK
    assert json.loads(out) == [{"u": "a", "c": 2}, {"u": "b", "c": 1}]


# --- input / query errors -------------------------------------------------


def test_empty_stdin_is_input_error(monkeypatch, capsys):
    code, out = _run(monkeypatch, capsys, "   ", "SELECT 1")
    assert code == sql_cli.EXIT_INPUT_ERROR
    assert out == ""


def test_bad_sql_is_query_error(monkeypatch, capsys):
    code, out = _run(monkeypatch, capsys, _ENVELOPE, "SELECT no_such_col FROM data")
    assert code == sql_cli.EXIT_QUERY_ERROR
    assert out == ""


# --- sandbox: the caller's SQL is sealed ----------------------------------


@pytest.mark.parametrize("hostile", [
    "SELECT * FROM read_csv('/etc/hostname')",                       # arbitrary file read
    "SELECT * FROM read_json_auto('/workspace/x/ground_truth.json')",  # held-out read-deny
    "ATTACH '/etc/hostname' AS e",                                   # attach another db
    "SET enable_external_access=true",                              # undo the seal
])
def test_sandbox_blocks_filesystem_and_unlock(monkeypatch, capsys, tmp_path, hostile):
    code, out = _run(monkeypatch, capsys, _ENVELOPE, hostile)
    assert code == sql_cli.EXIT_QUERY_ERROR
    assert out == ""


def test_sandbox_blocks_file_write(monkeypatch, capsys, tmp_path):
    target = tmp_path / "exfil.csv"
    code, _ = _run(monkeypatch, capsys, _ENVELOPE, f"COPY (SELECT 1 x) TO '{target}'")
    assert code == sql_cli.EXIT_QUERY_ERROR
    assert not target.exists()
