"""Tests for the defender-sql aggregation shim (scripts/gather_tools/sql.py).

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
import types
from pathlib import Path

import pytest

pytest.importorskip("duckdb")

_SQL_PATH = Path(__file__).resolve().parents[1] / "scripts" / "gather_tools" / "sql.py"
_spec = importlib.util.spec_from_file_location("defender_sql", _SQL_PATH)
defender_sql = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(defender_sql)


def _run(monkeypatch, capsys, payload, query: str) -> tuple[int, str]:
    # _run reads sys.stdin.buffer (bytes) so untrusted, possibly non-UTF-8
    # payloads never hit a text decode. Accept str (encoded UTF-8) or raw bytes.
    data = payload.encode() if isinstance(payload, str) else payload
    fake_stdin = types.SimpleNamespace(buffer=io.BytesIO(data))
    monkeypatch.setattr("sys.stdin", fake_stdin)
    code = defender_sql._run(query)
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
    assert code == defender_sql.EXIT_OK
    assert json.loads(out) == [
        {"user": "root", "c": 3, "ips": 2},
        {"user": "sre.alice", "c": 1, "ips": 1},
    ]


def test_aggregates_ndjson(monkeypatch, capsys):
    code, out = _run(
        monkeypatch, capsys, '{"u":"a"}\n{"u":"b"}\n{"u":"a"}\n',
        "SELECT u, count(*) c FROM data GROUP BY u ORDER BY u",
    )
    assert code == defender_sql.EXIT_OK
    assert json.loads(out) == [{"u": "a", "c": 2}, {"u": "b", "c": 1}]


# --- input / query errors -------------------------------------------------


def test_empty_stdin_is_input_error(monkeypatch, capsys):
    code, out = _run(monkeypatch, capsys, "   ", "SELECT 1")
    assert code == defender_sql.EXIT_INPUT_ERROR
    assert out == ""


def test_bad_sql_is_query_error(monkeypatch, capsys):
    code, out = _run(monkeypatch, capsys, _ENVELOPE, "SELECT no_such_col FROM data")
    assert code == defender_sql.EXIT_QUERY_ERROR
    assert out == ""


def test_utf8_payload_round_trips(monkeypatch, capsys):
    # Untrusted source data routinely carries non-ASCII (usernames, hostnames,
    # log lines). A multibyte payload must aggregate, not be mangled.
    code, out = _run(
        monkeypatch, capsys, '{"u":"André"}\n{"u":"André"}\n',
        "SELECT u, count(*) c FROM data GROUP BY u",
    )
    assert code == defender_sql.EXIT_OK
    assert json.loads(out) == [{"u": "André", "c": 2}]


def test_non_utf8_payload_is_clean_input_error(monkeypatch, capsys):
    # A payload with an invalid-UTF-8 byte must exit EXIT_INPUT_ERROR, not crash
    # with an uncaught UnicodeError (it would, if stdin were read in text mode).
    code, out = _run(monkeypatch, capsys, b'{"u":"a\xff b"}\n', "SELECT u FROM data")
    assert code == defender_sql.EXIT_INPUT_ERROR
    assert out == ""


def test_non_finite_floats_serialize_as_null(monkeypatch, capsys):
    # A divide-by-zero ratio yields a DOUBLE Infinity; the output must stay
    # strict JSON (null), not the bare `Infinity` literal RFC 8259 forbids and a
    # strict downstream parser (JS JSON.parse, Go) rejects.
    code, out = _run(
        monkeypatch, capsys, '{"hits":1,"total":0}',
        "SELECT hits::DOUBLE / total::DOUBLE AS ratio FROM data",
    )
    assert code == defender_sql.EXIT_OK
    assert "Infinity" not in out
    assert "NaN" not in out
    assert json.loads(out) == [{"ratio": None}]


def test_tmpdir_with_quote_does_not_break_materialization(monkeypatch, capsys, tmp_path):
    # mkdtemp honors $TMPDIR; a scratch path containing a single quote must not
    # break the read_json_auto call (it would, if the path were interpolated
    # into the SQL string instead of parameter-bound).
    qdir = tmp_path / "has'quote"
    qdir.mkdir()
    monkeypatch.setattr("tempfile.tempdir", str(qdir))
    code, out = _run(monkeypatch, capsys, '{"u":"x"}\n{"u":"y"}\n',
                     "SELECT count(*) c FROM data")
    assert code == defender_sql.EXIT_OK
    assert json.loads(out) == [{"c": 2}]


# --- sandbox: the caller's SQL is sealed ----------------------------------


@pytest.mark.parametrize("hostile", [
    "SELECT * FROM read_csv('/etc/hostname')",                       # arbitrary file read
    "SELECT * FROM read_json_auto('/workspace/x/ground_truth.json')",  # held-out read-deny
    "ATTACH '/etc/hostname' AS e",                                   # attach another db
    "SET enable_external_access=true",                              # undo the seal
])
def test_sandbox_blocks_filesystem_and_unlock(monkeypatch, capsys, tmp_path, hostile):
    code, out = _run(monkeypatch, capsys, _ENVELOPE, hostile)
    assert code == defender_sql.EXIT_QUERY_ERROR
    assert out == ""


def test_sandbox_blocks_file_write(monkeypatch, capsys, tmp_path):
    target = tmp_path / "exfil.csv"
    code, _ = _run(monkeypatch, capsys, _ENVELOPE, f"COPY (SELECT 1 x) TO '{target}'")
    assert code == defender_sql.EXIT_QUERY_ERROR
    assert not target.exists()
