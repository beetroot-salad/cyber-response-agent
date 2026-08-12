"""Tests for the defender-sql aggregation shim (scripts/gather_tools/sql.py).

Pins two contracts:

1. **Aggregation.** A JSON payload or NDJSON piped on stdin is exposed as
   the table `data` with `read_json_auto` inference — the payload's own
   top-level keys are the columns, with no wrapper envelope — so the
   caller's SQL (structs, `unnest`, GROUP BY) computes the answer. The
   tier-2 fallback for a source with no native aggregation.
2. **Sandbox.** The caller's SQL runs after the connection is sealed, so it
   cannot read files (including the held-out ground-truth the read-deny
   protects), write files, or re-enable access. This is what lets the shim
   be auto-approved for the gather subagent, which handles untrusted data.

Skipped when duckdb isn't installed (it lives in the `runtime` extra, not
`dev`/CI), mirroring the live/llm markers.
"""
from __future__ import annotations

import io
import json
import types

from defender.tests._by_path import DEFENDER, load_module

import pytest

pytest.importorskip("duckdb")

defender_sql = load_module(DEFENDER / "scripts" / "gather_tools" / "sql.py", name="defender_sql")


def _run_full(monkeypatch, capsys, payload, query: str) -> tuple[int, str, str]:
    data = payload.encode() if isinstance(payload, str) else payload
    fake_stdin = types.SimpleNamespace(buffer=io.BytesIO(data))
    monkeypatch.setattr("sys.stdin", fake_stdin)
    code = defender_sql._run(query)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def _run(monkeypatch, capsys, payload, query: str) -> tuple[int, str]:
    code, out, _err = _run_full(monkeypatch, capsys, payload, query)
    return code, out


_PAYLOAD = json.dumps({
    "index": "logs-*", "total": 4, "returned": 4, "truncated": False,
    "hits": [
        {"user": "root", "src_ip": "203.0.113.4"},
        {"user": "root", "src_ip": "203.0.113.4"},
        {"user": "root", "src_ip": "203.0.113.9"},
        {"user": "sre.alice", "src_ip": "10.0.0.5"},
    ],
})




def test_aggregates_over_the_payload(monkeypatch, capsys):
    code, out = _run(
        monkeypatch, capsys, _PAYLOAD,
        "SELECT h.user AS user, count(*) c, count(DISTINCT h.src_ip) ips "
        "FROM (SELECT unnest(hits) h FROM data) GROUP BY user ORDER BY c DESC",
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




_ECS_PAYLOAD = json.dumps({
    "index": "logs-*", "total": 1, "returned": 1, "truncated": False,
    "hits": [
        {
            "user": {"name": "sre.alice"},
            "process": {"name": "nc"},
            "host": {"name": "web-04"},
            "agent": {"name": "wazuh-agent-2"},
        },
    ],
})


def test_duplicate_output_columns_all_survive(monkeypatch, capsys):
    """ECS nests the interesting fields, so an unaliased two-field projection collides
    on the leaf name. Both values must reach the row — zipping into a dict used to keep
    only the last, and exit 0 said nothing about it (#854 F-13)."""
    code, out, err = _run_full(
        monkeypatch, capsys, _ECS_PAYLOAD,
        "SELECT h.user.name, h.process.name FROM (SELECT unnest(hits) h FROM data)",
    )
    assert code == defender_sql.EXIT_OK
    assert json.loads(out) == [{"name": "sre.alice", "name_1": "nc"}]
    assert "name -> name_1" in err


def test_duplicate_column_rename_is_stable_across_three_way_collision(monkeypatch, capsys):
    code, out, err = _run_full(
        monkeypatch, capsys, _ECS_PAYLOAD,
        "SELECT h.user.name, h.process.name, h.host.name "
        "FROM (SELECT unnest(hits) h FROM data)",
    )
    assert code == defender_sql.EXIT_OK
    assert json.loads(out) == [
        {"name": "sre.alice", "name_1": "nc", "name_2": "web-04"}]
    assert "name -> name_1" in err
    assert "name -> name_2" in err


def test_rename_does_not_collide_with_a_literal_alias_of_the_same_name(monkeypatch, capsys):
    """The renamer must not manufacture a NEW collision when the projection already
    contains the name it would generate."""
    assert defender_sql._disambiguate_columns(["name", "name_1", "name"]) == (
        ["name", "name_1", "name_2"], ["name -> name_2"])
    assert defender_sql._disambiguate_columns(["a", "b"]) == (["a", "b"], [])


def test_unique_columns_emit_no_collision_note(monkeypatch, capsys):
    code, out, err = _run_full(
        monkeypatch, capsys, _ECS_PAYLOAD,
        "SELECT h.user.name AS user_name, h.process.name AS process_name "
        "FROM (SELECT unnest(hits) h FROM data)",
    )
    assert code == defender_sql.EXIT_OK
    assert json.loads(out) == [{"user_name": "sre.alice", "process_name": "nc"}]
    assert "renamed" not in err


def test_empty_stdin_is_input_error(monkeypatch, capsys):
    code, out = _run(monkeypatch, capsys, "   ", "SELECT 1")
    assert code == defender_sql.EXIT_INPUT_ERROR
    assert out == ""


def test_bad_sql_is_query_error(monkeypatch, capsys):
    code, out = _run(monkeypatch, capsys, _PAYLOAD, "SELECT no_such_col FROM data")
    assert code == defender_sql.EXIT_QUERY_ERROR
    assert out == ""


def test_utf8_payload_round_trips(monkeypatch, capsys):
    code, out = _run(
        monkeypatch, capsys, '{"u":"André"}\n{"u":"André"}\n',
        "SELECT u, count(*) c FROM data GROUP BY u",
    )
    assert code == defender_sql.EXIT_OK
    assert json.loads(out) == [{"u": "André", "c": 2}]


def test_non_utf8_payload_is_clean_input_error(monkeypatch, capsys):
    code, out = _run(monkeypatch, capsys, b'{"u":"a\xff b"}\n', "SELECT u FROM data")
    assert code == defender_sql.EXIT_INPUT_ERROR
    assert out == ""


def test_non_finite_floats_serialize_as_null(monkeypatch, capsys):
    code, out = _run(
        monkeypatch, capsys, '{"hits":1,"total":0}',
        "SELECT hits::DOUBLE / total::DOUBLE AS ratio FROM data",
    )
    assert code == defender_sql.EXIT_OK
    assert "Infinity" not in out
    assert "NaN" not in out
    assert json.loads(out) == [{"ratio": None}]


def test_tmpdir_with_quote_does_not_break_materialization(monkeypatch, capsys, tmp_path):
    qdir = tmp_path / "has'quote"
    qdir.mkdir()
    monkeypatch.setattr("tempfile.tempdir", str(qdir))
    code, out = _run(monkeypatch, capsys, '{"u":"x"}\n{"u":"y"}\n',
                     "SELECT count(*) c FROM data")
    assert code == defender_sql.EXIT_OK
    assert json.loads(out) == [{"c": 2}]




@pytest.mark.parametrize("hostile", [
    "SELECT * FROM read_csv('/etc/hostname')",
    "SELECT * FROM read_json_auto('/workspace/x/ground_truth.json')",
    "ATTACH '/etc/hostname' AS e",
    "SET enable_external_access=true",
])
def test_sandbox_blocks_filesystem_and_unlock(monkeypatch, capsys, tmp_path, hostile):
    code, out = _run(monkeypatch, capsys, _PAYLOAD, hostile)
    assert code == defender_sql.EXIT_QUERY_ERROR
    assert out == ""


def test_sandbox_blocks_file_write(monkeypatch, capsys, tmp_path):
    target = tmp_path / "exfil.csv"
    code, _ = _run(monkeypatch, capsys, _PAYLOAD, f"COPY (SELECT 1 x) TO '{target}'")
    assert code == defender_sql.EXIT_QUERY_ERROR
    assert not target.exists()
