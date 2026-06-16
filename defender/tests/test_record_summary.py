"""Tests for the gather summary capture wrapper (scripts/tools/record_summary.py).

Pins the verifiable-summary contract: a computable dimension is a *recorded
computation whose stdout IS the value*, gated by a fail-closed, shell-free
wrapper. The gate is honest and deterministic — a tool allowlist of pure
transforms, read-scope confined to `gather_raw/`, env-scrubbed + rlimited
execution — and the row lands in `summaries.jsonl` with a `payload_seq` FK to
the queries table. `--lead` is the `:L` row id; `--run-dir` defaults to
`$DEFENDER_RUN_DIR`.
"""
from __future__ import annotations

import importlib.util
import json
import shutil
from pathlib import Path

import pytest

_RS_PATH = Path(__file__).resolve().parents[1] / "scripts" / "tools" / "record_summary.py"
_spec = importlib.util.spec_from_file_location("record_summary", _RS_PATH)
rs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rs)

_HAS_DATAMASH = shutil.which("datamash") is not None


# --- fixtures -------------------------------------------------------------


def _run_with_payload(tmp_path: Path, records: list) -> Path:
    """A run dir holding gather_raw/l-001/0.json with `records` (a JSON array)."""
    run_dir = tmp_path / "run"
    (run_dir / "gather_raw" / "l-001").mkdir(parents=True)
    (run_dir / "gather_raw" / "l-001" / "0.json").write_text(json.dumps(records))
    return run_dir


_SAMPLE = [
    {"data": {"srcuser": "root", "srcip": "1.1.1.1"}},
    {"data": {"srcuser": "root", "srcip": "1.1.1.1"}},
    {"data": {"srcuser": "admin", "srcip": "2.2.2.2"}},
    {"data": {"srcuser": "nagios", "srcip": "2.2.2.2"}},
]


# --- split_pipeline: quote-aware, rejects bare shell operators ------------


def test_split_pipeline_pipe_inside_quotes_is_one_segment():
    assert rs.split_pipeline("jq '.a | .b' f.json") == ["jq '.a | .b' f.json"]


def test_split_pipeline_bare_pipe_splits():
    assert rs.split_pipeline("jq -r '.x' f | sort | uniq -c") == [
        "jq -r '.x' f", "sort", "uniq -c"
    ]


def test_split_pipeline_gt_inside_quotes_is_allowed():
    # `>` inside a jq program is a comparison, not a redirect.
    assert rs.split_pipeline("jq 'select(.x > 5)' f") == ["jq 'select(.x > 5)' f"]


@pytest.mark.parametrize("bad", [
    "jq '.' f ; rm x",      # chain
    "jq '.' f && rm x",     # chain
    "jq '.' f > out",       # redirect
    "jq '.' f < in",        # redirect
    "jq `whoami` f",        # substitution
])
def test_split_pipeline_rejects_bare_operators(bad):
    with pytest.raises(rs.GateError):
        rs.split_pipeline(bad)


def test_split_pipeline_rejects_empty_segment():
    with pytest.raises(rs.GateError):
        rs.split_pipeline("jq '.' f | | sort")
    with pytest.raises(rs.GateError):
        rs.split_pipeline("| sort")


def test_split_pipeline_rejects_unterminated_quote():
    with pytest.raises(rs.GateError):
        rs.split_pipeline("jq '.a f")


# --- parse_inner: single command vs quoted pipeline -----------------------


def test_parse_inner_single_bare_command():
    assert rs.parse_inner(["jq", ".a", "f.json"]) == [["jq", ".a", "f.json"]]


def test_parse_inner_quoted_pipeline_one_element():
    assert rs.parse_inner(["jq -r '.x' f | sort | uniq -c"]) == [
        ["jq", "-r", ".x", "f"], ["sort"], ["uniq", "-c"]
    ]


def test_parse_inner_roundtrips_program_with_pipe_and_spaces():
    # A jq program carrying a pipe arrives as one argv element; it must stay one
    # segment, not be split as a shell pipe.
    assert rs.parse_inner(["jq", ".a | .b", "f"]) == [["jq", ".a | .b", "f"]]


# --- gate_tools: pure-transform allowlist ---------------------------------


def test_gate_tools_allows_suite():
    rs.gate_tools([["jq", ".", "f"]])
    rs.gate_tools([["jq", "-r", ".x", "f"], ["sort"], ["uniq", "-c"]])
    rs.gate_tools([["datamash", "mean", "1"]])


@pytest.mark.parametrize("argv", [
    ["python3", "-c", "print(1)"],
    ["awk", "{print}"],
    ["sqlite3", "db"],
    ["cat", "f"],          # not an analysis filter (and would bypass read-scope intent)
    ["sh", "-c", "x"],
    ["/usr/bin/awk", "x"],  # basename-checked
])
def test_gate_tools_rejects_scripting_and_other(argv):
    with pytest.raises(rs.GateError):
        rs.gate_tools([argv])


# --- gate_paths: read-scope + payload_seq ---------------------------------


def test_gate_paths_allows_gather_raw_and_derives_seq(tmp_path):
    run_dir = _run_with_payload(tmp_path, _SAMPLE)
    seq = rs.gate_paths([["jq", ".", "gather_raw/l-001/0.json"]], run_dir)
    assert seq == 0


def test_gate_paths_rejects_absolute_outside(tmp_path):
    run_dir = _run_with_payload(tmp_path, _SAMPLE)
    secret = tmp_path / "secret.env"
    secret.write_text("TOKEN=abc")
    with pytest.raises(rs.GateError):
        rs.gate_paths([["jq", ".", str(secret)]], run_dir)


def test_gate_paths_rejects_in_rundir_but_outside_gather_raw(tmp_path):
    run_dir = _run_with_payload(tmp_path, _SAMPLE)
    (run_dir / "alert.json").write_text("{}")
    with pytest.raises(rs.GateError):
        rs.gate_paths([["jq", ".", "alert.json"]], run_dir)


def test_gate_paths_rejects_dotdot_escape(tmp_path):
    run_dir = _run_with_payload(tmp_path, _SAMPLE)
    secret = tmp_path / "secret.env"
    secret.write_text("TOKEN=abc")
    with pytest.raises(rs.GateError):
        rs.gate_paths([["jq", ".", "gather_raw/l-001/../../../secret.env"]], run_dir)


def test_gate_paths_ignores_nonfile_pathish_tokens(tmp_path):
    # A jq program with a `/` (string split) points at no file → not constrained.
    run_dir = _run_with_payload(tmp_path, _SAMPLE)
    assert rs.gate_paths([["jq", '.path | split("/")', "gather_raw/l-001/0.json"]], run_dir) == 0


# --- main(): end-to-end over real tools, value-is-output ------------------


def test_main_records_value_and_passes_through(tmp_path, capsys):
    run_dir = _run_with_payload(tmp_path, _SAMPLE)
    rc = rs.main(["--run-dir", str(run_dir), "--lead", "l-001",
                  "--label", "distinct-users", "--",
                  "jq", "[.[].data.srcuser] | unique | length",
                  "gather_raw/l-001/0.json"])
    assert rc == 0
    out = capsys.readouterr().out
    assert out.strip() == "3"   # root, admin, nagios
    rows = [json.loads(ln) for ln in (run_dir / "summaries.jsonl").read_text().splitlines()]
    assert len(rows) == 1
    r = rows[0]
    assert r["lead_id"] == "l-001" and r["payload_seq"] == 0 and r["summary_seq"] == 0
    assert r["label"] == "distinct-users"
    assert r["output"].strip() == "3"
    assert r["output_status"] == "ok" and r["exit_code"] == 0
    assert r["tools"] == ["jq"]


def test_main_quoted_pipeline_records_final_stage(tmp_path, capsys):
    run_dir = _run_with_payload(tmp_path, _SAMPLE)
    rc = rs.main(["--run-dir", str(run_dir), "--lead", "l-001",
                  "--label", "srcip-distribution", "--",
                  "jq -r '.[].data.srcip' gather_raw/l-001/0.json | sort | uniq -c | sort -rn"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "2.2.2.2" in out and "1.1.1.1" in out
    row = json.loads((run_dir / "summaries.jsonl").read_text().splitlines()[0])
    assert set(row["tools"]) == {"jq", "sort", "uniq"}
    assert "2.2.2.2" in row["output"]


@pytest.mark.skipif(not _HAS_DATAMASH, reason="datamash not installed")
def test_main_datamash_pipeline(tmp_path, capsys):
    run_dir = _run_with_payload(tmp_path, [{"v": 1}, {"v": 2}, {"v": 3}, {"v": 4}])
    rc = rs.main(["--run-dir", str(run_dir), "--lead", "l-001", "--label", "median-v", "--",
                  "jq -r '.[].v' gather_raw/l-001/0.json | datamash median 1"])
    assert rc == 0
    assert capsys.readouterr().out.strip() == "2.5"


def test_main_value_is_output_on_snippet_error(tmp_path, capsys):
    # A snippet that errors yields no value — recorded as error, not a prose
    # substitute. This is the core "output IS the value" guarantee.
    run_dir = _run_with_payload(tmp_path, _SAMPLE)
    rc = rs.main(["--run-dir", str(run_dir), "--lead", "l-001", "--label", "broken", "--",
                  "jq", "{ this is not valid", "gather_raw/l-001/0.json"])
    assert rc != 0
    row = json.loads((run_dir / "summaries.jsonl").read_text().splitlines()[0])
    assert row["output_status"] == "error" and row["exit_code"] != 0
    assert row["output"] == ""


def test_main_summary_seq_increments_per_lead(tmp_path):
    run_dir = _run_with_payload(tmp_path, _SAMPLE)
    for label in ("a", "b"):
        rs.main(["--run-dir", str(run_dir), "--lead", "l-001", "--label", label, "--",
                 "jq", "length", "gather_raw/l-001/0.json"])
    rows = [json.loads(ln) for ln in (run_dir / "summaries.jsonl").read_text().splitlines()]
    assert [r["summary_seq"] for r in rows] == [0, 1]


# --- main(): gate rejections (exit 2, no row escapes) ---------------------


def test_main_rejects_disallowed_tool(tmp_path, capsys):
    run_dir = _run_with_payload(tmp_path, _SAMPLE)
    rc = rs.main(["--run-dir", str(run_dir), "--lead", "l-001", "--label", "x", "--",
                  "python3", "-c", "print(1)"])
    assert rc == 2
    assert "not a permitted analysis filter" in capsys.readouterr().err
    assert not (run_dir / "summaries.jsonl").exists()


def test_main_rejects_out_of_scope_read(tmp_path, capsys):
    run_dir = _run_with_payload(tmp_path, _SAMPLE)
    secret = tmp_path / "secret.env"
    secret.write_text("TOKEN=abc")
    rc = rs.main(["--run-dir", str(run_dir), "--lead", "l-001", "--label", "x", "--",
                  "jq", ".", str(secret)])
    assert rc == 2
    assert "out of scope" in capsys.readouterr().err
    assert not (run_dir / "summaries.jsonl").exists()


@pytest.mark.parametrize("bad_lead", ["../etc", "/etc", "x-001", "l 1", ""])
def test_main_rejects_invalid_lead(tmp_path, bad_lead):
    run_dir = _run_with_payload(tmp_path, _SAMPLE)
    rc = rs.main(["--run-dir", str(run_dir), "--lead", bad_lead, "--label", "x", "--",
                  "jq", "length", "gather_raw/l-001/0.json"])
    assert rc == 2
    assert not (run_dir / "summaries.jsonl").exists()


def test_main_rejects_invalid_label(tmp_path):
    run_dir = _run_with_payload(tmp_path, _SAMPLE)
    rc = rs.main(["--run-dir", str(run_dir), "--lead", "l-001", "--label", "Bad Label", "--",
                  "jq", "length", "gather_raw/l-001/0.json"])
    assert rc == 2
    assert not (run_dir / "summaries.jsonl").exists()


# --- --run-dir defaulting -------------------------------------------------


def test_main_defaults_run_dir_from_env(tmp_path, monkeypatch):
    run_dir = _run_with_payload(tmp_path, _SAMPLE)
    monkeypatch.setenv("DEFENDER_RUN_DIR", str(run_dir))
    rc = rs.main(["--lead", "l-001", "--label", "n", "--",
                  "jq", "length", "gather_raw/l-001/0.json"])
    assert rc == 0
    assert (run_dir / "summaries.jsonl").is_file()


def test_main_errors_when_no_run_dir(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("DEFENDER_RUN_DIR", raising=False)
    rc = rs.main(["--lead", "l-001", "--label", "n", "--", "jq", "length", "x.json"])
    assert rc == 2
    assert "DEFENDER_RUN_DIR is unset" in capsys.readouterr().err
