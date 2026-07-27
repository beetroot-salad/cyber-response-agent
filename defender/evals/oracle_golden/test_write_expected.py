"""Pins for the two tools that write ground truth (#711 M9 / AC 2).

Both are places where a careless default would corrupt the thing the oracle is
measured against, so both refuse rather than overwrite.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import yaml

GOLDEN_DIR = Path(__file__).resolve().parent


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None
    assert spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


WRITE = _load("oracle_golden_write_expected", GOLDEN_DIR / "write_expected.py")
RECORD = _load("oracle_golden_record", GOLDEN_DIR / "record_held_out.py")


def _case(root: Path, *, split: str = "held-out") -> Path:
    case = root / "case-x"
    (case / "scores").mkdir(parents=True)
    (case / "oracle_visible").mkdir(parents=True)
    (case / "manifest.yaml").write_text(
        yaml.safe_dump({"case_id": "case-x", "kind": "observed", "split": split}),
        encoding="utf-8")
    (case / "oracle_visible" / "leads.jsonl").write_text(
        json.dumps({"lead_id": "l-1", "queries": [
            {"query_id": "cmdb.host-trust-edges", "params": {"host": "web-1"}}]}) + "\n",
        encoding="utf-8")
    (case / "scores" / "t.json").write_text('{"rows": []}', encoding="utf-8")
    return case


# --------------------------------------------------------------------------
# write_expected
# --------------------------------------------------------------------------

def test_a_state_system_with_no_declared_rule_is_written_needs_label(tmp_path):
    """`needs-label` reaches expected.yaml deliberately: score.py matches it
    against no real class, so an undecided lead fails loudly instead of quietly
    counting as `0`."""
    case = _case(tmp_path)
    assert WRITE.main([str(case)]) == 0
    expected = yaml.safe_load((case / "expected.yaml").read_text(encoding="utf-8"))
    assert expected["leads"]["l-1"]["class"] == "needs-label"
    assert expected["case_id"] == "case-x"


def test_a_declared_state_class_is_honoured(tmp_path):
    case = _case(tmp_path)
    (case / "manifest.yaml").write_text(
        yaml.safe_dump({"case_id": "case-x", "kind": "observed", "split": "held-out",
                        "state_classes": {"cmdb": "0"}}), encoding="utf-8")
    WRITE.main([str(case)])
    expected = yaml.safe_load((case / "expected.yaml").read_text(encoding="utf-8"))
    assert expected["leads"]["l-1"]["class"] == "0"


def test_existing_ground_truth_is_never_silently_regenerated(tmp_path):
    """Regenerating labels after a projection has been scored is the move the
    procedure doc forbids unless it is a deliberate act."""
    case = _case(tmp_path)
    (case / "expected.yaml").write_text("case_id: case-x\n", encoding="utf-8")
    assert WRITE.main([str(case)]) == 1
    assert (case / "expected.yaml").read_text(encoding="utf-8") == "case_id: case-x\n"
    assert WRITE.main([str(case), "--force"]) == 0
    assert "DERIVED MECHANICALLY" in (case / "expected.yaml").read_text(encoding="utf-8")


# --------------------------------------------------------------------------
# record_held_out
# --------------------------------------------------------------------------

def _ledger(tmp_path: Path) -> Path:
    """A throwaway ledger, reached through the CLI's own `--ledger` option."""
    path = tmp_path / "ledger.yaml"
    path.write_text("# why this ledger exists\nentries: []\n", encoding="utf-8")
    return path


def test_a_held_out_result_is_recorded_with_its_hash(tmp_path):
    case = _case(tmp_path)
    ledger = _ledger(tmp_path)
    assert RECORD.main([str(case), "t", "--ledger", str(ledger)]) == 0
    entries = yaml.safe_load(ledger.read_text(encoding="utf-8"))["entries"]
    assert entries[0]["case"] == "case-x"
    assert entries[0]["sha256"] == hashlib.sha256(
        (case / "scores" / "t.json").read_bytes()).hexdigest()
    assert "why this ledger exists" in ledger.read_text(encoding="utf-8")


def test_the_same_tag_cannot_be_recorded_twice(tmp_path):
    """There is deliberately no flag to replace an entry: re-running a held-out
    case under one tag until the number improves is how a held-out set stops
    being held out."""
    case = _case(tmp_path)
    ledger = _ledger(tmp_path)
    assert RECORD.main([str(case), "t", "--ledger", str(ledger)]) == 0
    assert RECORD.main([str(case), "t", "--ledger", str(ledger)]) == 1


def test_a_dev_case_is_not_ledgered(tmp_path):
    case = _case(tmp_path, split="dev")
    ledger = _ledger(tmp_path)
    assert RECORD.main([str(case), "t", "--ledger", str(ledger)]) == 1


# --------------------------------------------------------------------------
# ground truth may only come from rows the activity can be shown to own
# --------------------------------------------------------------------------

def _observed_case(root: Path, *, query: str, attack_rows: list[dict],
                   control_rows: list[dict]) -> Path:
    """A one-lead case with one query, one live control, and stored payloads."""
    case = root / "case-y"
    (case / "oracle_visible").mkdir(parents=True)
    (case / "hidden" / "observed" / "l-1").mkdir(parents=True)
    (case / "hidden" / "controls" / "l-1").mkdir(parents=True)
    (case / "manifest.yaml").write_text(
        yaml.safe_dump({"case_id": "case-y", "kind": "observed"}), encoding="utf-8")
    (case / "oracle_visible" / "leads.jsonl").write_text(
        json.dumps({"lead_id": "l-1", "queries": [
            {"query_id": "elastic.probe", "params": {"query": query}}]}) + "\n",
        encoding="utf-8")

    def _payload(rows: list[dict]) -> dict:
        return {"query": query, "columns": [], "row_count": len(rows), "values": rows}

    (case / "hidden" / "observed" / "l-1" / "0.json").write_text(
        json.dumps(_payload(attack_rows)), encoding="utf-8")
    (case / "hidden" / "controls" / "l-1" / "0.json").write_text(
        json.dumps({"lead_id": "l-1", "seq": 0, "controls": [
            {"name": "C-7d", "window": ["a", "b"], "query": query, "live": True,
             "payload": _payload(control_rows)}]}), encoding="utf-8")
    return case


def test_an_unkeyable_query_with_a_live_baseline_yields_no_ground_truth(tmp_path):
    """A doc-returning query with no `KEEP` has no defensible row key, so the
    baseline-row exclusion cannot run — `key` is None and every baseline row would
    pass into `observed_fields`. That is the contamination the exclusion exists to
    stop, arriving through the door beside it. case-005's `l-011` was this shape,
    and its baseline-sourced `zeek.ssh.auth.success` had to be removed by hand."""
    case = _observed_case(
        tmp_path,
        query='FROM logs-* | WHERE @timestamp >= "x" AND @timestamp < "y"',
        attack_rows=[{"zeek.ssh.auth.success": True, "host.name": "jump-box-1"}],
        control_rows=[{"zeek.ssh.auth.success": True, "host.name": "jump-box-1"}])
    built = WRITE.build_expected(case)["leads"]["l-1"]
    assert "observed_fields" not in built
    assert "fields" not in built


def test_a_column_with_several_values_is_dropped_not_pinned_arbitrarily(tmp_path):
    """ES|QL without `SORT` guarantees no row order, so first-wins ground truth is
    decided by whichever row the cluster returned first. Neither pin one nor
    accept any — the column is not single-valued ground truth, and is reported."""
    case = _observed_case(
        tmp_path,
        query='FROM logs-* | WHERE @timestamp >= "x" AND @timestamp < "y" '
              '| STATS n = COUNT(*) BY user.name',
        attack_rows=[{"user.name": "root", "n": 2}, {"user.name": "admin", "n": 3}],
        control_rows=[])
    built = WRITE.build_expected(case)
    assert "user.name" not in (built["leads"]["l-1"].get("fields") or {})
    assert "user.name" in built["_not_single_valued"]["l-1"]


def test_a_single_valued_column_is_still_pinned(tmp_path):
    """The drop rule must not empty out the ordinary case it shares code with."""
    case = _observed_case(
        tmp_path,
        query='FROM logs-* | WHERE @timestamp >= "x" AND @timestamp < "y" '
              '| STATS n = COUNT(*) BY user.name',
        attack_rows=[{"user.name": "root", "n": 2}],
        control_rows=[])
    built = WRITE.build_expected(case)
    assert built["leads"]["l-1"]["fields"]["user.name"] == "root"
    assert built["_not_single_valued"] == {}


def test_a_retirement_reason_naming_entries_does_not_eat_the_header(tmp_path):
    """The header is split off by the `entries:` KEY, anchored to a line start.
    A bare `split("entries:")` also matches the word inside a `retired:` reason —
    and retirement reasons are free prose written about this very file."""
    case = _case(tmp_path)
    ledger = tmp_path / "ledger.yaml"
    ledger.write_text(
        "# Why this ledger exists.\n"
        "entries:\n"
        "- case: case-w\n"
        "  tag: t0\n"
        "  sha256: deadbeef\n"
        "  recorded: '2026-07-01'\n"
        "  retired: 'superseded; see the entries: list above'\n",
        encoding="utf-8")
    assert RECORD.main([str(case), "t", "--ledger", str(ledger)]) == 0
    text = ledger.read_text(encoding="utf-8")
    assert text.startswith("# Why this ledger exists.\n")
    doc = yaml.safe_load(text)
    assert [e["case"] for e in doc["entries"]] == ["case-w", "case-x"]
    assert "entries:" in doc["entries"][0]["retired"]
