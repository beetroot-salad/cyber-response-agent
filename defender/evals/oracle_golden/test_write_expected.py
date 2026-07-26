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

def _ledger(tmp_path: Path, monkeypatch) -> Path:
    path = tmp_path / "ledger.yaml"
    path.write_text("# why this ledger exists\nentries: []\n", encoding="utf-8")
    monkeypatch.setattr(RECORD, "LEDGER", path)
    return path


def test_a_held_out_result_is_recorded_with_its_hash(tmp_path, monkeypatch):
    case = _case(tmp_path)
    ledger = _ledger(tmp_path, monkeypatch)
    assert RECORD.main([str(case), "t"]) == 0
    entries = yaml.safe_load(ledger.read_text(encoding="utf-8"))["entries"]
    assert entries[0]["case"] == "case-x"
    assert entries[0]["sha256"] == hashlib.sha256(
        (case / "scores" / "t.json").read_bytes()).hexdigest()
    assert "why this ledger exists" in ledger.read_text(encoding="utf-8")


def test_the_same_tag_cannot_be_recorded_twice(tmp_path, monkeypatch):
    """There is deliberately no flag to replace an entry: re-running a held-out
    case under one tag until the number improves is how a held-out set stops
    being held out."""
    case = _case(tmp_path)
    _ledger(tmp_path, monkeypatch)
    assert RECORD.main([str(case), "t"]) == 0
    assert RECORD.main([str(case), "t"]) == 1


def test_a_dev_case_is_not_ledgered(tmp_path, monkeypatch):
    case = _case(tmp_path, split="dev")
    _ledger(tmp_path, monkeypatch)
    assert RECORD.main([str(case), "t"]) == 1
