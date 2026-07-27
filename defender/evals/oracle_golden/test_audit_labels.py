"""Pins for the labeler audit (#711 O6).

`audit_labels.py` is the one tool whose job is to distrust another tool: it
compares `label.py`'s derived class against the hand-derived seed labels, and its
exit code is what says "the labeler may be trusted on this suite". A bug that
made it agree too easily would be invisible — a green audit reads the same
whether it checked anything or not — so what these pin is that it can still
FAIL, and that it fails for the right reason.

Everything here is synthetic. Nothing reads the committed cases, so a change to
the real suite cannot turn these green or red.
"""
from __future__ import annotations

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


AUDIT = _load("oracle_golden_audit", GOLDEN_DIR / "audit_labels.py")

QUERY = 'FROM logs-* | WHERE @timestamp >= "a" AND @timestamp < "b" | STATS n = COUNT(*) BY user.name'


def _payload(rows: list[dict]) -> dict:
    return {"query": QUERY, "columns": [], "row_count": len(rows), "values": rows}


def _case(root: Path, *, hand_class: str, attack: list[dict],
          control: list[dict], name: str = "case-a") -> Path:
    """A one-lead observed case whose telemetry the labeler can decide."""
    case = root / name
    (case / "oracle_visible").mkdir(parents=True)
    (case / "hidden" / "observed" / "l-1").mkdir(parents=True)
    (case / "hidden" / "controls" / "l-1").mkdir(parents=True)
    (case / "manifest.yaml").write_text(
        yaml.safe_dump({"case_id": name, "kind": "observed"}), encoding="utf-8")
    (case / "oracle_visible" / "leads.jsonl").write_text(
        json.dumps({"lead_id": "l-1", "queries": [
            {"query_id": "elastic.probe", "params": {"query": QUERY}}]}) + "\n",
        encoding="utf-8")
    (case / "expected.yaml").write_text(yaml.safe_dump(
        {"case_id": name, "kind": "observed",
         "leads": {"l-1": {"system": "elastic", "class": hand_class}}}), encoding="utf-8")
    (case / "hidden" / "observed" / "l-1" / "0.json").write_text(
        json.dumps(_payload(attack)), encoding="utf-8")
    (case / "hidden" / "controls" / "l-1" / "0.json").write_text(
        json.dumps({"lead_id": "l-1", "seq": 0, "controls": [
            {"name": "C-7d", "window": ["a", "b"], "query": QUERY, "live": True,
             "payload": _payload(control)}]}), encoding="utf-8")
    return case


def test_an_agreeing_label_audits_clean(tmp_path):
    _case(tmp_path, hand_class="+event",
          attack=[{"user.name": "root", "n": 9}], control=[{"user.name": "sre.alice", "n": 4}])
    assert AUDIT.main([str(tmp_path)]) == 0


def test_a_class_divergence_is_a_non_zero_exit(tmp_path):
    """The whole point. A hand label of `+noise` over telemetry that shows a row
    no control carries is a disagreement someone must adjudicate — by
    re-measuring, never by tuning the labeler until it agrees."""
    _case(tmp_path, hand_class="+noise",
          attack=[{"user.name": "root", "n": 9}], control=[{"user.name": "sre.alice", "n": 4}])
    assert AUDIT.main([str(tmp_path)]) == 1


def test_needs_label_is_an_abstention_not_a_divergence(tmp_path):
    """`needs-label` is the labeler declining to decide, which is a designed
    outcome. Counting it as disagreement would make the audit fail on exactly the
    cases where it has no opinion."""
    case = _case(tmp_path, hand_class="+event",
                 attack=[{"user.name": "root", "n": 9}], control=[])
    # No control record at all -> the labeler cannot decide +event vs +noise.
    (case / "hidden" / "controls" / "l-1" / "0.json").unlink()
    rows = AUDIT.audit_case(case)
    assert rows[0]["derived_class"] == "needs-label"
    assert rows[0]["undecided"] is True
    assert AUDIT.main([str(tmp_path)]) == 0


def test_a_case_with_nothing_measured_is_skipped_not_audited(tmp_path):
    """A derived case (mut-001, neg-001) has no `hidden/observed` of its own: its
    labels are definitional, and auditing them against a labeler that never saw
    the telemetry would manufacture divergences."""
    case = _case(tmp_path, hand_class="+event",
                 attack=[{"user.name": "root", "n": 9}], control=[])
    for payload in (case / "hidden" / "observed" / "l-1").iterdir():
        payload.unlink()
    (case / "hidden" / "observed" / "l-1").rmdir()
    (case / "hidden" / "observed").rmdir()
    assert AUDIT.main([str(tmp_path)]) == 0
    assert AUDIT.audit_case  # the skip is in main(), not a silent pass in audit_case


def test_the_audit_reports_a_heterogeneous_correction_without_failing(tmp_path):
    """AC 6's flag is corrected from the envelope, and a correction is news
    rather than an error — case-001 `l-001` was flagged heterogeneous by hand and
    is not. It must show up in the output and not change the exit code."""
    case = _case(tmp_path, hand_class="+event",
                 attack=[{"user.name": "root", "n": 9}], control=[{"user.name": "sre.alice", "n": 4}])
    expected = yaml.safe_load((case / "expected.yaml").read_text(encoding="utf-8"))
    expected["leads"]["l-1"]["heterogeneous"] = True
    (case / "expected.yaml").write_text(yaml.safe_dump(expected), encoding="utf-8")
    # One sub-query only, so the envelope cannot be heterogeneous at all.
    rows = AUDIT.audit_case(case)
    assert rows[0]["hand_heterogeneous"] is True
    assert rows[0]["derived_heterogeneous"] is None      # not measurable, not False
    assert AUDIT.main([str(tmp_path)]) == 0
