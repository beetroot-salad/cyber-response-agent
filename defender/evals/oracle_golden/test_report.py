"""Pins for the roll-up reporter (#711 M3/AC 4/AC 5).

The reporter's job is to stop the suite overstating itself. Each test below pins
one way the old hand-rolled percentage did overstate: counting shared envelopes
as independent trials, publishing a point estimate off one unit, and pooling the
pool the prompt was fitted to with the pool that is supposed to certify it.
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


REPORT = _load("oracle_golden_report", GOLDEN_DIR / "report.py")

TAG = "t"


def _write_case(  # noqa: PLR0913 — each argument is one axis the reporter slices
                  # on; bundling them into a dict would hide which axis a test varies
        root: Path, case_id: str, *, split: str, family: str,
        host_pair: str, env: str, rows: list[dict],
        base_case: str | None = None, causes: dict | None = None) -> None:
    case = root / case_id
    (case / "scores").mkdir(parents=True, exist_ok=True)
    manifest = {"case_id": case_id, "split": split, "capture_environment": env,
                "unit": {"activity_family": family, "host_pair": host_pair}}
    if base_case:
        manifest["base_case"] = base_case
    (case / "manifest.yaml").write_text(yaml.safe_dump(manifest), encoding="utf-8")
    (case / "scores" / f"{TAG}.json").write_text(
        json.dumps({"rows": rows}, indent=2), encoding="utf-8")
    if causes is not None:
        (case / "scores" / f"{TAG}.causes.yaml").write_text(
            yaml.safe_dump({"causes": causes}), encoding="utf-8")


def _row(lead: str, system: str, expected: str, *, match: bool) -> dict:
    return {"lead": lead, "system": system, "expected": expected,
            "predicted": expected if match else "0", "class_match": match,
            "heterogeneous": False, "fields": {}, "contradictions": {},
            "intent_note": False}


def test_cases_sharing_one_envelope_count_as_one_unit(tmp_path):
    """The mistake the whole issue is about: 27 of the suite's 36 leads are one
    capture shown three times, and reading that as n=36 is what made 33/36 look
    like a result."""
    for case_id in ("case-a", "mut-a", "neg-a"):
        _write_case(tmp_path, case_id, split="dev", family="brute-force",
                    host_pair="ws->canary", env="snap-1",
                    rows=[_row("l-1", "elastic", "+event", match=True)],
                    base_case=None if case_id == "case-a" else "case-a")
    report = REPORT.build_report(REPORT.load_golden_cases(tmp_path), TAG, 0.90)
    overall = report["splits"]["dev"]["overall"]
    assert overall["n_leads"] == 3
    assert overall["n_units"] == 1


def test_two_cases_from_one_snapshot_are_one_environment(tmp_path):
    """AC 5. case-002 and case-003 really do share snapshot 412421678."""
    _write_case(tmp_path, "case-a", split="dev", family="f1", host_pair="a->b",
                env="snap-1", rows=[_row("l-1", "elastic", "+event", match=True)])
    _write_case(tmp_path, "case-b", split="dev", family="f2", host_pair="c->d",
                env="snap-1", rows=[_row("l-1", "elastic", "+event", match=True)])
    report = REPORT.build_report(REPORT.load_golden_cases(tmp_path), TAG, 0.90)
    assert report["splits"]["dev"]["overall"]["n_environments"] == 1
    assert report["splits"]["dev"]["overall"]["n_units"] == 2


def test_a_slice_below_the_unit_floor_reports_insufficient_not_a_number(tmp_path):
    """A Wilson interval on one unit spans [0.21, 1.00]; printing it beside a point
    estimate invites the point estimate to be read."""
    _write_case(tmp_path, "case-a", split="dev", family="f1", host_pair="a->b",
                env="e1", rows=[_row("l-1", "elastic", "+event", match=True)])
    report = REPORT.build_report(REPORT.load_golden_cases(tmp_path), TAG, 0.90)
    overall = report["splits"]["dev"]["overall"]
    assert overall["verdict"] == "insufficient"
    assert overall["interval"] is None


def test_dev_and_held_out_are_never_pooled(tmp_path):
    """Pooling would launder the pool the prompt was fitted to into the
    certification number."""
    for i in range(3):
        _write_case(tmp_path, f"dev-{i}", split="dev", family=f"f{i}",
                    host_pair=f"a->{i}", env=f"e{i}",
                    rows=[_row("l-1", "elastic", "+event", match=True)])
    for i in range(3):
        _write_case(tmp_path, f"ho-{i}", split="held-out", family=f"g{i}",
                    host_pair=f"b->{i}", env=f"f{i}",
                    rows=[_row("l-1", "elastic", "+event", match=False)])
    report = REPORT.build_report(REPORT.load_golden_cases(tmp_path), TAG, 0.90)
    assert report["splits"]["dev"]["overall"]["rate"] == 1.0
    assert report["splits"]["held-out"]["overall"]["rate"] == 0.0
    assert set(report["splits"]) == {"dev", "held-out"}


def test_a_perfect_rate_on_too_few_units_still_fails_to_certify(tmp_path):
    """35 units are needed at a perfect rate. Three perfect units is not a
    certification, and the report says what it would take."""
    for i in range(3):
        _write_case(tmp_path, f"case-{i}", split="dev", family=f"f{i}",
                    host_pair=f"a->{i}", env=f"e{i}",
                    rows=[_row("l-1", "elastic", "+event", match=True)])
    report = REPORT.build_report(REPORT.load_golden_cases(tmp_path), TAG, 0.90)
    overall = report["splits"]["dev"]["overall"]
    assert overall["rate"] == 1.0
    assert overall["verdict"] == "no-update"
    assert overall["units_needed"] == 35


def test_a_cause_needs_instances_across_distinct_units(tmp_path):
    """M6: five instances inside one unit is one observation repeated, not
    evidence. mut-001 and neg-001 are not independent of case-001."""
    for i in range(5):
        _write_case(tmp_path, f"same-{i}", split="dev", family="f", host_pair="a->b",
                    env="e", rows=[_row("l-1", "elastic", "+event", match=False)],
                    causes={"l-1": {"cause": "C-INTENT-SCOPE"}})
    report = REPORT.build_report(REPORT.load_golden_cases(tmp_path), TAG, 0.90)
    tally = report["splits"]["dev"]["causes"]["C-INTENT-SCOPE"]
    assert tally["instances"] == 5
    assert tally["units"] == 1
    assert tally["status"] == "insufficient"


def test_a_cause_across_enough_units_is_established(tmp_path):
    for i in range(5):
        _write_case(tmp_path, f"case-{i}", split="dev", family=f"f{i}",
                    host_pair=f"a->{i}", env=f"e{i}",
                    rows=[_row("l-1", "elastic", "+event", match=False)],
                    causes={"l-1": {"cause": "C-INTENT-SCOPE"}})
    report = REPORT.build_report(REPORT.load_golden_cases(tmp_path), TAG, 0.90)
    tally = report["splits"]["dev"]["causes"]["C-INTENT-SCOPE"]
    assert (tally["instances"], tally["units"]) == (5, 5)
    assert tally["status"] == "established"


def test_an_unreachable_bound_says_so_rather_than_naming_an_n(tmp_path):
    """The Wilson lower bound converges to the observed rate, so 0.90 at an
    observed 0.50 cannot be reached by recruiting."""
    for i in range(4):
        _write_case(tmp_path, f"case-{i}", split="dev", family=f"f{i}",
                    host_pair=f"a->{i}", env=f"e{i}",
                    rows=[_row("l-1", "elastic", "+event", match=(i % 2 == 0))])
    report = REPORT.build_report(REPORT.load_golden_cases(tmp_path), TAG, 0.90)
    overall = report["splits"]["dev"]["overall"]
    assert overall["verdict"] == "no-update"
    assert overall["units_needed"] is None
    assert "cannot qualify" in overall["why"]
