"""Pins for the roll-up reporter (#711 M3/AC 4/AC 5).

The reporter's job is to stop the suite overstating itself. Each test below pins
one way the old hand-rolled percentage did overstate: counting shared envelopes
as independent trials, publishing a point estimate off one unit, pooling the
pool the prompt was fitted to with the pool that is supposed to certify it —
and, since the judge redesign, letting the quiet band carry the headline and
charging a judge abstention to the oracle.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest
import yaml

GOLDEN_DIR = Path(__file__).resolve().parents[2] / "evals" / "oracle_golden"


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
        base_case: str | None = None, judged: bool = True,
        mechanical: dict | None = None) -> None:
    case = root / case_id
    (case / "scores").mkdir(parents=True, exist_ok=True)
    manifest = {"case_id": case_id, "split": split, "capture_environment": env,
                "unit": {"activity_family": family, "host_pair": host_pair}}
    if base_case:
        manifest["base_case"] = base_case
    (case / "manifest.yaml").write_text(yaml.safe_dump(manifest), encoding="utf-8")
    (case / "scores" / f"{TAG}.json").write_text(json.dumps({
        "judged": judged, "rows": rows, "why_unjudged": "" if judged else "no capture",
        "mechanical": {"malformed_leads": {}, "forbidden_emitted": [],
                       **(mechanical or {})},
    }, indent=2), encoding="utf-8")


def _row(lead: str, system: str, delta_kind: str, *, faithful: bool | None,
         cause: str | None = None) -> dict:
    return {"lead": lead, "system": system, "delta_kind": delta_kind,
            "faithful": faithful, "cause": cause, "heterogeneous": False,
            "undecidable_reason": None if faithful is not None else "insufficient-baseline",
            "form_notes": None, "rationale": "x", "evidence": "y"}


def test_cases_sharing_one_envelope_count_as_one_unit(tmp_path):
    """The mistake the whole issue is about: 27 of the suite's 36 leads are one
    capture shown three times, and reading that as n=36 is what made 33/36 look
    like a result."""
    for case_id in ("case-a", "mut-a", "neg-a"):
        _write_case(tmp_path, case_id, split="dev", family="brute-force",
                    host_pair="ws->canary", env="snap-1",
                    rows=[_row("l-1", "elastic", "present", faithful=True)],
                    base_case=None if case_id == "case-a" else "case-a")
    report = REPORT.build_report(REPORT.load_golden_cases(tmp_path), TAG, 0.90)
    overall = report["splits"]["dev"]["overall"]
    assert overall["n_leads"] == 3
    assert overall["n_units"] == 1


def test_two_cases_from_one_snapshot_are_one_environment(tmp_path):
    """AC 5. case-002 and case-003 really do share snapshot 412421678."""
    _write_case(tmp_path, "case-a", split="dev", family="f1", host_pair="a->b",
                env="snap-1", rows=[_row("l-1", "elastic", "present", faithful=True)])
    _write_case(tmp_path, "case-b", split="dev", family="f2", host_pair="c->d",
                env="snap-1", rows=[_row("l-1", "elastic", "present", faithful=True)])
    report = REPORT.build_report(REPORT.load_golden_cases(tmp_path), TAG, 0.90)
    assert report["splits"]["dev"]["overall"]["n_environments"] == 1
    assert report["splits"]["dev"]["overall"]["n_units"] == 2


def test_a_slice_below_the_unit_floor_reports_insufficient_not_a_number(tmp_path):
    """A Wilson interval on one unit spans [0.21, 1.00]; printing it beside a point
    estimate invites the point estimate to be read."""
    _write_case(tmp_path, "case-a", split="dev", family="f1", host_pair="a->b",
                env="e1", rows=[_row("l-1", "elastic", "present", faithful=True)])
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
                    rows=[_row("l-1", "elastic", "present", faithful=True)])
    for i in range(3):
        _write_case(tmp_path, f"ho-{i}", split="held-out", family=f"g{i}",
                    host_pair=f"b->{i}", env=f"f{i}",
                    rows=[_row("l-1", "elastic", "present", faithful=False)])
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
                    rows=[_row("l-1", "elastic", "present", faithful=True)])
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
                    env="e", rows=[_row("l-1", "elastic", "present", faithful=False,
                                        cause="C-INTENT-SCOPE")])
    report = REPORT.build_report(REPORT.load_golden_cases(tmp_path), TAG, 0.90)
    tally = report["splits"]["dev"]["causes"]["C-INTENT-SCOPE"]
    assert tally["instances"] == 5
    assert tally["units"] == 1
    assert tally["status"] == "insufficient"


def test_a_cause_across_enough_units_is_established(tmp_path):
    for i in range(5):
        _write_case(tmp_path, f"case-{i}", split="dev", family=f"f{i}",
                    host_pair=f"a->{i}", env=f"e{i}",
                    rows=[_row("l-1", "elastic", "present", faithful=False,
                                cause="C-INTENT-SCOPE")])
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
                    rows=[_row("l-1", "elastic", "present", faithful=(i % 2 == 0))])
    report = REPORT.build_report(REPORT.load_golden_cases(tmp_path), TAG, 0.90)
    overall = report["splits"]["dev"]["overall"]
    assert overall["verdict"] == "no-update"
    assert overall["units_needed"] is None
    assert "cannot qualify" in overall["why"]


# ------------------------------------------------------- bands and abstentions (#711 §5)

def test_the_quiet_band_cannot_carry_the_headline(tmp_path):
    """The fix worth having. On the seed data 27 of 36 dev leads were `0`, so a pooled
    0.92 was three-quarters correctly-said-nothing. Active and quiet are reported
    separately so a perfect quiet band cannot hide a failing active one."""
    _write_case(tmp_path, "case-a", split="dev", family="f", host_pair="a->b", env="e",
                rows=[_row("l-1", "elastic", "present", faithful=False),
                      _row("l-2", "elastic", "absent", faithful=True),
                      _row("l-3", "cmdb", "state-only", faithful=True),
                      _row("l-4", "cmdb", "state-only", faithful=True)])
    bands = REPORT.build_report(REPORT.load_golden_cases(tmp_path), TAG, 0.90)["splits"]["dev"]["bands"]
    assert bands["active"]["agreement"] == "0/1"
    assert bands["quiet"]["agreement"] == "3/3"
    assert (bands["active"]["n_leads"], bands["quiet"]["n_leads"]) == (1, 3), (
        "the bands partition the leads — a row counted in both would let the quiet "
        "band's rate leak into the active one")


@pytest.mark.parametrize(("delta_kind", "band"), [
    ("present", "active"), ("suppressed", "active"), ("indistinguishable", "active"),
    ("absent", "quiet"), ("state-only", "quiet"),
    ("undecidable", "unmeasured"),
    ("something-new", "unmeasured"),   # an unknown kind must not land in a rate
])
def test_every_delta_kind_lands_in_the_band_the_design_names(delta_kind, band):
    assert REPORT.band_of(delta_kind) == band


def test_an_abstention_is_not_charged_to_the_oracle(tmp_path):
    """`faithful is None` is the judge saying its inputs do not settle the lead. Counting
    it in the denominator would turn a limit of the capture into a defect of the oracle."""
    _write_case(tmp_path, "case-a", split="dev", family="f", host_pair="a->b", env="e",
                rows=[_row("l-1", "elastic", "present", faithful=True),
                      _row("l-2", "elastic", "present", faithful=True),
                      _row("l-3", "elastic", "undecidable", faithful=None)])
    overall = REPORT.build_report(REPORT.load_golden_cases(tmp_path), TAG, 0.90)["splits"]["dev"]["overall"]
    assert overall["n_leads"] == 3
    assert overall["n_decided"] == 2
    assert overall["abstentions"] == 1
    assert overall["rate"] == 1.0, "2/2 of the decided, not 2/3 of everything"


def test_a_slice_that_abstains_more_than_it_decides_is_not_a_measurement(tmp_path):
    """A rate over one decided lead beside two abstentions is arithmetic, not evidence,
    and printing it invites it to be read as one."""
    _write_case(tmp_path, "case-a", split="dev", family="f", host_pair="a->b", env="e",
                rows=[_row("l-1", "elastic", "present", faithful=True),
                      _row("l-2", "elastic", "undecidable", faithful=None),
                      _row("l-3", "elastic", "undecidable", faithful=None)])
    overall = REPORT.build_report(REPORT.load_golden_cases(tmp_path), TAG, 0.90)["splits"]["dev"]["overall"]
    assert overall["verdict"] == "not-a-measurement"
    assert overall["interval"] is None
    assert overall["rate"] == 1.0, "still recorded — the point is that it is not certified"


# ------------------------------------------------------------- the mechanical results

def test_a_derived_case_contributes_no_rows_but_is_still_named(tmp_path):
    """A mutation case has no capture of its own, so there is no measurement to grade a
    projection against. Dropping it silently would leave `cases: [...]` claiming a case
    that contributed nothing."""
    _write_case(tmp_path, "case-a", split="dev", family="f", host_pair="a->b", env="e",
                rows=[_row("l-1", "elastic", "present", faithful=True)])
    _write_case(tmp_path, "mut-a", split="dev", family="f", host_pair="a->b", env="e",
                rows=[], judged=False, base_case="case-a")
    data = REPORT.build_report(REPORT.load_golden_cases(tmp_path), TAG, 0.90)["splits"]["dev"]
    assert data["overall"]["n_leads"] == 1
    assert [x["case"] for x in data["mechanical"]["unjudged_cases"]] == ["mut-a"]
    assert "mut-a" in data["cases"]


def test_the_mechanical_results_survive_into_the_rollup(tmp_path):
    """`score.py` decides malformed grammar and pre-mutation leaks in code and never
    calls the judge for them. If the roll-up did not carry them, a mutation case's whole
    result would vanish with its rows."""
    _write_case(tmp_path, "mut-a", split="dev", family="f", host_pair="a->b", env="e",
                rows=[], judged=False,
                mechanical={"malformed_leads": {"l-2": "prose, not a marker"},
                            "forbidden_emitted": ["172.18.0.15"]})
    data = REPORT.build_report(REPORT.load_golden_cases(tmp_path), TAG, 0.90)["splits"]["dev"]
    assert data["mechanical"]["malformed_leads"] == 1
    assert data["mechanical"]["leaked_values"] == ["mut-a: 172.18.0.15"]


def test_a_pre_judge_score_document_is_refused_rather_than_skipped(tmp_path):
    """The old scorer's artifacts have no `delta_kind` and no `faithful`. Skipping one
    would drop a case from every rate while leaving it in the case count printed beside
    them."""
    case = tmp_path / "case-a"
    (case / "scores").mkdir(parents=True)
    (case / "manifest.yaml").write_text(yaml.safe_dump(
        {"case_id": "case-a", "split": "dev", "capture_environment": "e",
         "unit": {"activity_family": "f", "host_pair": "a->b"}}), encoding="utf-8")
    (case / "scores" / f"{TAG}.json").write_text(
        json.dumps({"rows": [{"lead": "l-1", "system": "elastic", "expected": "0",
                              "class_match": True}]}), encoding="utf-8")
    with pytest.raises(ValueError, match="predates the judge redesign"):
        REPORT.build_report(REPORT.load_golden_cases(tmp_path), TAG, 0.90)


def test_the_rollup_prints_the_active_band_first(tmp_path, capsys):
    _write_case(tmp_path, "case-a", split="dev", family="f", host_pair="a->b", env="e",
                rows=[_row("l-1", "elastic", "present", faithful=False),
                      _row("l-2", "cmdb", "state-only", faithful=True)])
    REPORT.print_rollup(REPORT.build_report(REPORT.load_golden_cases(tmp_path), TAG, 0.90))
    out = capsys.readouterr().out
    assert out.index("ACTIVE") < out.index("quiet   (absent/state-only)")
    assert "pooled (do not headline this)" in out
    assert "pre-mutation leaks: CLEAN" in out, "a check reported only on failure reads as unrun"
