#!/usr/bin/env python3
"""Roll the per-case scores up into a report that states what it cannot certify.

`score.py` is per-case; this aggregates, and every rate it prints is qualified by what
the sample can actually support.

**The headline is the ACTIVE band.** `delta_kind` groups into two:

  - **active** — `present`, `suppressed`, `indistinguishable`: the activity touched this
    envelope, and the oracle had to represent something;
  - **quiet** — `absent`, `state-only`: the oracle correctly said nothing.

Reporting one pooled number lets the quiet band carry the score — most leads are quiet,
so a 0.92 headline is mostly correctly-said-nothing. Both bands are printed; the active
one leads, because it is the one that measures whether the oracle can synthesize
telemetry.

A third band, **unmeasured**, holds the leads the label pass could not settle. They are
excluded from every rate and counted beside it — a judge abstention is a statement about
the instrument and must not be charged to the oracle.

Four more things this reports that a hand-rolled percentage did not:

**`n_units`, not `n_leads`.** A derived case reshows its base's envelopes, so a lead
count double-counts. The independent unit is (activity family x host pair); seeds and
re-runs POOL within a unit, because ten seeds of one scenario against one host pair are
ten runs of one story shape, not ten trials. Automation raises the capture count cheaply
and does **not** raise the unit count.

**An interval, computed at `n = n_units`.** The observed rate is the lead-level
one, but the interval is taken at the unit count with `k = round(rate x n_units)`
— a deliberately conservative full-within-unit-correlation design effect, held
until there is enough data to estimate the real intra-unit correlation. Below a
floor of `MIN_UNITS` a slice reports `insufficient` rather than a number, because
a Wilson interval on one unit spans [0.21, 1.00] and publishing that invites
someone to read the point estimate.

**`n_environments`.** Two cases captured from one restored snapshot are one
environment however different their stories, so a shared-snapshot pair cannot
inflate a slice's apparent independence.

**The mechanical results, separately.** Derived cases (mutation, negative-control) have
no capture of their own, so they contribute no judged rows at all — their result is the
grammar check, the leak check, and the manifest's `expectation:` clauses, reported as
counts and named failures rather than folded into a measured rate.

Dev and held-out are reported **separately and never pooled**: pooling them would
launder the pool the prompt was fitted to into the certification number.

Usage: report.py [<cases_dir>] [--json <out.json>] [--target-lower-bound 0.90]
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

import yaml

GOLDEN_DIR = Path(__file__).resolve().parent

# Run as a script from anywhere, so the package this module lives in has to be made
# importable before its own sibling can be — `score.py` establishes the convention.
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from defender.evals.oracle_golden import stats as STATS  # noqa: E402 — after the bootstrap

#: Fewest independent units a slice needs before an interval is published at all.
#: At n=1 Wilson spans [0.21, 1.00] and at n=2 [0.34, 1.00]; printing either
#: alongside a point estimate invites the point estimate to be read.
MIN_UNITS = 3

#: A cause is treated as real only at this many instances across this many distinct UNITS.
#: Units, not cases: a derived case is not independent evidence of anything its base shows.
CAUSE_MIN_INSTANCES = 5
CAUSE_MIN_UNITS = 3

#: The two reported bands, plus the third that is not a band but an admission. Keyed by
#: `delta_kind`; anything unknown lands in `unmeasured` rather than silently in a rate.
BANDS = {
    "present": "active", "suppressed": "active", "indistinguishable": "active",
    "absent": "quiet", "state-only": "quiet",
    "undecidable": "unmeasured",
}
BAND_ORDER = ("active", "quiet", "unmeasured")


def band_of(delta_kind: str) -> str:
    return BANDS.get(delta_kind, "unmeasured")


def load_golden_cases(cases_dir: Path) -> list[dict]:
    """Every case with its manifest and recorded scores."""
    out = []
    for case_dir in sorted(d for d in cases_dir.iterdir() if d.is_dir()):
        manifest_path = case_dir / "manifest.yaml"
        if not manifest_path.is_file():
            continue
        manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8")) or {}
        scores = {}
        for score_path in sorted((case_dir / "scores").glob("*.json")):
            scores[score_path.stem] = json.loads(score_path.read_text(encoding="utf-8"))
        out.append({"dir": case_dir, "id": case_dir.name, "manifest": manifest,
                    "scores": scores})
    return out


def unit_of(manifest: dict) -> str:
    unit = manifest.get("unit") or {}
    return f"{unit.get('activity_family', '?')} x {unit.get('host_pair', '?')}"


def summarize(rows: list[dict], units: set[str], environments: set[str]) -> dict:
    """One slice: counts, observed rate, and the interval at the unit count.

    The denominator is the DECIDED leads. `faithful is None` is the judge saying the
    telemetry it was given does not settle the lead — charging that to the oracle would
    turn a limit of the instrument into a defect of the thing measured. Abstentions are
    counted beside the rate instead, and a slice that abstains at least as often as it
    decides is reported as not a measurement at all.
    """
    n_leads = len(rows)
    n_units = len(units)
    decided = [r for r in rows if r["faithful"] is not None]
    abstentions = n_leads - len(decided)
    matched = sum(1 for r in decided if r["faithful"] is True)
    rate = matched / len(decided) if decided else None
    out = {
        "n_leads": n_leads,
        "n_decided": len(decided),
        "abstentions": abstentions,
        "n_units": n_units,
        "n_environments": len(environments),
        "agreement": f"{matched}/{len(decided)}",
        "rate": round(rate, 3) if rate is not None else None,
        "interval": None,
        "verdict": "insufficient",
        "units": sorted(units),
    }
    if n_leads and abstentions >= len(decided):
        out["not_a_measurement"] = True
        out["why"] = (f"{abstentions} of {n_leads} lead(s) abstained — the judge could not "
                      f"settle at least as many as it decided; this is a statement about "
                      f"the capture, not a rate")
        return out
    if n_units < MIN_UNITS or rate is None:
        out["why"] = (f"{n_units} independent unit(s) — below the floor of {MIN_UNITS}; "
                      f"an interval here would be uninformative")
        return out
    interval = STATS.wilson_interval(round(rate * n_units), n_units)
    # `wilson_interval` answers `None` only for `n == 0`, and the floor check above already
    # returned for anything under MIN_UNITS. Asserted rather than assumed: lowering
    # MIN_UNITS to 0 would otherwise turn a never-measured slice into a `TypeError` here.
    assert interval is not None, f"n_units={n_units} cleared the floor but has no interval"
    out["interval"] = [round(interval[0], 3), round(interval[1], 3)]
    return out


def certify(slice_summary: dict, target_lower_bound: float) -> dict:
    """Does this slice clear the stated bound, and if not, what would it take?"""
    interval = slice_summary.get("interval")
    if interval is None:
        slice_summary["verdict"] = ("not-a-measurement"
                                    if slice_summary.get("not_a_measurement")
                                    else "insufficient")
        return slice_summary
    if interval[0] >= target_lower_bound:
        slice_summary["verdict"] = "trusted"
        return slice_summary
    slice_summary["verdict"] = "no-update"
    needed = STATS.required_n(target_lower_bound, slice_summary["rate"] or 0.0)
    slice_summary["units_needed"] = needed
    slice_summary["why"] = (
        f"lower bound {interval[0]:.2f} < {target_lower_bound:.2f}; "
        + (f"would need ~{needed} units at the observed rate {slice_summary['rate']}"
           if needed else
           f"unreachable at the observed rate {slice_summary['rate']} — the bound "
           f"converges to the rate, so this slice cannot qualify without improving"))
    return slice_summary


def build_report(cases: list[dict], tag: str, target_lower_bound: float) -> dict:
    """The whole report for one projection tag, split by dev / held-out."""
    report: dict = {"tag": tag, "target_lower_bound": target_lower_bound, "splits": {}}

    for split in ("dev", "held-out"):
        members = [c for c in cases
                   if (c["manifest"].get("split") == split) and tag in c["scores"]]
        if not members:
            continue

        overall: dict = {"rows": [], "units": set(), "envs": set()}
        by_band: dict[str, dict] = defaultdict(
            lambda: {"rows": [], "units": set(), "envs": set()})
        by_slice: dict[tuple, dict] = defaultdict(
            lambda: {"rows": [], "units": set(), "envs": set()})
        cause_tally: dict[str, dict] = defaultdict(lambda: {"instances": 0, "units": set()})
        mechanical: dict = {"malformed_leads": 0, "leaked_values": [],
                            "expectation_failures": [], "unjudged_cases": []}

        for case in members:
            unit = unit_of(case["manifest"])
            env = case["manifest"].get("capture_environment", "?")
            score = case["scores"][tag]
            if "judged" not in score:
                # A pre-judge score doc. Skipping it silently would drop a whole case
                # from a rate without changing the case count printed beside it.
                raise ValueError(
                    f"{case['dir'].name}/scores/{tag}.json predates the judge redesign "
                    f"(#711 §5): it carries no `judged` flag and its rows have no "
                    f"`delta_kind`/`faithful`. Re-score it or remove it.")
            mech = score.get("mechanical") or {}
            mechanical["malformed_leads"] += len(mech.get("malformed_leads") or {})
            mechanical["leaked_values"] += [f"{case['id']}: {v}"
                                            for v in mech.get("forbidden_emitted") or []]
            # The manifest's `expectation:` clauses, which are the WHOLE result of a derived
            # case: it contributes no judged rows by construction, so dropping this would
            # print such a case's name and not its verdict. `leaked_values` above is one of
            # the five clauses (`must_not_emit`).
            mechanical["expectation_failures"] += [
                f"{case['id']}: {f}" for f in mech.get("expectation_failures") or []]
            if not score.get("judged"):
                # Carried by id, not silently dropped: a case that contributes no rows
                # must still be visible, or "6 cases" reads as six measurements.
                mechanical["unjudged_cases"].append(
                    {"case": case["id"], "why": score.get("why_unjudged", "")})
                continue
            overall["units"].add(unit)
            overall["envs"].add(env)
            for row in score["rows"]:
                overall["rows"].append(row)
                for bucket in (by_band[band_of(row["delta_kind"])],
                               by_slice[(row["system"], row["delta_kind"])]):
                    bucket["rows"].append(row)
                    bucket["units"].add(unit)
                    bucket["envs"].add(env)
                if row.get("cause"):
                    cause_tally[row["cause"]]["instances"] += 1
                    cause_tally[row["cause"]]["units"].add(unit)

        slices = {
            f"{system} x {delta_kind}": certify(
                summarize(b["rows"], b["units"], b["envs"]), target_lower_bound)
            for (system, delta_kind), b in sorted(by_slice.items())
        }
        bands = {
            name: certify(summarize(by_band[name]["rows"], by_band[name]["units"],
                                    by_band[name]["envs"]), target_lower_bound)
            for name in BAND_ORDER if name in by_band
        }

        report["splits"][split] = {
            "cases": [c["id"] for c in members],
            "bands": bands,
            "overall": certify(summarize(overall["rows"], overall["units"], overall["envs"]),
                               target_lower_bound),
            "slices": slices,
            "mechanical": mechanical,
            "causes": {
                code: {
                    "instances": data["instances"],
                    "units": len(data["units"]),
                    "status": ("established"
                               if (data["instances"] >= CAUSE_MIN_INSTANCES
                                   and len(data["units"]) >= CAUSE_MIN_UNITS)
                               else "insufficient"),
                }
                for code, data in sorted(cause_tally.items())
            },
        }
    return report


def print_rollup(report: dict) -> None:
    print(f"== oracle calibration — {report['tag']} "
          f"(target lower bound {report['target_lower_bound']:.2f}) ==")
    bound = report["target_lower_bound"]
    print(f"sizing: a >={bound:.2f} lower bound needs "
          f"~{STATS.required_n(bound)} units at a perfect rate, "
          f"~{STATS.required_n(bound, 0.97)} at 0.97\n")

    for split, data in report["splits"].items():
        banner = ("DEV — the pool prompt iteration may see. A result here is never "
                  "a certification."
                  if split == "dev" else
                  "HELD-OUT — scored once per tag, appended, never re-run for a "
                  "better number.")
        print(f"-- {split.upper()} ({len(data['cases'])} cases) --")
        print(f"   {banner}")
        for name in BAND_ORDER:
            summary = data["bands"].get(name)
            if summary is None:
                continue
            print(f"   {_BAND_GLOSS[name]:44} {summary['agreement']:>7} decided "
                  f"({summary['abstentions']} abstained) / {summary['n_units']} unit(s)  "
                  f"{_fmt_verdict(summary)}")
        overall = data["overall"]
        print(f"   {'pooled (do not headline this)':44} {overall['agreement']:>7} decided "
              f"({overall['abstentions']} abstained) / {overall['n_units']} unit(s), "
              f"{overall['n_environments']} environment(s)  {_fmt_verdict(overall)}")
        print("   -- by system x delta_kind --")
        for name, summary in data["slices"].items():
            print(f"     {name:38} {summary['agreement']:>7} decided "
                  f"({summary['abstentions']} abs) / {summary['n_units']} unit(s)  "
                  f"{_fmt_verdict(summary)}")
        _print_mechanical(data["mechanical"])
        if data["causes"]:
            print(f"   cause codes (>={CAUSE_MIN_INSTANCES} instances across "
                  f">={CAUSE_MIN_UNITS} units to count):")
            for code, tally in data["causes"].items():
                print(f"     {code:28} {tally['instances']} instance(s) across "
                      f"{tally['units']} unit(s) — {tally['status']}")
        print()

    if "held-out" not in report["splits"]:
        print("!! No held-out case carries this tag. Nothing here is a certification:\n"
              "   every number above comes from the pool the prompt was fitted to.")


_BAND_GLOSS = {
    "active":     "ACTIVE  (present/suppressed/indistinguishable)",
    "quiet":      "quiet   (absent/state-only)",
    "unmeasured": "unmeasured (the judge could not settle these)",
}


def _print_mechanical(mechanical: dict) -> None:
    """The checks that never reached a model. Printed even when clean — a leak check
    reported only on failure reads as "no mutation case was scored"."""
    print(f"   mechanical: {mechanical['malformed_leads']} malformed lead(s); "
          f"pre-mutation leaks: "
          f"{'CLEAN' if not mechanical['leaked_values'] else mechanical['leaked_values']}")
    failures = mechanical["expectation_failures"]
    print(f"   expectation clauses: {'CLEAN' if not failures else f'{len(failures)} FAILED'}")
    for failure in failures:
        print(f"     !! expectation — {failure}")
    for entry in mechanical["unjudged_cases"]:
        print(f"     !! {entry['case']} contributes NO judged rows — {entry['why']}")


def _fmt_verdict(summary: dict) -> str:
    if summary["interval"] is None:
        return (f"{summary['verdict'].upper().replace('-', ' ')} "
                f"({summary.get('why', '')})")
    lo, hi = summary["interval"]
    tail = f" — {summary['why']}" if summary["verdict"] != "trusted" else ""
    return f"{summary['rate']:.2f} [{lo:.2f}, {hi:.2f}] {summary['verdict'].upper()}{tail}"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("cases_dir", type=Path, nargs="?", default=GOLDEN_DIR / "cases")
    p.add_argument("--tag", default=None, help="projection tag (default: every tag found)")
    p.add_argument("--target-lower-bound", type=float, default=0.90)
    p.add_argument("--json", type=Path, default=None, dest="json_out")
    ns = p.parse_args(argv)

    cases = load_golden_cases(ns.cases_dir)
    tags = [ns.tag] if ns.tag else sorted({t for c in cases for t in c["scores"]})
    if not tags:
        print("no scored projections found", file=sys.stderr)
        return 1

    reports = []
    for tag in tags:
        report = build_report(cases, tag, ns.target_lower_bound)
        reports.append(report)
        print_rollup(report)

    if ns.json_out:
        ns.json_out.parent.mkdir(parents=True, exist_ok=True)
        ns.json_out.write_text(json.dumps(reports, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {ns.json_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
