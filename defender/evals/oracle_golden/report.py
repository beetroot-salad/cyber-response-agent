#!/usr/bin/env python3
"""Roll the per-case scores up into a report that states what it cannot certify (#711).

`score.py` is per-case and pure, and stays that way — its purity is what lets the
suite pin every committed artifact against scorer drift. But nothing aggregated
it: every headline in #711's issue body was computed by hand, and each one was
weaker than it looked.

Three things this reports that a hand-rolled percentage did not:

**`n_units`, not `n_leads`.** 27 of the suite's 36 leads are case-001's nine
envelopes shown three times (case-001, mut-001, neg-001). Reading that as n=36 is
the mistake the whole issue is about. The independent unit is
(activity family x host pair); seeds and re-runs POOL within a unit, because ten
seeds of one scenario against one host pair are ten runs of one story shape, not
ten trials. Automation raises the capture count cheaply and does **not** raise the
unit count — which is why the unit had to be fixed before recruitment started.

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

Dev and held-out are reported **separately and never pooled**: pooling them would
launder the pool the prompt was fitted to into the certification number.

Usage: report.py [<cases_dir>] [--json <out.json>] [--target-lower-bound 0.90]
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from collections import defaultdict
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


STATS = _load("oracle_golden_stats", GOLDEN_DIR / "stats.py")

#: Fewest independent units a slice needs before an interval is published at all.
#: At n=1 Wilson spans [0.21, 1.00] and at n=2 [0.34, 1.00]; printing either
#: alongside a point estimate invites the point estimate to be read.
MIN_UNITS = 3

#: A cause is treated as real only at this many instances across this many
#: distinct UNITS (#711 M6). Units, not cases: mut-001 and neg-001 are not
#: independent evidence of anything case-001 already shows.
CAUSE_MIN_INSTANCES = 5
CAUSE_MIN_UNITS = 3


def load_cases(cases_dir: Path) -> list[dict]:
    """Every case with its manifest, expected labels, and recorded scores."""
    out = []
    for case_dir in sorted(d for d in cases_dir.iterdir() if d.is_dir()):
        manifest_path = case_dir / "manifest.yaml"
        if not manifest_path.is_file():
            continue
        manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8")) or {}
        scores = {}
        for score_path in sorted((case_dir / "scores").glob("*.json")):
            scores[score_path.stem] = json.loads(score_path.read_text(encoding="utf-8"))
        causes = {}
        for cause_path in sorted((case_dir / "scores").glob("*.causes.yaml")):
            tag = cause_path.name[: -len(".causes.yaml")]
            causes[tag] = yaml.safe_load(cause_path.read_text(encoding="utf-8")) or {}
        out.append({"dir": case_dir, "id": case_dir.name, "manifest": manifest,
                    "scores": scores, "causes": causes})
    return out


def unit_of(manifest: dict) -> str:
    unit = manifest.get("unit") or {}
    return f"{unit.get('activity_family', '?')} x {unit.get('host_pair', '?')}"


def summarize(rows: list[dict], units: set[str], environments: set[str]) -> dict:
    """One slice: counts, observed rate, and the interval at the unit count."""
    n_leads = len(rows)
    n_units = len(units)
    matched = sum(1 for r in rows if r["class_match"])
    rate = matched / n_leads if n_leads else None
    out = {
        "n_leads": n_leads,
        "n_units": n_units,
        "n_environments": len(environments),
        "agreement": f"{matched}/{n_leads}",
        "rate": round(rate, 3) if rate is not None else None,
        "interval": None,
        "verdict": "insufficient",
        "units": sorted(units),
    }
    if n_units < MIN_UNITS or rate is None:
        out["why"] = (f"{n_units} independent unit(s) — below the floor of {MIN_UNITS}; "
                      f"an interval here would be uninformative")
        return out
    interval = STATS.wilson_interval(round(rate * n_units), n_units)
    out["interval"] = [round(interval[0], 3), round(interval[1], 3)]
    return out


def certify(slice_summary: dict, target_lower_bound: float) -> dict:
    """Does this slice clear the stated bound, and if not, what would it take?"""
    interval = slice_summary.get("interval")
    if interval is None:
        slice_summary["verdict"] = "insufficient"
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

        overall_rows: list[dict] = []
        overall_units: set[str] = set()
        overall_envs: set[str] = set()
        by_slice: dict[tuple, dict] = defaultdict(
            lambda: {"rows": [], "units": set(), "envs": set()})
        cause_tally: dict[str, dict] = defaultdict(lambda: {"instances": 0, "units": set()})

        for case in members:
            unit = unit_of(case["manifest"])
            env = case["manifest"].get("capture_environment", "?")
            overall_units.add(unit)
            overall_envs.add(env)
            for row in case["scores"][tag]["rows"]:
                overall_rows.append(row)
                key = (row["system"], row["expected"])
                bucket = by_slice[key]
                bucket["rows"].append(row)
                bucket["units"].add(unit)
                bucket["envs"].add(env)
            for entry in (case["causes"].get(tag, {}).get("causes") or {}).values():
                code = (entry or {}).get("cause")
                if code:
                    cause_tally[code]["instances"] += 1
                    cause_tally[code]["units"].add(unit)

        slices = {}
        for (system, expected), bucket in sorted(by_slice.items()):
            summary = summarize(bucket["rows"], bucket["units"], bucket["envs"])
            slices[f"{system} x {expected}"] = certify(summary, target_lower_bound)

        report["splits"][split] = {
            "cases": [c["id"] for c in members],
            "overall": certify(summarize(overall_rows, overall_units, overall_envs),
                               target_lower_bound),
            "slices": slices,
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


def print_report(report: dict) -> None:
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
        overall = data["overall"]
        print(f"   overall: {overall['agreement']} leads over {overall['n_units']} "
              f"unit(s), {overall['n_environments']} environment(s) -> "
              f"{_fmt_verdict(overall)}")
        for name, summary in data["slices"].items():
            print(f"     {name:34} {summary['agreement']:>7} leads / "
                  f"{summary['n_units']} unit(s)  {_fmt_verdict(summary)}")
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


def _fmt_verdict(summary: dict) -> str:
    if summary["interval"] is None:
        return f"INSUFFICIENT ({summary.get('why', '')})"
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

    cases = load_cases(ns.cases_dir)
    tags = [ns.tag] if ns.tag else sorted({t for c in cases for t in c["scores"]})
    if not tags:
        print("no scored projections found", file=sys.stderr)
        return 1

    reports = []
    for tag in tags:
        report = build_report(cases, tag, ns.target_lower_bound)
        reports.append(report)
        print_report(report)

    if ns.json_out:
        ns.json_out.parent.mkdir(parents=True, exist_ok=True)
        ns.json_out.write_text(json.dumps(reports, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {ns.json_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
