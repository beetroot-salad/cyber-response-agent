"""Calibrate the LABEL pass against the hand-derived labels, and measure its own noise.

Replaces `audit_labels.py`, which audited a labelling program that no longer exists.
The question is unchanged: when a measurement comes from something other than a human
reading the telemetry, that something is calibrated against hand-derived truth before
its output is trusted. A systematic bias biases every case the same way, and no amount
of `n` detects it — unlike human error, which is at least uncorrelated across cases.

Two numbers come out:

* **calibration** — does the label pass reproduce the hand labels, class for class?
  A divergence is adjudicated by RE-MEASUREMENT, never by tuning the prompt until it
  agrees. A judge fitted to the audit set calibrates nothing.
* **self-agreement** — with `--repeats N`, how often does the same lead get the same
  label? The judge runs at score time, so its variance is inside every interval the
  report prints. Unmeasured, every one of them is understated.

The VERDICT pass cannot be calibrated this way: nothing hand-labelled exists for it.
Watch its self-agreement and its `contradicts-measurement` rate instead.

Usage: audit_judge.py [--repeats N] [--case CASE]... [--out PATH] [--jobs N]
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from defender.evals.oracle_golden import judge  # noqa: E402

GOLDEN_DIR = Path(__file__).resolve().parent
CASES_DIR = GOLDEN_DIR / "cases"

#: The audit set: the four observed seed cases, whose labels were derived by hand
#: before any labelling program existed. Deliberately NOT case-005 (labelled by the
#: program this judge replaces — auditing against it would be auditing a copy) and not
#: the derived cases (no telemetry, so the label pass has nothing to measure).
AUDIT_CASES = (
    "case-001-ssh-bruteforce-canary",
    "case-002-authorized-keys-falco",
    "case-003-suppression-devws",
    "case-004-noise-stolen-cred",
)

#: Lookup/state systems: current configuration or an entity record, no event stream,
#: no @timestamp bounds to move, so no baseline-diff semantics.
STATE_SYSTEMS = frozenset({"cmdb", "identity", "threat-intel", "change-mgmt"})

#: The hand labels speak the retired four-class vocabulary; the label pass speaks
#: `delta_kind`. The mapping is mechanical and stated here rather than negotiated per
#: divergence — the one place it is not 1:1 is `0`, which collapsed two distinct
#: readings ("this event stream was quiet" and "this is a lookup, there is nothing to
#: diff") into a single class. Expanding it by the lead's own systems is a property of
#: the lead, not a judgement about the answer.
CLASS_TO_DELTA_KIND = {
    "+event": ("present",),
    "+noise": ("indistinguishable",),
    "-noise": ("suppressed",),
    "0": ("absent", "state-only"),
}


def lead_systems(lead: dict) -> set[str]:
    return {(q.get("query_id") or "").split(".")[0] for q in lead.get("queries") or []}


def expected_delta_kinds(case_class: str, lead: dict) -> tuple[str, ...]:
    """The `delta_kind` values that agree with a hand label for this lead."""
    kinds = CLASS_TO_DELTA_KIND.get(case_class)
    if kinds is None:
        return ()
    if case_class != "0":
        return kinds
    systems = lead_systems(lead)
    if systems and systems <= STATE_SYSTEMS:
        return ("state-only",)
    return ("absent",)


def audit_set(case_names: tuple[str, ...]) -> list[tuple[Path, str, str, dict]]:
    """(case_dir, lead_id, hand_class, lead_row) for every hand-labelled, measurable lead."""
    out = []
    for name in case_names:
        case_dir = CASES_DIR / name
        expected = yaml.safe_load((case_dir / "expected.yaml").read_text(encoding="utf-8"))
        leads = {row["lead_id"]: row for row in judge.load_leads(case_dir)}
        for lead_id, spec in (expected.get("leads") or {}).items():
            if lead_id not in leads:
                continue
            if not (case_dir / "hidden" / "observed" / lead_id).is_dir():
                continue  # a derived case: nothing to measure against
            out.append((case_dir, lead_id, (spec or {}).get("class"), leads[lead_id]))
    return out


def _label_once(case_dir: Path, lead_id: str, model: str, effort: str,
                call: judge.CallFn) -> dict:
    inputs = judge.load_lead_inputs(case_dir, lead_id)
    return judge.label_lead(inputs, model=model, effort=effort, call=call)


def run_audit(case_names: tuple[str, ...], repeats: int, jobs: int, *,
              model: str, effort: str, call: judge.CallFn = judge.call_model) -> dict:
    entries = audit_set(case_names)
    work = [(case_dir, lead_id, hand, lead, rep)
            for (case_dir, lead_id, hand, lead) in entries
            for rep in range(repeats)]
    with ThreadPoolExecutor(max_workers=max(1, min(jobs, len(work) or 1))) as pool:
        results = list(pool.map(
            lambda item: _label_once(item[0], item[1], model, effort, call), work
        ))

    by_lead: dict[tuple[str, str], list[dict]] = {}
    for (case_dir, lead_id, _hand, _lead, _rep), label in zip(work, results, strict=True):
        by_lead.setdefault((case_dir.name, lead_id), []).append(label)

    rows, divergences, agreements = [], 0, []
    for case_dir, lead_id, hand, lead in entries:
        labels = by_lead[(case_dir.name, lead_id)]
        kinds = [x["delta_kind"] for x in labels]
        counts = Counter(kinds)
        modal, modal_n = counts.most_common(1)[0]
        accepted = expected_delta_kinds(hand, lead)
        agrees = modal in accepted
        divergences += 0 if agrees else 1
        agreements.append(modal_n / len(kinds))
        rows.append({
            "case": case_dir.name, "lead": lead_id,
            "hand_class": hand, "accepted_delta_kinds": list(accepted),
            "modal_delta_kind": modal, "agrees": agrees,
            "self_agreement": round(modal_n / len(kinds), 3),
            "labels": kinds,
            "undecidable_reasons": [x["undecidable_reason"] for x in labels
                                    if x["undecidable_reason"]],
            "evidence": labels[0]["evidence"],
        })

    # The resolved judge, read back from every call rather than echoed from the request.
    # A run that fell back mid-sweep produced two judges' answers under one tag.
    resolved = {label["judge_model"] for labels in by_lead.values() for label in labels}
    if len(resolved) != 1:
        raise RuntimeError(f"the sweep ran on more than one judge: {sorted(resolved)}")
    costs = [label["cost_usd"] for labels in by_lead.values() for label in labels
             if label.get("cost_usd") is not None]

    decided = [r for r in rows if r["modal_delta_kind"] != "undecidable"]
    return {
        "judge_model": resolved.pop(), "judge_effort": effort,
        "tag_suffix": judge.tag_suffix(model, effort),
        "cost_usd": round(sum(costs), 4) if costs else None,
        "prompts_sha8": judge.prompts_sha8(), "repeats": repeats,
        "leads": len(rows),
        "agreeing": sum(1 for r in rows if r["agrees"]),
        "divergences": divergences,
        "abstentions": len(rows) - len(decided),
        "mean_self_agreement": round(sum(agreements) / len(agreements), 3) if agreements else None,
        "rows": rows,
    }


def render(report: dict) -> str:
    lines = [
        f"judge: {report['judge_model']} effort={report['judge_effort']} "
        f"prompts={report['prompts_sha8']} repeats={report['repeats']}"
        + (f" cost=${report['cost_usd']}" if report.get("cost_usd") else ""),
        f"calibration: {report['agreeing']}/{report['leads']} agree with the hand labels, "
        f"{report['divergences']} divergences, {report['abstentions']} abstentions",
        f"mean self-agreement: {report['mean_self_agreement']}",
        "",
    ]
    for r in report["rows"]:
        mark = "ok " if r["agrees"] else "!! "
        lines.append(
            f"{mark}{r['case']}/{r['lead']:6} hand={r['hand_class']:8} "
            f"-> {r['modal_delta_kind']:19} (accepted: {','.join(r['accepted_delta_kinds'])}; "
            f"self-agreement {r['self_agreement']})"
        )
    if report["divergences"]:
        lines += [
            "",
            "A divergence is adjudicated by RE-MEASUREMENT — re-read the telemetry and",
            "decide which side is wrong. Never tune the prompt until it agrees: a judge",
            "fitted to this set calibrates nothing.",
        ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repeats", type=int, default=1,
                    help="label each lead N times and report self-agreement")
    ap.add_argument("--case", action="append", dest="cases",
                    help="restrict to this case (repeatable); default is the audit set")
    ap.add_argument("--jobs", type=int, default=4, help="concurrent judge calls")
    ap.add_argument("--out", type=Path, help="write the JSON report here")
    args = ap.parse_args(argv)

    model, effort = judge.judge_model(), judge.judge_effort()
    report = run_audit(tuple(args.cases or AUDIT_CASES), args.repeats, args.jobs,
                       model=model, effort=effort)
    print(render(report))
    if args.out:
        args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"\nwrote {args.out}")
    return 1 if report["divergences"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
