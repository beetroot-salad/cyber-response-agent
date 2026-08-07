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
`--pass verdict` measures the two things that can be measured — self-agreement, and how
often it returns `contradicts-measurement` — over the leads a real projection was scored
on, reusing the same cached measurement `score.py` feeds it.

**Why the verdict audit is not optional.** The judge runs at score time, so its variance
sits inside every interval `report.py` prints. The dev active band is 7 leads: one lead
that flips between runs moves the headline 14 points. Without this number, a prompt
change smaller than the judge's own noise reads as an improvement.

Usage:
  audit_judge.py [--pass label|verdict] [--repeats N] [--case CASE]... [--tag TAG]
                 [--out PATH] [--jobs N]
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from defender.evals.oracle_golden import judge, score  # noqa: E402

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


#: Anchored in `judge.py` so the calibration and the report's slice axis cannot drift.
lead_systems = judge.lead_systems


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
    out: list[tuple[Path, str, str, dict]] = []
    for name in case_names:
        case_dir = CASES_DIR / name
        expected = yaml.safe_load((case_dir / "expected.yaml").read_text(encoding="utf-8"))
        leads = {row["lead_id"]: row for row in judge.load_case_leads(case_dir)}
        for lead_id, spec in (expected.get("leads") or {}).items():
            if lead_id not in leads:
                continue
            if not (case_dir / "hidden" / "observed" / lead_id).is_dir():
                continue  # a derived case: nothing to measure against
            hand_class = (spec or {}).get("class")
            if not hand_class:
                continue  # listed but never hand-labelled: not calibration evidence
            out.append((case_dir, lead_id, hand_class, leads[lead_id]))
    return out


@dataclass(frozen=True)
class _Agreement:
    """What one lead answered most often, over `n` repeats of the same question."""

    modal: object
    modal_n: int
    n: int

    @property
    def fraction(self) -> float:
        return self.modal_n / self.n

    @property
    def stable(self) -> bool:
        return self.modal_n == self.n


def _modal(answers: list) -> _Agreement:
    """The modal answer and how dominant it was. `Counter.most_common(1)` breaks ties by
    first-seen, which is arbitrary but consistent — and a tie is already reported as such,
    because `fraction` shows it."""
    modal, modal_n = Counter(answers).most_common(1)[0]
    return _Agreement(modal=modal, modal_n=modal_n, n=len(answers))


def _mean_agreement(rounds: list[_Agreement]) -> float | None:
    """`None`, not zero, for an empty sweep: nothing was asked, so nothing agreed."""
    return round(sum(r.fraction for r in rounds) / len(rounds), 3) if rounds else None


def _sweep(entries: list[tuple], repeats: int, jobs: int, ask) -> dict[tuple[str, str], list[dict]]:
    """Ask `ask` about every entry `repeats` times, grouped back by (case, lead).

    THE sweep. Both audits are the same experiment on different questions — fan one
    question across a thread pool, then collapse the repeats per lead to a modal answer and
    a self-agreement — and both wrote that fan-out and regroup by hand. The stakes are that
    the two numbers are compared to each other: the label pass's self-agreement and the
    verdict pass's are read side by side to say which pass a prompt change moved, and that
    reading assumes both were measured the same way.

    Every entry is a tuple whose first two elements are `(case_dir, lead_id)`; the rest is
    the caller's, and reaches `ask` untouched.
    """
    work = [(entry, rep) for entry in entries for rep in range(repeats)]
    with ThreadPoolExecutor(max_workers=max(1, min(jobs, len(work) or 1))) as pool:
        answers = list(pool.map(lambda item: ask(item[0]), work))

    by_lead: dict[tuple[str, str], list[dict]] = {}
    for (entry, _rep), answer in zip(work, answers, strict=True):
        case_dir, lead_id = entry[0], entry[1]
        by_lead.setdefault((case_dir.name, lead_id), []).append(answer)
    return by_lead


def run_audit(case_names: tuple[str, ...], repeats: int, jobs: int, *,
              model: str, effort: str, call: judge.CallFn = judge.call_model) -> dict:
    entries = audit_set(case_names)

    def ask(entry: tuple) -> dict:
        case_dir, lead_id = entry[0], entry[1]
        return judge.label_lead(judge.load_lead_inputs(case_dir, lead_id),
                                model=model, effort=effort, call=call)

    by_lead = _sweep(entries, repeats, jobs, ask)

    rows, rounds = [], []
    for case_dir, lead_id, hand, lead in entries:
        labels = by_lead[(case_dir.name, lead_id)]
        kinds = [x["delta_kind"] for x in labels]
        agreement = _modal(kinds)
        accepted = expected_delta_kinds(hand, lead)
        # An ABSTENTION is not a divergence, and conflating them charges the judge for
        # its own honesty. A divergence is the judge asserting a class the hand label
        # rules out; `undecidable` asserts nothing, and the design excludes it from
        # every denominator and tallies it separately.
        abstained = agreement.modal == "undecidable"
        agrees = agreement.modal in accepted
        rounds.append(agreement)
        rows.append({
            "case": case_dir.name, "lead": lead_id,
            "hand_class": hand, "accepted_delta_kinds": list(accepted),
            "modal_delta_kind": agreement.modal, "agrees": agrees, "abstained": abstained,
            "diverges": not agrees and not abstained,
            "self_agreement": round(agreement.fraction, 3),
            "labels": kinds,
            "undecidable_reasons": [x["undecidable_reason"] for x in labels
                                    if x["undecidable_reason"]],
            "evidence": labels[0]["evidence"],
        })

    replies = [label for labels in by_lead.values() for label in labels]
    decided = [r for r in rows if not r["abstained"]]
    return {
        "pass": "label",
        # The resolved judge, read back from every call rather than echoed from the request.
        # A run that fell back mid-sweep produced two judges' answers under one tag.
        "judge_model": judge.sole_judge(replies, what="the label sweep"),
        "judge_effort": effort,
        "tag_suffix": judge.tag_suffix(model, effort),
        "cost_usd": judge.total_cost(replies),
        "prompts_sha8": judge.prompts_sha8(), "repeats": repeats,
        "leads": len(rows),
        "decided": len(decided),
        "agreeing": sum(1 for r in rows if r["agrees"]),
        "divergences": sum(1 for r in rows if r["diverges"]),
        "abstentions": len(rows) - len(decided),
        "mean_self_agreement": _mean_agreement(rounds),
        "rows": rows,
    }


#: The oracle tag the verdict audit grades, unless `--tag` says otherwise. The verdict
#: pass is a function of a PROJECTION, so unlike the label pass it cannot be audited
#: without naming one.
DEFAULT_ORACLE_TAG = "glm-5.2_effort-none_prompt-711"


def verdict_set(case_names: tuple[str, ...],
                oracle_tag: str) -> list[tuple[Path, str, object, dict]]:
    """(case_dir, lead_id, events, measurement) for every lead a real score judged.

    Deliberately reuses the committed `labels/<judge-tag>.json` rather than re-measuring:
    the question is how stable the VERDICT pass is given a fixed measurement, and letting
    the label pass vary underneath it would fold the two variances into one number that
    names neither.
    """
    out: list[tuple[Path, str, object, dict]] = []
    model, effort = judge.judge_model(), judge.judge_effort()
    for name in case_names:
        case_dir = CASES_DIR / name
        proj_path = case_dir / "projections" / f"{oracle_tag}.yaml"
        labels_path = score.labels_path(case_dir, model, effort)
        if not (proj_path.is_file() and labels_path.is_file()):
            continue
        manifest = yaml.safe_load((case_dir / "manifest.yaml").read_text(encoding="utf-8")) or {}
        if manifest.get("defective") or score.is_derived(manifest.get("kind")):
            continue
        proj = yaml.safe_load(proj_path.read_text(encoding="utf-8")) or {}
        preds, _ = score.load_predictions(proj)
        labels = (json.loads(labels_path.read_text(encoding="utf-8")).get("leads") or {})
        for lead_id, label in sorted(labels.items()):
            # The same two exclusions score.py applies: an unmeasured envelope has
            # nothing to grade against, and a malformed projection never reaches the
            # judge at all. Auditing either would measure a call that never happens.
            if label.get("delta_kind") == "undecidable" or lead_id not in preds:
                continue
            if score.grammar_problem(preds[lead_id]) is not None:
                continue
            out.append((case_dir, lead_id, preds[lead_id], score.measurement(label)))
    return out


def run_verdict_audit(case_names: tuple[str, ...], oracle_tag: str, repeats: int,  # noqa: PLR0913 — every argument is an axis of the sweep; a config object would hide which one a caller varied
                      jobs: int, *, model: str, effort: str,
                      call: judge.CallFn = judge.call_model) -> dict:
    entries = verdict_set(case_names, oracle_tag)

    def ask(entry: tuple) -> dict:
        case_dir, lead_id, events, measurement = entry
        return judge.verdict_lead(judge.load_lead_inputs(case_dir, lead_id), events,
                                  measurement, model=model, effort=effort, call=call)

    by_lead = _sweep(entries, repeats, jobs, ask)

    rows, rounds = [], []
    for case_dir, lead_id, _events, measurement in entries:
        verdicts = by_lead[(case_dir.name, lead_id)]
        answers = [v["faithful"] for v in verdicts]
        agreement = _modal(answers)
        rounds.append(agreement)
        rows.append({
            "case": case_dir.name, "lead": lead_id,
            "delta_kind": measurement.get("delta_kind"),
            "modal_faithful": agreement.modal,
            "self_agreement": round(agreement.fraction, 3),
            "stable": agreement.stable,
            "faithful": answers,
            "causes": sorted({v["cause"] for v in verdicts if v["cause"]}),
            "undecidable_reasons": sorted({v["undecidable_reason"] for v in verdicts
                                           if v["undecidable_reason"]}),
            "rationale": verdicts[0]["rationale"],
        })

    replies = [v for vs in by_lead.values() for v in vs]
    unstable = [r for r in rows if not r["stable"]]
    contradicts = [r for r in rows if "contradicts-measurement" in r["undecidable_reasons"]]
    return {
        "pass": "verdict",
        "oracle_tag": oracle_tag,
        "judge_model": judge.sole_judge(replies, what="the verdict sweep"),
        "judge_effort": effort,
        "tag_suffix": judge.tag_suffix(model, effort),
        "cost_usd": judge.total_cost(replies),
        "prompts_sha8": judge.prompts_sha8(), "repeats": repeats,
        "leads": len(rows),
        "unstable_leads": len(unstable),
        # The number a prompt change has to beat. A dev band of 7 leads where 2 flip
        # between runs cannot resolve a one-lead improvement.
        "noise_floor_leads": len(unstable),
        "contradicts_measurement": len(contradicts),
        "mean_self_agreement": _mean_agreement(rounds),
        "rows": rows,
    }


def render_verdict(report: dict) -> str:
    lines = [
        f"judge: {report['judge_model']} effort={report['judge_effort']} "
        f"prompts={report['prompts_sha8']} repeats={report['repeats']} "
        f"oracle={report['oracle_tag']}"
        + (f" cost=${report['cost_usd']}" if report.get("cost_usd") else ""),
        f"self-agreement: {report['mean_self_agreement']} mean; "
        f"{report['unstable_leads']}/{report['leads']} lead(s) did not answer the same "
        f"way every time",
        f"contradicts-measurement: {report['contradicts_measurement']}/{report['leads']}",
        "",
    ]
    for r in report["rows"]:
        mark = "ok " if r["stable"] else "!! "
        answers = ",".join("T" if a is True else "F" if a is False else "?"
                           for a in r["faithful"])
        lines.append(f"{mark}{r['case']}/{r['lead']:6} {r['delta_kind']:18} "
                     f"[{answers}] agreement={r['self_agreement']}"
                     + (f" causes={','.join(r['causes'])}" if r["causes"] else ""))
    lines += [
        "",
        "There is no hand-labelled ground truth for this pass, so none of this is a",
        "calibration. It bounds how much of a score change is the judge rather than the",
        f"oracle: {report['unstable_leads']} lead(s) can move between two runs of the same",
        "unchanged projection, so a prompt edit that moves fewer than that has not been",
        "shown to do anything.",
    ]
    if report["contradicts_measurement"]:
        lines += [
            "",
            "`contradicts-measurement` means the verdict pass read the telemetry",
            "differently from the pass that measured it. That is a disagreement between",
            "the two passes, not an oracle failure — adjudicate it by re-reading the",
            "payload, and if the label pass is wrong the fix is a re-measurement.",
        ]
    return "\n".join(lines)


def render(report: dict) -> str:
    lines = [
        f"judge: {report['judge_model']} effort={report['judge_effort']} "
        f"prompts={report['prompts_sha8']} repeats={report['repeats']}"
        + (f" cost=${report['cost_usd']}" if report.get("cost_usd") else ""),
        f"calibration: {report['agreeing']}/{report['decided']} of the DECIDED leads agree "
        f"with the hand labels ({report['divergences']} class divergences); "
        f"{report['abstentions']}/{report['leads']} abstained",
        f"mean self-agreement: {report['mean_self_agreement']}",
        "",
    ]
    for r in report["rows"]:
        mark = "?? " if r["abstained"] else ("ok " if r["agrees"] else "!! ")
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
    if report["abstentions"]:
        lines += [
            "",
            "An abstention is not a divergence. Read its `evidence`: it names the payload",
            "that would have settled the lead, which is a statement about the INSTRUMENT.",
            "A set that abstains more than it decides is not a calibration.",
        ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--pass", dest="which", choices=["label", "verdict"], default="label",
                    help="label: calibrate against the hand labels. "
                         "verdict: self-agreement only — nothing hand-labelled exists")
    ap.add_argument("--repeats", type=int, default=1,
                    help="judge each lead N times and report self-agreement")
    ap.add_argument("--case", action="append", dest="cases",
                    help="restrict to this case (repeatable); default is the audit set")
    ap.add_argument("--tag", default=DEFAULT_ORACLE_TAG,
                    help="--pass verdict only: the oracle projection to grade")
    ap.add_argument("--jobs", type=int, default=4, help="concurrent judge calls")
    ap.add_argument("--out", type=Path, help="write the JSON report here")
    args = ap.parse_args(argv)

    model, effort = judge.judge_model(), judge.judge_effort()
    cases = tuple(args.cases or AUDIT_CASES)
    if args.which == "verdict":
        report = run_verdict_audit(cases, args.tag, args.repeats, args.jobs,
                                   model=model, effort=effort, call=judge.call_model)
        print(render_verdict(report))
        rc = 0          # instability is a measurement, not a failure
    else:
        report = run_audit(cases, args.repeats, args.jobs, model=model, effort=effort,
                           call=judge.call_model)
        print(render(report))
        rc = 1 if report["divergences"] else 0
    if args.out:
        args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"\nwrote {args.out}")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
