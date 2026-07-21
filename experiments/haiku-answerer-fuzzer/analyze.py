#!/usr/bin/env python3
"""Score classifier dispositions against extracted ground truth.

Usage: analyze.py [runs_dir] [fixtures_dir]
Scans runs/<arm>-<issue>-t<k>/dispositions.md, joins each against
fixtures/<issue>-truth.json, prints per-trial rows and per-arm aggregates
(per-occurrence means with n as support — no count-weighted scores).

Metric definitions (plan.md "Trials"):
- eligible premises: have a truth label AND are not phase-B pre-flagged
  (pre-flags route to §7 by construction in both arms — no signal).
- recall_known: truth-fork premises flagged fork/silent by this trial.
- false_consensus: truth-fork premises this trial called consensus
  (the dangerous direction — silent ambiguity loss).
- novel_forks: flagged fork/silent, truth says consensus/drop. Not junk by
  definition — adjudicated separately; counted here as §7-load pressure.
- unlabeled premises (631's 19 pre-merge defs) are reported, never scored.
"""
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

BUCKET_RE = re.compile(r"^(CONSENSUS|FORK|SILENT|DROP):\s*`?(test_\w+)`?")
HEDGE_RE = re.compile(
    r"unclear|unresolved|hedge|silen(?:t|ce)|unspecified"
    r"|doc (?:doesn'?t|does not|never)|never (?:states|discusses|addresses|says)"
    r"|not (?:stated|specified|addressed|discussed|say)"
    r"|no [^|]{0,40}stated|leaves? [^|]{0,20}open|\(PO\d+ open\)",
    re.I)


def parse_dispositions(path: Path):
    """-> {test_name: (bucket, hedged)}; SILENT folds into fork (routes as one).

    hedged marks a CONSENSUS line whose converged outcome is itself a hedge
    ("3/3 unclear whether ..."): the panel agreed the doc is silent. Scored
    apart from confident consensus — a unanimous hedge is visible caution,
    not silent ambiguity loss.
    """
    got = {}
    for line in path.read_text().splitlines():
        m = BUCKET_RE.match(line.strip())
        if not m:
            continue
        bucket = {"CONSENSUS": "consensus", "FORK": "fork",
                  "SILENT": "fork", "DROP": "drop"}[m.group(1)]
        hedged = bucket == "consensus" and bool(HEDGE_RE.search(line))
        got.setdefault(m.group(2), (bucket, hedged))  # first classification wins
    return got


def score(trial_dir: Path, truth: dict):
    got = parse_dispositions(trial_dir / "dispositions.md")
    labels = truth["truth"]
    pre = set(truth["preflagged_forks"])
    eligible = {n for n in truth["premises"] if n in labels and n not in pre}

    bucket = {n: v[0] for n, v in got.items()}
    hedged = {n for n, v in got.items() if v[1]}
    tf = {n for n in eligible if labels[n] == "fork"}          # truth forks
    flagged = {n for n in eligible if bucket.get(n) == "fork"}
    fc = [n for n in tf if bucket.get(n) == "consensus"]
    r = {
        "trial": trial_dir.name,
        "premises_classified": len(bucket),
        "missing_from_output": len([n for n in truth["premises"] if n not in bucket]),
        "recall_known": round(len(tf & flagged) / len(tf), 3) if tf else None,
        "n_truth_forks": len(tf),
        # dangerous: panel confidently converged on ONE outcome for a premise
        # the human ruled a real decision — ambiguity silently lost
        "false_consensus_confident": len([n for n in fc if n not in hedged]),
        # visible caution: panel unanimously hedged ("3/3 unclear") — the
        # ambiguity is on the record, it just didn't route as a fork
        "converged_hedge_on_fork": len([n for n in fc if n in hedged]),
        "novel_forks": sorted(flagged - tf),
        "n_novel": len(flagged - tf),
        "total_fork_load": len(flagged) + len(pre & set(bucket)),
        "unlabeled_flagged": len([n for n in bucket if n not in labels
                                  and bucket[n] == "fork"]),
    }
    return r


def main(runs="runs", fixtures="fixtures"):
    rows, by_arm = [], defaultdict(list)
    for d in sorted(Path(runs).iterdir()):
        m = re.match(r"(\w+)-(\d+)-t(\d+)", d.name)
        if not m or not (d / "dispositions.md").exists():
            continue
        truth = json.loads(Path(fixtures, f"{m.group(2)}-truth.json").read_text())
        row = score(d, truth)
        rows.append(row)
        by_arm[(m.group(1), m.group(2))].append(row)

    for r in rows:
        print(json.dumps(r))
    print("\n== per-arm aggregates (mean per occurrence, n = trials) ==")
    for (arm, issue), rs in sorted(by_arm.items()):
        rec = [r["recall_known"] for r in rs if r["recall_known"] is not None]
        print(f"{arm}-{issue}  n={len(rs)}  "
              f"recall={sum(rec)/len(rec):.3f}  " if rec else f"{arm}-{issue}  n={len(rs)}  recall=n/a  ",
              f"fc_confident={sum(r['false_consensus_confident'] for r in rs)/len(rs):.1f}  "
              f"conv_hedge={sum(r['converged_hedge_on_fork'] for r in rs)/len(rs):.1f}  "
              f"novel={sum(r['n_novel'] for r in rs)/len(rs):.1f}  "
              f"fork_load={sum(r['total_fork_load'] for r in rs)/len(rs):.1f}", sep="")


if __name__ == "__main__":
    main(*sys.argv[1:])
