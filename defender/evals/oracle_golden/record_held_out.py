#!/usr/bin/env python3
"""Append a held-out result to the ledger.

A held-out score is recorded **once per (case, tag)**. This appends the entry;
it will not replace one. That refusal is the mechanism: re-running a held-out
case under the same tag until the number improves is the way a held-out set
stops being held out, and there is no flag here to do it. Record a new oracle
version under a NEW tag instead.

Usage: record_held_out.py <case_dir> <tag>
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from defender.evals.oracle_golden import judge  # noqa: E402

GOLDEN_DIR = Path(__file__).resolve().parent
LEDGER = GOLDEN_DIR / "held_out_ledger.yaml"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("case_dir", type=Path)
    p.add_argument("tag")
    p.add_argument("--recorded", default="", help="ISO date; free text, for the reader")
    p.add_argument("--ledger", type=Path, default=None,
                   help="ledger to append to (default: the suite's own)")
    ns = p.parse_args(argv)
    ledger_path = ns.ledger if ns.ledger is not None else LEDGER

    manifest = yaml.safe_load((ns.case_dir / "manifest.yaml").read_text(encoding="utf-8")) or {}
    if manifest.get("split") != "held-out":
        print(f"!! {ns.case_dir.name} is split={manifest.get('split')!r}; only held-out "
              f"results are ledgered", file=sys.stderr)
        return 1

    score_path = ns.case_dir / "scores" / f"{ns.tag}.json"
    if not score_path.is_file():
        print(f"!! no {score_path}", file=sys.stderr)
        return 1

    # The judge runs at score time, so the tag names it. `judge_model()` reads an env var
    # with a fallback, so two machines can mint identically-named tags from different
    # judges. Refuse the one thing that would make the ledger lie: a result filed under a
    # tag that does not name the judge recorded inside it.
    score = json.loads(score_path.read_bytes())
    recorded = score.get("judge") or {}
    if not ns.tag.endswith(judge.tag_suffix(recorded.get("model", ""),
                                            recorded.get("effort", ""))):
        print(f"!! {score_path.name} was produced by "
              f"{recorded.get('model')!r}/{recorded.get('effort')!r} at prompts "
              f"{recorded.get('prompts_sha8')!r}, which is not the judge its tag names. "
              f"Re-score under the correct tag; do not rename the file.", file=sys.stderr)
        return 1

    doc = yaml.safe_load(ledger_path.read_text(encoding="utf-8")) or {}
    entries = doc.get("entries") or []
    key = (ns.case_dir.name, ns.tag)
    for entry in entries:
        if (entry.get("case"), entry.get("tag")) == key:
            print(f"!! {key[0]}/{key[1]} is already in the ledger. A held-out result is "
                  f"recorded once per tag — to record a new oracle version, use a new "
                  f"tag rather than re-running this one.", file=sys.stderr)
            return 1

    entries.append({
        "case": ns.case_dir.name,
        "tag": ns.tag,
        "sha256": hashlib.sha256(score_path.read_bytes()).hexdigest(),
        "recorded": ns.recorded,
    })
    # Keep the file's explanatory header (everything before `entries:`) and
    # re-serialize the list — the header is the only place that says why this
    # ledger exists, and a rewrite that dropped it would leave a bare hash list.
    head = ledger_path.read_text(encoding="utf-8").split("entries:")[0]
    ledger_path.write_text(
        head + yaml.safe_dump({"entries": entries}, sort_keys=False, width=100,
                              allow_unicode=True),
        encoding="utf-8")
    print(f"recorded {key[0]}/{key[1]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
