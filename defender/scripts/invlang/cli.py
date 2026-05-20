"""Minimal CLI over the cross-case query helpers + advisory adapter.

Primitive queries:
  python -m defender.scripts.invlang.cli <corpus_root> sequence [--contains S] [--disposition D] [--signature SIG]
  python -m defender.scripts.invlang.cli <corpus_root> hypotheses <pattern> [--final-weight W] [--disposition D] [--signature SIG]
  python -m defender.scripts.invlang.cli <corpus_root> branch-effects [--hyp PATTERN ...] [--min-support N]

Composed PLAN-time advisory recall:
  python -m defender.scripts.invlang.cli <corpus_root> advisory --signature SIG [--frontier ?H ...] [--class C ...] [--top-k 3] [--json]

Primitives emit JSON; `advisory` emits rendered markdown by default with
a `--json` toggle for the harness.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .advisory import VALID_CLASSES, advisory_recall
from .corpus import load_corpus
from .queries import (
    hypothesis_name_wildcard,
    lead_branch_effects,
    lead_sequence_pattern,
)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="defender.scripts.invlang.cli")
    p.add_argument("corpus_root", type=Path)
    p.add_argument("--quiet", action="store_true", help="Suppress LoadReport summary on stderr.")
    sub = p.add_subparsers(dest="cmd", required=True)

    p5 = sub.add_parser("sequence", help="Class 5: lead sequence pattern")
    p5.add_argument("--contains")
    p5.add_argument("--disposition")
    p5.add_argument("--signature")

    p6 = sub.add_parser("hypotheses", help="Class 6: hypothesis name wildcard")
    p6.add_argument("pattern")
    p6.add_argument("--final-weight", choices=["++", "+", "-", "--"])
    p6.add_argument("--disposition")
    p6.add_argument("--signature")

    p8 = sub.add_parser("branch-effects", help="Class 8: per-lead per-hypothesis effect")
    p8.add_argument("--hyp", action="append", default=[], help="Hypothesis fnmatch pattern (repeatable).")
    p8.add_argument("--min-support", type=int, default=1)
    p8.add_argument("--max-hypotheses-per-lead", type=int, default=5)

    pa = sub.add_parser("advisory", help="Composed PLAN-time advisory recall")
    pa.add_argument("--signature", required=True)
    pa.add_argument(
        "--frontier", action="append", default=[],
        help="Current ?hypothesis name (repeatable).",
    )
    pa.add_argument(
        "--class", dest="classes", action="append", default=[],
        choices=list(VALID_CLASSES),
        help="Subset of advisory classes (repeatable). Default: all.",
    )
    pa.add_argument("--top-k", type=int, default=3)
    pa.add_argument("--json", dest="as_json", action="store_true",
                    help="Emit JSON instead of rendered markdown.")

    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    if args.cmd == "advisory":
        # The adapter does its own (cached) corpus load + telemetry; skip
        # the upfront load + summary print so its own banner isn't shadowed.
        result = advisory_recall(
            args.corpus_root,
            signature_id=args.signature,
            frontier=tuple(args.frontier),
            classes=tuple(args.classes) if args.classes else VALID_CLASSES,
            top_k=args.top_k,
        )
        sys.stdout.write(result.as_json() if args.as_json else result.as_markdown())
        sys.stdout.write("\n")
        return 0

    corpus, report = load_corpus(args.corpus_root)
    if not args.quiet:
        print(
            f"loaded {len(corpus)}/{report.scanned} cases "
            f"(skipped={len(report.skipped)} partial={len(report.partial)} "
            f"warnings={report.total_warnings})",
            file=sys.stderr,
        )

    if args.cmd == "sequence":
        out = lead_sequence_pattern(
            corpus,
            contains=args.contains,
            disposition=args.disposition,
            signature_id=args.signature,
        )
    elif args.cmd == "hypotheses":
        out = hypothesis_name_wildcard(
            corpus,
            args.pattern,
            final_weight=args.final_weight,
            disposition=args.disposition,
            signature_id=args.signature,
        )
    elif args.cmd == "branch-effects":
        out = lead_branch_effects(
            corpus,
            hypothesis_patterns=tuple(args.hyp),
            min_support=args.min_support,
            max_hypotheses_per_lead=args.max_hypotheses_per_lead,
        )
    else:
        raise AssertionError(args.cmd)

    json.dump(out, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
