"""Minimal CLI over the cross-case query helpers.

  python -m defender.scripts.invlang.cli <corpus_root> sequence [--contains S] [--disposition D] [--signature SIG]
  python -m defender.scripts.invlang.cli <corpus_root> hypotheses <pattern> [--final-weight W] [--disposition D]
  python -m defender.scripts.invlang.cli <corpus_root> branch-effects [--hyp PATTERN ...] [--min-support N]

Emits JSON on stdout. Intended for ad-hoc inspection and as a callable
surface for the future advisory-retrieval adapter (which can shell out
or import the functions directly).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

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

    p8 = sub.add_parser("branch-effects", help="Class 8: per-lead per-hypothesis effect")
    p8.add_argument("--hyp", action="append", default=[], help="Hypothesis fnmatch pattern (repeatable).")
    p8.add_argument("--min-support", type=int, default=1)
    p8.add_argument("--max-hypotheses-per-lead", type=int, default=5)

    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
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
