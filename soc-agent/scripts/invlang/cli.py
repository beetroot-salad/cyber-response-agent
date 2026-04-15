"""CLI entry point for the investigation-language query tool.

Usage:
  python -m soc_agent.scripts.invlang.cli [options]
  python soc-agent/scripts/invlang/cli.py [options]

Run without arguments for the full demo across all 8 classes.
Pass --help for per-class argument documentation.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .corpus import Companion, load_corpus, PILOT_CORPUS_FILES, _corpus_root
from .queries import (
    ENUM_CHOICES,
    anchor_calibration,
    coarse_case_lookup,
    dead_lead_lookup,
    enumerate_corpus,
    hypothesis_name_wildcard,
    lead_effectiveness,
    lead_effectiveness_for_hypothesis,
    lead_sequence_pattern,
    prose_substring,
    refinement_chain_shapes,
)


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------

def _print_section(title: str) -> None:
    print(f"\n{'=' * 72}\n{title}\n{'=' * 72}")


def _print_result(label: str, result: dict[str, Any], limit: int = 6, as_json: bool = False) -> None:
    if as_json:
        print(json.dumps(result))
        return
    print(f"\n--- {label} → {result['count']} hit(s) ---")
    for key in ("hits", "distribution", "values"):
        if key not in result:
            continue
        items = result[key][:limit]
        for item in items:
            print(f"  {item}")
        if len(result[key]) > limit:
            print(f"  ... ({len(result[key]) - limit} more)")


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="invlang-query",
        description="""
Investigation-language v2.5 query tool.

Without --class or --enumerate, runs the full demo across all 8 classes.

QUERY CLASSES
  1  coarse-case-lookup     Filter cases by disposition/termination/archetype/confidence
  2  anchor-calibration     Distribution of anchor results × authority → disposition
  3  refinement-chains      Hypothesis refinement tree shapes per case
  4  dead-leads             Leads that errored or returned degraded data
  5  lead-sequence          Serialize gather blocks as trace strings; filter by substring
  6  hypothesis-wildcard    fnmatch on hypothesis names; filter by final weight
  7  prose-substring        Substring scan across all prose fields
  8  lead-effectiveness     Score leads by log1p(count) × mean_abs_weight_delta;
                            optionally restrict to hypotheses matching fnmatch patterns

ENUMERATION
  --enumerate leads|anchors|archetypes|hypotheses|dispositions
      List all distinct values of the chosen dimension across the corpus.
      Useful for discovering valid filter arguments before running a query.

CORPUS
  Default corpus: docs/experiments/investigation-language-pilot/ (PILOT_CORPUS_FILES).
  Override root directory via INVLANG_CORPUS_ROOT env var.

OUTPUT
  Default: human-readable.  --json: one JSON object per line.
""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    p.add_argument(
        "--class", dest="query_class", type=int, choices=range(1, 9), metavar="N",
        help="Run a single query class (1–8) instead of the full demo.",
    )
    p.add_argument(
        "--enumerate", dest="enumerate", choices=ENUM_CHOICES, metavar="KIND",
        help="List distinct values: leads | anchors | archetypes | hypotheses | dispositions",
    )
    p.add_argument("--json", action="store_true", help="Emit JSON instead of human-readable output.")

    g1 = p.add_argument_group("class 1 — coarse case lookup")
    g1.add_argument("--disposition", help="benign | unclear | true_positive")
    g1.add_argument("--termination", dest="termination_category", help="trust-root | severity-ceiling")
    g1.add_argument("--confidence", help="high | medium | low")
    g1.add_argument("--archetype", dest="matched_archetype", help="Exact matched_archetype value")
    g1.add_argument("--ceiling-kind", dest="ceiling_test_kind", help="tool-unavailable | out-of-band-human-contact")

    g2 = p.add_argument_group("class 2 — anchor calibration")
    g2.add_argument("--anchor-id", help="Filter by anchor_id")
    g2.add_argument("--result", help="confirmed | refuted | partial | no-data")
    g2.add_argument("--authority", dest="authority_for_question", help="full | partial")

    g4 = p.add_argument_group("class 4 — dead-lead lookup")
    g4.add_argument("--system", help="Filter by query_details.system")
    g4.add_argument("--failure-reason", dest="failure_reason",
                    help="adapter-error | attribution-opaque | partial-coverage | permission-denied | timeout | other")

    g5 = p.add_argument_group("class 5 — lead sequence")
    g5.add_argument("--contains", help="Filter traces containing this substring")

    g6 = p.add_argument_group("class 6 — hypothesis wildcard")
    g6.add_argument("--pattern", help="fnmatch pattern, e.g. '?*compromise*'")
    g6.add_argument("--weight", dest="final_weight", help="++ | + | - | --")

    g7 = p.add_argument_group("class 7 — prose substring")
    g7.add_argument("--phrase", help="Substring to scan across all prose fields")
    g7.add_argument("--case-sensitive", action="store_true")

    g8 = p.add_argument_group("class 8 — lead effectiveness")
    g8.add_argument(
        "--hypothesis", dest="hypothesis_patterns", nargs="+", metavar="PATTERN",
        help="One or more fnmatch patterns (AND-ed). "
             "E.g. --hypothesis '?*compromise*'  or  --hypothesis '?*monitoring*' '?*compromise*'",
    )

    return p


# ---------------------------------------------------------------------------
# Class dispatch
# ---------------------------------------------------------------------------

def _run_class(n: int, corpus: list[Companion], args: argparse.Namespace) -> dict[str, Any]:
    if n == 1:
        return coarse_case_lookup(
            corpus,
            disposition=args.disposition,
            termination_category=args.termination_category,
            confidence=args.confidence,
            matched_archetype=args.matched_archetype,
            ceiling_test_kind=args.ceiling_test_kind,
        )
    if n == 2:
        return anchor_calibration(
            corpus,
            anchor_id=args.anchor_id,
            result=args.result,
            authority_for_question=args.authority_for_question,
        )
    if n == 3:
        return refinement_chain_shapes(corpus)
    if n == 4:
        return dead_lead_lookup(corpus, system=args.system, failure_reason=args.failure_reason)
    if n == 5:
        return lead_sequence_pattern(corpus, contains=args.contains)
    if n == 6:
        if not args.pattern:
            print("error: --class 6 requires --pattern", file=sys.stderr)
            sys.exit(1)
        return hypothesis_name_wildcard(corpus, args.pattern, final_weight=args.final_weight, disposition=args.disposition)
    if n == 7:
        if not args.phrase:
            print("error: --class 7 requires --phrase", file=sys.stderr)
            sys.exit(1)
        return prose_substring(corpus, args.phrase, case_sensitive=args.case_sensitive)
    if n == 8:
        if args.hypothesis_patterns:
            return lead_effectiveness_for_hypothesis(corpus, *args.hypothesis_patterns)
        return lead_effectiveness(corpus)
    raise ValueError(f"unknown class {n}")


# ---------------------------------------------------------------------------
# Full demo
# ---------------------------------------------------------------------------

def _run_demo(corpus: list[Companion], as_json: bool) -> None:
    _print_section("Class 1 — coarse case lookup")
    _print_result("severity-ceiling + unclear", coarse_case_lookup(corpus, termination_category="severity-ceiling", disposition="unclear"), as_json=as_json)
    _print_result("tool-unavailable ceiling", coarse_case_lookup(corpus, ceiling_test_kind="tool-unavailable"), as_json=as_json)

    _print_section("Class 2 — anchor calibration")
    _print_result("all anchors — distribution", anchor_calibration(corpus), as_json=as_json)
    _print_result("partial-authority anchors", anchor_calibration(corpus, authority_for_question="partial"), as_json=as_json)

    _print_section("Class 3 — refinement chain shapes")
    all_chains = refinement_chain_shapes(corpus)
    _print_result("all chains", all_chains, limit=20, as_json=as_json)
    refined_only = {"hits": [h for h in all_chains["hits"] if h["max_depth"] > 1], "count": 0}
    refined_only["count"] = len(refined_only["hits"])
    _print_result("roots that refined (depth > 1)", refined_only, as_json=as_json)

    _print_section("Class 4 — dead-lead lookup")
    _print_result("all dead leads", dead_lead_lookup(corpus), as_json=as_json)

    _print_section("Class 5 — lead sequence pattern")
    _print_result("all traces", lead_sequence_pattern(corpus), as_json=as_json)
    _print_result("severity-ceiling traces", lead_sequence_pattern(corpus, contains="severity-ceiling"), as_json=as_json)

    _print_section("Class 6 — hypothesis name wildcard")
    _print_result("?*compromise*", hypothesis_name_wildcard(corpus, "?*compromise*"), as_json=as_json)
    _print_result("?*monitoring* weight=--", hypothesis_name_wildcard(corpus, "?*monitoring*", final_weight="--"), as_json=as_json)

    _print_section("Class 7 — prose substring")
    _print_result("'partial-authority'", prose_substring(corpus, "partial-authority"), as_json=as_json)
    _print_result("'burst'", prose_substring(corpus, "burst"), as_json=as_json)

    _print_section("Class 8 — lead effectiveness")
    _print_result("all leads", lead_effectiveness(corpus), limit=15, as_json=as_json)
    _print_result("?*compromise* hypotheses", lead_effectiveness_for_hypothesis(corpus, "?*compromise*"), as_json=as_json)
    _print_result("?*monitoring* ∧ ?*compromise*", lead_effectiveness_for_hypothesis(corpus, "?*monitoring*", "?*compromise*"), as_json=as_json)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    corpus = load_corpus()

    if args.enumerate:
        result = enumerate_corpus(corpus, args.enumerate)
        _print_result(f"enumerate({args.enumerate})", result, limit=200, as_json=args.json)
        return 0

    if args.query_class is not None:
        result = _run_class(args.query_class, corpus, args)
        _print_result(f"class {args.query_class}", result, limit=200, as_json=args.json)
        return 0

    _print_section(f"Corpus: {len(corpus)} companion(s) from {_corpus_root()}")
    for c in corpus:
        try:
            rel = c.source_path.relative_to(_corpus_root())
        except ValueError:
            rel = c.source_path
        print(f"  {c.case_id:30} {rel}")
        print(
            f"    vertices={len(c.prologue.get('vertices', []))}  "
            f"hypotheses={len(list(c.iter_new_hypotheses()))}  "
            f"leads={len(c.leads)}  "
            f"termination={c.conclude.get('termination', {}).get('category')}  "
            f"disposition={c.conclude.get('disposition')}"
        )
    if not corpus:
        print("No companions found.")
        return 1
    _run_demo(corpus, as_json=args.json)
    return 0


if __name__ == "__main__":
    sys.exit(main())
