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
    enumerate_hypothesis_tree,
    hypothesis_name_wildcard,
    independent_datasource_metric,
    lead_discrimination_score,
    lead_effectiveness,
    lead_effectiveness_for_hypothesis,
    lead_pair_synergy,
    lead_sequence_pattern,
    post_failure_recovery,
    prose_substring,
    refinement_chain_shapes,
    weight_reversal_mining,
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
    count_key = "count" if "count" in result else None
    count_val = result.get("count", "?")
    print(f"\n--- {label} → {count_val} hit(s) ---")
    for key in ("hits", "distribution", "values"):
        if key not in result:
            continue
        items = result[key][:limit]
        for item in items:
            print(f"  {item}")
        if len(result[key]) > limit:
            print(f"  ... ({len(result[key]) - limit} more)")
    # For enum-tree, pretty-print the tree structure
    if "tree" in result and "flat" not in result:
        pass  # handled below
    if "tree" in result:
        tree = result["tree"]
        flat = result.get("flat", [])
        print(f"\n  Tree ({len(tree)} root(s), {count_val} total hypotheses):")
        for root_id, children in tree.items():
            print(f"    {root_id}: {[c['id'] for c in children] or '(leaf)'}")


def _apply_top(result: dict[str, Any], top: int | None) -> dict[str, Any]:
    """Slice hits (and distribution) to at most top items."""
    if top is None:
        return result
    out = dict(result)
    for key in ("hits", "distribution", "values"):
        if key in out and isinstance(out[key], list):
            out[key] = out[key][:top]
    return out


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
                            optionally restrict to hypotheses matching fnmatch patterns;
                            optionally compute discrimination score between two hypothesis patterns
  9  weight-reversal        Find resolutions where weight moved from positive to negative
                            (pitfall extraction: evidence that looked supportive but wasn't)
  10 lead-pair-synergy      Composite dispatches where the pair discriminates more than either alone
  11 post-failure-recovery  After a dead lead, what lead came next and how effective was it?
  12 datasource-metric      Distinct system count per case, grouped by termination × disposition × confidence

ENUMERATION
  --enumerate leads|anchors|archetypes|hypotheses|dispositions
      List all distinct values of the chosen dimension across the corpus.
  --enum-tree
      Return the parent-child hierarchy of hypothesis IDs (inferred from h-001-002 ID structure).

GLOBAL OPTIONS
  --top N   Return at most the top N results (applied after class-specific default sort).

CORPUS
  Default corpus: docs/experiments/investigation-language-pilot/ (PILOT_CORPUS_FILES).
  Override root directory via INVLANG_CORPUS_ROOT env var.

OUTPUT
  Default: human-readable.  --json: one JSON object per line.
""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    p.add_argument(
        "--class", dest="query_class", type=int, choices=range(1, 13), metavar="N",
        help="Run a single query class (1–12) instead of the full demo.",
    )
    p.add_argument(
        "--enumerate", dest="enumerate", choices=ENUM_CHOICES, metavar="KIND",
        help="List distinct values: leads | anchors | archetypes | hypotheses | dispositions",
    )
    p.add_argument(
        "--enum-tree", dest="enum_tree", action="store_true",
        help="Return parent-child hierarchy of hypothesis IDs across the corpus.",
    )
    p.add_argument("--json", action="store_true", help="Emit JSON instead of human-readable output.")
    p.add_argument(
        "--top", dest="top", type=int, default=None, metavar="N",
        help="Return at most N results (applied after class-specific default sort).",
    )

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

    g4 = p.add_argument_group("class 4 / class 11 — dead-lead lookup / post-failure recovery")
    g4.add_argument("--system", help="Filter by query_details.system")
    g4.add_argument("--failure-reason", dest="failure_reason",
                    help="adapter-error | attribution-opaque | partial-coverage | permission-denied | timeout | other")

    g5 = p.add_argument_group("class 5 — lead sequence")
    g5.add_argument("--contains", help="Filter traces containing this substring")

    g6 = p.add_argument_group("class 6 / class 9 — hypothesis wildcard / weight-reversal")
    g6.add_argument("--pattern", help="fnmatch pattern, e.g. '?*compromise*' (class 6)")
    g6.add_argument("--weight", dest="final_weight", help="++ | + | - | -- (class 6)")
    g6.add_argument("--hyp-pattern", dest="hyp_pattern",
                    help="fnmatch pattern to filter hypotheses (class 9)")

    g7 = p.add_argument_group("class 7 — prose substring")
    g7.add_argument("--phrase", help="Substring to scan across all prose fields")
    g7.add_argument("--case-sensitive", action="store_true")

    g8 = p.add_argument_group("class 8 — lead effectiveness")
    g8.add_argument(
        "--hypothesis", dest="hypothesis_patterns", nargs="+", metavar="PATTERN",
        help="One or more fnmatch patterns (AND-ed). "
             "E.g. --hypothesis '?*compromise*'  or  --hypothesis '?*monitoring*' '?*compromise*'",
    )
    g8.add_argument(
        "--discriminate-between", dest="discriminate_between", nargs=2, metavar="PATTERN",
        help="Two fnmatch patterns. Scores each lead by mean(signed_delta_H1 - signed_delta_H2) "
             "across cases where both patterns are present.",
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
        if args.discriminate_between:
            p1, p2 = args.discriminate_between
            return lead_discrimination_score(corpus, p1, p2)
        if args.hypothesis_patterns:
            return lead_effectiveness_for_hypothesis(corpus, *args.hypothesis_patterns)
        return lead_effectiveness(corpus)
    if n == 9:
        return weight_reversal_mining(corpus, hypothesis_pattern=getattr(args, "hyp_pattern", None))
    if n == 10:
        return lead_pair_synergy(corpus)
    if n == 11:
        return post_failure_recovery(corpus, system=args.system, failure_reason=args.failure_reason)
    if n == 12:
        return independent_datasource_metric(corpus, disposition=args.disposition)
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
    _print_result("discriminate ?*monitoring* vs ?*brute*", lead_discrimination_score(corpus, "?*monitoring*", "?*brute*"), as_json=as_json)

    _print_section("Class 9 — weight-reversal mining")
    _print_result("all reversals", weight_reversal_mining(corpus), as_json=as_json)

    _print_section("Class 10 — lead pair synergy")
    _print_result("synergistic pairs", lead_pair_synergy(corpus), as_json=as_json)

    _print_section("Class 11 — post-failure recovery")
    _print_result("recovery map", post_failure_recovery(corpus), as_json=as_json)

    _print_section("Class 12 — independent data source metric")
    _print_result("system count per case", independent_datasource_metric(corpus), limit=20, as_json=as_json)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    corpus = load_corpus()

    if args.enum_tree:
        result = enumerate_hypothesis_tree(corpus)
        _print_result("hypothesis-tree", result, limit=200, as_json=args.json)
        return 0

    if args.enumerate:
        result = enumerate_corpus(corpus, args.enumerate)
        _print_result(f"enumerate({args.enumerate})", result, limit=200, as_json=args.json)
        return 0

    if args.query_class is not None:
        result = _run_class(args.query_class, corpus, args)
        result = _apply_top(result, args.top)
        limit = args.top if args.top is not None else 200
        _print_result(f"class {args.query_class}", result, limit=limit, as_json=args.json)
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
