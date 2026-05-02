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

from .corpus import Companion, load_corpus, _corpus_root, _merge_md_blocks, extract_ids
from .queries import (
    ENUM_CHOICES,
    _parse_vertex_where_spec,
    anchor_calibration,
    authorization_calibration,
    coarse_case_lookup,
    dead_lead_lookup,
    enumerate_corpus,
    enumerate_hypothesis_tree,
    hypothesis_name_wildcard,
    independent_datasource_metric,
    lead_discrimination_score,
    lead_effectiveness,
    lead_effectiveness_for_hypothesis,
    lead_exemplars,
    lead_pair_synergy,
    lead_sequence_pattern,
    loop_lead_distribution,
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
    count_val = result.get("count", "?")
    # When --top sliced the hits below count, note it in the header.
    hits = result.get("hits", [])
    if isinstance(count_val, int) and len(hits) < count_val:
        header_suffix = f" [showing top {len(hits)} of {count_val}]"
    else:
        header_suffix = ""
    print(f"\n--- {label} → {count_val} hit(s){header_suffix} ---")
    for key in ("hits", "distribution", "values"):
        if key not in result:
            continue
        val = result[key]
        if isinstance(val, dict):
            # class 15 returns `distribution` as dict[str, int] — render directly.
            print(f"\n  {key}:")
            if not val:
                print("    (empty)")
                continue
            for k, v in list(val.items())[:limit]:
                print(f"    {k}: {v}")
            if len(val) > limit:
                print(f"    ... ({len(val) - limit} more)")
            continue
        items = val[:limit]
        for item in items:
            print(f"  {item}")
        if len(val) > limit:
            print(f"  ... ({len(val) - limit} more)")
    if "tree" in result:
        tree = result["tree"]
        print(f"\n  Tree ({len(tree)} root(s), {count_val} total hypotheses):")
        for root_id, children in tree.items():
            print(f"    {root_id}: {[c['id'] for c in children] or '(leaf)'}")
    if "summary" in result and isinstance(result["summary"], dict):
        print("\n  Summary:")
        for k, v in result["summary"].items():
            print(f"    {k}: {v}")
    if "exemplars" in result and isinstance(result["exemplars"], dict):
        print("\n  Exemplars by verdict:")
        for verdict, rows in result["exemplars"].items():
            print(f"    {verdict} ({len(rows)}):")
            for row in rows:
                print(f"      {row}")
    if "matched_contracts" in result and isinstance(result["matched_contracts"], list):
        print(f"\n  Matched contracts ({len(result['matched_contracts'])}):")
        for c in result["matched_contracts"][:10]:
            print(f"    {c}")
    if "surprises" in result:
        print(f"\n  Surprises: {result['surprises']}")
    if "telemetry" in result and isinstance(result["telemetry"], dict):
        print("\n  Telemetry:")
        for k, v in result["telemetry"].items():
            print(f"    {k}: {v}")
    if "matched_case_ids" in result and isinstance(result["matched_case_ids"], list):
        ids = result["matched_case_ids"]
        print(f"\n  Matched case ids ({len(ids)}):")
        for cid in ids[:10]:
            print(f"    {cid}")


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
Investigation-language query tool (v2.7 corpus).

Without --class or --enumerate, runs the full demo across all 15 classes.

QUICK START
  --enumerate hypotheses          see all hypothesis names (run this before using patterns)
  --enumerate archetypes          see outcome clusters seen in past cases
  --class 1                       list all cases with disposition/confidence/archetype
  --class 8                       rank leads by effectiveness across the corpus
  --class 9 --reversals-only      pitfalls: hypotheses that looked right then got refuted

QUERY CLASSES
  1  coarse-case-lookup     Filter cases by disposition / termination / archetype / confidence
  2  anchor-calibration     Distribution of (anchor result × authority) → disposition
  3  refinement-chains      Hypothesis refinement tree shapes: depth and branching per root
  4  dead-leads             Leads that errored or returned degraded data (loop order)
  5  lead-sequence          Full investigation trace per case; filter by substring
  6  hypothesis-wildcard    fnmatch on hypothesis names; filter by final weight
  7  prose-substring        Substring scan across all prose fields (reasoning, summaries, concerns)
  8  lead-effectiveness     Rank leads on branching_delta + prediction_fidelity + kind_mix
                              --hypothesis PATTERN [PATTERN …]  restrict to matching hypotheses
                              --discriminate-between P1 P2       signed lift: moves P1 up, P2 down
  9  weight-reversal        Resolutions where weight moved from positive/null to negative
                              --hyp-pattern PATTERN  filter to matching hypotheses
                              --reversals-only       show only is_true_reversal=True rows
                                                     (before ∈ {+,++}, excludes null→negative)
  10 lead-pair-synergy      Composite dispatches: does the pair move more weight than either alone?
  11 post-failure-recovery  After a dead lead, what lead came next and how effective was it?
  12 datasource-metric      Distinct system count per case; distribution by termination × disposition
  13 lead-exemplars         (ANALYZE recall) past resolutions of leads matching --lead-pattern
                              + aggregate summary (disposition mix, modal hypothesis outcomes,
                              surprises). Optional: --vertex-where SPEC to scope to similar graph
                              context (e.g. 'endpoint:classification=high-trust').
  14 authz-calibration      (ANALYZE recall) verdict distribution + per-bucket exemplars for
                              --contract-pattern (matches hypothesis name OR predicate substring).
                              Optional: --vertex-where SPEC.
  15 loop-lead-distribution Cache-key recall: what lead was picked at --loop N in past cases
                              with the same signature + prologue topology.

VERTEX-WHERE FILTER (classes 13/14, optional class 15)
  --vertex-where SPEC          Restrict hits to cases whose confirmed graph
                                contains a matching vertex. Repeatable (AND).
      Forms:
        endpoint                       — kind only (any endpoint vertex)
        endpoint:classification=high   — kind + attribute predicate
        endpoint:os=linux*             — fnmatch on the value
        endpoint:role=*                — '*' on a value = presence-only
        *:classification=high          — any kind, attribute matches
  --vertex-scope target|prologue|any   (default: any)
      target   — match the lead's target vertex only
      prologue — match only prologue vertices
      any      — match any confirmed vertex (prologue + observations)

ENUMERATION
  --enumerate leads|anchors|archetypes|hypotheses|dispositions
      List distinct values of a corpus dimension.
  --enum-tree
      Parent-child hierarchy of hypothesis IDs (inferred from h-001-002-003 ID structure).

PATTERNS
  Hypothesis names start with '?'. Patterns use fnmatch syntax.
  The leading '?' in the pattern matches the literal '?' that begins every hypothesis name.

    ?*scanner*        matches  ?opportunistic-scanner, ?network-scanner-bot, …
    ?*brute*          matches  ?targeted-brute-force, ?brute-force-external, …
    ?*monitoring*     matches  ?monitoring-probe, ?internal-monitoring-loop, …

  Flag assignment — the same pattern syntax, different flags per class:
    --pattern PATTERN                         class 6  (hypothesis wildcard)
    --hypothesis PATTERN [PATTERN …]          class 8  (filter lead effectiveness)
    --hyp-pattern PATTERN                     class 9  (filter weight-reversal rows)
    --discriminate-between PATTERN1 PATTERN2  class 8  (discrimination score between two groups)

  Run --enumerate hypotheses first to see the exact vocabulary in this corpus.

GLOBAL OPTIONS
  --top N   Return at most N results (applied after class-specific default sort).

CORPUS
  Default: walks $SOC_AGENT_RUNS_DIR for **/investigation.md and merges each
  file's ```invlang fences into one companion. Finished investigations only
  (prologue + findings + conclude required).
  Override: set INVLANG_CORPUS_ROOT env var to point at a different runs tree.

OUTPUT
  Default: human-readable.  --json: emit one JSON object per invocation.
""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    p.add_argument(
        "--ids", dest="ids_path", metavar="PATH",
        help=(
            "Print all IDs currently present in a single investigation.md file, "
            "grouped by type (vertices, edges, hypotheses, leads). "
            "Use before writing a new block to confirm the ID namespace."
        ),
    )
    p.add_argument(
        "--class", dest="query_class", type=int, choices=range(1, 16), metavar="N",
        help="Run a single query class (1–15) instead of the full demo.",
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
                    help="fnmatch pattern to filter hypothesis names (class 9). "
                         "Note: use --hypothesis (not --hyp-pattern) for class 8.")
    g6.add_argument(
        "--reversals-only", dest="reversals_only", action="store_true",
        help="(class 9) Show only true reversals: hypotheses that were positively weighted "
             "(+ or ++) before going negative. Excludes null→negative first-scores.",
    )

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

    g13 = p.add_argument_group("class 13 — lead exemplars (ANALYZE recall)")
    g13.add_argument(
        "--lead-pattern", dest="lead_pattern", metavar="PATTERN",
        help="fnmatch pattern on lead.name (class 13 required, e.g. '*ssh*').",
    )

    g14 = p.add_argument_group("class 14 — authorization calibration (ANALYZE recall)")
    g14.add_argument(
        "--contract-pattern", dest="contract_pattern", metavar="PATTERN",
        help="fnmatch pattern on the fulfilling hypothesis name OR substring on its "
             "authorization_contract.predicate (class 14 required).",
    )

    g15 = p.add_argument_group("class 15 — loop-N lead distribution")
    g15.add_argument(
        "--loop", dest="loop", type=int, metavar="N",
        help="Loop number to recall the primary lead choice from (class 15 required).",
    )
    g15.add_argument(
        "--max-age-days", dest="max_age_days", type=int, default=180, metavar="DAYS",
        help="Recency cutoff for class 15 (default 180).",
    )

    g_graph = p.add_argument_group("graph-context filter (classes 13/14, optional class 15)")
    g_graph.add_argument(
        "--vertex-where", dest="vertex_where", action="append", metavar="SPEC",
        default=[],
        help="KIND[:KEY=VAL[,KEY=VAL...]] — restrict hits to cases whose confirmed graph "
             "contains a vertex matching this predicate. Repeatable (AND).",
    )
    g_graph.add_argument(
        "--vertex-scope", dest="vertex_scope",
        choices=("target", "prologue", "any"), default="any",
        help="Where to look for the matching vertex (default: any).",
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
        if getattr(args, "hypothesis_patterns", None):
            print(
                "note: --hypothesis is the class 8 flag. "
                "Use --hyp-pattern to filter hypothesis names in class 9.",
                file=sys.stderr,
            )
        return weight_reversal_mining(
            corpus,
            hypothesis_pattern=getattr(args, "hyp_pattern", None),
            reversals_only=getattr(args, "reversals_only", False),
        )
    if n == 10:
        return lead_pair_synergy(corpus)
    if n == 11:
        return post_failure_recovery(corpus, system=args.system, failure_reason=args.failure_reason)
    if n == 12:
        return independent_datasource_metric(corpus, disposition=args.disposition)
    if n == 13:
        if not args.lead_pattern:
            print("error: --class 13 requires --lead-pattern", file=sys.stderr)
            sys.exit(1)
        return lead_exemplars(
            corpus,
            args.lead_pattern,
            vertex_where=_parse_vertex_where_args(args.vertex_where),
            vertex_scope=args.vertex_scope,
            limit=args.top,
        )
    if n == 14:
        if not args.contract_pattern:
            print("error: --class 14 requires --contract-pattern", file=sys.stderr)
            sys.exit(1)
        return authorization_calibration(
            corpus,
            args.contract_pattern,
            vertex_where=_parse_vertex_where_args(args.vertex_where),
            vertex_scope=args.vertex_scope,
        )
    if n == 15:
        if args.loop is None:
            print("error: --class 15 requires --loop N", file=sys.stderr)
            sys.exit(1)
        # Class 15 is a cache-key lookup keyed on the *current* alert's
        # signature + prologue. The CLI form runs against an empty signature
        # filter — useful for ad-hoc inspection of the corpus's per-loop lead
        # distribution. Call sites that have a real prologue should call
        # `loop_lead_distribution` directly.
        scoped = _apply_vertex_where_filter(corpus, args)
        return loop_lead_distribution(
            scoped,
            signature_id="",
            prologue={"vertices": [], "edges": []},
            discriminating_classifications={},
            loop=args.loop,
            max_age_days=args.max_age_days,
        )
    raise ValueError(f"unknown class {n}")


def _parse_vertex_where_args(specs: list[str] | None) -> list[tuple[str, dict[str, str]]] | None:
    if not specs:
        return None
    return [_parse_vertex_where_spec(s) for s in specs]


def _apply_vertex_where_filter(
    corpus: list[Companion],
    args: argparse.Namespace,
) -> list[Companion]:
    """Pre-filter a corpus list by --vertex-where (used by class 15 which doesn't
    take the filter as a function arg)."""
    parsed = _parse_vertex_where_args(getattr(args, "vertex_where", None))
    if not parsed:
        return corpus
    from .queries import _vertex_where_match  # local import to avoid cycle at top
    scope = getattr(args, "vertex_scope", "any")
    if scope == "target":
        # 'target' is per-lead; not meaningful for class 15 case-level scoping.
        scope = "any"
    return [c for c in corpus if _vertex_where_match(c, parsed, scope)]


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

def _run_ids(path_str: str) -> int:
    """Print all IDs from a single investigation.md, grouped by type."""
    path = Path(path_str)
    if not path.exists():
        print("(file not yet created — ID namespace is empty)", file=sys.stderr)
        for kind in ("vertices", "edges", "hypotheses", "leads"):
            print(f"{kind + ':':<12} (none)")
        return 0

    merged = _merge_md_blocks(path.read_text())
    ids = extract_ids(merged)
    for kind, id_list in ids.items():
        val = "  ".join(id_list) if id_list else "(none)"
        print(f"{kind + ':':<12} {val}")
    return 0


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    if args.ids_path is not None:
        return _run_ids(args.ids_path)

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
