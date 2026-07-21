#!/usr/bin/env python3
from __future__ import annotations

import argparse
import math
import re
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

if (_root := str(Path(__file__).resolve().parents[3])) not in sys.path:
    sys.path.insert(0, _root)

from defender._corpus import iter_query_templates
from defender._paths import PATHS


PLUMBING_TOKENS = frozenset({"run_dir", "position", "window"})




@dataclass(frozen=True)
class Template:
    id: str
    system: str
    path: Path
    goal: str
    query_variants: tuple[frozenset[str], ...]
    cli: str
    status: str


def _query_variants(query_section: str) -> tuple[frozenset[str], ...]:
    variants: list[frozenset[str]] = []
    for m in re.finditer(r"```[\w.+-]*\n(.*?)```", query_section, re.DOTALL):
        body = m.group(1)
        variants.append(tokenize_query(body))
    if not variants:
        variants.append(tokenize_query(query_section))
    return tuple(variants)


def tokenize_query(text: str) -> frozenset[str]:
    raw = re.split(r"[^\w.\-*]+", text.lower())
    toks: list[str] = []
    for tok in raw:
        tok = tok.strip(".-*")
        if not tok:
            continue
        stripped = tok.replace(".", "").replace("-", "")
        if stripped.isdigit():
            continue
        if tok in PLUMBING_TOKENS:
            continue
        toks.append(tok)
    return frozenset(toks)


def _resolve_cli(template_id: str) -> str:
    if "." in template_id:
        return template_id.split(".", 1)[0]
    return "unknown"


def load_catalog(catalog_dir: Path | None = None) -> list[Template]:
    root = catalog_dir if catalog_dir is not None else PATHS.catalog_dir
    return [
        Template(
            id=t.id,
            system=t.system,
            path=t.path,
            goal=t.goal,
            query_variants=_query_variants(t.query),
            cli=_resolve_cli(t.id),
            status=t.status,
        )
        for t in iter_query_templates(root)
    ]




def build_idf(token_sets: list[frozenset[str]]) -> dict[str, float]:
    n = len(token_sets)
    df: Counter[str] = Counter()
    for ts in token_sets:
        for tok in ts:
            df[tok] += 1
    return {tok: math.log((n + 1) / (count + 1)) + 1.0 for tok, count in df.items()}


def weighted_jaccard(
    a: frozenset[str], b: frozenset[str], idf: dict[str, float]
) -> float:
    if not a or not b:
        return 0.0
    inter_w = sum(idf.get(t, 1.0) for t in a & b)
    union_w = sum(idf.get(t, 1.0) for t in a | b)
    return inter_w / union_w if union_w else 0.0


def _all_query_variants(catalog: list[Template]) -> list[frozenset[str]]:
    out: list[frozenset[str]] = []
    for t in catalog:
        out.extend(t.query_variants)
    return out


def _max_variant_score(
    src: tuple[frozenset[str], ...],
    tgt: tuple[frozenset[str], ...],
    idf: dict[str, float],
) -> float:
    best = 0.0
    for s in src:
        for t in tgt:
            score = weighted_jaccard(s, t, idf)
            if score > best:
                best = score
    return best


@dataclass(frozen=True)
class Neighbor:
    template_id: str
    template_path: Path
    score: float


def top_k_neighbors(
    query_id: str,
    catalog: list[Template],
    *,
    idf: dict[str, float] | None = None,
    k: int = 3,
) -> list[Neighbor]:
    by_id = {t.id: t for t in catalog}
    src = by_id[query_id]
    weights = idf or build_idf(_all_query_variants(catalog))
    scored: list[Neighbor] = []
    for t in catalog:
        if t.id == src.id:
            continue
        if t.cli != src.cli:
            continue
        score = _max_variant_score(src.query_variants, t.query_variants, weights)
        scored.append(Neighbor(t.id, t.path, round(score, 4)))
    scored.sort(key=lambda n: (-n.score, n.template_id))
    return scored[:k]




_HELP_DESCRIPTION = """\
Score the defender query-template catalog and surface the top-k
siblings for a given executed lead.

The lead-author driver uses this internally to build per-lead handoff
blocks. As a standalone CLI it's useful for inspecting why one
template ranked over another or sanity-checking a catalog edit before
shipping.
"""


_HELP_EPILOG = """\
Examples
  # Top-3 siblings for a known template
  python -m defender.learning.leads.lead_neighbors score \\
      --query-id {system}.auth-events

  # List every template's id, system, cli, and goal-first-line
  python -m defender.learning.leads.lead_neighbors dump

Common mistakes
  * --query-id must resolve in the catalog. If it doesn't, you'll get
    a KeyError — run `dump` to see what ids the catalog actually
    exposes.
  * The CLI firewall blocks cross-system neighbors. If you expected a
    cross-system match, the answer is "no neighbor", not "bug".
  * Tokens are lowercased and dotted-field-preserving (`rule.id` stays
    one token). If you grep results and your case doesn't match, you
    are not seeing the truth.
"""


def _cmd_score(args: argparse.Namespace) -> int:
    catalog = load_catalog(args.catalog)
    if not catalog:
        print(f"no templates found under {args.catalog}", file=sys.stderr)
        return 2
    by_id = {t.id: t for t in catalog}
    if args.query_id not in by_id:
        print(f"score: query_id {args.query_id!r} does not resolve in catalog "
              f"(run `dump` to see available ids)", file=sys.stderr)
        return 2
    neighbors = top_k_neighbors(args.query_id, catalog, k=args.k)
    if not neighbors:
        print("no neighbors (catalog filtered to empty after CLI firewall)")
        return 0
    width = max(len(n.template_id) for n in neighbors)
    for n in neighbors:
        print(f"  {n.template_id:<{width}}  score={n.score:.4f}  {n.template_path}")
    return 0


def _cmd_dump(args: argparse.Namespace) -> int:
    catalog = load_catalog(args.catalog)
    if not catalog:
        print(f"no templates found under {args.catalog}", file=sys.stderr)
        return 2
    width_id = max(len(t.id) for t in catalog)
    width_sys = max(len(t.system) for t in catalog)
    for t in catalog:
        first_line = (t.goal.splitlines() or [""])[0].strip()
        if len(first_line) > 80:
            first_line = first_line[:77] + "..."
        print(
            f"  {t.id:<{width_id}}  system={t.system:<{width_sys}}  "
            f"cli={t.cli:<8}  status={t.status:<11}  {first_line}"
        )
    return 0


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(
        prog="lead_neighbors",
        description=_HELP_DESCRIPTION,
        epilog=_HELP_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--catalog",
        type=Path,
        default=PATHS.catalog_dir,
        help=f"Catalog dir (defaults to {PATHS.catalog_dir}).",
    )
    sub = p.add_subparsers(dest="command", required=True, metavar="COMMAND")

    p_score = sub.add_parser(
        "score",
        help="print top-k neighbors for one lead",
        description="Score one executed lead against the catalog.",
    )
    p_score.add_argument("--query-id", required=True,
                         help="executed template id, e.g. {system}.auth-events")
    p_score.add_argument("-k", "--k", type=int, default=3,
                         help="number of neighbors to return (default 3)")
    p_score.set_defaults(func=_cmd_score)

    p_dump = sub.add_parser(
        "dump",
        help="list every template's id, system, cli, goal-first-line",
        description="Walk the catalog and print one line per template. "
                    "Use this when a score command errors with an unknown "
                    "query-id — it shows what ids actually exist.",
    )
    p_dump.set_defaults(func=_cmd_dump)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
