#!/usr/bin/env python3
"""Deterministic top-k neighbor scoring for the defender query catalog.

Used by ``lead_author.py`` to surface candidate sibling templates for
the lead-author agent to consider when deciding fold / split / skip.

Scores the executed template's ``## Query`` body against every other
catalog template's ``## Query`` body using a per-variant weighted
Jaccard with a CLI token firewall and TF-IDF weighting.

Leads whose ``query_id`` doesn't resolve in the catalog are a runtime
contract violation (per ``defender/CLAUDE.md``: "every id resolves").
The driver logs and drops them; this module does not handle them.

The regression-pin sanity fixture from the original PR lives in
``defender/tests/test_lead_neighbors.py`` rather than here, so the
production module stays free of fixture data.
"""
from __future__ import annotations

import argparse
import math
import re
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
CATALOG_ROOT = REPO_ROOT / "defender" / "skills" / "gather" / "queries"


PLUMBING_TOKENS = frozenset(
    {"run_dir", "position", "window", "start", "end", "limit"}
)


_SECTION_RE = re.compile(r"^## (.+)$", re.MULTILINE)
_FRONTMATTER_RE = re.compile(r"\A---\n(.*?)\n---", re.DOTALL)


# ---------------------------------------------------------------------------
# Catalog loading
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Template:
    id: str
    system: str
    path: Path
    goal_text: str
    query_variants: tuple[frozenset[str], ...]
    cli: str
    status: str  # "established" | "draft"


def _parse_frontmatter(text: str) -> dict[str, str]:
    m = _FRONTMATTER_RE.match(text)
    if not m:
        return {}
    out: dict[str, str] = {}
    for line in m.group(1).splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        key, _, value = line.partition(":")
        out[key.strip()] = value.strip()
    return out


def _sections(body: str) -> dict[str, str]:
    out: dict[str, str] = {}
    matches = list(_SECTION_RE.finditer(body))
    for i, m in enumerate(matches):
        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(body)
        out[m.group(1).strip()] = body[start:end].strip()
    return out


def _query_variants(query_section: str) -> tuple[frozenset[str], ...]:
    """Split the ## Query section into per-fence variants, tokenize each.

    Some templates document multiple query forms (e.g. a Lucene one and
    a JSON+aggs one) inside a single ``## Query`` section. Per-variant
    tokenization + per-pair max preserves the strength of each variant
    rather than diluting it across the average.

    The fence label is matched generically (``esql``, ``sql``, ``bash``,
    ``json``, or none): the ES|QL migration tags query bodies ```` ```esql ````,
    and a label-specific allowlist would silently fall through to tokenizing
    the *whole section* — prose, narrowing examples, and all — diluting the
    similarity signal the curator relies on to spot near-duplicates.
    """
    variants: list[frozenset[str]] = []
    for m in re.finditer(r"```[\w.+-]*\n(.*?)```", query_section, re.DOTALL):
        body = m.group(1)
        variants.append(tokenize_query(body))
    if not variants:
        variants.append(tokenize_query(query_section))
    return tuple(variants)


def tokenize_query(text: str) -> frozenset[str]:
    """Argument-side tokenizer for query-body scoring.

    Splits on punctuation, drops pure-numeric tokens and
    ``PLUMBING_TOKENS``, lowercases. Two identifier shapes are preserved
    as single tokens rather than shattered, because each is a strong
    "same data" signal the scorer would otherwise lose:

    - **Dotted field references** (``rule.id``, ``source.ip``) — so a
      template scoring on ``source.ip`` matches another using the same
      field, not just one that happens to mention ``source``.
    - **Hyphenated index / data-stream names** (``logs-system.auth-*``,
      ``logs-zeek.conn``) — for ES|QL the data stream a query hits is the
      single strongest discriminator between measurements; splitting on
      ``-`` would collapse every ``logs-*`` query onto the common ``logs``
      token. Trailing glob/hyphen punctuation is normalized off so
      ``logs-system.auth-*`` and ``logs-system.auth`` are one token.
    """
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
    """Map a template id to its CLI prefix for the firewall."""
    if "." in template_id:
        return template_id.split(".", 1)[0]
    return "unknown"


def load_catalog(catalog_dir: Path | None = None) -> list[Template]:
    """Walk the catalog and return one Template per ``.md`` file.

    Walks both established templates at ``{system}/*.md`` and drafts at
    ``{system}/_draft/*.md``. The ``status`` frontmatter field
    distinguishes them; for compatibility with pre-refinement templates
    the field defaults to ``"established"`` when absent.

    ``catalog_dir`` defaults to module-level ``CATALOG_ROOT`` resolved
    lazily so tests can rebind it.
    """
    root = catalog_dir if catalog_dir is not None else CATALOG_ROOT
    out: list[Template] = []
    paths = sorted(list(root.glob("*/*.md")) + list(root.glob("*/_draft/*.md")))
    for path in paths:
        if "tests" in path.parts:
            continue
        text = path.read_text()
        fm = _parse_frontmatter(text)
        tid = fm.get("id")
        if not tid:
            continue
        status = fm.get("status") or "established"
        body = text
        if body.startswith("---\n"):
            end = body.find("\n---", 4)
            if end != -1:
                body = body[end + 4:].lstrip("\n")
        sections = _sections(body)
        goal = sections.get("Goal", "")
        query = sections.get("Query", "")
        # The system dir is the parent's parent for _draft/ files,
        # otherwise the immediate parent.
        system = path.parent.parent.name if path.parent.name == "_draft" else path.parent.name
        out.append(
            Template(
                id=tid,
                system=system,
                path=path,
                goal_text=goal,
                query_variants=_query_variants(query),
                cli=_resolve_cli(tid),
                status=status,
            )
        )
    return out


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------


def build_idf(token_sets: list[frozenset[str]]) -> dict[str, float]:
    """Smoothed inverse document frequency over a token-set corpus."""
    n = len(token_sets)
    df: Counter[str] = Counter()
    for ts in token_sets:
        for tok in ts:
            df[tok] += 1
    return {tok: math.log((n + 1) / (count + 1)) + 1.0 for tok, count in df.items()}


def weighted_jaccard(
    a: frozenset[str], b: frozenset[str], idf: dict[str, float]
) -> float:
    """IDF-weighted Jaccard similarity. Empty inputs return 0."""
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
    """Pick the top-k siblings for an executed lead.

    ``query_id`` must resolve in the catalog. Caller is responsible for
    filtering unresolvable ids before calling — typically by dropping
    them from the handoff list and logging a corpus-health warning.

    Returns neighbors in descending score order. The executed template
    itself is excluded. Cross-CLI siblings (wazuh ↔ host-query) are
    excluded by the firewall.
    """
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


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


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
  python -m defender.learning.lead_neighbors score \\
      --query-id wazuh.auth-events

  # List every template's id, system, cli, and goal-first-line
  python -m defender.learning.lead_neighbors dump

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
        first_line = (t.goal_text.splitlines() or [""])[0].strip()
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
        default=CATALOG_ROOT,
        help=f"Catalog dir (defaults to {CATALOG_ROOT}).",
    )
    sub = p.add_subparsers(dest="command", required=True, metavar="COMMAND")

    p_score = sub.add_parser(
        "score",
        help="print top-k neighbors for one lead",
        description="Score one executed lead against the catalog.",
    )
    p_score.add_argument("--query-id", required=True,
                         help="executed template id, e.g. wazuh.auth-events")
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
