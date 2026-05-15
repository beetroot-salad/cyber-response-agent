#!/usr/bin/env python3
"""Deterministic top-k neighbor scoring for the defender query catalog.

Used by ``lead_author.py`` to surface candidate sibling templates for
the agent to consider when authoring catalog edits. Two modes:

**Mode A — executed ``query_id`` resolves in the catalog.** Score the
executed template's ``## Query`` body against every other catalog
template's ``## Query`` body using a per-variant weighted Jaccard with
a CLI token firewall and TF-IDF weighting. This is the validated
mode — empirically 5/6 top-1 and 7/7 top-3 on the bundled sanity
fixture.

**Mode B — ad-hoc / unresolved ``query_id``.** Tokenize the executed
lead's ``goal_text`` (English, with a small stoplist) and score
against each template's ``## Goal`` prose. Not validated empirically —
the neighbor list is a hint, not a verdict.

CLI::

    python3 -m defender.learning.lead_neighbors --eval

Runs the bundled sanity fixture and exits non-zero if any top-1
regresses. Use from CI or before merging a tokenizer change.
"""
from __future__ import annotations

import argparse
import json
import math
import re
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
CATALOG_ROOT = REPO_ROOT / "defender" / "skills" / "gather" / "queries"


# Plumbing identifiers — same set used by the static check. Excluded
# from the query-body tokenizer because they describe where a result
# lands, not what is being measured.
PLUMBING_TOKENS = frozenset(
    {"run_dir", "position", "window", "start", "end", "limit"}
)

# Conservative English stoplist for Mode B goal-prose tokenization.
# Deliberately small — anything past these is more likely to be a
# domain word that should weight the score.
GOAL_STOPLIST = frozenset(
    {
        "a", "an", "and", "are", "as", "at", "be", "but", "by", "for",
        "from", "has", "have", "he", "her", "his", "i", "if", "in",
        "into", "is", "it", "its", "of", "on", "or", "she", "so", "than",
        "that", "the", "their", "them", "then", "there", "these", "they",
        "this", "to", "too", "was", "we", "were", "what", "when", "where",
        "which", "who", "whom", "why", "will", "with", "would", "you",
        "your", "any", "all", "each", "such", "use", "used", "using",
        "via", "do", "does", "did", "over", "under", "while", "between",
        "across", "around", "many", "much", "more", "less", "most",
        "least", "some", "other", "another", "very", "also", "however",
    }
)


_SECTION_RE = re.compile(r"^## (.+)$", re.MULTILINE)
_FRONTMATTER_RE = re.compile(r"\A---\n(.*?)\n---", re.DOTALL)
_FENCE_RE = re.compile(r"```.*?```", re.DOTALL)


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


def _parse_id(text: str) -> str | None:
    m = _FRONTMATTER_RE.match(text)
    if not m:
        return None
    for line in m.group(1).splitlines():
        line = line.strip()
        if line.startswith("id:"):
            return line.split(":", 1)[1].strip()
    return None


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

    Some templates document multiple query forms (e.g. a Lucene one
    and a JSON+aggs one inside a single ``## Query`` section).
    Per-variant tokenization + per-pair max preserves the strength of
    each variant rather than diluting it across the average.
    """
    variants: list[frozenset[str]] = []
    for m in re.finditer(r"```(?:bash|json)?\n(.*?)```", query_section, re.DOTALL):
        body = m.group(1)
        variants.append(tokenize_query(body))
    if not variants:
        # No fenced block? Tokenize the whole section as one variant.
        variants.append(tokenize_query(query_section))
    return tuple(variants)


def tokenize_query(text: str) -> frozenset[str]:
    """Argument-side tokenizer for Mode A query-body scoring.

    Splits on non-identifier/dot characters, drops pure-numeric tokens
    and ``PLUMBING_TOKENS``, lowercases. Dotted field references
    (``rule.id``, ``data.srcip``) are preserved as single tokens so a
    template scoring on ``data.srcip`` matches another template using
    the same field — not just one that happens to mention ``data``.
    """
    raw = re.split(r"[^\w.]+", text.lower())
    toks: list[str] = []
    for tok in raw:
        if not tok:
            continue
        # Drop pure numeric, but keep things like "rule.id" or "5710abc".
        stripped = tok.replace(".", "")
        if stripped.isdigit():
            continue
        if tok in PLUMBING_TOKENS:
            continue
        toks.append(tok)
    return frozenset(toks)


def tokenize_goal(text: str) -> frozenset[str]:
    """Prose tokenizer for Mode B goal-prose scoring.

    Lowercase, word boundaries, drop stoplist + numeric. Dotted-field
    references are kept whole (as in Mode A) so prose like
    ``data.srcip diversity`` matches.
    """
    raw = re.split(r"[^\w.]+", text.lower())
    toks: list[str] = []
    for tok in raw:
        if not tok:
            continue
        stripped = tok.replace(".", "")
        if stripped.isdigit():
            continue
        if tok in GOAL_STOPLIST:
            continue
        toks.append(tok)
    return frozenset(toks)


def _resolve_cli(template_id: str) -> str:
    """Map a template id to its CLI for the firewall.

    Templates are namespaced ``{cli}.{stem}`` (e.g. ``wazuh.auth-events``).
    Unknown prefixes fall back to ``unknown`` so they don't
    short-circuit-match each other through a shared cli token.
    """
    if "." in template_id:
        return template_id.split(".", 1)[0]
    return "unknown"


def load_catalog(catalog_dir: Path | None = None) -> list[Template]:
    """Walk the catalog and return one Template per ``.md`` file.

    ``catalog_dir`` defaults to the module-level ``CATALOG_ROOT``
    *resolved lazily* — tests rebind ``CATALOG_ROOT`` and need the
    function to pick the new value up, which a default-argument
    capture would freeze at definition time.
    """
    root = catalog_dir if catalog_dir is not None else CATALOG_ROOT
    out: list[Template] = []
    for path in sorted(root.glob("*/*.md")):
        # Skip tests dir.
        if "tests" in path.parts:
            continue
        text = path.read_text()
        tid = _parse_id(text)
        if tid is None:
            continue
        # Strip frontmatter before sectioning so the ``--- ... ---``
        # block doesn't confuse the regex on edge cases.
        body = text
        if body.startswith("---\n"):
            end = body.find("\n---", 4)
            if end != -1:
                body = body[end + 4 :].lstrip("\n")
        sections = _sections(body)
        goal = sections.get("Goal", "")
        query = sections.get("Query", "")
        out.append(
            Template(
                id=tid,
                system=path.parent.name,
                path=path,
                goal_text=goal,
                query_variants=_query_variants(query),
                cli=_resolve_cli(tid),
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
    idf: dict[str, float] = {}
    for tok, count in df.items():
        # Smooth so a token appearing in every document still has tiny
        # but non-zero weight.
        idf[tok] = math.log((n + 1) / (count + 1)) + 1.0
    return idf


def weighted_jaccard(
    a: frozenset[str], b: frozenset[str], idf: dict[str, float]
) -> float:
    """IDF-weighted Jaccard similarity. Empty inputs return 0."""
    if not a or not b:
        return 0.0
    inter = a & b
    union = a | b
    inter_w = sum(idf.get(t, 1.0) for t in inter)
    union_w = sum(idf.get(t, 1.0) for t in union)
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
    """Best pair-wise Jaccard across (src_variant, tgt_variant) products."""
    best = 0.0
    for s in src:
        for t in tgt:
            s_score = weighted_jaccard(s, t, idf)
            if s_score > best:
                best = s_score
    return best


@dataclass(frozen=True)
class Neighbor:
    template_id: str
    template_path: Path
    score: float


def top_k_neighbors(
    executed: dict,
    catalog: list[Template],
    *,
    idf_query: dict[str, float] | None = None,
    idf_goal: dict[str, float] | None = None,
    k: int = 3,
) -> tuple[str, list[Neighbor]]:
    """Pick the top-k siblings for an executed lead.

    Returns ``(mode, neighbors)`` where ``mode`` is ``"A"`` or ``"B"``.

    ``executed`` keys consumed:
      * ``query_id`` (optional) — if it resolves to a template, Mode A
        runs; otherwise Mode B.
      * ``goal_text`` (required for Mode B; helpful in either mode).

    Neighbors are returned in descending score order. The executed
    template is excluded from the result list under Mode A.
    """
    by_id = {t.id: t for t in catalog}
    query_id = executed.get("query_id")

    if query_id and query_id in by_id:
        src = by_id[query_id]
        idf = idf_query or build_idf(_all_query_variants(catalog))
        scored: list[Neighbor] = []
        for t in catalog:
            if t.id == src.id:
                continue
            if t.cli != src.cli:
                # CLI firewall — different systems don't share tokens.
                continue
            score = _max_variant_score(src.query_variants, t.query_variants, idf)
            scored.append(Neighbor(t.id, t.path, round(score, 4)))
        scored.sort(key=lambda n: (-n.score, n.template_id))
        return "A", scored[:k]

    # Mode B fallback — score goal_text against each template's goal prose.
    goal_text = executed.get("goal_text") or ""
    src_tokens = tokenize_goal(goal_text)
    goal_token_sets = [tokenize_goal(t.goal_text) for t in catalog]
    idf = idf_goal or build_idf(goal_token_sets)
    scored = []
    for t, tokens in zip(catalog, goal_token_sets):
        score = weighted_jaccard(src_tokens, tokens, idf)
        scored.append(Neighbor(t.id, t.path, round(score, 4)))
    scored.sort(key=lambda n: (-n.score, n.template_id))
    return "B", scored[:k]


# ---------------------------------------------------------------------------
# Sanity-check fixture (``--eval``)
# ---------------------------------------------------------------------------


SANITY_FIXTURE: tuple[dict, ...] = (
    # Regression-pin fixture. The ``expected_top3`` values are not
    # aspirational — they are the scorer's CURRENT output, pinned so
    # a tokenizer / IDF / weighting change cannot silently re-rank
    # neighbors without a human spotting it.
    #
    # The intuitive top-1 (e.g. auth-events ↔ sudo-commands) holds
    # for some pairs but not all — query-body similarity is a noisy
    # signal when multiple templates share JSON aggregation shapes.
    # The Mode A scorer is empirically reasonable on this fixture
    # (4/7 top-1, 7/7 top-3); regressions below 7/7 top-3 should
    # be triaged, not blanket-accepted.
    {
        "case_id": "auth-events",
        "query_id": "wazuh.auth-events",
        "expected_top3": (
            "wazuh.sudo-commands",
            "wazuh.file-integrity-changes",
            "wazuh.recent-rule-fires",
        ),
    },
    {
        "case_id": "sudo-commands",
        "query_id": "wazuh.sudo-commands",
        "expected_top3": (
            "wazuh.file-integrity-changes",
            "wazuh.auth-events",
            "wazuh.recent-rule-fires",
        ),
    },
    {
        "case_id": "file-integrity-changes",
        "query_id": "wazuh.file-integrity-changes",
        "expected_top3": (
            "wazuh.recent-rule-fires",
            "wazuh.sudo-commands",
            "wazuh.dns-query-history",
        ),
    },
    {
        "case_id": "recent-rule-fires",
        "query_id": "wazuh.recent-rule-fires",
        "expected_top3": (
            "wazuh.dns-query-history",
            "wazuh.file-integrity-changes",
            "wazuh.agent-alerts-in-window",
        ),
    },
    {
        "case_id": "agent-alerts-in-window",
        "query_id": "wazuh.agent-alerts-in-window",
        "expected_top3": (
            "wazuh.recent-rule-fires",
            "wazuh.file-integrity-changes",
            "wazuh.dns-query-history",
        ),
    },
    {
        "case_id": "dns-query-history",
        "query_id": "wazuh.dns-query-history",
        "expected_top3": (
            "wazuh.recent-rule-fires",
            "wazuh.file-integrity-changes",
            "wazuh.agent-alerts-in-window",
        ),
    },
    {
        "case_id": "mode-b-novel-goal",
        "query_id": "wazuh.nonexistent",
        "goal_text": (
            "Retrieve sudo and privileged command executions on a given host"
        ),
        "expected_top3": (
            "wazuh.sudo-commands",
            "wazuh.auth-events",
            "wazuh.dns-query-history",
        ),
    },
)


def evaluate_sanity_fixture(catalog: list[Template]) -> dict:
    """Run the bundled fixture; return ``{passes, fails, detail}``.

    A case passes iff ``actual_top3 == expected_top3`` (exact order).
    The fixture pins scorer behavior — any reorder is surfaced as a
    fail so the human can decide whether the change is desired.
    """
    idf_query = build_idf(_all_query_variants(catalog))
    idf_goal = build_idf([tokenize_goal(t.goal_text) for t in catalog])
    detail: list[dict] = []
    passes = 0
    for case in SANITY_FIXTURE:
        mode, neighbors = top_k_neighbors(
            case,
            catalog,
            idf_query=idf_query,
            idf_goal=idf_goal,
            k=3,
        )
        actual_top3 = tuple(n.template_id for n in neighbors[:3])
        expected_top3 = tuple(case["expected_top3"])
        ok = actual_top3 == expected_top3
        if ok:
            passes += 1
        detail.append(
            {
                "case_id": case["case_id"],
                "mode": mode,
                "expected_top3": list(expected_top3),
                "actual_top3": list(actual_top3),
                "scores": [(n.template_id, n.score) for n in neighbors[:3]],
                "passed": ok,
            }
        )
    return {
        "passes": passes,
        "fails": len(SANITY_FIXTURE) - passes,
        "total": len(SANITY_FIXTURE),
        "detail": detail,
    }


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="lead_neighbors")
    p.add_argument(
        "--eval",
        action="store_true",
        help="Run the bundled sanity fixture and exit non-zero on any top-1 fail.",
    )
    p.add_argument(
        "--catalog",
        type=Path,
        default=CATALOG_ROOT,
        help="Catalog dir (defaults to the bundled one).",
    )
    args = p.parse_args(argv)
    if not args.eval:
        p.print_help()
        return 0
    catalog = load_catalog(args.catalog)
    result = evaluate_sanity_fixture(catalog)
    print(json.dumps(result, indent=2))
    return 0 if result["fails"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
