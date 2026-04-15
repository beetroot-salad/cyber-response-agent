"""Query primitive for investigation-language v2.5 companions.

Loads companion YAML files and answers the eight retrieval-query classes
from query-script-design.md against the corpus in-memory. Raw YAML is the
source of truth; no indexes, no database, no projection layer. Polars is
used on-demand for aggregation projections (classes 2, 5, and 8).

Run `uv run python scripts/query.py` for the demo.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

import polars as pl
import yaml


PILOT_ROOT = Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------------------
# Corpus loader
# ---------------------------------------------------------------------------

COMPANION_TOP_LEVEL = {"prologue", "hypothesize", "gather", "conclude"}

YAML_BLOCK_RE = re.compile(r"```yaml\n(.*?)\n```", re.DOTALL)

# Pilot corpus allowlist — which files contribute real investigation
# translations to the query corpus. Older spec versions, haiku test responses,
# spec worked examples, and retrieval sims are excluded even though they parse
# as companions. Updated deliberately when a new translation lands.
PILOT_CORPUS_FILES = (
    "case-a1/walk-a1-v2.5.yaml",
    "case-a4/walk-a4-v2.5.yaml",
    "case-m365/walk-m365-v2.5.yaml",
    "case-real-rule5710/companion-v2.5.yaml",
)


def _conclude_field(conclude: dict[str, Any], *path: str) -> Any:
    """Defensive nested access — returns None if any hop isn't a dict."""
    cur: Any = conclude
    for key in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur


@dataclass
class Companion:
    """A loaded v2.3 companion with its source path and parsed body."""

    case_id: str
    source_path: Path
    body: dict[str, Any]

    # convenience accessors — zero validation, callers handle KeyError
    @property
    def prologue(self) -> dict[str, Any]:
        return self.body.get("prologue", {})

    @property
    def hypotheses(self) -> list[dict[str, Any]]:
        return self.body.get("hypothesize", {}).get("hypotheses", [])

    @property
    def leads(self) -> list[dict[str, Any]]:
        return [entry["lead"] for entry in self.body.get("gather", []) if "lead" in entry]

    @property
    def conclude(self) -> dict[str, Any]:
        return self.body.get("conclude", {})

    def iter_new_hypotheses(self) -> Iterator[dict[str, Any]]:
        """Yields hypotheses declared at HYPOTHESIZE time + any new_hypotheses in leads."""
        yield from self.hypotheses
        for lead in self.leads:
            for h in lead.get("new_hypotheses", []) or []:
                yield h


def _looks_like_companion(doc: Any) -> bool:
    return isinstance(doc, dict) and COMPANION_TOP_LEVEL.issubset(doc.keys())


def _case_id_from_path(path: Path) -> str:
    return path.parent.name if path.parent.name not in {"", "."} else path.stem


def _load_from_path(path: Path) -> list[Companion]:
    """Parse a file and return every companion it contains (0+)."""
    results: list[Companion] = []
    if path.suffix == ".yaml":
        try:
            doc = yaml.safe_load(path.read_text())
        except yaml.YAMLError:
            return results
        if _looks_like_companion(doc):
            results.append(Companion(_case_id_from_path(path), path, doc))
    elif path.suffix == ".md":
        text = path.read_text()
        for match in YAML_BLOCK_RE.finditer(text):
            try:
                doc = yaml.safe_load(match.group(1))
            except yaml.YAMLError:
                continue
            if _looks_like_companion(doc):
                results.append(Companion(_case_id_from_path(path), path, doc))
    return results


def load_corpus(root: Path = PILOT_ROOT, paths: tuple[str, ...] = PILOT_CORPUS_FILES) -> list[Companion]:
    """Load the pilot corpus — the allowlisted files only.

    To operate on an ad-hoc set, pass `paths` explicitly (relative to `root`).
    """
    companions: list[Companion] = []
    for rel in paths:
        abs_path = root / rel
        if not abs_path.exists():
            print(f"warning: {rel} not found, skipping", file=sys.stderr)
            continue
        companions.extend(_load_from_path(abs_path))
    return companions


# ---------------------------------------------------------------------------
# Class 1 — coarse case lookup
# ---------------------------------------------------------------------------

def coarse_case_lookup(
    corpus: list[Companion],
    *,
    disposition: str | None = None,
    termination_category: str | None = None,
    confidence: str | None = None,
    matched_archetype: str | None = None,
    ceiling_test_kind: str | None = None,
) -> dict[str, Any]:
    """Filter on conclude-block structured fields."""
    hits = []
    for c in corpus:
        conclude = c.conclude
        if disposition is not None and conclude.get("disposition") != disposition:
            continue
        if (
            termination_category is not None
            and _conclude_field(conclude, "termination", "category") != termination_category
        ):
            continue
        if confidence is not None and conclude.get("confidence") != confidence:
            continue
        if matched_archetype is not None and conclude.get("matched_archetype") != matched_archetype:
            continue
        if (
            ceiling_test_kind is not None
            and (conclude.get("ceiling_test") or {}).get("kind") != ceiling_test_kind
        ):
            continue
        hits.append(
            {
                "case_id": c.case_id,
                "disposition": conclude.get("disposition"),
                "termination_category": conclude.get("termination", {}).get("category"),
                "confidence": conclude.get("confidence"),
                "matched_archetype": conclude.get("matched_archetype"),
                "ceiling_test": conclude.get("ceiling_test"),
                "summary_head": (conclude.get("summary") or "").strip().split("\n", 1)[0][:120],
            }
        )
    return {"hits": hits, "count": len(hits)}


# ---------------------------------------------------------------------------
# Class 2 — anchor calibration
# ---------------------------------------------------------------------------

def _anchor_rows(corpus: list[Companion]) -> list[dict[str, Any]]:
    rows = []
    for c in corpus:
        for lead in c.leads:
            tar = (lead.get("outcome") or {}).get("trust_anchor_result")
            if not tar:
                continue
            rows.append(
                {
                    "case_id": c.case_id,
                    "lead_id": lead.get("id"),
                    "lead_name": lead.get("name"),
                    "loop": lead.get("loop"),
                    "anchor_id": tar.get("anchor_id"),
                    "kind": tar.get("kind"),
                    "result": tar.get("result"),
                    "authority_for_question": tar.get("authority_for_question"),
                    "as_of": tar.get("as_of"),
                    "disposition": c.conclude.get("disposition"),
                    "termination_category": _conclude_field(c.conclude, "termination", "category"),
                }
            )
    return rows


def anchor_calibration(
    corpus: list[Companion],
    *,
    anchor_id: str | None = None,
    result: str | None = None,
    authority_for_question: str | None = None,
) -> dict[str, Any]:
    """Distribution of (result × authority) → disposition for a given anchor."""
    rows = _anchor_rows(corpus)
    if not rows:
        return {"hits": [], "distribution": [], "count": 0}
    df = pl.DataFrame(rows)
    if anchor_id is not None:
        df = df.filter(pl.col("anchor_id") == anchor_id)
    if result is not None:
        df = df.filter(pl.col("result") == result)
    if authority_for_question is not None:
        df = df.filter(pl.col("authority_for_question") == authority_for_question)
    dist = (
        df.group_by(["anchor_id", "result", "authority_for_question", "disposition"])
        .len(name="count")
        .sort(["anchor_id", "result", "authority_for_question", "disposition"])
    )
    return {
        "hits": df.to_dicts(),
        "distribution": dist.to_dicts(),
        "count": df.height,
    }


# ---------------------------------------------------------------------------
# Class 3 — refinement chain shapes
# ---------------------------------------------------------------------------

def _parse_hypothesis_chain(h_id: str) -> list[str]:
    """h-001-002-003 → ['h-001', 'h-001-002', 'h-001-002-003']."""
    parts = h_id.split("-")
    if not parts or parts[0] != "h":
        return [h_id]
    ancestors = []
    for i in range(2, len(parts) + 1):
        ancestors.append("-".join(parts[:i]))
    return ancestors


def refinement_chain_shapes(corpus: list[Companion]) -> dict[str, Any]:
    """For each case, report the refinement tree shape (depth and branching)."""
    hits = []
    for c in corpus:
        ids = [h["id"] for h in c.iter_new_hypotheses()]
        # group by top-level root
        roots: dict[str, list[str]] = {}
        for h_id in ids:
            chain = _parse_hypothesis_chain(h_id)
            root = chain[0]
            roots.setdefault(root, []).append(h_id)
        for root, descendants in roots.items():
            max_depth = max(len(_parse_hypothesis_chain(d)) for d in descendants)
            hits.append(
                {
                    "case_id": c.case_id,
                    "root": root,
                    "descendant_count": len(descendants),
                    "max_depth": max_depth,
                    "descendants": sorted(descendants),
                }
            )
    return {"hits": hits, "count": len(hits)}


# ---------------------------------------------------------------------------
# Class 4 — dead-lead lookup
# ---------------------------------------------------------------------------

def dead_lead_lookup(
    corpus: list[Companion],
    *,
    system: str | None = None,
    failure_reason: str | None = None,
) -> dict[str, Any]:
    """Leads that errored or returned degraded data, with system/reason filters."""
    hits = []
    for c in corpus:
        for lead in c.leads:
            outcome = lead.get("outcome") or {}
            fr = outcome.get("failure_reason")
            if not fr:
                continue
            lead_system = (lead.get("query_details") or {}).get("system")
            if system is not None and lead_system != system:
                continue
            if failure_reason is not None and fr != failure_reason:
                continue
            hits.append(
                {
                    "case_id": c.case_id,
                    "lead_id": lead.get("id"),
                    "lead_name": lead.get("name"),
                    "loop": lead.get("loop"),
                    "system": lead_system,
                    "failure_reason": fr,
                    "concerns": lead.get("concerns", []),
                    "target": lead.get("target"),
                }
            )
    return {"hits": hits, "count": len(hits)}


# ---------------------------------------------------------------------------
# Class 5 — lead sequence pattern
# ---------------------------------------------------------------------------

def _infer_lead_type(lead: dict[str, Any]) -> str:
    """Infer lead type from outcome content (v2.5 — no mode field).

    trust:   trust_anchor_result present
    refine:  attribute_updates only (no observations vertices/edges)
    scope:   observations with vertices or edges, or empty outcome
    fail:    failure_reason present
    """
    outcome = lead.get("outcome") or {}
    if outcome.get("failure_reason"):
        return "fail"
    if outcome.get("trust_anchor_result"):
        return "trust"
    obs = outcome.get("observations") or {}
    if outcome.get("attribute_updates"):
        # attribute_updates present — refining lead regardless of empty observations
        if not (obs.get("vertices") or obs.get("edges")):
            return "refine"
    return "scope"


def _lead_sequence(c: Companion) -> str:
    parts = []
    for lead in c.leads:
        name = lead.get("name", "?")
        outcome = lead.get("outcome") or {}
        tar = outcome.get("trust_anchor_result") or {}
        fr = outcome.get("failure_reason")
        lead_type = _infer_lead_type(lead)
        if lead_type == "trust":
            parts.append(f"trust({tar.get('anchor_id', name)}:{tar.get('result', '?')})")
        elif lead_type == "fail":
            parts.append(f"{name}:FAIL={fr}")
        elif lead_type == "refine":
            # prefix only if name doesn't already carry it (backward-compat with old scope(...) names)
            parts.append(name if name.startswith("refine(") else f"refine({name})")
        else:
            # scope — emit name bare; old scope(inner) names remain legible without double-wrapping
            parts.append(name)
    terminal = _conclude_field(c.conclude, "termination", "category") or "?"
    disposition = c.conclude.get("disposition", "?")
    parts.append(f"{terminal}:{disposition}")
    return "→".join(parts)


def lead_sequence_pattern(
    corpus: list[Companion],
    *,
    contains: str | None = None,
) -> dict[str, Any]:
    """Serialize each case's gather block as a trace string."""
    hits = []
    for c in corpus:
        trace = _lead_sequence(c)
        if contains is not None and contains not in trace:
            continue
        hits.append(
            {
                "case_id": c.case_id,
                "trace": trace,
                "lead_count": len(c.leads),
                "termination": _conclude_field(c.conclude, "termination", "category"),
                "disposition": c.conclude.get("disposition"),
            }
        )
    return {"hits": hits, "count": len(hits)}


# ---------------------------------------------------------------------------
# Class 6 — name wildcard
# ---------------------------------------------------------------------------

def hypothesis_name_wildcard(
    corpus: list[Companion],
    pattern: str,
    *,
    final_weight: str | None = None,
    disposition: str | None = None,
) -> dict[str, Any]:
    """Match hypothesis names against an fnmatch pattern (e.g., ?*compromise*)."""
    hits = []
    for c in corpus:
        if disposition is not None and c.conclude.get("disposition") != disposition:
            continue
        # compute final weight per hypothesis from the last resolution that touched it
        final: dict[str, str] = {h["id"]: h.get("weight") for h in c.iter_new_hypotheses()}
        for lead in c.leads:
            for r in lead.get("resolutions", []) or []:
                final[r["hypothesis"]] = r.get("after")
        for h in c.iter_new_hypotheses():
            name = h.get("name", "")
            if not fnmatch.fnmatchcase(name, pattern):
                continue
            weight = final.get(h["id"])
            if final_weight is not None and weight != final_weight:
                continue
            hits.append(
                {
                    "case_id": c.case_id,
                    "hypothesis_id": h["id"],
                    "name": name,
                    "final_weight": weight,
                    "disposition": c.conclude.get("disposition"),
                    "status": h.get("status", "active"),
                }
            )
    return {"hits": hits, "count": len(hits)}


# ---------------------------------------------------------------------------
# Class 7 — prose substring
# ---------------------------------------------------------------------------

_PROSE_FIELDS = (
    ("lead.concerns", "concerns"),
    ("lead.resolutions.reasoning", "reasoning"),
    ("conclude.ceiling_rationale", "ceiling_rationale"),
    ("conclude.summary", "summary"),
    ("conclude.termination.rationale", "termination_rationale"),
    ("vertex.concerns", "vertex_concerns"),
    ("hypothesis.concerns", "hypothesis_concerns"),
)


def _prose_snippets(c: Companion) -> Iterator[tuple[str, str]]:
    # vertices + hypotheses concerns
    for v in c.prologue.get("vertices", []) or []:
        for concern in v.get("concerns", []) or []:
            yield (f"prologue.vertex({v.get('id')}).concerns", concern)
    for h in c.iter_new_hypotheses():
        for concern in h.get("concerns", []) or []:
            yield (f"hypothesis({h.get('id')}).concerns", concern)
    # lead-level
    for lead in c.leads:
        for concern in lead.get("concerns", []) or []:
            yield (f"lead({lead.get('id')}).concerns", concern)
        for r in lead.get("resolutions", []) or []:
            reasoning = r.get("reasoning")
            if reasoning:
                yield (f"lead({lead.get('id')}).resolutions[{r.get('hypothesis')}].reasoning", reasoning)
    # conclude
    conclude = c.conclude
    for field_path in ["ceiling_rationale", "summary"]:
        val = conclude.get(field_path)
        if val:
            yield (f"conclude.{field_path}", val)
    term_rationale = (conclude.get("termination") or {}).get("rationale")
    if term_rationale:
        yield ("conclude.termination.rationale", term_rationale)


def prose_substring(
    corpus: list[Companion],
    phrase: str,
    *,
    case_sensitive: bool = False,
) -> dict[str, Any]:
    """Substring scan across the prose fields of every companion."""
    hits = []
    needle = phrase if case_sensitive else phrase.lower()
    for c in corpus:
        for path, text in _prose_snippets(c):
            haystack = text if case_sensitive else text.lower()
            if needle in haystack:
                # extract a ~120-char snippet around the hit
                idx = haystack.find(needle)
                start = max(0, idx - 40)
                end = min(len(text), idx + len(phrase) + 80)
                hits.append(
                    {
                        "case_id": c.case_id,
                        "path": path,
                        "snippet": text[start:end].strip(),
                    }
                )
    return {"hits": hits, "count": len(hits)}


# ---------------------------------------------------------------------------
# Class 8 — lead effectiveness
# ---------------------------------------------------------------------------

_WEIGHT_NUMERIC: dict[Any, int] = {
    None: 0,
    "++": 2,
    "+": 1,
    "-": -1,
    "--": -2,
}


def _abs_delta(before: Any, after: Any) -> float:
    """Absolute weight movement for a single resolution."""
    return abs(_WEIGHT_NUMERIC.get(after, 0) - _WEIGHT_NUMERIC.get(before, 0))


def _lead_effectiveness_rows(
    corpus: list[Companion],
    patterns: tuple[str, ...] = (),
) -> list[dict[str, Any]]:
    """Core aggregation shared by lead_effectiveness and lead_effectiveness_for_hypothesis.

    patterns — zero or more fnmatch patterns; ALL must match a hypothesis name for its
               resolution to count (conjunction). Empty tuple = match everything.
    """
    from math import log1p

    def matches(h_name: str) -> bool:
        return all(fnmatch.fnmatchcase(h_name, p) for p in patterns)

    per_name: dict[str, list[float]] = {}
    for c in corpus:
        # id → name map covering both HYPOTHESIZE declarations and new_hypotheses in leads
        h_names: dict[str, str] = {h["id"]: h.get("name", "") for h in c.iter_new_hypotheses()}

        for lead in c.leads:
            resolutions = lead.get("resolutions", []) or []
            if patterns:
                # restrict to resolutions whose hypothesis name matches all patterns
                deltas = [
                    _abs_delta(r.get("before"), r.get("after"))
                    for r in resolutions
                    if matches(h_names.get(r.get("hypothesis", ""), ""))
                ]
                if not deltas:
                    continue  # lead didn't touch any matching hypothesis
            else:
                deltas = [
                    _abs_delta(r.get("before"), r.get("after")) for r in resolutions
                ]

            lead_mean = sum(deltas) / len(deltas) if deltas else 0.0
            per_name.setdefault(lead.get("name", "?"), []).append(lead_mean)

    rows = []
    for name, corpus_deltas in sorted(per_name.items()):
        count = len(corpus_deltas)
        mean_delta = sum(corpus_deltas) / count
        rows.append(
            {
                "lead_name": name,
                "count": count,
                "mean_abs_weight_delta": round(mean_delta, 3),
                "effectiveness": round(log1p(count) * mean_delta, 4),
            }
        )
    rows.sort(key=lambda r: r["effectiveness"], reverse=True)
    return rows


def lead_effectiveness(corpus: list[Companion]) -> dict[str, Any]:
    """Score each lead name by log1p(count) × mean_abs_weight_delta across all hypotheses.

    count            — number of times a lead with this name appears in the corpus
    mean_abs_weight  — mean |numeric(after) - numeric(before)| across all resolutions
                       fired by leads sharing that name; leads with no resolutions
                       contribute delta=0 to the mean
    effectiveness    — log1p(count) × mean_abs_weight_delta
                       (log1p avoids zeroing singleton leads; rewards frequent leads
                       that move weight strongly)
    """
    rows = _lead_effectiveness_rows(corpus)
    return {"hits": rows, "count": len(rows)}


def lead_effectiveness_for_hypothesis(
    corpus: list[Companion],
    *patterns: str,
) -> dict[str, Any]:
    """Lead effectiveness restricted to hypotheses matching ALL supplied fnmatch patterns.

    Each pattern is matched against the hypothesis name (e.g. '?*compromise*').
    Multiple patterns are AND-ed: a resolution counts only if its hypothesis name
    satisfies every pattern simultaneously. Leads that never touched a matching
    hypothesis are excluded entirely.

    Examples:
      lead_effectiveness_for_hypothesis(corpus, '?*compromise*')
          → leads that moved any hypothesis whose name contains 'compromise'
      lead_effectiveness_for_hypothesis(corpus, '?*monitoring*', '?*compromise*')
          → leads that moved a hypothesis matching BOTH (e.g. '?monitoring-host-compromise')
    """
    if not patterns:
        raise ValueError("supply at least one fnmatch pattern")
    rows = _lead_effectiveness_rows(corpus, patterns)
    return {"hits": rows, "count": len(rows), "patterns": list(patterns)}


# ---------------------------------------------------------------------------
# Enumeration
# ---------------------------------------------------------------------------

_ENUM_CHOICES = ("leads", "anchors", "archetypes", "hypotheses", "dispositions")


def enumerate_corpus(corpus: list[Companion], kind: str) -> dict[str, Any]:
    """List distinct values of a corpus dimension.

    kind — one of: leads, anchors, archetypes, hypotheses, dispositions
    """
    values: set[str] = set()
    for c in corpus:
        if kind == "leads":
            for lead in c.leads:
                values.add(lead.get("name", "?"))
        elif kind == "anchors":
            for lead in c.leads:
                tar = (lead.get("outcome") or {}).get("trust_anchor_result")
                if tar and tar.get("anchor_id"):
                    values.add(tar["anchor_id"])
        elif kind == "archetypes":
            a = c.conclude.get("matched_archetype")
            if a:
                values.add(a)
        elif kind == "hypotheses":
            for h in c.iter_new_hypotheses():
                name = h.get("name")
                if name:
                    values.add(name)
        elif kind == "dispositions":
            d = c.conclude.get("disposition")
            if d:
                values.add(d)
        else:
            raise ValueError(f"unknown kind {kind!r}; choose from {_ENUM_CHOICES}")
    return {"kind": kind, "values": sorted(values), "count": len(values)}


# ---------------------------------------------------------------------------
# CLI — argparse + demo runner
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="query.py",
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

OUTPUT
  Default: human-readable.  --json: one JSON object per line (hits array).
""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    p.add_argument(
        "--class", dest="query_class", type=int, choices=range(1, 9), metavar="N",
        help="Run a single query class (1–8) instead of the full demo.",
    )
    p.add_argument(
        "--enumerate", dest="enumerate", choices=_ENUM_CHOICES, metavar="KIND",
        help="List distinct values: leads | anchors | archetypes | hypotheses | dispositions",
    )
    p.add_argument("--json", action="store_true", help="Emit JSON output instead of prose.")

    # Class 1
    g1 = p.add_argument_group("class 1 — coarse case lookup")
    g1.add_argument("--disposition", help="Filter by disposition (benign|unclear|true_positive)")
    g1.add_argument("--termination", dest="termination_category", help="Filter by termination category (trust-root|severity-ceiling)")
    g1.add_argument("--confidence", help="Filter by confidence (high|medium|low)")
    g1.add_argument("--archetype", dest="matched_archetype", help="Filter by matched_archetype exact value")
    g1.add_argument("--ceiling-kind", dest="ceiling_test_kind", help="Filter by ceiling_test.kind (tool-unavailable|out-of-band-human-contact)")

    # Class 2
    g2 = p.add_argument_group("class 2 — anchor calibration")
    g2.add_argument("--anchor-id", help="Filter by anchor_id")
    g2.add_argument("--result", help="Filter by anchor result (confirmed|refuted|partial|no-data)")
    g2.add_argument("--authority", dest="authority_for_question", help="Filter by authority_for_question (full|partial)")

    # Class 4
    g4 = p.add_argument_group("class 4 — dead-lead lookup")
    g4.add_argument("--system", help="Filter by query_details.system")
    g4.add_argument("--failure-reason", dest="failure_reason", help="Filter by failure_reason")

    # Class 5
    g5 = p.add_argument_group("class 5 — lead sequence")
    g5.add_argument("--contains", help="Filter traces containing this substring")

    # Class 6
    g6 = p.add_argument_group("class 6 — hypothesis wildcard")
    g6.add_argument("--pattern", help="fnmatch pattern against hypothesis names (e.g. '?*compromise*')")
    g6.add_argument("--weight", dest="final_weight", help="Filter by final weight (++|+|-|--)")

    # Class 7
    g7 = p.add_argument_group("class 7 — prose substring")
    g7.add_argument("--phrase", help="Substring to search across all prose fields")
    g7.add_argument("--case-sensitive", action="store_true")

    # Class 8
    g8 = p.add_argument_group("class 8 — lead effectiveness")
    g8.add_argument(
        "--hypothesis", dest="hypothesis_patterns", nargs="+", metavar="PATTERN",
        help="One or more fnmatch patterns (AND-ed conjunction) to restrict scoring to "
             "hypotheses whose name matches all patterns. "
             "E.g. --hypothesis '?*compromise*'  or  --hypothesis '?*monitoring*' '?*compromise*'",
    )

    return p


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
        return hypothesis_name_wildcard(
            corpus, args.pattern,
            final_weight=args.final_weight,
            disposition=args.disposition,
        )
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


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    corpus = load_corpus(PILOT_ROOT)

    if args.enumerate:
        result = enumerate_corpus(corpus, args.enumerate)
        _print_result(f"enumerate({args.enumerate})", result, limit=200, as_json=args.json)
        return 0

    if args.query_class is not None:
        result = _run_class(args.query_class, corpus, args)
        label = f"class {args.query_class}"
        _print_result(label, result, limit=200, as_json=args.json)
        return 0

    # Full demo
    _print_section(f"Corpus: {len(corpus)} companion(s) from {PILOT_ROOT}")
    for c in corpus:
        print(f"  {c.case_id:30} {c.source_path.relative_to(PILOT_ROOT)}")
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
