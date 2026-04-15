"""Query primitive for investigation-language v2.3 companions.

Loads companion YAML files and answers the seven retrieval-query classes
from query-script-design.md against the corpus in-memory. Raw YAML is the
source of truth; no indexes, no database, no projection layer. Polars is
used on-demand for aggregation projections (classes 2 and 5).

Run `uv run python scripts/query.py` for the demo.
"""

from __future__ import annotations

import fnmatch
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
    "case-a1/walk-a1-v2.3.yaml",
    "case-a4/walk-a4-v2.3.yaml",
    "case-m365/walk-m365-v2.3.yaml",
    "case-real-rule5710/companion-v2.3.yaml",
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

def _strip_redundant_mode_prefix(name: str, mode: str) -> str:
    """Strip a `mode(args)` outer wrapper when it duplicates the trace's mode.

    `scope(instance, concurrent-ssh)` with mode=scope → `instance, concurrent-ssh`
    but leaves `anchor-lookup(job-scheduler)` with mode=trust unchanged because
    the `anchor-lookup` prefix carries information beyond the mode.
    """
    prefix = f"{mode}("
    if name.startswith(prefix) and name.endswith(")"):
        return name[len(prefix):-1]
    return name


def _lead_sequence(c: Companion) -> str:
    parts = []
    for lead in c.leads:
        mode = lead.get("mode", "?")
        name = _strip_redundant_mode_prefix(lead.get("name", "?"), mode)
        outcome = lead.get("outcome") or {}
        tar = outcome.get("trust_anchor_result") or {}
        fr = outcome.get("failure_reason")
        if mode == "trust" and tar:
            parts.append(f"trust({tar.get('anchor_id', name)}:{tar.get('result', '?')})")
        elif fr:
            parts.append(f"{mode}({name}:FAIL={fr})")
        else:
            parts.append(f"{mode}({name})")
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
# Demo main — exercises every query class against the pilot corpus
# ---------------------------------------------------------------------------

def _print_section(title: str) -> None:
    print(f"\n{'=' * 72}\n{title}\n{'=' * 72}")


def _print_result(label: str, result: dict[str, Any], limit: int = 6) -> None:
    print(f"\n--- {label} → {result['count']} hit(s) ---")
    for key in ("hits", "distribution"):
        if key not in result:
            continue
        items = result[key][:limit]
        for item in items:
            # compact one-line rendering
            print(f"  {item}")
        if len(result[key]) > limit:
            print(f"  ... ({len(result[key]) - limit} more)")


def main() -> int:
    corpus = load_corpus(PILOT_ROOT)
    _print_section(f"Corpus: {len(corpus)} companion(s) loaded from {PILOT_ROOT}")
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

    _print_section("Class 1 — coarse case lookup")
    _print_result(
        "severity-ceiling + unclear",
        coarse_case_lookup(corpus, termination_category="severity-ceiling", disposition="unclear"),
    )
    _print_result(
        "tool-unavailable ceiling",
        coarse_case_lookup(corpus, ceiling_test_kind="tool-unavailable"),
    )

    _print_section("Class 2 — anchor calibration")
    _print_result("all anchors — distribution", anchor_calibration(corpus))
    _print_result(
        "approved-monitoring-sources only",
        anchor_calibration(corpus, anchor_id="approved-monitoring-sources"),
    )
    _print_result(
        "partial-authority anchors",
        anchor_calibration(corpus, authority_for_question="partial"),
    )

    _print_section("Class 3 — refinement chain shapes")
    _print_result("refinement shapes across corpus", refinement_chain_shapes(corpus), limit=20)
    # Highlight: roots that actually refined (max_depth > 1)
    refined_only = {
        "hits": [h for h in refinement_chain_shapes(corpus)["hits"] if h["max_depth"] > 1],
        "count": 0,
    }
    refined_only["count"] = len(refined_only["hits"])
    _print_result("roots that refined (max_depth > 1)", refined_only)

    _print_section("Class 4 — dead-lead lookup")
    _print_result("all dead leads", dead_lead_lookup(corpus))
    _print_result(
        "host_query adapter errors",
        dead_lead_lookup(corpus, system="host_query", failure_reason="adapter-error"),
    )

    _print_section("Class 5 — lead sequence pattern")
    _print_result("all traces", lead_sequence_pattern(corpus))
    _print_result(
        "traces touching severity-ceiling",
        lead_sequence_pattern(corpus, contains="severity-ceiling"),
    )

    _print_section("Class 6 — name wildcard")
    _print_result(
        "?*compromise*",
        hypothesis_name_wildcard(corpus, "?*compromise*"),
    )
    _print_result(
        "?*monitoring* weight=--",
        hypothesis_name_wildcard(corpus, "?*monitoring*", final_weight="--"),
    )
    _print_result(
        "?*self*|?*legitimate* (no matches expected — verifies negative case)",
        hypothesis_name_wildcard(corpus, "?*self*"),
    )

    _print_section("Class 7 — prose substring")
    _print_result(
        "'partial-authority'",
        prose_substring(corpus, "partial-authority"),
    )
    _print_result(
        "'burst'",
        prose_substring(corpus, "burst"),
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())
