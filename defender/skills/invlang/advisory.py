"""PLAN-time advisory retrieval over the defender invlang corpus.

Composes the three cross-case primitives (`lead_sequence_pattern`,
`hypothesis_name_wildcard`, `lead_branch_effects`) into a single
prompt-injection-ready block. This is the load-bearing API surface for
the upcoming retrieval A/B experiment — all three variants
(deterministic floor, Haiku NL→structured, in-defender structured)
call `advisory_recall` and differ only in *how* the call is
constructed, not what comes back.

Output is rendered markdown by default (defender consumes text
in-prompt; parsing JSON in-prompt is unnecessary friction). The harness
gets JSON via `as_json()` for diff/score.

Corpus parsing is cached per `corpus_root` so PLAN- and ANALYZE-time
calls during the same process share one parse.

Loud-empty is deliberate: when a signature has no past cases (or a
section yields zero hits), the markdown renders an explicit "no past
data for this signature" line rather than dropping the section
silently. Silent empties read as no-signal to the LLM consumer.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

from .corpus import Companion, LoadReport, load_corpus
from .queries import (
    hypothesis_name_wildcard,
    lead_branch_effects,
    lead_sequence_pattern,
)


CLASS_SIMILAR_CASES = "similar_cases"
CLASS_HYPOTHESIS_VOCAB = "hypothesis_vocab"
CLASS_LEAD_DISCRIMINATION = "lead_discrimination"
VALID_CLASSES: tuple[str, ...] = (
    CLASS_SIMILAR_CASES,
    CLASS_HYPOTHESIS_VOCAB,
    CLASS_LEAD_DISCRIMINATION,
)

CAVEAT = (
    "Caveat: precedent only. Use to choose what to gather; only current "
    "observations can support or refute hypotheses in this case."
)

_WEIGHT_BUCKETS: tuple[str, ...] = ("++", "+", "-", "--")


# ---------------------------------------------------------------------------
# Result container
# ---------------------------------------------------------------------------


@dataclass
class AdvisorySection:
    """One per requested class. `hits` carries the data; `note` carries the
    loud-empty message when there's nothing to show."""

    name: str
    hits: list[dict[str, Any]] = field(default_factory=list)
    note: str | None = None

    @property
    def empty(self) -> bool:
        return not self.hits


@dataclass
class AdvisoryResult:
    corpus_root: str
    signature_id: str
    frontier: list[str]
    classes: list[str]
    sections: dict[str, AdvisorySection]
    telemetry: dict[str, Any]

    def as_json(self) -> str:
        return json.dumps(
            {
                "corpus_root": self.corpus_root,
                "signature_id": self.signature_id,
                "frontier": self.frontier,
                "classes": self.classes,
                "sections": {k: asdict(v) for k, v in self.sections.items()},
                "telemetry": self.telemetry,
                "caveat": CAVEAT,
            },
            indent=2,
            sort_keys=False,
        )

    def as_markdown(self) -> str:
        t = self.telemetry
        lines = [
            "## ADVISORY RETRIEVAL (precedent, not evidence)",
            f"Corpus: {self.corpus_root} "
            f"({t['cases_loaded']} loaded, {t['cases_skipped']} skipped, "
            f"{t['cases_for_signature']} for {self.signature_id})",
            "",
        ]
        if t["cases_for_signature"] == 0:
            lines.append(
                f"_No past cases for {self.signature_id}. Retrieval yielded nothing._"
            )
            lines.extend(["", CAVEAT])
            return "\n".join(lines)

        for cls in self.classes:
            section = self.sections.get(cls)
            if section is None:
                continue
            lines.extend(_render_section(section, self.frontier))
            lines.append("")
        lines.append(CAVEAT)
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Loader cache
# ---------------------------------------------------------------------------


@lru_cache(maxsize=4)
def _cached_load(corpus_root: str) -> tuple[tuple[Companion, ...], LoadReport]:
    corpus, report = load_corpus(Path(corpus_root))
    return tuple(corpus), report


def clear_cache() -> None:
    """Drop the corpus-load cache. Tests should call this between fixtures."""
    _cached_load.cache_clear()


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def advisory_recall(
    corpus_root: Path | str,
    *,
    signature_id: str,
    frontier: tuple[str, ...] | list[str] = (),
    classes: tuple[str, ...] | list[str] = VALID_CLASSES,
    top_k: int = 3,
) -> AdvisoryResult:
    """Compose advisory retrieval for one PLAN-time call.

    `corpus_root`     — absolute path; must be explicit (no auto-discovery).
    `signature_id`    — e.g. "5710" (the alert's bare `rule.id`); used to filter Classes 5/6.
    `frontier`        — current `?hypothesis` names; routed into Class 8's
                        `hypothesis_patterns`. When empty, Class 8 surfaces
                        the top-`top_k` leads by occurrence regardless of
                        frontier (degenerate but useful for ORIENT-only runs).
    `classes`         — subset of VALID_CLASSES. Unknown names raise.
    `top_k`           — applies to Classes 5 (truncate hits) and 6 (truncate
                        aggregated hypothesis names by occurrence). Class 8
                        is governed by `frontier` and the primitive's
                        min_support, not top_k.
    """
    unknown = [c for c in classes if c not in VALID_CLASSES]
    if unknown:
        raise ValueError(f"unknown advisory classes: {unknown}")

    corpus, report = _cached_load(str(corpus_root))
    corpus_list = list(corpus)
    sig_count = sum(1 for c in corpus_list if c.signature_id == signature_id)

    sections: dict[str, AdvisorySection] = {}
    if sig_count == 0:
        # Loud-empty short-circuit. Every requested class becomes a
        # documented miss; the markdown renderer collapses to a single
        # banner so the LLM sees one clean signal, not three echoes.
        for cls in classes:
            sections[cls] = AdvisorySection(
                name=cls,
                note=f"no cases for {signature_id}",
            )
    else:
        if CLASS_SIMILAR_CASES in classes:
            sections[CLASS_SIMILAR_CASES] = _build_similar_cases(
                corpus_list, signature_id=signature_id, top_k=top_k
            )
        if CLASS_HYPOTHESIS_VOCAB in classes:
            sections[CLASS_HYPOTHESIS_VOCAB] = _build_hypothesis_vocab(
                corpus_list, signature_id=signature_id, top_k=top_k
            )
        if CLASS_LEAD_DISCRIMINATION in classes:
            sections[CLASS_LEAD_DISCRIMINATION] = _build_lead_discrimination(
                corpus_list,
                signature_id=signature_id,
                frontier=tuple(frontier),
                top_k=top_k,
            )

    telemetry = {
        "cases_scanned": report.scanned,
        "cases_loaded": len(corpus_list),
        "cases_skipped": len(report.skipped),
        "cases_partial": len(report.partial),
        "parse_warnings": report.total_warnings,
        "cases_for_signature": sig_count,
    }

    return AdvisoryResult(
        corpus_root=str(corpus_root),
        signature_id=signature_id,
        frontier=list(frontier),
        classes=list(classes),
        sections=sections,
        telemetry=telemetry,
    )


# ---------------------------------------------------------------------------
# Section builders
# ---------------------------------------------------------------------------


def _build_similar_cases(
    corpus: list[Companion], *, signature_id: str, top_k: int
) -> AdvisorySection:
    out = lead_sequence_pattern(corpus, signature_id=signature_id)
    hits = out["hits"][:top_k]
    note = None if hits else f"no traces for {signature_id}"
    return AdvisorySection(name=CLASS_SIMILAR_CASES, hits=hits, note=note)


def _build_hypothesis_vocab(
    corpus: list[Companion], *, signature_id: str, top_k: int
) -> AdvisorySection:
    """Aggregate Class 6 hits by hypothesis name. Each row carries the
    occurrence count + a per-bucket histogram of final weights, so the
    consumer sees frequency *and* outcome shape at a glance.
    """
    raw = hypothesis_name_wildcard(corpus, "?*", signature_id=signature_id)
    by_name: dict[str, dict[str, Any]] = defaultdict(
        lambda: {"n": 0, "buckets": Counter(), "unresolved": 0}
    )
    for hit in raw["hits"]:
        name = hit["name"]
        weight = hit["final_weight"]
        rec = by_name[name]
        rec["n"] += 1
        if weight in _WEIGHT_BUCKETS:
            rec["buckets"][weight] += 1
        else:
            rec["unresolved"] += 1

    rows = sorted(
        (
            {
                "name": name,
                "n": rec["n"],
                "buckets": {b: rec["buckets"].get(b, 0) for b in _WEIGHT_BUCKETS},
                "unresolved": rec["unresolved"],
            }
            for name, rec in by_name.items()
        ),
        key=lambda r: (-r["n"], r["name"]),
    )[:top_k]
    note = None if rows else f"no hypotheses recorded for {signature_id}"
    return AdvisorySection(name=CLASS_HYPOTHESIS_VOCAB, hits=rows, note=note)


def _build_lead_discrimination(
    corpus: list[Companion],
    *,
    signature_id: str,
    frontier: tuple[str, ...],
    top_k: int,
) -> AdvisorySection:
    """Class 8 against the signature-filtered corpus. When a frontier is
    provided, `lead_branch_effects` restricts the per-hypothesis breakdown
    to matching names; without one, we still emit the top-`top_k` most-used
    leads so PLAN gets a baseline view.
    """
    scoped = [c for c in corpus if c.signature_id == signature_id]
    out = lead_branch_effects(
        scoped,
        hypothesis_patterns=tuple(frontier),
        min_support=2,
    )
    leads = out["leads"]
    if not frontier:
        leads = leads[:top_k]
    note: str | None
    if not leads:
        note = (
            f"no recurring leads for {signature_id}"
            if not frontier
            else f"no leads touched frontier {list(frontier)} (n≥2)"
        )
    else:
        note = None
    return AdvisorySection(name=CLASS_LEAD_DISCRIMINATION, hits=leads, note=note)


# ---------------------------------------------------------------------------
# Markdown rendering
# ---------------------------------------------------------------------------


def _render_section(section: AdvisorySection, frontier: list[str]) -> list[str]:
    lines = [_render_section_header(section, frontier)]
    if section.empty:
        lines.append(f"_{section.note or 'no data'}_")
        return lines
    lines.extend(_render_section_body(section))
    return lines


def _render_section_header(section: AdvisorySection, frontier: list[str]) -> str:
    if section.name == CLASS_SIMILAR_CASES:
        return f"### Similar cases (n={len(section.hits)})"
    if section.name == CLASS_HYPOTHESIS_VOCAB:
        return f"### Hypothesis vocabulary (n={len(section.hits)})"
    if section.name == CLASS_LEAD_DISCRIMINATION:
        suffix = (
            f"| frontier: {', '.join(frontier)}"
            if frontier
            else "| no frontier — top recurring leads"
        )
        return f"### Lead discrimination {suffix}"
    return f"### {section.name}"


def _render_section_body(section: AdvisorySection) -> list[str]:
    if section.name == CLASS_SIMILAR_CASES:
        return [
            f"- {h['case_id']} ({h['disposition']}, {h['lead_count']} leads): {h['trace']}"
            for h in section.hits
        ]
    if section.name == CLASS_HYPOTHESIS_VOCAB:
        return [_render_hypothesis_vocab_row(h) for h in section.hits]
    if section.name == CLASS_LEAD_DISCRIMINATION:
        lines: list[str] = []
        for lead in section.hits:
            lines.append(
                f"{lead['lead_name']} (n={lead['n']}, empty {lead['empty_rate']})"
            )
            for hyp, bucket in lead["per_hypothesis_effect"].items():
                lines.append(
                    f"  {hyp}: "
                    + " ".join(f"{b}:{bucket[b]}" for b in _WEIGHT_BUCKETS)
                )
        return lines
    return []


def _render_hypothesis_vocab_row(h: dict) -> str:
    buckets = h["buckets"]
    histogram = ", ".join(f"{b}:{buckets[b]}" for b in _WEIGHT_BUCKETS)
    unresolved = f" (unresolved: {h['unresolved']})" if h["unresolved"] else ""
    return f"{h['name']}: {h['n']}× (final: {histogram}){unresolved}"
