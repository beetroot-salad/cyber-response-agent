
from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from typing import Any, TypeVar

from . import vocab
from .schema import (
    AnchorConsultation,
    AttributeUpdate,
    AuthzResolution,
    CompanionBody,
    EdgeRecord,
    HypothesisRecord,
    ImpactResolution,
    LeadOutcome,
    ResolutionRecord,
    ResolutionRow,
    VertexRecord,
)

REFUTED_WEIGHT = vocab.REFUTED_WEIGHT

_Row = TypeVar("_Row", bound=Mapping[str, object])


def all_vertices(companion: CompanionBody) -> list[VertexRecord]:
    out: list[VertexRecord] = []
    pro = companion.get("prologue") or {}
    out.extend(v for v in (pro.get("vertices") or []) if isinstance(v, dict))
    for lead in companion.get("findings") or []:
        if not isinstance(lead, dict):
            continue
        obs = (lead.get("outcome") or {}).get("observations") or {}
        out.extend(v for v in (obs.get("vertices") or []) if isinstance(v, dict))
    return out


def all_edges(companion: CompanionBody) -> list[EdgeRecord]:
    out: list[EdgeRecord] = []
    pro = companion.get("prologue") or {}
    out.extend(e for e in (pro.get("edges") or []) if isinstance(e, dict))
    for lead in companion.get("findings") or []:
        if not isinstance(lead, dict):
            continue
        obs = (lead.get("outcome") or {}).get("observations") or {}
        out.extend(e for e in (obs.get("edges") or []) if isinstance(e, dict))
    return out


def all_hypotheses(companion: CompanionBody) -> dict[str, HypothesisRecord]:
    out: dict[str, HypothesisRecord] = {}
    hyps = (companion.get("hypothesize") or {}).get("hypotheses") or []
    for h in hyps:
        if isinstance(h, dict) and isinstance(h.get("id"), str):
            out.setdefault(h["id"], h)
    for lead in companion.get("findings") or []:
        if not isinstance(lead, dict):
            continue
        for h in lead.get("new_hypotheses") or []:
            if isinstance(h, dict) and isinstance(h.get("id"), str):
                out.setdefault(h["id"], h)
    return out


def iter_resolutions(
    companion: CompanionBody,
) -> Iterator[tuple[str, ResolutionRecord]]:
    for lead in companion.get("findings") or []:
        if not isinstance(lead, dict):
            continue
        lid = lead.get("id", "?")
        for res in lead.get("resolutions") or []:
            if isinstance(res, dict):
                yield lid, res


def _iter_outcome_rows(
    companion: CompanionBody,
    select: Callable[[LeadOutcome], list[_Row] | None],
) -> Iterator[_Row]:
    # `select` rather than a field name: a TypedDict lookup needs a literal key,
    # so the bucket has to be picked at the call site to stay typed.
    for lead in companion.get("findings") or []:
        if not isinstance(lead, dict):
            continue
        for row in select(lead.get("outcome") or LeadOutcome()) or []:
            if isinstance(row, dict):
                yield row


def iter_authz_resolutions(companion: CompanionBody) -> Iterator[AuthzResolution]:
    return _iter_outcome_rows(
        companion, lambda o: o.get("authorization_resolutions")
    )


def iter_attr_updates(companion: CompanionBody) -> Iterator[AttributeUpdate]:
    return _iter_outcome_rows(companion, lambda o: o.get("attribute_updates"))


def iter_anchor_consultations(
    companion: CompanionBody,
) -> Iterator[AnchorConsultation]:
    return _iter_outcome_rows(companion, lambda o: o.get("anchor_consultations"))


def iter_impact_resolutions(companion: CompanionBody) -> Iterator[ImpactResolution]:
    return _iter_outcome_rows(companion, lambda o: o.get("impact_resolutions"))


def iter_grounded_resolutions(companion: CompanionBody) -> Iterator[ResolutionRow]:
    """Every row that resolves grounding against an anchor, across all three
    buckets — the rows that carry the shared provenance and citation keys.
    `:R attr_updates` is excluded: it records a fact, not a verdict."""
    yield from iter_authz_resolutions(companion)
    yield from iter_anchor_consultations(companion)
    yield from iter_impact_resolutions(companion)


def final_weights(companion: CompanionBody) -> dict[str, Any]:
    final: dict[str, Any] = {
        hid: h.get("weight") for hid, h in all_hypotheses(companion).items()
    }
    for _lid, res in iter_resolutions(companion):
        hid = res.get("hypothesis")
        if isinstance(hid, str):
            final[hid] = res.get("after")
    return final


def live_hypothesis_ids(companion: CompanionBody) -> list[str]:
    return [
        hid
        for hid, w in final_weights(companion).items()
        if w != REFUTED_WEIGHT
    ]
