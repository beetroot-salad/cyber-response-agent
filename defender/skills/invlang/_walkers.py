
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


def vertex_types(companion: CompanionBody) -> dict[str, str]:
    """Every vertex id in the document, mapped to its type — the WHOLE document, not the
    prologue.

    An investigation declares vertices in two places: the prologue's opening graph, and each
    lead's own `outcome.observations`. Indexing the prologue alone while filtering against the
    full hypothesis set (`all_hypotheses` walks both) silently drops any hypothesis anchored
    to a vertex the run discovered mid-investigation: the anchor resolves to no type, so an
    `attached_to_type` filter refuses it as a non-match rather than as a missing id.

    First declaration wins, matching `all_hypotheses`: the prologue is the declaring site for
    anything it names, and a later re-observation adds ids rather than re-typing them.

    That is NOT the same fold `effective_vertex_state` runs, and `frontier._node_state` pairs
    the two: `_seed_vertex_state` unions `attributes` across every `:V` row for the id and
    upgrades an open `classification` or `ident` to a concrete one, so a document that
    re-declares an id under a DIFFERENT `type` — which the validator accepts silently, since
    append-only only compares across writes — yields an `OpenSlot` carrying the FIRST row's
    type beside a later row's attribute. Reconciling the two folds is #919 follow-up work;
    do not read the first-wins rule here as a guarantee that the pair agrees.
    """
    v_type: dict[str, str] = {}
    for v in all_vertices(companion):
        vid = v.get("id")
        if isinstance(vid, str) and vid:
            v_type.setdefault(vid, v.get("type") or "")
    return v_type


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
    """Where every DECLARED hypothesis ended up: its `:H` weight, moved by each
    resolution against it, last move winning.

    NOT document order, and the difference is observable: `iter_resolutions` walks the LEADS in
    declaration order and each lead's rows within that, so two leads moving one hypothesis in a
    single `:T resolutions` block settle on the row belonging to the later-DECLARED lead, not
    the later-written row. A block whose rows follow their leads is where the orders coincide.

    A resolution MOVES a weight; it does not declare one. Seeding an entry from the resolution
    row would mint a hypothesis no `:H` row carries, and these keys are what
    `live_hypothesis_ids` reports — so an `h-*` existing only as a typo in `:T resolutions`
    would count as live. `validate_companion` denies that document, but this walker also reads
    documents that never went through it (one carrying a parse warning, or one read back after
    the fact).

    So the declared set is the whole key set, and an unknown `h-*` is dropped rather than
    added — silently, because naming it is the validator's job and this is the read side.
    """
    declared = all_hypotheses(companion)
    final: dict[str, Any] = {
        hid: h.get("weight") for hid, h in declared.items()
    }
    for _lid, res in iter_resolutions(companion):
        hid = res.get("hypothesis")
        if isinstance(hid, str) and hid in declared:
            final[hid] = res.get("after")
    return final


def live_hypothesis_ids(companion: CompanionBody) -> list[str]:
    return [
        hid
        for hid, w in final_weights(companion).items()
        if w != REFUTED_WEIGHT
    ]
