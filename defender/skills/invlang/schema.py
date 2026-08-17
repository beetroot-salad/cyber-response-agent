
from __future__ import annotations

from typing import TypedDict

AttributesMap = dict[str, str]


class AuthorityRef(TypedDict):

    kind: str
    source: str


class WhenRef(TypedDict):

    timestamp: str




class _VertexRequired(TypedDict):
    id: str
    type: str


class VertexRecord(_VertexRequired, total=False):

    classification: str
    identifier: str
    attributes: AttributesMap


class _EdgeRequired(TypedDict):
    id: str
    relation: str


class EdgeRecord(_EdgeRequired, total=False):

    source_vertex: str
    target_vertex: str
    when: WhenRef
    authority: AuthorityRef
    attributes: AttributesMap




class ParentVertex(TypedDict, total=False):

    type: str
    classification: str
    attributes: AttributesMap


class ProposedEdge(TypedDict, total=False):

    relation: str
    parent_vertex: ParentVertex


class _PredRequired(TypedDict):
    id: str
    subject: str


class PredictionRecord(_PredRequired, total=False):

    claim: str


class _AttrPredRequired(TypedDict):
    id: str
    target: str
    attribute: str


class AttrPredictionRecord(_AttrPredRequired, total=False):

    claim: str


class _RefutRequired(TypedDict):
    id: str


class RefutationRecord(_RefutRequired, total=False):

    claim: str
    refutes_predictions: list[str]


class AuthorizationContract(TypedDict):

    id: str
    edge_ref: str
    anchor_kind: str
    predicate: str
    on_unauthorized: str
    on_indeterminate: str


class _HypRequired(TypedDict):
    id: str
    name: str


class HypothesisRecord(_HypRequired, total=False):

    anchor: str
    proposed_edge: ProposedEdge
    integrity_waived: str
    weight: str | None
    status: str
    predictions: list[PredictionRecord]
    attribute_predictions: list[AttrPredictionRecord]
    refutation_shape: list[RefutationRecord]
    authorization_contract: list[AuthorizationContract]




class _ResolutionRequired(TypedDict):
    hypothesis: str
    hypothesis_id: str
    before: str
    after: str
    severity_of_test: str
    supporting_edges: list[str]
    matched_prediction_ids: list[str]
    matched_refutation_ids: list[str]


class ResolutionRecord(_ResolutionRequired, total=False):

    supporting_marker: str
    reasoning: str




class QueryDetails(TypedDict, total=False):

    system: str
    template: str
    query: str
    time_window: str


class Observations(TypedDict, total=False):

    vertices: list[VertexRecord]
    edges: list[EdgeRecord]




# The `:R` resolution buckets. Their rows are column-header driven — the author's `[a|b|c]`
# header names the keys, and `_canonicalize_resolution_row` renames the ones it knows and
# passes the rest through. So EVERY key is optional twice over: the header decides whether a
# column exists at all, and an empty cell is dropped rather than stored as "". These types
# name the keys the canonicalizer emits; they do not close the grammar.
#
# Key sets derive from the `:R` headers in docs/dense-investigation-format.md §`:R` and
# defender/skills/invlang/SKILL.md, plus the provenance tuple rules of
# docs/investigation-language.md. `ResolutionRow` holds the grounding/provenance keys all
# three anchor-resolving buckets carry; each subtype adds only what its own header adds.


class ResolutionRow(TypedDict, total=False):

    # Ownership and grounding are separate fields on purpose. `resolved_by_lead`
    # names the one lead whose work closed the row out — it is the projection
    # target, so it cannot be plural without the row landing on two outcomes and
    # double-counting. `cites_leads` names sibling leads the verdict rests on,
    # for the case where no single lead answers the question alone.
    resolved_by_lead: str
    cites_leads: list[str]
    verdict: str
    anchor_kind: str
    anchor_id: str
    grounding_kind: str
    authority_for_question: str
    as_of: str
    effective_window: str
    reasoning: str
    conditioning_context: list[str]
    concerns: list[str]


class AuthzResolution(ResolutionRow, total=False):

    edge: str
    fulfills_contract: str
    cites_past_case: str


class AnchorConsultation(ResolutionRow, total=False):

    result: str
    anchor_query: str


class ImpactResolution(ResolutionRow, total=False):

    prediction_ref: str
    dimension: str
    observed: str
    matched_prediction: str


# Unlike the buckets above, this one is not header-driven: the parser folds every
# `:R attr_updates` row for a target into one entry, so both keys always exist.
class AttributeUpdate(TypedDict):

    target: str
    updates: dict[str, str]


class LeadOutcome(TypedDict, total=False):

    failure_reason: str
    observations: Observations
    authorization_resolutions: list[AuthzResolution]
    anchor_consultations: list[AnchorConsultation]
    impact_resolutions: list[ImpactResolution]
    attribute_updates: list[AttributeUpdate]


class _FindingRequired(TypedDict):
    id: str


class FindingRecord(_FindingRequired, total=False):

    name: str
    target: str
    loop: int | str
    mode: str
    trust_root_reached: str
    screen_result: str
    status: str
    tests_hypotheses: list[str]
    outcome: LeadOutcome
    query_details: QueryDetails
    new_hypotheses: list[HypothesisRecord]
    resolutions: list[ResolutionRecord]
    shelved: list[str]
    shelved_rationales: dict[str, str]




class Termination(TypedDict, total=False):

    category: str | None
    rationale: str | None


class SurvivingHypothesis(TypedDict, total=False):
    """A `:T conclude.surviving` row. `hypothesis` rather than `hyp_id`: it is the same
    reference `:T resolutions` records already spell that way."""

    hypothesis: str
    final_weight: str


class Conclude(TypedDict, total=False):

    disposition: str | None
    impact_verdict: str | None
    impact_severity: str | None
    confidence: str | None
    matched_archetype: str | None
    ceiling_rationale: str | None
    summary: str | None
    # What the DETECTOR got wrong, kept out of `summary` on purpose: a run can find two
    # independent things (the alert's claim does not hold; the host is compromised anyway) and
    # `disposition` has room for one. Free text, ONE line like every other row here. It reaches
    # the judge because `render_synthesis` dumps this whole dict; deliberately NOT mirrored into
    # `report.md`, which is host-rendered from typed values and carries no model prose.
    detection_notes: str | None
    # The checks the run could NOT make — one entry per gap, which is why it is a list where its
    # neighbours are scalars: a run names each unreachable source separately ("authorized_keys
    # FIM on web-1 (auditd write events) not retrieved").
    #
    # Without it the judge cannot tell a benign close that checked everything from one that
    # named a load-bearing gap.
    #
    # A bare `none` is the format's way of saying "no ceiling" and projects as absence, so
    # `conclude.get("ceiling_test")` answers "did this run name a gap" without a sentinel.
    ceiling_test: list[str]
    # The lead id that tested the ALERTED entity for suspicion independent of the alert's own
    # claim. It is what makes `disposition false-positive` reachable: refuting the detector says
    # nothing about the host, so the exit is gated on having looked at the host anyway.
    #
    # A lead id and not prose, because prose cannot be checked. `_check_false_positive_gating`
    # resolves it against `:L findings` and requires the lead to have COMMITTED a result and to
    # target a vertex the PROLOGUE already carried. The prologue clause is the load-bearing one:
    # a run whose post-refutation leads all chase vertices the refutation itself introduced
    # never asks about the host it was paged for.
    entity_check: str | None
    # The run's own list of what it thinks survived, from
    # `:T conclude.surviving [hyp_id|final_weight]`. Projected so its `h-*` is checkable like
    # the other three sites that name one.
    #
    # Self-reported and omittable, which is why benign-gating computes survival from the
    # resolution record instead (enforcement ramp rule 5). Checkable, not authoritative.
    surviving_hypotheses: list[SurvivingHypothesis]
    termination: Termination


class Prologue(TypedDict, total=False):

    vertices: list[VertexRecord]
    edges: list[EdgeRecord]


class Hypothesize(TypedDict, total=False):

    hypotheses: list[HypothesisRecord]


class CompanionBody(TypedDict, total=False):

    prologue: Prologue
    hypothesize: Hypothesize
    conclude: Conclude
    closed_loops: list[int]
    findings: list[FindingRecord]
