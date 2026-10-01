
from __future__ import annotations

# `typing_extensions.TypedDict`, not stdlib: pydantic needs it on Python <3.12 to build schemas
# for `@model` fields typed with these (e.g. `corpus.Companion.body`), even under
# `SkipValidation`.
from typing_extensions import TypedDict

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


class _LeadPredRequired(TypedDict):
    id: str


class LeadPrediction(_LeadPredRequired, total=False):
    """A `:L l-NNN.lead_preds` row: a pre-committed route, not a world-state prediction.

    `if` is the condition on what the lead returns, `read_as` the interpretation it licenses,
    and `advance_to` the next lead (or `CONCLUDE` / `HYPOTHESIZE`). Nothing grades an `lp*` and
    no resolution cites one. The `if` cell is projected as `condition`, since `if` is a keyword.
    """

    condition: str
    read_as: str
    advance_to: str


class _ImpactPredRequired(TypedDict):
    id: str


class ImpactPrediction(_ImpactPredRequired, total=False):
    """A `:L l-NNN.impact_preds` row: the impact predicate a lead pre-registers at PREDICT
    and `:R impact` grades at ANALYZE.

    Only `id` is required by the parser; `validate._check_impact_prediction_structure` checks
    the rest and can say what a blank cell costs.
    """

    dimension: str
    claim: str
    on_match: str
    on_mismatch: str
    on_indeterminate: str
    escalation_on: str




# The `:R` resolution buckets. Rows are header-driven: the author's `[a|b|c]` header names
# the keys and `_canonicalize_resolution_row` renames known ones, so every key is optional
# (the column may not exist, and empty cells are dropped). These types name the keys the
# canonicalizer emits; they do not close the grammar. `ResolutionRow` holds the keys shared
# by the anchor-resolving buckets; each subtype adds its own header's.


class ResolutionRow(TypedDict, total=False):

    # `resolved_by_lead` is the one lead the row is projected onto (plural would double-count);
    # `cites_leads` names sibling leads the verdict also rests on.
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
    #: On an `indeterminate` verdict, why it is unsettled (`vocab.AUTHZ_INDET_BASIS`, default
    #: `retry`). `exhausted` only takes the contract off the retrieval frontier.
    basis: str


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
    #: `:L l-NNN.lead_preds`, named as spec rule #18 names the field. These are routes; the
    #: world-state predictions resolutions cite are `HypothesisRecord.predictions`.
    predictions: list[LeadPrediction]
    impact_predictions: list[ImpactPrediction]
    new_hypotheses: list[HypothesisRecord]
    resolutions: list[ResolutionRecord]




class Termination(TypedDict, total=False):

    category: str | None
    rationale: str | None


class SurvivingHypothesis(TypedDict, total=False):
    """A `:T conclude.surviving` row, keyed `hypothesis` to match `:T resolutions` records."""

    hypothesis: str
    final_weight: str


class DeferralRecord(TypedDict, total=False):
    """One `:T conclude.deferred_*` row: a commitment the close leaves open, and why.

    The rationale is the load-bearing cell; a blank one would discharge a commitment for
    free, so the closure rules refuse it. Each row keeps its table's reference column name
    (`contract_ref` for `deferred_authz`, `prediction_ref` otherwise), matching the spec;
    `validate._deferral_index` reads either.
    """

    contract_ref: str
    prediction_ref: str
    rationale: str


class Conclude(TypedDict, total=False):

    disposition: str | None
    impact_verdict: str | None
    impact_severity: str | None
    confidence: str | None
    matched_archetype: str | None
    ceiling_rationale: str | None
    summary: str | None
    # What the detector got wrong, separate from `summary` because a run can find two
    # independent things (the alert's claim fails; the host is compromised anyway). Not
    # mirrored into `report.md`, which carries no model prose.
    detection_notes: str | None
    # The checks the run could not make, one entry per gap, so a reader can tell a benign close
    # that checked everything from one with a load-bearing gap. A bare `none` projects as
    # absence.
    ceiling_test: list[str]
    # The lead id that tested the alerted entity independently of the alert's claim; gates
    # `disposition false-positive`, since refuting the detector says nothing about the host.
    # `_check_false_positive_gating` requires that lead to have committed a result on a vertex
    # already in the prologue.
    entity_check: str | None
    # The run's own list of survivors, from `:T conclude.surviving`. Projected so its `h-*`
    # ids are checkable; benign-gating computes survival from the resolution record instead.
    surviving_hypotheses: list[SurvivingHypothesis]
    # The three deferral tables, from `:T conclude.deferred_{authz,impact,preds}`: the only
    # alternative to "resolved" each closure rule accepts.
    deferred_authorizations: list[DeferralRecord]
    deferred_impact_predictions: list[DeferralRecord]
    deferred_predictions: list[DeferralRecord]
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
