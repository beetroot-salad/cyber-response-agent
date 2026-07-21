
from __future__ import annotations

from typing import Any, TypedDict

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


class LeadOutcome(TypedDict, total=False):

    failure_reason: str
    observations: Observations
    authorization_resolutions: list[dict[str, Any]]
    anchor_consultations: list[dict[str, Any]]
    impact_resolutions: list[dict[str, Any]]
    attribute_updates: list[dict[str, Any]]


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


class Conclude(TypedDict, total=False):

    disposition: str | None
    impact_verdict: str | None
    impact_severity: str | None
    confidence: str | None
    matched_archetype: str | None
    ceiling_rationale: str | None
    summary: str | None
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
