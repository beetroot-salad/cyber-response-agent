"""Single source of truth for the canonical invlang *companion* record shapes.

The parser (`parser.py`) projects ```invlang blocks into a nested
``body`` dict (`parse_dense_companion`); the corpus loader wraps it in
`corpus.Companion`; the structural validator (`validate.py`), the
`_walkers` helpers, and the advisory queries (`queries.py`) all read that
dict. Until now every one of those consumers spelled the shape as a bare
``dict[str, Any]`` and narrowed by hand — the `Any | None` debt #409 was
filed to retire (the mypy ramp's ``schemas/`` step).

These TypedDicts are that schema, defined ONCE here and imported by the
producer and every consumer, so the contract can't drift between the code
that builds a record and the code that reads it. The parser's row→record
projections are the authority for the actual field names and which keys are
guaranteed vs. conditional; this module mirrors them — keep them in lockstep.

Shape conventions
-----------------
- A record whose builder always emits a few keys uses the
  ``Required-base + total=False`` pattern: a base TypedDict carries the
  guaranteed keys, and the public record subclasses it ``total=False`` for
  the conditional ones. So ``out: VertexRecord = {"id": ..., "type": ...}``
  type-checks, and a later ``out["attributes"] = ...`` is a known optional
  key rather than a `dict[str, Any]` smuggle.
- A record built purely conditionally is a flat ``total=False`` TypedDict.
- The agent-facing projection of this schema (rendering the column grammar
  into the authoring skill at runtime, so SKILL.md stops hand-copying it) is
  a deliberate follow-up; this module is the code-side contract only.
"""

from __future__ import annotations

from typing import Any, TypedDict

# A free-form attribute bag (`_parse_attrs`) — keys are author-chosen, so it
# stays an open mapping rather than a closed TypedDict.
AttributesMap = dict[str, str]


class AuthorityRef(TypedDict):
    """Observational authority on an edge (`_parse_auth`): the ``auth_kind``
    and its source, split on the ``:`` in the ``auth_kind:source`` cell."""

    kind: str
    source: str


class WhenRef(TypedDict):
    """An edge's time anchor — the ``when`` cell wrapped as a single field."""

    timestamp: str


# --- Vertices & edges (prologue + per-lead observations) -------------------


class _VertexRequired(TypedDict):
    id: str
    type: str


class VertexRecord(_VertexRequired, total=False):
    """A `:V` prologue/observation vertex (`_vertex_record`).

    ``classification``/``identifier`` are always emitted (empty string when
    the cell is blank); ``attributes`` only when the ``attrs`` cell is set."""

    classification: str
    identifier: str
    attributes: AttributesMap


class _EdgeRequired(TypedDict):
    id: str
    relation: str


class EdgeRecord(_EdgeRequired, total=False):
    """A `:E` prologue/observation edge (`_edge_record`)."""

    source_vertex: str
    target_vertex: str
    when: WhenRef
    authority: AuthorityRef
    attributes: AttributesMap


# --- Hypotheses + their `:H h-NNN.<sub>` sub-blocks ------------------------


class ParentVertex(TypedDict, total=False):
    """The proposed parent vertex inside a hypothesis's proposed edge
    (`_build_proposed_edge`, `parent_attrs` sub-block)."""

    type: str
    classification: str
    attributes: AttributesMap


class ProposedEdge(TypedDict, total=False):
    """The edge a discovery-only `:H` proposes (`_build_proposed_edge`)."""

    relation: str
    parent_vertex: ParentVertex


class _PredRequired(TypedDict):
    id: str
    subject: str


class PredictionRecord(_PredRequired, total=False):
    """A `:H h-NNN.preds` row (`_hyp_sub_pred_row`)."""

    claim: str


class _AttrPredRequired(TypedDict):
    id: str
    target: str
    attribute: str


class AttrPredictionRecord(_AttrPredRequired, total=False):
    """A `:H h-NNN.attr_preds` row (`_hyp_sub_attr_pred_row`)."""

    claim: str


class _RefutRequired(TypedDict):
    id: str


class RefutationRecord(_RefutRequired, total=False):
    """A `:H h-NNN.refuts` row (`_hyp_sub_refut_row`). ``refutes_predictions``
    is the csv of prediction ids this refutation targets."""

    claim: str
    refutes_predictions: list[str]


class AuthorizationContract(TypedDict):
    """A `:H h-NNN.authz` row (`_hyp_sub_authz_row`) — all fields are emitted
    (defaulted, never omitted)."""

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
    """A `:H` hypothesis (`_hypothesis_record`) plus the sub-block content
    routed onto it (`_project_hyp_subblock` / `_HYP_SUB_DISPATCH`). ``weight``
    is ``None`` when the cell is the literal ``null``."""

    anchor: str
    proposed_edge: ProposedEdge
    integrity_waived: str
    weight: str | None
    status: str
    predictions: list[PredictionRecord]
    attribute_predictions: list[AttrPredictionRecord]
    refutation_shape: list[RefutationRecord]
    authorization_contract: list[AuthorizationContract]


# --- Resolutions (`:T resolutions`) ---------------------------------------


class _ResolutionRequired(TypedDict):
    hypothesis: str
    hypothesis_id: str  # alias of `hypothesis`, matches the soc-agent shape
    before: str
    after: str
    severity_of_test: str
    supporting_edges: list[str]
    matched_prediction_ids: list[str]
    matched_refutation_ids: list[str]


class ResolutionRecord(_ResolutionRequired, total=False):
    """A `:T resolutions` row (`_resolution_record`): a hypothesis moving
    ``before → after`` with its supporting edges and the prediction/refutation
    ids the iff annotation matched."""

    supporting_marker: str
    reasoning: str


# --- Leads / findings (`:L findings` + the per-lead `l-NNN.*` sub-blocks) --


class QueryDetails(TypedDict, total=False):
    """The gather binding carried on a lead (`_lead_header_record`)."""

    system: str
    template: str
    query: str
    time_window: str


class Observations(TypedDict, total=False):
    """A lead outcome's analyzed graph delta (`_project_lead_subblock`)."""

    vertices: list[VertexRecord]
    edges: list[EdgeRecord]


class LeadOutcome(TypedDict, total=False):
    """A lead's outcome bucket (`outcome` on the finding). The
    ``*_resolutions`` / ``anchor_consultations`` / ``attribute_updates``
    buckets (`_RESOLUTION_BUCKET_KEY`, projected from the `:R` blocks by
    `_project_resolution_block`) are nested *here* under ``outcome``, not on
    the finding itself."""

    failure_reason: str
    observations: Observations
    # These resolution-bucket rows are projected from the dense `:R` columns
    # (`_canonicalize_resolution_row`) — heterogeneous, author-extensible
    # shapes, so the values stay `Any` rather than a closed per-bucket schema.
    authorization_resolutions: list[dict[str, Any]]
    anchor_consultations: list[dict[str, Any]]
    impact_resolutions: list[dict[str, Any]]
    attribute_updates: list[dict[str, Any]]


class _FindingRequired(TypedDict):
    id: str


class FindingRecord(_FindingRequired, total=False):
    """A lead / finding row (`_lead_header_record` + the lead bucket assembled
    in `companion_from_blocks.lead_bucket`). ``loop`` is coerced to ``int``
    when numeric. The ``*_resolutions`` / ``attribute_updates`` buckets
    projected from the `:R`/`:T` blocks (`_RESOLUTION_BUCKET_KEY`) live nested
    under ``outcome`` (see `LeadOutcome`), not directly on the finding.

    ``shelved`` / ``shelved_rationales`` carry the `:T shelved` projection
    (`_project_shelved_block`)."""

    name: str
    target: str
    loop: int
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


# --- Top-level companion body ---------------------------------------------


class Termination(TypedDict, total=False):
    """The `:T conclude` ``termination.*`` scalars (`_project_conclude_scalars`)."""

    category: str | None
    rationale: str | None


class Conclude(TypedDict, total=False):
    """The `:T conclude` block (`_project_conclude_scalars`). A scalar value is
    ``None`` when the cell is the literal ``null``."""

    disposition: str | None
    impact_verdict: str | None
    impact_severity: str | None
    confidence: str | None
    matched_archetype: str | None
    ceiling_rationale: str | None
    summary: str | None
    termination: Termination


class Prologue(TypedDict, total=False):
    """The `:V/:E prologue.*` graph (`_project_block`)."""

    vertices: list[VertexRecord]
    edges: list[EdgeRecord]


class Hypothesize(TypedDict, total=False):
    """The `:H hypothesize.hypotheses` block (`_project_hypothesize_block`)."""

    hypotheses: list[HypothesisRecord]


class CompanionBody(TypedDict, total=False):
    """The canonical companion dict `parse_dense_companion` returns and
    `corpus.Companion.body` wraps. Every key is conditional — a companion that
    never reached a phase simply omits that phase's key."""

    prologue: Prologue
    hypothesize: Hypothesize
    conclude: Conclude
    closed_loops: list[int]
    findings: list[FindingRecord]
