"""Typed role boundaries for the seam-discovery workflow.

The types make evidence, assumptions, and counterfactuals explicit. They do not
attempt to encode semantic compatibility as a mechanical predicate.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


NonEmpty = Annotated[str, Field(min_length=1)]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SourceMaterial(StrictModel):
    id: NonEmpty
    kind: NonEmpty = "text"
    label: NonEmpty
    content: NonEmpty
    locator: str | None = None


class SourceEnvelope(StrictModel):
    raw_request: NonEmpty
    title_hint: str | None = None
    conversation_decisions: list[str] = Field(default_factory=list)
    materials: list[SourceMaterial] = Field(default_factory=list)

    @model_validator(mode="after")
    def unique_material_ids(self) -> SourceEnvelope:
        ids = [material.id for material in self.materials]
        if len(ids) != len(set(ids)):
            raise ValueError("source material IDs must be unique")
        return self


class Demand(StrictModel):
    id: NonEmpty
    statement: NonEmpty
    rationale: str = ""


class Referent(StrictModel):
    id: NonEmpty
    description: NonEmpty
    kind: NonEmpty = "artifact"
    locator: str | None = None
    observed_fact: str | None = None


class TaskFrame(StrictModel):
    title: NonEmpty
    task: NonEmpty
    product_intent: NonEmpty
    demands: list[Demand] = Field(default_factory=list)
    stable_context: list[str] = Field(default_factory=list)
    referents: list[Referent] = Field(default_factory=list)
    constraints: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def unique_ids(self) -> TaskFrame:
        for label, values in (("demand", self.demands), ("referent", self.referents)):
            ids = [value.id for value in values]
            if len(ids) != len(set(ids)):
                raise ValueError(f"{label} IDs must be unique")
        return self


class IntakeReadiness(StrEnum):
    READY = "ready"
    NEEDS_CLARIFICATION = "needs_clarification"
    EXPLORATORY = "exploratory"


class DerivationLink(StrictModel):
    target: NonEmpty = Field(
        description="A frame field or ID, for example product_intent or demand:D1"
    )
    source_ids: list[str] = Field(
        description="request, decision:N, or material IDs supporting the target"
    )
    status: Literal["explicit", "inferred", "defaulted"]
    account: NonEmpty


class ClarificationQuestion(StrictModel):
    question: NonEmpty
    why_it_matters: NonEmpty
    default_if_unanswered: str | None = None


class IntakeAssessment(StrictModel):
    readiness: IntakeReadiness
    derivations: list[DerivationLink]
    assumptions: list[str]
    unresolved: list[str]
    clarification_questions: list[ClarificationQuestion]
    framing_notes: NonEmpty


class IntakeProposal(IntakeAssessment):
    frame: TaskFrame


class IntakeRecord(StrictModel):
    assessment: IntakeAssessment
    source_sha256: NonEmpty
    frame_sha256: NonEmpty
    generated_by_model: NonEmpty
    elapsed_ms: int = Field(ge=0)
    usage: dict[str, Any]


class ProbeExposure(StrEnum):
    HOLDOUT = "holdout"
    DISCOVERY = "discovery"


class ProbeHypothesis(StrictModel):
    local_id: NonEmpty = Field(description="Identifier local to this questioner report")
    exposure: ProbeExposure = Field(
        description="holdout stays hidden from planner and leaves; discovery may inform root planning"
    )
    question: NonEmpty = Field(
        description="A question about an expected outcome, not a preferred process"
    )
    failure_story: NonEmpty = Field(
        description="A concrete way the whole could fail if this property is missed"
    )
    independence_rationale: NonEmpty = Field(
        description="Why this property follows from the stable task frame rather than a proposed decomposition"
    )
    resolving_evidence: list[str] = Field(
        description="Observations or artifacts that could resolve the question"
    )
    belief_would_change_if: list[str] = Field(
        description="Counterfactual observations that would change the questioner's concern"
    )


class QuestionerReport(StrictModel):
    lens: NonEmpty
    account: NonEmpty = Field(
        description="How this lens understands the task's main risks"
    )
    probes: list[ProbeHypothesis] = Field(min_length=1)
    blind_spots: list[str] = Field(
        description="What this lens is structurally likely to miss"
    )
    minority_report: str | None = Field(
        default=None,
        description="A concern that should survive synthesis even if other lenses do not share it",
    )


class Probe(StrictModel):
    id: NonEmpty
    source_lens: NonEmpty
    exposure: ProbeExposure
    question: NonEmpty
    failure_story: NonEmpty
    independence_rationale: NonEmpty
    resolving_evidence: list[str]
    belief_would_change_if: list[str]


class ProbeAccount(StrictModel):
    probe_id: NonEmpty
    answer: NonEmpty
    evidence: list[str] = Field(
        description="Artifact, referent, dossier, or observation references"
    )
    assumptions: list[str]
    answer_would_change_if: list[str]
    unresolved: list[str] = Field(default_factory=list)


class BaselineReport(StrictModel):
    framing: NonEmpty = Field(
        description="The root's prior understanding before seeing a decomposition"
    )
    accounts: list[ProbeAccount] = Field(min_length=1)
    cross_cutting_uncertainties: list[str]


class GlobalDecision(StrictModel):
    id: NonEmpty
    decision: NonEmpty
    rationale: NonEmpty
    evidence: list[str]
    volatile_if: list[str] = Field(
        description="Events that should unfreeze this decision"
    )


class DemandRelationKind(StrEnum):
    IMPLEMENTS = "implements"
    CONSUMES = "consumes"
    VERIFIES = "verifies"
    AFFECTED_BY = "affected_by"


class DemandRelation(StrictModel):
    demand_id: NonEmpty
    relation: DemandRelationKind
    obligation: NonEmpty


class SeamContract(StrictModel):
    id: NonEmpty
    version: int = Field(default=1, ge=1)
    parent_contract_id: str | None = None
    accountable_owner: NonEmpty
    statement: NonEmpty
    shared_invariants: list[str]
    evidence: list[str]
    demand_ids: list[str]
    unfreezes_if: list[str]


class LeafSpec(StrictModel):
    id: NonEmpty
    objective: NonEmpty
    dossier: NonEmpty
    contract_ids: list[str]
    demand_relations: list[DemandRelation]
    acceptance_referents: list[str]
    join_contribution: NonEmpty


class PlanStrategy(StrEnum):
    DECOMPOSE = "decompose"
    CONDITION = "condition"
    CHANGE_BASIS = "change_basis"
    DO_NOT_CUT = "do_not_cut"


class DecompositionPlan(StrictModel):
    strategy: PlanStrategy
    rationale: NonEmpty
    global_decisions: list[GlobalDecision]
    demand_accountability: dict[str, str] = Field(
        description="One accountable owner per whole-task demand; not a claim that only one leaf is affected"
    )
    contracts: list[SeamContract]
    leaves: list[LeafSpec] = Field(min_length=1)
    join_plan: NonEmpty
    irreducible_core: str | None = None
    root_uncertainties: list[str]

    @model_validator(mode="after")
    def unique_plan_ids(self) -> DecompositionPlan:
        for label, values in (("contract", self.contracts), ("leaf", self.leaves)):
            ids = [value.id for value in values]
            if len(ids) != len(set(ids)):
                raise ValueError(f"{label} IDs must be unique")
        return self


class ReferentFailure(StrictModel):
    leaf_id: NonEmpty
    cited_thing: NonEmpty
    why_not_grounded: NonEmpty
    consequence: NonEmpty


class CutReadiness(StrEnum):
    DISPATCH = "dispatch"
    REVISE = "revise"
    DO_NOT_CUT = "do_not_cut"


class SeamCritique(StrictModel):
    readiness: CutReadiness
    account_of_cut: NonEmpty
    referent_failures: list[ReferentFailure]
    unowned_invariants: list[str]
    dossier_concerns: list[str]
    strongest_contract_satisfying_failure: str | None
    revision_request: str | None
    minority_report: str | None


class InterfaceFinding(StrictModel):
    narrative: NonEmpty = Field(
        description="What surprised the leaf about the handoff or interface"
    )
    evidence: list[str]
    smallest_suspected_scope: NonEmpty
    consequence_if_absorbed: NonEmpty
    alternative_explanation: str | None = None


class LeafWork(StrictModel):
    summary: NonEmpty
    product: NonEmpty = Field(description="The leaf's substantive work product")
    claims: list[str]
    evidence: list[str]
    assumptions: list[str]
    surprises: list[str]
    interface_findings: list[InterfaceFinding] = Field(
        description="Required even when empty; an empty list is a positive no-mismatch assertion"
    )
    self_limitations: list[str]


class FrozenLeafResult(StrictModel):
    leaf_id: NonEmpty
    contract_versions: dict[str, int]
    work: LeafWork
    content_sha256: NonEmpty


class AuditReport(StrictModel):
    leaf_id: NonEmpty
    account_of_available_evidence: NonEmpty
    probe_accounts: list[ProbeAccount]
    observations_not_anticipated_by_probes: list[str]
    limits: list[str]


class AnonymizedAccountBundle(StrictModel):
    subject_alias: NonEmpty
    origin: Literal["root_baseline", "frozen_leaf_audit"]
    accounts: list[ProbeAccount]
    unprompted_observations: list[str] = Field(default_factory=list)


class WorldModel(StrictModel):
    name: NonEmpty
    account: NonEmpty
    supporting_subject_aliases: list[str]
    supporting_evidence: list[str]
    would_be_wrong_if: list[str]


class Tension(StrictModel):
    narrative: NonEmpty
    probe_ids: list[str]
    subject_aliases: list[str]
    competing_explanations: list[str]
    evidence_needed: list[str]


class BlindInterpretation(StrictModel):
    overview: NonEmpty
    world_models: list[WorldModel]
    tensions: list[Tension]
    correlated_assumptions: list[str]
    refusals_or_overreach: list[str]
    missing_evidence: list[str]
    minority_report: str | None
    topology_questions_to_defer: list[str] = Field(
        description="Questions that cannot be answered until the topology is revealed"
    )


class CausalFinding(StrictModel):
    observation: NonEmpty
    candidate_explanations: list[str] = Field(min_length=2)
    most_plausible_account: NonEmpty
    evidence_for: list[str]
    evidence_against: list[str]
    smallest_discriminating_observation: NonEmpty
    implicated_contract_ids: list[str]
    implicated_leaf_ids: list[str]


class TopologyDiagnosis(StrictModel):
    overview: NonEmpty
    findings: list[CausalFinding]
    likely_learning: list[str]
    likely_handoff_loss: list[str]
    likely_silent_coupling: list[str]
    benign_projection: list[str]
    unresolved: list[str]
    minimum_sufficient_next_step: NonEmpty


class AdvocacyStance(StrEnum):
    BENIGN = "benign_or_learning"
    COUPLING = "coupling_or_loss"


class AdvocateCase(StrictModel):
    stance: AdvocacyStance
    thesis: NonEmpty
    strongest_evidence: list[str]
    account_of_opposing_evidence: list[str]
    failure_cost_if_wrong: NonEmpty
    evidence_that_would_concede_the_case: list[str]
    recommended_action: NonEmpty


class DecisionAction(StrEnum):
    CONTINUE = "continue"
    GATHER_EVIDENCE = "gather_evidence"
    AMEND_CONTRACT = "amend_contract"
    RECOMPOSE = "recompose"
    DO_NOT_CUT = "do_not_cut"


class Adjudication(StrictModel):
    action: DecisionAction
    decision: NonEmpty
    reasoning: NonEmpty
    evidence_relied_on: list[str]
    evidence_rejected_or_discounted: list[str]
    affected_contract_ids: list[str]
    affected_leaf_ids: list[str]
    smallest_intervention: NonEmpty
    observation_that_would_reverse_decision: NonEmpty
    residual_risk: list[str]


class QuestionerDeps(StrictModel):
    frame: TaskFrame
    source_envelope: SourceEnvelope | None = None
    lens: NonEmpty


class IntakeDeps(StrictModel):
    source_envelope: SourceEnvelope


class BaselineDeps(StrictModel):
    frame: TaskFrame
    probes: list[Probe]


class PlannerDeps(StrictModel):
    frame: TaskFrame
    discovery_probes: list[Probe]
    prior_plan: DecompositionPlan | None = None
    prior_critique: SeamCritique | None = None


class CriticDeps(StrictModel):
    frame: TaskFrame
    discovery_probes: list[Probe]
    plan: DecompositionPlan


class LeafDeps(StrictModel):
    leaf: LeafSpec
    contracts: list[SeamContract]
    global_decisions: list[GlobalDecision]
    assigned_demands: list[Demand]


class AuditorDeps(StrictModel):
    frame: TaskFrame
    held_out_probes: list[Probe]
    leaf: LeafSpec
    contracts: list[SeamContract]
    frozen_result: FrozenLeafResult


class BlindInterpreterDeps(StrictModel):
    probes: list[Probe]
    bundles: list[AnonymizedAccountBundle]
    questioner_blind_spots: list[str]


class DiagnosticianDeps(StrictModel):
    frame: TaskFrame
    plan: DecompositionPlan
    baseline: BaselineReport
    audits: list[AuditReport]
    frozen_results: list[FrozenLeafResult]
    blind_interpretation: BlindInterpretation


class AdvocateDeps(StrictModel):
    stance: AdvocacyStance
    frame: TaskFrame
    plan: DecompositionPlan
    diagnosis: TopologyDiagnosis
    blind_interpretation: BlindInterpretation


class AdjudicatorDeps(StrictModel):
    frame: TaskFrame
    plan: DecompositionPlan
    diagnosis: TopologyDiagnosis
    benign_case: AdvocateCase
    coupling_case: AdvocateCase
    leaf_findings: list[InterfaceFinding]


class ModelPolicy(StrictModel):
    root_model: NonEmpty = "fireworks:accounts/fireworks/models/kimi-k3"
    leaf_model: NonEmpty = "fireworks:accounts/fireworks/models/kimi-k3"
    max_planning_rounds: int = Field(default=2, ge=1, le=5)
    max_concurrency: int = Field(default=5, ge=1, le=20)
    request_limit_per_role: int = Field(default=3, ge=1, le=10)


DEFAULT_LENSES = [
    "adversarial counterexample",
    "environment and execution context",
    "failure semantics",
    "shared invariant hunting",
    "artifact and referent inspection",
]


class HarnessSpec(StrictModel):
    frame: TaskFrame
    source_envelope: SourceEnvelope | None = None
    intake: IntakeRecord | None = None
    questioner_lenses: list[str] = Field(
        default_factory=lambda: list(DEFAULT_LENSES), min_length=1
    )
    policy: ModelPolicy = Field(default_factory=ModelPolicy)


class PlanningRound(StrictModel):
    round_number: int = Field(ge=1)
    plan: DecompositionPlan
    critique: SeamCritique


class HarnessResult(StrictModel):
    run_id: NonEmpty
    run_directory: NonEmpty
    questioner_reports: list[QuestionerReport]
    probes: list[Probe]
    baseline: BaselineReport
    planning_rounds: list[PlanningRound]
    final_plan: DecompositionPlan
    frozen_results: list[FrozenLeafResult]
    audits: list[AuditReport]
    blind_interpretation: BlindInterpretation
    diagnosis: TopologyDiagnosis
    advocate_cases: list[AdvocateCase]
    adjudication: Adjudication
    usage_by_role: dict[str, dict[str, Any]]
