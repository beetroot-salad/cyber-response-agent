"""Contracts for recursive context assembly.

The recursive solver treats a task tree as a hypothesis.  Agents propose local
expansions and evidence; the runtime owns node identity, budgets, scheduling,
and provenance.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import Field

from .models import Demand, SourceMaterial, StrictModel


NonEmpty = Annotated[str, Field(min_length=1)]
ThinkingSetting = bool | Literal["minimal", "low", "medium", "high", "xhigh"]


class NodeDisposition(StrEnum):
    SOLVE = "solve"
    EXPAND = "expand"
    NEEDS_EVIDENCE = "needs_evidence"
    IRREDUCIBLY_COUPLED = "irreducibly_coupled"


class ClaimBasis(StrEnum):
    OBSERVED = "observed"
    INFERRED = "inferred"
    HYPOTHESIS = "hypothesis"


class PacketSufficiency(StrEnum):
    READY = "ready_to_synthesize"
    PARTIAL = "partial"
    BLOCKED = "blocked"
    COUPLED = "coupled"


class KnowledgeTag(StrEnum):
    DEFINITION = "definition"
    CONSTRAINT = "constraint"
    EVIDENCE = "evidence"
    METHOD = "method"
    COUNTEREXAMPLE = "counterexample"
    RISK = "risk"
    ASSUMPTION = "assumption"
    UNCERTAINTY = "uncertainty"
    DECISION = "decision"
    INTERFACE = "interface"
    MEASUREMENT = "measurement"
    SYNTHESIS = "synthesis"


class KnowledgeRelation(StrEnum):
    ANSWERS = "answers"
    PARTIALLY_ANSWERS = "partially_answers"
    RESPONDS_TO = "responds_to"
    RAISES = "raises"
    REFINES = "refines"
    DEPENDS_ON = "depends_on"
    DUPLICATES = "duplicates"
    DERIVED_FROM = "derived_from"
    SUPPORTS = "supports"
    CONTRADICTS = "contradicts"
    SUPERSEDES = "supersedes"


class KnowledgeLinkProposal(StrictModel):
    source_id: NonEmpty = Field(
        description=(
            "An ID visible in the frozen knowledge board, or 'self' for the "
            "answer being authored"
        )
    )
    target_id: NonEmpty = Field(
        description="An existing ID visible in the frozen knowledge board"
    )
    relation: KnowledgeRelation
    rationale: NonEmpty


class KnowledgeQuestion(StrictModel):
    id: NonEmpty
    node_id: str | None = None
    text: NonEmpty
    rationale: NonEmpty
    acceptance_condition: NonEmpty
    demand_ids: list[str] = Field(default_factory=list)
    tags: list[KnowledgeTag] = Field(default_factory=list)
    content_sha256: NonEmpty


class KnowledgeAnswer(StrictModel):
    id: NonEmpty
    node_id: NonEmpty
    packet_id: NonEmpty | None = None
    post_id: NonEmpty | None = None
    body: NonEmpty | None = None
    summary: NonEmpty
    claim_ids: list[str] = Field(default_factory=list)
    sufficiency: PacketSufficiency | None = None
    tags: list[KnowledgeTag] = Field(default_factory=list)
    unresolved: list[str] = Field(default_factory=list)
    content_sha256: NonEmpty


class KnowledgeLink(StrictModel):
    id: NonEmpty
    source_id: NonEmpty
    target_id: NonEmpty
    relation: KnowledgeRelation
    response_effect: Literal["resolves", "advances", "no_claim"] | None = None
    rationale: str | None = None
    origin: Literal["runtime", "agent"] = "runtime"
    proposed_by_node_id: str | None = None
    content_sha256: NonEmpty


class KnowledgeBoardSnapshot(StrictModel):
    version: int = Field(ge=0)
    standard_tags: list[KnowledgeTag]
    questions_by_id: dict[str, KnowledgeQuestion]
    answers_by_id: dict[str, KnowledgeAnswer]
    links_by_id: dict[str, KnowledgeLink]
    answer_ids_by_question: dict[str, list[str]]
    question_ids_by_answer: dict[str, list[str]]
    incoming_link_ids_by_entry: dict[str, list[str]]
    outgoing_link_ids_by_entry: dict[str, list[str]]
    entry_ids_by_tag: dict[str, list[str]]
    content_sha256: NonEmpty


class WorkspaceIndexEntry(StrictModel):
    path: NonEmpty
    size_bytes: int = Field(ge=0)
    content_sha256: NonEmpty


class WorkspaceDocument(WorkspaceIndexEntry):
    content: str


class EvidenceCitation(StrictModel):
    source_id: NonEmpty = Field(
        description="A material ID, referent ID, or workspace-relative path"
    )
    locator: str | None = Field(
        default=None,
        description="A line, symbol, section, test name, or similarly stable locator",
    )
    excerpt: str | None = Field(
        default=None,
        description="A short supporting excerpt, never a substitute for source identity",
    )


class EvidenceClaimDraft(StrictModel):
    local_id: NonEmpty = Field(description="Identifier local to this one model output")
    statement: NonEmpty
    basis: ClaimBasis
    citations: list[EvidenceCitation] = Field(default_factory=list)
    derived_from_claim_ids: list[str] = Field(
        default_factory=list,
        description=(
            "Canonical child claim IDs, or local IDs in this draft that the "
            "runtime will canonicalize"
        ),
    )
    counterevidence: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0, le=1)


class EvidenceClaim(StrictModel):
    id: NonEmpty
    statement: NonEmpty
    basis: ClaimBasis
    citations: list[EvidenceCitation]
    derived_from_claim_ids: list[str]
    counterevidence: list[str]
    confidence: float = Field(ge=0, le=1)


class BoundaryFinding(StrictModel):
    narrative: NonEmpty
    evidence: list[str] = Field(default_factory=list)
    smallest_suspected_scope: NonEmpty
    consequence_if_absorbed: NonEmpty
    alternative_explanation: str | None = None


class RaisedQuestionDraft(StrictModel):
    local_id: NonEmpty
    text: NonEmpty
    rationale: NonEmpty
    acceptance_condition: NonEmpty
    target_question_ids: list[str] = Field(default_factory=list)
    discriminating_outcomes: list[str] = Field(default_factory=list)
    required_source_hints: list[str] = Field(default_factory=list)
    tags: list[KnowledgeTag] = Field(
        default_factory=lambda: [KnowledgeTag.UNCERTAINTY, KnowledgeTag.EVIDENCE]
    )


class EvidenceDraft(StrictModel):
    account: NonEmpty = Field(
        description="A compact answer to this node's objective, not a generic summary"
    )
    claims: list[EvidenceClaimDraft] = Field(default_factory=list)
    counterevidence: list[str] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)
    unresolved: list[str] = Field(default_factory=list)
    source_ids_consulted: list[str] = Field(default_factory=list)
    boundary_findings: list[BoundaryFinding] = Field(default_factory=list)
    knowledge_links: list[KnowledgeLinkProposal] = Field(
        default_factory=list, max_length=8
    )
    raised_questions: list[RaisedQuestionDraft] = Field(
        default_factory=list, max_length=6
    )
    sufficiency: PacketSufficiency
    next_observation: str | None = None


class EvidencePacket(StrictModel):
    id: NonEmpty
    node_id: NonEmpty
    objective: NonEmpty
    account: NonEmpty
    claims: list[EvidenceClaim]
    counterevidence: list[str]
    assumptions: list[str]
    unresolved: list[str]
    source_ids_consulted: list[str]
    boundary_findings: list[BoundaryFinding]
    knowledge_links: list[KnowledgeLinkProposal] = Field(default_factory=list)
    raised_questions: list[RaisedQuestionDraft] = Field(default_factory=list)
    sufficiency: PacketSufficiency
    next_observation: str | None = None
    child_packet_ids: list[str] = Field(default_factory=list)
    content_sha256: NonEmpty


class LocalDecidability(StrictModel):
    context_complete: bool
    acceptance_mechanical: bool
    independent_of_future_siblings: bool
    grounded_referents: list[str] = Field(default_factory=list)
    missing_context: list[str] = Field(default_factory=list)
    account: NonEmpty


class ChildProposal(StrictModel):
    local_id: NonEmpty
    objective: NonEmpty
    rationale: NonEmpty
    demand_ids: list[str] = Field(default_factory=list)
    source_ids: list[str] = Field(default_factory=list)
    source_paths: list[str] = Field(default_factory=list)
    knowledge_tags: list[KnowledgeTag] = Field(default_factory=list)
    separator_facts: list[str] = Field(
        default_factory=list,
        description="Shared facts intentionally duplicated into sibling dossiers",
    )
    acceptance_condition: NonEmpty
    expected_contribution: NonEmpty
    no_future_sibling_dependency: NonEmpty = Field(
        description="Why this child can finish without a sibling's future output"
    )


class SynthesisContract(StrictModel):
    parent_question: NonEmpty
    required_contributions: list[str] = Field(min_length=1)
    shared_invariants: list[str] = Field(default_factory=list)
    conflict_policy: NonEmpty
    acceptance_condition: NonEmpty


class NodePlan(StrictModel):
    disposition: NodeDisposition
    account: NonEmpty
    decidability: LocalDecidability
    children: list[ChildProposal] = Field(default_factory=list)
    synthesis_contract: SynthesisContract | None = None
    requested_source_paths: list[str] = Field(default_factory=list)
    requested_source_ids: list[str] = Field(default_factory=list)
    irreducible_core: str | None = None


class NodeTask(StrictModel):
    id: NonEmpty
    parent_id: str | None = None
    depth: int = Field(ge=0)
    objective: NonEmpty
    rationale: NonEmpty
    demand_ids: list[str] = Field(default_factory=list)
    source_ids: list[str] = Field(default_factory=list)
    source_paths: list[str] = Field(default_factory=list)
    knowledge_tags: list[KnowledgeTag] = Field(default_factory=list)
    separator_facts: list[str] = Field(default_factory=list)
    acceptance_condition: NonEmpty
    expected_contribution: NonEmpty


class PlanningDeps(StrictModel):
    node: NodeTask
    product_intent: NonEmpty
    constraints: list[str]
    assigned_demands: list[Demand]
    stable_context: list[str]
    source_materials: list[SourceMaterial]
    workspace_index: list[WorkspaceIndexEntry]
    workspace_documents: list[WorkspaceDocument]
    ancestor_decisions: list[str]
    knowledge_board: KnowledgeBoardSnapshot
    remaining_depth: int = Field(ge=0)
    remaining_node_budget: int = Field(ge=0)
    max_children: int = Field(ge=2)
    expansion_required: bool = False


class ResearchDeps(StrictModel):
    node: NodeTask
    product_intent: NonEmpty
    constraints: list[str]
    assigned_demands: list[Demand]
    stable_context: list[str]
    source_materials: list[SourceMaterial]
    workspace_documents: list[WorkspaceDocument]
    ancestor_decisions: list[str]
    knowledge_board: KnowledgeBoardSnapshot
    stop_reason: str | None = None


class SynthesisDeps(StrictModel):
    node: NodeTask
    product_intent: NonEmpty
    constraints: list[str]
    assigned_demands: list[Demand]
    contract: SynthesisContract
    child_packets: list[EvidencePacket] = Field(min_length=1)
    source_materials: list[SourceMaterial]
    workspace_documents: list[WorkspaceDocument]
    knowledge_board: KnowledgeBoardSnapshot


class FinalizationDeps(StrictModel):
    title: NonEmpty
    task: NonEmpty
    product_intent: NonEmpty
    demands: list[Demand]
    constraints: list[str]
    root_packet: EvidencePacket
    knowledge_board: KnowledgeBoardSnapshot


class FinalArtifact(StrictModel):
    content: NonEmpty = Field(description="The requested final deliverable")
    format: NonEmpty
    evidence_claim_ids_used: list[str] = Field(default_factory=list)
    unresolved: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class RecursivePolicy(StrictModel):
    root_model: NonEmpty = "fireworks:accounts/fireworks/models/kimi-k3"
    research_model: NonEmpty = (
        "fireworks:accounts/fireworks/models/deepseek-v4-flash-0731"
    )
    synthesis_model: NonEmpty = "fireworks:accounts/fireworks/models/kimi-k3"
    final_model: NonEmpty = "fireworks:accounts/fireworks/models/kimi-k3"
    root_thinking: ThinkingSetting | None = None
    research_thinking: ThinkingSetting | None = None
    synthesis_thinking: ThinkingSetting | None = None
    final_thinking: ThinkingSetting | None = None
    require_root_expansion: bool = False
    max_depth: int = Field(default=3, ge=0, le=8)
    max_nodes: int = Field(default=18, ge=1, le=100)
    max_children: int = Field(default=4, ge=2, le=10)
    max_concurrency: int = Field(default=6, ge=1, le=30)
    max_evidence_rounds: int = Field(default=2, ge=0, le=4)
    request_limit_per_call: int = Field(default=2, ge=1, le=8)
    adaptive_request_limit_per_call: int = Field(default=20, ge=2, le=30)
    request_timeout_seconds: int = Field(default=2700, ge=60, le=7200)
    stream_responses: bool = True
    max_adaptive_steps: int = Field(default=12, ge=1, le=100)
    max_adaptive_wave: int = Field(default=6, ge=1, le=20)
    max_query_results: int = Field(default=10, ge=1, le=50)
    max_source_chunk_chars: int = Field(default=8000, ge=500, le=32000)
    max_experiment_seconds: int = Field(default=60, ge=1, le=3600)
    enabled_experiment_adapters: list[str] = Field(
        default_factory=lambda: ["text_statistics"]
    )
    planner_max_tokens: int = Field(default=3000, ge=256, le=262144)
    research_max_tokens: int = Field(default=3000, ge=256, le=262144)
    synthesis_max_tokens: int = Field(default=4500, ge=256, le=262144)
    final_max_tokens: int = Field(default=6000, ge=256, le=262144)
    max_workspace_files: int = Field(default=500, ge=1, le=5000)
    max_workspace_file_bytes: int = Field(default=100_000, ge=1024)
    max_workspace_total_bytes: int = Field(default=4_000_000, ge=1024)
    transcript_token_budget: int = Field(default=400_000, ge=20_000, le=1_000_000)
    transcript_keep_recent_turns: int = Field(default=2, ge=1, le=10)
    push_wave_results: bool = True


class NodeTrace(StrictModel):
    node_id: NonEmpty
    parent_id: str | None
    depth: int = Field(ge=0)
    proposed_disposition: NodeDisposition
    effective_disposition: NonEmpty
    child_ids: list[str]
    packet_id: NonEmpty
    packet_sha256: NonEmpty
    stop_reason: str | None = None


class RecursiveResult(StrictModel):
    run_id: NonEmpty
    run_directory: NonEmpty
    workspace_root: str | None
    root_packet: EvidencePacket
    final_artifact: FinalArtifact
    knowledge_board: KnowledgeBoardSnapshot
    node_traces: list[NodeTrace]
    node_count: int = Field(ge=1)
    deepest_level: int = Field(ge=0)
    usage_by_role: dict[str, dict[str, Any]]


class RecursiveInvariantError(RuntimeError):
    """A typed model output violates a runtime-owned tree invariant."""


class WorkspaceLimitError(RuntimeError):
    """A requested workspace cannot be snapshotted within configured limits."""
