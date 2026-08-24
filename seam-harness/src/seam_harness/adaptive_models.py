"""Typed contracts for recursive, knowledge-navigating participants."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import Field

from .models import Demand, SourceMaterial, StrictModel
from .recursive_models import (
    EvidencePacket,
    KnowledgeBoardSnapshot,
    KnowledgeRelation,
    KnowledgeTag,
    RecursivePolicy,
    WorkspaceDocument,
    WorkspaceIndexEntry,
)


NonEmpty = Annotated[str, Field(min_length=1)]


class ResponseEffect(StrEnum):
    """What one post does to one question, without claiming global completion."""

    RESOLVES = "resolves"
    ADVANCES = "advances"
    NO_CLAIM = "no_claim"


class QuestionResponse(StrictModel):
    question_id: NonEmpty
    effect: ResponseEffect
    scope_or_reason: NonEmpty = Field(
        description=(
            "For resolves/advances, the supported scope; for no_claim, why no "
            "justified answer can be asserted from the available context"
        )
    )


class NewQuestion(StrictModel):
    local_id: NonEmpty
    text: NonEmpty
    rationale: NonEmpty
    acceptance_condition: NonEmpty
    target_question_ids: list[str] = Field(default_factory=list)
    tags: list[KnowledgeTag] = Field(default_factory=list, max_length=4)


class SeamSignal(StrictModel):
    """A structural mismatch, kept separate from epistemic response effects."""

    finding: NonEmpty
    affected_question_ids: list[str] = Field(min_length=1)
    smallest_scope: NonEmpty
    consequence_if_absorbed: NonEmpty
    contract_id: str | None = None


PostRelation = Literal[
    KnowledgeRelation.DERIVED_FROM,
    KnowledgeRelation.SUPPORTS,
    KnowledgeRelation.CONTRADICTS,
    KnowledgeRelation.SUPERSEDES,
    KnowledgeRelation.DUPLICATES,
]
"""The relations a post may author. `responds_to`, `raises`, `refines`, and
`depends_on` are written by the runtime from the post's other fields."""


class PostLink(StrictModel):
    """A semantic edge from the post being authored to an existing answer."""

    target_id: NonEmpty = Field(
        description=(
            "An answer ID retrieved in this call. Questions are addressed "
            "through responds_to, never through a link."
        )
    )
    relation: PostRelation
    rationale: NonEmpty


class KnowledgePost(StrictModel):
    """Natural answer body plus the minimum graph operations needed to reuse it."""

    body: NonEmpty
    responds_to: list[QuestionResponse] = Field(default_factory=list, max_length=12)
    new_questions: list[NewQuestion] = Field(default_factory=list, max_length=6)
    links: list[PostLink] = Field(default_factory=list, max_length=8)
    seam_signal: SeamSignal | None = None


class AdaptiveActionKind(StrEnum):
    DELEGATE = "delegate"
    VERIFY = "verify"
    CONTINUE = "continue"
    FINISH = "finish"
    # Kept so verified journals from the previous contract remain readable.
    INVESTIGATE = "investigate"
    SYNTHESIZE = "synthesize"
    RUN_EXPERIMENT = "run_experiment"


class DelegationSpec(StrictModel):
    local_id: NonEmpty
    question: NonEmpty
    rationale: NonEmpty
    acceptance_condition: NonEmpty
    target_question_ids: list[str] = Field(min_length=1)
    demand_ids: list[str] = Field(default_factory=list)
    tags: list[KnowledgeTag] = Field(default_factory=list, max_length=4)
    independence_account: NonEmpty = Field(
        description="Why this delegate need not wait for a peer in the same wave"
    )


class DelegateAction(StrictModel):
    kind: Literal[AdaptiveActionKind.DELEGATE] = AdaptiveActionKind.DELEGATE
    delegations: list[DelegationSpec] = Field(min_length=1)
    wave_rationale: NonEmpty


class VerifyAction(StrictModel):
    kind: Literal[AdaptiveActionKind.VERIFY] = AdaptiveActionKind.VERIFY
    proposition: NonEmpty
    adapter: NonEmpty
    arguments: dict[str, Any] = Field(default_factory=dict)
    target_entry_ids: list[str] = Field(min_length=1)
    target_question_ids: list[str] = Field(min_length=1)
    rationale: NonEmpty
    acceptance_condition: NonEmpty


class ContinueAction(StrictModel):
    kind: Literal[AdaptiveActionKind.CONTINUE] = AdaptiveActionKind.CONTINUE
    rationale: NonEmpty


class FinishAction(StrictModel):
    kind: Literal[AdaptiveActionKind.FINISH] = AdaptiveActionKind.FINISH
    answer_ids: list[str] = Field(
        min_length=1,
        description="Visible answer IDs; 'self' selects this turn's contribution",
    )
    rationale: NonEmpty
    unresolved_question_ids: list[str] = Field(default_factory=list)


ParticipantAction = Annotated[
    DelegateAction | VerifyAction | ContinueAction | FinishAction,
    Field(discriminator="kind"),
]


class ParticipantTurn(StrictModel):
    """One posterior update by an actor that both synthesizes and controls."""

    account: NonEmpty = Field(
        description="Why this contribution and next action fit the current posterior"
    )
    contribution: KnowledgePost | None = None
    action: ParticipantAction


class AdaptiveAssignment(StrictModel):
    id: NonEmpty
    objective: NonEmpty
    rationale: NonEmpty
    acceptance_condition: NonEmpty
    target_question_ids: list[str] = Field(default_factory=list)
    demand_ids: list[str] = Field(default_factory=list)
    tags: list[KnowledgeTag] = Field(default_factory=list)
    depth: int = Field(default=0, ge=0)


class KnowledgeStateSummary(StrictModel):
    snapshot_version: int = Field(ge=0)
    snapshot_sha256: NonEmpty
    question_count: int = Field(ge=0)
    answer_count: int = Field(ge=0)
    link_count: int = Field(ge=0)
    unanswered_question_count: int = Field(ge=0)
    contradicted_question_count: int = Field(ge=0)
    focus_question_ids: list[str] = Field(default_factory=list)


class ActionHistoryEntry(StrictModel):
    action_id: NonEmpty
    kind: AdaptiveActionKind
    account: NonEmpty
    actor_id: NonEmpty = "root"
    input_entry_ids: list[str] = Field(default_factory=list)
    output_entry_ids: list[str] = Field(default_factory=list)


class ExperimentAdapterInfo(StrictModel):
    name: NonEmpty
    description: NonEmpty
    argument_schema: dict[str, Any] = Field(default_factory=dict)
    executes_workspace_code: bool = False
    executes_model_authored_code: bool = False


class KnowledgeQueryRecord(StrictModel):
    sequence: int = Field(ge=1)
    tool: NonEmpty
    arguments: dict[str, Any]
    result_ids: list[str] = Field(default_factory=list)
    result: Any
    result_sha256: NonEmpty


class KnowledgeSearchHit(StrictModel):
    id: NonEmpty
    kind: Literal["question", "answer"]
    score: float = Field(ge=0)
    text: NonEmpty
    tags: list[KnowledgeTag] = Field(default_factory=list)
    answer_count: int | None = Field(default=None, ge=0)
    response_effects: list[ResponseEffect] = Field(default_factory=list)
    sufficiency: str | None = None  # legacy fixed-recursive packets
    unresolved_count: int | None = Field(default=None, ge=0)


class KnowledgeSearchResult(StrictModel):
    snapshot_sha256: NonEmpty
    query: str
    hits: list[KnowledgeSearchHit]
    truncated: bool = False


class KnowledgeEntryView(StrictModel):
    id: NonEmpty
    kind: Literal["question", "answer"]
    content: dict[str, Any]
    incoming_links: list[dict[str, Any]] = Field(default_factory=list)
    outgoing_links: list[dict[str, Any]] = Field(default_factory=list)


class KnowledgeThreadView(StrictModel):
    snapshot_sha256: NonEmpty
    question: KnowledgeEntryView
    answers: list[KnowledgeEntryView]
    related_questions: list[KnowledgeEntryView] = Field(default_factory=list)
    truncated: bool = False


class SourceSearchHit(StrictModel):
    source_id: NonEmpty
    locator: NonEmpty
    excerpt: NonEmpty
    score: float = Field(ge=0)
    content_sha256: NonEmpty


class SourceSearchResult(StrictModel):
    query: NonEmpty
    hits: list[SourceSearchHit]
    truncated: bool = False


class SourceReadResult(StrictModel):
    source_id: NonEmpty
    locator: NonEmpty
    content: str
    content_sha256: NonEmpty
    truncated: bool = False


class KnowledgePostRecord(StrictModel):
    id: NonEmpty
    node_id: NonEmpty
    answer_id: NonEmpty
    body: NonEmpty
    responds_to: list[QuestionResponse]
    new_question_ids: list[str]
    seam_signal: SeamSignal | None = None
    read_entry_ids: list[str] = Field(default_factory=list)
    read_source_ids: list[str] = Field(default_factory=list)
    pushed_entry_ids: list[str] = Field(default_factory=list)
    model_call_id: NonEmpty
    content_sha256: NonEmpty


class WaveResult(StrictModel):
    """One descendant's outcome, pushed into the parent's next turn dossier."""

    node_id: NonEmpty
    question_id: NonEmpty
    answer_id: str | None = None
    status: Literal["answered", "no_answer", "failed"]
    body: NonEmpty


class AdaptiveDeps(StrictModel):
    role: Literal["participant", "finalizer"]
    title: NonEmpty
    task: NonEmpty
    product_intent: NonEmpty
    demands: list[Demand]
    constraints: list[str]
    stable_context: list[str]
    assignment: AdaptiveAssignment
    knowledge_summary: KnowledgeStateSummary
    recent_actions: list[ActionHistoryEntry]
    workspace_index: list[WorkspaceIndexEntry]
    available_experiments: list[ExperimentAdapterInfo]
    selected_answer_ids: list[str] = Field(default_factory=list)
    step: int = Field(ge=0)
    remaining_steps: int = Field(ge=0)
    remaining_work_items: int = Field(ge=0)
    remaining_depth: int = Field(ge=0)
    max_parallel_delegations: int = Field(ge=1)
    max_query_results: int = Field(ge=1)
    max_source_chunk_chars: int = Field(ge=500)
    participant_feedback: list[str] = Field(default_factory=list)
    wave_results: list[WaveResult] = Field(default_factory=list)
    knowledge_board: KnowledgeBoardSnapshot = Field(exclude=True, repr=False)
    workspace_documents_by_path: dict[str, WorkspaceDocument] = Field(
        default_factory=dict, exclude=True, repr=False
    )
    source_materials_by_id: dict[str, SourceMaterial] = Field(
        default_factory=dict, exclude=True, repr=False
    )
    packets_by_id: dict[str, EvidencePacket] = Field(
        default_factory=dict, exclude=True, repr=False
    )
    posts_by_id: dict[str, KnowledgePostRecord] = Field(
        default_factory=dict, exclude=True, repr=False
    )
    query_log: list[KnowledgeQueryRecord] = Field(
        default_factory=list, exclude=True, repr=False
    )
    disclosed_source_ids: list[str] = Field(
        default_factory=list, exclude=True, repr=False
    )
    pushed_entry_ids: list[str] = Field(
        default_factory=list, exclude=True, repr=False
    )


class ExperimentResult(StrictModel):
    adapter: NonEmpty
    arguments: dict[str, Any]
    status: Literal["completed", "failed", "timed_out"]
    summary: NonEmpty
    stdout: str = ""
    stderr: str = ""
    exit_code: int | None = None
    elapsed_ms: int = Field(ge=0)
    content_sha256: NonEmpty


class AdaptiveActionRecord(StrictModel):
    action_id: NonEmpty
    sequence: int = Field(ge=1)
    actor_id: NonEmpty = "root"
    actor_depth: int = Field(default=0, ge=0)
    kind: AdaptiveActionKind
    account: NonEmpty
    snapshot_before_sha256: NonEmpty
    snapshot_after_sha256: NonEmpty
    input_entry_ids: list[str] = Field(default_factory=list)
    output_entry_ids: list[str] = Field(default_factory=list)
    work_item_ids: list[str] = Field(default_factory=list)
    experiment_id: str | None = None
    participant_call_id: NonEmpty | None = None
    decision_call_id: NonEmpty | None = None  # legacy journal field
    work_call_ids: list[str] = Field(default_factory=list)
    content_sha256: NonEmpty


class AdaptiveFinalArtifact(StrictModel):
    content: NonEmpty
    format: NonEmpty
    selected_answer_ids: list[str] = Field(default_factory=list)
    unresolved_question_ids: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class AdaptiveResult(StrictModel):
    run_id: NonEmpty
    run_directory: NonEmpty
    workspace_root: str | None
    final_artifact: AdaptiveFinalArtifact
    root_answer_id: NonEmpty
    knowledge_board: KnowledgeBoardSnapshot
    actions: list[AdaptiveActionRecord]
    selected_answer_ids: list[str]
    work_item_count: int = Field(ge=0)
    deepest_participant_level: int = Field(ge=0)
    usage_by_role: dict[str, dict[str, Any]]
    policy: RecursivePolicy
