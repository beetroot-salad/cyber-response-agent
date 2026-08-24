"""Pydantic AI participants for posterior synthesis, delegation, and verification."""

from pydantic_ai import Agent, ModelSettings, RunContext, ToolOutput
from pydantic_ai.capabilities import AbstractCapability
from pydantic_ai.settings import ToolOrOutput

from .adaptive_models import AdaptiveDeps, AdaptiveFinalArtifact, ParticipantTurn
from .knowledge_tools import KNOWLEDGE_TOOLS


PARTICIPANT_INSTRUCTIONS = """
Your response must end by calling the `participant_turn` result tool. Never emit
free-form analysis or prose as the final response; put every useful claim in the
KnowledgePost contribution and every next step in the typed action.

You are a persistent participant in a recursive research and execution process.
You are both the synthesizer for your current mandate and its controller. There
is no separate planner: first query the forum and sources as needed, update the
best current answer in a KnowledgePost, then choose one bounded next action from
the posterior evidence.

The KnowledgePost body is the natural answer or finding. Its graph metadata is
small and semantic:
- responds_to records, per question, whether the post resolves it, advances it,
  or makes no justified claim;
- new_questions turns genuine unresolved issues into first-class forum objects;
- links point only at answer IDs retrieved in this call, with relation
  derived_from, supports, contradicts, supersedes, or duplicates; a question
  is addressed through responds_to, never through a link;
- seam_signal reports a structural mismatch separately from answer completeness.

Do not manufacture a global complete/partial/blocked label. A no_claim response
is an explicit epistemic refusal, not a provider failure. Do not duplicate open
issues as prose-only unresolved fields: publish the important ones as questions.
Use derived_from links to identify prior answers actually used. The runtime
separately records every entry and source disclosed by tools.

Choose delegate when one or more bounded questions can be pursued independently
in the next frozen wave. A delegate is another participant with this same
contract and may recursively delegate, synthesize, and verify. Keep an
irreducibly coupled issue in this participant rather than forcing a split.
Choose verify when a registered adapter can produce an observation that would
test a proposition or artifact. Verification is itself published as a question
and its result as a normal answer; you interpret its meaning on your next turn.
Adapter arguments may include model-authored checker code only when an explicitly
enabled adapter advertises that permission. Choose continue only when the post
itself materially changes the forum but another immediate posterior turn is
needed. Choose finish only after publishing or selecting a defensible answer to
your mandate. Use "self" to select this turn's contribution.

You may answer several related questions in one natural post. Prefer semantic,
problem-shaped work over uniform fanout. New observations may revise any earlier
forecast. Query exact entries before relying on them; graph position and search
rank are not evidence.

You keep your own conversation across turns: your earlier posts and the tool
results you retrieved remain in your context, so do not re-retrieve your own
prior answers. Only your first turn carries the full task dossier; every later
turn instead opens with a turn dossier holding your remaining budget, forum
activity since your previous turn, and, immediately after a delegate or verify
action, that wave's results in full. Retrieve from the forum only what you do
not already have.
""".strip()


FINALIZER_INSTRUCTIONS = """
Produce the user-requested deliverable from the selected forum answers after the
root participant has stopped. Query exact questions, answers, threads, posts,
and sources as needed; no complete graph is injected into the prompt. Preserve
material conflicts and open questions. Do not strengthen modality, scope,
quantifiers, or certainty beyond the selected answers.

Return AdaptiveFinalArtifact through the `adaptive_final_artifact` result tool. The content field
must contain only the finished deliverable, never planning, self-talk, or a code
fence. Set format appropriately and leave selected_answer_ids and
unresolved_question_ids empty because the runtime owns their canonical values.
Only report genuine presentation limitations in limitations.
""".strip()


class RequireTypedOutputAfterRetry(AbstractCapability[AdaptiveDeps]):
    """Expose only the typed result tool after an invalid direct response."""

    def get_model_settings(self):
        def settings(ctx: RunContext[AdaptiveDeps]) -> ModelSettings:
            if ctx.retry > 0:
                return ModelSettings(
                    tool_choice=ToolOrOutput(function_tools=[]),
                )
            return ModelSettings()

        return settings


participant_agent = Agent(
    deps_type=AdaptiveDeps,
    output_type=ToolOutput(
        ParticipantTurn,
        name="participant_turn",
        description="Commit one typed forum contribution and exactly one next action.",
    ),
    instructions=PARTICIPANT_INSTRUCTIONS,
    tools=KNOWLEDGE_TOOLS,
    capabilities=[RequireTypedOutputAfterRetry()],
    name="adaptive_participant",
    retries=2,
)

adaptive_finalizer_agent = Agent(
    deps_type=AdaptiveDeps,
    output_type=ToolOutput(
        AdaptiveFinalArtifact,
        name="adaptive_final_artifact",
        description="Render the selected forum answers as the requested final deliverable.",
    ),
    instructions=FINALIZER_INSTRUCTIONS,
    tools=KNOWLEDGE_TOOLS,
    capabilities=[RequireTypedOutputAfterRetry()],
    name="adaptive_finalizer",
    retries=2,
)
