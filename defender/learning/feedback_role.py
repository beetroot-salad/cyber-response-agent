"""The feedback tick's decide agent (`FEEDBACK_DEF`, #1414 A3) and its deps class: deny-all, one request, no
tools. A person's comment, the framing run's captured lookups and its outcome are inlined by the host in one
user message; the model answers which lookups the comment approves. Outside `learning/core` for the reason
`judge_role` is outside the judge: the agent registry must reach the role without importing the tick."""

from __future__ import annotations

from typing import ClassVar

from defender._agent_role import AgentRole
from defender._model import model
from defender.investigation.agent_definition import AgentDefinition
from defender.learning.core.config import feedback_effort, feedback_model

_FEEDBACK_DENY_REASON = (
    "Blocked: nothing is reachable from a feedback decision. The comment, the run's outcome and the "
    "lookups the run made were rendered into the prompt you already hold; there is nothing left to read "
    "or ask. Answer from the prompt, as one JSON object, bare, with nothing before or after it."
)


@model(frozen=True)
class FeedbackDeps:
    """Zero fields: a field would be a channel to state this deny-all role must not have."""

    role: ClassVar[AgentRole] = AgentRole.FEEDBACK


FEEDBACK_DEF = AgentDefinition(
    role=AgentRole.FEEDBACK,
    model=feedback_model,
    effort=feedback_effort(),
    deps_cls=FeedbackDeps,
    deny_reason=_FEEDBACK_DENY_REASON,
)

__all__ = ["FEEDBACK_DEF", "FeedbackDeps"]
