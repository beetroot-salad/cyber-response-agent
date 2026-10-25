"""The family judge's agent definition (`JUDGE_DEF`) and its deps class, outside the judge
package so the agent registry (`defender.agents`, which the run process imports) reaches the
role without importing the judge's orchestration — which materialises tenant exports through
the delivery package the run process never imports (#1108 P4, P-3). `learning.judge.run`
re-exports both; the judge's prompt and model call stay there."""

from __future__ import annotations

from typing import ClassVar

from defender._model import model
from defender.learning.core.config import judge_effort, judge_model
from defender.runtime.agent_definition import AgentDefinition
from defender.runtime.agent_role import AgentRole

#: The judge's refusal text, carried on its compiled policy. Only the bash gate reads it, which
#: this tool-less role never invokes, so it surfaces to operators rather than to a draw.
#:
#: Where a deny reason is shown it is prompt surface, so it names no program or capability the
#: role lacks (that would teach a dead one). The grant gate checks programs; tools are kept out
#: by hand. It describes exactly what the prompt holds: one world plus its control.
_JUDGE_DENY_REASON = (
    "Blocked: nothing is reachable from a judge draw. This episode was archived before the "
    "call began, and the world under grading — with the control it is compared against — was "
    "rendered into the prompt you already hold. There is no path left to resolve and no "
    "system left to ask, and a grade that reached for more would be grading something other "
    "than what was served. Answer from the prompt, as one YAML reply document — bare, not "
    "inside a code fence, with nothing before or after it."
)


@model(frozen=True)
class JudgeDeps:
    """Zero fields: a field would be a channel to state this deny-all role must not have, since
    everything the judge reads is inlined by the host in one user message. `role` is a
    `ClassVar`, which is how `build_stage_agent` finds the definition.

    Not an `AgentDeps` subclass: that is the run scope (run dir, policy, box executor), and
    `bind(JUDGE_DEF, ...)` refuses by name, as there is no run for this role.
    """

    role: ClassVar[AgentRole] = AgentRole.JUDGE


#: The family judge's whole policy. Every grant surface is omitted (deny-all default) rather
#: than spelled as an empty grant, which a one-word edit would reopen.
JUDGE_DEF = AgentDefinition(
    role=AgentRole.JUDGE,
    model=judge_model,
    effort=judge_effort(),
    deps_cls=JudgeDeps,
    deny_reason=_JUDGE_DENY_REASON,
)


__all__ = ["JUDGE_DEF", "JudgeDeps"]
