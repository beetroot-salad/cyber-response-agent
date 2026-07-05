"""The agent-role discriminator threaded through `RunDeps`.

One value per agent, used now as an **identity label** — for observability and the
gather-capture `isinstance` narrow — NOT as the permission discriminator. The gate
keys on `deps.policy` (an `AgentPolicy`, i.e. data the agent brings), so adding an
agent is a new policy value (+ custom matchers), not a new gate branch. `role` is
just a name.
"""

from __future__ import annotations

from enum import Enum


class AgentRole(Enum):
    MAIN = "main"      # the orchestrator loop (slice 1)
    GATHER = "gather"  # the per-lead ES|QL gather subagent (slice 2)
    JUDGE = "judge"    # the learning-loop grounded-outcome judge (PydanticAI)
    ACTOR = "actor"    # the learning-loop adversarial/benign story actor (PydanticAI)
    ORACLE = "oracle"  # the learning-loop per-lead telemetry oracle (PydanticAI)
