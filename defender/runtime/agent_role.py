"""The agent-role discriminator threaded through `RunDeps`.

One value per PydanticAI agent in the runtime. The permission gate and the
gather capture path key on this instead of a main/not-main bool, so adding an
agent is a new enum value (+ a `RunDeps` subtype carrying its fields), not a
re-threaded boolean. `runtime/tools.py` pins the role per deps class; the
stateless `permission.py` gate reads it to pick a policy.
"""

from __future__ import annotations

from enum import Enum


class AgentRole(Enum):
    MAIN = "main"      # the orchestrator loop (slice 1)
    GATHER = "gather"  # the per-lead ES|QL gather subagent (slice 2)
