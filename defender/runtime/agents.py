"""The agent registry — the single lookup surface over every agent's ``AgentDefinition``
(#538).

Authorship stays PER-AGENT (the ``[[agent-role-primitive]]`` convention): each agent's
definition is co-located with its deps subtype + policy + prompt — the two runtime
agents (``MAIN_DEF`` / ``GATHER_DEF``) in ``driver``, the four learning stages in their
own engine modules. This module is only the thin collector that fans those six into one
role-keyed ``AGENTS`` dict (guarded against a duplicate role by ``build_registry``), so
``bind`` and the stage harness have ONE place to read every agent's tools + permissions.

It is HEAVY (importing the learning engines pulls the pydantic-ai graph), so nothing on
the runtime driver's load path imports it — ``build_agent_core`` / ``build_agent`` read
``MAIN_DEF`` / ``GATHER_DEF`` from ``driver`` directly, and ``_pydantic_stage`` imports
``AGENTS`` lazily. Consumers that want the whole registry (the tests, the stage harness's
role→toolset lookup) import it here."""
from __future__ import annotations

from defender.learning.author.verify_forward.engine import VERIFY_DEF
from defender.learning.leads.lead_author_engine import LEAD_AUTHOR_DEF
from defender.learning.pipeline.actor_engine import ACTOR_DEF
from defender.learning.pipeline.judge.engine_pydantic import JUDGE_DEF
from defender.learning.pipeline.oracle_engine import ORACLE_DEF
from defender.runtime.agent_definition import AgentDefinition, build_registry
from defender.runtime.agent_role import AgentRole
from defender.runtime.driver import GATHER_DEF, MAIN_DEF

# One entry per AgentRole; ``build_registry`` raises on a duplicate role rather than the
# dict-comp's silent last-wins, so a copy-paste that reuses a role fails loud here.
AGENTS: dict[AgentRole, AgentDefinition] = build_registry(
    (MAIN_DEF, GATHER_DEF, JUDGE_DEF, ACTOR_DEF, ORACLE_DEF, VERIFY_DEF, LEAD_AUTHOR_DEF)
)

__all__ = [
    "ACTOR_DEF",
    "AGENTS",
    "GATHER_DEF",
    "JUDGE_DEF",
    "LEAD_AUTHOR_DEF",
    "MAIN_DEF",
    "ORACLE_DEF",
    "VERIFY_DEF",
]
