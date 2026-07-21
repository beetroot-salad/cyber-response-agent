from __future__ import annotations

from defender.learning.author.curator_engine import CORPUS_AUTHOR_DEF
from defender.learning.author.verify_forward.engine import VERIFY_DEF
from defender.learning.leads.lead_author_engine import LEAD_AUTHOR_DEF
from defender.learning.pipeline.actor_engine import ACTOR_DEF
from defender.learning.pipeline.judge.engine_pydantic import JUDGE_DEF
from defender.learning.pipeline.oracle_engine import ORACLE_DEF
from defender.runtime.agent_definition import AgentDefinition, build_registry
from defender.runtime.agent_role import AgentRole
from defender.runtime.driver import GATHER_DEF, MAIN_DEF

AGENTS: dict[AgentRole, AgentDefinition] = build_registry(
    (MAIN_DEF, GATHER_DEF, JUDGE_DEF, ACTOR_DEF, ORACLE_DEF, VERIFY_DEF, LEAD_AUTHOR_DEF,
     CORPUS_AUTHOR_DEF)
)

__all__ = [
    "ACTOR_DEF",
    "AGENTS",
    "CORPUS_AUTHOR_DEF",
    "GATHER_DEF",
    "JUDGE_DEF",
    "LEAD_AUTHOR_DEF",
    "MAIN_DEF",
    "ORACLE_DEF",
    "VERIFY_DEF",
]
