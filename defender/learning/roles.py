"""The learning loop's agent roles, by role: the definitions the stage builder looks up.
`agents.py` composes this table with the runtime's roles into the one global registry, so both
hold the same objects. Imported where a stage is built, not at module load: the engines that
define these roles import the stage module."""
from __future__ import annotations

from defender._agent_role import AgentRole
from defender.learning.author.curator_engine import CORPUS_AUTHOR_DEF
from defender.learning.branch.estate.oracle import ORACLE_CHECK_DEF, ORACLE_DEF
from defender.learning.branch.questioner import QUESTIONER_DEF
from defender.learning.judge_role import JUDGE_DEF
from defender.learning.leads.lead_author_engine import LEAD_AUTHOR_DEF
from defender.investigation.agent_definition import AgentDefinition, build_registry

LEARNING_AGENTS: dict[AgentRole, AgentDefinition] = build_registry(
    (LEAD_AUTHOR_DEF, CORPUS_AUTHOR_DEF, QUESTIONER_DEF, JUDGE_DEF, ORACLE_DEF, ORACLE_CHECK_DEF)
)
