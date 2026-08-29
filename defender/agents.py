from __future__ import annotations

from defender.learning.author.curator_engine import CORPUS_AUTHOR_DEF
from defender.learning.author.verify_forward.engine import VERIFY_DEF
from defender.learning.branch.questioner import QUESTIONER_DEF
from defender.learning.leads.lead_author_engine import LEAD_AUTHOR_DEF
from defender.learning.pipeline.actor_engine import ACTOR_DEF
from defender.learning.pipeline.judge.engine_pydantic import JUDGE_DEF
from defender.learning.pipeline.oracle_engine import ORACLE_DEF
from defender.runtime.agent_definition import AgentDefinition, build_registry
from defender.runtime.agent_role import AgentRole
from defender.runtime.driver import GATHER_DEF, MAIN_DEF
from defender.runtime.review_roles import COMPOSER_DEF, SUPPORT_DEF

# A definition in this registry is what compiles a role's policy, so a registered role with no
# caller is a compiled grant nothing claims — retire the definition with the stage. The review
# side is ONE lens role plus the composer: SUPPORT is claimed by two calls (the support lens
# and its ablation), so there are two definitions and three calls. The questioner is the same
# shape one turn further out: one definition, three authoring calls and the comparator's.
AGENTS: dict[AgentRole, AgentDefinition] = build_registry(
    (MAIN_DEF, GATHER_DEF, JUDGE_DEF, ACTOR_DEF, ORACLE_DEF, VERIFY_DEF, LEAD_AUTHOR_DEF,
     CORPUS_AUTHOR_DEF, SUPPORT_DEF, COMPOSER_DEF, QUESTIONER_DEF)
)

__all__ = [
    "ACTOR_DEF",
    "AGENTS",
    "COMPOSER_DEF",
    "CORPUS_AUTHOR_DEF",
    "GATHER_DEF",
    "JUDGE_DEF",
    "LEAD_AUTHOR_DEF",
    "MAIN_DEF",
    "ORACLE_DEF",
    "QUESTIONER_DEF",
    "SUPPORT_DEF",
    "VERIFY_DEF",
]
