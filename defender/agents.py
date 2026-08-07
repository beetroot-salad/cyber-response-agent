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
from defender.runtime.review_roles import COMPOSER_DEF, DISCRIMINATION_DEF, SUPPORT_DEF

# #797 retired CHALLENGER_DEF, COHERENCE_CHECKER_DEF and PROJECTION_DEF here with the three
# review stages themselves — a definition in this registry is what compiles a role's policy,
# so a registered role with no caller is a compiled grant nothing claims. #796 registers the
# two lens roles and the composer that replace them; SUPPORT is claimed by two calls (the
# support lens and its ablation), which is why there are three definitions and four calls.
AGENTS: dict[AgentRole, AgentDefinition] = build_registry(
    (MAIN_DEF, GATHER_DEF, JUDGE_DEF, ACTOR_DEF, ORACLE_DEF, VERIFY_DEF, LEAD_AUTHOR_DEF,
     CORPUS_AUTHOR_DEF, DISCRIMINATION_DEF, SUPPORT_DEF, COMPOSER_DEF)
)

__all__ = [
    "ACTOR_DEF",
    "AGENTS",
    "COMPOSER_DEF",
    "CORPUS_AUTHOR_DEF",
    "DISCRIMINATION_DEF",
    "GATHER_DEF",
    "JUDGE_DEF",
    "LEAD_AUTHOR_DEF",
    "MAIN_DEF",
    "ORACLE_DEF",
    "SUPPORT_DEF",
    "VERIFY_DEF",
]
