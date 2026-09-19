from __future__ import annotations

from defender.learning.author.curator_engine import CORPUS_AUTHOR_DEF, CORPUS_REPAIR_DEF
from defender.learning.author.verify_forward.engine import VERIFY_DEF
from defender.learning.branch.questioner import QUESTIONER_DEF
from defender.learning.judge.run import JUDGE_DEF
from defender.learning.leads.lead_author_engine import LEAD_AUTHOR_DEF
from defender.runtime.agent_definition import AgentDefinition, build_registry
from defender.runtime.agent_role import AgentRole
from defender.runtime.driver import GATHER_DEF, MAIN_DEF
from defender.runtime.review_roles import COMPOSER_DEF, SUPPORT_DEF

# A definition in this registry is what compiles a role's policy, so a registered role with no
# caller is a compiled grant nothing claims — retire the definition with the stage.
#
# The review side is ONE lens role plus the composer: SUPPORT is claimed by two calls (the
# support lens and its ablation), so there are two definitions and three calls. The questioner
# is the same shape one turn further out: one definition, three authoring calls and the
# comparator's. The family judge does NOT join that key, and the enum says why: one deny-all
# key per PACKAGE. Two definitions here compile to policies that are empty on every grant
# surface and differ only in their refusal text, and that near-duplication is the intended
# cost — it is what keeps a grant added to one from arriving silently at the other.
AGENTS: dict[AgentRole, AgentDefinition] = build_registry(
    (MAIN_DEF, GATHER_DEF, VERIFY_DEF, LEAD_AUTHOR_DEF,
     CORPUS_AUTHOR_DEF, CORPUS_REPAIR_DEF, SUPPORT_DEF, COMPOSER_DEF, QUESTIONER_DEF, JUDGE_DEF)
)

__all__ = [
    "AGENTS",
    "COMPOSER_DEF",
    "CORPUS_AUTHOR_DEF",
    "CORPUS_REPAIR_DEF",
    "GATHER_DEF",
    "JUDGE_DEF",
    "LEAD_AUTHOR_DEF",
    "MAIN_DEF",
    "QUESTIONER_DEF",
    "SUPPORT_DEF",
    "VERIFY_DEF",
]
