
from __future__ import annotations

from enum import Enum


class AgentRole(Enum):
    MAIN = "main"
    GATHER = "gather"
    VERIFIER = "verifier"
    LEAD_AUTHOR = "lead_author"  # lint-run-records: ok — the lead-author role/drain/module's own name, not the `lead_author/` record dir
    CORPUS_AUTHOR = "corpus_author"
    # The drain's bounded repair spawn for a BAD-verdict lesson. A separate role rather than
    # a per-spawn override of CORPUS_AUTHOR, so its restricted toolset (write + lesson_read,
    # no bash) is fixed at build time.
    CORPUS_REPAIR = "corpus_repair"
    # A key here grants compiled policy and names a trace file, so every member must have a
    # definition (`set(AGENTS.keys()) == set(AgentRole)` is asserted); a retired stage retires
    # its key.
    #
    # Two roles, three calls: the ablation lens reuses SUPPORT, since its reading is only
    # interpretable against a support reading from the same model and effort. The calls
    # differ by projection, trace file and agent id, none keyed on the role.
    SUPPORT = "support"
    COMPOSER = "composer"
    # One deny-all key per package, not per grant or per kind of call. The questioner's three
    # authoring calls and the comparator's call all belong to the branch package and are told
    # apart by `agent_id` (`questioner`, `questioner:b`, `questioner:c`, `comparator:<n>`).
    QUESTIONER = "questioner"
    # Same rule: the family judge (`learning/judge/`) is its own package, so it has its own key
    # even though its policy is as empty as the questioner's. Otherwise a grant added to the
    # questioner would silently reach the judge; `agent_id` separates traces, never policies.
    JUDGE = "judge"
    # A branched world's live oracle and its verifier (#1224, M11): deny-all, their own models
    # and budget, apart from the runtime's `VERIFIER`. Preflighted only where branching runs.
    ORACLE = "oracle"
    ORACLE_CHECK = "oracle_check"


#: The turn-zero correlation lead's name in the verb-disposition table. Not an enum member:
#: the lead is bound from `GATHER_DEF` and differs only by a narrower projection of the same
#: table, so a key would be a second policy over the same grant. Lives in this leaf because
#: `verb_dispositions` and `lead_zero` both need it and cannot import each other.
CORRELATION_GRANT_HOLDER = "lead-zero-correlation"


#: The `agent_id` namespaces of the run's wire log (`llm_requests.jsonl`): bare `main`,
#: `gather:{lead_id}`, `review:{lens}`. Defined in this dependency-free leaf so the runtime
#: writers and the cost readers in `scripts/visualize/` share one spelling; a drifted prefix
#: would silently drop a namespace from the run's accounted cost.
GATHER_AGENT_ID_PREFIX = "gather:"
REVIEW_AGENT_ID_PREFIX = "review:"
