
from __future__ import annotations

from enum import Enum


class AgentRole(Enum):
    MAIN = "main"
    GATHER = "gather"
    LEAD_AUTHOR = "lead_author"  # lint-run-records: ok — the lead-author role/drain/module's own name, not the `lead_author/` record dir
    CORPUS_AUTHOR = "corpus_author"
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
    # The feedback tick's decide call (#1414): reads one person's comment as data and answers which lookups it
    # approves. Its own key, as every deny-all package has, so a grant added to another never reaches it.
    FEEDBACK = "feedback"
    # A branched world's live oracle and its verifier (#1224, M11): deny-all, their own models
    # and budget. Preflighted only where branching runs.
    ORACLE = "oracle"
    ORACLE_CHECK = "oracle_check"


#: The turn-zero correlation lead's name in the verb-disposition table. Not an enum member:
#: the lead is bound from `GATHER_DEF` and differs only by a narrower projection of the same
#: table, so a key would be a second policy over the same grant. Lives in this leaf because
#: `verb_dispositions` and `lead_zero` both need it and cannot import each other.
CORRELATION_GRANT_HOLDER = "lead-zero-correlation"


#: The `agent_id` namespaces of the run's wire log (`llm_requests.jsonl`): bare `main`,
#: `gather:{lead_id}`, `review:{lens}`. Defined in this dependency-free leaf so the runtime
#: writers and the cost readers in `presentation/` share one spelling; a drifted prefix
#: would silently drop a namespace from the run's accounted cost.
GATHER_AGENT_ID_PREFIX = "gather:"
REVIEW_AGENT_ID_PREFIX = "review:"

#: The reserved turn-zero correlation lead's id (`gather:l-00c` in the wire log and the spend
#: ledger). Sourced here so `lead_zero` and the cost readers share one spelling (#1377 r7.1 F).
CORRELATION_LEAD_ID = "l-00c"

#: The four kinds of agent that spend on a run's behalf (#1377 r7 S6), in the cost bar's order.
MAIN_KIND, GATHER_KIND, CORRELATION_KIND, REVIEW_KIND = "main", "gather", "correlation", "review"
AGENT_KINDS = (MAIN_KIND, GATHER_KIND, CORRELATION_KIND, REVIEW_KIND)


def agent_kind(agent_id: str) -> str:
    """The kind of the run-side agent `agent_id` names: exactly `main`, `gather:<lead>` (the
    correlation lead's reserved id is its own kind) or `review:<lens>`. Any other id, a bare
    `gather` or `review` and an empty lead or lens included, raises `ValueError`: an id the
    mapping does not know is never counted as MAIN's (#1377 r7.1 F)."""
    if agent_id == MAIN_KIND:
        return MAIN_KIND
    for prefix, kind in ((GATHER_AGENT_ID_PREFIX, GATHER_KIND), (REVIEW_AGENT_ID_PREFIX, REVIEW_KIND)):
        if agent_id.startswith(prefix) and agent_id != prefix:
            if kind == GATHER_KIND and agent_id == f"{prefix}{CORRELATION_LEAD_ID}":
                return CORRELATION_KIND
            return kind
    raise ValueError(f"{agent_id!r} is not a run-side agent id (main, gather:<lead>, review:<lens>)")
