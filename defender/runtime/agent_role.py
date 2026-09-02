
from __future__ import annotations

from enum import Enum


class AgentRole(Enum):
    MAIN = "main"
    GATHER = "gather"
    JUDGE = "judge"
    ACTOR = "actor"
    ORACLE = "oracle"
    VERIFIER = "verifier"
    LEAD_AUTHOR = "lead_author"
    CORPUS_AUTHOR = "corpus_author"
    # An enum key here grants compiled policy and names a trace file, so a member with no
    # definition behind it is a live grant nothing claims — a retired stage retires its key.
    #
    # TWO roles, THREE calls: the ablation lens reuses SUPPORT rather than holding a key of
    # its own, because its whole purpose is to be the support lens under a narrower
    # projection — the reading is only interpretable against a support reading produced by
    # the same model at the same effort, and a second role is a second place for those to
    # drift apart. What separates the two calls is the projection they are handed, plus their
    # own trace file and agent id; neither of those is keyed on the role.
    SUPPORT = "support"
    COMPOSER = "composer"
    # The same rule again, one level out: the questioner's THREE authoring calls plus the
    # comparator's judging call all run under this ONE key, because none of them holds a grant
    # and a second key would be a second compiled policy over the same empty one. What keeps
    # the four apart is their `agent_id` — `questioner`, `questioner:b`, `questioner:c`,
    # `compare` — which is what the wire log and the per-id trace are partitioned on.
    QUESTIONER = "questioner"


#: The turn-zero correlation lead's name in the verb-disposition table (#999). NOT an enum
#: member, on the rule the ablation lens follows above: the lead is bound from `GATHER_DEF`,
#: so gather's compiled policy, trace file and wire-log id are its own, and what separates it
#: is only a NARROWER projection of the same table — a key here would be a second compiled
#: policy over the same grant. What the lead does need is a name a table row can carry, so a
#: withholding can be written against it and a projection asked for by it. Published from
#: this leaf because `verb_dispositions` and `lead_zero` both read it and neither may import
#: the other to agree on the spelling.
CORRELATION_GRANT_HOLDER = "lead-zero-correlation"


#: The `agent_id` namespaces the run's ONE wire log (`llm_requests.jsonl`) is partitioned by:
#: bare `main`, `gather:{lead_id}` per gather subagent, `review:{lens}` per review stage.
#: Published HERE — the leaf that already owns agent identity — because the writers live in
#: the runtime (`tools_gather`, `review_roles`) and the cost readers in `scripts/visualize/`,
#: and a prefix that drifted on one side silently drops a whole namespace out of the run's
#: accounted total. This module imports nothing but `enum`, so the reader pays no runtime
#: edge to agree with the writer.
GATHER_AGENT_ID_PREFIX = "gather:"
REVIEW_AGENT_ID_PREFIX = "review:"
