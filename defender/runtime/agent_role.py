
from __future__ import annotations

from enum import Enum


class AgentRole(Enum):
    MAIN = "main"
    GATHER = "gather"
    VERIFIER = "verifier"
    LEAD_AUTHOR = "lead_author"
    CORPUS_AUTHOR = "corpus_author"
    # An enum key here grants compiled policy and names a trace file, so a member with no
    # definition behind it is a live grant nothing claims — a retired stage retires its key.
    # `judge`, `actor` and `oracle` left under #922 for exactly that reason: the pipeline that
    # was their only caller was deleted, and `set(AGENTS.keys()) == set(AgentRole)` is asserted,
    # so leaving the keys behind would have been red rather than merely wrong. `judge` came
    # BACK in #1008 (below) bound to the family judge — a different role that wanted the same
    # word, which is why it was re-added with its owner rather than held open here.
    #
    # TWO roles, THREE calls: the ablation lens reuses SUPPORT rather than holding a key of
    # its own, because its whole purpose is to be the support lens under a narrower
    # projection — the reading is only interpretable against a support reading produced by
    # the same model at the same effort, and a second role is a second place for those to
    # drift apart. What separates the two calls is the projection they are handed, plus their
    # own trace file and agent id; neither of those is keyed on the role.
    SUPPORT = "support"
    COMPOSER = "composer"
    # ONE DENY-ALL KEY PER PACKAGE — not per grant, and not per "kind of call". The
    # questioner's THREE authoring calls plus the comparator's judging call all run under this
    # ONE key because all four are the branch package's own machinery; what keeps them apart is
    # their `agent_id` — `questioner`, `questioner:b`, `questioner:c`, `compare` — which is what
    # the wire log and the per-id trace are partitioned on.
    QUESTIONER = "questioner"
    # The same rule, drawing the other side of the line: the family judge (`learning/judge/`)
    # is its own package with its own orchestration, so it holds its own key even though its
    # compiled policy is identical to the questioner's — empty. That is deliberate rather than
    # waste. A grant added to the questioner later would otherwise reach the judge with nothing
    # in the diff saying so, and the reviewer of that diff has no way to see it: `agent_id`
    # separates traces, never policies. Reading the rule as "one key per grant" would have
    # collapsed these two, and reading it as "one key per kind of call" invites a future
    # `everything that judges` role spanning packages — which is what the per-PACKAGE wording
    # forecloses.
    JUDGE = "judge"


#: The `agent_id` namespaces the run's ONE wire log (`llm_requests.jsonl`) is partitioned by:
#: bare `main`, `gather:{lead_id}` per gather subagent, `review:{lens}` per review stage.
#: Published HERE — the leaf that already owns agent identity — because the writers live in
#: the runtime (`tools_gather`, `review_roles`) and the cost readers in `scripts/visualize/`,
#: and a prefix that drifted on one side silently drops a whole namespace out of the run's
#: accounted total. This module imports nothing but `enum`, so the reader pays no runtime
#: edge to agree with the writer.
GATHER_AGENT_ID_PREFIX = "gather:"
REVIEW_AGENT_ID_PREFIX = "review:"
