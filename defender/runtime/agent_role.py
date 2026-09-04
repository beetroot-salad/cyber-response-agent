
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
    # #996: the clerk compiles MAIN's prose into invlang rows. A MINTED key, not a reuse of
    # SUPPORT's — an enum key names a trace file (`clerk:{n}`, beside `review:{lens}`), so a
    # zero-grant call sharing SUPPORT's key would share its trace and its agent id.
    CLERK = "clerk"


#: The `agent_id` namespaces the run's ONE wire log (`llm_requests.jsonl`) is partitioned by:
#: bare `main`, `gather:{lead_id}` per gather subagent, `review:{lens}` per review stage.
#: Published HERE — the leaf that already owns agent identity — because the writers live in
#: the runtime (`tools_gather`, `review_roles`) and the cost readers in `scripts/visualize/`,
#: and a prefix that drifted on one side silently drops a whole namespace out of the run's
#: accounted total. This module imports nothing but `enum`, so the reader pays no runtime
#: edge to agree with the writer.
GATHER_AGENT_ID_PREFIX = "gather:"
REVIEW_AGENT_ID_PREFIX = "review:"
#: The clerk's own namespace (#996), one entry per underlying clerk model call (`clerk:{n}`).
CLERK_AGENT_ID_PREFIX = "clerk:"

#: The two document verbs D14 (#996) retired from MAIN's roster (`append_block`, `fix_row`),
#: named ONCE — not as a bare literal in `hooks/budget_enforcer.py`'s own tail-tier table,
#: which sits on MAIN's runtime refusal surface (D15's census): a bare `"append_block"`
#: string there reads, to the surface scan, exactly like an instruction naming a verb MAIN no
#: longer holds. This tuple is DATA a replayed run's old transcript is matched against, never
#: text a model reads; importing it keeps the two retired spellings off that surface's own
#: literal-string census while the table itself still answers for them. Homed here (imports
#: nothing but `enum`) rather than in `runtime/tools/`, where any submodule import runs that
#: package's own `__init__` first and `hooks/budget_enforcer` sits behind it in the import
#: graph — a cycle this module cannot join.
RETIRED_DOCUMENT_VERBS: tuple[str, ...] = ("append_block", "fix_row")
