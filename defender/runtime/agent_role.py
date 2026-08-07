
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
    # #797 retired CHALLENGER, COHERENCE_CHECKER and PROJECTION — the live gate's three
    # review stages. An enum key here grants compiled policy and names a trace file, so a
    # member with no definition behind it is a live grant nothing claims; the retirement of
    # the stages and the retirement of their keys are therefore one change. #796's lenses and
    # composer land their own members.
