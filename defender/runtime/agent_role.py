
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
    CHALLENGER = "challenger"
    COHERENCE_CHECKER = "coherence_checker"
    #: #774 R6 — the LIVE write-time projection stage. Deliberately NOT spelled `oracle`:
    #: `ORACLE` above is the OFFLINE learning oracle, a different agent with a different
    #: prompt, grants and geography, and binding the live stage to it resolves — which is
    #: the worst kind of wrong join. The stage's own trace files keep the `oracle` name they
    #: already carry; only the ROLE is new.
    PROJECTION = "projection"
