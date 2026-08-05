
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
    #: the worst kind of wrong join. #791 retired the offline oracle, which is what makes
    #: that join consequential rather than merely confusing (it deletes the other referent);
    #: the stage's dispatch key, its fault detail, and both its trace files (live + hermetic)
    #: are re-keyed off this role's own name rather than the retired stage's.
    PROJECTION = "projection"
