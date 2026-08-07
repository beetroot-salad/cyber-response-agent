
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
    # the stages and the retirement of their keys were therefore one change.
    #
    # #796's replacements. TWO roles, THREE calls: the ablation lens reuses SUPPORT rather
    # than holding a key of its own, because its whole purpose is to be the support lens
    # under a narrower projection — the reading is only interpretable against a support
    # reading produced by the same model at the same effort, and a second role is a second
    # place for those to drift apart. What separates the two calls is the projection they are
    # handed, plus their own trace file and agent id; neither of those is keyed on the role.
    #
    # DISCRIMINATION was the third role and is retired. It audited LEAD DESIGN — for each
    # lead, which hypotheses its possible outcomes could have separated — which is a question
    # the gate cannot act on: the composer returns `holds` or `gap` about the disposition, and
    # a lead that discriminated nothing is a fact about a measurement already taken. On the
    # first measured live run its two findings were the only ones the composer discarded, one
    # of them explicitly ("about lead design, and is moot"), while the call cost 52% of the
    # review's spend and 90% of its critical path. Its key goes with it for the reason #797's
    # three did: a member here grants compiled policy and names a trace file, so one with no
    # definition behind it is a live grant nothing claims.
    SUPPORT = "support"
    COMPOSER = "composer"
