"""#923 — a host-terminated run trains nothing (O5, M3).

Every test here is one demand of `spec-flow/specs/spec_graph_923-inconclusive.yaml`, named by
that demand's `discharged_by`. RED against HEAD is the expected state.

THE DESIGN'S OWN ORACLE FOR THIS OBLIGATION CANNOT FAIL, AND BOTH REPAIRS ARE HERE. It said
"the new state selects no training direction" — but the direction router returns an empty list
for ANY unrecognized string, so that assertion is true on a build where the member was never
added to the untrained set, and true of a typo. Two things fix it:

* the union invariant — the union of every direction's dispositions is exactly the enum minus
  the untrained set — which BREAKS when a member joins the vocabulary and nothing else, and is
  asserted here together with its own mutation witness, so "this assertion can fail" is
  demonstrated rather than claimed;
* the §7-round-4 design change, which repairs the SAME defect in the code rather than in an
  assertion: an unknown verdict and a deliberately untrained one become distinct states, so
  `directions_for(<untrained member>) == []` finally says something about that member. That is
  `test_an_unknown_verdict_and_a_deliberately_untrained_one_are_distinct_states`, and the
  union invariant below is now its sibling rather than its only substitute;
* driving a real run cycle through the GATE-OVERRULE producer. Driving it through the obvious
  producer instead — the driver's retry exhaustion — would test nothing: that producer sets
  `truncated_by`, and the shared refusal predicate refuses any truncated run before the
  untrained set is ever consulted. That asymmetry was probed, and the retry-exhaustion case is
  kept below under its own name so a later reader does not quietly move the discriminating
  fixture onto it.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from defender._vocab import DISPOSITION_ENUM
from defender.learning.core.directions import (
    BY_NAME,
    UNTRAINED_DISPOSITIONS,
    directions_for,
)
from defender.tests._spec923 import MEMBER
from defender.tests._spec791 import (  # noqa: F401 — session-scoped autouse guard
    SpecSubagents,
    loop_paths,
    make_run_dir,
    worktree_package_guard,
)
from defender.tests._docker import satisfy_engine_keys

pytestmark = pytest.mark.gate


class _BoxRecorder:
    """The run-cycle box lifecycle, recorded rather than performed. A leg cannot dispatch
    without one, so "no box was requested" is the observable that says no leg ran — separately
    from what the subagents recorded, because a fake that only records calls cannot tell a leg
    that declined from a leg that died before calling."""

    def __init__(self) -> None:
        self.started: list[Any] = []

    def start_box(self, request, **_kw):
        self.started.append(request)
        return request

    def stop_box(self, _box, **_kw) -> None:
        return None


def _drive(tmp_path: Path, monkeypatch, disposition: str) -> tuple[int, SpecSubagents, _BoxRecorder]:
    from defender.learning.core import run_cycle

    satisfy_engine_keys(monkeypatch, disposition)
    box = _BoxRecorder()
    agents = SpecSubagents()
    run_dir = make_run_dir(tmp_path, name=f"case-923-{disposition}", disposition=disposition)
    rc = run_cycle.run_one(
        run_dir, paths=loop_paths(tmp_path), agents=agents,
        start_box=box.start_box, stop_box=box.stop_box,
    )
    return rc, agents, box


def test_a_run_in_the_new_state_dispatches_no_learning_leg(tmp_path, monkeypatch):
    """`unresolved` is a member of the untrained set, and a run carrying it dispatches no
    learning leg — no box, no actor leg, no judge leg. THE SET MEMBERSHIP IS THE CONSTRUCTION
    AND THE ASSERTION; the empty direction list is its consequence, not the oracle.

    A run the host terminated is evidence about the RUN, not about the world: the model never
    reached a finding, so neither actor has a story to write from it and neither hunt has a
    claim to disprove.

    Driven through the gate-overrule shape of a finished run — a committed report and no
    truncation marker — because that is the producer the untrained set actually decides. The
    positive control is the second half: the same drive on a `malicious` run DOES request a box
    and DOES dispatch its legs, so the empty recorders above are the routing and not a harness
    that never gets that far."""
    assert MEMBER in UNTRAINED_DISPOSITIONS, (
        "the member is in the vocabulary and not in the untrained set — the empty direction "
        "list below is then true of any unrecognized string and says nothing about this one"
    )

    rc, agents, box = _drive(tmp_path / "host-terminated", monkeypatch, MEMBER)
    assert rc == 0, "the loop refused the run rather than declining to train on it"
    assert directions_for(MEMBER) == []
    assert agents.calls == [], f"a host-terminated run dispatched {agents.calls}"
    assert box.started == [], "a run-cycle box was requested for a run with no legs to run"

    rc2, agents2, box2 = _drive(tmp_path / "control", monkeypatch, "malicious")
    assert agents2.calls, "the control dispatched nothing either — the drive never gets that far"
    assert box2.started, "the control requested no box"
    assert rc2 is not None


def test_the_retry_exhausted_run_is_refused_before_the_untrained_set_is_consulted(tmp_path):
    """The producer this obligation must NOT be driven through, kept as its own named case.

    The driver's retry-exhaustion limb sets a truncation marker, and the one refusal predicate
    both enqueues consult refuses any truncated run outright — before a disposition is read at
    all. So a test that drove the new state through that producer would pass with the untrained
    set untouched, and would go on passing if someone deleted the membership entirely.

    THREE RUNS, BECAUSE ONE PROVES NOTHING. Restating the literal the gate returns on its first
    line is what the earlier shape of this test did: every other input was inert and there was
    no run it let through, so it read identically on a build with the guard deleted. What
    discriminates is the pair plus the control — the truncation refusal is IDENTICAL for the
    host's untrainable verdict and for a trainable one (the guard never reads the disposition),
    and the same tree with no marker CLEARS the gate outright, which is only observable once
    the run carries a completed scan verdict. The clearing run is also the second half of this
    demand: the host's own verdict is not what this gate excludes, so the untrained set is a
    structurally separate decision made later."""
    from defender.run_common import learning_refusal_gate
    from defender.runtime import scrub, session_store

    marker = session_store.TRUNCATED_BY_RETRY_EXHAUSTED
    refusals = {}
    for disposition in (MEMBER, "malicious"):
        run_dir = make_run_dir(tmp_path, name=f"truncated-{disposition}", disposition=disposition)
        # The real primitive, not a hand-written verdict file: the walk writes `ran: true`
        # outside the tree it judges, and a run with no verdict is refused for THAT instead.
        scrub.scrub(run_dir)
        refusals[disposition] = learning_refusal_gate(
            run_dir, run_dir / "alert.json", truncated_by=marker,
        )
        assert refusals[disposition] is not None, disposition
        assert "truncated" in refusals[disposition], refusals[disposition]

    assert refusals[MEMBER] == refusals["malicious"], (
        f"the truncation refusal differs by disposition: {refusals} — this guard is supposed "
        f"to be disposition-blind, and a version that reads the verdict is the untrained set "
        f"wearing the truncation guard's name"
    )

    # The control, and the assertion the earlier shape had none of: the SAME tree with no
    # marker clears every net, so the refusals above are the marker and not a gate that
    # refuses whatever it is handed.
    cleared = make_run_dir(tmp_path, name="untruncated", disposition=MEMBER)
    scrub.scrub(cleared)
    assert learning_refusal_gate(cleared, cleared / "alert.json", truncated_by=None) is None, (
        learning_refusal_gate(cleared, cleared / "alert.json", truncated_by=None)
    )


def test_a_review_broken_by_the_content_under_review_stops_training_on_that_case(tmp_path):
    """M2 over M3 hands shaped content an OFF-SWITCH for learning, and this is where that is
    written down rather than absorbed.

    `challenge_gate._fail` fires when a review stage times out, raises, or answers outside its
    own contract — modes reachable from the attacker-influenced investigation content the
    reviewers read (J30). F3 widened M2 to move that arm onto the host's verdict; M3 then puts
    that verdict in the untrained set. Composed, content that reliably breaks a review excises
    its own case from the learning corpus. TODAY the same close commits `inconclusive` and
    `directions_for` selects BOTH directions, so this is a real change in what shaped content
    can do, and J30 was answered on the containment lane only.

    The exclusion is accepted here as a DENIAL OF TRAINING beside the denial of verdict it was
    already accepted as: a run whose review never returned produced no judgment about the
    world, and a corpus that learns from it learns from the failure of its own reviewer. What
    this test refuses to let happen quietly is the exclusion arriving unnamed.

    Three observations make it a check rather than a sentence. The broken-review close is
    DRIVEN through the real gate, not constructed. Its run is NOT refused by the truncation
    guard — that arm sets no marker (P9, executed) — so the untrained set is demonstrably what
    excludes it, and deleting the membership changes the answer. And the paired control is the
    same run dir, same content, closed with a review that HOLDS: it trains, so the empty
    routing above is the review outcome and nothing else."""
    from defender.run_common import learning_refusal_gate
    from defender.runtime import scrub
    from defender.tests import _review_bundle
    from defender.tests._spec923 import ab3_deps, close, committed_verdict

    def _raises(_request):
        raise RuntimeError("the provider dropped the call")

    async def _raising_stage(request):
        return _raises(request)

    from defender.runtime.review_roles import ReviewStages

    broken_deps, broken_run = ab3_deps(tmp_path / "review-broken")
    close(broken_deps, "malicious", stages=ReviewStages(
        support=_raising_stage, ablation=_raising_stage,
        composer=_review_bundle.stage(_review_bundle.composer_reply("holds")),
    ))
    verdict = committed_verdict(broken_run)
    assert verdict == MEMBER, (
        "a review broken by the content under review did not land in the host's own verdict"
    )

    scrub.scrub(broken_run)
    assert learning_refusal_gate(broken_run, broken_run / "alert.json", truncated_by=None) is None, (
        "the broken-review run is refused by the truncation guard — then the untrained set is "
        "not what excludes it and this composition says nothing"
    )
    assert MEMBER in UNTRAINED_DISPOSITIONS
    assert directions_for(verdict) == [], (
        "the run a broken review produced still selects a training direction"
    )

    # The control: the SAME investigation, the same alert, a review that returns. It trains —
    # so the exclusion above is the review outcome and not a run dir nothing can learn from.
    held_deps, held_run = ab3_deps(tmp_path / "review-held")
    close(held_deps, "malicious", stages=_review_bundle.bundle(
        composer=_review_bundle.composer_reply("holds"),
    ))
    held_verdict = committed_verdict(held_run)
    scrub.scrub(held_run)
    assert learning_refusal_gate(held_run, held_run / "alert.json", truncated_by=None) is None
    assert directions_for(held_verdict), (
        f"the control run ({held_verdict}) trains nothing either — the contrast above is not "
        f"the review outcome"
    )


def test_every_disposition_selects_a_direction_or_declares_itself_untrained():
    """The union of every learning direction's `dispositions` is exactly the disposition enum
    minus the untrained set: every member of the vocabulary either selects a training direction
    or DECLARES itself untrained, and none does both or neither.

    This is the invariant that makes the obligation above discriminating. Adding the member to
    the enum and nowhere else breaks it, which is why a member "present in the vocabulary but
    declared nowhere else" is structurally impossible — and why the empty direction list is a
    consequence rather than the oracle.

    The last assertion is the mutation witness, in line: recomputed without the new member in
    the untrained set, the invariant FAILS. An invariant nobody has shown can fail is a claim,
    not a check, and this obligation was caught once with an oracle that could not."""
    declared = {d for direction in BY_NAME.values() for d in direction.dispositions}

    assert declared == DISPOSITION_ENUM - UNTRAINED_DISPOSITIONS
    for member in DISPOSITION_ENUM - UNTRAINED_DISPOSITIONS:
        assert directions_for(member), member
    for member in UNTRAINED_DISPOSITIONS:
        assert directions_for(member) == [], member

    assert declared != DISPOSITION_ENUM - (UNTRAINED_DISPOSITIONS - {MEMBER}), (
        "the invariant holds with the new member REMOVED from the untrained set too, so it "
        "cannot be what discriminates the change"
    )


def test_an_unknown_verdict_and_a_deliberately_untrained_one_are_distinct_states():
    """"This verdict trains nothing" and "I could not read this verdict" are DIFFERENT answers
    from the training router, and the host's own verdict is the first of them.

    THIS IS WHY THE EXCLUSION TEST ABOVE WAS VACUOUS, AND IT IS FIXED IN THE CODE RATHER THAN
    IN THE ASSERTION. `directions_for` today returns the same empty list for a member it was
    deliberately told not to train on and for a string it has never heard of — so
    `directions_for(unresolved) == []` is true on a build where M3 was never applied, true of
    a typo, and true of a run whose report was malformed. The repair those readings kept
    reaching for was a better assertion; the honest repair is that the code stops giving one
    answer to two questions. Once it does, the empty list means what it says.

    It is asserted as DISTINCTNESS rather than as a shape, because the §7-round-4 design change
    settles the requirement and not the mechanism: an implementer may raise, or return a typed
    result, or hand back a sentinel. What is not open is that a malformed or unknown verdict
    comes back looking exactly like a deliberate decision not to train — that is the same
    silent coercion the read path is losing, one layer up.

    Three states, pairwise distinct, all driven through the real router:

    * `false-positive` — the shipped deliberate exclusion. It selects nothing, and the empty
      list is a STATED decision;
    * `unresolved` — the host's verdict, which must join it. Asserting it lands on the
      *untrained* answer and not on the *unknown* one is what makes M3 observable at all, and
      it is red until the member exists;
    * a value the vocabulary does not know — a garbage string and the two malformed spellings
      of a real member — which must be distinguishable from both."""
    from defender.tests._spec923 import MALFORMED_MEMBER_SPELLINGS, NOT_A_MEMBER

    def routing(value: str) -> tuple[str, object]:
        try:
            return ("returned", sorted(d.name for d in directions_for(value)))
        except Exception as e:  # noqa: BLE001 — the refusal's TYPE is the observation
            return ("refused", type(e).__name__)

    untrained = routing("false-positive")
    assert untrained == ("returned", []), (
        f"the shipped deliberate exclusion stopped returning an empty list ({untrained}) — "
        f"this test compares the other two states against it"
    )
    trainable = routing("malicious")
    assert trainable[0] == "returned", (
        f"a trainable member did not route at all ({trainable}) — the router is broken and "
        f"every comparison below is meaningless"
    )
    assert trainable[1], (
        f"a trainable member selects no direction ({trainable}) — the router is broken and "
        f"every comparison below is meaningless"
    )

    assert routing(MEMBER) == untrained, (
        f"the host's own verdict routes as {routing(MEMBER)} where a deliberately untrained "
        f"member routes as {untrained} — a verdict that is excluded because nobody added it to "
        f"the vocabulary is not the same fact as one excluded because a person decided it "
        f"teaches nothing, and the loop cannot tell them apart"
    )

    for value in (NOT_A_MEMBER, *MALFORMED_MEMBER_SPELLINGS):
        answer = routing(value)
        assert answer != untrained, (
            f"{value!r} routes exactly like a member the corpus deliberately does not train "
            f"on ({answer}) — so `directions_for(<untrained member>) == []` says nothing about "
            f"that member, which is the fake oracle this obligation was caught on once"
        )
        assert answer != trainable, f"{value!r} selected a training direction: {answer}"
