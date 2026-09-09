"""#1007 — N4/M9: honest counts, and what the review still rejects after M1 lands.

M1 makes reachability a measurement rather than an inference, and N4 splits a count that today
conflates the envelope's own hits with the door's. The consequence for `_rejection` is
asymmetric and that asymmetry is the demand set: the INJECTION branch retires (a world whose
envelope retrieves no injection is now recorded as unreachable, not rejected), while the patch,
contradiction and zero-exclusion branches survive unchanged.

Every survival test here is red-first in the other direction from most of this suite: it fails
if the implementer removes MORE than the one branch the design retires.
"""
from __future__ import annotations


from defender.tests import _world_1007 as W


def world_of(ov: dict, label: str = "b"):
    return W.mod("runtime.branch._family").parse_world(W.world_doc(label, ov=ov))


CLEAN_CONSISTENCY = {"mismatches": [], "control_mismatch_keys": []}


def contradicting_consistency() -> dict:
    verdict = W.mod("learning.branch.comparator").Verdict
    return {"mismatches": [{"key": "k1", "verdict": verdict.CONTRADICTION.value}],
            "control_mismatch_keys": []}


def test_injected_retrieved_is_the_envelopes_own_hits_and_present_is_the_door_count(
        tmp_path, monkeypatch):
    """`injected_retrieved` counts what the ENVELOPE returned; `injected_present` counts what
    the corpus HOLDS. Two facts, two fields.

    Observably true: a world that injected three documents into a corpus whose discriminating
    envelope returns one of them records `injected_present: 3` and `injected_retrieved: 1`.
    Today one number carries both readings, so "the envelope could not see it" and "staging
    never wrote it" are indistinguishable — and they are repaired differently.

    What failure looks like: the split is cosmetic, both fields hold the same number, and the
    record still cannot say whether the staging door or the discriminator is at fault.
    """
    review = W.mod("learning.branch.review")
    family_mod = W.mod("runtime.branch._family")
    _base, _src, root = W.configured_layout(tmp_path, monkeypatch)
    injected = [{"_id": f"i{n}", "host": {"name": f"h{n}"}} for n in range(3)]
    doc = W.family_doc(worlds=[
        W.base_world(),
        W.world_doc("b", ov=W.overlay(elastic=W.elastic_overlay(inject=injected)))])
    ep = W.episode(tmp_path, doc=doc, root=root)
    W.base_capture(ep, [W.captured_row(key="k1")])

    record = review.review(
        family_mod.parse_family(doc), episode_dir=ep,
        adapters=W.FakeAdapters({("elastic", "esql"): {"hits": [injected[0]]},
                                 ("elastic", "query"): {"hits": [injected[0]]}}),
        door=W.FakeDoor(counts={f"wv-{W.world_token('b')}-logs": 3}),
        invoke=W.FakeAgent("same"))

    block = record["worlds"]["b"]["reachability"]
    assert block["injected_present"] == 3, (
        f"injected_present is {block.get('injected_present')!r} for three staged documents")
    assert block["injected_retrieved"] == 1, (
        f"injected_retrieved is {block.get('injected_retrieved')!r} for an envelope that "
        "returned one of them — the two readings are still one number")


def test_a_world_whose_envelope_retrieves_no_injection_is_no_longer_rejected(tmp_path):
    """The INJECTION rejection branch retires: an unreachable injection is RECORDED, not fatal.

    Observably true: a world declaring an injection whose envelope ran and retrieved none of it
    is ACCEPTED, and the fact lands on its reachability block instead. Rejecting ended the
    whole episode before siblings ran, for a reading that M1 now measures properly and O4's
    ladder now acts on.

    What failure looks like: the branch survives. Every world whose discriminator is slightly
    off costs the entire episode, and the withholding ladder this change adds is never reached
    for exactly the population it was built for.
    """
    review = W.mod("learning.branch.review")
    world = world_of(W.overlay(elastic=W.elastic_overlay(inject=[{"_id": "i1"}])))
    block = W.reachability_block(envelope_ran=True, injected_retrieved=0, injected_present=1,
                                 patched_visible=False, exclusion_matches=None)

    reason = review._rejection(world, consistency=CLEAN_CONSISTENCY, reachability=block)

    assert reason is None, (
        f"an unreachable injection still rejects the world: {reason!r}")


def test_the_patch_rejection_branch_still_rejects(tmp_path):
    """SURVIVAL: the PATCH branch still rejects.

    Observably true: a world whose patches apply to nothing the envelope returned is still
    rejected — and under H1 `patched_visible` now means the merged CONTENT differs, so more
    worlds reach this branch than before, not fewer. Its positive control is that a world whose
    patch IS visible is accepted.

    What failure looks like: the injection branch's retirement is applied to the whole
    reachability arm, and a world whose declared difference is a patch that lands nowhere runs
    a full sibling investigation for nothing.
    """
    review = W.mod("learning.branch.review")
    world = world_of(W.overlay(patches={"identity": {"canary-1": {"owner": "sib"}}}))

    invisible = review._rejection(
        world, consistency=CLEAN_CONSISTENCY,
        reachability=W.reachability_block(envelope_ran=True, patched_visible=False,
                                          exclusion_matches=None))
    visible = review._rejection(
        world, consistency=CLEAN_CONSISTENCY,
        reachability=W.reachability_block(envelope_ran=True, patched_visible=True,
                                          exclusion_matches=None))

    assert invisible is not None, "a patch that applies to nothing no longer rejects"
    assert visible is None, "the control failed — a visible patch is being rejected"


def test_contradiction_and_zero_exclusion_rejections_survive(tmp_path):
    """SURVIVAL: the CONTRADICTION and ZERO-EXCLUSION branches still reject.

    Observably true: a world whose replayed answer contradicts the capture is rejected, and so
    is one whose exclusion predicate matches zero base documents — while an unanswerable
    exclusion count (`exclusion_count_failed`) is NOT, because a count nobody could ask has not
    been shown to remove nothing. All three readings are unchanged by this issue.

    What failure looks like: the `_rejection` ladder is rewritten around the new reachability
    fields, and the two branches that have nothing to do with reachability are lost in the
    rewrite — so a world that contradicts the corpus runs as a counterfactual of it.
    """
    review = W.mod("learning.branch.review")
    world = world_of(W.overlay(elastic=W.elastic_overlay(inject=[{"_id": "i1"}])))
    excluder = world_of(W.overlay(elastic=W.elastic_overlay(
        inject=[], exclude={"match_all": {}})), label="c")

    contradiction = review._rejection(
        world, consistency=contradicting_consistency(),
        reachability=W.reachability_block(envelope_ran=True, exclusion_matches=None))
    zero_exclusion = review._rejection(
        excluder, consistency=CLEAN_CONSISTENCY,
        reachability=W.reachability_block(envelope_ran=True, exclusion_matches=0,
                                          exclusion_count_failed=False))
    unanswerable = review._rejection(
        excluder, consistency=CLEAN_CONSISTENCY,
        reachability=W.reachability_block(envelope_ran=True, exclusion_matches=None,
                                          exclusion_count_failed=True))

    assert contradiction is not None, "a contradicting world is no longer rejected"
    assert zero_exclusion is not None, "an exclusion matching zero documents no longer rejects"
    assert unanswerable is None, (
        "an unanswerable exclusion count now rejects — an outage is being charged to the world")


def test_the_review_admits_a_world_that_is_unreachable_by_capture(tmp_path, monkeypatch):
    """The review ADMITS a world the capture cannot reach — that is the ladder's input, not a
    rejection.

    Observably true: a world with `reachable_by_capture: false` runs, its `decision` is
    `accepted`, and the episode is not ended. The positive control rides with it: a world that
    contradicts the capture on the same drive IS still rejected, so this is a fact about the
    new reading rather than about a review that stopped rejecting anything.

    What failure looks like: `reachable_by_capture: false` is wired into `_rejection` as a
    fifth reason. Every episode whose worlds the capture happened not to address is then killed
    before any sibling runs, and the withholding ladder — the entire point of O4 — is dead code.
    """
    review = W.mod("learning.branch.review")
    family_mod = W.mod("runtime.branch._family")
    _base, _src, root = W.configured_layout(tmp_path, monkeypatch)
    doc = W.family_doc(worlds=[
        W.base_world(),
        W.world_doc("b", ov=W.overlay(elastic=W.elastic_overlay(inject=[{"_id": "i1"}])))])
    ep = W.episode(tmp_path, doc=doc, root=root)
    W.base_capture(ep, [W.captured_row(key="k1")])

    record = review.review(
        family_mod.parse_family(doc), episode_dir=ep,
        adapters=W.FakeAdapters({("elastic", "query"): {"hits": [{"_id": "i1"}]},
                                 ("elastic", "esql"): {"hits": [{"_id": "i1"}]}}),
        door=W.FakeDoor(counts={f"wv-{W.world_token('b')}-logs": 1}),
        invoke=W.FakeAgent("same"))

    entry = record["worlds"]["b"]
    assert entry["reachability"]["reachable_by_capture"] is False, (
        "this drive did not produce the unreachable-by-capture state it is about")
    assert entry["decision"] == review.ACCEPTED, (
        f"a world unreachable by the capture was {entry['decision']}: {entry.get('reason')!r}")
    assert record["episode"]["decision"] == review.ACCEPTED
