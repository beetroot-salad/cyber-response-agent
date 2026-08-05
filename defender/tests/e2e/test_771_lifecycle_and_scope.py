"""#771 — the executable spec for the LIFECYCLE half and the scope pins: §7 D2's scan verdict
marker, the survival demands that say what must NOT move, and the mount-set premise the
hard-link non-obligation rests on.

Every test here is exactly one demand of `spec-flow/specs/spec_graph_771.yaml`, named by
that demand's `discharged_by`; the docstring carries the demand's observable-outcome prose.

WHY THE MARKER EXISTS. Demand #0 pins a refused write's planted entry as LEFT IN PLACE,
because removal is sanitizing and a deleted entry is one the reap scan can never report. X4
then refuted the premise underneath it, on an EXECUTED probe over the teardown's four-cell
input space: the scan ran in both clean-teardown cells and in NEITHER teardown-fault cell —
with nothing in flight the fault propagates but the walk still never ran, and under an
in-flight failure the fault is warned-and-swallowed AND the walk never ran. The reporter the
leave-in-place doctrine leans on is skipped on exactly the crash path most likely to be holding
what the box planted. §7 D2 converts that gap from silent to explicit: ONE verdict artifact,
written on both arms, and a tree carrying none reads as unverified.

WHERE THAT MARKER LIVES IS §7 D8, and it is the same decision as D7 one artifact over. The
verdict is a SIBLING of the tree it judges, keyed by that tree's identity — because in-tree it
was a host-side write into an attacker-owned tree the box could plant an alias at or author
outright, and the consumer rule fails closed on absence and on nothing else. Its accepted cost
is carried here too: the verdict no longer travels with the tree, so the quarantine path — the
one whose whole job is handing a tainted tree to a human — has to carry it separately or the
tree arrives unjudged.

FOUR OF §7'S SIX PROVISIONAL PINS ARE ENCODED HERE, and each is explicitly a spec-time guess
carried to the implementer as unsettled — a wrong pin is a spec bug, not an implementation bug.
The fifth (a container from an earlier run still alive when a later run dir is created) is still
NOT a test, but the reason narrowed. The probe that was standing at round three has since been
EXECUTED against a real daemon (P1-P4), and it found the outcome §7 guessed at is already the
code's behaviour for a same-named live container, and that a stale container cannot reach a
later run's tree at all. What no claim covers is still the DISCOVERY of a container running
under some OTHER name over the same tree, so the outcome stays a `form: clause` — but the cost
of never discovering one is now bounded by two facts, and those two facts are pinned here
(`test_a_live_run_dir_is_never_reused_and_a_stale_mount_never_follows_it`) rather than left
as the accident they are today.
"""
from __future__ import annotations

import contextlib
import errno
import json
import os
import shutil
import socket
import tarfile
from pathlib import Path

import pytest

from defender.runtime import box as box_mod
from defender.runtime import scrub as scrub_mod
from defender.tests.e2e._spec771 import (
    BAN_ABSENT,
    BAN_IN_FORCE,
    CENSUS,
    FORGED_IN_TREE_VERDICT_NAME,
    AliasProbeDocker,
    DockerFault,
    ban_not_in_force_error,
    drive_writer,
    outside,
    plant_hardlink,
    plant_symlink,
    quarantine_a_tainted_tree,
    read_verdict,
    run_tree,
    tree_verified,
    verdict_sidecar,
    worktree_tree,
    write_verdict,
)

pytestmark = pytest.mark.e2e

DEFENDER = Path(__file__).resolve().parents[2]


class _Recorder:
    """A recording `stop_box`/`scrub_tree` pair for driving `stop_and_scrub` directly — the
    seams the reap pair already carries as REQUIRED keyword arguments."""

    def __init__(self, *, stop_fault: BaseException | None = None):
        self.events: list[str] = []
        self._stop_fault = stop_fault

    def stop_box(self, _box, *_a, **_kw) -> None:
        self.events.append("stop")
        if self._stop_fault is not None:
            raise self._stop_fault

    def scrub_tree(self, tree: Path) -> None:
        self.events.append("scrub")
        scrub_mod.scrub(tree)


# --------------------------------------------------------------------------- #
# §7 D2 — the scan that never ran
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("in_flight", [False, True], ids=["teardown-fault", "in-flight-failure"])
def test_a_skipped_reap_scan_leaves_a_did_not_run_marker(in_flight, tmp_path):
    """skipped_scan_leaves_a_did_not_run_marker — when teardown faults and the walk is skipped,
    the tree carries a verdict recording that the scan DID NOT RUN, and the reason, on BOTH
    teardown-fault arms.

    §7 D2. Forcing the scan is not available — it requires a provably dead box, which is
    exactly what failed — so the gap is converted from silent to explicit instead. Rejected and
    recorded: failing the run outright (it escalates a teardown hiccup into a lost investigation,
    on a path where the run is already failing) and documenting without a marker (it leaves the
    most attack-relevant tree indistinguishable from a clean one).

    TWO ARMS, not one. The read of the teardown had the gap only on the in-flight path; the
    executed re-probe found the walk never ran in EITHER teardown-fault cell — with nothing in
    flight the fault still propagates, so the caller learns, but the tree is just as unscanned.
    A one-armed marker leaves half the crash paths silent."""
    tree = run_tree(tmp_path)
    before_tree = {str(p.relative_to(tree)) for p in tree.rglob("*")}
    rec = _Recorder(stop_fault=box_mod.BoxFault("teardown failed"))

    with contextlib.suppress(box_mod.BoxFault):
        box_mod.stop_and_scrub(object(), tree, stop_box=rec.stop_box,
                               scrub_tree=rec.scrub_tree, in_flight=in_flight)

    assert "scrub" not in rec.events, (
        "the walk ran after a teardown fault — the premise this demand exists for moved, and "
        "the marker is now testing nothing"
    )
    verdict = read_verdict(tree)
    assert verdict, f"the skipped scan left no verdict at {verdict_sidecar(tree)}"
    assert verdict.get("ran") is False, f"the verdict does not record the skip: {verdict}"
    assert verdict.get("reason"), "the verdict names no reason, so an operator cannot act on it"
    # §7 D8's siting, asserted on the arm that produces the marker rather than left to the
    # siting demand alone: this is the crash path, so it is the path on which an in-tree write
    # would be both most likely to matter and least likely to be noticed.
    new_in_tree = {str(p.relative_to(tree)) for p in tree.rglob("*")} - before_tree
    assert not new_in_tree, (
        f"recording the skipped scan created entries INSIDE the tree it judges "
        f"({sorted(new_in_tree)}) — the box owns that tree, so a verdict written there is one "
        f"it can plant an alias at or author outright"
    )


def test_consumers_treat_an_unmarked_tree_as_unverified(tmp_path):
    """unmarked_tree_is_treated_as_unverified — a tree carrying NO scan verdict reads as
    unverified, exactly like one whose verdict records a skip; only a tree whose verdict records
    a completed clean walk reads as verified.

    The consumer half of §7 D2, and the fail-closed direction: the marker's absence is itself
    the finding. This is also what settles the pin for a tree whose box NEVER STARTED (§7
    H10.2) without a rule of its own — that tree has no verdict, so it is unverified, which is
    the answer the pin gives.

    WHAT "VERIFIED" MEANS HERE, EXACTLY (§7 D6, and it is load-bearing). The third arm's
    `tree_verified` says THE WALK COMPLETED. It does not say the tree's contents are intact,
    and no consumer may read it that way. The scan permits any regular file, so an artifact the
    box emptied, rewrote or removed is indistinguishable from an untouched one and is observed
    by NOTHING in this change: the audit obligation is discharged against REDIRECTION only.
    Before this marker existed that loss was silent; a consumer that reads the marker as a
    contents-intact claim converts it into a certified one, which is strictly worse than no
    marker at all. Giving the obligation a real mechanism — comparing each artifact against a
    size or digest held outside the tree — was examined and rejected: it needs durable state
    outside the shared tree, which reopens NO3's refusal to re-site artifacts, and that refusal
    is what keeps this change narrow. Recorded as D6's cost, not as an oversight.

    The positive control is the third arm: without it, a consumer that called everything
    unverified would satisfy the negative and quietly strand every clean run."""
    never_started = run_tree(tmp_path / "never-started")
    assert not tree_verified(never_started), (
        "a tree whose box never started read as verified — the crash path most likely to hold "
        "what a box planted is the one that must not"
    )

    skipped = run_tree(tmp_path / "skipped")
    write_verdict(skipped, {"ran": False, "reason": "teardown faulted"})
    assert not tree_verified(skipped)

    scanned = run_tree(tmp_path / "scanned")
    scrub_mod.scrub(scanned)
    assert tree_verified(scanned), (
        "a tree the scan walked clean still reads as unverified, so every consumer is stranded"
    )


def test_the_learning_enqueue_refuses_an_unverified_tree(tmp_path, monkeypatch):
    """unmarked_tree_is_never_enqueued_for_learning — the run's real learning-enqueue step
    REFUSES a tree that carries no scan verdict and a tree whose verdict records a skip: it
    reports that it did not enqueue and leaves no marker in the queue. A tree the scan walked
    clean is enqueued as it is today.

    §7 D2'S SECOND HALF, DRIVEN AT A CONSUMER. The human's clause says every downstream
    consumer treats an unmarked tree as unverified, and until round four that half was
    discharged by one test calling the verdict predicate directly and checking it answers
    correctly. No demand required anything to CALL it — so an implementation that shipped the
    predicate and wired it nowhere passed the whole suite, which is the "document the gap
    without a marker" option D2 was chosen over, reached by another road.

    WHAT THIS PIN IS ACTUALLY FOR, STATED AGAINST THE LEDGER RATHER THAN AGAINST THE HAZARD IT
    WAS SOLD ON. D9 was argued from a live route — an unverified run reaching the learning loop
    becomes actor stories, judge findings and eventually lessons. G12's executed break attempt
    says that route is already shut: on exactly the skipped-scan cells this marker exists to
    describe, whichever exception won propagates out of the lifecycle and nothing above catches
    it, so the post-run steps are never reached and this entry point is never called with an
    unverified tree at all. The enqueue is unreachable with an unverified tree TODAY, and it is
    unreachable by accident of control flow, not by any rule.

    THIS DEMAND EXISTS SO THAT STAYS TRUE BY CONSTRUCTION. It is a tripwire for the change that
    starts CATCHING the lifecycle's fault — degrade that exception anywhere above the reap and
    the enqueue becomes reachable with an unverified tree, and this test is what fails. Read it
    as a defensive pin, not as a hole being plugged; the cost it accepts (a fifth module in play
    for the implementer) is priced accordingly.

    THIS CONSUMER, AND NOT ANOTHER, because it is the cheap one. It already reads the tree, and
    the refusal needs no new mechanism: this entry point already declines to enqueue on two
    other grounds (a truncated investigation, a held-out eval fixture), reporting False and
    saying why on stderr. An unverified tree is the third member of a set that exists.

    THE POSITIVE CONTROL IS THE THIRD ARM and it is not ceremony: a consumer that enqueued
    nothing would satisfy both refusals and silently end the learning loop, which is the failure
    mode nobody would see for weeks."""
    from defender import run_common

    state = tmp_path / "learning-state"
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(state))
    alert = tmp_path / "alert.json"
    alert.write_text('{"id": "a-771"}\n', encoding="utf-8")
    queue = state / "learn-queue"

    def queued() -> list[str]:
        # The queue's whole contents, not one expected name: every tree `run_tree` builds
        # carries the same directory name, so a per-name check would read a marker written for
        # a different arm as this arm's absence.
        return sorted(p.name for p in queue.glob("*.json")) if queue.is_dir() else []

    unmarked = run_tree(tmp_path / "unmarked")
    assert run_common.enqueue_learning(unmarked, alert) is False, (
        "a tree carrying no scan verdict was enqueued for learning — the marker is available "
        "and no consumer consults it, which is D2's clause discharged by a predicate nothing "
        "is required to call"
    )
    assert not queued(), (
        f"the enqueue reported a refusal and wrote a marker anyway ({queued()}), so the "
        f"learning loop picks the run up regardless of what the caller was told"
    )

    skipped = run_tree(tmp_path / "skipped")
    write_verdict(skipped, {"ran": False, "reason": "teardown faulted"})
    assert run_common.enqueue_learning(skipped, alert) is False, (
        "a tree whose verdict records that the walk never ran was enqueued — the crash path "
        "most likely to hold what a box planted is the one that must not feed the corpus"
    )
    assert not queued(), f"the skipped-scan tree left a marker in the queue: {queued()}"

    verified = run_tree(tmp_path / "verified")
    scrub_mod.scrub(verified)
    assert run_common.enqueue_learning(verified, alert) is True, (
        "a tree the scan walked clean was refused too, so the learning loop is starved and the "
        "two refusals above pass by the enqueue refusing everything"
    )
    assert (queue / f"{verified.name}.json").is_file(), (
        f"the enqueue reported success and left no marker in {queue}"
    )


def test_an_emptied_artifact_still_leaves_the_tree_verified(tmp_path):
    """destruction_is_not_observed_by_the_verdict — an artifact a box EMPTIED, with no alias
    anywhere, leaves a tree the scan walks clean and marks verified: nothing in this change
    observes destruction, and the verdict says the walk completed and never that the contents
    are intact.

    THIS TEST ASSERTS A WEAKNESS, DELIBERATELY. IT IS NOT A BUG AND MUST NOT BE "FIXED" TO
    EXPECT A REFUSAL. It is §7 D6's non-obligation made executable, and it reads oddly on
    purpose: the accepted loss is pinned as a PASSING test so that a future change which starts
    observing destruction fails here and has to reopen the clause deliberately, instead of the
    clause quietly drifting out of the artifact.

    WHY THE CLAUSE NEEDED A TRIPWIRE AT ALL. The audit obligation is discharged against
    REDIRECTION only. A box with code execution can always destroy what it can write, and the
    scan permits any regular file, so an emptied or rewritten artifact is indistinguishable
    from an untouched one. Carried as prose in the clause and two docstrings, that sentence was
    the only thing standing between this change and a consumer reading the verdict as a
    contents-intact claim — and that misreading is what makes the change WORSE than HEAD on
    this axis, because before the marker existed the loss was silent and a misread marker
    certifies a destroyed tree. Prose can be trimmed in review with nothing turning red.

    Giving the obligation a real mechanism — each artifact against a size or digest held
    outside the tree — was examined and rejected: it needs durable state outside the shared
    tree, which reopens NO3's refusal to re-site artifacts, and that refusal is what keeps this
    change narrow. Recorded as D6's cost, and now as a test rather than a sentence."""
    tree = run_tree(tmp_path)
    victim = tree / "alert.json"
    original = victim.read_bytes()
    assert original, "the artifact was already empty, so emptying it below changes nothing"

    victim.write_text("", encoding="utf-8")          # destruction, aliasing nothing

    scrub_mod.scrub(tree)

    assert victim.is_file(), (
        "the scan removed the emptied artifact — it is a reader, and a reader that repairs the "
        "tree is a writer no census counted"
    )
    assert victim.read_bytes() == b"", (
        "the scan restored the emptied artifact's contents, which would mean this change now "
        "holds durable state about them somewhere — reopen the clause, do not relax this"
    )
    assert tree_verified(tree), (
        "the tree with an emptied artifact reads as UNVERIFIED. If that is deliberate, this "
        "change now observes destruction and §7 D6's non-obligation is obsolete — reopen the "
        "clause and say so, rather than relaxing this assertion"
    )


def test_the_scan_verdict_lands_outside_the_tree_it_judges(tmp_path):
    """verdict_is_sited_outside_the_judged_tree — the scan's verdict lands BESIDE the tree,
    keyed by that tree's own identity, and the tree it judges gains no entry at all: the same
    siting the alias-refusal record has, for the same reason.

    §7 D8. In-tree the marker was a host-side write into an attacker-owned tree — no census
    row, no lint gate, and the project profile listed that module as a reader only, so all
    three writer instruments were blind to it at once. Two escapes follow from the siting and
    neither needs a bug: the box plants an alias at the verdict's own name (and the walk that
    would have caught the alias is precisely the walk that did not run on the crash path), or
    the box simply authors the verdict itself, because it is root on that mount and the
    consumer rule fails closed on ABSENCE and on nothing else.

    Driven on BOTH shared roots. The verdict is a property of a scanned tree, not of the run
    dir specifically, and a siting rule asserted on one root is how the drain lane ships with
    the other one — the same asymmetry F6 found for the write backstop.

    Rejected and recorded (§7 D8): censusing the in-tree writer instead, which buys the lint
    gate and the negative but leaves FORGERY untouched; and an authoritative out-of-tree record
    beside a non-authoritative in-tree copy, which is two artifacts that can disagree plus a
    precedence rule someone eventually forgets."""
    for build in (run_tree, worktree_tree):
        tree = build(tmp_path / build.__name__)
        before = {str(p.relative_to(tree)) for p in tree.rglob("*")}

        scrub_mod.scrub(tree)

        marker = verdict_sidecar(tree)
        assert marker.is_file(), (
            f"the completed walk over {tree.name} left no verdict at {marker} — a tree with no "
            f"verdict is unverified, so every clean run of this lane is stranded"
        )
        assert not marker.is_relative_to(tree), (
            "the verdict landed inside the tree it judges, which is the siting D8 rejected"
        )
        assert {str(p.relative_to(tree)) for p in tree.rglob("*")} == before, (
            f"the scan wrote into {tree.name} while judging it — the walk is a reader, and a "
            f"reader that writes is a writer no census counted"
        )
        assert tree_verified(tree), "a tree the scan walked clean still reads as unverified"


def test_a_verdict_planted_inside_the_tree_is_never_read_as_one(tmp_path):
    """in_tree_verdict_is_never_authoritative — a verdict artifact the BOX could have written
    — one sitting inside the tree, claiming a completed clean walk — does not make the tree
    read as verified; only the out-of-tree record does.

    The forgery half of §7 D8, and the reason censusing the in-tree writer was not enough. The
    consumer rule this change ships fails closed on the marker's ABSENCE; nothing fails closed
    on its PRESENCE. On the crash path the host's own marker write is the thing most likely
    not to happen, and a box-authored marker is what survives it — so a run whose scan never
    ran would read as verified on the strength of the attacker's own statement.

    The suite demonstrated the primitive before it forbade it: the consumer demand's skipped
    arm used to establish itself by hand-writing a marker into the tree.

    ITS POSITIVE CONTROL IS THE SECOND ARM, on the same tree under the complementary
    condition: with the real out-of-tree verdict present the same tree reads as verified. A
    consumer that answered "unverified" to everything would satisfy the negative alone."""
    tree = run_tree(tmp_path)
    forged = tree / FORGED_IN_TREE_VERDICT_NAME
    forged.write_text(json.dumps({"ran": True, "reason": "clean"}), encoding="utf-8")

    assert not tree_verified(tree), (
        "a verdict written INSIDE the tree was read as authoritative — the box is root on that "
        "mount, so this is the attacker certifying their own tree"
    )

    write_verdict(tree, {"ran": True, "reason": "walk completed"})
    assert tree_verified(tree), (
        "the real out-of-tree verdict does not make the tree read verified either, so the "
        "negative above passes by the consumer refusing everything"
    )
    assert forged.is_file(), "the consumer removed the planted entry — reading must not sanitize"


def test_a_quarantined_tainted_tree_carries_its_verdict_beside_the_archive(tmp_path):
    """quarantine_carries_the_verdict_out_of_band — when a tainted tree is preserved for a
    human, the verdict travels with it: the quarantine manifest beside the archive records the
    scan's verdict for that tree, and records its ABSENCE as unverified rather than omitting
    it.

    §7 D8'S ACCEPTED COST, MADE MECHANISM. The verdict no longer travels inside the tree, so a
    tree that is copied, moved or quarantined arrives with nothing attached — and #747's
    quarantine path exists precisely to hand a tainted tree to a human. The archive is a tar
    of the tree, so the marker cannot be in it: whatever moves the tree has to carry the
    verdict separately or the tree reads as unjudged at the one moment someone is reading it.
    Written as a demand rather than left in the clause because the alternative is an
    implementer discovering it after a real triage produced an unattributable tree.

    Both arms are driven, and the second is the one that fails closed: a quarantine of a tree
    with NO verdict must say so in the manifest. An absent key is indistinguishable from a
    manifest written before this field existed, which is how triage reads a skipped scan as a
    clean one.

    THE TWO ARMS SHARE ONE QUARANTINE DIRECTORY DELIBERATELY — that is the production shape,
    and it is where this demand was unsatisfiable by any correct implementation until round
    four. Each arm's manifest is read BY ITS OWN BATCH ID, the name the preserve step writes it
    under; reading "the first manifest in the directory" gave the fail-closed arm the JUDGED
    tree's manifest, so a correct implementation produced a real verdict there and the
    "invented a verdict" assertion fired on it. And the unjudged tree's premise is established
    between the taint walk and the preserve step, because the walk that taints is also the walk
    that would write a verdict — otherwise the helper judges the tree it is meant to hand over
    unjudged."""
    qdir = tmp_path / "quarantine"

    judged = run_tree(tmp_path / "judged")
    archive, doc = quarantine_a_tainted_tree(
        judged, qdir, batch_id="b-judged", verdict={"ran": True, "reason": "walk completed"})

    assert archive is not None, "nothing was preserved at all, so the rest of this is vacuous"
    assert archive.is_file(), f"the quarantine reported {archive} and wrote nothing there"
    with tarfile.open(archive) as tar:
        members = {Path(m.name).name for m in tar.getmembers()}
    assert FORGED_IN_TREE_VERDICT_NAME not in members, (
        "the verdict is inside the archive, so it was inside the tree — D8's siting is undone"
    )
    assert doc.get("verdict") == read_verdict(judged), (
        f"the quarantine manifest does not carry the tree's verdict: {doc.get('verdict')!r} — "
        f"the archive is a tar of the tree and the marker is not in the tree, so this manifest "
        f"is the only thing that can tell a human whether the tree was ever judged"
    )

    unjudged = run_tree(tmp_path / "unjudged")
    _archive, doc2 = quarantine_a_tainted_tree(unjudged, qdir, batch_id="b-unjudged")
    assert "verdict" in doc2, (
        "a tree with no verdict produced a manifest with no verdict FIELD — indistinguishable "
        "from a manifest written before the field existed, so an unjudged tree reads as one "
        "nobody thought to record"
    )
    assert not doc2["verdict"], (
        f"the manifest invented a verdict for a tree that has none: {doc2['verdict']!r}"
    )


def test_a_partial_reap_scan_failure_fails_closed_over_the_whole_tree(tmp_path):
    """partial_scan_failure_fails_closed — when the walk reclassifies some entries and then
    hits a fault, the whole tree is refused: a partially-walked tree is an unverified tree, and
    the verdict does not record a clean run.

    PINNED PROVISIONALLY (§7 H10.3) — no answerer found the design addressing a partial walk.
    The pin is fail-closed over the whole tree, consistent with the scan's existing posture:
    it already turns an unwalkable directory into a finding rather than a skipped subtree.

    The fault is induced through the walk's own `lister=` seam, which is part of the contract:
    a partial walk cannot be produced deterministically from outside, and a fault that cannot
    be induced cannot be specified (schema.md — pin the seam as a demand)."""
    tree = run_tree(tmp_path)

    def half_walk(root, **_kw):
        yield str(tree), [], ["alert.json"]
        yield str(tree), [], ["vanished.json"]      # listed, then not there to inspect

    with pytest.raises(scrub_mod.RunTainted) as e:
        scrub_mod.scrub(tree, lister=half_walk)

    assert "vanished.json" in str(e.value), "the partial walk's fault does not name the entry"
    assert read_verdict(tree).get("ran") is not True, (
        "a partially-walked tree recorded a completed scan, so a consumer reads it as verified"
    )


def test_an_entry_that_changes_shape_between_listing_and_inspection_is_refused(tmp_path):
    """entry_shape_change_mid_scan_refused — an entry that is an ordinary file when the walk
    lists it and an alias when the walk inspects it is REFUSED: the scan judges what it
    inspected, and any change between the two is itself a refusal.

    PINNED PROVISIONALLY (§7 H10.4). The pin is consistent with failing closed, and the
    alternative — judging what was listed — would let a box swap an entry inside the window and
    have the scan certify a shape that is no longer there.

    The swap is REAL: the regular file is replaced with a real `os.symlink` between the two
    steps, through the same `lister=` seam."""
    tree = run_tree(tmp_path)
    victim = tree / "report.md"
    victim.write_text("ordinary\n", encoding="utf-8")
    target = outside(tmp_path)

    def swapping_walk(root, **_kw):
        victim.unlink()
        plant_symlink(victim, target)               # the shape changes inside the window
        yield str(tree), [], ["report.md"]

    with pytest.raises(scrub_mod.RunTainted) as e:
        scrub_mod.scrub(tree, lister=swapping_walk)

    assert "report.md" in str(e.value)


def test_the_pre_first_turn_setup_writers_are_individually_guarded_in_any_order(tmp_path):
    """setup_writer_order_is_not_load_bearing — the pre-first-turn setup writers (the startup
    sentinel, the budget file and the session pointer) each refuse a planted alias on their own,
    in whatever order they run.

    PINNED PROVISIONALLY (§7 H10.1): the design does not say what order M2's probe runs in
    against these three, and the pin is that the order is NOT load-bearing because each is
    individually guarded. If any ordering IS load-bearing, this pin is wrong — and it is
    written as a per-writer property precisely so that a wrong pin fails here rather than
    silently holding through a reordering.

    THE THREE SHARE ONE TREE, in each order. Running each writer into a private run dir
    exercises three independent writers and calls the sequence an order — the arrangement
    cannot observe an ordering effect at all, because nothing the first writer does is visible
    to the second. Order is only load-bearing through shared state, so the sequence is driven
    against one tree with all three aliases planted up front, and then again reversed."""
    setup = [w for w in CENSUS if w.id in {"start_box", "budget_enforcer", "write_case_pointer"}]
    assert len(setup) == 3, "the pre-first-turn setup writer set drifted from the pin's three"

    for label, order in (("forward", setup), ("reversed", list(reversed(setup)))):
        d = tmp_path / label
        d.mkdir()
        run = run_tree(d)
        target = outside(d)
        original = target.read_bytes()
        for writer in order:
            plant_symlink(run / writer.artifact, target)

        for writer in order:
            # `drive_writer` catches BaseException and RETURNS the exception: the sentinel row
            # is driven at box startup, where its refusal is a startup fault rather than a
            # plain OSError, and an `except OSError` here errored out on exactly that row.
            refused = isinstance(drive_writer(writer, run), BaseException)
            assert target.read_bytes() == original, (
                f"{label}: {writer.id} redirected its setup write after "
                f"{[w.id for w in order[:order.index(writer)]]} ran ahead of it, so the order "
                f"IS load-bearing and the pin is wrong"
            )
            assert refused, (
                f"{label}: {writer.id} left the outside file alone but did not refuse either — "
                f"a guarded write that silently no-ops on every call (not only the aliased one) "
                f"passes the identity check above vacuously"
            )
            assert os.path.islink(run / writer.artifact), (
                f"{label}: {writer.id} removed the planted alias, so the writers that follow it "
                f"in this order meet a clean tree and the sequence proves nothing"
            )


def test_a_retry_against_a_leftover_sentinel_reports_the_ban_fault(tmp_path):
    """sentinel_retry_replaces_the_leftover — a second box start against a run dir a prior
    failed start already populated succeeds past the sentinel and reports the REAL fault, rather
    than failing on the leftover sentinel name.

    Fork R11's collision half is retired by §7 D1, and this is where that shows: the run-dir
    sentinel's name is fixed and is DELIBERATELY left behind on every fault, so it is the one
    writer where a legitimate leftover is guaranteed rather than incidental. Under a
    stage-then-rename conversion with an unpredictable staged name, the retry's own plant
    renames over the leftover and no `EEXIST` is ever reached at the destination — which is
    why the operator sees the ban fault they can act on instead of a collision they cannot."""
    run = run_tree(tmp_path)
    first = AliasProbeDocker(BAN_ABSENT)
    with pytest.raises(ban_not_in_force_error()):
        box_mod.start_box(run, DEFENDER, docker=first)
    # the sentinel is left behind by design (G10) — not asserted here; the retry below is the
    # actual demand.

    second = AliasProbeDocker(BAN_ABSENT)
    with pytest.raises(ban_not_in_force_error()) as e:
        box_mod.start_box(run, DEFENDER, docker=second)

    assert "sentinel" not in str(e.value).lower(), (
        "the retry failed on the leftover sentinel rather than on the ban, so the operator is "
        "shown the wrong fault on every retry until they clear the run dir by hand"
    )


# --------------------------------------------------------------------------- #
# what must not move
# --------------------------------------------------------------------------- #
def test_reap_scan_still_refuses_sockets_and_hard_links_under_the_ban(tmp_path):
    """scrub_refusal_set_unchanged — the reap scan's refusal set is unchanged by the ban: a
    socket and a hard link in either shared root still fail the run loudly.

    NO4 is now LOAD-BEARING rather than a boundary note (C5-fix). Under the exact deny set
    `bind(2)` on AF_UNIX SUCCEEDS and leaves a socket in the tree — executed twice,
    independently — so the socket shape is covered by the reap scan ALONE and narrowing the
    scan to match the ban's set would open it. The hard link matters for the same reason from
    the other direction: it is the shape the model's write gate is blind to (X17), so the scan
    is the only thing that catches one planted through that route.

    Both shapes are built with the real `socket.bind` and `os.link` in the test body, and both
    roots are built in their OWN shape — a run dir and a curator worktree. Two run dirs under
    different names would be one shape driven twice, which is the arrangement a claim about
    "either shared root" reads as covering and does not."""
    for tree, victim in ((run_tree(tmp_path / "run"), "gather_raw/l-001/0.json"),
                         (worktree_tree(tmp_path / "wt"), "defender/lessons/lesson-a.md")):
        sock_path = tree / "parked.sock"
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            s.bind(str(sock_path))
        finally:
            s.close()
        with pytest.raises(scrub_mod.RunTainted) as e:
            scrub_mod.scrub(tree)
        assert "parked.sock" in str(e.value)
        sock_path.unlink()

        first = tree / victim
        first.parent.mkdir(parents=True, exist_ok=True)
        if not first.is_file():
            first.write_text("[]", encoding="utf-8")
        plant_hardlink(first.with_suffix(".alias"), first)
        with pytest.raises(scrub_mod.RunTainted) as e:
            scrub_mod.scrub(tree)
        assert "alias" in str(e.value), (
            f"the walk over {tree.name} did not name the hard link it refused: {e.value}"
        )


def test_artifacts_still_land_at_their_current_paths_in_the_shared_tree(tmp_path):
    """artifact_paths_unchanged — every artifact still lands at the path it lands at today, in
    the same shared tree; nothing is re-sited out of the box's reach.

    NO3, and it is a decision rather than an omission: separating the artifacts was considered
    and rejected because the boxed agent's own tools legitimately author into that tree. So the
    tree stays shared and the ban plus the backstop are what make that safe — which means a
    quietly relocated artifact would move a writer OUT of the census the whole O1 suite is
    keyed on, and every negative over it would then pass by not applying."""
    for writer in CENSUS:
        d = tmp_path / writer.id
        d.mkdir()
        fresh = run_tree(d)
        # No alias is planted here — every writer is expected to land cleanly, so a raise is
        # a genuine failure to surface, never a subset to skip past (an over-eager guard that
        # refuses every write, aliased or not, must fail this test rather than exit the loop
        # silently on `continue`).
        writer.invoke(fresh)
        landed = fresh / writer.artifact
        assert landed.is_file(), f"{writer.id} no longer lands at {writer.artifact}"
        assert landed.resolve().is_relative_to(fresh.resolve()), (
            f"{writer.id}'s artifact was re-sited out of the shared tree (NO3)"
        )


def test_the_box_writable_mount_set_pins_the_hard_link_non_obligation(tmp_path):
    """box_writable_mount_set_pins_the_hardlink_premise — the investigation lane renders exactly
    ONE writable bind (the run dir) beside its read-only mounts and its `/tmp` tmpfs, and the
    read-only lane renders none.

    This is the premise, and only the premise, under an explicit NON-OBLIGATION. The model's
    write gate is blind to a hard link (X17/G3, refuted and executed) — but the box cannot reach
    that blindness, because `link(2)` refuses to cross a mount boundary (R6: cross-mount and
    rootfs-to-shared both `EXDEV`, within-mount succeeded). The box's only writable mount is the
    shared tree, so a hard link it creates can only alias entries already inside that tree. The
    gate's blindness is real; the route to it is not.

    The premise pinned here is the MOUNT SET, not permissions. Widening a bind, or mounting a
    parent directory read-write, would convert this from unreachable to live without touching
    any code #771 changes — and the gate would still be blind. This test is what fails loudly
    when the mount topology drifts."""
    from defender.learning.core.run_cycle import _run_cycle_box_request

    run = run_tree(tmp_path)
    rec = AliasProbeDocker(BAN_IN_FORCE)
    box_mod.start_box(run, DEFENDER, docker=rec)

    writable = [m for m in rec.mounts() if not m["readonly"]]
    assert len(writable) == 1, f"the investigation lane's writable bind set moved: {writable}"
    assert Path(writable[0]["target"]) == run, (
        "the one writable bind is no longer the run dir, so a hard link the box creates can "
        "alias something outside it"
    )
    assert rec.tmpfs(), "the /tmp tmpfs is gone; the read-only lane loses its only probe target"

    learning_run_dir = tmp_path / "learning-run"
    learning_run_dir.mkdir()
    ro = AliasProbeDocker(BAN_IN_FORCE)
    box_mod.start_box(
        _run_cycle_box_request(run_tree(tmp_path / "rc"), learning_run_dir, DEFENDER), docker=ro)
    assert not [m for m in ro.mounts() if not m["readonly"]], (
        "the read-only lane gained a writable bind — X16's premise moved"
    )


def test_a_live_run_dir_is_never_reused_and_a_stale_mount_never_follows_it(tmp_path, monkeypatch):
    """live_run_dir_never_reused_and_stale_mount_never_follows — a run directory that still
    exists is never materialized into a second time (the mint refuses and leaves the existing
    tree byte-for-byte), and the box's one writable bind is sourced at that run directory
    ITSELF, so a reference taken while it was alive resolves to the deleted tree and never to a
    fresh directory created at the same path.

    THE PREMISE, AND ONLY THE PREMISE, UNDER AN EXPLICIT NON-OBLIGATION — the same treatment
    the mount set already gets under the hard-link non-obligation, applied to the one #7 left
    open. An executed probe (P4) forced the adversarial state by hand: a container from an
    earlier run still alive, its bind mount originally over a run dir that an external cleanup
    then deleted, with a later run's directory created at the identical path. From inside that
    container the mount showed an EMPTY directory, a read of the new run's artifact returned
    'No such file or directory', and a write returned 'Directory nonexistent'. The stale
    container is not a live writer into the later run's tree.

    IT IS SAFE FOR TWO REASONS, AND NEITHER WAS BUILT FOR THIS. The first is an application
    check with an unrelated job: the run-dir mint refuses to write into a directory that still
    exists, which is the only thing that keeps a later run off a path a stale container may
    still hold — the deletion step in the probe had to be performed by hand because nothing in
    the box code performs it. The second is generic Linux: a bind mount pins the object it
    resolved, not the path string it was spelled with, so it stays on the deleted directory
    instead of following a new one into place. Meanwhile the scan's own justification for when
    it may walk a tree is that there is no live writer in it. That justification is therefore
    resting on two facts nothing in this codebase asserts, tests, or even names — which is
    exactly the shape that evaporates silently under a change nobody connects to it.

    THREE ARMS, one per way it could evaporate. An explicit-run-id retry path that skipped the
    refuse-on-exists check would put a second run inside a tree a stale container is mounted on.
    A mount type that resolved its host path lazily instead of pinning what it opened would let
    the stale container follow a recreated directory. And a bind sourced at an ANCESTOR of the
    run dir — the runs base rather than the run dir — would pin a dentry the deletion never
    removes, so the pinning would still hold and would still buy nothing. Each arm carries its
    own positive control, because every one of them is a not-observable assertion and the
    vacuous pass is a tree with nothing in it."""
    from defender import run_common

    runs = tmp_path / "runs"
    runs.mkdir()
    alert = tmp_path / "alert.json"
    alert.write_text('{"id": "a-771"}\n', encoding="utf-8")
    monkeypatch.setenv("DEFENDER_RUNS_BASE", str(runs))

    # ARM 1 — the mint refuses an id whose directory is still on disk, and touches nothing.
    first, _salt = run_common.materialize_run_dir(alert, "stale-771")
    (first / "report.md").write_text("FIRST RUN\n", encoding="utf-8")
    before = sorted(p.name for p in first.iterdir())

    with pytest.raises(SystemExit) as exit_:
        run_common.materialize_run_dir(alert, "stale-771")

    assert "already exists" in str(exit_.value), (
        f"the second mint on a live run id did not refuse on the directory's existence: "
        f"{exit_.value} — the refusal is what keeps a later run out of a tree a container from "
        f"an earlier run may still be mounted on"
    )
    assert sorted(p.name for p in first.iterdir()) == before, (
        "the refused mint still wrote into the existing tree"
    )
    assert (first / "report.md").read_text(encoding="utf-8") == "FIRST RUN\n", (
        "the refused mint overwrote the earlier run's artifact"
    )
    # The complementary condition: a FRESH id under the same base materializes, so the refusal
    # above is the existing directory and not a mint that fails on everything.
    fresh, _ = run_common.materialize_run_dir(alert, "fresh-771")
    assert fresh.is_dir(), "no run dir can be minted at all under this base"
    assert fresh != first, "a fresh id minted the same directory the refusal was about"

    # ARM 2 — a reference taken while the tree was alive is a reference to the OBJECT. This
    # re-probes the kernel rule on every run rather than pinning a one-time observation of it.
    pinned = os.open(str(first), os.O_RDONLY | os.O_DIRECTORY)
    try:
        shutil.rmtree(first)
        first.mkdir()
        (first / "report.md").write_text("SECOND RUN\n", encoding="utf-8")

        assert (first / "report.md").read_text(encoding="utf-8") == "SECOND RUN\n", (
            "the recreated tree holds nothing, so the three checks below would pass by having "
            "nothing to find — the vacuous shape this arm fails into"
        )
        assert os.listdir(pinned) == [], (
            f"the reference followed the path to the recreated directory and now lists the "
            f"later run's files: {os.listdir(pinned)}"
        )
        with pytest.raises(FileNotFoundError):
            os.open("report.md", os.O_RDONLY, dir_fd=pinned)
        with pytest.raises(FileNotFoundError):
            os.open("planted", os.O_WRONLY | os.O_CREAT, dir_fd=pinned)
    finally:
        os.close(pinned)

    # ARM 3 — the half this codebase owns: what the box actually pins.
    run = run_tree(tmp_path / "boxed")
    rec = AliasProbeDocker(BAN_IN_FORCE)
    box_mod.start_box(run, DEFENDER, docker=rec)

    argv = rec.create_argv or []
    specs = [tok for prev, tok in zip(argv, argv[1:], strict=False) if prev == "--mount"]
    assert specs, "the lane rendered no mount at all, so the two checks below look at nothing"
    assert all(s.startswith("type=bind,") for s in specs), (
        f"a box mount is no longer a bind: {specs} — a mount type that resolves its host path "
        f"lazily follows a directory recreated at that path, and the isolation this premise "
        f"rests on is gone without any code #771 touches having changed"
    )
    writable = [m for m in rec.mounts() if not m["readonly"]]
    assert len(writable) == 1, f"the writable bind set moved: {writable}"
    assert Path(writable[0]["source"]).resolve() == run.resolve(), (
        f"the writable bind is sourced at {writable[0]['source']!r} rather than at the run dir "
        f"itself — an ancestor source pins a directory the run dir's deletion never removes, so "
        f"a container from an earlier run walks straight into the later run's tree"
    )


def test_a_planted_hard_link_still_refuses_the_guarded_write(tmp_path):
    """guarded_write_refuses_a_hard_link — the guarded primitive refuses a HARD LINK planted at
    an artifact name, not only a symlink: the aliased file outside the tree keeps its bytes.

    `O_NOFOLLOW` does not help here — B9 executed it: a hard link defeats it entirely, the open
    succeeds and truncates the aliased file. So the primitive's refusal has to come from the
    link count rather than from the open flag, and a spec that pinned only the symlink shape
    would ship a primitive that is green on every symlink test and blind on the shape the
    model's own gate is already blind to.

    THE TOLERATED ERRNO SET IS THE TWO A LINK-COUNT REFUSAL CAN PRODUCE. `ELOOP` was in it and
    is now out: `ELOOP` is what `O_NOFOLLOW` raises when it meets a SYMLINK, and B9's whole
    finding is that a hard link never reaches that path — the open succeeds. Admitting it made
    the assertion tolerate an implementation that could only have refused for a reason this
    plant cannot cause, which is a symlink-shaped guard passing a hard-link test."""
    run = run_tree(tmp_path)
    target = outside(tmp_path)
    original = target.read_bytes()
    planted = plant_hardlink(run / "report.md", target)

    with pytest.raises(OSError) as e:  # noqa: PT011 — the errno is asserted immediately below
        write_guarded_hardlink_arm(planted)

    assert e.value.errno in (errno.EEXIST, errno.EMLINK), (
        f"the refusal did not come from the link-count check: errno={e.value.errno} — under a "
        f"hard-link plant `O_NOFOLLOW` does not fire at all (B9), so an ELOOP here would mean "
        f"the primitive refused for a reason this plant cannot produce"
    )
    assert target.read_bytes() == original, "the guarded write truncated through the hard link"
    assert os.lstat(target).st_nlink == 2, "the refusal unlinked the plant (sanitizing)"


def write_guarded_hardlink_arm(path: Path) -> None:
    """Drive the guarded primitive at `path` — split out so the demand's test body reads as
    one assertion about one observable."""
    from defender.tests.e2e._spec771 import write_guarded

    write_guarded(path, "REDIRECTED\n")


def test_the_box_start_fault_removes_the_container_it_created(tmp_path):
    """box_start_fault_reaps_its_container — a box whose ban probe failed is removed rather than
    left running, so a faulted start leaks no container holding the shared tree open.

    R3's sentinel-mismatch precedent, inherited: a bad in-box observation already raises and
    `rm -f`s the container. The ban probe is the second observation of that shape, and a leaked
    container is the one way a startup fault can still leave a live writer on the tree the
    verdict marker has just recorded as unscanned."""
    rec = AliasProbeDocker(BAN_ABSENT)
    with pytest.raises(ban_not_in_force_error()):
        box_mod.start_box(run_tree(tmp_path), DEFENDER, docker=rec)

    assert any(a[:3] == ["docker", "rm", "-f"] for a in rec.calls), (
        "the faulted start left its container running"
    )


def test_a_teardown_fault_under_an_in_flight_failure_still_reports_both(tmp_path):
    """teardown_fault_reports_both_causes — when teardown faults while an exception is already
    in flight, the in-flight failure still reaches the caller AND the teardown fault is
    recorded rather than lost.

    X4's executed probe found this cell silent on BOTH counts: the fault is warned-and-swallowed
    and the walk never runs. §7 D2's verdict marker fixes the second half; this demand pins the
    first, because a swallowed teardown fault is how a leaked box becomes invisible.

    THE IN-FLIGHT FAILURE IS REAL HERE, not a flag. `in_flight=True` is what the caller passes
    to say an exception is already propagating, and passing it with nothing actually in flight
    exercises the branch while observing only half the guarantee: "the in-flight failure still
    reaches the caller" is unfalsifiable when there is no failure to reach anyone. The reap
    pair is therefore driven where production drives it — from a `finally` under a real
    exception — so the demand's first clause has something to be true OF."""
    tree = run_tree(tmp_path)
    rec = _Recorder(stop_fault=box_mod.BoxFault("teardown failed while a run error was in flight"))
    in_flight_failure = RuntimeError("the investigation itself failed")

    escaped: BaseException | None = None
    try:
        try:
            raise in_flight_failure
        finally:
            box_mod.stop_and_scrub(object(), tree, stop_box=rec.stop_box,
                                   scrub_tree=rec.scrub_tree, in_flight=True)
    except BaseException as e:  # noqa: BLE001 — WHICH exception escapes is the observable
        escaped = e

    assert escaped is in_flight_failure, (
        f"the run's own failure did not reach the caller: {escaped!r} — the work's own error "
        f"is the more informative signal, and a teardown BoxFault raised on top of it replaces "
        f"the reason the run was already dying with a complaint about the box"
    )
    assert "stop" in rec.events, "the teardown never ran, so nothing could have faulted"
    verdict = read_verdict(tree)
    assert verdict.get("ran") is False, (
        f"the swallowed teardown left no did-not-run verdict on the tree: {verdict}"
    )
    assert "teardown" in str(verdict.get("reason", "")).lower(), (
        f"the swallowed teardown fault left no trace of its cause: {verdict}"
    )


def test_a_faulted_box_create_leaves_a_verdict_on_the_tree_it_touched(tmp_path):
    """faulted_create_marks_its_tree — a box whose creation faulted leaves a VERDICT ARTIFACT on
    the tree it had already touched: the marker is present, records that the scan did not run,
    and names the reason — and the tree therefore reads as unverified.

    The tree of a box that never started, pinned under §7 D2's marker rather than a rule of its
    own (§7 H10.2). It matters because the host has already written into that tree before the
    box exists — the sentinel plant is host-side and lands before the create is confirmed.

    THE MARKER'S PRESENCE IS THE DEMAND, not the tree's unverified reading. Asserting only
    `not tree_verified(...)` is satisfied by no verdict existing at all — i.e. by the sibling
    demand's absence-means-unverified rule, which was already true before this demand was
    written. A pin that discharges to a rule that already held reads as confirmed without
    having been tested, and this is one of the six provisional pins carried to the implementer
    as unsettled, so a false confirmation here is expensive.

    WHAT THE MARKER DOES NOT SAY (§7 D6): `ran: false` here records that the walk never
    happened. Even `ran: true` would only record that the walk COMPLETED — never that the
    tree's contents are intact. Nothing in this change observes an artifact a box emptied,
    rewrote or removed."""
    run = run_tree(tmp_path)
    rec = AliasProbeDocker(BAN_IN_FORCE,
                           create=DockerFault(rc=1, stderr="no such image\n", cite="R3"))

    with pytest.raises(box_mod.BoxFault):
        box_mod.start_box(run, DEFENDER, docker=rec)

    verdict = read_verdict(run)
    assert verdict, (
        f"a faulted create left no verdict at {verdict_sidecar(run)} for the tree the host had "
        f"already written into — this demand would then discharge to the absence rule its "
        f"sibling already pins, and the provisional pin reads as confirmed untested"
    )
    assert verdict.get("ran") is False, f"the verdict does not record the skip: {verdict}"
    assert verdict.get("reason"), (
        "the verdict names no reason, so an operator meeting this tree cannot tell a faulted "
        "create from any other unscanned tree"
    )
    assert not tree_verified(run), (
        "a tree whose box never started reads as verified — the fail-closed default D2 sets"
    )
