"""#870 M8 — the partition follows the handoff, and what the tick tells a human.

Every test here is one demand of `spec-flow/specs/spec_graph_870.yaml`, named after that
demand's `discharged_by` pointer and carrying its prose in its docstring. The seam contract
lives in `defender/tests/_declared870.py`.

Today the curated set is `row.system in kept` and a reducer row has no system (C18/C9's row
`s1`, executed), so a taught reducer row is buried on the tick that taught it. FK-7 makes the
criterion ASYMMETRIC — system rows keep `kept`-membership, a shim row is curated only when a
reducer handoff was emitted AND the commit's changed set contains the reducer literal.

WHICH SEAM CARRIES THAT CONDITION IS FORK F3 AND IS NOT PINNED HERE. Every demand below
observes `run_pitfalls`' own outputs — the queue file, the consumed ledger, the deadletter,
the commit, the log — so the implementer keeps F3's choice between passing the handoff list,
a flag, or a builder-computed id set into `_split_batch_by_membership`.

TWO DEMANDS BELOW ARE THE ROUND'S REVIEW, NOT ITS ORIGINAL SPEC, and they bound the two ends
FK-7 left open:

* `an_unoffered_reducer_edit_is_refused` — FK-7 asked what a handoff MEANS for rotation and
  the M7 literal allowance answered a different question: the reducer surface became writable
  on every tick, including one whose batch held no reducer row. The offer now gates the COMMIT
  as well as the partition.
* `a_perpetually_declined_hold_retires_at_the_ceiling` — FK-7's hold ("neither rotated nor
  graveyarded") had no exit, so a row the curator can never teach re-spawned the curator agent
  every drain pass forever. The hold keeps its meaning and gains the same
  `author_max_attempts()` ceiling every other exit from this queue already had.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from defender.learning.core import drains, persist
from defender.learning.core.config import LoopPaths
from defender.learning.leads import pitfalls_curator
from defender.learning.leads.lead_extraction import LeadAuthorError
from defender.tests._declared870 import (
    PITFALLS_SECTION,
    REDUCER_REL,
    Spawn,
    by_surface,
    commit_all,
    consumed_by_id,
    curate_execution_md,
    curate_reducer_surface,
    edits,
    git,
    graveyard_by_id,
    head_files,
    loop_log,
    pitfall_row,
    queue_ids,
    seed_tree,
    shim_row,
    write,
    write_reducer_surface,
)

ELASTIC_MD = "defender/skills/elastic/execution.md"


@pytest.fixture
def scene(tmp_path: Path, monkeypatch):
    """A committed worktree carrying the reducer surface, and a `LoopPaths` over state kept
    OUTSIDE it — a queue file inside the repo would read to the corpus-scope walk as a stray.

    The threshold is set to 1 so these demands are about the PARTITION rather than about the
    gate; FK-3's gate has its own file.
    """
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "1")
    repo = seed_tree(tmp_path, adapters=("elastic", "cmdb"), markers=("elastic",),
                     skills=("elastic",), catalog=(), non_systems=("gather",))
    write_reducer_surface(repo)
    commit_all(repo, "seed the reducer surface")
    return repo, LoopPaths(repo_root=repo, state_dir=tmp_path / "state")


def _shim_batch(paths, n: int = 3) -> list[str]:
    """N rows behind ONE reducer mistake — the l-003 shape, which is what a real reducer
    batch looks like. Appended through the production appender, into the real queue file."""
    rows = [shim_row(f"r:l-003:{i}") for i in range(n)]
    persist.append_pitfalls(rows, paths=paths)
    return [r["pitfall_id"] for r in rows]


# FK-7 — a handoff is an OFFER; only a confirmed edit is curation.


def test_a_taught_reducer_row_is_consumed_not_retired(scene):
    """On a tick that emits a reducer handoff AND whose curator's commit actually changes the
    reducer literal, the shim rows behind it rotate as `consumed_committed` carrying the
    commit sha, and appear in NO deadletter entry.

    Today they land in `dropped_ids`, because the curated set is computed as
    `row.system in kept` and a reducer row has no system (C18/C9's row `s1`, executed): taught
    on the same tick it was buried, and stamped with a sha of a commit that contains nothing
    about them.

    FK-7's criterion is ASYMMETRIC and this is its positive arm: the handoff AND the confirmed
    edit. The no-edit half is `a_no_edit_reducer_tick_holds_its_rows`' own arm, and it is that
    demand's positive control.
    """
    repo, paths = scene
    ids = _shim_batch(paths)
    spawn = Spawn(curate_reducer_surface())
    head_before = git(repo, "rev-parse", "HEAD").stdout.strip()

    assert pitfalls_curator.run_pitfalls(paths=paths, invoke=spawn) == 0
    assert by_surface(spawn.handoffs)["reducer"], "no reducer handoff, so the arm is vacuous"
    # THIS TICK's commit, not HEAD's file list: the fixture seeds the reducer surface in its
    # own commit, so `REDUCER_REL in head_files(repo)` is true from the seed whenever the tick
    # commits nothing at all — the assertion would hold on a build that never wrote the file.
    assert git(repo, "rev-parse", "HEAD").stdout.strip() != head_before, (
        "the curator's edit never reached a commit"
    )
    assert REDUCER_REL in head_files(repo), "the tick committed, but not the reducer surface"

    consumed = consumed_by_id(paths)
    assert set(consumed) == set(ids)
    for pid in ids:
        assert consumed[pid]["consumed_category"] == "consumed_committed"
        assert consumed[pid]["consumed_commit"], "a taught row carries no provenance"
    assert graveyard_by_id(paths) == {}, "a taught row reached the deadletter"
    assert queue_ids(paths) == []


def test_a_no_edit_reducer_tick_holds_its_rows(scene):
    """A tick that emits a reducer handoff but whose curator declines to edit leaves the shim
    rows behind it STILL IN THE QUEUE afterwards — neither `consumed_committed` nor
    `consumed_unattributable`, and in no deadletter entry.

    `lead_pitfalls.md`'s "skip that failure; never invent one" rule makes a no-edit outcome
    legitimate, and PO-R2 shows the batch most likely to produce one — silent reducer failures
    carrying no diagnosis. A handoff alone is not curation; only a confirmed edit is. Without
    this arm a reducer row would be discarded on the tick it was merely OFFERED, before
    anything was taught, and its queue row is the only record of the mistake that any test
    here demonstrates — the graveyard's unreadness is NOT shown by this suite; it is the
    clause demand `graveyard_is_still_unread`'s recorded deferral, open until #903 lands.

    Every surface the row could have left through is bound, because a row that vanished
    quietly would satisfy a negative asserted on one of them: the queue HOLDS it, the consumed
    ledger does not have it, the deadletter does not have it, and nothing was committed.
    `a_taught_reducer_row_is_consumed_not_retired` is the positive control on the same
    address.

    THE SECOND ARM IS THE DISCRIMINATING ONE, AND IT IS THE LIKELIER TICK. FK-7's criterion is
    a CONJUNCTION — a reducer handoff emitted AND the commit's changed set containing the
    reducer literal — and an arm that fails both conjuncts together cannot tell it apart from
    the loose reading "a handoff was emitted and the tick committed something". So the second
    arm commits: a mixed batch where the curator teaches a declared system's `execution.md`
    and SKIPS the reducer entry, which `lead_pitfalls.md`'s "skip that failure; never invent
    one" rule makes a first-class outcome and PO-R2 makes frequent (an undiagnosable reducer
    failure is exactly what a curator should decline to guess at). Under the loose reading the
    shim rows rotate as `consumed_committed` carrying ELASTIC's sha — a sha of a commit that
    contains nothing about them, which is verbatim the data loss FK-7 was resolved to close,
    on the one record the mistake ever produced.
    """
    repo, paths = scene
    ids = _shim_batch(paths)
    head_before = git(repo, "rev-parse", "HEAD").stdout.strip()
    spawn = Spawn(None)

    assert pitfalls_curator.run_pitfalls(paths=paths, invoke=spawn) == 0
    assert by_surface(spawn.handoffs)["reducer"], "the offer was never made"

    assert queue_ids(paths) == ids, "the rows were consumed on a tick that taught nothing"
    assert consumed_by_id(paths) == {}
    assert graveyard_by_id(paths) == {}
    assert git(repo, "rev-parse", "HEAD").stdout.strip() == head_before, (
        "the tick committed something on a tick whose curator declined to edit"
    )

    # The second conjunct alone: a handoff WAS emitted, a commit DID land, and the reducer
    # literal is absent from its changed set.
    persist.append_pitfalls([pitfall_row("r:l-000:0", "elastic")], paths=paths)
    taught_elsewhere = Spawn(curate_execution_md("elastic"))
    assert pitfalls_curator.run_pitfalls(paths=paths, invoke=taught_elsewhere) == 0

    surfaces = by_surface(taught_elsewhere.handoffs)
    assert surfaces["reducer"], "the reducer entry was never offered on the mixed tick"
    assert git(repo, "rev-parse", "HEAD").stdout.strip() != head_before, (
        "nothing was committed, so this arm cannot see the second conjunct"
    )
    assert head_files(repo) == [ELASTIC_MD]
    assert REDUCER_REL not in head_files(repo)

    consumed = consumed_by_id(paths)
    assert consumed_by_id(paths).get("r:l-000:0", {}).get("consumed_category") == (
        "consumed_committed"
    ), "the system row that WAS taught must still be consumed — this arm is not a dead tick"
    for pid in ids:
        assert pid not in consumed, (
            f"{pid} was consumed on a tick that committed someone else's lesson — it now "
            f"carries a sha of a commit containing nothing about it"
        )
        assert pid not in graveyard_by_id(paths)
    assert set(queue_ids(paths)) == set(ids)


def test_an_unoffered_reducer_edit_is_refused(scene):
    """A tick whose batch holds NO reducer row may not commit the reducer surface, even though
    the path is in the lane's vocabulary.

    M7 opened `REDUCER_REL` as ONE literal allowance in `_pitfalls_path_rule`, and a path rule
    is a constant of the deployment: it admitted the surface on every tick. But the curator's
    static prompt names that path unconditionally, and every failure's `stderr_digest` —
    alert-derived text — is in its context. So on a pure `elastic` batch a digest carrying
    "also record this in <the reducer surface>" was obeyable, admitted by the gate on the
    literal, and INVISIBLE to FK-7, which computes `reducer_taught` from the offer and
    therefore sees none. The write landed on the one file EVERY system's reduce reads before
    EVERY attempt. Before this round the same path was refused outright, so the round opened
    it wider than the lesson it exists to teach.

    "May the lane ever write this path" and "was this tick offered it" are different questions
    and the second is a fact about the BATCH, which is why the path rule's own verdict is
    unchanged and asserted so below.

    The positive control is the same curator, the same edit, one shim row added to the queue.
    """
    repo, paths = scene
    persist.append_pitfalls([pitfall_row("r:l-000:0", "elastic")], paths=paths)
    head_before = git(repo, "rev-parse", "HEAD").stdout.strip()
    overreach = Spawn(edits(curate_execution_md("elastic"), curate_reducer_surface()))

    with pytest.raises(LeadAuthorError, match="offered no reducer handoff"):
        pitfalls_curator.run_pitfalls(paths=paths, invoke=overreach)

    assert not by_surface(overreach.handoffs)["reducer"], (
        "the batch offered the reducer surface after all, so the demand is vacuous"
    )
    assert git(repo, "rev-parse", "HEAD").stdout.strip() == head_before, (
        "the unoffered reducer edit reached a commit"
    )
    # The PATH rule's verdict is untouched: the literal is still in the lane's vocabulary, and
    # what refused this tick is the offer, not the path.
    assert pitfalls_curator._pitfalls_path_rule(
        " M", REDUCER_REL, systems=frozenset({"elastic", "cmdb"}),
    ) is None

    # Positive control: one shim row makes the offer, and the identical edit now commits.
    _shim_batch(paths, n=1)
    offered = Spawn(edits(curate_execution_md("elastic"), curate_reducer_surface()))
    assert pitfalls_curator.run_pitfalls(paths=paths, invoke=offered) == 0
    assert by_surface(offered.handoffs)["reducer"]
    assert REDUCER_REL in head_files(repo), "the offered edit was refused too"


def test_a_perpetually_declined_hold_retires_at_the_ceiling(scene, monkeypatch):
    """A held reducer row survives being declined, and being declined again, and then LEAVES —
    on the same `author_max_attempts()` ceiling every other exit from this queue rides on.

    FK-7 made a no-edit reducer tick a first-class outcome and left the rows in the queue,
    which is right: `lead_pitfalls.md`'s "skip that failure; never invent one" makes declining
    a correct answer, and PO-R2 makes the undiagnosable reduce the frequent shape. What the
    hold had no version of was an EXIT. The row satisfied the arrival gate on its own
    occurrences, was offered, was declined, and came back byte-identical: the wake gate stayed
    open, `attempts` was never bumped by anything, and the drain re-spawned an LLM curator on
    every pass with nothing to show for it and no operator signal beyond "held for a later
    tick". Every other route out of this queue is bounded — `consumed_committed` on a taught
    row, `consumed_unattributable` plus the graveyard on an undeclared name, the `batch-error:`
    ceiling on a faulting batch — and the hold was the one that was not.

    So the ceiling is what this pins, and the HOLD is what it does not touch: the row is still
    there after the first decline and after the second, which is `a_no_edit_reducer_tick_holds_
    its_rows`' demand and stays true. The attempt is spent only on a tick that actually made
    the offer.
    """
    monkeypatch.setenv("LEARNING_AUTHOR_MAX_ATTEMPTS", "3")
    repo, paths = scene
    ids = _shim_batch(paths)

    for tick in (1, 2):
        assert pitfalls_curator.run_pitfalls(paths=paths, invoke=Spawn(None)) == 0
        assert queue_ids(paths) == ids, f"the hold did not survive tick {tick}"
        assert [
            r.get(pitfalls_curator.OFFERS_DECLINED_KEY) for r in persist.read_pitfalls(paths)
        ] == [tick] * len(ids), f"the declined offer was not counted on tick {tick}"
        assert graveyard_by_id(paths) == {}, f"the row retired early, on tick {tick}"

    assert pitfalls_curator.run_pitfalls(paths=paths, invoke=Spawn(None)) == 0
    assert queue_ids(paths) == [], "the queue never drains, so the curator re-spawns forever"
    grave = graveyard_by_id(paths)
    assert set(grave) == set(ids)
    for pid in ids:
        assert grave[pid]["deadletter_reason"] == pitfalls_curator.HELD_CEILING_REASON, (
            "the retirement is filed as a fault, but the tick worked and the curator declined"
        )
    # Conserved, not merely gone: the retirement is terminal through the channel's own ledger.
    assert {
        pid: consumed_by_id(paths)[pid]["consumed_category"] for pid in ids
    } == {pid: "consumed_retired" for pid in ids}
    assert repo.is_dir()


def test_a_faulting_tick_does_not_spend_the_offer_budget(scene, monkeypatch):
    """The hold's ceiling counts DECLINES. A tick that raised is not a decline, and must not
    bring a row any closer to retiring as `reducer-offered-never-taught`.

    The ceiling above was first written on `drain.retire`'s default `attempts`, which is the
    lane's FAULT counter — `drains._retire_pitfalls_batch` bumps it for every row in the batch
    on any tick that raised, whether or not that row was ever offered anything. One counter
    serving both ceilings makes each arrive early in the other's traffic, and the direction
    that bites is this one: two infra-faulting ticks spend a freshly-queued row's whole offer
    budget, so its FIRST decline retires it terminally with its lesson never taught. That is
    verbatim the loss FK-7's hold exists to prevent, reintroduced by the bound meant to
    complete it — and it is invisible in the ceiling demand above, whose ticks all decline.

    So the two counters are driven apart here: faults accumulate on `attempts` while the offer
    budget stays untouched, and the row still gets its full complement of declines afterwards.
    The converse (a decline not spending the fault budget) rides on the same separation.
    """
    monkeypatch.setenv("LEARNING_AUTHOR_MAX_ATTEMPTS", "3")
    _repo, paths = scene
    ids = _shim_batch(paths, n=1)

    def _faulting(_paths, box=None):
        raise ImportError("the curator module vanished mid-tick")

    for tick in (1, 2):
        drains._drain_pitfalls(paths, _faulting)
        assert queue_ids(paths) == ids, f"the faulting tick {tick} retired the row early"
    rows = persist.read_pitfalls(paths)
    assert [r.get("attempts") for r in rows] == [2], "the fault counter did not move"
    assert [r.get(pitfalls_curator.OFFERS_DECLINED_KEY) for r in rows] == [None], (
        "a tick that never offered the row spent its offer budget"
    )

    # The row now gets its FULL complement of declines — the third is what retires it, not the
    # first riding on two unrelated faults.
    for tick in (1, 2):
        assert pitfalls_curator.run_pitfalls(paths=paths, invoke=Spawn(None)) == 0
        assert queue_ids(paths) == ids, f"the row retired on decline {tick} of 3"
        assert [
            r.get(pitfalls_curator.OFFERS_DECLINED_KEY) for r in persist.read_pitfalls(paths)
        ] == [tick]
        assert graveyard_by_id(paths) == {}

    assert pitfalls_curator.run_pitfalls(paths=paths, invoke=Spawn(None)) == 0
    assert queue_ids(paths) == [], "the offer ceiling stopped bounding the hold"
    assert set(graveyard_by_id(paths)) == set(ids)


def test_a_reducer_only_batch_still_reaches_the_curator(scene):
    """A batch whose every row is a systemless `∅.bash-shim` row REACHES the curator: handoffs
    is non-empty (one reducer entry), so `run_pitfalls` does not take the `not handoffs` arm
    that retires the batch unread.

    That arm is correct only when nothing could ever be taught, and at this base it is the arm
    a reducer-only batch takes — every systemless row fails `_build_pitfalls_handoffs`'
    membership filter, the tick logs "none named a system the adapter set declares", and the
    whole batch is graveyarded and rotated away (PO-R2's own observation: handoffs from pure
    reducer traffic = `[]`).
    """
    repo, paths = scene
    ids = _shim_batch(paths)
    spawn = Spawn(curate_reducer_surface())

    assert pitfalls_curator.run_pitfalls(paths=paths, invoke=spawn) == 0
    assert spawn.calls, "the curator was never spawned for a batch that had a lesson"
    assert [e["surface"] for e in spawn.handoffs] == ["reducer"]
    assert set(consumed_by_id(paths)) == set(ids)
    assert graveyard_by_id(paths) == {}, (
        "the reducer-only batch took the `not handoffs` arm and was retired unread"
    )


def test_no_row_leaves_the_queue_without_a_record(scene):
    """Over a batch of a declared-system row, an undeclared-name row, a systemless non-shim
    row, a malformed `'../evil'` row and a shim row, every id lands in EXACTLY ONE of two
    places after the tick — `consumed_committed` with a sha, or the deadletter plus
    `consumed_unattributable` — and the queue is empty.

    O1's oracle reads the queue file, the consumed ledger and the deadletter, never the drain
    log: a row is conserved when a durable record says where it went, not when a line said so
    once. The curator teaches BOTH surfaces on this tick, so the shim row meets FK-7's
    confirmed-edit condition and the mixed batch is the one shape that can see every route at
    once.
    """
    repo, paths = scene
    persist.append_pitfalls(
        [pitfall_row("r:l-000:0", "elastic"),
         pitfall_row("r:l-001:0", "newsys"),
         pitfall_row("r:l-002:0", "", digest="exit=1; a systemless non-shim row"),
         pitfall_row("r:l-003:0", "../evil"),
         shim_row("r:l-004:0")],
        paths=paths,
    )
    every_id = {"r:l-000:0", "r:l-001:0", "r:l-002:0", "r:l-003:0", "r:l-004:0"}
    spawn = Spawn(edits(curate_execution_md("elastic"), curate_reducer_surface()))

    assert pitfalls_curator.run_pitfalls(paths=paths, invoke=spawn) == 0

    consumed, graveyard = consumed_by_id(paths), graveyard_by_id(paths)
    assert queue_ids(paths) == []
    assert set(consumed) == every_id, "a row left the queue with no consumed record"

    committed = {i for i, r in consumed.items() if r["consumed_category"] == "consumed_committed"}
    unattributable = {
        i for i, r in consumed.items() if r["consumed_category"] == "consumed_unattributable"
    }
    assert committed | unattributable == every_id, "a third category appeared"
    assert committed == {"r:l-000:0", "r:l-004:0"}
    assert set(graveyard) == unattributable, (
        "an uncurated row left without a durable record, or a curated one gained one"
    )
    for pid in committed:
        assert consumed[pid]["consumed_commit"]
    for pid in unattributable:
        assert "consumed_commit" not in consumed[pid]


# What the commit carries, and what a human is told about it.


def test_the_commit_carries_exactly_what_the_rule_admitted(scene):
    """The commit's path list EQUALS the rule's `changed` list.

    `commit_corpus` stages `git add -- defender/skills` — the whole pathspec — while
    `_pitfalls_path_rule` only ever adjudicated the records `_verify_corpus_scope` handed it,
    so "this round widens the write surface by exactly one literal path" is a claim about the
    rule that only the COMMIT can confirm. Driven over a two-surface tick, the paths the
    commit message names and the paths the commit actually touches are the same set.

    THE CONVERGED PREMISE BEHIND FK-5 IS REFUTED AND THE CORRECTION IS WHAT IS PINNED: a
    newly-dirty NON-`.md` file under the corpus does NOT ride the commit unexamined —
    `_verify_corpus_scope` computes `new_stray` from `not _in_corpus(p)` and RAISES on it, so
    the tick refuses outright and nothing is committed. The residual gap is different and is
    recorded as a known limitation rather than pinned here: `baseline_stray` snapshots only
    files OUTSIDE `defender/skills/*.md`, so pre-existing IN-corpus dirt is folded into this
    tick's commit and sha-stamped onto this tick's rows.
    """
    repo, paths = scene
    _shim_batch(paths, n=1)
    persist.append_pitfalls([pitfall_row("r:l-000:0", "elastic")], paths=paths)
    spawn = Spawn(edits(curate_execution_md("elastic"), curate_reducer_surface()))

    assert pitfalls_curator.run_pitfalls(paths=paths, invoke=spawn) == 0

    message = git(repo, "log", "-1", "--pretty=%B").stdout
    named = sorted(
        line[2:].strip() for line in message.splitlines() if line.startswith("- ")
    )
    assert named == sorted([ELASTIC_MD, REDUCER_REL])
    assert sorted(head_files(repo)) == named, (
        "the commit carries paths the rule never adjudicated"
    )

    # The correction, executed: a newly-dirty non-`.md` file under the corpus refuses the
    # whole tick rather than riding it.
    persist.append_pitfalls([shim_row("r2:l-009:0", digest="exit=1; a second mistake")],
                            paths=paths)
    stray = Spawn(edits(
        curate_reducer_surface("a second lesson"),
        lambda root: write(root / "defender" / "skills" / "gather" / "notes.txt", "dirt\n"),
    ))
    head_before = git(repo, "rev-parse", "HEAD").stdout.strip()
    with pytest.raises(LeadAuthorError) as exc:
        pitfalls_curator.run_pitfalls(paths=paths, invoke=stray)
    assert "outside" in str(exc.value)
    assert "notes.txt" in str(exc.value)
    assert git(repo, "rev-parse", "HEAD").stdout.strip() == head_before


def test_a_reducer_only_tick_reports_what_it_taught(scene, capsys):
    """On a tick that taught ONLY the reducer surface, the operator log NAMES that surface and
    the commit message stops claiming it folded pitfalls into per-system `execution.md`.

    `run_pitfalls`' operator line builds its named set from a TRUTHY comprehension over
    attributed systems (`{s for r in records if (s := ...)}`), and a reducer-only tick is
    systemless BY CONSTRUCTION — so it contributes nothing to the named-systems text and G5
    reproduced exactly that (row `s1` retired unnamed). `_pitfalls_commit_message` says
    "learning(lead-author): execution.md pitfalls" / "Folded … into per-system execution.md
    ## Common pitfalls" UNCONDITIONALLY, so on this tick it misdescribes its own contents.

    These two strings are the human-visible records this lane produces, which is what makes a
    wrong one a live defect rather than a cosmetic one (FK-6). That the graveyard is the only
    other candidate and is unread until #903 is NOT demonstrated here — it is a deliberate
    prose deferral recorded as the clause demand `graveyard_is_still_unread` (G22, searched),
    named rather than asserted so a reader cannot mistake this suite for its evidence. The four existing test files that assert the message verbatim are
    updated by the same change.
    """
    repo, paths = scene
    _shim_batch(paths)
    head_before = git(repo, "rev-parse", "HEAD").stdout.strip()
    capsys.readouterr()

    assert pitfalls_curator.run_pitfalls(paths=paths, invoke=Spawn(curate_reducer_surface())) == 0

    log = loop_log(capsys)
    named = [ln for ln in log.splitlines() if REDUCER_REL in ln or "defender-sql.md" in ln]
    assert named, f"an operator cannot tell a reducer lesson was taught: {log}"

    summary = git(repo, "log", "-1", "--pretty=%B").stdout.split("Paths:")[0]
    assert "per-system execution.md" not in summary, (
        f"the commit misdescribes a tick that touched no execution.md: {summary!r}"
    )
    assert "pitfalls" in summary
    assert git(repo, "rev-parse", "HEAD").stdout.strip() != head_before, (
        "nothing was committed, so the message asserted above is the seed's"
    )
    assert REDUCER_REL in head_files(repo)


# The composition frame — two ticks over one corpus tree and one queue.


def _leg(paths, spawn):
    """`_invoke_pitfalls`' shape, so the drain drives the REAL curation leg."""
    return lambda p, box=None: pitfalls_curator.run_pitfalls(paths=p, invoke=spawn, box=box)


def test_two_curation_ticks_land_distinctly_in_every_shared_sink(scene):
    """Two successive curation ticks, driven through the DRAIN that fans them, leave every
    shared sink holding both ticks' work: the reducer surface carries both bullets, the
    consumed ledger carries both batches' ids exactly once each, and each row carries the sha
    of ITS OWN tick.

    R2(b) bound at the composition frame rather than at the leg, because a single-leg test
    cannot see a cross-tick collision: every sink this round writes is `serialized-append`,
    the serialization is the TICK rather than a lock (the pitfalls channel has
    `drain_lock: None` by design), and a second tick that regenerated the reducer surface
    instead of appending to it — or re-stamped the first tick's rows with its own sha — would
    be green in every per-tick test here.

    The drain's own `_discard_worktree_changes` runs between the two, so the second tick reads
    exactly the committed state the first one left, which is what makes this two ticks rather
    than one long one.
    """
    repo, paths = scene
    first = _shim_batch(paths, n=2)
    drains._drain_pitfalls(paths, _leg(paths, Spawn(curate_reducer_surface("a LIST, not JSON"))))
    sha_one = git(repo, "rev-parse", "HEAD").stdout.strip()

    second = [shim_row("r2:l-004:0", digest="exit=1; Parser Error: at or near \"@timestamp\"")]
    persist.append_pitfalls(second, paths=paths)
    drains._drain_pitfalls(
        paths, _leg(paths, Spawn(curate_reducer_surface("quote @timestamp"))),
    )
    sha_two = git(repo, "rev-parse", "HEAD").stdout.strip()
    assert sha_one != sha_two, "the second tick committed nothing, so nothing is being shared"

    surface = (repo / REDUCER_REL).read_text(encoding="utf-8")
    assert surface.count("a LIST, not JSON") == 1, "the first tick's lesson was overwritten"
    assert surface.count("quote @timestamp") == 1
    assert surface.count(PITFALLS_SECTION) == 1, "the second tick restarted the section"

    consumed = consumed_by_id(paths)
    assert set(consumed) == {*first, "r2:l-004:0"}
    for pid in first:
        assert consumed[pid]["consumed_commit"] == sha_one
    assert consumed["r2:l-004:0"]["consumed_commit"] == sha_two
    assert queue_ids(paths) == []
    assert graveyard_by_id(paths) == {}


def test_a_committed_batch_is_not_re_bumped(scene, monkeypatch):
    """Rows already rotated to `consumed_committed` do not gain `attempts` when a LATER step
    in the same tick fails, and do not reach the graveyard: the retirement bumps only the rows
    still in the queue.

    The commit-then-rotate window is inherited machinery, but M8 changes WHICH rows the bump
    lands on — a reducer row is now in the curated set — and a batch that is durably taught
    being walked toward a ceiling graveyard for work that succeeded is the shape FK-10 keeps
    closed while explicitly declining to re-architect the fault posture this round.

    The fault is injected at the drain's own leg seam and its class is the one FK-10's
    answerer traced: `ImportError` is not in `SYSTEMIC_FAULTS`, so it falls to the generic
    guard and is routed to `_retire_pitfalls_batch` → `drain.retire`, identical bounded
    retirement to a curator `rc != 0`.
    """
    repo, paths = scene
    monkeypatch.setenv("LEARNING_AUTHOR_MAX_ATTEMPTS", "3")
    persist.append_pitfalls(
        [shim_row("r:l-003:0"), pitfall_row("r:l-000:0", "elastic")], paths=paths,
    )

    def _half_done(p, box=None):
        persist.rotate_pitfalls(
            ["r:l-003:0"], "deadbeef", paths=p, category="consumed_committed",
        )
        raise ImportError("the curator module vanished mid-tick")

    drains._drain_pitfalls(paths, _half_done)

    consumed, graveyard = consumed_by_id(paths), graveyard_by_id(paths)
    entry = consumed.get("r:l-003:0", {})
    assert entry.get("consumed_category") == "consumed_committed"
    assert "attempts" not in entry, "a durably taught row was re-bumped"
    assert "r:l-003:0" not in graveyard

    still_queued = {r["pitfall_id"]: r for r in persist.read_pitfalls(paths)}
    assert set(still_queued) == {"r:l-000:0"}
    assert still_queued["r:l-000:0"]["attempts"] == 1
