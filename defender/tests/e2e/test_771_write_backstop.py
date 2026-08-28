"""#771 — the executable spec for the WRITE BACKSTOP half: M3's alias-refusing primitive and
its lint (O1), M4's atomic-write rewrite, and the four call-site postures F1 preserved.

Every test here is exactly one demand of `spec-flow/specs/spec_graph_771.yaml`, named by
that demand's `discharged_by`, and its docstring carries the demand's observable-outcome prose
(that docstring is what `spec-graph binds` scans in place of an `outcome`).

RED BY CONSTRUCTION, and that is the expected state of a spec. `_io.write_guarded`,
`_io.guarded_mkdir`, `_io.stage_name`, `_io.sweep_staged` and the new lint do not exist at
`c98bc86c`. Measured after the round-five hygiene pass, the census negative below is RED on
THIRTEEN of its fifteen rows: a planted symlink at the artifact name redirects the write to a
file outside the tree today. Exactly TWO already hold (`claim_lead`'s `O_CREAT|O_EXCL`, and
`write_atomic`'s DESTINATION plant, which `os.replace` replaces rather than follows — B5) and
they stay in the census because the census is the contract, not a to-do list. A third row used
to read as a hold and did not: the guarded primitive is its own census row, and driving a
symbol that does not exist writes nothing, so the row passed for the one reason that proves
nothing. It now carries the missing-symbol guard the parity demand already carried.

THREE §7 RESOLUTIONS ARE LOAD-BEARING HERE AND ARE ENCODED LITERALLY:

  * D1 — every replacing write stages under an UNPREDICTABLE name, then renames into place.
    Our own staged names never repeat, so a leftover cannot collide with a later write and an
    attacker cannot pre-plant a name they cannot predict; an occupied staged name is therefore
    ALWAYS hostile and `EEXIST` fails closed unambiguously. No retry-on-collision: a retry
    would re-open exactly the ambiguity the unpredictable name dissolves.
  * D3 — an alias refusal is RECORDED but is exempt from every failure circuit, so it can
    never end a run. This is a deliberate, narrow amendment to F1's "preserve every call-site
    posture", and without it F1's own rationale (do not hand the box a denial-of-service lever)
    was false in three places. Its positive control is the GENUINE failure, which still
    escalates — and on the ELAPSED limb, because X14 re-probed the kill as two refused writes
    past a 300s window, never "five consecutive".
  * The X17/G3 REFUTATION — the model's write gate is blind to a planted HARD LINK.
    `Path.resolve()` does not dereference one, so the resolved path is the allowlisted name
    itself and `write_text` truncates the shared inode. The two gated model writers are back in
    the negatives on that axis; the retained-property clause now covers only the symlink shape.

No `monkeypatch.setattr` (CI ratchets new sites). Every alias is built with the real
`os.symlink`/`os.link` in the test body, so the taxonomy assumption is re-probed on every run.
"""
from __future__ import annotations

import contextlib
import errno
import json
import os
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from defender import _io  # noqa: E402
from defender.agents import MAIN_DEF  # noqa: E402
from defender.hooks import budget_enforcer, record_lead  # noqa: E402
from defender.learning.core import markers, persist  # noqa: E402
from defender.learning.core.config import LoopPaths  # noqa: E402
from defender.runtime import circuit_breaker, tools as runtime_tools  # noqa: E402
from defender.runtime.agent_definition import bind  # noqa: E402
from defender.tests.e2e._spec771 import (  # noqa: E402
    CENSUS,
    LINT_BASELINE,
    LINT_HARD_GATED_MODULES,
    POSTURES,
    X5_MEASURED_SITES,
    Writer,
    accounting_sidecar,
    alias_refusals,
    drive_drain_restore,
    drive_fault_exit_trace,
    drive_normal_exit_trace,
    drive_writer,
    drive_writer_at,
    guarded_mkdir,
    is_eexist,
    load_write_lint,
    outside,
    plant_component_for,
    plant_dir_symlink,
    plant_hardlink,
    plant_symlink,
    posture_class,
    run_tree,
    snapshot_outside,
    sweep_staged,
    worktree_tree,
    write_guarded,
)

pytestmark = pytest.mark.e2e


# demand #0 and its leave-in-place doctrine
def test_refused_write_raises_oserror_and_leaves_the_outside_target_intact(tmp_path):
    """refused_write_outcome — driving the guarded primitive at a name a symlink occupies
    RAISES `OSError` at the primitive and writes NOTHING through the alias: the outside
    target's bytes, inode and link count are unchanged, and no new entry appears beside it.

    F1 resolved the return contract in favour of raising rather than returning a status, so
    the observable is the exception, not a flag a caller may ignore. The errno is B7's `ELOOP`
    (O_NOFOLLOW met a link) or B6's `EEXIST` (the exclusive create met an occupied name) —
    both were executed on a real filesystem; which one arrives depends on the idiom, and the
    demand is that one of them does rather than a silent success.

    THE ORACLE IS THE WHOLE OUTSIDE TREE, and that is the repair rather than a flourish. The
    docstring promised that no new entry appears beside the target while the body compared the
    target's own bytes, inode and link count — so a refusal that wrote the payload to a NEW
    name in the same directory satisfied every assertion here. The suite already carries the
    tree-wide snapshot the census negative uses for exactly this, one demand over."""
    run = run_tree(tmp_path)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    target = outside(elsewhere)
    before = snapshot_outside(elsewhere)

    with pytest.raises(OSError) as e:  # noqa: PT011 — the idiom decides ELOOP vs EEXIST (B6/B7)
        write_guarded(plant_symlink(run / "report.md", target), "REDIRECTED\n")

    assert e.value.errno in (errno.ELOOP, errno.EEXIST), (
        f"the refusal must come from the alias-refusing open, not incidentally: got "
        f"errno={e.value.errno}"
    )
    assert snapshot_outside(elsewhere) == before, (
        "the refused write reached the tree outside the run dir — either through the alias, or "
        "beside it under a name of its own"
    )
    assert os.lstat(target).st_nlink == 1, "the refusal left a second name for the target"


def test_a_refused_write_leaves_the_planted_alias_in_place(tmp_path):
    """refused_write_leaves_the_planted_entry — a refused write does NOT remove the entry it
    refused: the symlink is still a symlink, still pointing where it pointed, after the raise.

    Removal is sanitizing, and M10's doctrine refuses it — an entry deleted by the writer is
    an entry the reap scan can never report. The pin has a known weakness the ledger measured:
    X4 refutes "the scan always runs" on BOTH teardown-fault arms, so the reporter this
    doctrine leans on is not guaranteed. §7 D2 is what makes the pin true — the skipped scan
    now leaves a did-not-run verdict, pinned by
    `test_a_skipped_reap_scan_leaves_a_did_not_run_marker`."""
    run = run_tree(tmp_path)
    target = outside(tmp_path)
    planted = plant_symlink(run / "report.md", target)

    with pytest.raises(OSError):  # noqa: PT011 — see the sibling demand's note
        write_guarded(planted, "REDIRECTED\n")

    assert os.path.islink(planted), "the refusal sanitized the evidence away"
    assert Path(os.readlink(planted)) == target, "the refusal rewrote the alias"


# O1's census-keyed negative and its positive control
@pytest.mark.parametrize("writer", CENSUS, ids=lambda w: w.id)
def test_no_writer_follows_a_link_planted_at_its_artifact_name(writer: Writer, tmp_path):
    """no_write_through_planted_leaf — for EVERY host-side writer into a shared tree, a
    symlink planted at the artifact name it is about to write leaves the outside target
    byte-identical: the write fails closed instead of redirecting.

    CENSUS-KEYED, and the census is a FLOOR. C1 claimed twelve writers in three idioms; it was
    refuted twice — C3-fix raised it to at least fourteen in at least five, and both additions
    (`write_atomic` on the budget artifact, and the host-side lead-claim hook) are structurally
    invisible to the grep that produced C1. A grep is not a census instrument, which is why
    `test_a_new_shared_tree_writer_is_a_lint_finding` demands the lint see a WRAPPER.

    THE DRIVER'S FAULT-EXIT TRACE WRITE IS A ROW HERE, and its absence was the sharpest hole
    in this suite: it is the second of the two sites the original issue reported, it shares one
    fixed artifact name with the happy-path trace writer, and it was missing from the census,
    the lint's gate list and the project profile's writer list at the same time — three
    instruments, all hand-derived, all blind to the same write. The queries table is a row for
    the neighbouring reason: one bound edge covered a writer with two artifacts and only one
    was ever driven.

    The oracle is the whole outside tree, not one file: `assert target.read_text() == original`
    is also green when the writer created a NEW file beside the target. Every surface the
    redirected content could reach out there is compared.

    AND A ROW WHOSE SYMBOL DOES NOT EXIST YET IS NOT A PASS. The guarded primitive is itself a
    census row, and at HEAD driving it raises a missing-symbol error: nothing is written, the
    outside tree is trivially unchanged, and the row went green for the one reason that proves
    nothing. The parity demand one screen away already refuses to grade an arm that measured a
    missing symbol rather than a write failure; applying that rule here and not there is how
    "93 red at HEAD" became 93 red and one green-because-absent."""
    run = run_tree(tmp_path)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    target = elsewhere / "secret.txt"
    target.write_text("ORIGINAL OUTSIDE\n", encoding="utf-8")
    before = snapshot_outside(elsewhere)

    plant_symlink(run / writer.artifact, target)
    outcome = drive_writer(writer, run)   # a raising posture is one of the four F1 preserved;
    # the sentinel row's raise is a BoxFault rather than an OSError, so the swallow is by
    # BaseException — a narrower catch errors out on exactly the fatal-posture row.

    assert posture_class(outcome) != "raised:AttributeError", (
        f"{writer.id}'s arm measured a MISSING SYMBOL rather than a refused write — nothing "
        f"ran, so the outside tree is unchanged for a reason that has nothing to do with this "
        f"demand. The same guard the parity demand carries, for the same reason: a row whose "
        f"target does not exist yet must be red, never counted as coverage."
    )
    assert snapshot_outside(elsewhere) == before, (
        f"{writer.id} ({writer.idiom}, cites {writer.cite}) wrote through the planted alias"
    )


def test_each_writer_lands_its_artifact_when_nothing_is_planted(tmp_path):
    """writer_lands_artifact_unlinked — with NOTHING planted, every census writer still lands
    real bytes at its own artifact path inside the tree.

    The positive control for `no_write_through_planted_leaf`, and it is not ceremony: a bare
    negative passes vacuously on any writer that simply stopped writing, which is exactly what
    a too-eager refusal would produce. Proof the mechanism fired and the observation channel
    can see the difference.

    ONE ROW IS EXEMPT FROM THE ANTI-VACUITY CHECK and names itself: the driver's fault-exit
    trace write is literally `write_text("")`, so an empty artifact IS its contract. The
    exemption is a per-row flag rather than a size threshold, because a threshold would have
    silently excused any writer that later stopped producing bytes."""
    landed: dict[str, int] = {}
    for writer in CENSUS:
        d = tmp_path / writer.id
        d.mkdir()
        run = run_tree(d)
        writer.invoke(run)
        artifact = run / writer.artifact
        assert artifact.is_file(), f"{writer.id} wrote no artifact at {writer.artifact}"
        assert not os.path.islink(artifact), f"{writer.id} left a link where a file belongs"
        if not writer.lands_empty:
            landed[writer.id] = artifact.stat().st_size

    assert all(size > 0 for size in landed.values()), (
        f"a writer produced an EMPTY artifact, which would make the negative vacuous: {landed}"
    )


def test_the_fault_exit_trace_write_never_blanks_a_completed_one(tmp_path):
    """tool_trace_write_is_torn_write_safe — when the trace write raises inside the run, the
    fault-exit path leaves `tool_trace.jsonl` present and parseable as (empty) JSONL rather
    than a torn write; and on the happy path the fault handler never touches the file the
    normal exit wrote.

    Two writers, one fixed name, both truncating — the R2 hit the gate leaf minted this demand
    from. Reading both call sites shows the fault-exit write only runs when the normal one
    itself raised, so they cannot collide today; nothing asserted it, and nothing exercised the
    fault path at all. The store is driven to raise through the harness's `store_factory=`
    seam, which is the condition `driver.py`'s own `except` comment names.

    THE HAPPY-PATH ARM DRIVES BOTH WRITERS TOGETHER, which is the only arrangement in which
    "the fault handler never touches the file the normal exit wrote" can be false. It used to
    drive the fault path in one tree and then call the normal trace writer, alone, in another —
    two writers exercised, never the same run, so the mutual exclusion the demand is about was
    asserted of nothing. Both live in one `try/except` inside the real driver, so one hermetic
    run with a working store puts the handler in place and requires it to stay quiet."""
    run = run_tree(tmp_path)
    (run / "report.md").write_text("---\ndisposition: benign\n---\n", encoding="utf-8")
    drive_fault_exit_trace(run)

    trace = run / "tool_trace.jsonl"
    assert trace.is_file(), "the fault exit left no trace artifact at all"
    body = trace.read_text(encoding="utf-8")
    assert body == "", (
        "the fault-exit path did not run, so this demand is vacuous — the store must refuse "
        f"its READS while the run's own writes proceed. Got: {body[:120]!r}"
    )

    happy = run_tree(tmp_path / "happy")
    (happy / "report.md").write_text("---\ndisposition: benign\n---\n", encoding="utf-8")
    drive_normal_exit_trace(happy)
    good = (happy / "tool_trace.jsonl").read_text(encoding="utf-8")
    assert good.strip(), (
        "after a run whose store reads fine, the trace is empty — either the normal write never "
        "happened, or the fault handler ran anyway and blanked what it wrote"
    )


# the directory-component half (B8/B10, five sites not two)
def test_no_writer_mkdirs_through_a_planted_directory_component(tmp_path):
    """no_write_through_planted_dir_component — a symlink-to-directory planted at a path
    COMPONENT a writer will create or traverse makes the write fail closed; nothing lands in
    the directory the component points at, at ANY depth.

    B8: `O_NOFOLLOW` on the leaf does not protect a swapped component — the write still lands
    outside. B10: `mkdir(parents=True, exist_ok=True)` over a symlink-to-directory succeeds
    SILENTLY, with no error to notice. The rule is stated over the whole call and is
    depth-agnostic (firm consensus #13), so the plant here is at a component the writer must
    traverse rather than at the one it creates first. F8/G15/X1 refuted the design's "two
    sites": there are at least FIVE, and this demand binds five edges.

    ALL FIVE ARE DRIVEN, and that is the repair rather than a flourish. The three PRODUCTION
    sites — the model-named gather_raw component, the lead sidecar's parent create, and the
    fixed gather_summaries component — were bound by this demand and exercised by nothing: the
    body drove the primitive and the drain restore, and named the other three in prose. A
    negative that binds an edge it never drives is a negative that is silently scoped to the
    edges someone thought to plant at, which is the same failure one level up from the one this
    demand exists to catch. Executed while writing this: with a symlink-to-directory at a
    snapshot key's parent component, the drain restore lands its blob inside the outside
    directory and raises nothing at all."""
    run = run_tree(tmp_path)
    elsewhere = tmp_path / "elsewhere"
    outside_dir = elsewhere / "loot"
    outside_dir.mkdir(parents=True)
    before = snapshot_outside(elsewhere)

    # The three PRODUCTION component-creating writers first, each driven over a planted
    # component of its own — the census rows this demand's binds already named. Measured while
    # writing this: all three land their payload inside the outside directory today,
    # byte-for-byte, and two of them report success while doing it.
    for writer in [w for w in CENSUS if w.mkdirs_component]:
        d = tmp_path / f"component-{writer.id}"
        d.mkdir()
        fresh = run_tree(d)
        plant_component_for(writer, fresh, outside_dir)
        drive_writer(writer, fresh)
        assert snapshot_outside(elsewhere) == before, (
            f"{writer.id} created through the planted component and landed outside the tree — "
            f"B10's silent success at a bound edge nothing was driving"
        )

    component = run / "gather_raw" / "l-002"
    plant_dir_symlink(component, outside_dir)

    with pytest.raises(OSError):  # noqa: PT011 — the component check's errno is the idiom's
        guarded_mkdir(component / "deep" / "deeper", base=run)

    assert snapshot_outside(elsewhere) == before, (
        "the primitive created through the planted component and landed outside the tree"
    )

    # the fifth site: the drain lane's restore, driven at a planted COMPONENT of its own
    worktree = tmp_path / "wt"
    corpus = worktree / "defender" / "lessons"
    corpus.mkdir(parents=True)
    plant_dir_symlink(corpus / "sub", outside_dir)
    with contextlib.suppress(OSError):
        drive_drain_restore(worktree, corpus, {"sub/lesson-a.md": b"# restored\n"})

    assert snapshot_outside(elsewhere) == before, (
        "the drain lane's restore mkdir'd through a planted component and landed its blob "
        "outside the second shared root — B10's silent success, on the site the design's own "
        "'two mkdir sites' count never had"
    )


def test_directory_component_writers_land_when_nothing_is_planted(tmp_path):
    """dir_component_write_lands_when_unplanted — with no component planted, the same
    writers create their nested directories inside the tree and land their payloads there.

    The positive control for `no_write_through_planted_dir_component`: without it, a component
    guard that refused everything would pass the negative and silently break every gather
    payload, every lead sidecar and every gather summary."""
    run = run_tree(tmp_path)
    guarded_mkdir(run / "gather_raw" / "l-003" / "deep", base=run)
    assert (run / "gather_raw" / "l-003" / "deep").is_dir()

    for writer in CENSUS:
        if not writer.mkdirs_component:
            continue
        d = tmp_path / f"ok-{writer.id}"
        d.mkdir()
        fresh = run_tree(d)
        writer.invoke(fresh)
        assert (fresh / writer.artifact).is_file(), (
            f"{writer.id} did not land its artifact under an unplanted component"
        )


def test_a_symlinked_ancestor_above_the_tree_does_not_refuse(tmp_path):
    """component_guard_is_anchored_at_the_tree_root — a symlinked component ABOVE the shared
    tree does not refuse the write, and a run whose runs base sits under one still opens its
    session store; a component planted INSIDE the tree is still refused in that same layout.

    THE NEGATIVE CONTROL FOR THE ANCHOR, AND IT IS A REAL CONFIGURATION. Judging every
    component down from `/` reads a symlinked ancestor as the hazard, but an ancestor is host
    configuration the box cannot influence — and the layout is ordinary rather than exotic:
    `/tmp` is a symlink on macOS and that is where the default runs base lives, and a symlinked
    `/data` or `/var/run` does the same on Linux. The blast radius is total rather than
    partial: `open_store` does not catch the refusal, so NO RUN STARTS, and the three sidecar
    writers that swallow `OSError` degrade to permanent silent no-ops — a run that appears
    healthy while persisting nothing.

    The third arm is what keeps the anchor from being a hole. Anchoring is only free because
    the box's writable mounts start AT the tree, so the region the walk stops judging is the
    region the box cannot reach; if the plant-inside-the-tree arm ever passed under a symlinked
    ancestor, the anchor would have moved above the box's reach instead of to it."""
    from defender.runtime import session_store

    # The whole shared tree sits under a symlinked ancestor — the macOS `/tmp` shape.
    real_base = tmp_path / "real"
    real_base.mkdir()
    linked = tmp_path / "linked"
    os.symlink(real_base, linked, target_is_directory=True)

    run = run_tree(linked)
    guarded_mkdir(run / "gather_raw" / "l-010" / "deep", base=run)
    assert (run / "gather_raw" / "l-010" / "deep").is_dir(), (
        "the guard refused a component under a symlinked ANCESTOR — the host's own layout "
        "read as the box's plant"
    )

    # The consequence that is not recoverable by any caller: a run cannot start at all.
    handle = session_store.open_store(case_id="c-771-anchor", runs_base=linked / "runs")
    try:
        assert handle.path.is_file(), "the session store did not land under a symlinked base"
    finally:
        handle.connection.close()

    # …and the anchor did not buy that by ceasing to look inside the tree.
    outside_dir = tmp_path / "elsewhere" / "loot"
    outside_dir.mkdir(parents=True)
    before = snapshot_outside(tmp_path / "elsewhere")
    component = run / "gather_raw" / "l-011"
    plant_dir_symlink(component, outside_dir)
    with pytest.raises(OSError):  # noqa: PT011 — the component check's errno is the idiom's
        guarded_mkdir(component / "deep", base=run)
    assert snapshot_outside(tmp_path / "elsewhere") == before, (
        "under a symlinked ancestor the guard stopped judging components INSIDE the tree — "
        "the anchor moved above the box's reach rather than to it"
    )


# §7 D1 — the staged name, and the collision class it dissolves
def test_a_replacing_write_stages_under_an_unpredictable_name(tmp_path):
    """staged_name_is_unpredictable — the replacing write stages its payload under a name that
    is never `<artifact>.tmp` and never repeats between two writes to the SAME artifact.

    §7 D1, applied literally. `write_atomic`'s deterministic `<name>.tmp` (F7/B4) is both a
    plantable address and the whole source of the legitimate-collision class fork R3 opened:
    a stale `.tmp` from a killed write, two concurrent accounted tool calls, and a model-chosen
    basename colliding with another artifact's temp name all produce a pre-existing name with
    no adversary anywhere. Removing the predictable address removes the plant target and the
    false-positive class at once, which is the only reading under which all five premises
    answer the same way.

    Driving the name source directly is the discriminating shape: asserting that two full
    writes left no `.tmp` behind would also be green for a primitive that stages
    deterministically and cleans up."""
    artifact = run_tree(tmp_path) / "budget.json"
    names = {str(_io.stage_name(artifact)) for _ in range(32)}  # type: ignore[attr-defined]

    assert len(names) == 32, f"the staged name repeats across writes: {len(names)} of 32 distinct"
    assert str(artifact) + ".tmp" not in names, "the deterministic `.tmp` address survived the fix"
    for name in names:
        assert Path(name).parent == artifact.parent, (
            "the staged name left the artifact's own directory, so the rename would cross a "
            "filesystem boundary"
        )


def test_atomic_write_refuses_a_planted_temp_name(tmp_path):
    """write_atomic_temp_not_followed — when the staged name is already occupied, the
    replacing write fails closed with `EEXIST` and the payload never reaches whatever that
    entry aliases; there is no retry under another name.

    §7 D1's second half: because our own staged names never repeat and an attacker cannot
    predict one, an occupied staged name is ALWAYS hostile — so failing closed is unambiguous
    rather than the false-positive generator fork R3 feared. A retry-on-collision would put
    that ambiguity straight back.

    The staged name is pinned through the primitive's `stage_name=` seam. The design gives the
    name source no observation point, and a fault that cannot be induced cannot be specified —
    so the seam is part of the contract (schema.md), and `test_every_shared_tree_writer_routes_
    through_the_guarded_primitive` pins its signature."""
    run = run_tree(tmp_path)
    target = outside(tmp_path)
    original = target.read_bytes()
    staged = run / "budget.json.staged-771"
    plant_symlink(staged, target)

    with pytest.raises(OSError) as e:  # noqa: PT011 — EEXIST is the demand; see the assert
        write_guarded(run / "budget.json", '{"tool_calls": 1}', stage_name=lambda _p: staged)

    assert is_eexist(e.value), f"the occupied staged name was not refused with EEXIST: {e.value}"
    assert target.read_bytes() == original, "the payload landed on the outside target (B4's shape)"
    assert not (run / "budget.json").exists(), "the rename ran despite the refused staging"


def test_orphaned_staged_files_are_swept_through_the_same_primitive(tmp_path):
    """orphaned_staged_files_are_swept — a staged file an interrupted write left behind is
    removed by the sweep, the sweep is itself a guarded write into the tree, and it refuses to
    follow an alias planted at an orphan's name.

    §7 D1's ACCEPTED COST, made mechanism: unpredictable staged names mean no later write ever
    replaces an orphan by name, so orphans accumulate after every crash. The human's resolution
    states the sweep inherits the same primitive — so an attacker who plants an alias at a name
    the sweep will touch must not get a deletion outside the tree either."""
    run = run_tree(tmp_path)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    victim = elsewhere / "keepme.txt"
    victim.write_text("STILL HERE\n", encoding="utf-8")
    before = snapshot_outside(elsewhere)

    orphan = run / "budget.json.staged-abandoned"
    orphan.write_text("half a payload", encoding="utf-8")
    plant_symlink(run / "report.md.staged-hostile", victim)

    swept = sweep_staged(run)

    assert not orphan.exists(), "the sweep left the orphan the unpredictable name guarantees"
    assert orphan in swept or str(orphan) in {str(p) for p in swept}, (
        "the sweep did not report what it removed, so a silent no-op reads as a clean tree"
    )
    assert snapshot_outside(elsewhere) == before, "the sweep followed an alias out of the tree"
    assert (run / "alert.json").is_file(), "the sweep removed a real artifact"


# the four postures F1 preserved, and §7 D3's exemption
@pytest.mark.parametrize("writer", CENSUS, ids=lambda w: w.id)
def test_each_writer_keeps_its_exception_posture_when_the_write_is_refused(writer, tmp_path):
    """call_site_postures_preserved — for EVERY census writer, an alias refusal produces the
    same observable that site produces today when its write fails for an ordinary reason, and
    the outside target stays byte-identical; across the census the four posture classes X5
    measured are all still distinguishable.

    F1 chose to preserve every call site's posture rather than unify them, and this is the
    demand that pins it. It is parametrized over the CENSUS, not over the four labels: keying
    the arms on labels certified the four rows someone had thought to label and left eleven
    exercised by no arm at all — including the writer the artifact's own comment named as the
    exemplar of the posture it was supposed to be testing.

    TODAY'S POSTURE IS MEASURED, NOT DECLARED. Each row is driven twice in this test: once
    with a REAL directory squatting the artifact name (an ordinary, root-proof write failure
    with no alias anywhere — the shape 47-reground used), and once with a real planted symlink.
    Arm one is the site's posture as it exists at HEAD; arm two must reproduce it. That is what
    lets the demand cover fifteen rows without an author's prior standing in for a measurement
    at the eleven sites X5 never looked at — and it re-probes the premise on every run rather
    than pinning a table that drifts the moment a handler moves.

    WHAT PARITY CANNOT SEE, AND WHERE THAT IS COVERED. Both arms run against the same code, so
    an implementation that changed a site's reaction in BOTH lanes agrees with itself and
    passes here. This demand is therefore internal consistency plus the anti-collapse floor,
    and the absolute anchor is a separate demand:
    `test_the_four_call_site_postures_the_ledger_measured_are_unchanged` drives X5's own four
    sites under X5's own faults and asserts the four observables the ledger recorded. Measuring
    "today" during the test run is what makes preservation vacuous for a site that moves
    twice; the ledger's four measurements are the only "today" that predates the change.

    ALTITUDE IS PART OF THE ROW, and one altitude claim came back the other way when measured:
    the sentinel's plant helper already converts its write failure into a box STARTUP fault, so
    that row was at the right height all along and the defect was on the reading side — a
    startup fault is not an `OSError`, so the two tests that touched X5's one fatal class caught
    nothing and ERRORED. `drive_writer` catches `BaseException` and `posture_class` keys a raise
    by its exception TYPE for exactly that reason: a startup fault and an ordinary OSError are
    one outcome to `except OSError` and two to the caller X5 was reading. The lesson-load row
    did move: it is driven at its production site, which swallows, rather than at the shared
    appender underneath, which raises. And the trace row's LABEL moved: X5's swallow-continue
    site is the driver's accounting call, one frame above `observe.write_trace`, which raises at
    its own altitude — the census carried that label on the wrong writer until the anchor
    demand went back to the ledger's own four sites.

    The fatal-looking fifth case is NOT here: §7 D3 exempts an alias refusal from every failure
    circuit, so the budget site's escalation no longer rides on this demand. Its own pair is
    `test_an_alias_refusal_is_recorded_but_never_ends_the_run` and
    `test_a_genuine_accounting_write_failure_still_kills_on_the_elapsed_limb`."""
    ordinary_dir = tmp_path / f"{writer.id}-ordinary"
    ordinary_dir.mkdir()
    ordinary_run = run_tree(ordinary_dir)
    squat = ordinary_run / writer.artifact
    squat.parent.mkdir(parents=True, exist_ok=True)
    squat.mkdir()
    today = posture_class(drive_writer(writer, ordinary_run))
    assert today != "raised:AttributeError", (
        f"{writer.id}'s ordinary-failure arm measured a MISSING SYMBOL rather than a write "
        f"failure, so both arms of this row would agree vacuously — the shape that makes a "
        f"parity assertion green against a target that does nothing at all"
    )

    aliased_dir = tmp_path / f"{writer.id}-aliased"
    aliased_dir.mkdir()
    aliased_run = run_tree(aliased_dir)
    target = outside(aliased_dir)
    original = target.read_bytes()
    plant_symlink(aliased_run / writer.artifact, target)
    refused = posture_class(drive_writer(writer, aliased_run))

    assert target.read_bytes() == original, f"{writer.id} redirected the write"
    assert refused == today, (
        f"{writer.id}'s posture under an alias refusal ({refused}) is not the posture it "
        f"produces today under an ordinary write failure ({today}). F1 preserved every call "
        f"site's posture, so a changed one is a spec violation and not an implementation "
        f"detail — and this row's posture is MEASURED in this test, so a drift here is a real "
        f"divergence and not a stale table."
    )
    assert len(POSTURES) == 4, "the X5 posture record moved; re-read the ledger before editing"


@pytest.mark.parametrize("site", X5_MEASURED_SITES, ids=lambda s: s.posture)
def test_the_four_call_site_postures_the_ledger_measured_are_unchanged(site, tmp_path):
    """measured_postures_anchored_to_the_ledger — each of the four call sites X5 measured still
    produces, under the fault X5 induced there, the observable X5 recorded: the accounting site
    returns normally while its silent failure counter advances, the gather raw-payload writer
    returns None, the lead sidecar writer returns 0, and the startup sentinel raises a box
    fault rather than an ordinary `OSError`.

    THE ANCHOR FOR F1, and the reason the parity demand alone is not one. F1's content is
    "every call site keeps the posture it has TODAY"; measuring "today" during the test run
    makes that vacuous for any site whose reaction changes in both the ordinary lane and the
    aliased lane, because the two arms then agree with each other about the new behaviour. The
    ledger's four measurements are the only "today" that predates this change, and until this
    demand existed they sat in the census as data and were asserted by nothing.

    THE SITES ARE X5'S, NOT THE CENSUS'S, and that distinction found a real misattribution. Two
    of the four are not census rows: the swallow-continue posture belongs to
    `driver._account_executed_call`, one frame ABOVE the trace writer the census had labelled
    with it — driven at its own altitude `observe.write_trace` raises, so the census row was
    carrying a measurement of a different function. Re-deriving a ledger label from the nearest
    row is exactly the move that produces a green test about the wrong thing.

    THE FAULTS ARE X5'S TOO. `claim_lead` is the case that shows why: under X5's fault (a plain
    file squatting the parent component) it returns 0, indistinguishable from success; under
    the census row's fault (a directory squatting the artifact name) the exclusive create sees
    `EEXIST` and the site answers 2 — reporting a write failure as a duplicate lead id. Both
    are today's behaviour and only the first is the measurement, so the anchor rebuilds the
    ledger's own fault rather than borrowing the row's.

    Each fault is built with the real filesystem in the test body and each is root-proof: a
    real directory or a real regular file occupying a name, never a permission bit."""
    run = run_tree(tmp_path)

    observed = posture_class(drive_writer_at(site, run))

    assert observed == site.observed, (
        f"{site.site} no longer produces the posture the ledger measured under {site.fault}: "
        f"observed {observed}, X5 recorded {site.observed}. F1 preserved these four rather than "
        f"unifying them, and this is the only assertion in the suite anchored to a measurement "
        f"taken before the change rather than during the test run."
    )
    assert site.posture in POSTURES, (
        f"{site.posture!r} is not one of X5's four classes {POSTURES} — the ledger moved and "
        f"this anchor is describing something else"
    )


def test_the_census_still_exhibits_all_four_measured_posture_classes(tmp_path):
    """census_exhibits_every_measured_posture — driving the whole census under an ordinary
    write failure still produces at least the FOUR distinguishable posture classes X5 measured,
    including one that is not a swallow.

    The anti-collapse control for `call_site_postures_preserved`. That demand compares each
    row against its own measurement, so it is satisfied — vacuously — by an implementation
    that made every site behave identically, because the two arms would then agree everywhere.
    This is the assertion that fails when F1's whole point is undone: four postures preserved
    rather than unified, and at least one of them fatal rather than silent."""
    observed: dict[str, str] = {}
    for writer in CENSUS:
        d = tmp_path / writer.id
        d.mkdir()
        run = run_tree(d)
        squat = run / writer.artifact
        squat.parent.mkdir(parents=True, exist_ok=True)
        squat.mkdir()
        seen = posture_class(drive_writer(writer, run))
        # A missing symbol is not a posture. Counting it would let a row that measures nothing
        # inflate the class count and carry this control past a real collapse.
        if seen != "raised:AttributeError":
            observed[writer.id] = seen

    classes = set(observed.values())
    assert len(classes) >= len(POSTURES), (
        f"the census collapsed to {len(classes)} posture classes {sorted(classes)}; X5 measured "
        f"{len(POSTURES)} distinct ones ({', '.join(POSTURES)}) and F1 preserved them: "
        f"{observed}"
    )
    assert any(c.startswith("raised:") for c in classes), "no census site raises at all"
    assert any(not c.startswith("raised:") for c in classes), (
        "every census site now raises, so the swallowing postures F1 preserved are gone"
    )

    # The two rows below are read by name, so a row that DEGRADED to a missing symbol (and was
    # therefore dropped from `observed` above) must fail here as a stated finding rather than
    # as a KeyError three lines into a traceback — the reading-side defect that made X5's fatal
    # class error out instead of asserting, one instrument over.
    contrasted = ("start_box", "gather_dispatch")
    missing = [row for row in contrasted if row not in observed]
    assert not missing, (
        f"{missing} measured no posture at all (a missing symbol, not a reaction), so the "
        f"fatal-vs-swallow contrast below has nothing to compare and this control would pass "
        f"by not applying"
    )
    assert observed["start_box"] != observed["gather_dispatch"], (
        "the startup-fault site and a swallow-and-continue site produce the same observable — "
        "X5's fourth class is exactly the one a single-posture implementation erases"
    )


def test_an_alias_refusal_is_recorded_but_never_ends_the_run(tmp_path):
    """alias_refusal_exempt_from_every_failure_circuit — a write refused BECAUSE an alias was
    planted is recorded in the accounting sidecar OUTSIDE the run dir, and counts toward
    nothing: the accounting failure counter does not advance, the first-failure stamp is never
    set, no number of such refusals raises `BudgetKill`, and the shared tree gains no new
    artifact for the record.

    §7 D3, and it is a deliberate narrow amendment to F1's preserve-every-posture rule.
    Without it F1's own rationale — do not hand the box a reliable denial-of-service lever
    (plant a link, kill the run) — was false in three places. X14 measured the lever and it is
    worse than the ledger recorded: one refusal, one success, then a single further refusal
    past the elapsed threshold ends the run, and the posture that makes it reachable is CI's.

    §7 D7 DECIDES WHERE THE RECORD LIVES, and it is mechanism rather than tidiness. An in-tree
    JSONL sink would have been a sixteenth writer into the attacker-controlled tree — absent
    from the census, absent from the lint's gate list, and reachable by the exact plant this
    change exists to stop: the box plants an alias at the record's own name, the record write
    is refused, and D3's own accepted cost (a refused write may be swallowed at its site) makes
    that silent. The mechanism observing the attack would have been suppressible BY the attack.
    So the record goes to the sidecar the demand already bound — a sibling of the run dir (X6),
    outside every box mount, and where the failure circuit already writes.

    The last assertion is the negative half of D7 and is what keeps the fix from drifting back:
    no new artifact appears inside the tree.

    THE ENFORCEMENT FLAG CANNOT CHANGE WHICH IDIOM THIS DEMAND EXERCISES, and that is stated
    rather than assumed because X13's refutation ends with an instruction not to inherit a
    posture. `account_call` is driven directly, BELOW the branch: the flag is read at the hook
    build site and decides whether the accounting hook fires at all, while `account_call`
    itself always reaches the staged-temp write. So this pair pins one idiom under both values
    of the flag, and needs neither arm nor a pinned environment to say which."""
    run = run_tree(tmp_path)
    target = outside(tmp_path)
    plant_symlink(run / "budget.json", target)
    before_tree = {str(p.relative_to(run)) for p in run.rglob("*")}
    limits = {**budget_enforcer.DEFAULT_LIMITS, "accounting_failure_max_elapsed": 0}

    for _ in range(10):
        budget_enforcer.account_call(run, "r-771", "bash", limits=limits, tier="main")

    state = budget_enforcer.accounting_failure_state(run)
    assert state["consecutive_failures"] == 0, (
        "an alias refusal advanced the accounting failure counter — the DoS lever is back"
    )
    assert state["first_failure_at"] is None, (
        "an alias refusal set the first-failure stamp, which never clears (X14) — two more "
        "refusals past the window would then end the run"
    )
    assert target.read_bytes() == b"ORIGINAL OUTSIDE\n", "the refused write still redirected"

    recorded = alias_refusals(run)
    assert recorded, (
        f"the refusal was exempted from the circuit AND left no record in "
        f"{accounting_sidecar(run).name} — D3 requires both halves"
    )
    assert any(str(r.get("path", "")).endswith("budget.json") for r in recorded), (
        f"the record names no refused path, so an operator cannot act on it: {recorded}"
    )
    assert not accounting_sidecar(run).is_relative_to(run), (
        "the record landed inside the run dir after all — D7 sites it outside every box mount "
        "precisely so the box cannot plant an alias at the record's own name"
    )
    new_in_tree = {str(p.relative_to(run)) for p in run.rglob("*")} - before_tree
    assert not new_in_tree, (
        f"recording the refusal created new entries INSIDE the shared tree ({sorted(new_in_tree)}) "
        f"— the extra writer D7 removed, back again and still absent from the census and the lint"
    )


def test_a_genuine_accounting_write_failure_still_kills_on_the_elapsed_limb(tmp_path):
    """genuine_accounting_failure_still_escalates — a write that fails for a reason that is NOT
    an alias refusal still counts: past the elapsed threshold, a single further failure raises
    `BudgetKill`, and the kill names the elapsed limb rather than the consecutive one.

    The positive control for D3's exemption — without it, "no alias refusal ever ends the run"
    is also satisfied by an escalation circuit that was accidentally disabled for everything.

    X14, re-probed EXECUTED, changed the magnitude: `_reset_accounting_failure` zeroes
    `consecutive_failures` and never clears `first_failure_at`, so past 300s against a 1200s
    wall clock TWO refused writes total end the run. A test written against "five consecutive"
    passes while that path stays open, which is why the elapsed limb is what is asserted.

    LIKE ITS PAIR, THIS DRIVES `account_call` DIRECTLY, below the enforcement flag's branch —
    the flag decides whether the accounting hook fires, not which idiom `account_call` uses —
    so the posture X13 warned against inheriting is not inherited here either."""
    run = run_tree(tmp_path)
    (run / "budget.json").mkdir()          # a directory squatting the artifact name: a REAL,
    # root-proof write failure with no alias anywhere (the same shape 47-reground used for the
    # breaker, chosen because root ignores permission bits and `defender/CLAUDE.md` records
    # four #631 tests that invert under root for exactly that reason).
    limits = {**budget_enforcer.DEFAULT_LIMITS,
              "accounting_failure_max_consecutive": 1000,
              "accounting_failure_max_elapsed": 0}

    def drive_three() -> None:
        for _ in range(3):
            budget_enforcer.account_call(run, "r-771", "bash", limits=limits, tier="main")

    with pytest.raises(budget_enforcer.BudgetKill) as e:
        drive_three()

    assert "elapsed" in str(e.value).lower(), (
        f"the kill came from the consecutive limb, not the elapsed one X14 measured: {e.value}"
    )


def test_a_refused_circuit_breaker_write_does_not_crash_the_run(tmp_path):
    """breaker_refused_write_does_not_crash_the_run — a refused write to `circuit_breaker.json`
    raises no uncaught `OSError` out of the run: the refusal is contained at the writer, the
    outside target is untouched, and the investigation continues.

    A rider on §7 D3, fixed regardless of the exemption. 47-reground executed this: today
    `update_json_locked` opens `r+` with no `OSError` handling, `record_outcome` does not catch
    either, and the call site sits OUTSIDE the query tool's control-flow except — so the error
    propagates past `_drive_agent` (which catches only four named types) and crashes the
    process HARDER than `BudgetKill`, with no partial-trace branch firing. That is a plain
    robustness bug, and this demand is what keeps it fixed."""
    run = run_tree(tmp_path)
    target = outside(tmp_path)
    original = target.read_bytes()
    plant_symlink(run / "circuit_breaker.json", target)

    circuit_breaker.record_outcome(run, "elastic", 2)

    assert target.read_bytes() == original, "the breaker's write followed the alias"


def test_a_refused_circuit_breaker_read_is_not_silently_reported_as_untripped(tmp_path):
    """breaker_refused_read_is_observable — when the breaker's state cannot be read, the run
    does not silently report "not tripped": the unreadable state is observable to the operator
    rather than indistinguishable from a healthy, freshly-initialised breaker.

    The second rider on §7 D3. 47-reground executed it: `_load` wraps its read in
    `except (JSONDecodeError, OSError): return _blank()`, so with the state file sabotaged
    `is_tripped()` returned `False` and `down_message()` returned its normal templated string.
    A safety mechanism that reports its own absence as health is disarmed, and nothing today
    can tell the difference."""
    run = run_tree(tmp_path)
    (run / "circuit_breaker.json").mkdir()   # unreadable as a file, and root-proof

    assert circuit_breaker.is_tripped(run, "elastic"), (
        "an unreadable breaker state read as a healthy UNTRIPPED breaker — the disarmed "
        "safety mechanism 47-reground executed. It must fail closed, the same direction §7 D2 "
        "takes for an unmarked tree."
    )
    assert "unreadable" in circuit_breaker.down_message(run, "elastic").lower(), (
        "the operator is shown the ordinary breaker-tripped message, so a corrupted state file "
        "is indistinguishable from real infrastructure degradation"
    )


# the two budget idioms, the seam, the lint, and the callers outside every box
def test_budget_write_is_alias_safe_under_both_enforcement_postures(tmp_path, monkeypatch):
    """budget_write_alias_safe_under_the_enforce_flag — `budget.json` is alias-safe under BOTH
    values of the enforcement flag: the flag-on lane (stage-then-rename) and the flag-off lane
    (locked read-modify-write) each leave the outside target byte-identical.

    The flag SELECTS WHICH OF TWO IDIOMS writes the artifact, so a test that exercises one
    certifies nothing about the other. X13, re-probed by MEASUREMENT rather than inference:
    both CI pytest jobs set the flag for the whole collected suite, and the audit counted 759
    stagings of `budget.json.tmp` in one suite run. The B4-unsafe lane is therefore the
    CI-DEFAULT lane, including for every test in this file — so the posture is PINNED here
    explicitly on both arms rather than inherited, which would silently exercise one branch
    twice."""
    for value, arm in (("1", "enforcing"), ("0", "locked")):
        monkeypatch.setenv("DEFENDER_BUDGET_ENFORCE", value)
        d = tmp_path / arm
        d.mkdir()
        run = run_tree(d)
        target = outside(d)
        original = target.read_bytes()
        plant_symlink(run / "budget.json", target)

        try:
            if value == "1":
                budget_enforcer.account_call(
                    run, "r-771", "bash", limits=budget_enforcer.DEFAULT_LIMITS, tier="main")
            else:
                budget_enforcer.update_budget_locked(run, "r-771", "bash")
        except OSError:
            pass

        assert target.read_bytes() == original, f"the {arm} budget idiom followed the alias"


def test_locked_json_open_fails_before_the_lock_is_acquired(tmp_path):
    """locked_json_open_refuses_before_the_lock — the locked read-modify-write idiom refuses at
    the OPEN, with `ELOOP`, so `flock` is never taken on the outside target and its bytes are
    unchanged.

    `O_NOFOLLOW` fails the open before the lock (B7, executed) — which matters beyond the
    write: taking an exclusive lock on a file outside the tree is itself a denial-of-service
    the box would otherwise get for free. Fork R24 found the circuit breaker shares this idiom,
    so both artifacts are driven; the demand binds at the TREE rather than at either artifact's
    identity facet so the collision question stays open rather than reading as answered."""
    run = run_tree(tmp_path)
    target = outside(tmp_path)
    original = target.read_bytes()

    for artifact in ("budget.json", "circuit_breaker.json"):
        plant_symlink(run / artifact, target)
        with pytest.raises(OSError) as e:  # noqa: PT011 — asserted on errno immediately below
            write_guarded(run / artifact, "{}", mode="update")
        assert e.value.errno == errno.ELOOP, (
            f"{artifact}: the refusal did not come from O_NOFOLLOW at the open (B7), so the "
            f"lock may already have been taken on the outside target: errno={e.value.errno}"
        )
        (run / artifact).unlink()

    assert target.read_bytes() == original


def test_every_shared_tree_writer_routes_through_the_guarded_primitive(tmp_path):
    """write_guarded_is_the_single_write_seam — the guarded primitive exists with the declared
    signature, its three modes are distinguishable in effect, and it is reachable for both
    shared roots.

    M3 gives fourteen writers a new dependency and nothing pinned a seam for it — schema.md's
    "if the design gives a dependency no seam, the seam is part of the contract" case. This is
    what write-code-from-spec's reconciliation reads, and it is what the new lint keys on: a
    lint with no canonical writer to point at degrades into a pattern matcher, which is exactly
    how C1's own grep went blind on a wrapper.

    The signature is asserted because a `kind: seam` demand IS the signature; the modes are
    then EXERCISED, because a field's existence is not its wiring. And BOTH ROOTS are driven
    because the demand binds both edges: a seam demonstrated only against a run dir is the
    shape under which the drain lane's own writers have no pinned primitive to route through."""
    import inspect

    sig = inspect.signature(_io.write_guarded)  # type: ignore[attr-defined]
    assert {"mode", "stage_name"} <= set(sig.parameters), (
        f"the guarded primitive carries no mode/stage_name seam: {sig}"
    )

    run = run_tree(tmp_path)
    write_guarded(run / "notes.jsonl", '{"a": 1}\n', mode="append")
    write_guarded(run / "notes.jsonl", '{"a": 2}\n', mode="append")
    assert len((run / "notes.jsonl").read_text(encoding="utf-8").splitlines()) == 2, (
        "append mode replaced instead of appending, so the modes are not distinguishable"
    )

    write_guarded(run / "notes.jsonl", "replaced\n")
    assert (run / "notes.jsonl").read_text(encoding="utf-8") == "replaced\n"
    assert not list(run.glob("notes.jsonl.*")), "the replacing write left its staged name behind"

    # THE THIRD MODE. `update` is the locked read-modify-write lane, and it was named in the
    # outcome sentence and never driven here — its only appearance in the suite was a REFUSAL
    # (the ELOOP-before-the-lock demand), which shows the mode exists without showing it does
    # anything. Three modes "distinguishable in effect" needs all three to have an effect.
    write_guarded(run / "state.json", '{"n": 1}')
    write_guarded(run / "state.json", '{"n": 2}', mode="update")
    assert json.loads((run / "state.json").read_text(encoding="utf-8"))["n"] == 2, (
        "update mode did not land its payload, so the third mode is a signature and not a lane"
    )

    worktree = worktree_tree(tmp_path / "wt")
    write_guarded(worktree / "defender" / "lessons" / "lesson-b.md", "# authored\n")
    assert (worktree / "defender" / "lessons" / "lesson-b.md").is_file(), (
        "the primitive does not reach the second shared root, so the drain lane has no seam to "
        "convert its writers onto"
    )


def test_a_new_shared_tree_writer_is_a_lint_finding(tmp_path):
    """new_writer_without_primitive_is_a_finding — the lint reports a shared-tree write that
    reaches the tree through a HELPER WRAPPER, not only one written as a direct idiom.

    C3-fix is the discriminating case and the reason this demand exists at all: the census
    missed `budget_enforcer`'s wrapper around the atomic helper precisely because the
    instrument that produced it was a grep over write idioms, and a grep cannot see a wrapper.
    A pattern-matching lint reproduces C1's own blind spot and certifies it.

    NOT claimed: that the lint proves a link cannot arrive in the tree by some other route. A
    host-side bug or a restored corpus is backstopped by the primitive, not disproved by the
    lint (NO7)."""
    module = load_write_lint()

    tree = tmp_path / "src"
    (tree / "pkg").mkdir(parents=True)
    (tree / "pkg" / "wrapper.py").write_text(
        "from defender._io import write_atomic\n"
        "def _write_thing_atomic(run_dir, state):\n"
        "    write_atomic(run_dir / 'thing.json', state)\n",
        encoding="utf-8",
    )
    (tree / "pkg" / "guarded.py").write_text(
        "from defender._io import write_guarded\n"
        "def _write_thing(run_dir, state):\n"
        "    write_guarded(run_dir / 'thing.json', state)\n",
        encoding="utf-8",
    )

    found = {f.fingerprint for f in module._scan(tree)}
    assert any("wrapper.py" in f for f in found), (
        "the lint missed a writer reaching the tree through a wrapper — C1's own blind spot"
    )
    assert not any("guarded.py" in f for f in found), (
        "the lint flags the guarded primitive itself, so every converted writer stays red"
    )


def test_the_write_lint_hard_gates_the_census_rows_and_ratchets_only_new_ones(tmp_path):
    """lint_hard_gates_the_census_rows — the lint's baseline does NOT contain any census row:
    every writer C1 names must be converted before merge, and the ratchet applies only to
    writers discovered after this change.

    Fork R25. Thirteen ratcheted lint modules already exist, so the ratchet is the default
    nobody chooses — and a baseline that accepts unconverted rows makes the next miscount
    invisible in exactly the way C1's grep did. The census is the thing this design already
    got wrong twice: twelve writers became fourteen, two mkdir sites became five.

    THE GATE LIST IS DERIVED FROM THE CENSUS, NOT TYPED BESIDE IT, and that is the repair
    rather than a tidy-up. A hand-typed list of ten module paths is what dropped the driver's
    fault-exit trace write out of the gate while the demand still bound its edge: the design
    said the lint is what covers the oracle's blind spot, and for that writer neither
    instrument held. Deriving it means a census row added later cannot be silently absent
    here — which is the only failure mode this demand exists for. The drain lane's restore
    module rides along for the same reason: F6's parity is asserted at the tool, and the lint
    is the backstop for the lane's own writers."""
    assert LINT_BASELINE.is_file(), f"the lint ships no baseline at {LINT_BASELINE}"
    entries = json.loads(LINT_BASELINE.read_text(encoding="utf-8")).get("entries", {})

    # The gate list the LINT actually runs on is a copy: a repo-root lint cannot import this
    # package. Comparing the two set-for-set is the only thing that makes "derived from the
    # census" true of the shipped gate rather than only of this module — without it a census
    # row added here and not there is a module the gate silently stops covering, which is the
    # exact way `runtime/driver.py` went missing from it once already.
    assert load_write_lint().LINT_HARD_GATED_MODULES == LINT_HARD_GATED_MODULES, (
        "the lint's hard-gate list has drifted from the census it mirrors — a census module "
        "missing there is a writer CI stops gating"
    )

    assert "runtime/driver.py" in LINT_HARD_GATED_MODULES, (
        "the derived gate list lost the driver's fault-exit trace write — one of the two sites "
        "the issue itself reported, and the row whose absence made this assertion vacuous"
    )
    assert "learning/author/drain.py" in LINT_HARD_GATED_MODULES, (
        "the derived gate list names no drain-lane module, so the second shared root's own "
        "writers can ship unconverted with the parity demand green"
    )
    leaked = {fp for fp in entries if any(m in fp for m in LINT_HARD_GATED_MODULES)}
    assert not leaked, (
        f"census rows were ratcheted into the baseline instead of converted: {sorted(leaked)}"
    )


def test_write_atomic_callers_outside_the_run_dir_still_write(tmp_path):
    """write_atomic_callers_survive — ALL FOUR atomic-write callers that land OUTSIDE every box
    mount keep working after the primitive changes: the learning enqueue marker, the marker
    rewrite, the pending-queue rewrite and the accounting-failure sidecar each still write, and
    each one's content is read back and checked.

    The fix is at the primitive, so all five call sites get it whether or not they are exposed
    (G2/X6, firm consensus #14). This is a survival demand, not a coverage one: a primitive
    hardened only for the exposed caller breaks callers that have nothing to do with boxes, and
    nothing in the O1 negatives looks at them.

    ALL FOUR ARE DRIVEN, and that is the repair rather than a flourish. Driving one and naming
    four in the prose is the shape that reads as a passing survival demand while three of the
    four callers are untested — and this demand is the only thing standing between the
    primitive's rewrite and them."""
    run = run_tree(tmp_path)
    state_dir = tmp_path / "state"
    paths = LoopPaths(repo_root=tmp_path, state_dir=state_dir)

    # 1. the learning enqueue marker
    markers.enqueue_for_learning(run, paths)
    marker = paths.learn_queue_dir / f"{run.name}.json"
    assert marker.is_file(), "the learning enqueue marker outside every box mount stopped writing"
    assert json.loads(marker.read_text(encoding="utf-8"))["run_id"] == run.name

    # 2. the marker rewrite — a second, distinct call site on the same artifact
    markers.rewrite_marker(marker, {"run_id": run.name, "attempt": 2})
    assert json.loads(marker.read_text(encoding="utf-8"))["attempt"] == 2, (
        "the marker rewrite stopped landing, so a retried learning batch loses its own state"
    )

    # 3. the pending-queue rewrite — the caller whose whole job is replacing a file's contents
    pending = state_dir / "pending.jsonl"
    pending.parent.mkdir(parents=True, exist_ok=True)
    pending.write_text('{"id": "a"}\n{"id": "b"}\n', encoding="utf-8")
    persist._rewrite_queue(pending, state_dir / "consumed.jsonl", "id", [], [{"id": "a"}], None)
    assert pending.read_text(encoding="utf-8") == '{"id": "b"}\n', (
        "the queue rewrite no longer drops the consumed row — the drain would re-process it"
    )

    # 4. the accounting-failure sidecar, a SIBLING of the run dir and outside the bind (X6)
    sidecar = accounting_sidecar(run)
    budget_enforcer._record_accounting_failure(run, budget_enforcer.DEFAULT_LIMITS)
    assert sidecar.is_file(), "the accounting-failure sidecar outside the run dir stopped writing"
    assert json.loads(sidecar.read_text(encoding="utf-8"))["consecutive_failures"] == 1
    assert not sidecar.is_relative_to(run), "the sidecar moved inside the box's reach"

    leftovers = [str(q) for p in (run.parent, state_dir, paths.learn_queue_dir) if p.is_dir()
                 for q in p.glob("*.tmp")]
    assert not leftovers, f"a staged name was left beside a caller's target: {leftovers}"


# the lead tables, and the second shared root
def test_a_duplicate_lead_id_still_fails_exclusive_create(tmp_path):
    """duplicate_lead_claim_still_refuses — claiming a `lead_id` twice still fails on the
    exclusive create: the second claim reports the reuse and does NOT overwrite the first
    sidecar's contents.

    Pre-existing behaviour C3-fix named, and the one place where fail-closed-on-a-pre-existing-
    name is ALREADY the contract rather than fork R3's new false-positive class. It is pinned
    here because §7 D1 changes the staging discipline around it and a careless conversion to
    stage-then-rename would silently make a duplicate claim overwrite."""
    run = run_tree(tmp_path)
    dispatch = {"run_dir": str(run), "lead_id": "l-001", "goal": "first", "what_to_summarize": []}

    # `== CLAIMED`, not `!= 2` (#855 F-12): "not the reuse code" is satisfied by the silent
    # refusal too, which is exactly the read that let an unclaimed dispatch run. The first
    # claim of this pair is the premise the rest of the demand rests on, so it asserts that
    # the row was WRITTEN.
    assert record_lead.claim_lead(dispatch) == record_lead.CLAIMED
    sidecar = run / "gather_raw" / "l-001.lead.json"
    first = sidecar.read_text(encoding="utf-8")

    assert record_lead.claim_lead({**dispatch, "goal": "second"}) == record_lead.ALREADY_CLAIMED, (
        "the duplicate claim did not report reuse"
    )
    assert sidecar.read_text(encoding="utf-8") == first, "the duplicate claim overwrote the first"


def test_the_claim_time_and_gather_seam_lead_id_gates_accept_the_same_set(tmp_path):
    """lead_id_gates_agree_at_both_check_sites — the claim-time gate and the gather-seam gate
    accept and reject exactly the same `lead_id` values, driven at both enforcement sites over
    a boundary set.

    The brief's "enforced at claim and again at the gather seam" is true of the SITES and false
    of the mechanism: the dispatched probe (G16) found two independently authored `re.compile`
    calls with no cross-import, plus a third copy on the read/join side. They agree today only
    because nobody has edited either — anchoring, the character class or a stray `IGNORECASE`
    could diverge with a one-line single-file edit the other file's suite would not catch.

    This is load-bearing for the census's own no-traversal argument: `gather_raw`'s first path
    component is MODEL-NAMED, and the claim that it carries no traversal rests on both copies
    staying equal. Comparing the two compiled patterns would NOT discharge it — one site could
    stop consulting its pattern entirely and the comparison would still be green."""
    import asyncio

    from defender.runtime.tools_gather import _run_gather

    cases = ("l-1", "l-abc123", "l-", "L-1", "l-abc_def", "l-abc-def", " l-1", "l-1 ", "l-1\n",
             "../etc", "l-1/../..")

    def claim_rejects(lead_id: str) -> bool:
        # The observable is whether a SIDECAR appeared, not the return code — and it stays the
        # observable now that #855 F-12 has split the codes (a refusal answers `NOT_CLAIMED`,
        # success `CLAIMED`), because the two gates being compared are the shape checks, and
        # only one of them has a code to report at all.
        d = tmp_path / f"claim-{abs(hash(lead_id))}"
        d.mkdir()
        run = run_tree(d)
        before = {p for p in run.rglob("*") if p.is_file()}
        record_lead.claim_lead(
            {"run_dir": str(run), "lead_id": lead_id, "goal": "g", "what_to_summarize": []}
        )
        return {p for p in run.rglob("*") if p.is_file()} == before

    def seam_rejects(lead_id: str) -> bool:
        d = tmp_path / f"seam-{abs(hash(lead_id))}"
        d.mkdir()
        run = run_tree(d)
        deps = bind(MAIN_DEF, run, defender_dir=Path(__file__).parents[2])
        request = type("R", (), {"lead_id": lead_id, "system": "elastic", "goal": "g",
                                 "what_to_summarize": []})()
        try:
            asyncio.run(_run_gather(deps, None, 1, request, None))
        except Exception as e:  # noqa: BLE001 — anything past the gate means the gate passed
            return "invalid lead_id" in str(e)
        return False

    divergent = {c for c in cases if claim_rejects(c) != seam_rejects(c)}
    assert not divergent, (
        f"the two independently authored lead_id gates disagree on {sorted(divergent)} — the "
        f"census's no-traversal argument for the model-named gather_raw component rests on "
        f"them staying equal (G16)"
    )


def test_the_drain_worktree_writers_meet_a_planted_alias_the_same_way(tmp_path):
    """alias_backstop_covers_the_second_shared_root — the writers into the SECOND shared root
    (the curator drain worktree) meet a planted alias exactly as the run-dir writers do: the
    outside target is byte-identical and the write fails closed.

    O1 is surface-general, and copy2's operative consequence is the one that matters: a fix or
    test written AT THE TOOL covers both lanes, one written at the run dir covers only lane 1.
    The drain lane's writable set is batch-dependent (X16), so "which tree" is not a static
    property of the lane — which is why this binds the root's identity facet rather than a
    path.

    A PRODUCTION DRAIN-LANE WRITER IS DRIVEN HERE, not only the primitive. Driving the
    primitive twice against drain-lane-SHAPED paths asserts nothing about the lane: the whole
    drain lane could ship unconverted with such a test green, and the lint would be the only
    backstop — with the drain module absent from its gate list. The corpus restore is the
    lane's own writer (X9's shape: `mkdir(parents=True, exist_ok=True)` then `write_bytes`
    from an `except` around the agent call), and it redirects at HEAD: driven against a symlink
    planted at a snapshot leaf, it truncates the outside file with the restored blob.

    The stray-discard writer is bound but is NOT a redirect risk: 47-reground executed
    `git checkout -- <path>` against a planted symlink and it REPLACED the link with the
    committed blob, leaving the outside file untouched — the same answer B5 gave for
    `os.replace`. Fork R19 is closed on that ground; the row stays because it is a subprocess
    write into a box-writable tree that no static walk censuses."""
    worktree = tmp_path / "wt"
    corpus = worktree / "defender" / "lessons"
    corpus.mkdir(parents=True)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    target = elsewhere / "secret.txt"
    target.write_text("ORIGINAL OUTSIDE\n", encoding="utf-8")
    before = snapshot_outside(elsewhere)

    # 1. the lane's OWN production writer — the fault-path corpus restore
    plant_symlink(corpus / "lesson-a.md", target)
    with contextlib.suppress(OSError):   # the restore's posture is its own (F1 preserves it)
        drive_drain_restore(worktree, corpus, {"lesson-a.md": b"# restored\n"})
    assert snapshot_outside(elsewhere) == before, (
        "the drain lane's corpus restore wrote through a planted alias and landed outside the "
        "second shared root — the lane a fix written at the run dir never reaches"
    )
    (corpus / "lesson-a.md").unlink()

    # 2. the primitive itself, on this root's paths
    plant_symlink(corpus / "lesson-b.md", target)
    with pytest.raises(OSError):  # noqa: PT011 — the idiom decides ELOOP vs EEXIST
        write_guarded(corpus / "lesson-b.md", "# authored\n")

    plant_symlink(worktree / ".box-sentinel-771", target)
    with pytest.raises(OSError):  # noqa: PT011 — the sentinel plant converts this to a fault
        write_guarded(worktree / ".box-sentinel-771", "token")

    assert snapshot_outside(elsewhere) == before, (
        "a drain-lane writer redirected out of the second shared root"
    )


# the gated model writers, back in the negatives on the hard-link axis
#: The four arms X17's executed matrix covered: both gated model write tools crossed with both
#: names the write allowlist admits. Each arm carries content its own artifact schema accepts,
#: so a refusal in the test can only come from the alias check and never from the schema.
REPORT_BODY = "---\ndisposition: benign\n---\n\nnothing to see.\n"
INVESTIGATION_BODY = "+ spec investigation\n"

GATED_WRITE_ARMS = (
    ("write_file", "report.md", REPORT_BODY,
     lambda deps, p: runtime_tools._tool_write_file(deps, p, REPORT_BODY)),
    ("write_file", "investigation.md", INVESTIGATION_BODY,
     lambda deps, p: runtime_tools._tool_write_file(deps, p, INVESTIGATION_BODY)),
    ("edit_file", "report.md", REPORT_BODY,
     lambda deps, p: runtime_tools._tool_edit_file(deps, p, "nothing to see.", "PWNED")),
    ("edit_file", "investigation.md", INVESTIGATION_BODY,
     lambda deps, p: runtime_tools._tool_edit_file(deps, p, "spec", "PWNED")),
    # #810: `append_block` is main's ONLY writer, so it is the arm that now matters most here
    # — the other two are held by the curator and lead-author roles. One arm, not two: the verb
    # is bound to investigation.md and takes no path, so report.md is unreachable through it by
    # construction rather than by refusal. It ignores the `p` the harness passes for the same
    # reason, and lands on `deps.run_dir / "investigation.md"` — the planted name.
    ("append_block", "investigation.md", INVESTIGATION_BODY,
     lambda deps, p: runtime_tools._tool_append_block(deps, INVESTIGATION_BODY)),
)

#: (#774/R1: report.md left the model's write_file/edit_file allow entirely — both tools now
#: refuse it unconditionally, planted alias or not — so it is no longer a positive-control arm.
#: The hard-link negative above still drives all four GATED_WRITE_ARMS: refusal is refusal
#: regardless of cause, and report.md refusing a hard-linked plant is still true. Only the
#: "lands when nothing is planted" control below narrows, to the one name that still lands.)
LANDING_ARMS = tuple(arm for arm in GATED_WRITE_ARMS if arm[1] != "report.md")


@pytest.mark.parametrize(
    ("tool", "name", "seed", "drive"), GATED_WRITE_ARMS,
    ids=[f"{t}-{n}" for t, n, _s, _d in GATED_WRITE_ARMS],
)
def test_the_gated_model_writers_refuse_a_planted_hard_link(tool, name, seed, drive, tmp_path):
    """gated_model_writers_refuse_a_planted_hard_link — a HARD LINK planted at either of the two
    names the model's write allowlist admits leaves the outside file byte-identical, through
    EITHER gated write tool: all four arms refuse rather than truncating the shared inode.

    FOUR ARMS, DRIVEN. X17's matrix was executed over both tools and both names and the outside
    file was overwritten in all four; a negative that drove one of them was a sound test of a
    quarter of its own docstring. Re-executed while writing this: `write_file` on `report.md`
    replaced the outside bytes with the report body, `write_file` on `investigation.md` replaced
    them with the invlang line, and both `edit_file` arms rewrote the outside file in place.

    THIS IS THE REFUTATION THE SPEC EXISTS TO PIN. X17 and G3 both claimed the gate denies "a
    statically planted link", and the executed alias matrix overturned both: symlinks are
    denied (absolute and relative), but `Path.resolve()` does not dereference a HARD link, so
    the resolved path IS the allowlisted name — it passes the allowlist, passes the
    read-containment check, passes the content schema, and `write_text` truncates the outside
    file. Executed on both tools and both allowed names; the outside file was overwritten in
    all four arms.

    So the stated ground for binding these two rows to the retained-property clause instead of
    the O1 negatives is false on this axis. The clause still covers the symlink shape and the
    check-then-write race; it no longer covers the plant.

    The residual exposure is detection-after-the-fact even once this is red-to-green: the reap
    scan refuses a hard link (`nlink > 1`), and X4 says that scan is skipped on exactly the
    crash path — which is what §7 D2's verdict marker is for."""
    run = run_tree(tmp_path)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    target = elsewhere / "secret.txt"
    # Seeded with the arm's OWN schema-valid content, so the artifact's content gate cannot be
    # what refuses: a deny for a schema reason would make this negative pass for the wrong
    # cause, which is exactly how a plant-shaped oracle certifies a gate that never looked.
    target.write_text(seed, encoding="utf-8")

    deps = bind(MAIN_DEF, run, defender_dir=Path(__file__).resolve().parents[2])
    plant_hardlink(run / name, target)
    # WRITE-CODE-FROM-SPEC FIX: `before` moves to AFTER the plant, not before it. Planting a
    # hard link unconditionally raises the target's own st_nlink 1->2 (plant_hardlink's own
    # postcondition, asserted a few lines up its stack) — a `before` snapshot taken earlier
    # captures nlink=1 and NO write can ever match it again, so the assertion below failed on
    # every arm regardless of whether the write was refused. The oracle's intent is "the write
    # did not change anything past the plant", so the baseline has to include the plant.
    before = snapshot_outside(elsewhere)

    refused = False
    try:
        drive(deps, str(run / name))
    except Exception:  # noqa: BLE001 — ModelRetry today; the demand is that it refuses at all
        refused = True

    assert snapshot_outside(elsewhere) == before, (
        f"{tool} truncated the outside file through the hard link at {name} — X17's executed "
        f"finding, and the reason these two rows are back in the O1 negatives"
    )
    assert refused, f"{tool} reported success on an aliased {name} operand"


@pytest.mark.parametrize(
    ("tool", "name", "seed", "drive"), LANDING_ARMS,
    ids=[f"{t}-{n}" for t, n, _s, _d in LANDING_ARMS],
)
def test_the_gated_model_write_lands_when_nothing_is_planted(tool, name, seed, drive, tmp_path):
    """gated_model_write_lands_when_nothing_is_planted — with no alias planted, each gated write
    tool still writes each allowlisted artifact and reports it.

    The positive control for the hard-link negative, and it takes the negative's shape: the
    same bytes ARE written through the sanctioned path. (#774/R1 narrowed this from four arms
    to two: report.md left the model's write allow entirely, so it no longer has a "lands"
    case — see test_report_md_refuses_the_gated_model_writers_even_when_nothing_is_planted for
    its own positive-shaped control.) Without this, a gate that refused every write would pass
    the negative while silently ending the model's ability to author investigation.md — and a
    control driven on one arm would leave that possible on the other."""
    run = run_tree(tmp_path)
    deps = bind(MAIN_DEF, run, defender_dir=Path(__file__).resolve().parents[2])
    artifact = run / name
    artifact.write_text(seed, encoding="utf-8")   # `edit_file` needs a baseline to edit

    result = drive(deps, str(artifact))

    assert name in result, f"{tool} did not report the artifact it wrote: {result!r}"
    assert artifact.read_text(encoding="utf-8"), f"{tool} left {name} empty"
    assert os.lstat(artifact).st_nlink == 1, "the sanctioned write left a second name"


@pytest.mark.parametrize(
    ("tool", "name", "seed", "drive"),
    [arm for arm in GATED_WRITE_ARMS if arm[1] == "report.md"],
    ids=[f"{t}-{n}" for t, n, _s, _d in GATED_WRITE_ARMS if n == "report.md"],
)
def test_report_md_refuses_the_gated_model_writers_even_when_nothing_is_planted(
    tool, name, seed, drive, tmp_path,
):
    """report_md_refuses_the_gated_model_writers_even_when_nothing_is_planted (#774/R1) — the
    positive control LANDING_ARMS lost when report.md left the model's write_file/edit_file
    allow entirely: unlike the other allowlisted name, there is no "lands" case for report.md
    to be missing a control for. Both tools refuse it unconditionally now, plant or no plant —
    the close tool (runtime/close_tool.py) is its sole writer."""
    run = run_tree(tmp_path)
    deps = bind(MAIN_DEF, run, defender_dir=Path(__file__).resolve().parents[2])
    artifact = run / name
    artifact.write_text(seed, encoding="utf-8")   # `edit_file` needs a baseline to edit

    refused = False
    try:
        drive(deps, str(artifact))
    except Exception:  # noqa: BLE001 — ModelRetry today; the demand is that it refuses at all
        refused = True

    assert refused, f"{tool} reported success writing report.md directly"
