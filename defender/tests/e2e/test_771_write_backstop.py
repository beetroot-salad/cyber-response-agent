"""#771 — write backstop: the alias-refusing guarded write primitive (symlink/hard-link/planted-directory refusal at every shared-tree writer, unpredictable staged names, ELOOP before lock), refusal postures preserved per call site, and the gated model writers."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import fixture_runs_base

from defender.tests.support.shared.contracts._spec1077 import fixture_run

import contextlib
import errno
import json
import os
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from defender.run_repository import RunPaths
from defender import _io  # noqa: E402
from defender.agents import MAIN_DEF  # noqa: E402
from defender.hooks import record_lead  # noqa: E402
from defender.runtime import tools as runtime_tools  # noqa: E402
from defender.runtime.agent_definition import bind  # noqa: E402
from defender.tests.e2e._spec771 import (  # noqa: E402
    CENSUS,
    POSTURES,
    Writer,
    drive_drain_restore,
    drive_fault_exit_trace,
    drive_normal_exit_trace,
    drive_writer,
    guarded_mkdir,
    is_eexist,
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
from defender.run_repository import SessionPaths  # noqa: E402

pytestmark = pytest.mark.e2e


# demand #0 and its leave-in-place doctrine
def test_refused_write_raises_oserror_and_leaves_the_outside_target_intact(tmp_path):
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
    refused: the symlink is still a symlink, still pointing where it pointed, after the raise."""
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
    real bytes at its own artifact path inside the tree."""
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
    run = run_tree(tmp_path)
    elsewhere = tmp_path / "elsewhere"
    outside_dir = elsewhere / "loot"
    outside_dir.mkdir(parents=True)
    before = snapshot_outside(elsewhere)

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
    """dir_component_write_lands_when_unplanted — with no component planted, the same writers
    create their nested directories inside the tree and land their payloads there."""
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
    handle = session_store.open_store(case_id="c-771-anchor", sessions=SessionPaths(fixture_runs_base(linked / "runs")))
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


# #1279 A5 — the exclusive mode: the final component must be made by this call
def test_an_exclusive_mkdir_makes_the_final_component_and_the_missing_ones_above_it(tmp_path):
    """exclusive_mkdir_creates — a fresh final component is made, with the missing folders
    between it and the base (#1279 A5)."""
    run = run_tree(tmp_path)

    guarded_mkdir(run / "gather_raw" / "l-020" / "fresh", base=run, exclusive=True)

    assert (run / "gather_raw" / "l-020" / "fresh").is_dir()
    assert not (run / "gather_raw" / "l-020" / "fresh").is_symlink()
    assert list((run / "gather_raw" / "l-020" / "fresh").iterdir()) == []


@pytest.mark.parametrize("kind", ["empty-dir", "dir-with-content", "regular-file", "link-to-dir",
                                  "dangling-link"])
def test_an_exclusive_mkdir_refuses_whatever_already_holds_the_final_name(tmp_path, kind):
    """exclusive_mkdir_refuses_existing — a dir, file or link (followed or dangling) at the final
    name is a `FileExistsError` and is left as found; a link is not followed (#1279 A5)."""
    run = run_tree(tmp_path)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    final = run / "gather_raw" / "l-021"
    if kind in ("empty-dir", "dir-with-content"):
        final.mkdir()
        if kind == "dir-with-content":
            (final / "kept.txt").write_text("kept\n", encoding="utf-8")
    elif kind == "regular-file":
        final.write_text("not a dir\n", encoding="utf-8")
    elif kind == "link-to-dir":
        plant_dir_symlink(final, elsewhere / "loot")
    else:
        os.symlink(elsewhere / "nowhere", final)
    before_outside = snapshot_outside(elsewhere)
    before_run = snapshot_outside(run)

    with pytest.raises(FileExistsError):
        guarded_mkdir(final, base=run, exclusive=True)

    assert snapshot_outside(elsewhere) == before_outside, "the refused mkdir reached through the link"
    assert snapshot_outside(run) == before_run, "the refused mkdir changed the tree"
    assert os.path.islink(final) == (kind in ("link-to-dir", "dangling-link"))
    assert not (elsewhere / "nowhere").exists()


def test_an_exclusive_mkdir_still_refuses_a_planted_component_above_the_final_name(tmp_path):
    """exclusive_mkdir_keeps_the_component_check — the exclusive mode judges the folders above
    the final name as the default mode does (#1279 A5)."""
    run = run_tree(tmp_path)
    elsewhere = tmp_path / "elsewhere"
    plant_dir_symlink(run / "gather_raw" / "l-022", elsewhere / "loot")
    before = snapshot_outside(elsewhere)

    with pytest.raises(OSError) as refused:  # noqa: PT011 — the component check's errno is the idiom's
        guarded_mkdir(run / "gather_raw" / "l-022" / "fresh", base=run, exclusive=True)

    assert not isinstance(refused.value, FileExistsError), refused.value
    assert snapshot_outside(elsewhere) == before, "the exclusive mkdir created through the component"


def test_the_default_mkdir_still_accepts_an_existing_final_name(tmp_path):
    """default_mkdir_is_idempotent — control for the exclusive cases: without the mode an
    existing final directory is accepted (#1279 A5)."""
    run = run_tree(tmp_path)
    (run / "gather_raw" / "l-023").mkdir()
    (run / "gather_raw" / "l-023" / "kept.txt").write_text("kept\n", encoding="utf-8")

    guarded_mkdir(run / "gather_raw" / "l-023", base=run)
    guarded_mkdir(run / "gather_raw" / "l-023", base=run, exclusive=False)

    assert (run / "gather_raw" / "l-023" / "kept.txt").read_text(encoding="utf-8") == "kept\n"


# §7 D1 — the staged name, and the collision class it dissolves
def test_a_replacing_write_stages_under_an_unpredictable_name(tmp_path):
    """staged_name_is_unpredictable — the replacing write stages its payload under a name that is
    never `<artifact>.tmp` and never repeats between two writes to the SAME artifact."""
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
    assert RunPaths(run).alert.is_file(), "the sweep removed a real artifact"


# the four postures F1 preserved, and §7 D3's exemption
@pytest.mark.parametrize("writer", CENSUS, ids=lambda w: w.id)
def test_each_writer_keeps_its_exception_posture_when_the_write_is_refused(writer, tmp_path):
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


# the locked idiom, the seam, the lint, and the callers outside every box
def test_locked_json_open_fails_before_the_lock_is_acquired(tmp_path):
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


# the lead tables, and the second shared root
def test_a_duplicate_lead_id_still_fails_exclusive_create(tmp_path):
    run = run_tree(tmp_path)
    dispatch = {"run_dir": str(run), "lead_id": "l-001", "goal": "first", "what_to_summarize": []}

    assert record_lead.claim_lead(dispatch, run=fixture_run(run)) == record_lead.CLAIMED
    sidecar = run / "gather_raw" / "l-001.lead.json"
    first = sidecar.read_text(encoding="utf-8")

    assert record_lead.claim_lead({**dispatch, "goal": "second"}, run=fixture_run(run)) == record_lead.ALREADY_CLAIMED, (
        "the duplicate claim did not report reuse"
    )
    assert sidecar.read_text(encoding="utf-8") == first, "the duplicate claim overwrote the first"


def test_the_claim_time_and_gather_seam_lead_id_gates_accept_the_same_set(tmp_path):
    import asyncio

    from defender.runtime.tools_gather import _run_gather

    cases = ("l-1", "l-abc123", "l-", "L-1", "l-abc_def", "l-abc-def", " l-1", "l-1 ", "l-1\n",
             "../etc", "l-1/../..")

    def claim_rejects(lead_id: str) -> bool:
        d = tmp_path / f"claim-{abs(hash(lead_id))}"
        d.mkdir()
        run = run_tree(d)
        before = {p for p in run.rglob("*") if p.is_file()}
        record_lead.claim_lead(
            {"run_dir": str(run), "lead_id": lead_id, "goal": "g", "what_to_summarize": []}, run=fixture_run(run)
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
            asyncio.run(_run_gather(deps, None, 1, request, None, catalog=None))
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
    ("append_block", "investigation.md", INVESTIGATION_BODY,
     lambda deps, p: runtime_tools._tool_append_block(deps, INVESTIGATION_BODY)),
)

LANDING_ARMS = tuple(arm for arm in GATED_WRITE_ARMS if arm[1] != "report.md")


@pytest.mark.parametrize(
    ("tool", "name", "seed", "drive"), GATED_WRITE_ARMS,
    ids=[f"{t}-{n}" for t, n, _s, _d in GATED_WRITE_ARMS],
)
def test_the_gated_model_writers_refuse_a_planted_hard_link(tool, name, seed, drive, tmp_path):
    run = run_tree(tmp_path)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    target = elsewhere / "secret.txt"
    target.write_text(seed, encoding="utf-8")

    deps = bind(MAIN_DEF, run, defender_dir=Path(__file__).resolve().parents[2])
    plant_hardlink(run / name, target)
    before = snapshot_outside(elsewhere)

    refused = False
    try:
        drive(deps, f"/runs/current/{name}")
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
    tool still writes each allowlisted artifact and reports it."""
    run = run_tree(tmp_path)
    deps = bind(MAIN_DEF, run, defender_dir=Path(__file__).resolve().parents[2])
    artifact = run / name
    artifact.write_text(seed, encoding="utf-8")   # `edit_file` needs a baseline to edit

    result = drive(deps, f"/runs/current/{name}")

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
    run = run_tree(tmp_path)
    deps = bind(MAIN_DEF, run, defender_dir=Path(__file__).resolve().parents[2])
    artifact = run / name
    artifact.write_text(seed, encoding="utf-8")   # `edit_file` needs a baseline to edit

    refused = False
    try:
        drive(deps, f"/runs/current/{name}")
    except Exception:  # noqa: BLE001 — ModelRetry today; the demand is that it refuses at all
        refused = True

    assert refused, f"{tool} reported success writing report.md directly"
