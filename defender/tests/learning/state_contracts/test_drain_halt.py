"""The corpus drain tick over the learning store: a fault that halts the tick, and a fault contained to its curator.

#1135 pinned this over the file queues (a refused state entry halted the tick with exit 2; the locks of a halted tick were free
for the next). #1278 deleted the handle, the refusals and the locks (design r8 Locks, A1/O10); what survives is the tick's
two-way rule for a fault in a curator, observed over the store (`drains._HALTING`, `store_tick.Tick`):
- a halting fault (a git or box fault, a stop) ends the tick with exit 2, the sibling curator does not run, and the batch
  neither holds the lane nor strands its items (the next tick finds the lane free and the items waiting);
- any other fault is contained to its curator: the sibling still runs, the tick exits 0, and what the first curator
  committed is still delivered in the tick.

Retired with the handle (deleted files, design r8 A1/O10, Locks; `test_1278_census.py` now holds the line that no product code
reaches the old root or its handle): `test_1135_handle.py` (the handle's refusal of linked entries, roots, lock roles, claim
moves, ledger refusal, `move_at`, `open_lock_at`: every verb is gone) and `test_1135_front_door.py` (the tenant-selected root
routes and `describe` strings: `LoopPaths.state_root` is gone, and so is the root).

Retired from this file (their obligation is a file-state one the store replaced):
- `test_a_refusal_in_the_first_curator_halts_the_tick_with_exit_2` (a planted linked ledger refused): state refusal
  halting was the handle's (A1/O10); the halting rule survives as the first test below.
- `test_a_refused_stuck_report_raises_instead_of_logging_not_written`, `test_1135_ordinary_write_failure_at_each_phase_under_the_stuck_guard`,
  `test_1135_a_deadline_lock_name_is_a_planted_entry_when_run_batch_takes_the_repo_lock`,
  `test_1135_an_everyday_failure_writing_moving_or_locking_a_state_record`: stuck reports, ledgers, the repo lock and
  record moves are gone (statuses and transactions replace them: design r8 Schema "Retired files", Locks).
- `test_1135_locks_of_a_halted_tick_are_free_for_the_next_tick`: the file locks are gone; the lane's freedom after a
  halted tick is the last assertion of the first test below (the working-batch unique rule plus the lease, Locks).

Retired with `retrieval/test_1195_lessons_run_windows.py` (deleted; #1195's per-spawn box windows over the file-state tick:
`Tick`'s `cfg.post_rotate`/`cfg.gate`/`tree_for`/`JournalHeld` journal, `drains._drain_curators(paths, state, trigger)`, the
rotated queue and `run_batch(hold_committed=True, cfg=)`: every verb it drove is gone, design r8 Flows, Schema "Retired files"):
- the box's own life (main reads input, each window attaches, ends when its holder dies): design r8 "Box (amends #1344 O9)",
  enforced by BOX::test_a2_* (`tests/box/`), not here;
- a box fault in the first curator halts the tick before the second, and a non-box fault is contained with the second still
  run (`test_a_box_fault_from_the_first_curators_step...`, `..._in_the_first_curator_halts_the_tick_before_the_second`,
  `control_a_non_box_fault_in_the_first_curator_is_contained...`): the first and second tests below; a box fault in the
  SECOND curator halting the tick is the box-fault stop test below (the first curator's batch is not delivered);
- a stop fault under a failing spawn, a swallowed stop fault, a stop fault at the stop's proof, a run-start fault, and "a
  batch-start fault writes no stuck record" (`a_stop_fault_under_a_failing_*`, `a_swallowed_stop_fault_*`,
  `a_seam_fault_at_the_stops_proof_*`, `a_batch_start_fault_charges_no_curator_row_and_writes_no_stuck_record`): the stop
  fault winning over a contained failure is the last test below; stuck records and curator rows are gone; the seam-level
  variants drove `Tick.trigger`'s private plumbing;
- the settle/undo and commit-race tests (`a_process_left_in_the_box_cannot_change_a_read_lesson`, `control_a_process_that_outlived...`,
  `what_the_box_writes_during_its_own_run_is_what_is_committed`, `a_path_the_box_first_writes_as_its_run_stops_is_settled...`,
  `a_stray_the_box_writes_outside_the_lanes...`, `a_box_fault_outranks_an_undo_fault...`, `control_an_undo_fault_still_replaces...`,
  `a_lessons_spawns_deps_refuse_the_handle_as_its_box`, `a_failing_spawns_box_is_stopped_before_the_undo_runs`): the undo and
  the settle of a held corpus are the lane's draft/commit-maker, replaced by the batch's draft (design r8 D1, Flows); what a
  call commits is observed in `tests/learning/curation/test_1278_call_folders.py` and `test_1278_curator_fates.py`.
"""
from __future__ import annotations

import logging

import pytest

pytest.importorskip("pydantic_ai")

from defender.tests.support.learning.core._curators1278 import (  # noqa: E402
    QUESTIONER, Reply, ScriptedModel, result, scripted)
from defender.tests.support.learning.core._store1278 import (  # noqa: E402
    call, lesson_citing, migrated_database, world, world_finding)  # noqa: F401 — fixtures
from defender.tests.tenancy.tenant_1108_p4._drain_support import (  # noqa: E402
    BoxSpy, author_drain, critical_text, remote_branches)
from defender.tests.tenancy.tenant_1108_p4.conftest import p4_tenant  # noqa: E402, F401 — fixture `world` is built on

pytestmark = pytest.mark.postgres


def _items(w) -> dict:
    return {(i.kind, i.key): i for i in call(w.dsn, "work", w.t.tenant_id)}


def _seed(w) -> None:
    from defender.tests.support.learning.curation._drain719 import finding_row

    call(w.dsn, "publish_findings", w.t.tenant_id, "run-1", [finding_row("f1", run_id="run-f1")], kind="finding")
    call(w.dsn, "publish_findings", w.t.tenant_id, "run-1", [world_finding("q1")], kind="questioner_finding")


class _Seam:
    """The `trigger_author` seam: records each curator it is asked for; `faults` maps a module name to the exception it
    raises instead of running; every other module runs the drain's own default step (the real curator, scripted model)."""

    def __init__(self, model: ScriptedModel, faults: dict[str, BaseException]) -> None:
        import functools

        from defender.learning.core import drains
        from defender.learning.core.config import AUTHOR_DRAIN_LABEL

        self.modules: list[str] = []
        self.faults = faults
        self._default = functools.partial(drains._maybe_trigger_author, label=AUTHOR_DRAIN_LABEL,
                                          make_model=model.make_model)

    def __call__(self, paths, state, kind, threshold_env, module_name, pending_label, **kw) -> None:
        self.modules.append(module_name)
        if module_name in self.faults:
            raise self.faults[module_name]
        self._default(paths, state, kind, threshold_env, module_name, pending_label, **kw)


def _tick(w, model: ScriptedModel, faults: dict[str, BaseException]) -> tuple[int, _Seam]:
    seam = _Seam(model, faults)
    with scripted(model, w.monkeypatch):
        rc = author_drain(w.t, w.paths, trigger=seam, box=BoxSpy(), make_model=model.make_model)
    return rc, seam


def _halting_faults():
    from defender import box as box_mod
    from defender._git import GitError

    return [GitError(["status"], 128, "git failed in the curator"), box_mod.BoxFault("the box would not stop")]


@pytest.mark.parametrize("which", [0, 1], ids=["git-fault", "box-fault"])
def test_a_halting_fault_in_the_first_curator_halts_the_tick_with_exit_2(world, caplog, which):  # noqa: F811 — the imported fixture
    """A git or box fault in the lessons curator ends the tick with exit 2 and a CRITICAL line, the questioner curator never
    runs, and the claim is not left holding the lane: the batch ends, its items wait again, and the next tick runs. (`_HALTING`)"""
    caplog.set_level(logging.INFO)
    w = world
    _seed(w)
    fault = _halting_faults()[which]
    ok = ScriptedModel(lessons=Reply({"l1.md": lesson_citing("f1")}, result(committed=["f1"])))

    rc, seam = _tick(w, ok, {"author": fault})

    assert rc == 2, f"a halting fault did not halt the tick: exit {rc}"
    assert str(fault) in "\n".join(r.getMessage() for r in caplog.records if r.levelno == logging.CRITICAL), critical_text(caplog)
    assert seam.modules == ["author"], f"the sibling curator ran in the halted tick: {seam.modules}"
    assert [b.phase for b in call(w.dsn, "batches", w.t.tenant_id)] == ["ended"], "the halted tick left its batch holding the lane"
    assert {k: i.status for k, i in _items(w).items()} == {
        ("finding", "f1"): "waiting", ("questioner_finding", "q1"): "waiting"}, "the halted tick stranded its items"
    assert remote_branches(w.t.remote) == {}, "the halted tick pushed a batch"

    rc2, again = _tick(w, ok, {})  # the next tick: the lane is free and both items are claimed again
    assert rc2 == 0, critical_text(caplog)
    assert again.modules == ["author", "questioner_curator"]
    assert len(w.t.forge.creates) == 1


def test_a_non_refusal_fault_in_the_first_curator_stays_contained(world, caplog):  # noqa: F811 — the imported fixture
    """A systemic fault that is not a halting one (a `StageAbort`) in the lessons curator is contained: the tick exits 0
    with nothing CRITICAL, the questioner curator still runs and its lesson is delivered, and the lessons curator's item
    waits again with its attempt counted. (`_HALTING` excludes it)"""
    from defender.learning.core.config import StageAbort

    caplog.set_level(logging.INFO)
    w = world
    _seed(w)
    model = ScriptedModel(questioner=Reply({"q1.md": lesson_citing("q1")}, result(committed=["q1"])))

    rc, seam = _tick(w, model, {"author": StageAbort("the lessons curator: a systemic fault that is not a halt")})

    assert rc == 0, f"a contained fault reached the stage runner: exit {rc}: {critical_text(caplog)}"
    assert [r for r in caplog.records if r.levelno == logging.CRITICAL] == [], "the contained fault was reported CRITICAL"
    assert seam.modules == ["author", "questioner_curator"], seam.modules
    assert model.keys_shown(QUESTIONER) == ["q1"], "the questioner curator did not run after the contained fault"
    items = _items(w)
    assert items[("finding", "f1")].status == "waiting"
    assert items[("finding", "f1")].attempts == 1, "the contained fault's item did not keep its claim's attempt"
    assert items[("questioner_finding", "q1")].status == "in_batch"
    assert len(w.t.forge.creates) == 1, "the sibling's lesson was not delivered"


def test_a_non_refusal_fault_in_the_second_curator_after_the_first_committed_still_delivers_the_first(world, caplog):  # noqa: F811 — the imported fixture
    """The lessons curator commits f1; the questioner curator then meets a contained systemic fault: the tick exits 0, the
    lessons batch is pushed and its PR opened, f1 stays in the batch, and q1 waits again. (`_HALTING` excludes it)"""
    from defender.learning.core.config import StageAbort

    caplog.set_level(logging.INFO)
    w = world
    _seed(w)
    model = ScriptedModel(lessons=Reply({"l1.md": lesson_citing("f1")}, result(committed=["f1"])))

    rc, seam = _tick(w, model, {"questioner_curator": StageAbort("questioner curator: a systemic fault that is not a halt")})

    assert rc == 0, critical_text(caplog)
    assert [r for r in caplog.records if r.levelno == logging.CRITICAL] == []
    assert seam.modules == ["author", "questioner_curator"], seam.modules
    [batch] = call(w.dsn, "batches", w.t.tenant_id)
    assert (batch.phase, batch.pr_number is not None) == ("in_review", True), "the first curator's batch was not delivered in the tick"
    assert [c["head"] for c in w.t.forge.creates] == [batch.branch]
    items = _items(w)
    assert (items[("finding", "f1")].status, items[("finding", "f1")].batch_id) == ("in_batch", batch.id)
    assert items[("questioner_finding", "q1")].status == "waiting"


class _StopBox(BoxSpy):
    """`BoxSpy` whose stop refuses with a box fault, as a container that would not stop does."""

    def stop(self, _box, **_kw) -> None:
        from defender import box as box_mod

        super().stop(_box)
        raise box_mod.BoxFault("the box would not stop")


def test_a_tick_runs_both_curators_in_one_box_and_stops_it(world, caplog):  # noqa: F811 — the imported fixture
    """One box serves the tick: it is started once, handed to each curator that runs, and stopped when the tick ends."""
    caplog.set_level(logging.INFO)
    w = world
    _seed(w)
    model = ScriptedModel(lessons=Reply({"l1.md": lesson_citing("f1")}, result(committed=["f1"])),
                          questioner=Reply({"q1.md": lesson_citing("q1")}, result(committed=["q1"])))
    seam = _Seam(model, {})
    boxes: list = []
    inner = seam._default

    def recording(paths, state, kind, threshold_env, module_name, pending_label, **kw):
        boxes.append((module_name, kw.get("box")))
        return inner(paths, state, kind, threshold_env, module_name, pending_label, **kw)

    seam._default = recording
    spy = BoxSpy()
    with scripted(model, w.monkeypatch):
        rc = author_drain(w.t, w.paths, trigger=seam, box=spy, make_model=model.make_model)

    assert rc == 0, critical_text(caplog)
    assert (len(spy.requests), spy.stopped) == (1, 1), "the tick did not start one box and stop it once"
    assert [m for m, _ in boxes] == ["author", "questioner_curator"]
    assert boxes[0][1] is not None, "the curators were not handed the one box of the tick"
    assert boxes[0][1] is boxes[1][1], "the curators were not handed the one box of the tick"


def test_a_box_that_will_not_stop_halts_the_tick_and_delivers_nothing(world, caplog):  # noqa: F811 — the imported fixture
    """A stop fault at the tick's end is a halting fault: exit 2 with a CRITICAL line, and the batch the curators filled is
    not pushed (a box that may still be running must not have its work delivered)."""
    caplog.set_level(logging.INFO)
    w = world
    _seed(w)
    model = ScriptedModel(lessons=Reply({"l1.md": lesson_citing("f1")}, result(committed=["f1"])))

    seam = _Seam(model, {})
    with scripted(model, w.monkeypatch):
        rc = author_drain(w.t, w.paths, trigger=seam, box=_StopBox(), make_model=model.make_model)

    assert rc == 2, f"a stop fault did not halt the tick: exit {rc}"
    assert "the box would not stop" in "\n".join(r.getMessage() for r in caplog.records if r.levelno == logging.CRITICAL), critical_text(caplog)
    assert remote_branches(w.t.remote) == {}, "a batch was pushed after its box failed to stop"
    assert not [b for b in call(w.dsn, "batches", w.t.tenant_id) if b.phase == "in_review"], "the halted tick opened a review"


def test_a_stop_fault_outranks_a_contained_failure_in_a_curator(world, caplog):  # noqa: F811 — the imported fixture
    """The lessons curator fails with a contained fault and the box then will not stop: the stop fault wins, exit 2."""
    from defender.learning.core.config import StageAbort

    caplog.set_level(logging.INFO)
    w = world
    _seed(w)
    model = ScriptedModel()

    seam = _Seam(model, {"author": StageAbort("the lessons curator: a contained fault")})
    with scripted(model, w.monkeypatch):
        rc = author_drain(w.t, w.paths, trigger=seam, box=_StopBox(), make_model=model.make_model)

    assert rc == 2, f"the box that would not stop was outranked by a contained failure: exit {rc}"
    assert "the box would not stop" in "\n".join(r.getMessage() for r in caplog.records if r.levelno == logging.CRITICAL), critical_text(caplog)
