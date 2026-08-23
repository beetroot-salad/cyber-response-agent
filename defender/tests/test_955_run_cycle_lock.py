"""#955 F-49, second half — one live pass per run, so two lanes cannot share one box name.

The ownership check in `box._reap_stale_before_create` makes the collision HONEST: a second
lane now refuses instead of force-removing the first lane's container mid-run. This file is
about the collision not happening.

The reachable path was never two drain workers — `learn_drain` holds a single-drainer lease and
has since it began reclaiming inflight claims. It is that the lease is not the only door.
`run_one` is also a CLI stage in its own right (`learning/core/cli.py`'s bare run-dir
positional), reached by hand, holding nothing; and the run-cycle box is the one caller that
REUSES a container name across starts, `defender-runcycle-{run_id}`. A hand-run pass on a run
the worker had already claimed therefore put two live boxes on one name, and before the
ownership check the loser reaped the winner's container and the winner reported the loss as a
mount error rather than as the collision it was.

The lock is per RUN ID, not global: two different runs share no container name and must still
be able to learn at the same time.
"""
from __future__ import annotations

import json

import pytest

from defender.learning.author import shared as author_shared
from defender.learning.core import run_cycle
from defender.learning.core.config import RunAlreadyLive
from defender.tests._docker import satisfy_engine_keys
from defender.tests._spec791 import loop_paths, make_run_dir, noop_stop_box


def _holding(paths, run_id: str):
    """Whatever another live pass on `run_id` would be holding, taken from outside."""
    return author_shared.acquire_flock(paths.run_cycle_lock_file(run_id))


def test_a_second_pass_on_a_run_already_being_learned_refuses(tmp_path):
    """The whole behaviour: refuse, loudly, and do no work.

    Not "wait for it" — a second pass has nothing to add to a run already being learned, and
    blocking would hang a human's CLI on a worker that holds the run for the length of a full
    learning cycle. `start_box` is a sentinel that fails the test if reached: the refusal has
    to land BEFORE anything asks the daemon for that container name, which is the collision.

    The refusal RAISES rather than returning 0. `learn_drain._serve_marker` reads any
    non-raising return as a completed learn and unlinks the queue marker, so a returned
    refusal deleted the only record that the run still needed learning — see
    `test_a_refused_pass_leaves_the_run_on_the_queue`. `RunAlreadyLive` is its own type
    because it is TRANSIENT: the marker is re-queued, never quarantined."""
    paths = loop_paths(tmp_path)
    run_dir = make_run_dir(tmp_path, name="case-955")

    def _must_not_start(*_a, **_kw):
        raise AssertionError(
            "a second pass reached the box start — both lanes are now on "
            "defender-runcycle-case-955, which is the collision this lock exists to prevent"
        )

    held = _holding(paths, "case-955")
    assert held is not None, "the fixture could not take the lock it is meant to model"
    try:
        with pytest.raises(RunAlreadyLive, match="already live on this run"):
            run_cycle.run_one(
                run_dir, paths=paths, agents=object(),
                start_box=_must_not_start, stop_box=noop_stop_box,
            )
    finally:
        author_shared.release_flock(held)


def test_a_refused_pass_leaves_the_run_on_the_queue(tmp_path):
    """The property the refusal exists to protect, asserted where it can actually be lost.

    `_serve_marker` distinguishes exactly two outcomes: it raised (quarantine to `failed/`) or
    it did not (unlink the claim AND the queued marker, count it drained). A refusal that
    returned 0 landed in the second: an operator hand-running a run the worker had already
    claimed made the worker delete that run's markers and log "drained 1 run(s)" — and if the
    hand pass then died, the run was learned by nobody, gone from the queue, and absent from
    `failed/`. Transient, so the marker goes back on the QUEUE rather than to `failed/`."""
    paths = loop_paths(tmp_path)
    run_dir = make_run_dir(tmp_path, name="case-955")
    qdir = paths.learn_queue_dir
    qdir.mkdir(parents=True, exist_ok=True)
    marker = qdir / "case-955.json"
    marker.write_text(json.dumps({"run_id": "case-955", "run_dir": str(run_dir)}) + "\n")

    held = _holding(paths, "case-955")
    assert held is not None
    try:
        run_cycle.learn_drain(paths, render=lambda _p: None)
    finally:
        author_shared.release_flock(held)

    assert marker.exists(), (
        "the drain deleted the queue marker for a run it refused — that run is now learned by "
        "nobody, with nothing left to retry from"
    )
    failed = list((qdir / "failed").glob("*")) if (qdir / "failed").is_dir() else []
    assert not failed, f"a TRANSIENT refusal was quarantined rather than re-queued: {failed}"


def test_a_run_id_the_grammar_refuses_is_quarantined_not_dropped(tmp_path):
    """The other refusal, and the other channel. A name that fails the run-id grammar will not
    become valid on a retry, so it is `RunUnprocessable` — which `_serve_marker` writes to
    `failed/` with a reason, exactly as the pre-#955 path did by letting `container_name`'s own
    grammar check raise. Returning 0 deleted the marker and left `failed/` empty."""
    paths = loop_paths(tmp_path)
    run_dir = make_run_dir(tmp_path, name="case-955")
    bad = run_dir.parent / "_bad-run"
    run_dir.rename(bad)
    qdir = paths.learn_queue_dir
    qdir.mkdir(parents=True, exist_ok=True)
    (qdir / "_bad-run.json").write_text(
        json.dumps({"run_id": "_bad-run", "run_dir": str(bad)}) + "\n"
    )

    run_cycle.learn_drain(paths, render=lambda _p: None)

    quarantined = list((qdir / "failed").glob("*")) if (qdir / "failed").is_dir() else []
    assert quarantined, "an unprocessable run left no dead letter — the marker was dropped"


def test_the_lock_is_released_so_the_next_pass_can_run(tmp_path, monkeypatch):
    """A lock held past the pass would turn the fix into a one-shot: the run-cycle name is
    REUSED, so every later pass on that run id would refuse forever."""
    # Without an ambient key per engine, key sourcing raises BEFORE the box start and this
    # test would pass on the wrong exception — a lock never released would still look fine.
    satisfy_engine_keys(monkeypatch)
    paths = loop_paths(tmp_path)
    run_dir = make_run_dir(tmp_path, name="case-955")
    reached: list[str] = []

    def _start(*_a, **_kw):
        reached.append("started")
        raise RuntimeError("far enough — the lock was free")

    with pytest.raises(RuntimeError, match="far enough"):
        run_cycle.run_one(
            run_dir, paths=paths, agents=object(),
            start_box=_start, stop_box=noop_stop_box,
        )
    assert reached == ["started"], "the pass never reached the box start"
    held = _holding(paths, "case-955")
    assert held is not None, "the lock outlived the pass that took it"
    author_shared.release_flock(held)


def test_two_different_runs_are_not_serialised_against_each_other(tmp_path):
    """Per run id, not one global lease. Two runs share no container name, and a global lock
    would make the fix a throughput regression on the drain's whole queue."""
    paths = loop_paths(tmp_path)
    a = _holding(paths, "case-955-a")
    b = _holding(paths, "case-955-b")
    try:
        assert a is not None, "the first run id could not take its own lock"
        assert b is not None, \
            "a second run id contended for the first one's lock — the lease is global, and "\
            "the drain's whole queue is now serialised behind one run"
    finally:
        author_shared.release_flock(a)
        author_shared.release_flock(b)
