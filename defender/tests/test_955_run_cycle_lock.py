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

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from defender.learning.core import run_cycle              # noqa: E402
from defender.tests._docker import satisfy_engine_keys           # noqa: E402
from defender.tests._spec791 import loop_paths, make_run_dir     # noqa: E402


def _holding(paths, run_id: str):
    """Whatever another live pass on `run_id` would be holding, taken from outside."""
    from defender.learning.author import shared as _author_shared

    return _author_shared.acquire_flock(paths.run_cycle_lock_file(run_id))


def test_a_second_pass_on_a_run_already_being_learned_refuses(tmp_path, monkeypatch):
    """The whole behaviour: refuse, loudly, and do no work.

    Not "wait for it" — a second pass has nothing to add to a run already being learned, and
    blocking would hang a human's CLI on a worker that holds the run for the length of a full
    learning cycle. `start_box` is a sentinel that fails the test if reached: the refusal has
    to land BEFORE anything asks the daemon for that container name, which is the collision."""
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
        rc = run_cycle.run_one(
            run_dir, paths=paths, agents=object(),
            start_box=_must_not_start, stop_box=lambda *_a, **_kw: None,
        )
    finally:
        from defender.learning.author import shared as _author_shared
        _author_shared.release_flock(held)
    assert rc == 0, "a refused pass reported an error rather than 'nothing learned'"


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
            start_box=_start, stop_box=lambda *_a, **_kw: None,
        )
    assert reached == ["started"], "the pass never reached the box start"
    held = _holding(paths, "case-955")
    assert held is not None, "the lock outlived the pass that took it"
    from defender.learning.author import shared as _author_shared
    _author_shared.release_flock(held)


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
        from defender.learning.author import shared as _author_shared
        _author_shared.release_flock(a)
        _author_shared.release_flock(b)
