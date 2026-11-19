"""#1487 Flow 3 as Amendment r5.2 places it: once a post-step's container exits, its helper asks the learning store it
bound (the tenant, the author lane, the thresholds of its environment) whether work still waits, and says it by its exit
status: `job_host.WORK_WAITS` or `NOTHING_WAITS`. A question that fails, or a post-step told to stop, exits 0, which the
worker reads as no answer. The real helper in this process over a container stand-in (`run_kind`), a real PostgreSQL;
the worker's reading of the status is `test_1487_post_step_waiting.py`."""
from __future__ import annotations

import os
import signal
import sys
from typing import Any

import pytest

from defender.tests.support.jobs import _job_helper as J
from defender.tests.support.jobs import _relay1487 as R
from defender.tests.support.jobs._job_helper_learning import run_kind
from defender.tests.support.learning.core._store1278 import FINDING, call, finding
from defender.tests.support.shared._postgres1339 import execute, migrated_database  # noqa: F401 — the scene's database

process_state = J.process_state
scene = J.scene

pytestmark = [pytest.mark.postgres, pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux only")]


def _publish(scene: Any, key: str = "s/w/0/0") -> None:
    call(scene.dsn, "publish_findings", scene.tenant, "run-1", [finding(key)], kind=FINDING)


def _post_step(scene: Any, body: Any = None, *, rc: int = 0) -> int:
    """A family-less post-step whose container runs `body(container)` and exits `rc`: the helper's exit status."""
    def job(container: Any) -> int:
        if body is not None:
            body(container)
        return rc

    return run_kind(scene, "post-step", job, family_less=True).rc


@pytest.mark.parametrize("waits", [True, False], ids=["work-waits", "nothing-waits"])
def test_r52_the_helper_exits_with_the_stores_answer(scene, monkeypatch, waits):
    """A finding at the threshold waits: `WORK_WAITS`; an empty store: `NOTHING_WAITS`, whatever the container's own
    status. (Amendment r5.2)"""
    from defender import job_host

    R.settings_env(monkeypatch, threshold=1)
    if waits:
        _publish(scene)
    assert _post_step(scene, rc=3) == (job_host.WORK_WAITS if waits else job_host.NOTHING_WAITS)


def test_r52_the_answer_reads_the_store_as_the_container_left_it(scene, monkeypatch):
    """The container publishes a finding while it runs: once it exits, work waits. (Flow 3: asked after the container)"""
    from defender import job_host

    R.settings_env(monkeypatch, threshold=1)
    assert _post_step(scene, lambda _c: _publish(scene)) == job_host.WORK_WAITS


def test_r52_the_thresholds_are_the_helpers_environments(scene, monkeypatch):
    """One finding at the helper's threshold 2 is not work; the control at threshold 1 is. (Flow 3: the thresholds are the
    helper's own, bound to its adapter)"""
    from defender import job_host

    _publish(scene)
    R.settings_env(monkeypatch, threshold=2)
    assert _post_step(scene) == job_host.NOTHING_WAITS
    R.settings_env(monkeypatch, threshold=1)
    assert _post_step(scene) == job_host.WORK_WAITS


def test_r52_a_question_that_fails_exits_0(scene, monkeypatch):
    """The learning tables cannot be read when the helper asks: it exits 0, no answer, and the worker keeps the clock
    running. The control, with the tables readable, answers. (O7: an unknown answer is never "nothing waits")"""
    from defender import job_host

    R.settings_env(monkeypatch, threshold=1)
    execute(scene.dsn, "ALTER TABLE learning.batches RENAME TO batches_unreadable")
    try:
        assert _post_step(scene) == 0
    finally:
        execute(scene.dsn, "ALTER TABLE learning.batches_unreadable RENAME TO batches")
    assert _post_step(scene) == job_host.NOTHING_WAITS, "control: with the tables readable the helper answers"


def test_r52_a_post_step_told_to_stop_exits_0(scene, monkeypatch):
    """The helper is signalled while the container runs: it does not ask, and exits 0 though nothing waits. (Flow 3: a
    stop leaves the clock not idle)"""
    R.settings_env(monkeypatch, threshold=1)

    def body(container: Any) -> None:
        os.kill(os.getpid(), signal.SIGTERM)
        assert container.stopping.wait(30), "premise: the stop reached the container"

    assert _post_step(scene, body, rc=143) == 0
