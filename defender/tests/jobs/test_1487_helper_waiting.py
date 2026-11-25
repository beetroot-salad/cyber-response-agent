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

from defender.tests.support.evidence._evidence1546 import evidence_keys, garage  # noqa: E402, F401 — fixtures the helper's store seams take
from defender.tests.support.shared._openbao1163 import openbao  # noqa: E402, F401 — fixture

pytestmark = [pytest.mark.postgres, pytest.mark.garage, pytest.mark.openbao,
              pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux only")]


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


# --- G6: the helper's answer over every state of the work-waits class ------------------------------------------------

#: The phases a batch is in, each made by the store's own verbs (`_batch_in`).
_PHASES = ("working", "in_review", "needs_person", "ended")
#: The author lane's own item kinds: a waiting one at threshold 1 is a claim the post-step's author tick would make.
_AUTHOR_KINDS = ("finding", "questioner_finding", "feedback_instruction")


def _lanes() -> tuple[str, ...]:
    """Every lane the store knows: the author lane, the lanes its tick reconciles, and any it does not (none today:
    `LANES == AUTHOR_DRAIN_RECONCILES`, so the class has no unreconciled lane; a new lane joins it here)."""
    from defender.jobs.learning_models import LANES

    return tuple(LANES)


def _cells() -> list[Any]:
    """Lane x phase x abandon request x claimable findings, plus the store with no batch. An abandon request is only
    recorded on a parked batch (`request_abandon` refuses any other phase), so it is crossed with `needs_person` alone."""
    cells = [pytest.param(None, None, False, f, id=f"no-batch-{'findings' if f else 'empty'}") for f in (True, False)]
    for lane in _lanes():
        for phase in _PHASES:
            for asked in ((False, True) if phase == "needs_person" else (False,)):
                for found in (True, False):
                    cells.append(pytest.param(lane, phase, asked, found, id="-".join(
                        [lane, phase, "abandon-asked" if asked else "no-request", "findings" if found else "none"])))
    return cells


def _batch_in(scene: Any, lane: str, phase: str, *, asked: bool) -> None:
    """One batch of `lane` brought to `phase` by the store's own verbs; ended with its items held, so its end leaves
    nothing a claim could take (no item back to waiting, no replacement due)."""
    from defender.learning_store import Outcome, Why
    from defender.tests.support.learning.core._declared870 import shim_row

    tenant = scene.tenant
    if lane == "author":
        _publish(scene, "s/w/0/0")
        held = call(scene.dsn, "claim", tenant, lane, owner="g6", thresholds={"finding": 1})
    elif lane == "lead_author":
        call(scene.dsn, "add_pitfall", tenant, shim_row("g6-run:1"))
        held = call(scene.dsn, "claim", tenant, lane, owner="g6", thresholds={"pitfall": 1})
    else:
        tick = call(scene.dsn, "begin_feedback_tick", tenant, owner="g6")
        held = call(scene.dsn, "claim_registry", tick)
    assert held is not None, "premise: the lane's batch was claimed"
    assert held.lane == lane, "premise: the batch is of its lane"
    if phase == "in_review":
        call(scene.dsn, "in_review", held, 41, {})
    elif phase == "needs_person":
        call(scene.dsn, "needs_person", tenant, str(held.batch_id), Why.batch("foreign_pr", "by hand"))
        if asked:
            call(scene.dsn, "request_abandon", tenant, str(held.batch_id), actor="u-g6")
    elif phase == "ended":
        call(scene.dsn, "end_no_commits", held, {(k, key): Outcome.held("curator_held", "g6") for k, key, _ in held.items})
    [(now,)] = execute(scene.dsn, "SELECT phase FROM learning.batches WHERE id = %s", (str(held.batch_id),))
    assert now == phase, f"premise: the batch is {phase}"


def _waiting_author_items(scene: Any) -> int:
    [(n,)] = execute(scene.dsn, "SELECT count(*) FROM learning.work_items WHERE tenant_id = %s AND status = 'waiting' "
                                "AND kind = ANY(%s)", (scene.tenant, list(_AUTHOR_KINDS)))
    return int(n)


def _expected_waits(lane: str | None, phase: str | None, asked: bool, found: bool) -> bool:
    """The rule as `work_waiting`'s docstring states it, for the author lane reconciling `AUTHOR_DRAIN_RECONCILES`: a batch
    of the author lane working; a batch of a reconciled lane in review, or parked with a person's abandon request; or a
    claim the author lane would make, by the claim's rules: something due, and the lane not busy (a batch of it working,
    or an authoring batch of it not ended)."""
    from defender.learning.core.drains import AUTHOR_DRAIN_RECONCILES

    if lane is not None:
        if lane == "author" and phase == "working":
            return True
        if lane in AUTHOR_DRAIN_RECONCILES and (phase == "in_review" or (phase == "needs_person" and asked)):
            return True
    author_busy = lane == "author" and phase != "ended"
    return found and not author_busy


@pytest.mark.parametrize(("lane", "phase", "asked", "found"), _cells())
def test_g6_the_helper_answers_work_waits_exactly_when_the_rule_does(scene, monkeypatch, lane, phase, asked, found):
    """Every state of the class (a batch of each lane in each phase, with or without a person's abandon request, with or
    without author findings due): the real helper over a real store exits `WORK_WAITS` exactly when the rule of
    `learning_store.tick.work_waiting` says work waits, `NOTHING_WAITS` otherwise. (Amendment r5.2, r5.3)"""
    from defender import job_host

    R.settings_env(monkeypatch, threshold=1)
    if lane is not None:
        _batch_in(scene, lane, phase, asked=asked)
    if found:
        _publish(scene, "s/w/0/9")
    assert _waiting_author_items(scene) == (1 if found else 0), "premise: only the planted finding is due"

    expected = job_host.WORK_WAITS if _expected_waits(lane, phase, asked, found) else job_host.NOTHING_WAITS
    assert _post_step(scene) == expected
