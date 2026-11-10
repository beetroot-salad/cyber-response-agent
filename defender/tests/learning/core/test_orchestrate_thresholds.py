"""A non-numeric loop threshold env var fails loud as exit 2 (FatalConfigError); the stage runner's exit mapping; the wake gate.

#1278 moved the drain's queues, markers, quarantine and wake counts into the learning store (design r8 Flows, Schema), so the
obligations survive over it: a bad threshold stops either drain with exit 2 naming the variable (the first block of tests), a
lead-lane fault of the systemic family is not quarantined per request (the second), and the wake gate counts what a tick could
take (the last). The stage runner's exit mapping needs no store and is unchanged.

Retired from this file:
- `test_run_or_dead_letter_*` (4 tests): `faults.run_or_dead_letter` and the per-marker dead-letter are gone (design r8 Schema
  "Retired files": dead-letter, stuck and failed files become statuses). What they pinned survives in the drains: a plain
  failure is contained to its request, a systemic one is not (`test_lead_author_drain_*` below, `test_1135_drain_halt.py`).
- `test_lead_author_drain_unlinks_marker_on_success`, `..._quarantines_a_plain_failure`, `..._requeues_a_transient_with_bumped_attempts`,
  `test_drain_pitfalls_*`: the marker, its quarantine and its attempts counter are the item's status, attempts and ceiling
  (the same flows are ported in `test_loop.py`, whose lead-author tests drive the real tick over the store).
- `test_881_pending_queue_count_measures_rows_the_drain_could_author`: the file lines, blank and unreadable lines, and
  `held_reason` stamps it counted are gone; its surviving obligation (held rows are no work, deferred rows are) is the last test.
"""
from __future__ import annotations

import pytest

from defender import _git  # type: ignore[import-not-found]
from defender.learning.core import cli  # type: ignore[import-not-found]
from defender.learning.core.config import (  # type: ignore[import-not-found]
    FatalConfigError,
    RunUnprocessable,
    StageAbort,
)
from defender.tests.support.learning.core._store1278 import call, execute, migrated_database, world  # noqa: F401 — fixtures
from defender.tests.tenancy.tenant_1108_p4._drain_support import BoxSpy, author_drain, lead_author_drain
from defender.tests.tenancy.tenant_1108_p4.conftest import p4_tenant  # noqa: F401 — fixture `world` is built on


@pytest.mark.postgres
@pytest.mark.parametrize(("variable", "lane"), [
    ("LEARNING_AUTHOR_THRESHOLD", "author"), ("LEARNING_QUESTIONER_THRESHOLD", "author"),
    ("LEARNING_PITFALLS_THRESHOLD", "lead")], ids=["author", "questioner", "pitfalls"])
def test_a_non_numeric_threshold_stops_the_drain_with_exit_two_naming_the_variable(world, caplog, variable, lane):  # noqa: F811 — the imported fixture
    """The stage maps a bad threshold to exit 2 with the variable named, before any batch starts (a queued request or finding
    must not let it slip past the gate). (FatalConfigError, store claim thresholds)"""
    w = world
    if lane == "author":
        from defender.tests.support.learning.curation._drain719 import finding_row

        call(w.dsn, "publish_findings", w.t.tenant_id, "run-1", [finding_row("f1/b/0/0", run_id="run-1")], kind="finding")
    else:
        call(w.dsn, "enqueue_request", w.t.tenant_id, "run-1", "case-1",
             {"case_id": "case-1", "tenant_id": w.t.tenant_id, "run_id": "run-1"})
        call(w.dsn, "add_pitfall", w.t.tenant_id, {"pitfall_id": "p1", "system": "elastic"})
    w.monkeypatch.setenv(variable, "high")
    drain = author_drain if lane == "author" else lead_author_drain
    kw = {"trigger": None} if lane == "author" else {}

    assert drain(w.t, w.paths, box=BoxSpy(), **kw) == 2
    assert variable in caplog.text, caplog.text
    assert call(w.dsn, "batches", w.t.tenant_id) == [], "a batch was started under a malformed threshold"


def _raise(exc):
    """A zero-arg stage that raises ``exc`` (closure dodges lambda's no-raise limit)."""
    def _stage():
        raise exc
    return _stage


def test_run_stage_maps_stage_abort_to_exit_two():
    assert cli._run_stage(_raise(StageAbort("systemic"))) == 2
    assert cli._run_stage(_raise(FatalConfigError("bad cfg"))) == 2
    assert cli._run_stage(
        _raise(StageAbort("systemic")), allow_run_error=True
    ) == 2


def test_run_stage_propagates_run_unprocessable_on_a_drain():
    """The guard: on a drain path (allow_run_error=False, the default) a leaked
    RunUnprocessable propagates uncaught rather than being mapped to a clean exit 2."""
    with pytest.raises(RunUnprocessable, match="bad run"):
        cli._run_stage(_raise(RunUnprocessable("bad run")))


def test_run_stage_maps_run_unprocessable_to_exit_two_on_direct_run():
    """The direct single-run path (loop.py <run_dir>) has no queue to quarantine into,
    so a bad run maps to the contracted exit 2 — the behavior main() preserves."""
    assert cli._run_stage(
        _raise(RunUnprocessable("bad run")), allow_run_error=True
    ) == 2


def test_run_stage_maps_giterror_to_exit_2():
    """At the stage boundary a ``GitError`` becomes the contracted FATAL exit 2."""
    from defender import _git  # type: ignore[import-not-found]

    def stage() -> int:
        raise _git.GitError(["commit"], 1, "pre-commit hook rejected")

    assert cli._run_stage(stage) == 2


# --- the wake gate -------------------------------------------------------------------------------------------------------


def _set_status(dsn, tenant_id, prefix, status, *, deferrals=0):
    execute(dsn, "UPDATE learning.work_items SET status = %s, deferrals = %s WHERE tenant_id = %s AND item_key LIKE %s",
            (status, deferrals, tenant_id, f"{prefix}/%"))


@pytest.mark.postgres
def test_881_the_wake_gate_counts_what_a_tick_could_take(world, monkeypatch):  # noqa: F811 — the imported fixture
    """The author wake gate fires for five waiting findings, not for rows a tick would only hold again; a deferred row (it
    may land on the next tick) is still work. (design r8 Schema statuses: held is not waiting; G-T1)"""
    from defender.learning.core import drains
    from defender.tests.support.learning.curation._drain719 import finding_row

    w = world
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "5")
    tid = w.t.tenant_id

    def seed(prefix: str, n: int) -> None:
        call(w.dsn, "publish_findings", tid, "run-1", [finding_row(f"{prefix}/b/0/{i}", run_id=f"run-{prefix}") for i in range(n)], kind="finding")

    seed("held", 5)
    _set_status(w.dsn, tid, "held", "held")
    assert drains.author_work_waiting(w.paths) is False, "the wake gate fired for five rows already held for a person"

    seed("one", 1)
    assert drains.author_work_waiting(w.paths) is False, "one waiting row beside five held ones is one row of work, not six"

    seed("five", 5)
    assert drains.author_work_waiting(w.paths) is True, "five waiting rows must wake the drain, however many held ones sit beside them"

    _set_status(w.dsn, tid, "five", "waiting", deferrals=1)
    assert drains.author_work_waiting(w.paths) is True, "deferred rows were subtracted from the wake gate"
