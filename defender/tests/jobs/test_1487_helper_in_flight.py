"""#1487 Flow 3: the post-step's helper answers "work waits" only from a store its session no longer changes. A store
request still being answered when the container exits (a claim blocked on the lane's lock, say) may yet commit, so the
helper exits 0, no answer, and answers no store request after. The real helper in this process over a container
stand-in, a real PostgreSQL."""
from __future__ import annotations

import sys
import threading
import time
from typing import Any

import psycopg
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

_LANE_LOCK = "SELECT pg_advisory_xact_lock(hashtextextended('learning.lane:' || %s || ':author', 0))"


def _waiting_on_a_lock(dsn: str) -> bool:
    return bool(execute(dsn, "SELECT 1 FROM pg_locks WHERE locktype = 'advisory' AND NOT granted"))


def _post_step(scene: Any, *, in_flight: bool) -> tuple[int, Any]:
    """A family-less post-step whose container sends `store.claim` while the test holds the author lane's lock and exits
    once the claim waits on it (`in_flight`), or once the claim was answered (the control). The helper's exit status, and
    what the claim was answered."""
    answered: list[Any] = []

    with psycopg.connect(scene.dsn) as holder:
        holder.execute(_LANE_LOCK, (str(scene.tenant),))

        def job(container: Any) -> int:
            def claim() -> None:
                try:
                    answered.append(container.request("store.claim"))
                except Exception as refused:  # noqa: BLE001 — what the claim got is the case's to judge
                    answered.append(refused)

            sender = threading.Thread(target=claim, daemon=True)
            sender.start()
            deadline = time.monotonic() + 30
            while not _waiting_on_a_lock(scene.dsn):
                assert time.monotonic() < deadline, "premise: the claim reached the lane's lock"
                time.sleep(0.05)
            if in_flight:
                # The helper answers once this returns, then waits for the claim's thread at its end: the lock goes
                # after the answer was decided.
                threading.Timer(3.0, holder.rollback).start()
            else:
                holder.rollback()
                sender.join(30)
                assert answered, "control: the claim was answered once the lock went"
            return 0

        rc = run_kind(scene, "post-step", job, family_less=True).rc
        holder.rollback()
    return rc, answered


def test_a_store_request_in_flight_when_the_container_exits_leaves_no_answer(scene, monkeypatch):
    """The container exits while its claim waits on the lane's lock: the helper exits 0 (no answer), not WORK_WAITS or
    NOTHING_WAITS, though a finding waits. The control, the claim answered before the exit, answers: the batch it
    claimed is the author lane's working batch, so work waits."""
    from defender import job_host

    R.settings_env(monkeypatch, threshold=1)
    call(scene.dsn, "publish_findings", scene.tenant, "run-1", [finding("s/w/0/0")], kind=FINDING)

    rc, _answered = _post_step(scene, in_flight=True)
    assert rc == 0, f"the helper answered {rc} with a store request still in flight"

    # The claim committed once the lock went: put its finding back to waiting for the control.
    execute(scene.dsn, "UPDATE learning.work_items SET status = 'waiting', batch_id = NULL WHERE tenant_id = %s",
            (scene.tenant,))
    execute(scene.dsn, "DELETE FROM learning.batches WHERE tenant_id = %s", (scene.tenant,))
    rc, answered = _post_step(scene, in_flight=False)
    assert rc == job_host.WORK_WAITS, (rc, answered)
