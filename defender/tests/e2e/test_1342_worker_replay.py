"""#1342 O16: one hermetic replay through the real worker lane, child process included.

The real `Worker` (in-process) over a per-test database claims a queued investigation, writes the
launch files and spawns `_job_entry1342.py`, which runs the real job entry with the replay harness's
seams (unboxed opt-out, replay model closing `inconclusive`). The row is read back from the database."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

from defender.tests.support.jobs._jobs1342 import (
    DEFENDER,
    StandInContainers,
    an_alert,
    job_store,
    make_worker,
    register_tenant,
    row,
)
from defender.tests.support.shared._postgres1339 import migrated_database  # noqa: F401 — fixture

pytestmark = [pytest.mark.anyio, pytest.mark.postgres, pytest.mark.e2e]

ENTRY = DEFENDER / "tests" / "support" / "jobs" / "_job_entry1342.py"


async def test_o16_a_replay_through_the_worker_lane_completes_with_its_disposition(
        migrated_database, tmp_path, monkeypatch):  # noqa: F811
    """queued → completed `inconclusive`, knowledge current at the published commit, no failure detail. (O16)"""
    from defender import box as box_mod
    from defender.tests.tenancy.tenant_1108_p4 import _s_b_support as B

    root = tmp_path / "data"
    root.mkdir()
    monkeypatch.setenv("DEFENDER_DATA_ROOT", str(root))
    monkeypatch.setenv("DEFENDER_ALLOW_UNSANDBOXED", "1")
    monkeypatch.delenv(box_mod.BoxSpec.ENV_VAR, raising=False)
    with B.run_tenant(tmp_path, root) as t:
        register_tenant(migrated_database, t.tenant_id)

        def child(launch) -> list[str]:
            return [sys.executable, str(ENTRY), t.commit, "--job", launch.investigation_id,
                    "--tenant", launch.tenant_id, "--parent-pid", str(launch.parent_pid)]

        async with job_store(migrated_database) as store:
            alert = await an_alert(store, t.tenant_id)
            inv, _ = await store.create_investigation(t.tenant_id, alert.alert_id, "k1", actor="u-1")
            worker = make_worker(store, root, child, containers=StandInContainers(tmp_path / "containers"))
            await worker.drain()

        stored = row(migrated_database, inv.investigation_id)
        runs = root / t.tenant_id / "runs"
        assert (stored["stage"], stored["disposition"], stored["failure_reason"]) == (
            "completed", "inconclusive", None), stored
        assert stored["knowledge"] == {"status": "current", "commit": t.commit, "stale_kind": None}
        assert (runs / inv.investigation_id / "report.md").is_file()
        assert (runs / f"{inv.investigation_id}.job-end.json").is_file()
        assert Path(runs / f"{inv.investigation_id}.launch.json").is_file()
