"""#1342 O16: one hermetic replay through the real worker lane, child process included.

The real `Worker` (in-process) over a per-test database claims a queued investigation, writes the
launch files and spawns `_job_entry1342.py`, which runs the real job entry with the replay harness's
seams (an unboxed executor handed through the lifecycle's `start_box` seam, never the environment;
a replay model closing with the golden's disposition). The row is read back from the database."""
from __future__ import annotations

import json
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
    """queued → completed with the golden's disposition, cost read from its sessions, knowledge current at the published commit. (O16)"""
    from defender.records.formats import parse_report_text
    from defender.tests.tenancy.tenant_1108_p4 import _s_b_support as B

    root = tmp_path / "data"
    root.mkdir()
    monkeypatch.setenv("DEFENDER_DATA_ROOT", str(root))
    monkeypatch.delenv("DEFENDER_ALLOW_UNSANDBOXED", raising=False)
    golden = DEFENDER / "tests" / "fixtures" / "e2e" / "golden-v2sshd"
    disposition = parse_report_text((golden / "report.md").read_text(encoding="utf-8")).disposition
    with B.run_tenant(tmp_path, root) as t:
        register_tenant(migrated_database, t.tenant_id)
        (root / t.tenant_id / "runs").mkdir(exist_ok=True)  # R1: a set-up tenant has runs/

        def child(launch) -> list[str]:
            return [sys.executable, str(ENTRY), "replay", t.commit, str(tmp_path / "marks"), "--job", launch.investigation_id,
                    "--tenant", launch.tenant_id, "--parent-pid", str(launch.parent_pid)]

        async with job_store(migrated_database) as store:
            alert = await an_alert(store, t.tenant_id, raw=(golden / "alert.json").read_bytes())
            inv, _ = await store.create_investigation(t.tenant_id, alert.alert_id, "k1", actor="u-1")
            worker = make_worker(store, root, child, containers=StandInContainers(tmp_path / "containers"))
            await worker.drain()

        stored = row(migrated_database, inv.investigation_id)
        runs = root / t.tenant_id / "runs"
        assert (stored["stage"], stored["disposition"], stored["failure_reason"]) == (
            "completed", disposition, None), stored
        assert (runs / f"{inv.investigation_id}.session-pointer.json").is_file(), "premise: the run opened its session store"
        assert stored["cost_usd"] == 0.0, "the replay model is unpriced: read from its sessions, not unknown"
        assert stored["knowledge"] == {"status": "current", "commit": t.commit, "stale_kind": None}
        assert (runs / inv.investigation_id / "report.md").is_file()
        assert (runs / f"{inv.investigation_id}.job-end.json").is_file()
        assert Path(runs / f"{inv.investigation_id}.launch.json").is_file()
        assert json.loads((runs / f"{inv.investigation_id}.job-end.json").read_text(encoding="utf-8")) == {
            "setup": "done", "box": "started", "report_committed": True, "scrub_verified": True}
