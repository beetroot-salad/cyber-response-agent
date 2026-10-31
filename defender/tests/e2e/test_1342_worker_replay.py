"""#1342 O16: one hermetic replay through the real worker lane, child process included.

The real `Worker` (in-process) over a per-test database claims a queued investigation, writes the
launch files and spawns `_job_entry1342.py`, which runs the real job entry with the replay harness's
seams (an unboxed executor handed through the lifecycle's `start_box` seam, never the environment;
a replay model closing with the golden's disposition). The row is read back from the database."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

from defender.tests.support.jobs._jobs1342 import (
    DEFENDER,
    StandInContainers,
    an_alert,
    is_box_token,
    job_store,
    make_worker,
    register_tenant,
    row,
)
from defender.tests.support.shared._postgres1339 import migrated_database  # noqa: F401 — fixture

pytestmark = [pytest.mark.anyio, pytest.mark.postgres, pytest.mark.e2e]

ENTRY = DEFENDER / "tests" / "support" / "jobs" / "_job_entry1342.py"


@pytest.mark.parametrize("line_ends", ["as stored", "CRLF", "padded", "decomposed", "zwnbsp", "feff_rich"])
async def test_o16_a_replay_through_the_worker_lane_completes_with_its_disposition(
        migrated_database, tmp_path, monkeypatch, line_ends):  # noqa: F811
    """queued → completed with the golden's disposition, cost read from its sessions, knowledge current at the published commit; the run holds the alert's exact bytes, CRLF, padding whitespace, decomposed text and a U+FEFF inside a value included. (O16, r5 C1/C2: the real driver's review state is what the record's `report_committed` reads)"""
    from defender.records.formats import parse_report_text
    from defender.tests.tenancy.tenant_1108_p4 import _s_b_support as B

    root = tmp_path / "data"
    root.mkdir()
    monkeypatch.setenv("DEFENDER_DATA_ROOT", str(root))
    monkeypatch.delenv("DEFENDER_ALLOW_UNSANDBOXED", raising=False)
    golden = DEFENDER / "tests" / "fixtures" / "e2e" / "golden-v2sshd"
    disposition = parse_report_text((golden / "report.md").read_text(encoding="utf-8")).disposition
    golden_bytes = (golden / "alert.json").read_bytes()
    if line_ends == "CRLF":
        golden_bytes = golden_bytes.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
        assert b"\r\n" in golden_bytes, "premise: the alert has line ends to turn into CRLF"
    elif line_ends == "padded":
        golden_bytes = b"\n\t " + golden_bytes.rstrip(b"\n") + b"   \n"
    elif line_ends == "decomposed":
        document = json.loads(golden_bytes)
        document["analyst_note"] = "cafe\u0301"
        golden_bytes = (json.dumps(document, indent=2, ensure_ascii=False) + "\n").encode()
        assert "e\u0301".encode() in golden_bytes, "premise: a decomposed sequence in the stored bytes"
    elif line_ends == "zwnbsp":
        document = json.loads(golden_bytes)
        document["analyst_note"] = "a\ufeffb"
        golden_bytes = (json.dumps(document, indent=2, ensure_ascii=False) + "\n").encode()
        assert b"\xef\xbb\xbf" in golden_bytes, "premise: a U+FEFF in the stored bytes"
        assert not golden_bytes.startswith(b"\xef\xbb\xbf"), "premise: not a leading byte-order mark"
    elif line_ends == "feff_rich":
        document = json.loads(golden_bytes)
        document.update({"lead": "\ufeffx", "tail": "y\ufeff", "pair": "p\ufeff\ufeffq", "apart": "\ufeffm\ufeffn",
                         "k\ufeffey": 1})
        golden_bytes = (json.dumps(document, indent=2, ensure_ascii=False) + "\n").encode()
        bom = b"\xef\xbb\xbf"
        for shape in (b'"' + bom, bom + b'"', bom + bom, b"m" + bom + b"n", b'"k' + bom + b'ey":'):
            assert shape in golden_bytes, ("premise", shape)
    with B.run_tenant(tmp_path, root) as t:
        register_tenant(migrated_database, t.tenant_id)
        (root / t.tenant_id / "runs").mkdir(exist_ok=True)  # R1: a set-up tenant has runs/

        def child(launch) -> list[str]:
            return [sys.executable, str(ENTRY), "replay", t.commit, str(tmp_path / "marks"), "--job", launch.investigation_id,
                    "--tenant", launch.tenant_id, "--parent-pid", str(launch.parent_pid)]

        async with job_store(migrated_database) as store:
            alert = await an_alert(store, t.tenant_id, raw=golden_bytes)
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
        from defender.records import RunPaths

        launch = json.loads((runs / f"{inv.investigation_id}.launch.json").read_text(encoding="utf-8"))
        held = RunPaths(runs / inv.investigation_id).alert.read_bytes()
        assert held == (runs / f"{inv.investigation_id}.alert.json").read_bytes() == golden_bytes
        assert hashlib.sha256(held).hexdigest() == launch["digest"]
        assert is_box_token(launch["box_token"]), launch
        assert (tmp_path / "marks" / "start-token").read_text(encoding="utf-8") == launch["box_token"], \
            "the child's box start was not handed the launch record's token (r5 C1)"


async def test_o8_a_provider_fault_after_the_real_drivers_close_still_records_the_report_committed(
        migrated_database, tmp_path, monkeypatch):  # noqa: F811
    """The replay model commits the golden's report and the next model request raises inside the real driver: the job-end record still says `report_committed: true`, because the driver's own review state (the holder's dict) closed. (O8, M2, r5 C2)"""
    from defender.tests.tenancy.tenant_1108_p4 import _s_b_support as B

    root = tmp_path / "data"
    root.mkdir()
    monkeypatch.setenv("DEFENDER_DATA_ROOT", str(root))
    monkeypatch.delenv("DEFENDER_ALLOW_UNSANDBOXED", raising=False)
    golden = DEFENDER / "tests" / "fixtures" / "e2e" / "golden-v2sshd"
    with B.run_tenant(tmp_path, root) as t:
        register_tenant(migrated_database, t.tenant_id)
        (root / t.tenant_id / "runs").mkdir(exist_ok=True)

        def child(launch) -> list[str]:
            return [sys.executable, str(ENTRY), "replay-fault-after-close", t.commit, str(tmp_path / "marks"),
                    "--job", launch.investigation_id, "--tenant", launch.tenant_id,
                    "--parent-pid", str(launch.parent_pid)]

        async with job_store(migrated_database) as store:
            alert = await an_alert(store, t.tenant_id, raw=(golden / "alert.json").read_bytes())
            inv, _ = await store.create_investigation(t.tenant_id, alert.alert_id, "k1", actor="u-1")
            await make_worker(store, root, child, containers=StandInContainers(tmp_path / "containers")).drain()

        runs = root / t.tenant_id / "runs"
        end = json.loads((runs / f"{inv.investigation_id}.job-end.json").read_text(encoding="utf-8"))
        assert (runs / inv.investigation_id / "report.md").is_file(), "premise: the report was committed before the fault"
        assert (end["setup"], end["box"]) == ("done", "started"), end
        assert end["report_committed"] is True, end
