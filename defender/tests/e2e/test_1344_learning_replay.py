"""#1344 one flow through the real wiring: a worker-run investigation completes, its auto job is claimed, a real family
runs on scripted models (siblings as real `run.main` in a child process), the judge's findings wait in the episode, the
row ends, the post-step publishes them to the queue and the drain gate runs.

Also the old-history outcome (O3, L5): a source recorded before fork snapshots existed ends `skipped`, typed, never a crash.
Not real here: the Docker boxes (unboxed executor), the models (scripts), the tenant's systems (a stand-in elastic)."""
from __future__ import annotations

import json
import sys

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
from defender.tests.support.shared._postgres1339 import execute, migrated_database  # noqa: F401 — fixture

pytestmark = [pytest.mark.anyio, pytest.mark.postgres, pytest.mark.e2e]

ENTRY = DEFENDER / "tests" / "support" / "jobs" / "_flow_entry1344.py"
JOB_COLUMNS = ("id", "status", "reason", "message", "fork_message_id", "findings_count", "publish_state")


def _jobs(dsn: str, investigation: str) -> list[dict]:
    found = execute(dsn, f"SELECT {', '.join(JOB_COLUMNS)} FROM jobs.learning_jobs WHERE investigation_id = %s",  # noqa: S608
                    (investigation,))
    return [dict(zip(JOB_COLUMNS, r, strict=True)) for r in found]


def _admitted_gathers(tenant: str, run_id: str) -> tuple[list[int], list[int]]:
    """MAIN's `gather` responses in the worker-made run, and those the existing admission check lets a world fork at."""
    from pydantic_ai.messages import ModelResponse, ToolCallPart

    from defender.investigation import branch
    from defender.records import RunId, session_store
    from defender.tenancy import _tenant
    from defender.tests.support.learning.branch._branch_947 import spec_at
    from defender.tests.support.shared._locations_1210 import fixture_data_root

    root = _tenant.resolve_data_root()
    source = _tenant.accept_tenant(fixture_data_root(root), tenant, defender_dir=DEFENDER).runs_repository().open(
        RunId.parse(run_id))
    opened = branch.source_store_if_any(source.run_dir, source_run=source)
    assert opened is not None, "premise: the run kept a session store"
    with opened as store:
        session = session_store.main_session_id(store)
        ids = session_store.path_row_ids(store, session)
        messages = session_store.hydrate(store, session, role="analysis")
        gathers = [rid for rid, m in zip(ids, messages, strict=True) if isinstance(m, ModelResponse)
                   and any(isinstance(p, ToolCallPart) and p.tool_name == "gather" for p in m.parts)]
        admitted = []
        for rid in gathers:
            try:
                branch.validate(store, spec_at(store, source.run_dir, rid), source_run=source)
            except branch.BranchError:
                continue
            admitted.append(rid)
    return gathers, admitted


async def _run_flow(migrated_database, tmp_path, monkeypatch, *, investigate_mode, damage=None):  # noqa: F811
    """The worker over one queued investigation, learning slot on: returns what the cases read back."""
    from defender.tests.tenancy.tenant_1108_p4 import _s_b_support as B

    root = tmp_path / "data"
    root.mkdir()
    monkeypatch.setenv("DEFENDER_DATA_ROOT", str(root))
    monkeypatch.setenv("DEFENDER_DATABASE_DSN", migrated_database)
    monkeypatch.delenv("DEFENDER_ALLOW_UNSANDBOXED", raising=False)
    if damage is not None:
        monkeypatch.setenv("FLOW_DAMAGE", damage)
    golden = DEFENDER / "tests" / "fixtures" / "e2e" / "golden-v2sshd"
    marks = tmp_path / "marks"
    with B.run_tenant(tmp_path, root) as t:
        register_tenant(migrated_database, t.tenant_id, data_root=root)
        (root / t.tenant_id / "runs").mkdir(exist_ok=True)
        flow: dict = {"tenant": t.tenant_id, "root": root, "marks": marks}

        def tail(launch, source: str) -> list[str]:
            return ["--job", source, "--tenant", launch.tenant_id, "--parent-pid", str(launch.parent_pid)]

        def investigation(launch) -> list[str]:
            return [sys.executable, str(ENTRY), investigate_mode, t.commit, str(marks / "investigate"),
                    *tail(launch, launch.investigation_id)]

        async with job_store(migrated_database) as store:
            alert = await an_alert(store, t.tenant_id, raw=(golden / "alert.json").read_bytes())
            inv, _ = await store.create_investigation(t.tenant_id, alert.alert_id, "k1", actor="u-1")
            flow["investigation"] = inv.investigation_id

            def learning(launch) -> list[str]:
                return [sys.executable, str(ENTRY), "family", t.commit, str(marks / "family"), "--job", launch.job_id,
                        "--tenant", launch.tenant_id, "--source", inv.investigation_id, "--parent-pid", str(launch.parent_pid)]

            def post_step(launch) -> list[str]:
                return [sys.executable, str(ENTRY), "post-step", t.commit, str(marks / "post-step"), "--job", launch.job_id,
                        "--tenant", launch.tenant_id, "--pending", *launch.pending_job_ids,
                        "--parent-pid", str(launch.parent_pid)]

            worker = make_worker(store, root, investigation, containers=StandInContainers(tmp_path / "containers"),
                                 slots=3, learning_slots=1, learning_argv=learning, post_step_argv=post_step)
            await worker.drain()
        flow["gathers"] = _admitted_gathers(t.tenant_id, inv.investigation_id)
    return flow


async def test_o1_o8_o14_a_completed_investigation_is_learned_from_end_to_end_and_its_findings_reach_the_queue(
        migrated_database, tmp_path, monkeypatch):  # noqa: F811
    """Completed run → auto job → family → judge → row `completed` → published → drain gate saw the findings. (O1, O3, O4, O8, O14, D-C)"""
    from defender.learning.core.state import FINDINGS
    from defender.tests.support.learning.core._state1135 import state_over

    flow = await _run_flow(migrated_database, tmp_path, monkeypatch, investigate_mode="investigate")

    stored = row(migrated_database, flow["investigation"])
    assert stored["stage"] == "completed", stored
    gathers, admitted = flow["gathers"]
    assert len(gathers) == 1, "premise: MAIN made one gather call"
    assert admitted == gathers, "premise: the run's gather response passes the existing admission check (fork yield, claim 5a)"
    (job,) = _jobs(migrated_database, flow["investigation"])
    assert (job["status"], job["reason"]) == ("completed", None), job
    assert job["fork_message_id"] == str(gathers[0]), "the family forked somewhere but at MAIN's gather"
    assert job["findings_count"] >= 1, job
    assert job["publish_state"] == "done", job
    queue = state_over(flow["root"] / flow["tenant"] / "learning").rows(FINDINGS)
    assert [r for r in queue if "the lead was never revisited" in json.dumps(r)], "the judge's finding never reached the queue"
    gate = flow["marks"] / "post-step" / "gate"
    assert gate.is_file(), "the drain gate never ran"
    assert int(gate.read_text(encoding="utf-8")) >= 1, "the gate ran before this job's findings were published"
    record = json.loads((flow["root"] / flow["tenant"] / "runs" / f"{job['id']}.post-step.json").read_text(encoding="utf-8"))
    assert record == {"published": [job["id"]], "refused": []}
    assert sorted(p.name for p in (flow["marks"] / "family").glob("sibling-*")), "no sibling ran as a real run"


async def test_o3_a_completed_investigation_with_no_gather_ends_its_job_skipped_and_nothing_is_published(
        migrated_database, tmp_path, monkeypatch):  # noqa: F811
    """Same flow, MAIN never gathered: `skipped`/`no_fork_point`, no sibling, no queue row, no gate. (O3, L3)"""
    from defender.learning.core.state import FINDINGS
    from defender.tests.support.learning.core._state1135 import state_over

    flow = await _run_flow(migrated_database, tmp_path, monkeypatch, investigate_mode="investigate-no-gather")

    assert row(migrated_database, flow["investigation"])["stage"] == "completed"
    assert flow["gathers"] == ([], []), "premise: MAIN made no gather call"
    (job,) = _jobs(migrated_database, flow["investigation"])
    assert (job["status"], job["reason"]) == ("skipped", "no_fork_point"), job
    assert job["findings_count"] == 0
    assert state_over(flow["root"] / flow["tenant"] / "learning").rows(FINDINGS) == []
    assert not (flow["marks"] / "post-step" / "gate").exists(), "a job that started no family step ran the gate"
    assert not list((flow["marks"] / "family").glob("sibling-*")), "a sibling started with no fork point"


async def test_l5_a_source_whose_session_store_is_of_another_version_ends_skipped_history_unreadable_not_in_a_crash(
        migrated_database, tmp_path, monkeypatch):  # noqa: F811
    """The source's database carries a format version current code refuses: typed `skipped`/`history_unreadable` with the type in the message, before any sibling; the intact flow above is the control. (O3, L5, Old history)"""
    from defender.learning.core.state import FINDINGS
    from defender.tests.support.learning.core._state1135 import state_over

    flow = await _run_flow(migrated_database, tmp_path, monkeypatch, investigate_mode="investigate", damage="store-version")

    assert row(migrated_database, flow["investigation"])["stage"] == "completed"
    assert (flow["marks"] / "family" / "runs").is_file(), "premise: the family step started and damaged the store"
    (job,) = _jobs(migrated_database, flow["investigation"])
    assert (job["status"], job["reason"]) == ("skipped", "history_unreadable"), job
    assert "UnknownSchemaVersion" in (job["message"] or ""), "the message names the refusal type"
    assert not list((flow["marks"] / "family").glob("sibling-*")), "a sibling started on a history that cannot be read"
    assert state_over(flow["root"] / flow["tenant"] / "learning").rows(FINDINGS) == []
