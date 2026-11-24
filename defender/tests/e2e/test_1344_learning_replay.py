"""#1344 one flow through the real wiring: a worker-run investigation completes, its auto job is claimed, a real family
runs on scripted models (siblings as real `run.main` in the job container's process), the judge's findings wait in the
episode, the row ends, the post-step publishes them to the queue and the drain gate runs.

#1546: both jobs run behind the real per-job helper over the real evidence store (Garage and OpenBao, as
`e2e/test_worker_replay.py`'s lane): the investigation stores its run as its bundle and nothing of it stays on the host
(A-O1), the learning job pulls that accepted bundle as its one input (r10), and each end is the worker's decision over the
facts its helper staged. What the cases read of the source run is read from its stored bundle.

Also the unreadable-history outcome (O3, L5): a source whose stored session store carries a format version current code
refuses ends `failed`/`launch_refused`, typed, never a crash.
Not real here: the Docker containers and boxes (the helper's docker stand-in; an unboxed executor), the models (scripts),
the tenant's systems (a stand-in elastic), the post-step's helper (a socket stand-in)."""
from __future__ import annotations

import json
import shutil
import sys
import tempfile
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
from defender.tests.support.shared._postgres1339 import execute, migrated_database  # noqa: F401 — fixture

pytestmark = [pytest.mark.anyio, pytest.mark.postgres, pytest.mark.e2e, pytest.mark.openbao, pytest.mark.garage]

ENTRY = Path("defender") / "tests" / "support" / "jobs" / "_flow_entry1344.py"
#: The build commit the children's code copy is marked with (any non-empty stamp: siblings must agree with each other).
COPY_COMMIT = "1344" + "c" * 36


def entry_in_a_code_copy(home: Path) -> Path:
    """`_flow_entry1344.py` inside a code copy of this checkout made by the worker's own start step
    (`refresh_code_copy`), as a deployed worker runs every child: a run started from it stamps the copy's marker
    (clean, `code_copy`), never the live checkout, whose state is the developer's. The copy carries the tests, since it
    copies the whole `defender/`."""
    from defender.worker import refresh_code_copy

    home.mkdir(parents=True, exist_ok=True)
    copy = refresh_code_copy(home, source=DEFENDER.parent, environ={"DEFENDER_BUILD_COMMIT": COPY_COMMIT})
    return copy / ENTRY
JOB_COLUMNS = ("id", "status", "reason", "message", "fork_message_id", "publish_state")


def _stored_by(dsn: str, job: str) -> int:
    """How many learning work items carry the job as their `source_run` (the rows its end added)."""
    return execute(dsn, "SELECT count(*) FROM learning.work_items WHERE source_run = %s", (job,))[0][0]


def _jobs(dsn: str, investigation: str) -> list[dict]:
    found = execute(dsn, f"SELECT {', '.join(JOB_COLUMNS)} FROM jobs.learning_jobs WHERE investigation_id = %s",  # noqa: S608
                    (investigation,))
    return [dict(zip(JOB_COLUMNS, r, strict=True)) for r in found]


def _admitted_gathers(lane, run_id: str, dest: Path) -> tuple[list[int], list[int]]:
    """MAIN's `gather` responses in the worker-made run, and those the existing admission check lets a world fork at. The
    run is read from the investigation's own stored bundle (#1546 A-O1: nothing of it stays on the host), extracted under
    `dest` (`test_worker_replay.Lane.run`)."""
    from pydantic_ai.messages import ModelResponse, ToolCallPart

    from defender.investigation import branch
    from defender.records import session_store
    from defender.tests.support.learning.branch._branch_947 import spec_at
    from defender.tests.support.shared.contracts._spec1077 import fixture_run

    source = fixture_run(lane.run(run_id, dest))
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


async def _run_flow(migrated_database, tmp_path, monkeypatch, request, *, investigate_mode, damage=None):  # noqa: F811
    """The worker over one queued investigation, learning slot on: returns what the cases read back. #1546: the lane has
    the store every job needs (`test_worker_replay._lane`: Garage by the helper's environment names, the tenant's
    `evidence-<T>` key and its AppRole login, handed to each helper through `_flow_entry1344.LOGIN_ENV`), and the tenant is
    this test's alone (`fresh_tenant`: the store's objects live under `t/<tenant>/`, which the `garage` fixture empties at
    each test's end)."""
    from defender.tests.e2e.test_worker_replay import _lane, fresh_tenant
    from defender.tests.tenancy.tenant_1108_p4 import _s_b_support as B

    openbao, garage, evidence_keys = (request.getfixturevalue(name) for name in ("openbao", "garage", "evidence_keys"))
    # A short data root (#1170): the investigation's job socket lives under it, and pytest's folders overrun a unix
    # socket's ~108 bytes.
    root = Path(tempfile.mkdtemp(prefix="j", dir="/tmp"))
    request.addfinalizer(lambda: shutil.rmtree(root, ignore_errors=True))
    monkeypatch.setenv("DEFENDER_DATA_ROOT", str(root))
    monkeypatch.setenv("DEFENDER_DATABASE_DSN", migrated_database)
    monkeypatch.delenv("DEFENDER_ALLOW_UNSANDBOXED", raising=False)
    monkeypatch.setenv("PYTHONDONTWRITEBYTECODE", "1")  # the copy is read-only, as the worker's children see it
    entry = entry_in_a_code_copy(tmp_path / "code")
    if damage is not None:
        # L5: the learning job's helper child, before its helper starts, rewrites the source's stored bundle
        # (`_flow_entry1344._a_source_of_another_store_version`): in its own process, never on this test's event loop,
        # where the worker's transactions are parked.
        monkeypatch.setenv("FLOW_DAMAGE", damage)
    golden = DEFENDER / "tests" / "fixtures" / "e2e" / "golden-v2sshd"
    marks = tmp_path / "marks"
    with B.run_tenant(tmp_path, root, tenant_id=fresh_tenant()) as t:
        register_tenant(migrated_database, t.tenant_id, data_root=root)
        (root / t.tenant_id / "runs").mkdir(exist_ok=True)
        (root / t.tenant_id / "learning").mkdir(exist_ok=True)  # the host's prepare step makes the learning root
        lane = _lane(monkeypatch, migrated_database, t.tenant_id, openbao, garage, evidence_keys)
        flow: dict = {"tenant": t.tenant_id, "root": root, "marks": marks}

        def tail(launch, source: str) -> list[str]:
            return ["--job", source, "--tenant", launch.tenant_id, "--parent-pid", str(launch.parent_pid)]

        def investigation(launch) -> list[str]:
            return [sys.executable, str(entry), investigate_mode, t.commit, str(marks / "investigate"), str(t.remote),
                    *tail(launch, launch.investigation_id), "--alert-digest", launch.alert_digest]  # C-1: the digest the worker hands the helper

        async with job_store(migrated_database) as store:
            alert = await an_alert(store, t.tenant_id, raw=(golden / "alert.json").read_bytes())
            inv, _ = await store.create_investigation(t.tenant_id, alert.alert_id, "k1", actor="u-1")
            flow["investigation"] = inv.investigation_id

            def learning(launch) -> list[str]:
                return [sys.executable, str(entry), "family", t.commit, str(marks / "family"), str(t.remote), "--job", launch.job_id,
                        "--tenant", launch.tenant_id, "--source", inv.investigation_id, "--parent-pid", str(launch.parent_pid)]

            def post_step(launch) -> list[str]:
                return [sys.executable, str(entry), "post-step", t.commit, str(marks / "post-step"), str(t.remote), "--job", launch.job_id,
                        "--tenant", launch.tenant_id, "--parent-pid", str(launch.parent_pid)]

            worker = make_worker(store, root, investigation, containers=StandInContainers(tmp_path / "containers"),
                                 slots=3, learning_slots=1, learning_argv=learning, post_step_argv=post_step)
            await worker.drain()
        if damage is None:  # a damaged store is one current code refuses to open, by design
            flow["gathers"] = _admitted_gathers(lane, str(inv.investigation_id), tmp_path / "stored")
        else:  # the source as the learning job's pull was served it: the stored bundle, read back here
            from defender.tests.support.jobs import _store_version1546 as V

            body = lane.bundle(str(inv.investigation_id))
            assert body is not None, "premise: the investigation stored its bundle"
            flow["stored_version"] = V.store_version(body, str(inv.investigation_id), tmp_path / "read-back")
    return flow


def _queued_findings(dsn: str, tenant_id: str) -> list[dict]:
    """The finding rows the tenant's learning store holds (#1278: published rows, not a queue file)."""
    from defender.tests.support.learning.core._store1278 import call

    return [dict(item.payload) for item in call(dsn, "work", tenant_id) if item.kind == "finding"]


async def test_o1_o8_o14_a_completed_investigation_is_learned_from_end_to_end_and_its_findings_reach_the_queue(
        migrated_database, tmp_path, monkeypatch, request):  # noqa: F811
    """Completed run → auto job → family → judge → row `completed` → published → drain gate saw the findings. (O1, O3, O4, O8, O14, D-C)"""

    flow = await _run_flow(migrated_database, tmp_path, monkeypatch, request, investigate_mode="investigate")

    stored = row(migrated_database, flow["investigation"])
    assert stored["stage"] == "completed", stored
    gathers, admitted = flow["gathers"]
    assert len(gathers) == 1, "premise: MAIN made one gather call"
    assert admitted == gathers, "premise: the run's gather response passes the existing admission check (fork yield, claim 5a)"
    (job,) = _jobs(migrated_database, flow["investigation"])
    assert (job["status"], job["reason"]) == ("completed", None), job
    assert job["fork_message_id"] == str(gathers[0]), "the family forked somewhere but at MAIN's gather"
    assert _stored_by(migrated_database, job["id"]) >= 1, job  # #1589: the stored rows, not a count on the row
    assert job["publish_state"] == "done", job
    queue = _queued_findings(migrated_database, flow["tenant"])
    assert [r for r in queue if "the lead was never revisited" in json.dumps(r)], "the judge's finding never reached the queue"
    gate = flow["marks"] / "post-step" / "gate"
    assert gate.is_file(), "the drain gate never ran"
    assert int(gate.read_text(encoding="utf-8")) >= 1, "the gate ran before this job's findings were published"
    assert not (flow["root"] / flow["tenant"] / "runs" / f"{job['id']}.post-step.json").exists(), "the post-step wrote a record (#1487 O7: the worker answers 'waiting')"
    assert sorted(p.name for p in (flow["marks"] / "family").glob("sibling-*")), "no sibling ran as a real run"


async def test_o3_a_completed_investigation_with_no_gather_ends_its_job_skipped_and_nothing_is_published(
        migrated_database, tmp_path, monkeypatch, request):  # noqa: F811
    """Same flow, MAIN never gathered: `skipped`/`no_fork_point`, no sibling, no queue row; the child started, so the post-step and its gate still run. (O3, O8, L3)"""

    flow = await _run_flow(migrated_database, tmp_path, monkeypatch, request, investigate_mode="investigate-no-gather")

    assert row(migrated_database, flow["investigation"])["stage"] == "completed"
    assert flow["gathers"] == ([], []), "premise: MAIN made no gather call"
    (job,) = _jobs(migrated_database, flow["investigation"])
    assert (job["status"], job["reason"]) == ("skipped", "no_fork_point"), job
    assert _stored_by(migrated_database, job["id"]) == 0
    assert _queued_findings(migrated_database, flow["tenant"]) == []
    gate = flow["marks"] / "post-step" / "gate"
    assert gate.is_file(), "the job's child started, so the post-step runs the gate whatever the ending"
    assert int(gate.read_text(encoding="utf-8")) == 0
    assert not (flow["root"] / flow["tenant"] / "runs" / f"{job['id']}.post-step.json").exists(), "the post-step wrote a record (#1487 O7)"
    assert not list((flow["marks"] / "family").glob("sibling-*")), "a sibling started with no fork point"


async def test_l5_a_source_whose_session_store_is_of_another_version_ends_failed_launch_refused_not_in_a_crash(
        migrated_database, tmp_path, monkeypatch, request):  # noqa: F811
    """The source's database carries a format version current code refuses: `failed`/`launch_refused` with the `schema-version` kind's fixed wording, before any sibling, as every source whose closing record cannot be looked at (owner decision, #1534: no backwards compatibility; no longer `skipped`/`history_unreadable`); the intact flow above is the control. (O3, L5, Old history, V-LOOK)"""
    from defender.tests.support.jobs import _store_version1546 as V
    from defender.tests.support.storage import _readers1534 as R

    flow = await _run_flow(migrated_database, tmp_path, monkeypatch, request, investigate_mode="investigate", damage="store-version")

    assert row(migrated_database, flow["investigation"])["stage"] == "completed"
    assert flow.get("stored_version") == V.OTHER_VERSION, "premise: the source's stored bundle holds a session store of another version"
    assert (flow["marks"] / "family" / "runs").is_file(), "premise: the family step started (behind its real helper)"
    (job,) = _jobs(migrated_database, flow["investigation"])
    assert (job["status"], job["reason"]) == ("failed", "launch_refused"), job
    assert R.names_only("schema-version", job["message"] or ""), job
    assert str(tmp_path) not in (job["message"] or ""), "the fault's detail (a path) reached the job's message"
    assert not list((flow["marks"] / "family").glob("sibling-*")), "a sibling started on a history that cannot be read"
    assert _queued_findings(migrated_database, flow["tenant"]) == []
