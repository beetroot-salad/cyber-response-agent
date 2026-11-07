"""#1344 store and worker: learning jobs in the store and on the worker's slots, over a real database and real
child processes. The children are scripted: they leave the records a case names (names: `interface.md`); the worker decides.
"""
from __future__ import annotations

import asyncio
import datetime as dt
import inspect
import json
import os
import re
import signal
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from defender.jobs import Conflict, UnknownReference
from defender.jobs.store import is_refusal
from defender.tests.jobs.test_1342_worker import _FAST, _child, _committed, _queued, _run_one, _until, _worker
from defender.tests.support.jobs._jobs1342 import (
    NOW,
    T1,
    T2,
    JobsAudit,
    ScriptedChild,
    an_alert,
    job_store,
    move_tenant,
    register_tenant,
    row,
)
from defender.tests.support.shared._postgres1339 import execute
from defender.tests.support.shared.filesystem._handoff import write_whole

pytestmark = [pytest.mark.anyio, pytest.mark.postgres]

END = "{id}.learning-end.json"
PROGRESS = "{id}.learning-progress.json"
COLUMNS = ("id", "request_key", "attempt", "trigger", "status", "stage", "fork_message_id", "created_at",
           "reason", "message", "sibling_cost_usd", "findings_count", "publish_state")
RUN_TEXT = "RUN-TEXT-1344"
OVER_AGE = NOW - dt.timedelta(hours=25)
SKIPPED_BY_THE_ENTRY = ("no_fork_point", "history_unreadable", "family_unusable")
FAILED_BY_THE_ENTRY = ("control_failed", "launch_refused", "verify_refused", "source_unavailable", "judge_failed",
                       "entry_error")


@pytest.fixture
def world(migrated_database: str, tmp_path: Path) -> dict:
    """Tenant T1 with its `runs` and `sessions`, the shape `test_1342_worker`'s fixture gives."""
    register_tenant(migrated_database, T1)
    root = tmp_path / "data"
    (root / T1 / "runs").mkdir(parents=True)
    (root / T1 / "sessions").mkdir()
    return {"dsn": migrated_database, "root": root, "runs": root / T1 / "runs", "tmp": tmp_path}


def learning_end(status: str, reason: str | None = None, *, message: str | None = None, findings: int = 0,
                 cost: float = 0.0, fork: str | None = "m-1", stage: str | None = "judge") -> str:
    """The entry's end record, in the interface's whole shape."""
    return json.dumps({"status": status, "reason": reason, "message": message, "fork_message_id": fork,
                       "stage": stage, "findings_count": findings, "sibling_cost_usd": cost})


def jobs_of(dsn: str, investigation: str) -> list[dict]:
    """Every attempt of every job of an investigation, oldest attempt first."""
    found = execute(dsn, f"SELECT {', '.join(COLUMNS)} FROM jobs.learning_jobs "  # noqa: S608
                         "WHERE investigation_id = %s ORDER BY request_key, attempt", (investigation,))
    return [dict(zip(COLUMNS, r, strict=True)) for r in found]


def job_row(dsn: str, job_id: str) -> dict | None:
    found = execute(dsn, f"SELECT {', '.join(COLUMNS)} FROM jobs.learning_jobs WHERE id = %s",  # noqa: S608
                    (job_id,))
    return dict(zip(COLUMNS, found[0], strict=True)) if found else None


def investigation_of(dsn: str, job_id: str) -> str:
    return execute(dsn, "SELECT investigation_id FROM jobs.learning_jobs WHERE id = %s", (job_id,))[0][0]


def set_created(dsn: str, table: str, row_id: str, when: dt.datetime) -> None:
    """Age one row: `fixed_clock` gives every row the same `created_at`."""
    assert table in {"learning_jobs", "investigations"}
    execute(dsn, f"UPDATE jobs.{table} SET created_at = %s WHERE id = %s", (when, row_id))  # noqa: S608


class JobChild(ScriptedChild):
    """`learning_argv`: `ScriptedChild` keyed by the job's id."""

    def __call__(self, launch) -> list[str]:
        write_whole(self.spec, json.dumps(self.spec_dict()))
        return [sys.executable, str(self.script), str(self.spec), "--job", launch.job_id,
                "--tenant", launch.tenant_id, "--parent-pid", str(launch.parent_pid)]


class PostStepChild(ScriptedChild):
    """`post_step_argv`: records what the worker handed over and the job's row as the child starts, and answers with a
    record naming the handed jobs as published, except `refuse` (refused) and `omit` (in neither: a queue-level
    failure). `recording=False`: it leaves no record; `record_text`: it leaves exactly that text as its record."""

    def __init__(self, *a, dsn: str, refuse: tuple[str, ...] = (), omit: tuple[str, ...] = (),
                 recording: bool = True, record_text: str | None = None, **kw) -> None:
        super().__init__(*a, **kw)
        self.dsn, self.refuse, self.omit, self.recording, self.record_text = dsn, refuse, omit, recording, record_text
        self.handed: list[tuple[str, list[str], str]] = []

    def __call__(self, launch) -> list[str]:
        pending = sorted(launch.pending_job_ids)
        self.handed.append((launch.job_id, pending, job_row(self.dsn, launch.job_id)["status"]))
        self.files = {} if not self.recording else {"{id}.post-step.json": self.record_text if self.record_text is not None
                                                       else json.dumps({
            "published": [j for j in pending if j not in (*self.refuse, *self.omit)],
            "refused": [j for j in pending if j in self.refuse]})}
        write_whole(self.spec, json.dumps(self.spec_dict()))
        return [sys.executable, str(self.script), str(self.spec), "--job", launch.job_id,
                "--tenant", launch.tenant_id, "--parent-pid", str(launch.parent_pid)]


def job_child(world: dict, name: str = "job", **kw) -> JobChild:
    return JobChild(world["tmp"] / name, world["runs"], **kw)


def post_child(world: dict, name: str = "post", **kw) -> PostStepChild:
    return PostStepChild(world["tmp"] / name, world["runs"], dsn=world["dsn"], **kw)


def learning_worker(world: dict, store, *, job, post, inv=None, **kw):
    """A worker with one learning slot (a bare `Worker` has none) and both commands."""
    investigations = inv if inv is not None else _child(world)
    kw.setdefault("learning_slots", 1)
    return _worker(world, store, investigations, learning_argv=job, post_step_argv=post, **kw)


async def completed_investigation(store, *, ticket: str, key: str = "k1", tenant: str = T1) -> str:
    """An investigation brought to `completed` by the store's own claim and finish: its job queued."""
    alert = await an_alert(store, tenant, ticket=ticket)
    inv, _ = await store.create_investigation(tenant, alert.alert_id, key, actor="u-1")
    claim = await store.claim()
    assert claim.record.investigation_id == inv.investigation_id, "premise: nothing else was queued"
    await store.finish(tenant, inv.investigation_id, stage="completed", disposition="malicious", cost_usd=0.0)
    return inv.investigation_id


async def queued_job(world: dict, store, *, ticket: str, tenant: str = T1) -> str:
    return jobs_of(world["dsn"], await completed_investigation(store, ticket=ticket, tenant=tenant))[0]["id"]


def _stop_serving(serving: asyncio.Task) -> None:
    if not serving.done():
        os.kill(os.getpid(), signal.SIGTERM)


def _alive(child: ScriptedChild) -> int:
    """Children of this stand-in running now, by the order of their start and end events."""
    return sum(1 if kind == "start" else -1 for kind, _ in child.events())


def _lapse(dsn: str, job_id: str) -> None:
    execute(dsn, "UPDATE jobs.learning_jobs SET lease_expires_at = now() - interval '1 second' WHERE id = %s", (job_id,))


#: Text at an end record's path that cannot be read as the interface's shape.
UNREADABLE_END = [
    pytest.param("", id="empty"), pytest.param('{"status": "comp', id="truncated"), pytest.param("[]", id="not-an-object"),
    pytest.param(json.dumps({"status": "completed"}), id="missing-fields"),
    pytest.param(learning_end("done"), id="unknown-status"),
]
#: Likewise for the post-step record's.
UNREADABLE_POST = [
    pytest.param("", id="empty"), pytest.param('{"published": [', id="truncated"), pytest.param("[]", id="not-an-object"),
    pytest.param(json.dumps({"published": []}), id="missing-refused"),
    pytest.param(json.dumps({"published": "x", "refused": []}), id="wrong-type"),
]


def _starts(child: ScriptedChild) -> list[str]:
    return [run for kind, run in child.events() if kind == "start"]


# --- O1: atomic creation -------------------------------------------------------------------------


async def test_o1_a_completed_investigation_queues_one_auto_job_through_the_real_worker(world):
    """A run the worker ends `completed` has one queued attempt-1 auto job; slots=1 means no learning. (O1, O5)"""
    inv, stored = await _run_one(world, _child(world, files=_committed()), slots=1)

    assert stored["stage"] == "completed"
    jobs = jobs_of(world["dsn"], inv)
    assert [(j["trigger"], j["status"], j["attempt"]) for j in jobs] == [("auto", "queued", 1)]
    assert jobs[0]["request_key"] != stored["request_key"], "an auto job's key is a system key of its own"
    assert jobs[0]["publish_state"] == "none"


@pytest.mark.parametrize(("stage", "queued"), [("completed", 1), ("unparseable", 0), ("failed", 0), ("aborted", 0)])
async def test_o1_only_a_completed_ending_queues_a_job(world, stage, queued):
    """`completed` inserts one auto job; `unparseable`, `failed`, `aborted` insert none. (O1)"""
    async with job_store(world["dsn"]) as store:
        inv = await _queued(store)
        assert (await store.claim()).record.investigation_id == inv
        await store.finish(T1, inv, stage=stage, cost_usd=0.0, **({"disposition": "malicious"} if queued else {}))
    assert row(world["dsn"], inv)["stage"] == stage
    assert len(jobs_of(world["dsn"], inv)) == queued


@pytest.mark.parametrize("live", ["queued", "running"])
async def test_o1_a_cancelled_investigation_queues_no_job(world, live):
    """Cancel ends `aborted`; no learning job comes of it. (O1)"""
    async with job_store(world["dsn"]) as store:
        inv = await _queued(store)
        if live == "running":
            await store.claim()
        await store.cancel_investigation(T1, inv, actor="u-1")
    assert row(world["dsn"], inv)["stage"] == "aborted"
    assert jobs_of(world["dsn"], inv) == []


async def test_o1_a_finish_that_changed_nothing_queues_no_second_job(world):
    """A repeated finish on an ended row is a no-op, so the one job stays one. (O1)"""
    async with job_store(world["dsn"]) as store:
        inv = await completed_investigation(store, ticket="T-1")
        again = await store.finish(T1, inv, stage="completed", disposition="malicious", cost_usd=0.0)
    assert again is None
    assert len(jobs_of(world["dsn"], inv)) == 1


async def test_o1_a_job_insert_the_database_refuses_takes_the_completed_write_back_with_it(world):
    """Store level: a real failed insert rolls back; the row stays `running` and no job exists. (O1, D10)"""
    execute(world["dsn"], "ALTER TABLE jobs.learning_jobs ADD CONSTRAINT refuses_1344 CHECK (false) NOT VALID")
    async with job_store(world["dsn"]) as store:
        inv = await _queued(store)
        await store.claim()
        with pytest.raises(Exception) as caught:  # noqa: PT011 — the store drops the database's text; only the class is asked
            await store.finish(T1, inv, stage="completed", disposition="malicious", cost_usd=0.0)
    assert is_refusal(caught.value), "the store did not call a refused insert a refusal"
    assert row(world["dsn"], inv)["stage"] == "running"
    assert jobs_of(world["dsn"], inv) == []


async def test_d10_a_job_insert_the_database_refuses_ends_the_investigation_failed_as_a_worker_error(world):
    """Worker level: the refused insert ends the investigation `failed`/`worker_error` with a message; no job row. (D10, O1)"""
    execute(world["dsn"], "ALTER TABLE jobs.learning_jobs ADD CONSTRAINT refuses_1344 CHECK (false) NOT VALID")

    inv, stored = await _run_one(world, _child(world, files=_committed()), slots=1)

    assert (stored["stage"], stored["failure_reason"]) == ("failed", "worker_error"), stored
    assert stored["failure_message"]
    assert jobs_of(world["dsn"], inv) == []


@pytest.mark.parametrize("name", ["claim_learning_job", "create_learning_job", "take_over"])
def test_o5_the_learning_store_methods_are_coroutine_functions(name):
    """The learning surface of the store is awaited like the rest. (O5, O11)"""
    from defender.jobs import JobStore

    assert inspect.iscoroutinefunction(getattr(JobStore, name))


# --- the end record's outcomes, O12 ----------------------------------------------------------------


def _end_rows() -> list:
    """Every row of r5's outcome table the entry can write, one record each (cost 0.75 on every one)."""
    rows = [pytest.param(learning_end("completed", findings=3, cost=0.75), "completed", None, id="completed"),
            pytest.param(learning_end("completed", message="not comparable", cost=0.75), "completed", None,
                         id="completed-not-comparable")]
    rows += [pytest.param(learning_end("skipped", r, message=f"why {r}", cost=0.75, fork=None, stage="fork"
                                       if r == "no_fork_point" else "preflight"), "skipped", r, id=r)
             for r in SKIPPED_BY_THE_ENTRY]
    rows += [pytest.param(learning_end("failed", r, message=f"why {r}", cost=0.75), "failed", r, id=r)
             for r in FAILED_BY_THE_ENTRY]
    return rows


@pytest.mark.parametrize(("record", "status", "reason"), _end_rows())
async def test_the_end_record_alone_decides_the_row(world, record, status, reason):
    """Each status/reason row of the table becomes the row, carries the record's values, shows no run text, and is
    not retried; a post-step follows whatever the status. (O8, O12, O13)"""
    want = json.loads(record)
    job_proc = job_child(world, files={END: record}, exit=0, printed=RUN_TEXT)
    post = post_child(world)
    async with job_store(world["dsn"]) as store:
        job = await queued_job(world, store, ticket="T-1")
        inv = investigation_of(world["dsn"], job)
        await learning_worker(world, store, job=job_proc, post=post).drain()

    stored = job_row(world["dsn"], job)
    assert (stored["status"], stored["reason"]) == (status, reason), stored
    assert (stored["message"] or None) == want["message"]
    assert (stored["findings_count"], stored["sibling_cost_usd"]) == (want["findings_count"], 0.75)
    assert (stored["fork_message_id"], stored["stage"]) == (want["fork_message_id"], want["stage"])
    assert stored["publish_state"] == ("done" if status == "completed" else "none")
    assert RUN_TEXT not in json.dumps(stored, default=str), "run text reached the row"
    assert post.handed == [(job, [job] if status == "completed" else [], status)]
    assert len(jobs_of(world["dsn"], inv)) == 1, "an ending the child decided was retried"


@pytest.mark.parametrize(("record", "exit_code", "status"), [
    pytest.param(learning_end("completed", findings=2), 1, "completed", id="completed-though-a-sibling-failed"),
    pytest.param(learning_end("completed", findings=2), 0, "completed", id="completed-exit-0"),
    pytest.param(learning_end("failed", "judge_failed", message="the judge failed"), 0, "failed", id="judge-crash-exit-0"),
    pytest.param(learning_end("failed", "judge_failed", message="the judge failed"), 9, "failed", id="judge-crash-exit-9"),
])
async def test_the_exit_code_never_decides_the_row(world, record, exit_code, status):
    """The same record gives the same row whatever the child's exit code. (End record)"""
    job_proc = job_child(world, files={END: record}, exit=exit_code)
    async with job_store(world["dsn"]) as store:
        job = await queued_job(world, store, ticket="T-1")
        await learning_worker(world, store, job=job_proc, post=post_child(world)).drain()
    assert job_row(world["dsn"], job)["status"] == status


@pytest.mark.parametrize("exit_code", [0, 7])
async def test_no_record_from_a_child_nobody_signalled_is_exited_without_result(world, exit_code):
    """No end record and no signal: `failed`/`exited_without_result` with our own message, never run text. (End record, O12)"""
    job_proc = job_child(world, exit=exit_code, printed=RUN_TEXT)
    post = post_child(world)
    async with job_store(world["dsn"]) as store:
        job = await queued_job(world, store, ticket="T-1")
        await learning_worker(world, store, job=job_proc, post=post).drain()

    stored = job_row(world["dsn"], job)
    assert (stored["status"], stored["reason"], stored["publish_state"]) == ("failed", "exited_without_result", "none")
    assert stored["message"]
    assert RUN_TEXT not in json.dumps(stored, default=str)
    assert [h[0] for h in post.handed] == [job], "the job started a family step, so a post-step follows"
    assert [j["attempt"] for j in jobs_of(world["dsn"], investigation_of(world["dsn"], job))] == [1]


@pytest.mark.parametrize("text", UNREADABLE_END)
async def test_an_end_record_that_cannot_be_read_counts_as_none_from_a_child_nobody_signalled(world, text):
    """An unreadable record is no record: `failed`/`exited_without_result`, one attempt, a post-step follows. (End record, O12)"""
    job_proc = job_child(world, files={END: text})
    post = post_child(world)
    async with job_store(world["dsn"]) as store:
        job = await queued_job(world, store, ticket="T-1")
        await learning_worker(world, store, job=job_proc, post=post).drain()

    stored = job_row(world["dsn"], job)
    assert (stored["status"], stored["reason"]) == ("failed", "exited_without_result"), stored
    assert [h[0] for h in post.handed] == [job]
    assert len(jobs_of(world["dsn"], investigation_of(world["dsn"], job))) == 1


@pytest.mark.parametrize("text", UNREADABLE_END)
async def test_an_end_record_that_cannot_be_read_counts_as_none_from_a_signalled_child_and_is_a_hand_back(world, text):
    """Signalled and unreadable: the row is handed back (lapsed, retried as attempt 2), not ended on the text; no post-step. (End record, O6)"""
    dsn = world["dsn"]
    job_proc = job_child(world, files={END: text}, term="finish", term_mark=str(world["tmp"] / "termed"),
                         wait_for=world["tmp"] / "never")
    post = post_child(world)
    async with job_store(dsn) as store:
        inv = await completed_investigation(store, ticket="T-1")
        job = jobs_of(dsn, inv)[0]["id"]
        serving = asyncio.create_task(learning_worker(world, store, job=job_proc, post=post, **_FAST).serve())
        try:
            await _until(lambda: job_proc.seen(job), "the job's child")
        finally:
            _stop_serving(serving)
            await asyncio.wait_for(serving, timeout=60)
        assert [j["status"] for j in jobs_of(dsn, inv)] == ["running"], "an unreadable record decided the row"
        await store.take_over()

    old, new = jobs_of(dsn, inv)
    assert (old["status"], old["reason"], new["attempt"], new["status"]) == ("failed", "lease_lapsed", 2, "queued")
    assert post.handed == []


@pytest.mark.parametrize("state", ["creating", "offboarding", "offboarded"])
async def test_a_job_of_a_tenant_that_is_not_active_fails_as_a_worker_error_with_no_child(world, state):
    """Tenant not active: `failed`/`worker_error`, no child, and no post-step for a job that started nothing. (End record, O8)"""
    job_proc, post = job_child(world), post_child(world)
    async with job_store(world["dsn"]) as store:
        job = await queued_job(world, store, ticket="T-1")
        move_tenant(world["dsn"], T1, state=state)
        await learning_worker(world, store, job=job_proc, post=post).drain()

    stored = job_row(world["dsn"], job)
    assert (stored["status"], stored["reason"]) == ("failed", "worker_error")
    assert stored["message"]
    assert job_proc.seen_all() == {}
    assert post.handed == []


async def test_a_job_whose_child_cannot_be_spawned_is_a_worker_error_and_the_worker_carries_on(world):
    """An unexecutable learning command ends that row `worker_error` with no post-step; the next job runs. (End record, O8)"""
    good, post = job_child(world, files={END: learning_end("completed", findings=1)}), post_child(world)
    async with job_store(world["dsn"]) as store:
        bad = await queued_job(world, store, ticket="T-1")
        fine = await queued_job(world, store, ticket="T-2")
        set_created(world["dsn"], "learning_jobs", bad, NOW - dt.timedelta(hours=1))

        def argv(launch):
            return [str(world["tmp"] / "no-such-program")] if launch.job_id == bad else good(launch)

        await learning_worker(world, store, job=argv, post=post).drain()

    stored = job_row(world["dsn"], bad)
    assert (stored["status"], stored["reason"]) == ("failed", "worker_error")
    assert stored["message"]
    assert job_row(world["dsn"], fine)["status"] == "completed", "the worker did not carry on"
    assert [h[0] for h in post.handed] == [fine], "a post-step followed a job that started no family step"


# --- O2, O6, O7: a retry is a new row; a stop is a hand-back; a deploy leaves jobs runnable ---------------------


@pytest.mark.parametrize(("term", "files"), [
    pytest.param("finish", {END: learning_end("stopped", fork=None, stage=None)}, id="stopped-record"),
    pytest.param("mark", {}, id="no-record-after-a-signal"),
])
async def test_o2_o6_o7_a_stopped_family_is_handed_back_and_retried_on_the_new_worker(world, term, files):
    """A stopped record, or none from a signalled child, is a hand-back using an attempt: same key, new id, attempt 2,
    its original's age, run past the age limit by the new worker with the other queued job; no post-step. (O2, O6, O7, D4)"""
    dsn = world["dsn"]
    stopped = job_child(world, name="stopped", files=files, term=term,
                        term_mark=str(world["tmp"] / "termed"), wait_for=world["tmp"] / "never")
    post = post_child(world)
    async with job_store(dsn) as store:
        inv = await completed_investigation(store, ticket="T-1")
        other = await completed_investigation(store, ticket="T-2", key="k2")
        first, second = jobs_of(dsn, inv)[0], jobs_of(dsn, other)[0]
        set_created(dsn, "learning_jobs", first["id"], NOW - dt.timedelta(hours=1))
        serving = asyncio.create_task(learning_worker(world, store, job=stopped, post=post, **_FAST).serve())
        try:
            await _until(lambda: stopped.seen(first["id"]), "the job's child")
        finally:
            _stop_serving(serving)
            await asyncio.wait_for(serving, timeout=60)
        assert list(stopped.seen_all()) == [first["id"]], "the oldest job runs first, and one at a time"
        assert post.handed == [], "a handed-back row has not ended, so no post-step"
        assert job_row(dsn, first["id"])["status"] == "running", "a hand-back is not an ending of its own"

        set_created(dsn, "learning_jobs", first["id"], OVER_AGE)
        retried = job_child(world, name="retried", files={END: learning_end("completed")})
        serving = asyncio.create_task(learning_worker(world, store, job=retried, post=post, **_FAST).serve())
        try:
            await _until(lambda: len(jobs_of(dsn, inv)) == 2 and {j["status"] for j in jobs_of(dsn, inv)[1:]
                                                                    + jobs_of(dsn, other)} == {"completed"},
                         "the retry and the other job to run")
        finally:
            _stop_serving(serving)
            await asyncio.wait_for(serving, timeout=60)

    old, new = jobs_of(dsn, inv)
    assert (old["status"], old["reason"]) == ("failed", "lease_lapsed")
    assert old["message"]
    assert new["id"] != old["id"]
    assert (new["request_key"], new["attempt"], new["trigger"]) == (old["request_key"], 2, "auto")
    assert new["created_at"] == OVER_AGE, "a retry keeps its original's age"
    assert set(retried.seen_all()) == {new["id"], second["id"]}, "the new code did not run both, or the retry expired"
    assert list(stopped.seen_all()) == [first["id"]]


async def test_a_stopped_record_from_a_child_nobody_signalled_is_still_a_hand_back(world):
    """`stopped` always hands the row back, signal or not: it lapses at once, so the next take-over retries it. (End record, O6)"""
    dsn = world["dsn"]
    job_proc, post = job_child(world, files={END: learning_end("stopped", fork=None, stage=None)}), post_child(world)
    async with job_store(dsn) as store:
        inv = await completed_investigation(store, ticket="T-1")
        await learning_worker(world, store, job=job_proc, post=post).drain()
        assert [j["status"] for j in jobs_of(dsn, inv)] == ["running"]
        await store.take_over()

    old, new = jobs_of(dsn, inv)
    assert (old["status"], old["reason"], new["attempt"], new["status"]) == ("failed", "lease_lapsed", 2, "queued")
    assert post.handed == []


@pytest.mark.parametrize(("record", "status", "publish"), [
    pytest.param(learning_end("completed", findings=2), "completed", "pending", id="completed"),
    pytest.param(learning_end("failed", "judge_failed", message="m"), "failed", "none", id="failed"),
    pytest.param(learning_end("skipped", "no_fork_point", message="m", fork=None, stage="fork"), "skipped", "none",
                 id="skipped"),
])
async def test_a_stop_landing_after_a_record_does_not_override_it(world, record, status, publish):
    """The child records as the SIGTERM lands: the record stands, nothing is retried, and no post-step starts
    (publishing waits for a later one). (End record, O8, O14, D5)"""
    dsn = world["dsn"]
    job_proc = job_child(world, files={END: record}, term="finish", term_mark=str(world["tmp"] / "termed"),
                         wait_for=world["tmp"] / "never")
    post = post_child(world)
    async with job_store(dsn) as store:
        inv = await completed_investigation(store, ticket="T-1")
        job = jobs_of(dsn, inv)[0]["id"]
        serving = asyncio.create_task(learning_worker(world, store, job=job_proc, post=post, **_FAST).serve())
        try:
            await _until(lambda: job_proc.seen(job), "the job's child")
        finally:
            _stop_serving(serving)
            await asyncio.wait_for(serving, timeout=60)

    assert [(j["status"], j["publish_state"]) for j in jobs_of(dsn, inv)] == [(status, publish)]
    assert post.handed == [], "a stopping worker started a post-step"


@pytest.mark.parametrize("moved", [("failed", "worker_error"), ("skipped", "expired")], ids=["failed", "skipped"])
async def test_o2_a_job_row_moved_while_its_child_runs_is_not_written_and_nothing_is_published(world, moved):
    """A running job's row moved under it: its child is ended, the row keeps every column, no `pending` is made, the other job is untouched. (O2, P1)"""
    status, reason = moved
    dsn = world["dsn"]
    release, mark = world["tmp"] / "release", world["tmp"] / "term-{id}"
    jobs = job_child(world, files={END: learning_end("completed", findings=2, cost=1.5)}, wait_for=release, term="finish",
                     term_mark=str(mark))
    post = post_child(world)
    async with job_store(dsn) as store:
        fenced = await queued_job(world, store, ticket="T-1")
        other = await queued_job(world, store, ticket="T-2")
        draining = asyncio.create_task(learning_worker(
            world, store, job=jobs, post=post, slots=3, learning_slots=2, **_FAST).drain())
        try:
            await _until(lambda: len(jobs.seen_all()) == 2, "both families to start")
            execute(dsn, "UPDATE jobs.learning_jobs SET status = %s, reason = %s, message = 'moved by test', finished_at = %s, "
                         "lease_expires_at = NULL WHERE id = %s", (status, reason, NOW, fenced))
            snapshot = job_row(dsn, fenced)
            await _until(lambda: Path(str(mark).replace("{id}", fenced)).exists(), "the moved row's child to be ended", timeout=10)
        finally:
            release.touch()
            await asyncio.wait_for(draining, timeout=60)

    assert job_row(dsn, fenced) == snapshot, "the worker wrote on a row it no longer held"
    assert snapshot["publish_state"] == "none"
    assert not Path(str(mark).replace("{id}", other)).exists(), "an unmoved row's child was ended"
    assert job_row(dsn, other)["status"] == "completed"
    assert all(fenced not in pending for _, pending, _ in post.handed), "the moved row was handed to a post-step"


async def test_o6_a_running_job_keeps_its_lease_renewed(world):
    """A family longer than several leases is not taken over while its worker lives: one attempt, `completed`. (O6)"""
    dsn = world["dsn"]
    release = world["tmp"] / "release"
    job_proc = job_child(world, files={END: learning_end("completed")}, wait_for=release)
    async with job_store(dsn, lease=1.0) as store:
        inv = await completed_investigation(store, ticket="T-1")
        job = jobs_of(dsn, inv)[0]["id"]
        serving = asyncio.create_task(learning_worker(world, store, job=job_proc, post=post_child(world), **_FAST).serve())
        try:
            await _until(lambda: job_proc.seen(job), "the job's child")
            await asyncio.sleep(2.5)
            release.touch()
            await _until(lambda: job_row(dsn, job)["status"] == "completed", "the job to end")
        finally:
            release.touch()
            _stop_serving(serving)
            await asyncio.wait_for(serving, timeout=60)
    assert [(j["attempt"], j["status"]) for j in jobs_of(dsn, inv)] == [(1, "completed")]


async def test_o6_only_a_lapsed_lease_retries_and_the_third_lapse_ends_retry_cap(world):
    """Take-over: a live lease is left; each lapse is `failed`/`lease_lapsed` and a new queued attempt that keeps its
    original's age and is claimed past the age limit; at the cap the row is `retry_cap` and no fourth is made. (O6, D4)"""
    dsn = world["dsn"]
    async with job_store(dsn) as store:
        inv = await completed_investigation(store, ticket="T-1")
        claim = await store.claim_learning_job()
        await store.take_over()
        assert [(j["attempt"], j["status"]) for j in jobs_of(dsn, inv)] == [(1, "running")], "a live lease was taken over"

        set_created(dsn, "learning_jobs", claim.record.learning_job_id, OVER_AGE)
        for attempt in (1, 2, 3):
            execute(dsn, "UPDATE jobs.learning_jobs SET lease_expires_at = now() - interval '1 second' WHERE id = %s",
                    (claim.record.learning_job_id,))
            await store.take_over()
            if attempt < 3:
                claim = await store.claim_learning_job()
                assert claim is not None, f"attempt {attempt + 1} was expired instead of run"
                assert job_row(dsn, claim.record.learning_job_id)["attempt"] == attempt + 1

    rows = jobs_of(dsn, inv)
    assert [(j["attempt"], j["status"], j["reason"]) for j in rows] == [
        (1, "failed", "lease_lapsed"), (2, "failed", "lease_lapsed"), (3, "failed", "retry_cap")]
    assert {j["created_at"] for j in rows} == {OVER_AGE}
    assert all(j["message"] for j in rows)


# --- O5: the learning-slots rule ------------------------------------------------------------------


@pytest.mark.parametrize(("slots", "learning"), [(3, 1), (4, 2), (2, 1)])
async def test_o5_learning_runs_in_at_most_its_slots_and_investigations_keep_the_rest(world, slots, learning):
    """With more jobs and investigations queued than slots, `learning` jobs and `slots - learning` investigations
    run; a free learning slot goes to a job first; drain leaves nothing queued. (O5)"""
    release = world["tmp"] / "release"
    jobs = job_child(world, files={END: learning_end("failed", "judge_failed", message="m")}, wait_for=release)
    invs = _child(world, wait_for=release)
    async with job_store(world["dsn"]) as store:
        wanted_jobs = [await queued_job(world, store, ticket=f"J-{n}") for n in range(learning + 1)]
        queued = [await _queued(store, ticket=f"I-{n}", key=f"i{n}") for n in range(slots)]
        draining = asyncio.create_task(learning_worker(
            world, store, job=jobs, post=post_child(world), inv=invs, slots=slots, learning_slots=learning).drain())
        try:
            await _until(lambda: len(jobs.seen_all()) + len(invs.seen_all()) == slots, "the slots to fill")
            await asyncio.sleep(0.5)
            assert (len(jobs.seen_all()), len(invs.seen_all())) == (learning, slots - learning)
        finally:
            release.touch()
        await asyncio.wait_for(draining, timeout=60)

    assert jobs.max_alive() == learning, "learning went over its slots"
    assert set(jobs.seen_all()) == set(wanted_jobs), "drain() left a job queued"
    assert set(invs.seen_all()) == set(queued)


async def test_o5_idle_slots_stay_idle_while_jobs_wait(world):
    """Three queued jobs and no investigations on slots=3, L=1: one family at a time. (O5)"""
    release = world["tmp"] / "release"
    jobs = job_child(world, files={END: learning_end("failed", "judge_failed", message="m")}, wait_for=release)
    async with job_store(world["dsn"]) as store:
        wanted = [await queued_job(world, store, ticket=f"J-{n}") for n in range(3)]
        draining = asyncio.create_task(learning_worker(world, store, job=jobs, post=post_child(world)).drain())
        try:
            await _until(lambda: jobs.seen_all(), "the first family")
            await asyncio.sleep(0.5)
            assert len(jobs.seen_all()) == 1
        finally:
            release.touch()
        await asyncio.wait_for(draining, timeout=60)
    assert set(jobs.seen_all()) == set(wanted)
    assert jobs.max_alive() == 1


async def test_o5_a_freed_learning_slot_goes_to_the_next_job_before_an_older_investigation(world):
    """slots=2, L=1: when the job ends, the next job takes the learning slot although an investigation is older. (O5)"""
    dsn = world["dsn"]
    release_job, release_inv = world["tmp"] / "release-job", world["tmp"] / "release-inv"
    jobs = job_child(world, files={END: learning_end("completed")}, wait_for=release_job)
    invs = _child(world, wait_for=release_inv)
    async with job_store(dsn) as store:
        wanted = [await queued_job(world, store, ticket=f"J-{n}") for n in (1, 2)]
        queued = [await _queued(store, ticket=f"I-{n}", key=f"i{n}") for n in (1, 2)]
        for n, inv in enumerate(queued):
            set_created(dsn, "investigations", inv, NOW - dt.timedelta(hours=2, minutes=-n))
        draining = asyncio.create_task(learning_worker(
            world, store, job=jobs, post=post_child(world), inv=invs, slots=2).drain())
        try:
            await _until(lambda: jobs.seen_all() and invs.seen_all(), "one job and one investigation")
            release_job.touch()
            await _until(lambda: len(jobs.seen_all()) == 2, "the second job to take the freed learning slot")
            assert list(invs.seen_all()) == [queued[0]], "the freed slot went to the older investigation"
        finally:
            release_job.touch()
            release_inv.touch()
        await asyncio.wait_for(draining, timeout=60)
    assert set(jobs.seen_all()) == set(wanted)
    assert set(invs.seen_all()) == set(queued)


async def test_o5_investigations_take_every_slot_while_no_job_is_queued(world):
    """slots=3, L=1, no job queued: three investigations run at once; a reserved learning slot is not left idle. (O5)"""
    release = world["tmp"] / "release"
    invs = _child(world, wait_for=release)
    async with job_store(world["dsn"]) as store:
        queued = [await _queued(store, ticket=f"I-{n}", key=f"i{n}") for n in range(4)]
        draining = asyncio.create_task(learning_worker(
            world, store, job=job_child(world), post=post_child(world), inv=invs, slots=3, learning_slots=1).drain())
        try:
            await _until(lambda: len(invs.seen_all()) == 3, "three investigations at once")
            await asyncio.sleep(0.3)
            assert len(invs.seen_all()) == 3, "a fourth ran past the slots"
        finally:
            release.touch()
        await asyncio.wait_for(draining, timeout=60)
    assert set(invs.seen_all()) == set(queued)
    assert invs.max_alive() == 3


async def test_o5_a_job_queued_while_every_slot_is_busy_takes_the_first_freed_slot_before_an_older_investigation(world):
    """slots=2, L=1: both slots run investigations, then a job is queued; the first slot freed goes to the job, not to the older queued investigation. (O5)"""
    dsn = world["dsn"]
    releases = {name: world["tmp"] / f"release-{name}" for name in ("a", "b", "job")}
    async with job_store(dsn) as store:
        source = await _queued(store, ticket="X-1", key="kx")
        assert (await store.claim()).record.investigation_id == source, "premise: the test holds the source running"
        first, second, older = [await _queued(store, ticket=f"I-{n}", key=f"i{n}") for n in (1, 2, 3)]
        for inv, hours in ((first, 4), (second, 3), (older, 2)):
            set_created(dsn, "investigations", inv, NOW - dt.timedelta(hours=hours))
        runs = {first: ScriptedChild(world["tmp"] / "a", world["runs"], wait_for=releases["a"]),
                second: ScriptedChild(world["tmp"] / "b", world["runs"], wait_for=releases["b"]),
                older: ScriptedChild(world["tmp"] / "c", world["runs"])}
        jobs = job_child(world, files={END: learning_end("completed")}, wait_for=releases["job"])
        draining = asyncio.create_task(learning_worker(
            world, store, job=jobs, post=post_child(world), inv=lambda launch: runs[launch.investigation_id](launch),
            slots=2).drain())
        try:
            await _until(lambda: runs[first].seen_all() and runs[second].seen_all(), "both slots busy with investigations")
            await store.finish(T1, source, stage="completed", disposition="malicious", cost_usd=0.0)
            releases["a"].touch()
            await _until(lambda: jobs.seen_all(), "the job to take the freed slot")
            assert not runs[older].seen_all(), "the freed slot went to the older investigation"
        finally:
            for release in releases.values():
                release.touch()
        await asyncio.wait_for(draining, timeout=60)
    assert set(runs[older].seen_all()) == {older}


async def test_o5_jobs_investigations_and_post_steps_together_never_run_in_more_than_the_slots(world):
    """slots=2, L=1, two jobs and two investigations queued, post-steps held: the children alive at once, post-steps counted, never pass 2. (O5, O8)"""
    release = world["tmp"] / "release"
    jobs = JobChild(world["tmp"] / "jobs", world["runs"], files={END: learning_end("completed", findings=1)})
    post = PostStepChild(world["tmp"] / "post", world["runs"], dsn=world["dsn"], wait_for=release)
    invs = ScriptedChild(world["tmp"] / "invs", world["runs"], wait_for=release)
    peaks: list[int] = []

    async def sample() -> None:
        while True:
            peaks.append(sum(_alive(c) for c in (jobs, post, invs)))
            await asyncio.sleep(0.005)

    async with job_store(world["dsn"]) as store:
        wanted = [await queued_job(world, store, ticket=f"J-{n}") for n in (1, 2)]
        queued = [await _queued(store, ticket=f"I-{n}", key=f"i{n}") for n in (1, 2)]
        draining = asyncio.create_task(learning_worker(world, store, job=jobs, post=post, inv=invs, slots=2).drain())
        sampler = asyncio.create_task(sample())
        try:
            await _until(lambda: _alive(post) and _alive(invs), "a post-step and an investigation at once")
            await asyncio.sleep(0.5)
        finally:
            release.touch()
        await asyncio.wait_for(draining, timeout=90)
        sampler.cancel()
    assert max(peaks) == 2, f"control: both slots were used, peak {max(peaks)}"
    assert set(jobs.seen_all()) == set(wanted)
    assert set(invs.seen_all()) == set(queued)


async def test_o5_jobs_are_claimed_oldest_first(world):
    """Three queued jobs, aged against their creation order, are claimed in age order. (O5)"""
    dsn = world["dsn"]
    async with job_store(dsn) as store:
        made = [await queued_job(world, store, ticket=f"J-{n}") for n in range(3)]
        for job, hours in zip(made, (1, 3, 2), strict=True):
            set_created(dsn, "learning_jobs", job, NOW - dt.timedelta(hours=hours))
        claimed = [(await store.claim_learning_job()).record.learning_job_id for _ in made]
    assert claimed == [made[1], made[2], made[0]]


async def test_a_bare_worker_claims_no_job_and_learning_slots_need_both_commands(world):
    """A bare `Worker` leaves a queued job queued (control: with a learning slot and commands it runs it); a
    learning slot without both commands is refused at construction. (O5, D8)"""
    from defender.worker import Worker

    jobs, post = job_child(world), post_child(world)
    async with job_store(world["dsn"]) as store:
        job = await queued_job(world, store, ticket="T-1")
        await _worker(world, store, _child(world)).drain()
        assert job_row(world["dsn"], job)["status"] == "queued"
        assert jobs.seen_all() == {}

        await learning_worker(world, store, job=jobs, post=post).drain()
        assert job_row(world["dsn"], job)["status"] != "queued"
        assert set(jobs.seen_all()) == {job}

        for refused in ({"learning_argv": jobs}, {"post_step_argv": post}, {}):
            with pytest.raises(ValueError, match="learning"):
                Worker(store, data_root=world["root"], child_argv=_child(world), slots=3, learning_slots=1,
                       clock=lambda: NOW, containers=object(), **refused)
        Worker(store, data_root=world["root"], child_argv=_child(world), slots=1, clock=lambda: NOW,
               containers=object())  # a bare slots=1 is valid


@pytest.mark.parametrize(("slots", "learning"), [(3, 3), (1, 1), (3, -1)])
def test_o5_learning_slots_stay_within_zero_and_slots_minus_one(tmp_path, slots, learning):
    """Learning slots outside 0..slots-1 are refused. (O5)"""
    from defender.worker import Worker

    with pytest.raises(ValueError, match="learning"):
        Worker(SimpleNamespace(lease_seconds=30.0), data_root=tmp_path, child_argv=lambda launch: [], slots=slots,
               learning_slots=learning, clock=lambda: NOW, containers=object(), learning_argv=lambda launch: [],
               post_step_argv=lambda launch: [])


@pytest.mark.parametrize(("max_age", "hours", "runs"), [
    pytest.param(None, 23, True, id="inside-the-default-24h"),
    pytest.param(None, 25, False, id="past-the-default-24h"),
    pytest.param(3600, 0.5, True, id="inside-a-set-hour"),
    pytest.param(3600, 2, False, id="past-a-set-hour"),
])
async def test_d4_a_first_attempt_past_the_age_limit_is_skipped_when_claimed(world, max_age, hours, runs):
    """The limit is `learning_max_age` (default 24 h): over it the claim ends the job `skipped`/`expired` with a message. (D4, L3)"""
    knobs = {} if max_age is None else {"learning_max_age": max_age}
    async with job_store(world["dsn"], **knobs) as store:
        job = await queued_job(world, store, ticket="J-1")
        set_created(world["dsn"], "learning_jobs", job, NOW - dt.timedelta(hours=hours))
        claim = await store.claim_learning_job()

    stored = job_row(world["dsn"], job)
    if runs:
        assert claim.record.learning_job_id == job
        assert stored["status"] == "running"
    else:
        assert claim is None
        assert (stored["status"], stored["reason"]) == ("skipped", "expired")
        assert stored["message"]


async def test_d4_an_expired_job_starts_nothing_and_the_next_job_runs_in_its_slot(world):
    """Expired at claim: no child and no post-step; the fresh job runs. (D4, O8)"""
    jobs = job_child(world, files={END: learning_end("failed", "judge_failed", message="m")})
    post = post_child(world)
    async with job_store(world["dsn"]) as store:
        old = await queued_job(world, store, ticket="J-1")
        fresh = await queued_job(world, store, ticket="J-2")
        set_created(world["dsn"], "learning_jobs", old, OVER_AGE)
        await learning_worker(world, store, job=jobs, post=post).drain()

    assert job_row(world["dsn"], old)["reason"] == "expired"
    assert set(jobs.seen_all()) == {fresh}, "an expired job started"
    assert [h[0] for h in post.handed] == [fresh], "a post-step followed a job that started no family step"


async def test_d4_expiry_waits_for_a_pick_to_reach_the_queue(world):
    """With the learning slot busy an expired job stays `queued`, not skipped; it is skipped once a pick reaches it. (O5, D4)"""
    release = world["tmp"] / "release"
    jobs = job_child(world, files={END: learning_end("completed")}, wait_for=release)
    async with job_store(world["dsn"]) as store:
        running = await queued_job(world, store, ticket="J-1")
        old = await queued_job(world, store, ticket="J-2")
        set_created(world["dsn"], "learning_jobs", running, NOW - dt.timedelta(hours=1))
        draining = asyncio.create_task(learning_worker(world, store, job=jobs, post=post_child(world), **_FAST).drain())
        try:
            await _until(lambda: jobs.seen(running), "the first family")
            set_created(world["dsn"], "learning_jobs", old, OVER_AGE)
            await asyncio.sleep(1.0)
            assert job_row(world["dsn"], old)["status"] == "queued", "expired though no pick reached it"
        finally:
            release.touch()
        await asyncio.wait_for(draining, timeout=60)
    assert job_row(world["dsn"], old)["reason"] == "expired"


async def test_o5_with_no_learning_slot_jobs_stay_queued_however_old(world):
    """L=0 is the off switch: expiry happens only when a pick reaches the queue. (O5, D4)"""
    jobs = job_child(world)
    async with job_store(world["dsn"]) as store:
        job = await queued_job(world, store, ticket="J-1")
        set_created(world["dsn"], "learning_jobs", job, OVER_AGE)
        await learning_worker(world, store, job=jobs, post=post_child(world), slots=1, learning_slots=0).drain()
    assert job_row(world["dsn"], job)["status"] == "queued"
    assert jobs.seen_all() == {}


async def test_o5_drain_claims_a_job_queued_by_a_finish_that_happens_during_it(world):
    """One investigation queued, no job yet: drain runs it, then the job its finish queued, and a post-step. (O5, O1)"""
    jobs = job_child(world, files={END: learning_end("completed", findings=1)})
    post = post_child(world)
    async with job_store(world["dsn"]) as store:
        inv = await _queued(store)
        await learning_worker(world, store, job=jobs, post=post, inv=_child(world, files=_committed())).drain()

    (stored,) = jobs_of(world["dsn"], inv)
    assert (stored["status"], stored["publish_state"]) == ("completed", "done")
    assert set(jobs.seen_all()) == {stored["id"]}


# --- O13: progress is copied to the row ---------------------------------------------------------------


async def test_o13_the_progress_record_is_copied_to_the_running_row_and_the_end_record_has_the_final_values(world):
    """Pick, stage and sibling cost reach the `running` row on the loop as the entry replaces the record; the end
    record's values are the ones that stay. (O3, O13)"""
    dsn = world["dsn"]
    release = world["tmp"] / "release"
    final = learning_end("completed", findings=3, cost=2.0, fork="m-7", stage="judge")
    job_proc = job_child(world, files={END: final}, wait_for=release)
    async with job_store(dsn) as store:
        job = await queued_job(world, store, ticket="T-1")
        path = world["runs"] / PROGRESS.format(id=job)
        write_whole(path, json.dumps({"fork_message_id": "m-7", "stage": "questioner", "sibling_cost_usd": 0.5}))
        draining = asyncio.create_task(learning_worker(world, store, job=job_proc, post=post_child(world), **_FAST).drain())
        try:
            await _until(lambda: (r := job_row(dsn, job))["status"] == "running" and r["fork_message_id"] == "m-7",
                         "the pick to reach the row")
            await _until(lambda: (job_row(dsn, job)["stage"], job_row(dsn, job)["sibling_cost_usd"]) == ("questioner", 0.5),
                         "the stage and cost to reach the row")
            write_whole(path, json.dumps({"fork_message_id": "m-7", "stage": "siblings", "sibling_cost_usd": 1.25}))
            await _until(lambda: (job_row(dsn, job)["stage"], job_row(dsn, job)["sibling_cost_usd"]) == ("siblings", 1.25),
                         "the later record to reach the row")
            assert job_row(dsn, job)["status"] == "running"
        finally:
            release.touch()
        await asyncio.wait_for(draining, timeout=60)

    stored = job_row(dsn, job)
    assert (stored["status"], stored["stage"], stored["sibling_cost_usd"], stored["findings_count"]) == (
        "completed", "judge", 2.0, 3)
    assert stored["fork_message_id"] == "m-7"


async def test_o13_the_spend_already_copied_stays_visible_when_the_child_leaves_no_end_record(world):
    """A family that spent and then died without an end record is `exited_without_result` and keeps its copied cost. (O13)"""
    dsn = world["dsn"]
    release = world["tmp"] / "release"
    job_proc = job_child(world, wait_for=release)
    async with job_store(dsn) as store:
        job = await queued_job(world, store, ticket="T-1")
        write_whole(world["runs"] / PROGRESS.format(id=job),
                    json.dumps({"fork_message_id": "m-3", "stage": "siblings", "sibling_cost_usd": 0.75}))
        draining = asyncio.create_task(learning_worker(world, store, job=job_proc, post=post_child(world), **_FAST).drain())
        try:
            await _until(lambda: job_row(dsn, job)["sibling_cost_usd"] == 0.75, "the cost to reach the row")
        finally:
            release.touch()
        await asyncio.wait_for(draining, timeout=60)

    stored = job_row(dsn, job)
    assert (stored["reason"], stored["sibling_cost_usd"], stored["fork_message_id"]) == ("exited_without_result", 0.75, "m-3")


# --- O8, O14: publishing pending jobs and the author gate --------------------------------------------


async def test_o5_a_post_step_holds_the_learning_slot(world):
    """A post-step is learning-class: the next job waits for it with slots free. (O5, O8)"""
    release = world["tmp"] / "release"
    jobs = job_child(world, files={END: learning_end("completed")})
    post = post_child(world, wait_for=release)
    async with job_store(world["dsn"]) as store:
        a, b = [await queued_job(world, store, ticket=f"J-{n}") for n in (1, 2)]
        draining = asyncio.create_task(learning_worker(world, store, job=jobs, post=post).drain())
        try:
            await _until(lambda: post.seen_all(), "the post-step")
            ran, waiting = (a, b) if a in post.seen_all() else (b, a)
            await asyncio.sleep(0.5)
            assert job_row(world["dsn"], waiting)["status"] == "queued"
            assert job_row(world["dsn"], ran)["status"] == "completed", "a post-step holds no running row"
        finally:
            release.touch()
        await asyncio.wait_for(draining, timeout=60)
    assert set(jobs.seen_all()) == {a, b}


async def test_o8_renewals_never_end_a_running_post_step(world):
    """A post-step lives through many renewal ticks, though its row has ended: one registry, no fence. (O8, O9)"""
    release, mark = world["tmp"] / "release", world["tmp"] / "post-termed"
    jobs = job_child(world, files={END: learning_end("completed", findings=1)})
    post = post_child(world, wait_for=release, term="mark", term_mark=str(mark))
    async with job_store(world["dsn"]) as store:
        job = await queued_job(world, store, ticket="J-1")
        draining = asyncio.create_task(learning_worker(world, store, job=jobs, post=post, **_FAST).drain())
        try:
            await _until(lambda: post.seen(job), "the post-step")
            await asyncio.sleep(1.5)
            assert not mark.exists(), "a renewal tick told the post-step to stop"
            assert post.events() == [("start", job)]
        finally:
            release.touch()
        await asyncio.wait_for(draining, timeout=60)
    assert job_row(world["dsn"], job)["publish_state"] == "done"


async def test_o14_a_stranded_completed_job_is_published_by_the_next_post_step_of_any_status(world):
    """A's post-step dies: A stays `completed`/`pending`. B then fails, and B's post-step is handed A, and the worker
    writes `done` from its record. Findings are never published before the row ended. (O8, O14, D5)"""
    dsn = world["dsn"]
    ended = job_child(world, name="a", files={END: learning_end("completed", findings=1)})
    lost = post_child(world, name="lost", recording=False, exit=3)
    async with job_store(dsn) as store:
        a = await queued_job(world, store, ticket="J-1")
        await learning_worker(world, store, job=ended, post=lost).drain()
        stored = job_row(dsn, a)
        assert (stored["status"], stored["reason"], stored["publish_state"]) == ("completed", None, "pending")
        assert lost.handed == [(a, [a], "completed")], "its own pending job, after the row ended"

        failing = job_child(world, name="b", files={END: learning_end("failed", "control_failed", message="m")})
        post = post_child(world, name="post")
        b = await queued_job(world, store, ticket="J-2")
        await learning_worker(world, store, job=failing, post=post).drain()

    assert post.handed == [(b, [a], "failed")]
    assert job_row(dsn, a)["publish_state"] == "done"
    assert job_row(dsn, b)["publish_state"] == "none", "a failed job has nothing to publish"


async def test_o14_findings_failing_validation_end_refused_and_are_not_handed_over_again(world):
    """`refused` is visible on the row, and one bad job never retries. (O14)"""
    dsn = world["dsn"]
    ended = job_child(world, files={END: learning_end("completed", findings=1)})
    async with job_store(dsn) as store:
        a = await queued_job(world, store, ticket="J-1")
        await learning_worker(world, store, job=ended, post=post_child(world, name="p1", recording=False)).drain()
        assert job_row(dsn, a)["publish_state"] == "pending", "premise"

        b = await queued_job(world, store, ticket="J-2")
        await learning_worker(world, store, job=ended, post=post_child(world, name="p2", refuse=(a,))).drain()
        assert job_row(dsn, a)["publish_state"] == "refused"
        assert job_row(dsn, b)["publish_state"] == "done"

        c = await queued_job(world, store, ticket="J-3")
        later = post_child(world, name="p3")
        await learning_worker(world, store, job=ended, post=later).drain()
    assert later.handed == [(c, [c], "completed")], "a refused or done job was handed over again"


async def test_o14_a_queue_level_failure_leaves_the_job_pending_to_be_handed_again(world):
    """A job the record names neither published nor refused stays `pending` (not `refused`) and is handed over next time. (O14)"""
    dsn = world["dsn"]
    ended = job_child(world, files={END: learning_end("completed", findings=1)})
    async with job_store(dsn) as store:
        a = await queued_job(world, store, ticket="J-1")
        await learning_worker(world, store, job=ended, post=post_child(world, name="p1", omit=(a,))).drain()
        assert job_row(dsn, a)["publish_state"] == "pending"

        b = await queued_job(world, store, ticket="J-2")
        later = post_child(world, name="p2")
        await learning_worker(world, store, job=ended, post=later).drain()
    assert later.handed == [(b, sorted([a, b]), "completed")]
    assert [job_row(dsn, j)["publish_state"] for j in (a, b)] == ["done", "done"]


@pytest.mark.parametrize("text", UNREADABLE_POST)
async def test_o14_a_post_step_record_that_cannot_be_read_counts_as_none_and_the_job_stays_pending(world, text):
    """An unreadable post-step record leaves the job `pending` (not `done`, not `refused`) to be handed over again. (O14, O8)"""
    dsn = world["dsn"]
    ended = job_child(world, files={END: learning_end("completed", findings=1)})
    async with job_store(dsn) as store:
        a = await queued_job(world, store, ticket="J-1")
        await learning_worker(world, store, job=ended, post=post_child(world, name="p1", record_text=text)).drain()
        assert job_row(dsn, a)["publish_state"] == "pending"

        b = await queued_job(world, store, ticket="J-2")
        later = post_child(world, name="p2")
        await learning_worker(world, store, job=ended, post=later).drain()
    assert later.handed == [(b, sorted([a, b]), "completed")]
    assert [job_row(dsn, j)["publish_state"] for j in (a, b)] == ["done", "done"]


@pytest.mark.parametrize("text", UNREADABLE_POST)
async def test_o14_a_post_step_record_left_as_the_worker_stops_it_counts_as_none_when_unreadable(world, text):
    """A signalled post-step whose record is unreadable: the job stays `completed`/`pending`. (O14, O9)"""
    jobs = job_child(world, files={END: learning_end("completed", findings=1)})
    post = post_child(world, record_text=text, term="finish", term_mark=str(world["tmp"] / "post-termed"),
                      wait_for=world["tmp"] / "never")
    async with job_store(world["dsn"]) as store:
        job = await queued_job(world, store, ticket="J-1")
        serving = asyncio.create_task(learning_worker(world, store, job=jobs, post=post, stop_grace=30, **_FAST).serve())
        try:
            await _until(lambda: post.seen(job), "the post-step")
        finally:
            _stop_serving(serving)
            await asyncio.wait_for(serving, timeout=15)
    stored = job_row(world["dsn"], job)
    assert (stored["status"], stored["publish_state"]) == ("completed", "pending")


async def test_o8_a_post_step_that_cannot_be_spawned_leaves_its_row_alone_and_the_next_one_publishes_it(world):
    """An unexecutable post-step command: the job keeps its ending and `pending`, the worker carries on, and the next post-step is handed it. (O8, O14)"""
    dsn = world["dsn"]
    ended = job_child(world, files={END: learning_end("completed", findings=1)})
    good = post_child(world)
    async with job_store(dsn) as store:
        a = await queued_job(world, store, ticket="J-1")
        b = await queued_job(world, store, ticket="J-2")
        set_created(dsn, "learning_jobs", a, NOW - dt.timedelta(hours=1))

        def post(launch):
            return [str(world["tmp"] / "no-such-program")] if launch.job_id == a else good(launch)

        await learning_worker(world, store, job=ended, post=post).drain()

    stored = job_row(dsn, a)
    assert (stored["status"], stored["reason"]) == ("completed", None), "a lost post-step changed the job's ending"
    assert good.handed == [(b, sorted([a, b]), "completed")]
    assert [job_row(dsn, j)["publish_state"] for j in (a, b)] == ["done", "done"]


async def test_o14_a_post_step_is_handed_only_its_own_tenants_pending_jobs(world):
    """Another tenant's `pending` job is not handed to this tenant's post-step, and stays pending. (O14, O8)"""
    dsn = world["dsn"]
    register_tenant(dsn, T2)
    ended = job_child(world, files={END: learning_end("completed", findings=1)})
    post = post_child(world)
    async with job_store(dsn) as store:
        theirs = await queued_job(world, store, ticket="J-0", tenant=T2)
        execute(dsn, "UPDATE jobs.learning_jobs SET status = 'completed', publish_state = 'pending', findings_count = 1, "
                     "finished_at = %s, lease_expires_at = NULL WHERE id = %s", (NOW, theirs))
        ours = await queued_job(world, store, ticket="J-1")
        await learning_worker(world, store, job=ended, post=post).drain()

    assert post.handed == [(ours, [ours], "completed")]
    assert job_row(dsn, theirs)["publish_state"] == "pending"
    assert job_row(dsn, ours)["publish_state"] == "done"


def _count_of(word: str, text: str) -> int:
    found = re.search(rf"{word}\D{{0,4}}(\d+)|(\d+)\D{{0,4}}{word}", text)
    assert found, f"no {word} count in {text!r}"
    return int(found.group(1) or found.group(2))


async def test_o8_each_post_step_announces_one_audit_event_with_its_published_and_refused_counts(world, caplog):
    """After a post-step that published two jobs and refused one: one `learning_post_step` event by the system for the
    tenant, carrying 2 and 1. (O8)"""
    audit = JobsAudit(caplog)
    dsn = world["dsn"]
    ended = job_child(world, files={END: learning_end("completed", findings=1)})
    async with job_store(dsn) as store:
        a, b = [await queued_job(world, store, ticket=f"J-{n}") for n in (1, 2)]
        await learning_worker(world, store, job=ended, post=post_child(world, name="lost", recording=False)).drain()
        seen = len([e for e in audit.events() if e.action == "learning_post_step"])
        await queued_job(world, store, ticket="J-3")
        await learning_worker(world, store, job=ended, post=post_child(world, name="p", refuse=(a,))).drain()

    new = [e for e in audit.events() if e.action == "learning_post_step"][seen:]
    assert len(new) == 1, f"events of `defender.jobs.audit` after the second drain: {[e.action for e in audit.events()]}"
    assert (new[0].actor, new[0].tenant_id) == ("system", T1)
    assert (_count_of("published", new[0].detail or ""), _count_of("refused", new[0].detail or "")) == (2, 1)
    assert job_row(dsn, b)["publish_state"] == "done"


# --- O9: a stopping worker's post-step stops --------------------------------------------------------


async def test_o9_a_stopping_worker_signals_its_post_step(world):
    """A deploy does not wait out an author tick; the job's row keeps its ending. (O9, O8)"""
    mark = world["tmp"] / "post-termed"
    jobs = job_child(world, files={END: learning_end("completed")})
    post = post_child(world, term="mark", term_mark=str(mark), wait_for=world["tmp"] / "never")
    async with job_store(world["dsn"]) as store:
        job = await queued_job(world, store, ticket="J-1")
        serving = asyncio.create_task(learning_worker(world, store, job=jobs, post=post, stop_grace=30, **_FAST).serve())
        try:
            await _until(lambda: post.seen(job), "the post-step")
        finally:
            _stop_serving(serving)
            await asyncio.wait_for(serving, timeout=15)
    assert mark.exists(), "the post-step was not told to stop"
    stored = job_row(world["dsn"], job)
    assert (stored["status"], stored["publish_state"]) == ("completed", "pending")


# --- O10: delete -----------------------------------------------------------------------------------


async def test_o10_delete_removes_the_investigations_queued_attempts_and_leaves_other_investigations_jobs(world):
    """Deleting a `completed` investigation removes every job row it has, queued ones included; another's stay. (O10, D6)"""
    dsn = world["dsn"]
    async with job_store(dsn) as store:
        inv = await completed_investigation(store, ticket="T-1")
        other = await completed_investigation(store, ticket="T-2", key="k2")
        explicit, _ = await store.create_learning_job(T1, inv, "client-1", actor="u-1")
        set_created(dsn, "learning_jobs", jobs_of(dsn, inv)[0]["id"], NOW - dt.timedelta(hours=2))
        set_created(dsn, "learning_jobs", explicit.learning_job_id, NOW - dt.timedelta(hours=1))
        claim = await store.claim_learning_job()
        execute(dsn, "UPDATE jobs.learning_jobs SET lease_expires_at = now() - interval '1 second' WHERE id = %s",
                (claim.record.learning_job_id,))
        await store.take_over()
        assert len(jobs_of(dsn, inv)) == 3, "premise: a lapsed attempt, its queued retry and the explicit job"

        await store.delete_investigation(T1, inv, actor="u-1")

        assert jobs_of(dsn, inv) == []
        assert job_row(dsn, explicit.learning_job_id) is None
        assert row(dsn, inv) is None
        assert [j["status"] for j in jobs_of(dsn, other)] == ["queued"]


@pytest.mark.parametrize("record", [
    learning_end("completed", findings=1), learning_end("failed", "judge_failed", message="m"),
    learning_end("skipped", "no_fork_point", message="m", fork=None, stage="fork")], ids=["completed", "failed", "skipped"])
async def test_o10_delete_removes_finished_jobs_and_a_deleted_pending_jobs_findings_are_never_published(world, record):
    """Finished jobs go with the investigation; a deleted `pending` job is not handed to a later post-step. (O10, O14)"""
    dsn = world["dsn"]
    ended = job_child(world, files={END: record})
    async with job_store(dsn) as store:
        inv = await completed_investigation(store, ticket="T-1")
        await learning_worker(world, store, job=ended, post=post_child(world, name="p1", recording=False)).drain()
        assert jobs_of(dsn, inv)[0]["status"] != "queued", "premise: the job ended"
        await store.delete_investigation(T1, inv, actor="u-1")
        assert jobs_of(dsn, inv) == []

        later = await queued_job(world, store, ticket="T-2")
        post = post_child(world, name="p2")
        await learning_worker(world, store, job=job_child(world, name="b", files={END: learning_end(
            "failed", "judge_failed", message="m")}), post=post).drain()
    assert post.handed == [(later, [], "failed")], "a deleted job's findings were handed over"


async def test_o10_delete_is_a_conflict_while_any_of_its_jobs_runs_and_removes_nothing(world):
    """A running job refuses the delete, whichever attempt is running; once it ends the delete goes through. (O10, D6)"""
    dsn = world["dsn"]
    async with job_store(dsn) as store:
        inv = await completed_investigation(store, ticket="T-1")
        claim = await store.claim_learning_job()
        execute(dsn, "UPDATE jobs.learning_jobs SET lease_expires_at = now() - interval '1 second' WHERE id = %s",
                (claim.record.learning_job_id,))
        await store.take_over()
        retry = await store.claim_learning_job()
        assert job_row(dsn, retry.record.learning_job_id)["attempt"] == 2, "premise: attempt 2 runs"

        with pytest.raises(Conflict):
            await store.delete_investigation(T1, inv, actor="u-1")
        assert [(j["attempt"], j["status"]) for j in jobs_of(dsn, inv)] == [(1, "failed"), (2, "running")]
        assert row(dsn, inv)["stage"] == "completed"

        execute(dsn, "UPDATE jobs.learning_jobs SET lease_expires_at = now() - interval '1 second' WHERE id = %s",
                (retry.record.learning_job_id,))
        await store.take_over()
        await store.delete_investigation(T1, inv, actor="u-1")
    assert jobs_of(dsn, inv) == []
    assert row(dsn, inv) is None


async def test_o10_delete_is_a_conflict_while_a_job_of_another_request_key_runs_after_the_auto_chain_ended(world):
    """Auto attempt 1 lapsed and attempt 2 completed, an explicit job running: the delete is a Conflict that removes nothing; once that attempt ends it removes every row. (O10, D6)"""
    dsn = world["dsn"]
    async with job_store(dsn) as store:
        inv = await completed_investigation(store, ticket="T-1")
        first = await store.claim_learning_job()
        _lapse(dsn, first.record.learning_job_id)
        await store.take_over()
        second = await store.claim_learning_job()
        execute(dsn, "UPDATE jobs.learning_jobs SET status = 'completed', finished_at = %s, lease_expires_at = NULL, "
                     "publish_state = 'done' WHERE id = %s", (NOW, second.record.learning_job_id))
        explicit, _ = await store.create_learning_job(T1, inv, "client-1", actor="u-1")
        running = await store.claim_learning_job()
        assert running.record.learning_job_id == explicit.learning_job_id, "premise: the explicit job runs"
        assert sorted((j["trigger"], j["attempt"], j["status"]) for j in jobs_of(dsn, inv)) == [
            ("auto", 1, "failed"), ("auto", 2, "completed"), ("explicit", 1, "running")]

        with pytest.raises(Conflict):
            await store.delete_investigation(T1, inv, actor="u-1")
        assert len(jobs_of(dsn, inv)) == 3
        assert row(dsn, inv) is not None

        _lapse(dsn, explicit.learning_job_id)
        await store.take_over()
        await store.delete_investigation(T1, inv, actor="u-1")
    assert jobs_of(dsn, inv) == []
    assert row(dsn, inv) is None


async def test_o10_a_claim_that_commits_while_the_delete_waits_makes_the_delete_a_conflict(world):
    """The delete locks the job rows before it checks: a claim that lands first wins and the delete sees `running`. (O10, D6)"""
    import psycopg

    dsn = world["dsn"]
    async with job_store(dsn) as store:
        inv = await completed_investigation(store, ticket="T-1")
        job = jobs_of(dsn, inv)[0]["id"]
        async with await psycopg.AsyncConnection.connect(dsn) as holder:
            await holder.execute("SELECT id FROM jobs.learning_jobs WHERE id = %s FOR UPDATE", (job,))
            deleting = asyncio.ensure_future(store.delete_investigation(T1, inv, actor="u-1"))
            await _until(lambda: deleting.done() or execute(dsn, "SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' "
                                                                 "AND datname = current_database()")[0][0] >= 1,
                         "the delete to wait on the locked job row")
            assert not deleting.done(), "the delete did not wait for the job row's lock"
            await holder.execute("UPDATE jobs.learning_jobs SET status = 'running', started_at = now(), "
                                 "lease_expires_at = now() + interval '30 seconds' WHERE id = %s", (job,))
            await holder.commit()
        with pytest.raises(Conflict):
            await asyncio.wait_for(deleting, timeout=30)
    assert job_row(dsn, job)["status"] == "running"
    assert row(dsn, inv) is not None


async def test_o10_a_delete_that_lands_first_leaves_the_claim_nothing(world):
    """Delete first: the job is gone with its investigation and a claim finds nothing. (O10)"""
    async with job_store(world["dsn"]) as store:
        inv = await completed_investigation(store, ticket="T-1")
        await store.delete_investigation(T1, inv, actor="u-1")
        assert await store.claim_learning_job() is None


# --- O11: explicit re-learn --------------------------------------------------------------------------


async def test_o11_a_relearn_is_created_once_per_request_and_replays_to_the_latest_attempt(world):
    """Created, replayed, a second request makes a second job, and after a retry the replay answers attempt 2. (O11)"""
    dsn = world["dsn"]
    async with job_store(dsn) as store:
        inv = await completed_investigation(store, ticket="T-1")
        made, created = await store.create_learning_job(T1, inv, "client-1", actor="u-1")
        assert created is True
        again, created_again = await store.create_learning_job(T1, inv, "client-1", actor="u-1")
        assert (again.learning_job_id, created_again) == (made.learning_job_id, False)
        stored = job_row(dsn, made.learning_job_id)
        assert (stored["trigger"], stored["request_key"], stored["attempt"]) == ("explicit", "client-1", 1)
        distinct, created_distinct = await store.create_learning_job(T1, inv, "client-2", actor="u-1")
        assert created_distinct is True
        assert distinct.learning_job_id not in {made.learning_job_id, again.learning_job_id}

        execute(dsn, "UPDATE jobs.learning_jobs SET status = 'running', lease_expires_at = now() - interval '1 second', "
                     "started_at = %s WHERE id = %s", (NOW, made.learning_job_id))
        await store.take_over()
        latest, created_later = await store.create_learning_job(T1, inv, "client-1", actor="u-1")
        assert created_later is False
        assert latest.learning_job_id != made.learning_job_id
        assert (job_row(dsn, latest.learning_job_id)["attempt"], job_row(dsn, latest.learning_job_id)["trigger"]) == (
            2, "explicit")


@pytest.mark.parametrize("stage", ["queued", "running", "failed", "unparseable", "aborted"])
async def test_o11_a_relearn_of_an_investigation_that_is_not_completed_is_a_conflict(world, stage):
    """Only `completed` can be learned from; every other stage is `Conflict` and leaves no job. (O11)"""
    async with job_store(world["dsn"]) as store:
        inv = await _queued(store, ticket="T-2", key="k2")
        if stage != "queued":
            await store.claim()
        if stage not in {"queued", "running"}:
            await store.finish(T1, inv, stage=stage, cost_usd=0.0)
        with pytest.raises(Conflict):
            await store.create_learning_job(T1, inv, "client-3", actor="u-1")
    assert jobs_of(world["dsn"], inv) == []


async def test_o11_an_investigation_this_tenant_does_not_have_is_an_unknown_reference(world):
    """No such id, and another tenant's completed investigation, are `UnknownReference`. (O11)"""
    register_tenant(world["dsn"], T2)
    async with job_store(world["dsn"]) as store:
        theirs = await completed_investigation(store, ticket="T-9", tenant=T2)
        for named in ("00000000-0000-4000-8000-000000000000", theirs):
            with pytest.raises(UnknownReference):
                await store.create_learning_job(T1, named, "client-2", actor="u-1")
    assert len(jobs_of(world["dsn"], theirs)) == 1, "the other tenant's own job is untouched"


async def test_o11_a_client_request_id_equal_to_the_auto_key_neither_replays_nor_replaces_the_auto_job(world):
    """The auto job's own key, sent as a client's request id, is refused or made a separate explicit job; it never answers with the auto job nor makes a second auto one. (O11, Request key; design gap: the reserved prefix's treatment is unstated)"""
    dsn = world["dsn"]
    async with job_store(dsn) as store:
        inv = await completed_investigation(store, ticket="T-1")
        (auto,) = jobs_of(dsn, inv)
        try:
            made, created = await store.create_learning_job(T1, inv, auto["request_key"], actor="u-1")
        except (Conflict, ValueError):
            made = None
        else:
            assert created is True
            assert made.learning_job_id != auto["id"], "the auto job was replayed as the client's"

    rows = jobs_of(dsn, inv)
    assert [(j["trigger"], j["attempt"]) for j in rows if j["trigger"] == "auto"] == [("auto", 1)]
    assert {j["id"] for j in rows} == {auto["id"], *([made.learning_job_id] if made is not None else [])}


@pytest.mark.postgres
def test_o1_the_migration_queues_no_job_for_investigations_completed_before_it(empty_database):
    """A database holding a completed investigation, taken to head: no learning job row appears, the investigation stays. (O1, no backfill)"""
    from alembic import command

    from defender.migrations import _config, _scripts, head, upgrade
    from defender.tests.migrations.test_1343_migrations import TENANT, _inv, _plant

    config = _config()
    config.attributes["dsn"] = empty_database
    command.upgrade(config, _scripts().get_revision(head()).down_revision)
    execute(empty_database, "INSERT INTO tenancy.tenants (id, created_at, state) VALUES (%s, now(), 'active')", (TENANT,))
    _plant(empty_database, _inv("done"), "completed", "t0", cost=2.5)
    _plant(empty_database, _inv("still-queued"), "queued", "t1")

    upgrade(empty_database)

    assert execute(empty_database, "SELECT count(*) FROM jobs.learning_jobs") == [(0,)]
    assert execute(empty_database, "SELECT count(*) FROM jobs.investigations WHERE stage = 'completed'") == [(1,)]


async def test_o1_the_database_refuses_a_second_job_with_the_same_tenant_investigation_key_and_attempt(world):
    """A real second insert of the auto job's `(tenant, investigation, request key, attempt)` is a unique violation; the next attempt and another key insert. (O1, O2, Request key)"""
    import psycopg

    dsn = world["dsn"]
    async with job_store(dsn) as store:
        inv = await completed_investigation(store, ticket="T-1")
    (auto,) = jobs_of(dsn, inv)

    # Every column, whatever the table adds beyond the named ones: the store sets values in Python, with no server defaults.
    others = [c for (c,) in execute(dsn, "SELECT column_name FROM information_schema.columns WHERE table_schema = 'jobs' "
                                         "AND table_name = 'learning_jobs' AND column_name NOT IN ('id', 'request_key', 'attempt')")]

    def copy_of(*, key: str | None = None, attempt: int | None = None) -> None:
        kept = ", ".join(others)
        execute(dsn, f"INSERT INTO jobs.learning_jobs (id, request_key, attempt, {kept}) "  # noqa: S608
                     f"SELECT gen_random_uuid(), coalesce(%s, request_key), coalesce(%s, attempt), {kept} "
                     "FROM jobs.learning_jobs WHERE id = %s", (key, attempt, auto["id"]))

    with pytest.raises(psycopg.errors.UniqueViolation):
        copy_of()
    assert len(jobs_of(dsn, inv)) == 1
    copy_of(attempt=2)
    copy_of(key="another-key")
    assert len(jobs_of(dsn, inv)) == 3


async def test_o11_an_explicit_job_runs_on_the_same_slots_as_an_auto_one(world):
    """The worker runs an explicit job like an auto one. (O11, O5)"""
    jobs = job_child(world, files={END: learning_end("completed", findings=1)})
    async with job_store(world["dsn"]) as store:
        inv = await completed_investigation(store, ticket="T-1")
        await store.create_learning_job(T1, inv, "client-1", actor="u-1")
        await learning_worker(world, store, job=jobs, post=post_child(world)).drain()
    assert sorted((j["trigger"], j["status"]) for j in jobs_of(world["dsn"], inv)) == [
        ("auto", "completed"), ("explicit", "completed")]
