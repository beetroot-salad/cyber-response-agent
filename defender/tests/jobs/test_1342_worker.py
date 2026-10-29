"""#1342 the worker in-process over a real database and real child processes: slots (O4), the fence
(O5), the job lane files (O6), the container backstop (O7), the ending rules 1-5 read from the
job-end record (O8), cost and knowledge at finish, and system-actor audit (O13).

Entry: `defender.worker.Worker(store, data_root=, child_argv=, containers=, slots=, clock=)` and
`await worker.drain()` (claim until nothing is queued, then wait for every slot's task). The child is
`ScriptedChild`: it writes the host records a case names and exits; the worker decides the stage."""
from __future__ import annotations

import asyncio
import inspect
import json
import logging
import os
import re
from pathlib import Path

import pytest

from defender.tests.support.jobs._jobs1342 import (
    ALERT_BYTES,
    ALERT_DIGEST,
    GOLDEN_REPORT,
    JOBS_AUDIT_LOGGER,
    MALICIOUS_REPORT,
    NOW,
    T1,
    T2,
    TITLE,
    WORKER_LOGGER,
    JobsAudit,
    ScriptedChild,
    StandInContainers,
    VisibleAtEmit,
    an_alert,
    job_end,
    job_store,
    knowledge_record,
    knowledge_record_of,
    make_worker,
    plant_fork,
    plant_queued_investigation,
    plant_sessions,
    register_tenant,
    row,
    session_db,
    session_pointer,
    tree,
)
from defender.tests.support.shared._postgres1339 import execute

pytestmark = [pytest.mark.anyio, pytest.mark.postgres]

COMMIT = "c" * 40
OTHER_COMMIT = "d" * 40
MARKER = "ATTACKER-TEXT-1342"
CASE = "a1" * 16
GOOD = GOLDEN_REPORT.read_text(encoding="utf-8")  # disposition: inconclusive
SONNET_IN, SONNET_OUT, HAIKU_IN = 3.0, 15.0, 1.0  # USD per million tokens (configuration/_pricing.py)


@pytest.fixture
def world(migrated_database: str, tmp_path: Path) -> dict:
    """Tenant T1 registered, its working folder and `runs` container on disk (R1: tenant setup
    makes `runs/`; the worker never does); T2 likewise, to show nothing leaks across tenants."""
    register_tenant(migrated_database, T1)
    register_tenant(migrated_database, T2)
    root = tmp_path / "data"
    for tenant in (T1, T2):
        (root / tenant / "runs").mkdir(parents=True)
        (root / tenant / "sessions").mkdir()
        (root / tenant / "tenant.json").write_text("{}", encoding="utf-8")
    return {"dsn": migrated_database, "root": root, "runs": root / T1 / "runs",
            "other_runs": root / T2 / "runs", "tmp": tmp_path}


async def _queued(store, ticket: str = "T-1", key: str = "k1") -> str:
    alert = await an_alert(store, T1, ticket=ticket)
    inv, _ = await store.create_investigation(T1, alert.alert_id, key, actor="u-1")
    return inv.investigation_id


async def _run_one(world: dict, child: ScriptedChild, **kw) -> tuple[str, dict]:
    async with job_store(world["dsn"]) as store:
        inv = await _queued(store)
        await make_worker(store, world["root"], child, **kw).drain()
    return inv, row(world["dsn"], inv)


def _child(world: dict, **kw) -> ScriptedChild:
    return ScriptedChild(world["tmp"] / "child", world["runs"], **kw)


def _committed(**overrides) -> dict[str, str]:
    """Host records for a run whose report the host committed and whose tree the scrub walked."""
    return {"{id}.job-end.json": job_end(), "{id}/report.md": GOOD,
            "{id}.knowledge-source.json": knowledge_record(COMMIT), **overrides}


def _no_run_text(stored: dict) -> None:
    assert MARKER not in json.dumps(stored, default=str), "run text reached the row"


def _warned(caplog, inv: str) -> bool:
    """A WARNING or worse from the worker that names the row (D-r); routine INFO lines do not count."""
    return any(inv in r.getMessage() for r in caplog.records
               if r.name.startswith(WORKER_LOGGER) and r.levelno >= logging.WARNING)


def _names_code(stored: dict, inv: str, code: int) -> bool:
    """The failure message carries `code` as a delimited number; the row's own id is taken out first."""
    return re.search(rf"\b{code}\b", stored["failure_message"].replace(inv, "")) is not None


EXIT = 77  # no digit of a UUID, timestamp or stage word can stand for it


def test_o12_the_worker_entry_points_are_coroutines():
    """`drain` and `serve` are coroutine functions, as the store is async. (O12)"""
    from defender.worker import Worker

    assert inspect.iscoroutinefunction(Worker.drain)
    assert inspect.iscoroutinefunction(Worker.serve)


# --- O4: slots -------------------------------------------------------------------------------------

async def test_o4_three_children_run_at_once_and_a_fourth_waits_for_a_free_slot(world):
    """Four queued rows, three slots: three live children together, never four; the fourth runs once one ends. (O4, D2)"""
    release = world["tmp"] / "release"
    child = _child(world, files=_committed(), wait_for=release)
    async with job_store(world["dsn"]) as store:
        ids = [await _queued(store, ticket=f"T-{n}", key=f"k{n}") for n in range(4)]
        drained = asyncio.create_task(make_worker(store, world["root"], child, slots=3).drain())
        for _ in range(1500):
            if len(child.seen_all()) == 3:
                break
            await asyncio.sleep(0.01)
        assert len(child.seen_all()) == 3, "three children did not start together"
        await asyncio.sleep(0.5)  # a fourth would have started by now
        assert len(child.seen_all()) == 3
        assert child.max_alive() == 3
        pids = [seen["pid"] for seen in child.seen_all().values()]
        assert all(Path(f"/proc/{pid}").exists() for pid in pids), "the three are not alive together"
        stages = sorted(row(world["dsn"], i)["stage"] for i in ids)
        assert stages == ["queued", "running", "running", "running"]
        release.touch()
        await asyncio.wait_for(drained, timeout=90)

    assert child.max_alive() == 3, "a fourth child overlapped the three"
    assert sorted(child.seen_all()) == sorted(ids)
    assert [row(world["dsn"], i)["stage"] for i in ids] == ["completed"] * 4


async def test_o4_two_workers_never_run_one_row_twice(world):
    """Two workers draining one queue: every row's child starts exactly once. (O4)"""
    child = _child(world, files=_committed())
    async with job_store(world["dsn"]) as one, job_store(world["dsn"]) as two:
        ids = [await _queued(one, ticket=f"T-{n}", key=f"k{n}") for n in range(4)]
        await asyncio.gather(make_worker(one, world["root"], child, slots=2).drain(),
                             make_worker(two, world["root"], child, slots=2).drain())

    starts = [run for kind, run in child.events() if kind == "start"]
    assert sorted(starts) == sorted(ids)
    assert [row(world["dsn"], i)["stage"] for i in ids] == ["completed"] * 4


# --- O5: the fence ---------------------------------------------------------------------------------

@pytest.mark.parametrize("moved", ["failed", "cancelled"])
async def test_o5_a_row_moved_while_its_child_runs_is_left_alone_and_logged(world, caplog, moved):
    """After SQL moves a running row, the finish changes nothing, is logged, emits no finish event; the worker carries on. (O5)"""
    caplog.set_level(logging.INFO, logger=WORKER_LOGGER)
    audit = JobsAudit(caplog)
    release = world["tmp"] / "release"
    child = _child(world, files=_committed(), wait_for=release)
    sql = {"failed": "stage = 'failed', failure_reason = 'worker_error', failure_message = 'moved by test'",
           "cancelled": "stage = 'aborted', failure_reason = 'cancelled'"}[moved]
    async with job_store(world["dsn"]) as store:
        fenced = await _queued(store, ticket="T-1", key="k1")
        other = await _queued(store, ticket="T-2", key="k2")
        drained = asyncio.create_task(make_worker(store, world["root"], child).drain())
        for _ in range(1500):
            if len(child.seen_all()) == 2:
                break
            await asyncio.sleep(0.01)
        assert len(child.seen_all()) == 2, "the children never started"
        execute(world["dsn"], f"UPDATE jobs.investigations SET {sql}, finished_at = %s WHERE id = %s",  # noqa: S608
                (NOW, fenced))
        snapshot = row(world["dsn"], fenced)
        release.touch()
        await asyncio.wait_for(drained, timeout=60)

    assert row(world["dsn"], fenced) == snapshot, "the worker's terminal write overwrote the moved row"
    assert snapshot["disposition"] is None
    assert _warned(caplog, fenced), "the refused write was not logged"
    assert not _warned(caplog, other), "a clean finish was logged as a fault"
    assert row(world["dsn"], other)["stage"] == "completed", "the worker stopped working on every row"
    finishes = [e.target for e in audit.events() if e.action == "investigation.finish"]
    assert finishes == [other], "a finish was audited for a write that changed nothing"


# --- O6: the job lane ------------------------------------------------------------------------------

async def test_o6_the_launch_record_and_alert_file_exist_before_the_child_and_nowhere_else(
        world, monkeypatch):
    """Both files are written beside the run folder before the child starts; argv, data root and session as ratified; nothing else is made. (O6)"""
    monkeypatch.setenv("DEFENDER_DATA_ROOT", str(world["tmp"] / "somewhere-else"))
    before = tree(world["root"])
    other_before = tree(world["other_runs"])
    child = _child(world)  # writes nothing: only the worker's files can be new
    inv, _ = await _run_one(world, child)

    seen = child.seen()
    assert seen is not None, "the child never ran"
    assert seen["argv"] == ["--job", inv, "--tenant", T1, "--parent-pid", str(os.getpid())]
    assert seen["data_root"] == str(world["root"]), "the child must be given DEFENDER_DATA_ROOT"
    assert (seen["launch_at_start"], seen["alert_at_start"]) == (True, True)
    assert seen["sid"] == seen["pid"] != os.getsid(0), "the child must lead its own session"
    assert (world["runs"] / f"{inv}.alert.json").read_bytes() == ALERT_BYTES
    launch = json.loads((world["runs"] / f"{inv}.launch.json").read_text(encoding="utf-8"))
    alert_id = launch["alert_id"]
    assert launch == {"investigation_id": inv, "tenant_id": T1, "alert_id": alert_id,
                      "digest": ALERT_DIGEST, "label": TITLE}
    assert alert_id
    created = {k for k in tree(world["root"]) if k not in before}
    assert created == {f"{T1}/runs/{inv}.launch.json", f"{T1}/runs/{inv}.alert.json"}
    assert {k: v for k, v in tree(world["root"]).items() if k in before} == before
    assert tree(world["other_runs"]) == other_before


@pytest.mark.parametrize("present", [".launch.json", ".alert.json"])
async def test_o6_launch_files_are_create_only_and_a_failed_write_is_a_worker_error(world, present):
    """A launch file that already exists is not overwritten; no child; `failed`/`worker_error`. (O6)"""
    import uuid

    inv = str(uuid.uuid4())
    child = _child(world, files=_committed())
    async with job_store(world["dsn"]) as store:
        alert = await an_alert(store, T1)
        plant_queued_investigation(world["dsn"], tenant=T1, alert_id=alert.alert_id, investigation_id=inv)
        (world["runs"] / f"{inv}{present}").write_text("planted", encoding="utf-8")
        await make_worker(store, world["root"], child).drain()

    stored = row(world["dsn"], inv)
    assert (stored["stage"], stored["failure_reason"]) == ("failed", "worker_error")
    assert stored["failure_message"]
    assert (world["runs"] / f"{inv}{present}").read_text(encoding="utf-8") == "planted"
    assert child.seen() is None, "a child started although its launch files could not be written"


@pytest.mark.parametrize("shape", ["tenant folder without runs", "no tenant folder on this host"])
async def test_o6_a_tenant_with_no_runs_container_fails_as_a_worker_error_and_nothing_is_made(world, shape):
    """No `<root>/<T>/runs` → `failed`/`worker_error`, no child, nothing created anywhere. (O6, R1)"""
    import shutil

    if shape == "no tenant folder on this host":
        shutil.rmtree(world["root"] / T1)
    else:
        world["runs"].rmdir()
    before = tree(world["root"])
    child = _child(world, files=_committed())
    inv, stored = await _run_one(world, child)

    assert (stored["stage"], stored["failure_reason"]) == ("failed", "worker_error")
    assert stored["failure_message"]
    assert stored["finished_at"] == NOW
    assert child.seen() is None, "a child was started without a runs container"
    assert tree(world["root"]) == before, f"the worker made something for {inv}"
    assert not world["runs"].exists()


async def test_o6_a_child_that_cannot_be_spawned_is_a_worker_error_and_the_worker_carries_on(world):
    """An argv that cannot be executed ends the row `failed`/`worker_error`; `drain` returns. (O6)"""
    missing = world["tmp"] / "no-such-program"
    inv, stored = await _run_one(world, lambda launch: [str(missing), "--job", launch.investigation_id])

    assert (stored["stage"], stored["failure_reason"]) == ("failed", "worker_error")
    assert stored["failure_message"]
    assert stored["finished_at"] == NOW
    assert inv


# --- O8: the worker's rule, one case per branch ----------------------------------------------------

def _spec(*, expect, exit=0, says=(), lacks=(), code=None, **spec):  # noqa: A002 — mirrors the child's exit code
    return {"spec": spec, "exit": exit, "expect": expect, "says": says, "lacks": lacks, "code": code}


def _refused(**extra) -> dict[str, str]:
    return {"{id}.job-end.json": job_end(setup="refused", box="not_started", report_committed=False,
                                         scrub_verified=False), **extra}


MARKED_REPORT = GOOD + f"\n{MARKER}\n"
HEADER = "---\ndisposition: benign\n---\n"
CASES = {
    # rule 1: no job-end record; the run folder, the exit and the report decide nothing
    "1-no-job-end": _spec(files={"{id}/report.md": MARKED_REPORT}, exit=EXIT,
                          expect=("failed", "no_report", None), code=EXIT),
    "1-no-job-end-exit-zero": _spec(files={"{id}/report.md": MARKED_REPORT}, exit=0,
                                    expect=("failed", "no_report", None)),
    "1-job-end-unreadable": _spec(files={"{id}.job-end.json": "{not json", "{id}/report.md": GOOD},
                                  exit=EXIT, expect=("failed", "no_report", None), code=EXIT),
    # rule 2
    "2-setup-refused": _spec(files=_refused(), exit=1, expect=("failed", "setup_refused", None)),
    "2-refused-before-a-planted-report": _spec(
        files=_refused(**{"{id}/report.md": MARKED_REPORT}), exit=1,
        expect=("failed", "setup_refused", None)),
    # rule 3
    "3-box-start-failed": _spec(
        files={"{id}.job-end.json": job_end(box="start_failed", report_committed=False,
                                            scrub_verified=False)}, exit=1,
        expect=("failed", "worker_error", None)),
    "3-start-failed-before-a-report": _spec(
        files=_committed(**{"{id}.job-end.json": job_end(box="start_failed")}),
        expect=("failed", "worker_error", None)),
    # rule 4
    "4-completed-inconclusive": _spec(files=_committed(), expect=("completed", None, "inconclusive")),
    "4-completed-malicious-whatever-the-exit": _spec(
        files=_committed(**{"{id}/report.md": MALICIOUS_REPORT.read_text(encoding="utf-8") + f"\n{MARKER}\n"}),
        exit=4, expect=("completed", None, "malicious")),
    "4-no-front-matter": _spec(files=_committed(**{"{id}/report.md": f"no front matter {MARKER}\n"}),
                               expect=("unparseable", None, None)),
    "4-no-disposition": _spec(
        files=_committed(**{"{id}/report.md": f"---\ncase_id: x\n---\n{MARKER}\n"}),
        expect=("unparseable", None, None)),
    "4-disposition-outside-the-vocabulary": _spec(
        files=_committed(**{"{id}/report.md": f"---\ndisposition: sorta-bad\n---\n{MARKER}\n"}),
        expect=("unparseable", None, None)),
    "4-two-dispositions": _spec(
        files=_committed(**{"{id}/report.md": f"---\ndisposition: benign\ndisposition: malicious\n---\n{MARKER}\n"}),
        expect=("unparseable", None, None)),
    "4-report-missing": _spec(files=_committed(**{"{id}/notes.md": MARKER}),
                              expect=("unparseable", None, None)),
    "4-report-is-a-directory": _spec(files=_committed(**{"{id}/notes.md": MARKER}),
                                     dirs=["{id}/report.md"], expect=("unparseable", None, None)),
    "4-report-not-utf8": _spec(
        files=_committed(**{"{id}/notes.md": MARKER}),
        binary={"{id}/report.md": (HEADER + "\n").encode().hex() + "fffe"},
        expect=("unparseable", None, None)),
    "4-report-oversize": _spec(
        files=_committed(**{"{id}/notes.md": MARKER}),
        sparse={"{id}/report.md": [HEADER, 70 * 1024 * 1024]}, expect=("unparseable", None, None)),
    "4-report-symlinked": _spec(
        files=_committed(**{"{id}/notes.md": MARKER}),
        links={"{id}/report.md": str(GOLDEN_REPORT)}, expect=("unparseable", None, None)),
    # rule 5: each failed fact, named
    "5-box-planted-report-not-committed": _spec(
        files=_committed(**{"{id}.job-end.json": job_end(report_committed=False),
                            "{id}/report.md": MARKED_REPORT}),
        exit=4, expect=("failed", "no_report", None), says=("report",), lacks=("scrub", "setup")),
    "5-tree-not-verified": _spec(
        files=_committed(**{"{id}.job-end.json": job_end(scrub_verified=False)}),
        expect=("failed", "no_report", None), says=("scrub",), lacks=("setup",)),
    "5-setup-crashed": _spec(
        files={"{id}.job-end.json": job_end(setup="crashed", box="not_started", report_committed=False,
                                            scrub_verified=False)}, exit=1,
        expect=("failed", "no_report", None), says=("setup",), lacks=()),
}


@pytest.mark.parametrize("case", list(CASES))
async def test_o8_the_stage_comes_from_the_job_end_record_and_the_report(world, caplog, case):
    """Rules 1-5: stage, reason and disposition from the host-held job-end record and the report read by the worker; no run text reaches the row. (O8)"""
    caplog.set_level(logging.INFO, logger=WORKER_LOGGER)
    plan = CASES[case]
    stage, reason, disposition = plan["expect"]
    child = _child(world, exit=plan["exit"], printed=MARKER, **plan["spec"])
    inv, stored = await _run_one(world, child)

    assert child.seen() is not None, "the stand-in child never ran"
    assert (stored["stage"], stored["disposition"]) == (stage, disposition)
    assert stored["failure_reason"] == reason
    if stage == "completed":
        assert (stored["failure_reason"], stored["failure_message"]) == (None, None)
    if stage == "failed":
        assert stored["failure_message"], "a failed row carries our own message"
        message = stored["failure_message"].lower()
        for word in plan["says"]:
            assert word in message, (word, stored["failure_message"])
        for word in plan["lacks"]:  # a fact that held is not named as the failure
            assert word not in message, (word, stored["failure_message"])
        if plan["code"] is not None:
            assert _names_code(stored, inv, plan["code"]), ("exit code", stored["failure_message"])
    assert stored["finished_at"] == NOW
    assert stored["started_at"] == NOW
    _no_run_text(stored)
    assert inv


# --- cost -------------------------------------------------------------------------------------------

def _pointer_files(case_id: str, **extra) -> dict[str, str]:
    return _committed(**{"{id}.session-pointer.json": session_pointer(case_id), **extra})


async def test_o8_cost_is_the_sum_over_every_session_of_the_pointers_database(world):
    """MAIN + a gather lead + lead zero, priced from the pricing table; located by case id, never `store_path`; `tool_trace.jsonl` is not read. (O8 cost, M7)"""
    plant_sessions(world["runs"], CASE, [
        ("main", "claude-sonnet-4-6", {"input_tokens": 1_000_000}),
        ("l-001", "claude-sonnet-4-6", {"output_tokens": 1_000_000}),
        ("l-002", "claude-haiku-4-5", {"input_tokens": 2_000_000}),
        ("l-000", "claude-haiku-4-5", {"input_tokens": 1_000_000}),
    ])
    trace = json.dumps({"type": "result", "cost_usd": 999.0})
    child = _child(world, files=_pointer_files(CASE, **{"{id}/tool_trace.jsonl": trace + "\n"}))
    _, stored = await _run_one(world, child)

    assert stored["stage"] == "completed"
    assert stored["cost_usd"] == pytest.approx(SONNET_IN + SONNET_OUT + 2 * HAIKU_IN + HAIKU_IN)


async def test_o8_a_forked_sessions_inherited_prefix_is_not_charged_twice(world):
    """A session forked from MAIN is charged only for its own response, not the prefix it inherited. (O8 cost, M7)"""
    made = plant_sessions(world["runs"], CASE, [("main", "claude-sonnet-4-6", {"input_tokens": 1_000_000})])
    plant_fork(world["runs"], CASE, made["main"], agent_id="main", model="claude-sonnet-4-6",
               usage={"output_tokens": 1_000_000})
    _, stored = await _run_one(world, _child(world, files=_pointer_files(CASE)))

    assert stored["stage"] == "completed"
    assert stored["cost_usd"] == pytest.approx(SONNET_IN + SONNET_OUT)  # 21.0 would count the prefix twice


async def test_o8_a_run_that_crashed_still_has_its_spend_recorded(world):
    """A failed row (no job-end) carries the cost of the sessions the run left. (O8 cost)"""
    plant_sessions(world["runs"], CASE, [("main", "claude-sonnet-4-6", {"output_tokens": 1_000_000})])
    child = _child(world, files={"{id}.session-pointer.json": session_pointer(CASE)}, exit=1)
    _, stored = await _run_one(world, child)

    assert (stored["stage"], stored["failure_reason"]) == ("failed", "no_report")
    assert stored["cost_usd"] == pytest.approx(SONNET_OUT)


async def test_o8_no_session_pointer_costs_nothing(world, caplog):
    """No pointer (the store was never opened) → cost 0, not unknown. (O8 cost)"""
    caplog.set_level(logging.INFO, logger=WORKER_LOGGER)
    inv, stored = await _run_one(world, _child(world, files=_committed()))
    assert stored["stage"] == "completed"
    assert stored["cost_usd"] == 0
    assert not _warned(caplog, inv), "a run with no pointer logged a cost fault"


def _break_database(runs: Path, case_id: str) -> None:
    db = session_db(runs, case_id)
    db.parent.mkdir(parents=True, exist_ok=True)
    db.write_bytes(b"this is not a sqlite database" * 64)


@pytest.mark.parametrize("fault", ["pointer-not-json", "case-id-escapes", "no-database",
                                   "database-will-not-open", "main-has-a-parent"])
async def test_o8_a_cost_read_fault_keeps_the_stage_and_leaves_cost_unknown(world, caplog, fault):
    """Pointer present but unusable → stage and disposition kept, `cost_usd` null, the fault logged. (O8 cost, R3)"""
    caplog.set_level(logging.INFO, logger=WORKER_LOGGER)
    pointer = session_pointer(CASE)
    if fault == "pointer-not-json":
        pointer = "{not json"
    elif fault == "case-id-escapes":
        pointer = session_pointer("../../../outside")
    elif fault == "database-will-not-open":
        _break_database(world["runs"], CASE)
    elif fault == "main-has-a-parent":
        made = plant_sessions(world["runs"], CASE, [("main", "claude-sonnet-4-6", {"input_tokens": 1_000_000})])
        pointer = session_pointer(CASE, session_id=plant_fork(
            world["runs"], CASE, made["main"], agent_id="main", model="claude-sonnet-4-6",
            usage={"output_tokens": 10}))
    child = _child(world, files=_committed(**{"{id}.session-pointer.json": pointer}))
    inv, stored = await _run_one(world, child)

    assert (stored["stage"], stored["disposition"]) == ("completed", "inconclusive")
    assert stored["cost_usd"] is None
    assert _warned(caplog, inv), "the cost fault was not logged"


# --- knowledge --------------------------------------------------------------------------------------

def _knowledge(status: str, commit: str | None, stale_kind: str | None = None) -> dict:
    return {"status": status, "commit": commit, "stale_kind": stale_kind}


STALE_OPERATOR = _knowledge("stale", None, "operator")
KNOWLEDGE = {
    "fresh": (knowledge_record(COMMIT), _knowledge("current", COMMIT)),
    "stale-transient": (knowledge_record_of("stale", OTHER_COMMIT, stale_kind="transient", reason=MARKER),
                        _knowledge("stale", OTHER_COMMIT, "transient")),
    "stale-operator": (knowledge_record_of("stale", OTHER_COMMIT, stale_kind="operator", reason=MARKER),
                       _knowledge("stale", OTHER_COMMIT, "operator")),
    "pinned": (knowledge_record_of("pinned", OTHER_COMMIT), _knowledge("pinned", OTHER_COMMIT)),
    "unreadable-record": ("{not json", STALE_OPERATOR),
    "record-of-another-shape": (json.dumps(["fresh", COMMIT]), STALE_OPERATOR),
}


@pytest.mark.parametrize("name", list(KNOWLEDGE))
async def test_o8_knowledge_is_the_host_record_mapped_to_the_api_shape(world, name):
    """A started run's knowledge record maps to `{status, commit, stale_kind}`; an unreadable one to `{stale, operator, null}`; record text never reaches the row. (O8 knowledge, M6)"""
    record, expected = KNOWLEDGE[name]
    child = _child(world, files=_committed(**{"{id}.knowledge-source.json": record}))
    _, stored = await _run_one(world, child)

    assert stored["knowledge"] == expected
    _no_run_text(stored)


async def test_o8_a_started_run_with_no_record_is_stale_operator(world):
    """The run folder exists but the record is missing → `{stale, operator, null}`, even on a failed row. (O8 knowledge, M6)"""
    child = _child(world, dirs=["{id}"], exit=1)
    _, stored = await _run_one(world, child)
    assert (stored["stage"], stored["failure_reason"]) == ("failed", "no_report")
    assert stored["knowledge"] == STALE_OPERATOR


async def test_o8_a_failed_run_that_started_still_shows_the_knowledge_it_read(world):
    """Rule 1 failure with a run folder and a fresh record → `{current, commit}`. (O8 knowledge)"""
    child = _child(world, dirs=["{id}"], files={"{id}.knowledge-source.json": knowledge_record(COMMIT)})
    _, stored = await _run_one(world, child)
    assert stored["stage"] == "failed"
    assert stored["knowledge"] == _knowledge("current", COMMIT)


@pytest.mark.parametrize("stray_record", [False, True])
async def test_o8_knowledge_is_null_when_there_is_no_run_folder(world, stray_record):
    """No run folder (setup refused before the run existed) → null, whether or not a record sits beside it. (O8 knowledge, M6)"""
    files = _refused()
    if stray_record:
        files["{id}.knowledge-source.json"] = knowledge_record(COMMIT)
    _, stored = await _run_one(world, _child(world, files=files, exit=1))
    assert (stored["stage"], stored["failure_reason"]) == ("failed", "setup_refused")
    assert stored["knowledge"] is None


# --- O7: the backstop, in-process ------------------------------------------------------------------

async def test_o7_after_the_child_exits_the_backstop_removes_a_leftover_box_only_if_present(world, tmp_path):
    """`defender-run-<id>` is removed when it exists; an absent one is looked at, never an error, and the row is the rules' alone. (O7)"""
    containers = StandInContainers(tmp_path / "containers")
    child = _child(world, files=_committed())
    async with job_store(world["dsn"]) as store:
        left = await _queued(store, ticket="T-1", key="k1")
        clean = await _queued(store, ticket="T-2", key="k2")
        containers.plant(f"defender-run-{left}")
        await make_worker(store, world["root"], child, containers=containers).drain()

    assert ("remove", f"defender-run-{left}") in containers.calls
    assert ("exists", f"defender-run-{clean}") in containers.calls
    assert ("remove", f"defender-run-{clean}") not in containers.calls
    assert not (containers.where / f"defender-run-{left}").exists()
    assert row(world["dsn"], clean)["stage"] == "completed"
    assert row(world["dsn"], left)["stage"] == "completed", "the backstop must not decide the row"


async def test_o7_the_backstop_runs_for_a_run_that_failed_and_never_writes_the_row(world, tmp_path):
    """A failed run's leftover box is removed; the row keeps the rules' verdict, not a backstop's. (O7, M8)"""
    containers = StandInContainers(tmp_path / "containers")
    child = _child(world, exit=EXIT)  # no job-end record: rule 1
    async with job_store(world["dsn"]) as store:
        inv = await _queued(store)
        containers.plant(f"defender-run-{inv}")
        await make_worker(store, world["root"], child, containers=containers).drain()

    assert ("remove", f"defender-run-{inv}") in containers.calls
    stored = row(world["dsn"], inv)
    assert (stored["stage"], stored["failure_reason"]) == ("failed", "no_report")
    assert _names_code(stored, inv, EXIT), stored["failure_message"]


def _docker_world(tmp_path: Path):
    from defender.tests.support.sandbox._box1195 import FakeDaemon

    daemon = FakeDaemon(tmp_path)
    calls: list[list[str]] = []

    def docker(argv, **kw):
        calls.append([str(a) for a in argv])
        return daemon(argv, **kw)

    return daemon, docker, calls


def _removes(calls: list[list[str]], name: str) -> bool:
    return any(name in argv and ("rm" in argv or "remove" in argv) for argv in calls)


def test_o7_the_docker_seam_looks_first_and_removes_only_a_container_that_is_there(tmp_path):
    """`DockerContainers(docker=fn)`: present → exists and removed (control); absent → looked at, nothing removed, no error. (O7, D-o)"""
    from defender.worker import DockerContainers

    daemon, docker, calls = _docker_world(tmp_path)
    containers = DockerContainers(docker=docker)
    daemon.hold("defender-run-here", "exited")
    daemon.hold("defender-run-other", "running")

    assert containers.exists("defender-run-here") is True
    containers.remove("defender-run-here")
    assert daemon.names() == ["defender-run-other"]
    assert _removes(calls, "defender-run-here"), calls

    calls.clear()
    assert containers.exists("defender-run-gone") is False
    assert calls, "an absent container was not even looked at"
    assert not _removes(calls, "defender-run-gone")
    assert daemon.names() == ["defender-run-other"]


async def test_o7_a_worker_given_no_containers_uses_docker_and_removes_only_its_own_leftover(
        world, monkeypatch):
    """Omitting `containers` → the backstop is the docker one (a `docker` first on PATH): the row's leftover box goes, another run's stays, a clean run is no error. (O7, D-o)"""
    import uuid

    from defender.worker import Worker
    from defender.tests.support.jobs._jobs1342 import fixed_clock

    daemon, _docker, _calls = _docker_world(world["tmp"])
    daemon.install(monkeypatch)
    left_id = str(uuid.uuid4())
    child = _child(world, files=_committed())
    async with job_store(world["dsn"]) as store:
        alert = await an_alert(store, T1, ticket="T-L")
        plant_queued_investigation(world["dsn"], tenant=T1, alert_id=alert.alert_id, investigation_id=left_id)
        clean = await _queued(store, ticket="T-2", key="k2")
        daemon.hold(f"defender-run-{left_id}", "exited")
        daemon.hold("defender-run-someone-else", "running")
        await Worker(store, data_root=world["root"], child_argv=child, slots=3, clock=fixed_clock).drain()

    assert daemon.names() == ["defender-run-someone-else"], daemon.names()
    assert row(world["dsn"], left_id)["stage"] == "completed"
    assert row(world["dsn"], clean)["stage"] == "completed", "an absent container broke the clean run"


def test_d2_the_ratified_defaults_are_three_slots_and_a_thirty_second_grace():
    """`Worker(...)` defaults: `slots=3`, `stop_grace=30`. (O4, O7, D2)"""
    from defender.worker import Worker

    params = inspect.signature(Worker).parameters
    assert params["slots"].default == 3
    assert params["stop_grace"].default == 30


async def test_o8_the_childs_output_is_inherited_not_piped(world, capfd):
    """A child's stdout and stderr land on the worker's own descriptors. (design: child output)"""
    _, stored = await _run_one(world, _child(world, files=_committed(), printed=MARKER))
    out, err = capfd.readouterr()

    assert stored["stage"] == "completed"
    assert (MARKER in out, MARKER in err) == (True, True), "the child's output did not reach the worker's stdout and stderr"
    _no_run_text(stored)


# --- O13 -----------------------------------------------------------------------------------------

async def test_o13_claim_and_finish_are_audited_as_the_system_after_commit(world, caplog):
    """`investigation.claim` then `investigation.finish` (detail: stage), actor `system`, each emitted after its row committed. (O13)"""
    import logging as _logging

    audit = JobsAudit(caplog)
    visible = VisibleAtEmit(world["dsn"])
    watched = _logging.getLogger(JOBS_AUDIT_LOGGER)
    watched.addHandler(visible)
    try:
        inv, _ = await _run_one(world, _child(world, files=_committed()))
    finally:
        watched.removeHandler(visible)

    worker_events = [e for e in audit.events() if e.action in ("investigation.claim", "investigation.finish")]
    assert [(e.action, e.actor, e.tenant_id, e.target) for e in worker_events] == [
        ("investigation.claim", "system", T1, inv), ("investigation.finish", "system", T1, inv)]
    assert "completed" in (worker_events[1].detail or "")
    claimed = [stage for action, stage in visible.seen if action == "investigation.claim"]
    finished = [stage for action, stage in visible.seen if action == "investigation.finish"]
    assert claimed == ["running"], "claim was emitted before its transaction committed"
    assert finished == ["completed"], "finish was emitted before its transaction committed"


async def test_o13_a_failed_finish_names_stage_and_reason_in_its_detail(world, caplog):
    """The finish event for a failed row carries the stage and the failure reason. (O13)"""
    audit = JobsAudit(caplog)
    inv, _ = await _run_one(world, _child(world, exit=2))

    finish = [e for e in audit.events() if e.action == "investigation.finish"]
    assert [(e.target, e.actor) for e in finish] == [(inv, "system")]
    assert "failed" in finish[0].detail
    assert "no_report" in finish[0].detail
    assert MARKER not in finish[0].detail

