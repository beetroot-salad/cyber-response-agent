"""#1342 the worker in-process over a real database and real child processes: slots (O4), the fence
(O5), the job lane files (O6), the container backstop (O7), the ending rules 1-5 read from the
job-end record (O8), cost and knowledge at finish, and system-actor audit (O13).

Entry: `defender.worker.Worker(store, data_root=, child_argv=, containers=, slots=, clock=)` and
`await worker.drain()` (claim until nothing is queued, then wait for every slot's task). The child is
`ScriptedChild`: it writes the host records a case names and exits; the worker decides the stage."""
from __future__ import annotations

import asyncio
import contextlib
import hashlib
import inspect
import json
import logging
import os
import re
import shutil
import signal
import sys
import time
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest

from defender.tests.support.jobs._jobs1342 import (
    ALERT_BYTES,
    ALERT_DIGEST,
    AWKWARD_ALERT_BYTES,
    DECOMPOSED_ALERT_BYTES,
    FEFF_RICH_ALERT_BYTES,
    GOLDEN_REPORT,
    JOBS_AUDIT_LOGGER,
    MALICIOUS_REPORT,
    NOW,
    PADDED_ALERT_BYTES,
    ZWNBSP_ALERT_BYTES,
    T1,
    T2,
    TITLE,
    WORKER_LOGGER,
    FaultyContainers,
    JobsAudit,
    ScriptedChild,
    StandInContainers,
    VisibleAtEmit,
    an_alert,
    fd_identity,
    fixed_clock,
    is_box_token,
    job_end,
    job_store,
    knowledge_record,
    knowledge_record_of,
    make_worker,
    move_tenant,
    plant_fork,
    plant_queued_investigation,
    plant_sessions,
    register_tenant,
    restate_tenant,
    row,
    session_db,
    session_pointer,
    tree,
)
from defender.tests.support.shared._postgres1339 import execute

pytestmark = [pytest.mark.anyio, pytest.mark.postgres]
_LINUX_ONLY = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="reads /proc/<pid>")

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
    return {"dsn": migrated_database, "root": root, "runs": root / T1 / "runs",
            "other_runs": root / T2 / "runs", "tmp": tmp_path}


@pytest.fixture(autouse=True)
def _no_database_address_in_the_workers_environment(monkeypatch):
    """R7-1: the worker reads the tenant's state through the store's own claim, so it needs no `DEFENDER_DATABASE_DSN`; none is set here."""
    monkeypatch.delenv("DEFENDER_DATABASE_DSN", raising=False)


def _worker(world: dict, store, child, **kw):
    """`make_worker` over the world's data root; the tenant state comes with the store's claim (R7-1)."""
    return make_worker(store, world["root"], child, **kw)


async def _queued(store, ticket: str = "T-1", key: str = "k1") -> str:
    alert = await an_alert(store, T1, ticket=ticket)
    inv, _ = await store.create_investigation(T1, alert.alert_id, key, actor="u-1")
    return inv.investigation_id


async def _run_one(world: dict, child: ScriptedChild, **kw) -> tuple[str, dict]:
    async with job_store(world["dsn"]) as store:
        inv = await _queued(store)
        await _worker(world, store, child, **kw).drain()
    return inv, row(world["dsn"], inv)


def _child(world: dict, **kw) -> ScriptedChild:
    return ScriptedChild(world["tmp"] / "child", world["runs"], **kw)


def _committed(**overrides) -> dict[str, str]:
    """Host records for a run whose report the host committed and whose tree the scrub walked.
    An override of `None` leaves that record out (a shape whose file the case makes another way)."""
    files = {"{id}.job-end.json": job_end(), "{id}/report.md": GOOD,
             "{id}.knowledge-source.json": knowledge_record(COMMIT), **overrides}
    return {name: text for name, text in files.items() if text is not None}


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

@_LINUX_ONLY
async def test_o4_three_children_run_at_once_and_a_fourth_waits_for_a_free_slot(world):
    """Four queued rows, three slots: three live children together, never four; the fourth runs once one ends. (O4, D2)"""
    release = world["tmp"] / "release"
    child = _child(world, files=_committed(), wait_for=release)
    async with job_store(world["dsn"]) as store:
        ids = [await _queued(store, ticket=f"T-{n}", key=f"k{n}") for n in range(4)]
        drained = asyncio.create_task(_worker(world, store, child, slots=3).drain())
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
        await asyncio.gather(_worker(world, one, child, slots=2).drain(),
                             _worker(world, two, child, slots=2).drain())

    starts = [run for kind, run in child.events() if kind == "start"]
    assert sorted(starts) == sorted(ids)
    assert [row(world["dsn"], i)["stage"] for i in ids] == ["completed"] * 4


# --- O5: the fence ---------------------------------------------------------------------------------

@pytest.mark.parametrize("moved", ["failed", "cancelled", "completed"])
async def test_o5_a_row_moved_while_its_child_runs_keeps_its_stage_and_gains_the_holders_final_accounting(world, caplog, moved):
    """CONFLICT-UPDATED (#1343 B-P2, B3, B4): a row moved to a terminal stage under its child keeps every stage field; its child is ended and the holder adds final cost, knowledge and the mark; no finish is audited. The `queued` variant is retired: nothing re-queues a row (r4 item 2)."""
    caplog.set_level(logging.INFO, logger=WORKER_LOGGER)
    audit = JobsAudit(caplog)
    release = world["tmp"] / "release"
    mark = world["tmp"] / "term-{id}"
    child = _child(world, files=_committed(), wait_for=release, term="finish", term_mark=str(mark))
    sql = {"failed": "stage = 'failed', failure_reason = 'worker_error', failure_message = 'moved by test', finished_at = %s",
           "cancelled": "stage = 'aborted', failure_reason = 'cancelled', finished_at = %s",
           "completed": "stage = 'completed', disposition = 'benign', finished_at = %s"}[moved]
    async with job_store(world["dsn"]) as store:
        fenced = await _queued(store, ticket="T-1", key="k1")
        other = await _queued(store, ticket="T-2", key="k2")
        drained = asyncio.create_task(_worker(world, store, child, **_FAST).drain())
        try:
            await _until(lambda: len(child.seen_all()) == 2, "the children to start")
            execute(world["dsn"], f"UPDATE jobs.investigations SET {sql} WHERE id = %s", (NOW, fenced))  # noqa: S608
            snapshot = row(world["dsn"], fenced)
            await _until(lambda: Path(str(mark).replace("{id}", fenced)).exists(), "the moved row's child to be ended", timeout=5)
            await _until(lambda: accounting_written(world["dsn"], fenced) is not None, "the holder's final accounting", timeout=10)
        finally:
            release.touch()
            await asyncio.wait_for(drained, timeout=60)

    final, sibling = row(world["dsn"], fenced), row(world["dsn"], other)
    stage_fields = lambda r: {k: v for k, v in r.items() if k not in ("cost_usd", "knowledge")}  # noqa: E731
    assert stage_fields(final) == stage_fields(snapshot), "the holder's write changed the moved row's stage"
    assert final["cost_usd"] == 0
    assert final["knowledge"] is not None
    assert final["knowledge"] == sibling["knowledge"]
    assert not Path(str(mark).replace("{id}", other)).exists(), "an unmoved row's child was ended"
    assert not _warned(caplog, other), "a clean finish was logged as a fault"
    assert sibling["stage"] == "completed", "the worker stopped working on every row"
    assert [e.target for e in audit.events() if e.action == "investigation.finish"] == [other], \
        "a finish was audited for a row the worker did not finish"


# --- O6: the job lane ------------------------------------------------------------------------------

async def test_o6_the_launch_record_and_alert_file_exist_before_the_child_and_nowhere_else(
        world, monkeypatch):
    """Both files are written beside the run folder before the child starts; argv, data root and session as ratified; the record has a worker-minted box token; nothing else is made. (O6, r5 C1)"""
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
    assert is_box_token(launch.get("box_token")), launch
    assert launch == {"investigation_id": inv, "tenant_id": T1, "alert_id": alert_id,
                      "digest": ALERT_DIGEST, "label": TITLE, "box_token": launch["box_token"]}
    assert alert_id
    created = {k for k in tree(world["root"]) if k not in before}
    assert created == {f"{T1}/runs/{inv}.launch.json", f"{T1}/runs/{inv}.alert.json"}
    assert {k: v for k, v in tree(world["root"]).items() if k in before} == before
    assert tree(world["other_runs"]) == other_before



@pytest.mark.parametrize("raw", [AWKWARD_ALERT_BYTES, PADDED_ALERT_BYTES, DECOMPOSED_ALERT_BYTES, ZWNBSP_ALERT_BYTES,
                                 FEFF_RICH_ALERT_BYTES],
                         ids=["crlf tab multibyte", "leading whitespace and trailing spaces", "decomposed unicode",
                              "zero-width no-break space in a string", "feff_rich"])
async def test_o6_the_alert_file_is_the_stored_raw_bytes_whatever_they_contain(world, raw):
    """An alert that CRLF, tabs, multibyte text, padding whitespace or a decomposed sequence would change reaches `<id>.alert.json` byte for byte, and the launch digest is of those bytes. (O6, M5)"""
    import unicodedata

    from defender.records.formats import admit

    admit(raw)  # premise: admission accepts these bytes
    if raw is FEFF_RICH_ALERT_BYTES:
        bom = b"\xef\xbb\xbf"
        for shape in (b'"' + bom, bom + b'"', bom + bom, b"m" + bom + b"n", b'"k' + bom + b'ey":'):
            assert shape in raw, ("premise", shape)
        assert not raw.startswith(bom)
    elif raw is ZWNBSP_ALERT_BYTES:
        assert b"\xef\xbb\xbf" in raw, "premise: a U+FEFF in the bytes"
        assert not raw.startswith(b"\xef\xbb\xbf"), "premise: not a leading byte-order mark"
    else:
        assert (raw != raw.strip() or b"\r\n" in raw or raw.decode() != unicodedata.normalize("NFC", raw.decode())), (
            "premise: bytes a strip, a line-end or a normalization step would change")
    if raw is AWKWARD_ALERT_BYTES:
        assert b"\r\n" in raw
        assert len(raw.decode()) < len(raw), "premise: multibyte text"
    child = _child(world)
    async with job_store(world["dsn"]) as store:
        alert = await an_alert(store, T1, raw=raw)
        inv, _ = await store.create_investigation(T1, alert.alert_id, "k1", actor="u-1")
        await _worker(world, store, child).drain()

    written = (world["runs"] / f"{inv.investigation_id}.alert.json").read_bytes()
    assert written == raw
    launch = json.loads((world["runs"] / f"{inv.investigation_id}.launch.json").read_text(encoding="utf-8"))
    assert launch["digest"] == hashlib.sha256(raw).hexdigest()


@pytest.mark.parametrize("present", [".launch.json"])
async def test_o6_launch_files_are_create_only_and_a_failed_write_is_a_worker_error(world, present):
    """A launch record that already exists is not overwritten; no child; `failed`/`worker_error`. (O6, D-af: a leftover alert file is not a launch marker)"""
    import uuid

    inv = str(uuid.uuid4())
    child = _child(world, files=_committed())
    async with job_store(world["dsn"]) as store:
        alert = await an_alert(store, T1)
        plant_queued_investigation(world["dsn"], tenant=T1, alert_id=alert.alert_id, investigation_id=inv)
        (world["runs"] / f"{inv}{present}").write_text("planted", encoding="utf-8")
        await _worker(world, store, child).drain()

    stored = row(world["dsn"], inv)
    assert (stored["stage"], stored["failure_reason"]) == ("failed", "worker_error")
    assert stored["failure_message"]
    assert stored["cost_usd"] == 0, "a worker fault before the run is cost 0, not unknown"
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
    assert stored["cost_usd"] == 0, "a worker fault before the run is cost 0, not unknown"
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
    assert stored["cost_usd"] == 0, "a worker fault before the run is cost 0, not unknown"
    assert inv


# --- O8: the worker's rule, one case per branch ----------------------------------------------------

def _spec(*, expect, exit=0, says=(), lacks=(), code=None, **spec):  # noqa: A002 — mirrors the child's exit code
    return {"spec": spec, "exit": exit, "expect": expect, "says": says, "lacks": lacks, "code": code}


def _refused(**extra) -> dict[str, str]:
    return {"{id}.job-end.json": job_end(setup="refused", box="not_started", report_committed=False,
                                         scrub_verified=False), **extra}


JSON_NULL = object()  # `_job_end_with(key=JSON_NULL)` writes an explicit JSON null


def _job_end_with(**changes) -> str:
    """A job-end record of the ratified keys with `changes` applied (a `None` value drops the key)."""
    body = json.loads(job_end())
    body.update(changes)
    return json.dumps({k: (None if v is JSON_NULL else v) for k, v in body.items() if v is not None})


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
    "1-job-end-empty-object": _spec(files=_committed(**{"{id}.job-end.json": "{}"}), exit=EXIT,
                                    expect=("failed", "no_report", None), code=EXIT),
    "1-job-end-an-array": _spec(files=_committed(**{"{id}.job-end.json": "[]"}), exit=EXIT,
                                expect=("failed", "no_report", None), code=EXIT),
    "1-job-end-a-string": _spec(files=_committed(**{"{id}.job-end.json": '"done"'}), exit=EXIT,
                                expect=("failed", "no_report", None), code=EXIT),
    "1-job-end-committed-as-a-string": _spec(
        files=_committed(**{"{id}.job-end.json": _job_end_with(report_committed="false")}), exit=EXIT,
        expect=("failed", "no_report", None), code=EXIT),
    "1-job-end-verified-as-a-number": _spec(
        files=_committed(**{"{id}.job-end.json": _job_end_with(scrub_verified=0)}), exit=EXIT,
        expect=("failed", "no_report", None), code=EXIT),
    "1-job-end-unknown-setup-word": _spec(
        files=_committed(**{"{id}.job-end.json": _job_end_with(setup="skipped")}), exit=EXIT,
        expect=("failed", "no_report", None), code=EXIT),
    "1-job-end-unknown-box-word": _spec(
        files=_committed(**{"{id}.job-end.json": _job_end_with(box="paused")}), exit=EXIT,
        expect=("failed", "no_report", None), code=EXIT),
    "1-job-end-committed-as-json-null": _spec(
        files=_committed(**{"{id}.job-end.json": _job_end_with(report_committed=JSON_NULL)}), exit=EXIT,
        expect=("failed", "no_report", None), code=EXIT),
    "1-job-end-verified-as-json-null": _spec(
        files=_committed(**{"{id}.job-end.json": _job_end_with(scrub_verified=JSON_NULL)}), exit=EXIT,
        expect=("failed", "no_report", None), code=EXIT),
    "1-job-end-committed-as-the-number-one": _spec(
        files=_committed(**{"{id}.job-end.json": _job_end_with(report_committed=1)}), exit=EXIT,
        expect=("failed", "no_report", None), code=EXIT),
    "1-job-end-committed-as-the-number-zero": _spec(
        files=_committed(**{"{id}.job-end.json": _job_end_with(report_committed=0)}), exit=EXIT,
        expect=("failed", "no_report", None), code=EXIT),
    "1-job-end-verified-as-the-number-one": _spec(
        files=_committed(**{"{id}.job-end.json": _job_end_with(scrub_verified=1)}), exit=EXIT,
        expect=("failed", "no_report", None), code=EXIT),
    "1-job-end-setup-word-capitalised": _spec(
        files=_committed(**{"{id}.job-end.json": _job_end_with(setup="Done")}), exit=EXIT,
        expect=("failed", "no_report", None), code=EXIT),
    "1-job-end-setup-word-spaced": _spec(
        files=_committed(**{"{id}.job-end.json": _job_end_with(setup=" done")}), exit=EXIT,
        expect=("failed", "no_report", None), code=EXIT),
    "1-job-end-setup-word-upper-case": _spec(
        files=_committed(**{"{id}.job-end.json": _job_end_with(setup="DONE")}), exit=EXIT,
        expect=("failed", "no_report", None), code=EXIT),
    "1-job-end-box-word-upper-case": _spec(
        files=_committed(**{"{id}.job-end.json": _job_end_with(box="STARTED")}), exit=EXIT,
        expect=("failed", "no_report", None), code=EXIT),
    "1-job-end-box-word-capitalised": _spec(
        files=_committed(**{"{id}.job-end.json": _job_end_with(box="Started")}), exit=EXIT,
        expect=("failed", "no_report", None), code=EXIT),
    "1-job-end-box-word-spaced": _spec(
        files=_committed(**{"{id}.job-end.json": _job_end_with(box=" started")}), exit=EXIT,
        expect=("failed", "no_report", None), code=EXIT),
    "1-job-end-box-word-shouted": _spec(
        files=_committed(**{"{id}.job-end.json": _job_end_with(box="BOX")}), exit=EXIT,
        expect=("failed", "no_report", None), code=EXIT),
    "1-job-end-an-extra-key": _spec(
        files=_committed(**{"{id}.job-end.json": _job_end_with(extra="x")}), exit=EXIT,
        expect=("failed", "no_report", None), code=EXIT),
    "1-job-end-a-missing-key": _spec(
        files=_committed(**{"{id}.job-end.json": _job_end_with(scrub_verified=None)}), exit=EXIT,
        expect=("failed", "no_report", None), code=EXIT),
    "1-job-end-setup-as-a-list": _spec(
        files=_committed(**{"{id}.job-end.json": _job_end_with(setup=["done"])}), exit=EXIT,
        expect=("failed", "no_report", None), code=EXIT),
    "1-job-end-box-as-an-object": _spec(
        files=_committed(**{"{id}.job-end.json": _job_end_with(box={})}), exit=EXIT,
        expect=("failed", "no_report", None), code=EXIT),
    "1-job-end-setup-a-list-and-box-an-object": _spec(
        files=_committed(**{"{id}.job-end.json": _job_end_with(setup=["done"], box={})}), exit=EXIT,
        expect=("failed", "no_report", None), code=EXIT),
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
    "4-report-missing": _spec(files=_committed(**{"{id}/report.md": None, "{id}/notes.md": MARKER}),
                              expect=("unparseable", None, None)),
    "4-report-is-a-directory": _spec(files=_committed(**{"{id}/report.md": None, "{id}/notes.md": MARKER}),
                                     dirs=["{id}/report.md"], expect=("unparseable", None, None)),
    "4-report-not-utf8": _spec(
        files=_committed(**{"{id}/report.md": None, "{id}/notes.md": MARKER}),
        binary={"{id}/report.md": (HEADER + "\n").encode().hex() + "fffe"},
        expect=("unparseable", None, None)),
    "4-report-oversize": _spec(
        files=_committed(**{"{id}/report.md": None, "{id}/notes.md": MARKER}),
        sparse={"{id}/report.md": [HEADER, 70 * 1024 * 1024]}, expect=("unparseable", None, None)),
    "4-report-symlinked": _spec(
        files=_committed(**{"{id}/report.md": None, "{id}/notes.md": MARKER}),
        links={"{id}/report.md": str(GOLDEN_REPORT)}, expect=("unparseable", None, None)),
    # rule 4 after an abnormal child end whose facts are both true (r5 C2: the driver raised after a clean close)
    "4-completed-when-the-child-died-after-both-facts": _spec(files=_committed(), exit=1,
                                                              expect=("completed", None, "inconclusive")),
    # rule 5: each failed fact, named
    "5-committed-then-the-teardown-faulted": _spec(
        files=_committed(**{"{id}.job-end.json": job_end(report_committed=True, scrub_verified=False)}), exit=1,
        expect=("failed", "no_report", None), says=("scrub",), lacks=("setup",)),
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

_SPELLINGS = {"trailing space": lambda w: w + " ", "trailing newline": lambda w: w + "\n",
              "trailing tab": lambda w: w + "\t", "trailing carriage return and newline": lambda w: w + "\r\n",
              "full-width": lambda w: w.translate({ord(c): ord(c) + 0xFEE0 for c in w if c.isascii() and c.isalpha()}),
              "leading newline": lambda w: "\n" + w, "leading tab": lambda w: "\t" + w,
              "leading carriage return and newline": lambda w: "\r\n" + w, "leading nul": lambda w: "\x00" + w,
              "leading space": lambda w: " " + w, "leading zero-width space": lambda w: "\u200b" + w,
              "leading byte-order mark": lambda w: "\ufeff" + w,
              "zero-width space inside": lambda w: w[:2] + "\u200b" + w[2:]}
for _key, _words in (("setup", ("refused", "crashed", "done")), ("box", ("not_started", "start_failed", "started"))):
    for _word in _words:
        for _how, _spell in _SPELLINGS.items():
            CASES[f"1-job-end-{_key}-word-{_word}-{_how.replace(' ', '-')}"] = _spec(
                files=_committed(**{"{id}.job-end.json": _job_end_with(**{_key: _spell(_word)})}), exit=EXIT,
                expect=("failed", "no_report", None), code=EXIT)



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


def _job_end_junk_characters() -> list[str]:
    import unicodedata

    kinds = {"Zs", "Zl", "Zp", "Cf"}
    found = {chr(n) for n in range(0x110000) if unicodedata.category(chr(n)) in kinds}
    return sorted(found | set("\x00\t\n\r\x0b\x0c\x85\x1c\x1d\x1e\x1f"))


_JUNK = _job_end_junk_characters()
_JUNK_SPELLINGS = {"leading": lambda w, c: c + w, "trailing": lambda w, c: w + c,
                   "interior": lambda w, c: w[:len(w) // 2] + c + w[len(w) // 2:]}
_JOB_END_WORDS = (("setup", "refused"), ("setup", "crashed"), ("setup", "done"),
                  ("box", "not_started"), ("box", "start_failed"), ("box", "started"))
_JUNK_VARIANTS = [(key, word, where) for key, word in _JOB_END_WORDS for where in _JUNK_SPELLINGS]


@pytest.mark.parametrize("junk", _JUNK, ids=lambda c: f"U{ord(c):04X}")
def test_o8_no_junk_character_leading_trailing_or_inside_a_job_end_word_makes_it_one(junk):
    """Each of the six words with `junk` before, after or inside it is not a job-end record the job entry could write. (O8, M3)"""
    from defender.records.job_lane import JobEnd

    assert JobEnd.parse(job_end()) is not None, "premise: the honest record parses"
    for key, word, where in _JUNK_VARIANTS:
        text = _job_end_with(**{key: _JUNK_SPELLINGS[where](word, junk)})
        assert JobEnd.parse(text) is None, (key, word, where, text)


@pytest.mark.parametrize("junk", _JUNK, ids=lambda c: f"U{ord(c):04X}")
async def test_o8_a_job_end_word_with_junk_anywhere_is_a_failed_run_with_the_exit_code(world, junk):
    """Per junk character, one worker drain over leading, trailing and interior (the word rotating with the character): failed/no_report naming the exit code. (O8, M3)"""
    base = _JUNK.index(junk)
    variants = [(*_JOB_END_WORDS[(base + n) % len(_JOB_END_WORDS)], where) for n, where in enumerate(_JUNK_SPELLINGS)]
    child = _child(world, exit=EXIT, printed=MARKER)
    order: list[tuple[str, str, str]] = []

    def argv(launch):
        key, word, where = variants[len(order)]
        order.append((key, word, where))
        child.files = _committed(**{"{id}.job-end.json": _job_end_with(**{key: _JUNK_SPELLINGS[where](word, junk)})})
        return child(launch)

    async with job_store(world["dsn"]) as store:
        ids = [await _queued(store, ticket=f"T-{n}", key=f"k{n}") for n in range(len(variants))]
        await _worker(world, store, argv, slots=1).drain()

    assert len(order) == len(ids), "premise: a launch for every queued run"
    assert len(child.seen_all()) == len(ids), "premise: every child ran"
    for inv in ids:
        stored = row(world["dsn"], inv)
        assert (stored["stage"], stored["disposition"], stored["failure_reason"]) == ("failed", None, "no_report"), stored
        assert _names_code(stored, inv, EXIT), ("exit code", stored["failure_message"])
        _no_run_text(stored)


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


def _sqlite(runs: Path, sql: str) -> None:
    import sqlite3

    conn = sqlite3.connect(session_db(runs, CASE))
    try:
        conn.execute(sql)
        conn.commit()
    finally:
        conn.close()


@pytest.mark.parametrize("fault", ["pointer-not-json", "case-id-escapes", "no-database",
                                   "database-will-not-open", "main-has-a-parent", "stale-schema-version",
                                   "corrupt-payload", "no-main-session", "pointed-session-not-in-database"])
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
    elif fault == "stale-schema-version":
        plant_sessions(world["runs"], CASE, [("main", "claude-sonnet-4-6", {"input_tokens": 1_000_000})])
        _sqlite(world["runs"], "PRAGMA user_version = 4242")
    elif fault == "corrupt-payload":
        plant_sessions(world["runs"], CASE, [("main", "claude-sonnet-4-6", {"input_tokens": 1_000_000})])
        _sqlite(world["runs"], "UPDATE message_payload SET payload = '{\"parts\": ['")
    elif fault == "no-main-session":
        plant_sessions(world["runs"], CASE, [("l-001", "claude-sonnet-4-6", {"input_tokens": 1_000_000})])
    elif fault == "pointed-session-not-in-database":
        plant_sessions(world["runs"], CASE, [("main", "claude-sonnet-4-6", {"input_tokens": 1_000_000})])
        pointer = session_pointer(CASE, session_id="no-such-session")
    child = _child(world, files=_committed(**{"{id}.session-pointer.json": pointer}))
    inv, stored = await _run_one(world, child)

    assert (stored["stage"], stored["disposition"]) == ("completed", "inconclusive")
    assert stored["cost_usd"] is None
    assert _warned(caplog, inv), "the cost fault was not logged"


@pytest.mark.parametrize("shape", ["an array", "an empty object", "a case id that is a number"])
async def test_o8_a_session_pointer_of_the_wrong_shape_keeps_the_stage_and_leaves_cost_unknown(
        world, caplog, shape):
    """A pointer that is an array, lacks `case_id` or has a numeric one: stage and disposition kept, `cost_usd` null, the fault logged, no crash. (O8 cost, R3)"""
    caplog.set_level(logging.INFO, logger=WORKER_LOGGER)
    if shape == "a case id that is a number":  # a database exists under the number's spelling
        plant_sessions(world["runs"], "5", [("main", "claude-sonnet-4-6", {"input_tokens": 1_000_000})])
    pointer = {"an array": "[]", "an empty object": "{}",
               "a case id that is a number": json.dumps({"case_id": 5, "store_path": "/nonexistent/elsewhere.db"})}[shape]
    inv, stored = await _run_one(world, _child(world, files=_committed(**{"{id}.session-pointer.json": pointer})))

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

def _claim_token(world: dict, inv: str) -> str:
    """The `box_token` the worker wrote into this row's launch record."""
    return json.loads((world["runs"] / f"{inv}.launch.json").read_text(encoding="utf-8"))["box_token"]


async def test_o7_after_the_child_exits_the_backstop_reaps_under_the_claims_token_and_a_missing_box_is_normal(
        world, tmp_path, caplog):
    """`reap(name, token)` is asked with the token in the launch record, per claim: a box that start stamped is removed, an absent one reads `absent`, and the row is the rules' alone. (O7, r5 C1)"""
    caplog.set_level(logging.INFO, logger=WORKER_LOGGER)
    containers = StandInContainers(tmp_path / "containers")
    owning = _child(world, files=_committed(), box_dir=containers.where)  # its start made and stamped the box
    bare = ScriptedChild(world["tmp"] / "child-bare", world["runs"], files=_committed())
    async with job_store(world["dsn"]) as store:
        left = await _queued(store, ticket="T-1", key="k1")
        await _worker(world, store, owning, containers=containers).drain()
        clean = await _queued(store, ticket="T-2", key="k2")
        await _worker(world, store, bare, containers=containers).drain()

    left_token, clean_token = _claim_token(world, left), _claim_token(world, clean)
    assert is_box_token(left_token), left_token
    assert is_box_token(clean_token), clean_token
    assert left_token != clean_token, "one token per claim"
    assert containers.reaped(f"defender-run-{left}") == [left_token]
    assert containers.reaped(f"defender-run-{clean}") == [clean_token], "an absent box is still asked about"
    assert not containers.held(f"defender-run-{left}")
    assert row(world["dsn"], clean)["stage"] == "completed"
    assert row(world["dsn"], left)["stage"] == "completed", "the backstop must not decide the row"
    assert not _warned(caplog, clean), "an absent box is normal: nothing to warn about"


async def test_o7_the_backstop_runs_for_a_run_that_failed_and_never_writes_the_row(world, tmp_path):
    """A failed run's leftover box (this claim's token) is removed; the row keeps the rules' verdict, not a backstop's. (O7, M8, r5 C1)"""
    containers = StandInContainers(tmp_path / "containers")
    child = _child(world, exit=EXIT, box_dir=containers.where)  # no job-end record: rule 1
    inv, stored = await _run_one(world, child, containers=containers)

    assert containers.reaped(f"defender-run-{inv}") == [_claim_token(world, inv)]
    assert not containers.held(f"defender-run-{inv}")
    assert (stored["stage"], stored["failure_reason"]) == ("failed", "no_report")
    assert _names_code(stored, inv, EXIT), stored["failure_message"]


async def test_o7_the_backstop_runs_after_the_child_has_exited(world, tmp_path):
    """The reap happens once the child is gone, never while it runs (its box may still be in use). (O7, r5 C1)"""
    containers = StandInContainers(tmp_path / "containers")
    child = _child(world, files=_committed(), box_dir=containers.where)
    seen_at_reap: list[list[tuple[str, str]]] = []
    real_reap = containers.reap

    def reap(name: str, token: str) -> str:
        seen_at_reap.append(child.events())
        return real_reap(name, token)

    containers.reap = reap  # a recording wrapper on the test's own stand-in, not a patch of production
    inv, _ = await _run_one(world, child, containers=containers)

    assert seen_at_reap == [[("start", inv), ("end", inv)]], seen_at_reap


@pytest.mark.parametrize("stamp", ["other", "none"])
async def test_o7_a_container_already_holding_the_name_that_is_not_the_claims_is_left_and_logged(
        world, tmp_path, caplog, stamp):
    """A same-name container with another token or none is left in place and logged at WARNING; the row is `failed`/`worker_error` (box start_failed), as before. (O7, r5 C1)"""
    caplog.set_level(logging.INFO, logger=WORKER_LOGGER)
    containers = StandInContainers(tmp_path / "containers")
    refused = job_end(box="start_failed", report_committed=False, scrub_verified=False)
    child = _child(world, files={"{id}.job-end.json": refused}, exit=1, box_dir=containers.where, box_token=stamp)
    inv, stored = await _run_one(world, child, containers=containers)

    name = f"defender-run-{inv}"
    assert containers.held(name), "a container that is not this job's was removed"
    assert (containers.where / name).read_text(encoding="utf-8") == {"other": "f" * 32, "none": ""}[stamp]
    assert containers.reaped(name) == [_claim_token(world, inv)]
    warned = [r.getMessage() for r in caplog.records
              if r.name.startswith(WORKER_LOGGER) and r.levelno >= logging.WARNING]
    assert any(name in m and "left in place" in m for m in warned), warned
    assert (stored["stage"], stored["failure_reason"]) == ("failed", "worker_error")


async def test_o7_a_box_that_is_ours_is_removed_without_a_warning(world, tmp_path, caplog):
    """Control for the foreign-container case: the claim's own leftover is removed and nothing is warned about. (O7, r5 C1)"""
    caplog.set_level(logging.INFO, logger=WORKER_LOGGER)
    containers = StandInContainers(tmp_path / "containers")
    inv, _ = await _run_one(world, _child(world, files=_committed(), box_dir=containers.where), containers=containers)

    assert not containers.held(f"defender-run-{inv}")
    assert not _warned(caplog, inv), "an own leftover is routine"


async def test_o7_a_backstop_that_cannot_ask_leaves_the_row_to_the_rules_and_the_worker_goes_on(world, tmp_path):
    """A containers seam whose `reap` raises: both rows keep the stage the rules gave, the worker carries on. (O7, r5 C1)"""
    containers = FaultyContainers(tmp_path / "containers")
    child = _child(world, files=_committed())
    async with job_store(world["dsn"]) as store:
        ids = [await _queued(store, ticket=f"T-{n}", key=f"k{n}") for n in range(2)]
        await _worker(world, store, child, containers=containers).drain()

    assert sorted(name for _kind, name, _token in containers.calls) == sorted(f"defender-run-{i}" for i in ids)
    for i in ids:
        stored = row(world["dsn"], i)
        assert (stored["stage"], stored["disposition"], stored["failure_reason"]) == ("completed", "inconclusive", None)


_DOCKER_STAND_IN = """
import json, re, sys
from pathlib import Path

home = Path(sys.argv[1])
argv = sys.argv[2:]
with open(home / "calls.log", "a", encoding="utf-8") as log:
    log.write(json.dumps(argv) + "\\n")
if (home / "down").exists():  # the daemon does not answer anything
    print("Cannot connect to the Docker daemon at unix:///var/run/docker.sock", file=sys.stderr)
    sys.exit(1)
args = argv[1:] if argv[:1] and Path(argv[0]).name == "docker" else argv
while args[:1] and args[0].startswith("-"):  # global flags before the verb
    args = args[2:] if "=" not in args[0] and args[0] in ("--log-level", "-l", "--context", "-c",
                                                          "--host", "-H", "--config") else args[1:]
args = args[1:] if args[:1] == ["container"] else args
verb, rest = (args[0] if args else ""), args[1:]
verb = {"remove": "rm", "ls": "ps", "list": "ps"}.get(verb, verb)
held = lambda: sorted(p.name for p in (home / "held").iterdir())
state_of = lambda n: (home / "held" / n).read_text(encoding="utf-8").split("\\n")[0].strip() or "exited"  # exited, running or paused
token_of = lambda n: (home / "held" / n).read_text(encoding="utf-8").partition("\\n")[2]  # the start-token label exactly as stored, "" for none
operands, filters, fmt, skip = [], [], None, None
for a in rest:
    if skip:
        if skip == "--filter":
            filters.append(a)
        elif skip == "--format":
            fmt = a
        skip = None
    elif a in ("--format", "--filter", "--type", "--time", "-t") or (a == "-f" and verb in ("inspect", "ps")):
        skip = {"-f": "--filter" if verb == "ps" else "--format"}.get(a, a)
    elif a.startswith("--filter="):
        filters.append(a.split("=", 1)[1])
    elif a.startswith("--format="):
        fmt = a.split("=", 1)[1]
    elif not a.startswith("-"):
        operands.append(a)
if verb == "inspect":
    gone = [n for n in operands if n not in held()]
    if gone:
        print("Error: No such object: " + gone[0], file=sys.stderr)
        sys.exit(1)
    states = {n: {"Status": state_of(n), "Running": state_of(n) in ("running", "paused"), "Paused": state_of(n) == "paused"}
              for n in operands}
    if fmt is None:
        print(json.dumps([{"Name": "/" + n, "State": states[n]} for n in operands]))
    else:
        for n in operands:
            if "Config.Labels" in fmt:  # `{{index .Config.Labels "<key>"}}`: docker prints this text for a label the container lacks
                if (home / "blind").exists():  # the state answers, the label read does not
                    print("Error: the daemon dropped the label read", file=sys.stderr)
                    sys.exit(1)
                if (home / "emptied" / n).exists():  # the label is set, to nothing: docker prints an empty line
                    print("")
                    continue
                print(token_of(n) or "<no value>")
                continue
            fields = {"{{.State.Status}}": states[n]["Status"], "{{.State.Running}}": str(states[n]["Running"]).lower(),
                      "{{.State.Paused}}": str(states[n]["Paused"]).lower(), "{{json .State}}": json.dumps(states[n])}
            print(fields.get(fmt.strip()) or ("/" + n if "Name" in fmt else n if "Id" in fmt else states[n]["Status"]))
elif verb == "rm":
    force = any(a in ("-f", "--force") for a in rest)
    for n in operands:
        if n not in held():
            print("Error: No such container: " + n, file=sys.stderr)
            sys.exit(1)
        if (home / "stuck" / n).exists() and not (home / "waited" / n).exists():  # paused under runsc
            print(f"Error response from daemon: cannot remove container {n}: container is paused", file=sys.stderr)
            sys.exit(1)
        if state_of(n) in ("running", "paused") and not force:
            print(f"Error response from daemon: cannot remove container {n}: container is {state_of(n)}: "
                  "stop the container before removing or force remove", file=sys.stderr)
            sys.exit(1)
        if (home / "jammed" / n).exists():  # survives every removal, waited on or not
            print(f"Error response from daemon: cannot remove container {n}: container is paused", file=sys.stderr)
            sys.exit(1)
        (home / "held" / n).unlink()
elif verb == "ps":
    wanted = [f.split("=", 1)[1].strip("^$").lstrip("/") for f in filters if f.startswith("name=")]
    every = any(a == "--all" or (a.startswith("-") and not a.startswith("--") and "a" in a) for a in rest)
    for n in held():  # plain `ps` shows the running (and paused) ones; `-a` every one
        if not every and state_of(n) == "exited":
            continue
        if not wanted or any(re.search(w, n) for w in wanted):
            print(n)
elif verb == "wait":
    for n in operands:
        if n not in held():
            print("Error: No such container: " + n, file=sys.stderr)
            sys.exit(1)
        if state_of(n) == "running" and not (home / "stuck" / n).exists():  # real docker blocks until it exits
            print(f"Error: would block: container {n} is running", file=sys.stderr)
            sys.exit(1)
        (home / "waited" / n).write_text("", encoding="utf-8")
        print("0")
elif verb == "version":
    print("27.0.0")
else:
    print("unknown command: " + " ".join(argv), file=sys.stderr)
    sys.exit(1)
"""


class _DockerStandIn:
    """A docker that answers inspect, rm and ps in their usual forms (also under `container`), over
    files in `<tmp>/docker-stand-in`; the `docker=` seam and, once `install`ed, `docker` on PATH."""

    def __init__(self, tmp_path: Path) -> None:
        self.home = tmp_path / "docker-stand-in"
        for sub in ("held", "stuck", "jammed", "waited", "emptied"):
            (self.home / sub).mkdir(parents=True)
        self.script = self.home / "stand_in.py"
        self.script.write_text(_DOCKER_STAND_IN, encoding="utf-8")

    def __call__(self, argv, **_kw):
        import subprocess
        import sys

        return subprocess.run([sys.executable, str(self.script), str(self.home), *map(str, argv)],
                              capture_output=True, text=True, check=False)

    def hold(self, name: str, state: str = "exited", token: str | None = None) -> None:
        """The daemon holds `name` in `state` (`exited`, `running` or `paused`), carrying `token` as its
        `defender.start-token` label (`None`: no such label)."""
        (self.home / "held" / name).write_text(state if token is None else f"{state}\n{token}", encoding="utf-8")

    def stick(self, name: str) -> None:
        """Every `rm` of `name` fails until a `docker wait` on it has returned (a paused box under runsc)."""
        (self.home / "stuck" / name).write_text("", encoding="utf-8")

    def jam(self, name: str) -> None:
        """Every `rm` of `name` fails, `docker wait` or not: a box that cannot be removed."""
        (self.home / "jammed" / name).write_text("", encoding="utf-8")

    def empty_the_label(self, name: str) -> None:
        """`name` carries the start-token label, set to the empty string (not an absent label)."""
        (self.home / "emptied" / name).write_text("", encoding="utf-8")

    def go_blind(self) -> None:
        """Reading a container's labels fails (rc 1, no "no such object"), though its state still answers."""
        (self.home / "blind").write_text("", encoding="utf-8")

    def go_down(self) -> None:
        """The daemon answers nothing: every call exits non-zero."""
        (self.home / "down").write_text("", encoding="utf-8")

    def names(self) -> list[str]:
        return sorted(p.name for p in (self.home / "held").iterdir())

    @property
    def calls(self) -> list[list[str]]:
        log = self.home / "calls.log"
        return [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()] if log.exists() else []

    def install(self, monkeypatch) -> None:
        import sys

        bin_dir = self.home / "bin"
        bin_dir.mkdir()
        shim = bin_dir / "docker"
        shim.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{self.script}" "{self.home}" "$@"\n', encoding="utf-8")
        shim.chmod(0o755)
        monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")


def _docker_world(tmp_path: Path):
    daemon = _DockerStandIn(tmp_path)
    return daemon, daemon


def _removes(calls: list[list[str]], name: str) -> bool:
    return any(name in argv and ("rm" in argv or "remove" in argv) for argv in calls)


TOKEN = "3f9a1c07be52d84e6a0b7c19e3d5f248"  # not periodic: no swap, rotation or reshuffle of it reads as it
OTHER_TOKEN = "cd" * 16


def _with(token: str, at: int, char: str) -> str:
    return token[:at] + char + token[at + 1:]


@pytest.mark.parametrize("state", ["exited", "running", "paused"])
def test_o7_the_docker_seam_removes_a_box_carrying_the_claims_token_and_nothing_else(tmp_path, state):
    """`DockerContainers(docker=fn).reap(name, token)`: a container with this token, in any state → `removed` and gone; another container is untouched. (O7, r5 C1)"""
    from defender.worker import DockerContainers

    daemon, docker = _docker_world(tmp_path)
    daemon.hold("defender-run-here", state, TOKEN)
    daemon.hold("defender-run-other", "running", TOKEN)  # the same token on another name is not this job's box

    assert DockerContainers(docker=docker).reap("defender-run-here", TOKEN) == "removed"
    assert daemon.names() == ["defender-run-other"]
    assert not _removes(daemon.calls, "defender-run-other")


def test_o7_the_docker_seam_removes_an_owned_box_the_first_forced_removal_cannot(tmp_path):
    """A paused own box that survives `rm -f` until it has exited (#1202) still reads `removed` and is gone. (O7, r5 C1, D5-3)"""
    from defender.worker import DockerContainers

    daemon, docker = _docker_world(tmp_path)
    daemon.hold("defender-run-here", "paused", TOKEN)
    daemon.stick("defender-run-here")

    assert DockerContainers(docker=docker).reap("defender-run-here", TOKEN) == "removed"
    assert daemon.names() == []


def test_o7_a_box_that_survives_the_forced_removal_even_after_waiting_is_a_box_fault_and_stays_held(tmp_path):
    """An owned box whose `rm -f`, `wait` and second `rm -f` all fail: `reap` raises `BoxFault`, never answers `removed`, and the box is still held. (O7, r5 C1, D-u)"""
    from defender.box import BoxFault
    from defender.worker import DockerContainers

    daemon, docker = _docker_world(tmp_path)
    daemon.hold("defender-run-here", "paused", TOKEN)
    daemon.jam("defender-run-here")

    with pytest.raises(BoxFault):
        DockerContainers(docker=docker).reap("defender-run-here", TOKEN)

    assert daemon.names() == ["defender-run-here"], daemon.calls
    assert _removes(daemon.calls, "defender-run-here"), "the forced removal was never tried"


def test_o7_the_docker_seam_reads_an_absent_box_as_absent_and_removes_nothing(tmp_path):
    """No such container → `absent`, looked at, no removal, other boxes untouched. (O7, r5 C1)"""
    from defender.worker import DockerContainers

    daemon, docker = _docker_world(tmp_path)
    daemon.hold("defender-run-other", "running", TOKEN)

    assert DockerContainers(docker=docker).reap("defender-run-gone", TOKEN) == "absent"
    assert daemon.calls, "an absent container was not even looked at"
    assert not any("rm" in argv or "remove" in argv for argv in daemon.calls), daemon.calls
    assert daemon.names() == ["defender-run-other"]


#: Tokens that look like `TOKEN` to a prefix, case-folding, containment, position-skipping or
#: letter-multiset compare but are not it.
NEAR_MISS_TOKENS = {
    "another token": OTHER_TOKEN,
    "no token": None,
    "first character differs": _with(TOKEN, 0, "4"),
    "a middle character differs": _with(TOKEN, 16, "f"),
    "last character differs": TOKEN[:-1] + "c",
    "an adjacent pair swapped": TOKEN[:4] + TOKEN[5] + TOKEN[4] + TOKEN[6:],
    "a distant pair swapped": TOKEN[-1] + TOKEN[1:-1] + TOKEN[0],
    "rotated by one": TOKEN[1:] + TOKEN[0],
    "reversed": TOKEN[::-1],
    "case changed": _with(TOKEN, 1, TOKEN[1].upper()),
    "a prefix of it": TOKEN[:-1],
    "it with a suffix": TOKEN + "0",
    "it with a prefix": "0" + TOKEN,
}


def _one_character_changed(token: str, at: int) -> str:
    """`token` with the character at `at` replaced by the next hex digit, so it is still a well-formed token."""
    digits = "0123456789abcdef"
    return token[:at] + digits[(digits.index(token[at]) + 1) % 16] + token[at + 1:]


#: Tokens that are the claim's token with something added: no non-alphanumeric is ignored, nothing is trimmed.
DECORATED_TOKENS = {
    "a hyphen after it": TOKEN + "-",
    "an underscore after it": TOKEN + "_",
    "an exclamation mark after it": TOKEN + "!",
    "a hyphen before it": "-" + TOKEN,
    "an underscore before it": "_" + TOKEN,
    "a hyphen inside it": TOKEN[:16] + "-" + TOKEN[16:],
    "an underscore inside it": TOKEN[:16] + "_" + TOKEN[16:],
    "a space inside it": TOKEN[:16] + " " + TOKEN[16:],
    "a tab inside it": TOKEN[:16] + "\t" + TOKEN[16:],
}


@pytest.mark.parametrize("state", ["exited", "running", "paused"])
def test_o7_a_box_whose_token_differs_in_any_one_character_is_not_the_claims_wherever_it_differs(tmp_path, state):
    """For every position of the token, a container whose token differs from the claim's in that one character alone → `not_ours`, still held, never removed (no position is skipped). (O7, r5 C1)"""
    from defender.worker import DockerContainers

    daemon, docker = _docker_world(tmp_path)
    for at in range(len(TOKEN)):
        daemon.hold("defender-run-here", state, _one_character_changed(TOKEN, at))
        assert DockerContainers(docker=docker).reap("defender-run-here", TOKEN) == "not_ours", f"position {at}"
        assert daemon.names() == ["defender-run-here"], f"position {at}"
    assert not _removes(daemon.calls, "defender-run-here"), daemon.calls


@pytest.mark.parametrize("state", ["exited", "running", "paused"])
@pytest.mark.parametrize("holds", list(DECORATED_TOKENS))
def test_o7_a_box_whose_token_is_the_claims_with_something_added_is_not_the_claims(tmp_path, state, holds):
    """The claim's token with a hyphen, underscore, mark or whitespace added before, inside or after it is another token: `not_ours`, never removed. (O7, r5 C1)"""
    from defender.worker import DockerContainers

    daemon, docker = _docker_world(tmp_path)
    daemon.hold("defender-run-here", state, DECORATED_TOKENS[holds])

    assert DockerContainers(docker=docker).reap("defender-run-here", TOKEN) == "not_ours"
    assert daemon.names() == ["defender-run-here"]
    assert not _removes(daemon.calls, "defender-run-here"), daemon.calls


@pytest.mark.parametrize("padding", ["{} ", " {}", "{}\t", "\t{}"])
def test_o7_a_box_whose_token_is_the_claims_padded_with_whitespace_is_not_the_claims(tmp_path, padding):
    """The claim's token with whitespace before or after it is another token: `not_ours`, never removed. (O7, r5 C1)"""
    from defender.worker import DockerContainers

    daemon, docker = _docker_world(tmp_path)
    daemon.hold("defender-run-here", "running", padding.format(TOKEN))

    assert DockerContainers(docker=docker).reap("defender-run-here", TOKEN) == "not_ours"
    assert daemon.names() == ["defender-run-here"]


@pytest.mark.parametrize("state", ["exited", "running", "paused"])
@pytest.mark.parametrize("holds", list(NEAR_MISS_TOKENS))
def test_o7_the_docker_seam_leaves_a_box_that_is_not_the_claims_in_place(tmp_path, state, holds):
    """A container with another start token, a near miss of it (same prefix, case, containment) or none → `not_ours`, still held, never removed. (O7, r5 C1)"""
    from defender.worker import DockerContainers

    daemon, docker = _docker_world(tmp_path)
    daemon.hold("defender-run-here", state, NEAR_MISS_TOKENS[holds])

    assert DockerContainers(docker=docker).reap("defender-run-here", TOKEN) == "not_ours"
    assert daemon.names() == ["defender-run-here"]
    assert not _removes(daemon.calls, "defender-run-here"), daemon.calls


@pytest.mark.parametrize("held", [True, False])
def test_o7_a_daemon_that_does_not_answer_is_a_box_fault_never_absent(tmp_path, held):
    """With the daemon down the seam raises `BoxFault` (held or not) and removes nothing; it never reports `absent`. (O7, r5 C1)"""
    from defender.box import BoxFault
    from defender.worker import DockerContainers

    daemon, docker = _docker_world(tmp_path)
    if held:
        daemon.hold("defender-run-here", "running", TOKEN)
    daemon.go_down()

    with pytest.raises(BoxFault):
        DockerContainers(docker=docker).reap("defender-run-here", TOKEN)


@pytest.mark.parametrize("state", ["exited", "running", "paused"])
def test_o7_a_label_read_that_fails_while_the_box_answers_is_a_box_fault_never_absent(tmp_path, state):
    """The container answers its state but not its label: `reap` raises `BoxFault`, never `absent` or `removed`, and the box stays. (O7, r5 C1)"""
    from defender.box import BoxFault
    from defender.worker import DockerContainers

    daemon, docker = _docker_world(tmp_path)
    daemon.hold("defender-run-here", state, TOKEN)
    daemon.go_blind()

    with pytest.raises(BoxFault):
        DockerContainers(docker=docker).reap("defender-run-here", TOKEN)

    assert daemon.names() == ["defender-run-here"]
    assert not _removes(daemon.calls, "defender-run-here"), daemon.calls


@pytest.mark.parametrize("state", ["exited", "running", "paused"])
def test_o7_a_box_whose_token_label_is_set_to_nothing_is_not_the_claims_and_stays(tmp_path, state):
    """A start-token label that exists but is empty (`k=`) is no token: `not_ours`, still held, never removed. (O7, r5 C1)"""
    from defender.worker import DockerContainers

    daemon, docker = _docker_world(tmp_path)
    daemon.hold("defender-run-here", state, TOKEN)
    daemon.empty_the_label("defender-run-here")

    assert DockerContainers(docker=docker).reap("defender-run-here", TOKEN) == "not_ours"
    assert daemon.names() == ["defender-run-here"]
    assert not _removes(daemon.calls, "defender-run-here"), daemon.calls


@pytest.mark.parametrize("state", ["exited", "running"])
async def test_o7_a_worker_given_no_containers_uses_docker_and_removes_only_its_own_leftover(
        world, monkeypatch, state):
    """Omitting `containers` → the backstop is the docker one (a `docker` first on PATH): the box this claim's start stamped goes, a same-name box with another token and another run's box stay. (O7, r5 C1)"""
    from defender.worker import Worker

    daemon, _docker = _docker_world(world["tmp"])
    daemon.install(monkeypatch)
    held = daemon.home / "held"
    daemon.hold("defender-run-someone-else", "running", OTHER_TOKEN)
    own = _child(world, files=_committed(), box_dir=held, box_state=state)
    foreign = ScriptedChild(world["tmp"] / "child-foreign", world["runs"], files=_committed(), box_dir=held,
                            box_state=state, box_token="other")
    bare = ScriptedChild(world["tmp"] / "child-bare", world["runs"], files=_committed())
    async with job_store(world["dsn"]) as store:
        ids = {}
        for n, (kind, child) in enumerate((("own", own), ("foreign", foreign), ("clean", bare))):
            ids[kind] = await _queued(store, ticket=f"T-{n}", key=f"k{n}")
            await Worker(store, data_root=world["root"], child_argv=child, slots=3, clock=fixed_clock).drain()

    assert daemon.names() == sorted(["defender-run-someone-else", f"defender-run-{ids['foreign']}"]), daemon.names()
    for kind, inv in ids.items():
        assert row(world["dsn"], inv)["stage"] == "completed", kind


def test_d2_the_ratified_defaults_are_three_slots_and_a_thirty_second_grace():
    """`Worker(...)` defaults: `slots=3`, `stop_grace=30`. (O4, O7, D2)"""
    from defender.worker import Worker

    params = inspect.signature(Worker).parameters
    assert params["slots"].default == 3
    assert params["stop_grace"].default == 30


async def test_o8_the_childs_output_is_inherited_not_piped(world, capfd):
    """A child's stdout and stderr land on the worker's own descriptors. (design: child output)"""
    import anyio

    child = _child(world, files=_committed(), printed=MARKER + "x" * (1 << 20))  # well past a pipe buffer
    async with job_store(world["dsn"]) as store:
        inv = await _queued(store)
        with anyio.fail_after(60):  # a worker that pipes the output and copies it later hangs here
            await _worker(world, store, child).drain()
    stored = row(world["dsn"], inv)
    out, err = capfd.readouterr()

    assert stored["stage"] == "completed"
    assert (MARKER in out, MARKER in err) == (True, True), "the child's output did not reach the worker's stdout and stderr"
    _no_run_text(stored)


async def test_o4_serve_also_holds_three_children_and_never_a_fourth(world):
    """`serve()` with four queued rows and held children: three alive together, never four; the fourth runs once one ends. (O4, D2)"""
    import signal

    release = world["tmp"] / "release"
    child = _child(world, files=_committed(), wait_for=release)
    async with job_store(world["dsn"]) as store:
        ids = [await _queued(store, ticket=f"T-{n}", key=f"k{n}") for n in range(4)]
        serving = asyncio.create_task(_worker(world, store, child, slots=3).serve())
        try:
            for _ in range(1500):
                if len(child.seen_all()) >= 3:
                    break
                await asyncio.sleep(0.01)
            await asyncio.sleep(1.0)  # a fourth would have started by now
            assert len(child.seen_all()) == 3, "serve did not hold the slot cap"
            assert child.max_alive() == 3
            release.touch()
            for _ in range(3000):
                if [row(world["dsn"], i)["stage"] for i in ids] == ["completed"] * 4:
                    break
                await asyncio.sleep(0.02)
        finally:
            release.touch()
            assert not serving.done(), "premise: serve() is still running, so the SIGTERM below is its to handle"
            os.kill(os.getpid(), signal.SIGTERM)
            await asyncio.wait_for(serving, timeout=60)

    assert child.max_alive() == 3, "a fourth child overlapped the three"
    assert [row(world["dsn"], i)["stage"] for i in ids] == ["completed"] * 4


class _StoreWhoseAlertReadFails:
    """The real store, except that reading one alert raises an error nobody planned for."""

    def __init__(self, store, alert_id: str, fault: Exception) -> None:
        self._store, self._alert_id, self._fault = store, alert_id, fault

    def __getattr__(self, name):
        return getattr(self._store, name)

    async def get_alert(self, tenant_id, alert_id):
        if alert_id == self._alert_id:
            raise self._fault
        return await self._store.get_alert(tenant_id, alert_id)


class _LaneFailing:
    """The real job lane, except that `method` raises `fault` for run `inv`; with `method="close"`,
    closing the lane that read that run's ending raises, after it really closed."""

    def __init__(self, lane, inv: str, method: str, fault: Exception) -> None:
        self._lane, self._inv, self._method, self._fault = lane, inv, method, fault
        self._read_inv = False

    def __getattr__(self, name):
        real = getattr(self._lane, name)
        if not callable(real) or name == "close":
            return real

        def call(*args, **kwargs):
            if args and str(args[0]) == self._inv:
                self._read_inv = self._read_inv or name == "read_job_end"
                if name == self._method:
                    raise self._fault
            return real(*args, **kwargs)
        return call

    def close(self) -> None:
        self._lane.close()
        if self._method == "close" and self._read_inv:
            raise self._fault

    def __enter__(self):
        return self

    def __exit__(self, *_exc) -> None:
        self.close()


def _lanes_failing(inv: str, method: str, fault: Exception):
    """A job-lane door whose lanes fault as `_LaneFailing` says."""
    from defender.records import job_lane

    return lambda root, tenant: _LaneFailing(job_lane.JobLane.open(root, tenant), inv, method, fault)


class _NobodyPlannedThis(Exception):  # noqa: N818 — derives directly from Exception, in no list of expected faults
    """A fault type no handler in the worker can know by name."""


@pytest.mark.parametrize("fault_type", [RuntimeError, KeyError, TypeError, AssertionError, AttributeError,
                                        IndexError, _NobodyPlannedThis])
@pytest.mark.parametrize("seam", ["child-argv", "store-read", "job-end-read"])
async def test_o6_an_unexpected_fault_at_any_seam_ends_that_row_worker_error_and_the_worker_goes_on(
        world, seam, fault_type):
    """A fault of any kind nobody planned for (not an OS error) in one row's task: that row `failed`/`worker_error`, another row still completes. (O6, design flows)"""
    fault = fault_type("a seam fell over")
    child = _child(world, files=_committed())
    async with job_store(world["dsn"]) as store:
        bad = await _queued(store, ticket="T-1", key="k1")
        good = await _queued(store, ticket="T-2", key="k2")
        used = store
        argv = child
        lanes = None
        if seam == "child-argv":
            def argv(launch):  # noqa: F811
                if launch.investigation_id == bad:
                    raise fault
                return child(launch)
        elif seam == "store-read":
            used = _StoreWhoseAlertReadFails(store, (await store.get_investigation(T1, bad)).alert_id, fault)
        else:
            lanes = _lanes_failing(bad, "read_job_end", fault)
        await _worker(world, used, argv, open_lane=lanes).drain()

    stored = row(world["dsn"], bad)
    assert (stored["stage"], stored["failure_reason"]) == ("failed", "worker_error")
    assert stored["failure_message"]
    assert stored["finished_at"] == NOW
    assert row(world["dsn"], good)["stage"] == "completed", "one row's fault stopped the others"


@pytest.mark.parametrize("fault_type", [RuntimeError, KeyError, TypeError, AssertionError, AttributeError,
                                        IndexError, _NobodyPlannedThis])
@pytest.mark.parametrize("seam", ["report-disposition", "lane-cost", "lane-knowledge", "lane-close"])
async def test_1396_an_unexpected_fault_after_the_ending_is_decided_keeps_that_ending(
        world, caplog, seam, fault_type):
    """A fault nobody planned for once the host committed a report and the scrub walked the tree:
    reading the report's disposition ends the row `unparseable`, as an unreadable disposition
    does; reading cost or knowledge, or closing the lane, keeps the decided stage and disposition,
    and the value that could not be read is unknown (cost null; knowledge the unreadable shape,
    never "no run"). Never `worker_error`; the fault is logged as an error, and another row still
    completes. (#1396)"""
    caplog.set_level(logging.INFO, logger=WORKER_LOGGER)
    fault = fault_type("a seam fell over")
    child = _child(world, files=_committed())
    async with job_store(world["dsn"]) as store:
        bad = await _queued(store, ticket="T-1", key="k1")
        good = await _queued(store, ticket="T-2", key="k2")
        method = {"report-disposition": "report_disposition", "lane-cost": "cost",
                  "lane-knowledge": "knowledge", "lane-close": "close"}[seam]
        await _worker(world, store, child, open_lane=_lanes_failing(bad, method, fault)).drain()

    stored = row(world["dsn"], bad)
    assert (stored["stage"], stored["disposition"], stored["failure_reason"]) == (
        ("unparseable", None, None) if seam == "report-disposition" else ("completed", "inconclusive", None))
    assert stored["cost_usd"] == (None if seam == "lane-cost" else 0)
    assert stored["knowledge"] == (STALE_OPERATOR if seam == "lane-knowledge" else _knowledge("current", COMMIT))
    assert any(bad in r.getMessage() and r.levelno >= logging.ERROR for r in caplog.records
               if r.name.startswith(WORKER_LOGGER)), "a fault nobody planned for was not logged as an error"
    assert row(world["dsn"], good)["stage"] == "completed", "one row's fault stopped the others"


class _StoreWhoseFinishFails:
    """The real store, except that one row's first `fails` finishes raise, and every finish is noted. With `commit`, each failing finish first writes, then loses its answer; with `alert_missing`, that row's alert reads as absent."""

    def __init__(self, store, inv: str, fault: Exception, *, fails: int, commit: bool = False,
                 alert_missing: bool = False) -> None:
        self._store, self._inv, self._fault = store, inv, fault
        self._fails, self._commit, self._alert_missing = fails, commit, alert_missing
        self.finishes: list[tuple[str, dict]] = []
        self.at: list[tuple[str, float]] = []

    def __getattr__(self, name):
        return getattr(self._store, name)

    async def get_alert(self, tenant_id, alert_id):
        if self._alert_missing and alert_id == (await self._store.get_investigation(tenant_id, self._inv)).alert_id:
            return None
        return await self._store.get_alert(tenant_id, alert_id)

    async def finish(self, tenant_id, investigation_id, **kw):
        self.finishes.append((investigation_id, kw))
        self.at.append((investigation_id, time.monotonic()))
        if investigation_id == self._inv and self._fails > 0:
            self._fails -= 1
            if self._commit:
                await self._store.finish(tenant_id, investigation_id, **kw)
            raise self._fault
        return await self._store.finish(tenant_id, investigation_id, **kw)

    def tries(self, inv: str) -> list[tuple]:
        return [(kw["stage"], kw["failure_reason"], kw["cost_usd"]) for i, kw in self.finishes if i == inv]

    def gaps(self, inv: str) -> list[float]:
        times = [t for i, t in self.at if i == inv]
        return [b - a for a, b in zip(times, times[1:], strict=False)]


async def _run_with_failing_finish(world, fault, **kw) -> tuple[str, str, _StoreWhoseFinishFails]:
    child = _child(world, files=_committed())
    async with job_store(world["dsn"]) as store:
        bad = await _queued(store, ticket="T-1", key="k1")
        good = await _queued(store, ticket="T-2", key="k2")
        used = _StoreWhoseFinishFails(store, bad, fault, **kw)
        await _worker(world, used, child).drain()
    assert row(world["dsn"], good)["stage"] == "completed", "one row's failed finish stopped the others"
    return bad, good, used


_OUTAGES = ["connection-error", "os-error", "operational", "interface", "pool-timeout", "invalidated"]


def _outage(kind: str) -> Exception:
    """An environment fault (r5 item 13): the database could not be reached or answered transiently."""
    from sqlalchemy.exc import DBAPIError, InterfaceError, OperationalError
    from sqlalchemy.exc import TimeoutError as PoolTimeout

    sql, gone = "UPDATE jobs.investigations", Exception("server closed the connection unexpectedly")
    return {"connection-error": lambda: ConnectionError("the database is gone"),
            "os-error": lambda: OSError("network is unreachable"),
            "operational": lambda: OperationalError(sql, {}, gone),
            "interface": lambda: InterfaceError(sql, {}, gone),
            "invalidated": lambda: DBAPIError(sql, {}, gone, connection_invalidated=True),
            "pool-timeout": lambda: PoolTimeout("QueuePool limit of size 10 overflow 10 reached")}[kind]()


def _data_fault(kind: str) -> Exception:
    """A fault of another class (r5 item 13): a bug of ours, or a value the schema refuses; waiting never cures it."""
    from sqlalchemy.exc import DataError, IntegrityError, ProgrammingError

    sql, refused = "UPDATE jobs.investigations", Exception("refused")
    return {"runtime": RuntimeError("a bug"), "unplanned": _NobodyPlannedThis("a bug"),
            "data": DataError(sql, {}, Exception("value too long")),
            "integrity": IntegrityError(sql, {}, refused),
            "programming": ProgrammingError(sql, {}, refused)}[kind]


@pytest.mark.parametrize("kind", _OUTAGES)
async def test_o6_a_decided_ending_whose_write_fails_once_as_an_outage_is_written_again_unchanged(world, kind):
    """CONFLICT-UPDATED (#1343 B5, r5 item 7; was any fault type): the decided ending fails without committing and is written again, never another verdict. (#1378, B5)"""
    bad, _, used = await _run_with_failing_finish(world, _outage(kind), fails=1)

    tries = used.tries(bad)
    assert [t[:2] for t in tries] == [("completed", None)] * 2, "the decided ending was replaced"
    assert tries[0] == tries[1]
    assert row(world["dsn"], bad)["stage"] == "completed"


async def test_o6_a_decided_ending_whose_write_keeps_failing_as_an_outage_is_retried_each_second_until_it_lands(world):
    """CONFLICT-UPDATED (#1343 B5; replaces #1393's three bounded tries): four failures then success is five tries about a second apart, the same ending each time, and `drain()` waits for it. (B5, r5 item 10)"""
    bad, good, used = await _run_with_failing_finish(world, _outage("connection-error"), fails=4)

    assert [t[0] for t in used.tries(bad)] == ["completed"] * 5
    assert all(0.5 <= gap <= 2.5 for gap in used.gaps(bad)), f"not retried about each second: {used.gaps(bad)}"
    assert (row(world["dsn"], bad)["stage"], row(world["dsn"], good)["stage"]) == ("completed", "completed")


@pytest.mark.parametrize("kind", ["runtime", "unplanned", "data", "integrity", "programming"])
async def test_o6_a_decided_ending_whose_write_fails_with_a_non_outage_error_is_logged_dropped_and_the_row_lapses_into_a_retry(
        world, caplog, kind):
    """A fault that is not a connection fault is tried once and logged loudly; the row leaves the held set, its lease lapses, a take-over fails it `lease_lapsed` and its retry runs. (B5, r5 item 7)"""
    child = _child(world, files=_committed())
    dsn = world["dsn"]
    async with job_store(dsn, lease=1.0) as store:
        bad = await _queued(store, ticket="T-1", key="k1")
        used = _StoreWhoseFinishFails(store, bad, _data_fault(kind), fails=99)
        serving = asyncio.create_task(_worker(world, used, child, **_FAST).serve())
        try:
            await _until(lambda: used.tries(bad), "the first end write")
            await _until(lambda: row(dsn, bad)["failure_reason"] == "lease_lapsed", "the dropped row's lease to lapse", timeout=15)
            await _until(lambda: execute(dsn, "SELECT stage FROM jobs.investigations WHERE request_key = 'k1' "
                                               "AND attempt = 2") == [("completed",)], "the retry to run", timeout=20)
        finally:
            if not serving.done():
                os.kill(os.getpid(), signal.SIGTERM)
            await asyncio.wait_for(serving, timeout=60)

    assert [t[0] for t in used.tries(bad)] == ["completed"], "a non-outage fault was retried"
    assert any(r.levelno >= logging.ERROR and bad in r.getMessage() for r in caplog.records
               if r.name.startswith(WORKER_LOGGER)), "the dropped ending was not logged loudly"


async def test_o6_a_decided_ending_that_committed_but_lost_its_answer_is_not_changed_by_the_retry(world):
    """The first write commits and only its answer is lost: the retry changes nothing, the row keeps that ending. (#1378)"""
    bad, _, used = await _run_with_failing_finish(world, ConnectionError("the answer was lost"), fails=1, commit=True)

    assert [t[0] for t in used.tries(bad)] == ["completed", "completed"]
    stored = row(world["dsn"], bad)
    assert (stored["stage"], stored["failure_reason"]) == ("completed", None)


@pytest.mark.parametrize("path", ["worker-fault", "catch-all"])
async def test_o6_a_worker_error_ending_whose_write_fails_as_an_outage_is_retried_unchanged_until_it_lands(world, path):
    """CONFLICT-UPDATED (#1343 B5; was bounded to FINISH_ATTEMPTS): a `failed`/`worker_error` ending whose write fails four times is written a fifth time with the same values and lands; no other ending is written. (B5, #1378)"""
    child = _child(world, files=_committed())
    async with job_store(world["dsn"]) as store:
        bad = await _queued(store, ticket="T-1", key="k1")
        if path == "worker-fault":
            used = _StoreWhoseFinishFails(store, bad, ConnectionError("dropped"), fails=4, alert_missing=True)
        else:
            alert_id = (await store.get_investigation(T1, bad)).alert_id
            used = _StoreWhoseFinishFails(_StoreWhoseAlertReadFails(store, alert_id, _NobodyPlannedThis("x")),
                                          bad, ConnectionError("dropped"), fails=4)
        await _worker(world, used, child).drain()

    expect_cost = 0.0 if path == "worker-fault" else None
    assert used.tries(bad) == [("failed", "worker_error", expect_cost)] * 5
    stored = row(world["dsn"], bad)
    assert (stored["stage"], stored["failure_reason"]) == ("failed", "worker_error")
    assert child.seen(bad) is None, "a child started for a row that failed before its launch"


# --- M1: what the worker reads, and where ------------------------------------------------------------

OVER_THE_LIMIT = 70 * 1024 * 1024


def _tampered(world: dict, which: str, shape: str) -> tuple[dict[str, str], dict]:
    """Host records with `which` replaced by a symlink to a valid copy, or by a valid copy padded past
    any size limit; returns the child's files and its extra spec."""
    name = {"job-end": "{id}.job-end.json", "knowledge": "{id}.knowledge-source.json",
            "pointer": "{id}.session-pointer.json"}[which]
    text = {"job-end": job_end(), "knowledge": knowledge_record(COMMIT), "pointer": session_pointer(CASE)}[which]
    files = _committed(**{name: None})
    if shape == "symlinked":
        target = world["tmp"] / "elsewhere" / "record.json"
        target.parent.mkdir()
        target.write_text(text, encoding="utf-8")
        return files, {"links": {name: str(target)}}
    return files, {"padded": {name: (text, OVER_THE_LIMIT)}}


@pytest.mark.parametrize("shape", ["symlinked", "oversize"])
@pytest.mark.parametrize("which", ["job-end", "knowledge", "pointer"])
async def test_m1_a_symlinked_or_oversize_host_record_is_unreadable_not_followed_or_swallowed(
        world, caplog, which, shape):
    """The job-end record, knowledge record and session pointer are read no-follow and size-limited: tampered, each counts as unreadable. (M1, D-f, R3, O8)"""
    caplog.set_level(logging.INFO, logger=WORKER_LOGGER)
    plant_sessions(world["runs"], CASE, [("main", "claude-sonnet-4-6", {"input_tokens": 1_000_000})])
    files, extra = _tampered(world, which, shape)
    child = _child(world, files=files, exit=EXIT, **extra)
    inv, stored = await _run_one(world, child)

    if which == "job-end":  # unreadable = absent: rule 1
        assert (stored["stage"], stored["failure_reason"]) == ("failed", "no_report")
        assert _names_code(stored, inv, EXIT), stored["failure_message"]
    else:
        assert (stored["stage"], stored["disposition"]) == ("completed", "inconclusive")
    if which == "knowledge":
        assert stored["knowledge"] == STALE_OPERATOR
    if which == "pointer":
        assert stored["cost_usd"] is None
        assert _warned(caplog, inv)


@pytest.mark.parametrize("linked", ["tenant folder", "runs container"])
async def test_m1_a_symlinked_tenant_folder_or_runs_container_is_refused_and_nothing_is_written(world, linked):
    """`<root>/<T>` or `<root>/<T>/runs` a symlink: `failed`/`worker_error`, no child, nothing written anywhere. (M1, O6)"""
    real = world["tmp"] / "real"
    if linked == "tenant folder":
        (world["root"] / T1).rename(real)
        (world["root"] / T1).symlink_to(real)
    else:
        world["runs"].rename(real)
        world["runs"].symlink_to(real)
    before, before_real = tree(world["root"]), tree(real)
    child = _child(world, files=_committed())
    inv, stored = await _run_one(world, child)

    assert (stored["stage"], stored["failure_reason"]) == ("failed", "worker_error")
    assert stored["failure_message"]
    assert child.seen() is None, "a child started through a symlinked path"
    assert tree(real) == before_real, f"the worker wrote through the symlink for {inv}"
    assert tree(world["root"]) == before


@pytest.mark.parametrize("present", [".launch.json"])
async def test_m1_a_symlink_where_the_launch_record_goes_is_not_written_through(world, present):
    """A symlink planted at the launch record's name is refused: its target is never created; `failed`/`worker_error`, no child. (M1, O6)"""
    inv = str(uuid.uuid4())
    target = world["tmp"] / "elsewhere" / "target"
    target.parent.mkdir()
    (world["runs"] / f"{inv}{present}").symlink_to(target)
    child = _child(world, files=_committed())
    async with job_store(world["dsn"]) as store:
        alert = await an_alert(store, T1)
        plant_queued_investigation(world["dsn"], tenant=T1, alert_id=alert.alert_id, investigation_id=inv)
        await _worker(world, store, child).drain()

    stored = row(world["dsn"], inv)
    assert (stored["stage"], stored["failure_reason"]) == ("failed", "worker_error")
    assert not target.exists(), "the worker wrote through a planted symlink"
    assert child.seen() is None


@pytest.mark.parametrize("target_exists", [False, True], ids=["target-absent", "target-present"])
async def test_m1_a_symlink_where_the_alert_file_goes_is_refused_not_written_through(world, target_exists):
    """A symlink at `<id>.alert.json` is a non-plain entry and is refused (D-af, M1): the row ends `failed`/`worker_error`, no child starts, the link is still a link, and its target is neither created nor changed. (M1, O6, D-af)"""
    inv = str(uuid.uuid4())
    target = world["tmp"] / "elsewhere" / "target"
    target.parent.mkdir()
    if target_exists:
        target.write_bytes(b"not ours")
    link = world["runs"] / f"{inv}.alert.json"
    link.symlink_to(target)
    child = _child(world, files=_committed())
    async with job_store(world["dsn"]) as store:
        alert = await an_alert(store, T1)
        plant_queued_investigation(world["dsn"], tenant=T1, alert_id=alert.alert_id, investigation_id=inv)
        await _worker(world, store, child).drain()

    stored = row(world["dsn"], inv)
    assert (stored["stage"], stored["failure_reason"]) == ("failed", "worker_error")
    assert child.seen() is None, "a child started although the alert file could not be written"
    assert link.is_symlink(), "the link was replaced"
    assert link.readlink() == target, "the link was changed"
    if target_exists:
        assert target.read_bytes() == b"not ours", "the worker wrote through the alert-file link"
    else:
        assert not target.exists(), "the worker created the link's target"


async def test_o8_the_childs_stdout_and_stderr_are_the_workers_own_descriptors(world, capfd):
    """The child's fd 1 and fd 2 are open on what the worker's are (not a pipe the worker reads). (design: child output)"""
    child = _child(world, files=_committed(), printed=MARKER)
    await _run_one(world, child)

    seen = child.seen()
    assert seen is not None
    assert seen["stdio"] == [fd_identity(1), fd_identity(2)], "the child's output does not go straight to the worker's descriptors"


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



# --- the box token is minted per claim; one loop owns every child (r5 C1, drain()/serve()) -------------------

async def _until(condition, what: str, *, timeout: float = 30.0) -> None:
    for _ in range(int(timeout / 0.02)):
        if condition():
            return
        await asyncio.sleep(0.02)
    raise AssertionError(f"timed out waiting for {what}")


def _gone(pid: int) -> bool:
    """Dead: no such process, or one that has exited and only awaits its parent's wait (a killed grandchild is reparented, and may stay a zombie)."""
    if not Path("/proc/self/status").exists():  # no /proc here: signal 0 says whether the pid is still there
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        except PermissionError:
            return False
        return False
    try:
        status = Path(f"/proc/{pid}/status").read_text(encoding="utf-8")
    except (FileNotFoundError, ProcessLookupError):  # ESRCH: it exited while its status was being read
        return True
    return "\nState:\tZ" in status


async def test_o7_the_same_id_claimed_twice_by_one_worker_gets_two_different_tokens_neither_a_function_of_the_id(world):
    """The box token is minted fresh at each claim, not once per worker: ONE worker claiming the same id again (rows and files cleared between) writes another token, and neither is a hash or the hex of the id. (O7, r5 C1)"""
    inv = str(uuid.uuid4())
    tokens: list[str] = []
    async with job_store(world["dsn"]) as store:
        alert = await an_alert(store, T1)
        worker = _worker(world, store, ScriptedChild(world["tmp"] / "child", world["runs"], files=_committed()))
        for _ in range(3):
            plant_queued_investigation(world["dsn"], tenant=T1, alert_id=alert.alert_id, investigation_id=inv)
            await worker.drain()
            assert row(world["dsn"], inv)["stage"] == "completed", "premise: the claim ran"
            tokens.append(_claim_token(world, inv))
            execute(world["dsn"], "DELETE FROM jobs.investigations WHERE id = %s", (inv,))
            for path in world["runs"].glob(f"{inv}*"):
                shutil.rmtree(path) if path.is_dir() else path.unlink()

    for token in tokens:
        assert is_box_token(token), token
    assert len(set(tokens)) == 3, f"one worker minted a repeat for one id: {tokens}"
    derived = {uuid.UUID(inv).hex, inv.replace("-", ""), *(getattr(hashlib, h)(inv.encode()).hexdigest()[:32]
                                                         for h in ("sha256", "sha1", "md5", "sha512"))}
    assert not set(tokens) & derived, "the token is derived from the id"


async def test_o7_one_worker_claiming_two_ids_gets_two_different_tokens(world):
    """Two rows claimed by one worker carry two different tokens (a token per worker would pass the per-id test and fail here). (O7, r5 C1)"""
    async with job_store(world["dsn"]) as store:
        ids = [await _queued(store, ticket=f"T-{n}", key=f"k{n}") for n in range(3)]
        await _worker(world, store, _child(world, files=_committed())).drain()

    tokens = [_claim_token(world, i) for i in ids]
    assert all(is_box_token(t) for t in tokens), tokens
    assert len(set(tokens)) == 3, f"rows claimed by one worker share a token: {tokens}"


class _StoreWhoseClaimFails:
    """The real store, except that each claim numbered in `faults` (1-based) first waits for `until()`, then raises that fault."""

    def __init__(self, store, *, faults: dict[int, Exception], until=lambda: True) -> None:
        self._store, self._faults, self._until, self.calls = store, faults, until, 0

    def __getattr__(self, name):
        return getattr(self._store, name)

    async def claim(self):
        self.calls += 1
        if self.calls in self._faults:
            await _until(self._until, "the cue for the claim fault")
            raise self._faults[self.calls]
        return await self._store.claim()


@contextlib.asynccontextmanager
async def _a_drain_that_lost_its_store_with_children_running(world, *, children: int = 2):
    """`children` rows claimed and each child holding a box stamped with its claim's token, then the next claim raises: yields what is left once `drain()` has raised."""
    containers = StandInContainers(world["tmp"] / "containers")
    release = world["tmp"] / "release"
    child = _child(world, files=_committed(), box_dir=containers.where, wait_for=release)
    async with job_store(world["dsn"]) as store:
        ids = [await _queued(store, ticket=f"T-{n}", key=f"k{n}") for n in range(children)]
        names = [f"defender-run-{i}" for i in ids]
        failing = _StoreWhoseClaimFails(store, faults={children + 1: _NobodyPlannedThis("the store fell over")},
                                        until=lambda: all(containers.held(n) for n in names))
        worker = _worker(world, failing, child, containers=containers)
        try:
            with pytest.raises(_NobodyPlannedThis):
                await asyncio.wait_for(worker.drain(), timeout=30)
            yield SimpleNamespace(ids=ids, names=names, containers=containers, child=child)
        finally:
            release.touch()


async def test_o4_a_store_fault_in_drain_ends_every_running_child_reaps_every_box_and_hands_every_row_back(world):
    """CONFLICT-UPDATED (#1343 B11 `_abandon` is a stop): `drain()` leaving by a store fault with two children running: both are dead, both boxes (each under its claim's token) removed, and each row is handed back, not given a stage. (O4, D3, D-w)"""
    async with _a_drain_that_lost_its_store_with_children_running(world) as left:
        for inv, name in zip(left.ids, left.names, strict=True):
            assert _gone(left.child.seen(inv)["pid"]), f"the fault left {inv}'s child running"
            assert not left.containers.held(name), f"the fault left {inv}'s box behind"
            assert set(left.containers.reaped(name)) == {_claim_token(world, inv)}
            _handed_back(world["dsn"], inv)


async def test_o7_a_drain_cancelled_while_two_children_run_ends_both_and_reaps_both_boxes(world):
    """`drain()` cancelled with two children running: both are dead and both boxes (each under its claim's token) removed, the rows handed back. (O7, B11 `_abandon`)"""
    containers = StandInContainers(world["tmp"] / "containers")
    release = world["tmp"] / "release"
    child = _child(world, files=_committed(), box_dir=containers.where, wait_for=release)
    async with job_store(world["dsn"]) as store:
        ids = [await _queued(store, ticket=f"T-{n}", key=f"k{n}") for n in range(2)]
        names = [f"defender-run-{i}" for i in ids]
        draining = asyncio.create_task(_worker(world, store, child, containers=containers).drain())
        try:
            await _until(lambda: all(containers.held(n) for n in names), "both children's boxes")
            draining.cancel()
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(draining, timeout=30)
        finally:
            release.touch()

        for inv, name in zip(ids, names, strict=True):
            assert _gone(child.seen(inv)["pid"]), f"the cancelled drain left {inv}'s child running"
            assert not containers.held(name), f"the cancelled drain left {inv}'s box behind"
            assert set(containers.reaped(name)) == {_claim_token(world, inv)}
            _handed_back(world["dsn"], inv)


async def test_o7_a_drain_cancelled_while_a_child_that_ignores_sigterm_runs_still_reaps_its_box(world):
    """A cancelled drain whose child ignores SIGTERM: the child is group-killed after `stop_grace`, and its box is reaped all the same, the row handed back. (O7, D3, B11)"""
    containers = StandInContainers(world["tmp"] / "containers")
    release = world["tmp"] / "release"
    child = _child(world, files=_committed(), box_dir=containers.where, wait_for=release, term="ignore")
    async with job_store(world["dsn"]) as store:
        inv = await _queued(store)
        name = f"defender-run-{inv}"
        worker = _worker(world, store, child, containers=containers, stop_grace=0.5)
        draining = asyncio.create_task(worker.drain())
        try:
            await _until(lambda: containers.held(name), "the child's box")
            draining.cancel()
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(draining, timeout=30)
        finally:
            release.touch()

        assert _gone(child.seen(inv)["pid"]), "the cancelled drain left the child running"
        assert not containers.held(name), "the box of a child that had to be killed was left behind"
        assert set(containers.reaped(name)) == {_claim_token(world, inv)}
        _handed_back(world["dsn"], inv)


#: Claim faults of different kinds, in a row: an OSError family one is no more fatal than any other.
CLAIM_FAULTS = [ConnectionError("the store went away"), OSError("the socket broke"),
                _NobodyPlannedThis("the store blinked"), ConnectionResetError("reset by peer")]


async def test_o4_serve_waits_out_consecutive_claim_faults_of_any_kind_and_still_runs_the_next_row(world):
    """Four claim faults in a row (connection, OS and other errors) while serving: each is retried, none ends `serve()`, and the queued row behind them still runs. (O4, D-p, D-w)"""
    import signal

    async with job_store(world["dsn"]) as store:
        inv = await _queued(store)
        failing = _StoreWhoseClaimFails(store, faults=dict(enumerate(CLAIM_FAULTS, start=1)))
        serving = asyncio.create_task(_worker(world, failing, _child(world, files=_committed())).serve())
        try:
            for _ in range(6000):  # up to 120 s: the faults are waited out at the poll interval
                if row(world["dsn"], inv)["stage"] == "completed" or serving.done():
                    break
                await asyncio.sleep(0.02)
            assert not serving.done(), f"serve() ended on a claim fault (claim {failing.calls}): {serving}"
            assert row(world["dsn"], inv)["stage"] == "completed", "the row behind the claim faults never ran"
            assert failing.calls > len(CLAIM_FAULTS)
        finally:
            if not serving.done():
                os.kill(os.getpid(), signal.SIGTERM)
            await asyncio.wait_for(asyncio.gather(serving, return_exceptions=True), timeout=60)


class _StoreWhoseClaimAlwaysFails:
    """The real store, except that every claim raises (after yielding once, as a real round trip does) and is counted."""

    def __init__(self, store, fault: Exception) -> None:
        self._store, self._fault, self.calls = store, fault, 0

    def __getattr__(self, name):
        return getattr(self._store, name)

    async def claim(self):
        self.calls += 1
        await asyncio.sleep(0)
        raise self._fault


async def test_o4_serve_over_a_persistent_claim_fault_polls_at_an_interval_not_in_a_hot_loop(world, caplog):
    """A store whose claim always raises while serving for 1.5 s: the claim is retried on the poll wait (D-p, M10), not again at once, so it is asked a handful of times, nowhere near as often as a loop with no wait would. (O4, D-p, D-w)"""
    import signal

    caplog.set_level(logging.CRITICAL, logger=WORKER_LOGGER)  # the retry's own log lines are not under test
    async with job_store(world["dsn"]) as store:
        failing = _StoreWhoseClaimAlwaysFails(store, _NobodyPlannedThis("the store is down"))
        serving = asyncio.create_task(_worker(world, failing, _child(world, files=_committed())).serve())
        try:
            await asyncio.sleep(1.5)
            asked = failing.calls
            assert not serving.done(), f"serve() ended on a claim fault: {serving}"
        finally:
            if not serving.done():
                os.kill(os.getpid(), signal.SIGTERM)
            await asyncio.wait_for(asyncio.gather(serving, return_exceptions=True), timeout=60)

    assert 1 <= asked <= 100, f"the claim was asked {asked} times in 1.5 s: a fault is waited out at the poll interval"


async def test_o4_a_drain_whose_first_claim_faults_raises_it_though_no_child_runs(world):
    """`drain()` over a store whose first claim raises, with no child running: it raises that fault (D-w), it does not read it as an empty queue; the queued row is left queued. (O4, D-w)"""
    async with job_store(world["dsn"]) as store:
        inv = await _queued(store)
        failing = _StoreWhoseClaimFails(store, faults={1: _NobodyPlannedThis("the store fell over")})
        with pytest.raises(_NobodyPlannedThis):
            await asyncio.wait_for(_worker(world, failing, _child(world, files=_committed())).drain(), timeout=30)

    assert row(world["dsn"], inv)["stage"] == "queued"


async def test_d3_a_child_that_ignores_sigterm_is_group_killed_after_the_stop_grace_not_a_longer_time(world):
    """A cancelled drain over a child that ignores SIGTERM with a 0.2 s `stop_grace`: the child's group is dead well before 2 s after the cancel (the grace is not stretched). (D3, M8)"""
    containers = StandInContainers(world["tmp"] / "containers")
    release = world["tmp"] / "release"
    child = _child(world, files=_committed(), box_dir=containers.where, wait_for=release, term="ignore", grandchild=True)
    async with job_store(world["dsn"]) as store:
        inv = await _queued(store)
        name = f"defender-run-{inv}"
        draining = asyncio.create_task(_worker(world, store, child, containers=containers, stop_grace=0.2).drain())
        try:
            await _until(lambda: containers.held(name) and (child.seen(inv) or {}).get("grandchild"), "the child and its grandchild")
            started = time.monotonic()
            draining.cancel()
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(draining, timeout=30)
            took = time.monotonic() - started
            seen = child.seen(inv)
            gone = _gone(seen["pid"]) and _gone(seen["grandchild"])
        finally:
            release.touch()

    assert gone, "the child's group was left running"
    assert took < 1.5, f"a 0.2 s stop_grace took {took:.2f} s to end a child that ignores SIGTERM"


def _still_running(seen: dict | None, *, grandchild: bool) -> list[str]:
    """Which of the child and (when asked) its grandchild are alive, from what the child wrote about itself."""
    if seen is None:
        return []
    alive = []
    if not _gone(seen["pid"]):
        alive.append("the child")
    if grandchild and seen.get("grandchild") and not _gone(seen["grandchild"]):
        alive.append("the child's grandchild")
    return alive


def _kill_whatever_remains(seen: dict | None) -> None:
    """Whatever the worker did, nothing outlives the test."""
    import signal

    for pid in (seen or {}).get("pid"), (seen or {}).get("grandchild"):
        if pid and not _gone(pid):
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.killpg(pid, signal.SIGKILL)


async def _serve_with_a_stop_landing_while_the_child_is_spawned(world, monkeypatch, child, *, stop_grace=None):
    """Serves one queued row with SIGTERM sent to this process just before the real spawn is awaited,
    and the spawn handed back to the worker only once the child is up (it has written what it saw, so
    its SIGTERM disposition is set) and the loop has had time to act on the stop: the stop is under
    way, and has not met the child, when the worker takes hold of it.

    A worker that stops by cancelling the row's task has the cancel land in the wrapper's wait. As
    asyncio's own spawn does once the child exists, the wrapper then keeps waiting for the child to
    be up, re-raises the cancel at the worker's next await (`current_task().cancel()`) and hands the
    child back, so the worker holds a child it must end itself; the wrapper kills nothing. A cancel
    that lands inside the real spawn propagates as it would from asyncio's. Returns the row's id and
    stage, whether the cancel landed inside the spawn, and what was still running when serve() returned."""
    import signal

    real_spawn = asyncio.create_subprocess_exec
    landed_in_spawn = False

    async def spawn_while_stopping(*argv, **kw):
        nonlocal landed_in_spawn
        assert not serving.done()
        os.kill(os.getpid(), signal.SIGTERM)
        landed_in_spawn = True  # until the real spawn has returned
        proc = await real_spawn(*argv, **kw)
        landed_in_spawn = False
        arrived = child.seen_dir / f"{argv[argv.index('--job') + 1]}.json"
        cancelled = False
        while True:
            try:
                await _until(arrived.exists, "the spawned child to be up")
                await asyncio.sleep(0.05)  # the loop acts on the stop meanwhile: its snapshot of children cannot include this one
                break
            except asyncio.CancelledError:  # the worker stops by cancelling the row's task: the child exists, so wait for it, then hand the cancel on
                cancelled = True
        if cancelled:
            asyncio.current_task().cancel()
        return proc

    monkeypatch.setattr(asyncio, "create_subprocess_exec", spawn_while_stopping)  # lint-monkeypatch: ok — the only point where a stop can land between a child's spawn and the worker holding it; the real spawn runs
    async with job_store(world["dsn"]) as store:
        inv = await _queued(store)
        serving = asyncio.create_task(_worker(world, store, child, stop_grace=stop_grace).serve())
        left_running: list[str] = []
        try:
            await asyncio.wait_for(asyncio.shield(serving), timeout=20)
            left_running = _still_running(child.seen(inv), grandchild=not landed_in_spawn)  # at the moment serve() returned, before the child is released
        finally:
            (world["tmp"] / "release").touch()
            await asyncio.wait_for(asyncio.gather(serving, return_exceptions=True), timeout=60)
            _kill_whatever_remains(child.seen(inv))
        return SimpleNamespace(inv=inv, stage=row(world["dsn"], inv)["stage"], in_spawn=landed_in_spawn,
                               left_running=left_running)


async def test_d3_a_child_spawned_while_the_stop_is_under_way_is_ended_not_left_running(world, monkeypatch):
    """A SIGTERM that lands while a row's child is being spawned: the child is ended with the rest, not left running for its own length (however the worker stops its rows). (D3, r5 one loop owns every child)"""
    child = _child(world, files=_committed(), wait_for=world["tmp"] / "release")
    done = await _serve_with_a_stop_landing_while_the_child_is_spawned(world, monkeypatch, child)

    assert not done.left_running, "the child ran on after the stop"
    assert ("end", done.inv) not in child.events(), "the child ran to its end after the stop"
    _handed_back(world["dsn"], done.inv)


async def test_d3_a_child_spawned_while_the_stop_is_under_way_that_ignores_sigterm_is_group_killed(world, monkeypatch):
    """Same stop, but the child (and a grandchild in its group) ignore SIGTERM: after the short `stop_grace` the whole group is killed. (D3, M8)"""
    child = _child(world, files=_committed(), wait_for=world["tmp"] / "release", term="ignore", grandchild=True)
    done = await _serve_with_a_stop_landing_while_the_child_is_spawned(world, monkeypatch, child, stop_grace=0.5)

    assert not done.left_running, f"after the stop, {' and '.join(done.left_running)} still ran"
    _handed_back(world["dsn"], done.inv)


# --- r7: the claim carries the tenant's state (R7-1; r6 R6-4's read mechanism and R6-5 are retired) ----

def _nothing_left_for_a_refused_claim(world: dict, child: ScriptedChild, inv: str) -> None:
    """The row ended `failed`/`worker_error` naming a cause; no launch file, no child, no lock folder."""
    stored = row(world["dsn"], inv)
    assert (stored["stage"], stored["failure_reason"]) == ("failed", "worker_error"), stored
    assert stored["failure_message"]
    assert stored["finished_at"] == NOW
    assert sorted(p.name for p in world["runs"].iterdir()) == [], "a launch file was written for a refused claim"
    assert child.seen() is None, "a child started for a refused claim"
    assert child.events() == []
    assert not (world["root"] / ".host-locks").exists(), "the worker took a tenant lock"


@pytest.mark.parametrize("state", ["creating", "offboarding", "offboarded"])
async def test_r7_1_a_tenant_that_is_not_active_fails_the_row_as_a_worker_error_before_any_file_or_child(world, state):
    """A claim whose tenant (a real `tenancy.tenants` row) is not `active` ends `failed`/`worker_error` naming the state; no launch file, no child. (R7-1)"""
    restate_tenant(world["dsn"], T1, state=state)
    child = _child(world, files=_committed())
    inv, stored = await _run_one(world, child)

    _nothing_left_for_a_refused_claim(world, child, inv)
    assert state in stored["failure_message"]


async def test_r7_1_control_an_active_tenants_row_runs_to_completion(world):
    """Control: the same setup with an `active` tenant starts its child and completes. (R7-1)"""
    child = _child(world, files=_committed())
    inv, stored = await _run_one(world, child)

    assert stored["stage"] == "completed"
    assert child.seen(inv) is not None


@pytest.mark.parametrize("state", ["creating", "offboarding", "offboarded"])
async def test_r7_1_a_tenant_that_is_not_active_is_refused_before_the_alert_is_read(world, state):
    """For a non-active tenant `get_alert` is never called: the state is required before the alert is read. (R7-1)"""
    restate_tenant(world["dsn"], T1, state=state)
    events: list = []
    child = _child(world, files=_committed())
    async with job_store(world["dsn"]) as store:
        inv = await _queued(store)
        await _worker(world, _OrderRecordingStore(store, events), child).drain()

    assert events == [], f"the alert was read for a tenant that is {state}: {events}"
    _nothing_left_for_a_refused_claim(world, child, inv)


class _OrderRecordingStore:
    """The real store, except that every `get_alert` is noted in the shared event list."""

    def __init__(self, store, events: list) -> None:
        self._store, self._events = store, events

    def __getattr__(self, name):
        return getattr(self._store, name)

    async def get_alert(self, tenant_id, alert_id):
        self._events.append(("get_alert", tenant_id, alert_id))
        return await self._store.get_alert(tenant_id, alert_id)


async def test_r7_1_a_tenant_restated_between_two_claims_fails_the_second_row(world):
    """Two rows of one tenant, one slot: the tenant goes `offboarding` after the first child has finished; the first completes, the second is a worker error with no launch files and no child. (R7-1)"""
    moved: list[str] = []

    class RestatedBetweenClaims:
        def __init__(self, inner) -> None:
            self._inner = inner

        def __getattr__(self, name):
            return getattr(self._inner, name)

        async def claim(self):
            if not moved and any(e[0] == "end" for e in child.events()):
                moved.append(T1)
                move_tenant(world["dsn"], T1, state="offboarding")
            return await self._inner.claim()

    async with job_store(world["dsn"]) as store:
        first = await _queued(store, ticket="T-1", key="k1")
        second = await _queued(store, ticket="T-2", key="k2")
        child = _child(world, files=_committed())
        await _worker(world, RestatedBetweenClaims(store), child, slots=1).drain()

    stages = {i: row(world["dsn"], i) for i in (first, second)}
    done = [i for i, r in stages.items() if r["stage"] == "completed"]
    refused = [i for i, r in stages.items() if (r["stage"], r["failure_reason"]) == ("failed", "worker_error")]
    assert (len(done), len(refused)) == (1, 1), {i: (r["stage"], r["failure_reason"]) for i, r in stages.items()}
    assert moved, "premise: the tenant was restated between the claims"
    assert "offboarding" in stages[refused[0]]["failure_message"]
    assert child.events() == [("start", done[0]), ("end", done[0])], "a child started for the second row"
    assert sorted(p.name for p in world["runs"].iterdir() if p.name.startswith(refused[0])) == [], \
        "launch files were written for the refused row"


@pytest.mark.parametrize("entry", ["drain", "serve"])
async def test_r7_1_a_worker_whose_environment_has_no_database_address_starts_and_claims(world, monkeypatch, entry):
    """No `DEFENDER_DATABASE_DSN`: `drain()`/`serve()` start and claim the queued row (its child, not the worker, needs the address). (R7-1, retires R6-5's refusal)"""
    import signal

    monkeypatch.delenv("DEFENDER_DATABASE_DSN", raising=False)
    release = world["tmp"] / "release"
    child = _child(world, files=_committed(), wait_for=release)
    async with job_store(world["dsn"]) as store:
        inv = await _queued(store)
        running = asyncio.create_task(getattr(_worker(world, store, child), entry)())
        try:
            await _until(lambda: child.seen(inv) is not None, "the child to start")
        finally:
            release.touch()
            if entry == "serve":
                await _until(lambda: row(world["dsn"], inv)["stage"] != "running", "the row to end")
                if not running.done():
                    os.kill(os.getpid(), signal.SIGTERM)
            await asyncio.wait_for(running, timeout=60)

    assert row(world["dsn"], inv)["stage"] == "completed"


class _ProbingStore:
    """The real store, except that each `claim()` and `get_alert()` also tries the tenant's host lock exclusive (once) and lists its holders."""

    def __init__(self, store, root: Path) -> None:
        self._store, self.root, self.probes = store, root, []

    def __getattr__(self, name):
        return getattr(self._store, name)

    async def claim(self):
        got = await self._store.claim()
        self.probes.append(probe_host_lock(self.root, T1))
        return got

    async def get_alert(self, tenant_id, alert_id):
        self.probes.append(probe_host_lock(self.root, tenant_id))
        return await self._store.get_alert(tenant_id, alert_id)


def probe_host_lock(root: Path, tenant_id: str) -> SimpleNamespace:
    """Whether an exclusive try-once on the tenant's host lock succeeds now (given back at once), and the pids it lists as holders."""
    from defender.tenancy import host_lock

    fd = host_lock.acquire(root, tenant_id, exclusive=True, timeout=0)
    host_lock.release_lock(fd)
    return SimpleNamespace(free=fd is not None, holders=[h.pid for h in host_lock.holders(root, tenant_id)])


async def test_r6_4_the_worker_holds_no_tenant_lock_and_is_no_holder_during_a_claim_or_a_run(world):
    """Around the claim and while the child runs, an exclusive try-once on the tenant's host lock succeeds and the worker's pid is no holder (teardown signals every holder). (R6-4, kept by R7-1)"""
    release = world["tmp"] / "release"
    child = _child(world, files=_committed(), wait_for=release)
    async with job_store(world["dsn"]) as store:
        probing = _ProbingStore(store, world["root"])
        inv = await _queued(store)
        draining = asyncio.create_task(_worker(world, probing, child).drain())
        try:
            await _until(lambda: child.seen(inv) is not None, "the child to start")
            while_running = probe_host_lock(world["root"], T1)
        finally:
            release.touch()
            await asyncio.wait_for(draining, timeout=60)

    assert probing.probes, "premise: the worker claimed through the probing store"
    for probe in [*probing.probes, while_running]:
        assert probe.free, "the worker held the tenant's host lock"
        assert os.getpid() not in probe.holders, "the worker is on the tenant's holder list"
    assert row(world["dsn"], inv)["stage"] == "completed"


async def test_r6_4_no_tenant_lock_is_held_or_a_holder_while_the_launch_files_are_written(world, monkeypatch):
    """Inside the launch-file write itself, an exclusive try-once on the tenant's host lock succeeds and the worker's pid is no holder; a lock folder that already exists is no excuse. The spied name `JobLane.write_launch` is a pinned seam (D-ab). (R6-4)"""
    from defender.records import job_lane

    lock_folder = world["root"] / ".host-locks" / T1
    lock_folder.mkdir(parents=True)  # exists before the claim, so only a probe inside the write can see a taken lock
    probes: list[SimpleNamespace] = []
    real_write = job_lane.JobLane.write_launch

    def probing_write(self, *args, **kwargs):
        probes.append(probe_host_lock(world["root"], T1))
        return real_write(self, *args, **kwargs)
    monkeypatch.setattr(job_lane.JobLane, "write_launch", probing_write)  # lint-monkeypatch: ok — the lane is built inside the Worker and no seam injects a lane stand-in; this observes the lock state at the write and runs the real write

    child = _child(world, files=_committed())
    inv, stored = await _run_one(world, child)

    assert probes, "premise: the worker wrote the launch files through the job lane"
    for probe in probes:
        assert probe.free, "the worker held the tenant's host lock while it wrote the launch files"
        assert os.getpid() not in probe.holders, "the worker is on the tenant's holder list during the write"
    assert stored["stage"] == "completed"


# --- r7: the launch record is the only "launched" marker (D-af) ------------------------------------------

def _lane_write(world: dict, inv: str, alert: bytes) -> None:
    """`JobLane.write_launch` for `inv` on T1's runs container, as the worker calls it."""
    from defender.records import job_lane
    from defender.tenancy import data_root_from_path

    record = job_lane.LaunchRecord(investigation_id=inv, tenant_id=T1, alert_id=str(uuid.uuid4()),
                                   digest=hashlib.sha256(alert).hexdigest(), label=TITLE, box_token="ab" * 16)
    with job_lane.JobLane.open(data_root_from_path(world["root"]), T1) as lane:
        lane.write_launch(record, alert)


def test_d_af_a_leftover_alert_file_without_a_launch_record_does_not_block_write_launch(world):
    """`write_launch` over a leftover `<id>.alert.json` writes the launch record and replaces the alert with the new bytes. (D-af)"""
    inv = str(uuid.uuid4())
    (world["runs"] / f"{inv}.alert.json").write_bytes(b"leftover from a launch that never finished")

    _lane_write(world, inv, ALERT_BYTES)

    assert (world["runs"] / f"{inv}.alert.json").read_bytes() == ALERT_BYTES
    assert json.loads((world["runs"] / f"{inv}.launch.json").read_text(encoding="utf-8"))["investigation_id"] == inv


def test_d_af_control_a_present_launch_record_still_raises_file_exists(world):
    """Control: with the launch record already there, `write_launch` raises `FileExistsError` and leaves the record. (D-af)"""
    inv = str(uuid.uuid4())
    (world["runs"] / f"{inv}.launch.json").write_text("planted", encoding="utf-8")

    with pytest.raises(FileExistsError):
        _lane_write(world, inv, ALERT_BYTES)

    assert (world["runs"] / f"{inv}.launch.json").read_text(encoding="utf-8") == "planted"


async def test_d_af_a_worker_launches_a_row_whose_alert_file_was_left_behind(world):
    """A row whose `<id>.alert.json` is a leftover (no launch record) is launched: its child runs and the alert file is the stored bytes. (D-af)"""
    inv = str(uuid.uuid4())
    child = _child(world, files=_committed())
    async with job_store(world["dsn"]) as store:
        alert = await an_alert(store, T1)
        plant_queued_investigation(world["dsn"], tenant=T1, alert_id=alert.alert_id, investigation_id=inv)
        (world["runs"] / f"{inv}.alert.json").write_bytes(b"leftover")
        await _worker(world, store, child).drain()

    assert row(world["dsn"], inv)["stage"] == "completed"
    assert child.seen(inv) is not None
    assert (world["runs"] / f"{inv}.alert.json").read_bytes() == ALERT_BYTES


# --- r7: one cleanup follows each row's child (D-ac) -----------------------------------------------------

async def test_d_ac_a_grandchild_left_by_a_child_that_exits_normally_is_gone_after_the_row_ends(world):
    """The child starts a long `sleep` in its session and exits 0; once `drain()` returns the grandchild is dead. (D-ac)"""
    child = _child(world, files=_committed(), grandchild=True)
    seen = None
    try:
        inv, stored = await _run_one(world, child)
        seen = child.seen(inv)
        assert stored["stage"] == "completed"
        assert seen["grandchild"], "premise: the child started a grandchild"
        await _until(lambda: _gone(seen["grandchild"]), "the grandchild to be gone", timeout=5)
    finally:
        _kill_whatever_remains(seen or child.seen())


async def test_d_ac_a_row_cancelled_while_its_spawn_is_in_flight_ends_the_spawned_childs_group_and_runs_the_backstop(
        world, monkeypatch):
    """A claim fault ends `drain()` while a row's spawn has not yet returned: the child and its grandchild die, the box is reaped under the claim's token, the row stays running. (D-ac)

    The worker's spawn through `asyncio.create_subprocess_exec` is a pinned test seam (r7 D-ac), like `JobLane.write_launch` (D-ab): this test patches it to hold the spawn in flight."""
    containers = StandInContainers(world["tmp"] / "containers")
    release = world["tmp"] / "release"
    child = _child(world, files=_committed(), box_dir=containers.where, wait_for=release, grandchild=True)
    real_spawn = asyncio.create_subprocess_exec
    in_flight: list[str] = []

    async def spawn_that_returns_late(*argv, **kw):
        proc = await real_spawn(*argv, **kw)  # the child exists; the worker does not hold it yet
        arrived = child.seen_dir / f"{argv[argv.index('--job') + 1]}.json"
        await _until(arrived.exists, "the spawned child to be up")
        in_flight.append(argv[argv.index("--job") + 1])
        await asyncio.sleep(1.0)
        return proc

    monkeypatch.setattr(asyncio, "create_subprocess_exec", spawn_that_returns_late)  # lint-monkeypatch: ok — the only way to hold a spawn in flight at the moment the claim loop ends; the real spawn runs
    seen = None
    async with job_store(world["dsn"]) as store:
        inv = await _queued(store)
        failing = _StoreWhoseClaimFails(store, faults={2: _NobodyPlannedThis("the store fell over")},
                                        until=lambda: bool(in_flight))
        try:
            with pytest.raises(_NobodyPlannedThis):
                await asyncio.wait_for(_worker(world, failing, child, containers=containers).drain(), timeout=30)
            seen = child.seen(inv)
            assert seen is not None, "premise: the child was spawned"
            await _until(lambda: _gone(seen["pid"]) and _gone(seen["grandchild"]), "the child's group to be dead",
                         timeout=5)
            assert not containers.held(f"defender-run-{inv}"), "the box of the cancelled row was left behind"
            assert set(containers.reaped(f"defender-run-{inv}")) == {_claim_token(world, inv)}
            assert row(world["dsn"], inv)["stage"] == "running"  # stage only: production cancels row tasks only in `_abandon`, which r5 item 3 makes a stop; the hand-back tests pin lease and mark
        finally:
            release.touch()
            _kill_whatever_remains(seen or child.seen())


# --- r7 attack round (candidate 33): D-ac one cleanup however the row ends, D-af, R7-1 -----------------

async def _the_group_to_be_gone(seen: dict | None, what: str) -> None:
    """The child and the grandchild it left in its session are both dead (a killed grandchild may linger a moment as a zombie)."""
    assert seen is not None, "premise: the child ran"
    assert seen["grandchild"], "premise: the child started a grandchild"
    await _until(lambda: _gone(seen["pid"]) and _gone(seen["grandchild"]), what, timeout=5)


async def test_d_ac_a_grandchild_left_by_a_child_that_exits_nonzero_is_gone_after_the_row_ends(world):
    """The child starts a long `sleep` in its session and exits with a failure code; once `drain()` returns the grandchild is dead and the row is the child's failure. (D-ac: whatever way the row ends)"""
    child = _child(world, exit=EXIT, grandchild=True)
    seen = None
    try:
        inv, stored = await _run_one(world, child)
        seen = child.seen(inv)
        assert stored["stage"] == "failed", stored
        await _the_group_to_be_gone(seen, "the grandchild of a failed child to be gone")
    finally:
        _kill_whatever_remains(seen or child.seen())


async def test_d_ac_a_grandchild_is_gone_after_a_deliberate_stop_that_the_child_honours(world):
    """`serve()` stopped by SIGTERM while a child (default SIGTERM) and its grandchild run: the child ends on the SIGTERM, and the grandchild left in its session is dead when `serve()` returns; the row is handed back. (D-ac, D3, B11)"""
    import signal

    release = world["tmp"] / "release"
    child = _child(world, files=_committed(), wait_for=release, grandchild=True)
    seen = None
    async with job_store(world["dsn"]) as store:
        inv = await _queued(store)
        serving = asyncio.create_task(_worker(world, store, child).serve())
        try:
            await _until(lambda: (child.seen(inv) or {}).get("grandchild"), "the child and its grandchild")
            seen = child.seen(inv)
            assert not serving.done()
            os.kill(os.getpid(), signal.SIGTERM)
            await asyncio.wait_for(serving, timeout=60)
            await _the_group_to_be_gone(seen, "the grandchild to be gone after serve() returned")
        finally:
            release.touch()
            if not serving.done():
                serving.cancel()
                await asyncio.gather(serving, return_exceptions=True)
            _kill_whatever_remains(seen)
    _handed_back(world["dsn"], inv)


async def test_d_ac_a_grandchild_is_gone_after_a_drain_cancelled_while_a_child_that_honours_sigterm_runs(world):
    """`drain()` cancelled (a claim fault ends the same way) after the child is up, the child taking SIGTERM and leaving a grandchild in its session: both are dead afterwards, the row is handed back. (D-ac, B11)"""
    containers = StandInContainers(world["tmp"] / "containers")
    release = world["tmp"] / "release"
    child = _child(world, files=_committed(), box_dir=containers.where, wait_for=release, grandchild=True)
    seen = None
    async with job_store(world["dsn"]) as store:
        inv = await _queued(store)
        draining = asyncio.create_task(_worker(world, store, child, containers=containers).drain())
        try:
            await _until(lambda: containers.held(f"defender-run-{inv}") and (child.seen(inv) or {}).get("grandchild"),
                         "the child, its box and its grandchild")
            seen = child.seen(inv)
            draining.cancel()
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(draining, timeout=30)
            await _the_group_to_be_gone(seen, "the cancelled row's group to be gone")
        finally:
            release.touch()
            _kill_whatever_remains(seen)
    _handed_back(world["dsn"], inv)


class _ReapProbingContainers(StandInContainers):
    """The stand-in containers whose `reap` notes, at the moment it is asked, whether anything the child left in its session is still alive."""

    def __init__(self, where: Path, survivors) -> None:
        super().__init__(where)
        self._survivors = survivors
        self.alive_at_reap: list[bool] = []

    def reap(self, name: str, token: str) -> str:
        deadline = time.monotonic() + 2.0  # a SIGKILL already sent takes a moment to land; one not yet sent never does within this
        while self._survivors() and time.monotonic() < deadline:
            time.sleep(0.02)
        self.alive_at_reap.append(bool(self._survivors()))
        return super().reap(name, token)


async def test_d_ac_the_childs_group_is_ended_before_the_backstop_runs(world):
    """A child that exits normally and leaves a grandchild: when the backstop asks the container seam to reap, the grandchild is already dead (the group is ended first, then the box is removed). (D-ac: one step follows the child: the group kill, then the backstop)"""
    seen: dict = {}

    def survivors() -> bool:
        grandchild = (child.seen() or {}).get("grandchild")
        return bool(grandchild) and not _gone(grandchild)

    containers = _ReapProbingContainers(world["tmp"] / "containers", survivors)
    child = _child(world, files=_committed(), grandchild=True)
    try:
        inv, stored = await _run_one(world, child, containers=containers)
        seen = child.seen(inv) or {}
        assert stored["stage"] == "completed", stored
        assert seen.get("grandchild"), "premise: the child started a grandchild"
        assert containers.alive_at_reap == [False], "the backstop ran while the child's group still lived"
    finally:
        _kill_whatever_remains(seen or child.seen())


async def test_d_ac_a_cancelled_row_ends_its_child_with_sigterm_first_as_a_stop_does(world):
    """`drain()` cancelled while a child runs: the child is sent SIGTERM and gets `stop_grace` to answer it (a child that records the SIGTERM and exits has recorded it) before any SIGKILL. (D-ac, D3)"""
    containers = StandInContainers(world["tmp"] / "containers")
    release = world["tmp"] / "release"
    mark = world["tmp"] / "termed"
    child = _child(world, files=_committed(), box_dir=containers.where, wait_for=release, term="mark", term_mark=str(mark))
    async with job_store(world["dsn"]) as store:
        inv = await _queued(store)
        draining = asyncio.create_task(_worker(world, store, child, containers=containers, stop_grace=20).drain())
        try:
            await _until(lambda: containers.held(f"defender-run-{inv}"), "the child's box")
            draining.cancel()
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(draining, timeout=30)
        finally:
            release.touch()
            _kill_whatever_remains(child.seen(inv))

    assert mark.exists(), "the cancelled row's child was killed without the SIGTERM a stop sends first"
    assert _gone(child.seen(inv)["pid"])
    assert row(world["dsn"], inv)["stage"] == "running"  # stage only: production cancels row tasks only in `_abandon`, which r5 item 3 makes a stop; the hand-back tests pin lease and mark


def _is_a_rows_task(task: asyncio.Task) -> bool:
    """The task the worker made for a claim: its coroutine was handed that `Claim`. (#1343 adds renewal, cost and take-over tasks beside the rows' own, so 'every new task' no longer means 'the row'.)"""
    from defender.jobs import Claim

    frame = getattr(task.get_coro(), "cr_frame", None)
    return frame is not None and any(isinstance(v, Claim) for v in frame.f_locals.values())


async def test_d_ac_a_row_cancelled_twice_while_its_spawn_is_in_flight_still_ends_the_spawned_childs_group_and_runs_the_backstop(
        world, monkeypatch):
    """The row's task is cancelled, and cancelled again while it waits for its spawn: the child the spawn then returns is still ended with its grandchild, and the box is reaped under the claim's token. (D-ac: a cancelled row waits out its spawn however many cancels arrive)

    The spawn through `asyncio.create_subprocess_exec` is the pinned seam (r7 D-ac): the patch holds it in flight while the test cancels the row's task twice (the one task the worker made for the claim)."""
    containers = StandInContainers(world["tmp"] / "containers")
    release = world["tmp"] / "release"
    child = _child(world, files=_committed(), box_dir=containers.where, wait_for=release, grandchild=True)
    real_spawn = asyncio.create_subprocess_exec
    before = set(asyncio.all_tasks())
    cancels: list[bool] = []
    rows_seen: list[int] = []

    async def spawn_cancelled_twice(*argv, **kw):
        proc = await real_spawn(*argv, **kw)  # the child exists; the worker does not hold it yet
        await _until((child.seen_dir / f"{argv[argv.index('--job') + 1]}.json").exists, "the spawned child to be up")
        rows = [t for t in asyncio.all_tasks() if t not in before and t is not asyncio.current_task()
                and t is not draining and _is_a_rows_task(t)]
        rows_seen.append(len(rows))
        for _ in range(2):
            cancels.extend(t.cancel() for t in rows)
            await asyncio.sleep(0.2)  # the row has taken the cancel and is waiting out the spawn
        return proc

    monkeypatch.setattr(asyncio, "create_subprocess_exec", spawn_cancelled_twice)  # lint-monkeypatch: ok — the pinned spawn seam (D-ac); the real spawn runs
    seen = None
    async with job_store(world["dsn"]) as store:
        inv = await _queued(store)
        draining = asyncio.create_task(_worker(world, store, child, containers=containers).drain())
        try:
            await asyncio.wait_for(draining, timeout=30)
            assert rows_seen == [1], "premise: one row task was there to cancel"
            assert cancels == [True, True], "premise: it was cancelled twice"
            seen = child.seen(inv)
            assert seen is not None, "premise: the child was spawned"
            await _the_group_to_be_gone(seen, "the twice-cancelled row's group to be gone")
            assert not containers.held(f"defender-run-{inv}"), "the box of the cancelled row was left behind"
            assert set(containers.reaped(f"defender-run-{inv}")) == {_claim_token(world, inv)}
            assert row(world["dsn"], inv)["stage"] == "running"  # stage only: production cancels row tasks only in `_abandon`, which r5 item 3 makes a stop; the hand-back tests pin lease and mark
        finally:
            release.touch()
            _kill_whatever_remains(seen or child.seen())


# --- r7 attack round: the launch files (D-af) ---------------------------------------------------------

def test_d_af_a_present_launch_record_leaves_the_alert_file_as_it_was(world):
    """With the launch record already there, `write_launch` raises `FileExistsError` and neither file changes: the alert file keeps its bytes. (D-af: a launch record already present is `FileExistsError`; nothing is written)"""
    inv = str(uuid.uuid4())
    (world["runs"] / f"{inv}.launch.json").write_text("planted record", encoding="utf-8")
    (world["runs"] / f"{inv}.alert.json").write_bytes(b"the alert of the earlier launch")

    with pytest.raises(FileExistsError):
        _lane_write(world, inv, ALERT_BYTES)

    assert (world["runs"] / f"{inv}.alert.json").read_bytes() == b"the alert of the earlier launch"
    assert (world["runs"] / f"{inv}.launch.json").read_text(encoding="utf-8") == "planted record"


def test_d_af_the_launch_record_write_is_create_only_even_when_the_record_appears_after_the_presence_check(world, monkeypatch):
    """A launch record that turns up between the lane's look and its record write (planted at the held folder's write of that name) is `FileExistsError` and is not replaced. (D-af: the record write is create-only)

    Observation chosen: the real `write_launch` runs over the real held folder; the only seam is the held folder's `write`, which plants the record just before the real write of the record's name. It asserts what the planted file holds afterwards, not which `mode` was passed, so a lane that enforces create-only any other way passes."""
    from defender import _io

    inv = str(uuid.uuid4())
    record = world["runs"] / f"{inv}.launch.json"
    real_write = _io.Held.write

    def write_after_a_racer(self, name, *args, **kwargs):
        if str(name).endswith(".launch.json"):
            record.write_text("planted by a racer", encoding="utf-8")
        return real_write(self, name, *args, **kwargs)
    monkeypatch.setattr(_io.Held, "write", write_after_a_racer)  # lint-monkeypatch: ok — the only point between a lane's presence check and its record write; the real write runs

    with pytest.raises(FileExistsError):
        _lane_write(world, inv, ALERT_BYTES)

    assert record.read_text(encoding="utf-8") == "planted by a racer", "the launch record was replaced"


async def test_d_af_an_alert_file_that_cannot_be_written_leaves_no_launch_record_and_the_id_stays_launchable(world):
    """The alert file's write is refused (a symlink sits at its name): the row ends `failed`/`worker_error`, no launch record is left behind, and once the obstacle is gone the same id can be launched. (D-af: the alert is written first, the record is the only mark of a launch)"""
    inv = str(uuid.uuid4())
    link = world["runs"] / f"{inv}.alert.json"
    link.symlink_to(world["tmp"] / "elsewhere")
    child = _child(world, files=_committed())
    async with job_store(world["dsn"]) as store:
        alert = await an_alert(store, T1)
        plant_queued_investigation(world["dsn"], tenant=T1, alert_id=alert.alert_id, investigation_id=inv)
        await _worker(world, store, child).drain()

    stored = row(world["dsn"], inv)
    assert (stored["stage"], stored["failure_reason"]) == ("failed", "worker_error")
    assert child.seen() is None
    assert not (world["runs"] / f"{inv}.launch.json").exists(), "a launch record was left behind a failed alert write"
    link.unlink()
    _lane_write(world, inv, ALERT_BYTES)  # relaunchable: no record blocks it
    assert (world["runs"] / f"{inv}.launch.json").is_file()


# --- r7 attack round: the tenant's state belongs to each claim (R7-1) -----------------------------------

async def test_r7_1_a_tenant_that_was_creating_at_one_claim_and_is_active_at_a_later_one_runs_the_later_row(world):
    """Two rows of one tenant, one slot: the tenant is `creating` at the first claim (that row is a worker error) and `active` at the second, whose row runs to completion. A refusal is not remembered. (R7-1)"""
    class ActivatedAtTheSecondClaim:
        def __init__(self, inner) -> None:
            self._inner, self.calls = inner, 0

        def __getattr__(self, name):
            return getattr(self._inner, name)

        async def claim(self):
            self.calls += 1
            if self.calls == 2:
                move_tenant(world["dsn"], T1, state="active")
            return await self._inner.claim()

    child = _child(world, files=_committed())
    async with job_store(world["dsn"]) as store:
        first = await _queued(store, ticket="T-1", key="k1")
        second = await _queued(store, ticket="T-2", key="k2")
        move_tenant(world["dsn"], T1, state="creating")
        await _worker(world, ActivatedAtTheSecondClaim(store), child, slots=1).drain()

    stages = {i: row(world["dsn"], i) for i in (first, second)}
    refused = [i for i, r in stages.items() if (r["stage"], r["failure_reason"]) == ("failed", "worker_error")]
    ran = [i for i, r in stages.items() if r["stage"] == "completed"]
    assert (len(refused), len(ran)) == (1, 1), {i: (r["stage"], r["failure_reason"]) for i, r in stages.items()}
    assert "creating" in stages[refused[0]]["failure_message"]
    assert child.events() == [("start", ran[0]), ("end", ran[0])]


class _StopDuringClaim:
    """The job store, except that its first claim sends this process SIGTERM and lets the loop
    act on it before the claim answers: the stop lands while a row is being claimed."""

    def __init__(self, store) -> None:
        self._store = store
        self._sent = False

    def __getattr__(self, name):
        return getattr(self._store, name)

    async def claim(self):
        import signal

        if not self._sent:
            self._sent = True
            os.kill(os.getpid(), signal.SIGTERM)
            await asyncio.sleep(0.05)  # the worker's handler runs: the stop is set before the claim answers
        return await self._store.claim()


async def test_d3_a_row_claimed_while_the_stop_lands_is_handed_back_with_nothing_launched_or_spent(world):
    """CONFLICT-UPDATED (#1343 B11, r4 item 4; was 'left running'): SIGTERM while `serve()` is claiming: no launch record, alert file or child, and the row is handed back (lease lapsed, cost 0, no knowledge, mark set). (D3, D-af, B11)"""
    child = _child(world, files=_committed())
    async with job_store(world["dsn"]) as store:
        inv = await _queued(store)
        await asyncio.wait_for(_worker(world, _StopDuringClaim(store), child, **_FAST).serve(), timeout=30)

    _handed_back(world["dsn"], inv, cost=0, knowledge=None)
    assert not (world["runs"] / f"{inv}.launch.json").exists(), "a stopping worker launched the row"
    assert not (world["runs"] / f"{inv}.alert.json").exists(), "a stopping worker wrote the row's alert"
    assert child.events() == [], "a stopping worker started a child"


# --- #1343 piece B: leases, take-over, cancel of running, deliberate stop ---------------------------------
# Ratified seams (r5 item 11): `JobStore(dsn, *, clock, lease=30.0)`; `Worker(..., renewal_interval=1.0,
# cost_interval=15.0, takeover_interval=5.0)`; `JobStore.take_over(*, held)`; columns `lease_expires_at`,
# `accounting_written_at`. The worker's own write names are not pinned: faults are injected by outcome
# (`_StoreOutage` fails whatever is not on the stable read/admission list; `_StoreWhoseFinishFails` fails `finish`).

from defender.tests.support.jobs._jobs1342 import (  # noqa: E402
    accounting_written,
    lapse_lease,
    lease_left,
    session_database_held_locked,
)

SONNET = "claude-sonnet-4-6"
_FAST = {"renewal_interval": 0.2, "cost_interval": 0.3, "takeover_interval": 0.1}
_SPEND = [(SONNET, {"input_tokens": 1_000_000})]  # priced SONNET_IN = 3.0 USD


def _spending(world: dict, steps: list[tuple[str, dict]], *, released: bool = False, **kw) -> tuple[ScriptedChild, Path]:
    """A child that holds its session database open and appends one priced response per step, then waits for `marks/go-<n>` (`released`: they exist already)."""
    marks = world["tmp"] / "marks"
    if released:
        marks.mkdir(exist_ok=True)
        for n in range(len(steps)):
            (marks / f"go-{n}").touch()
    return _child(world, sessions={"case": CASE, "per_run": True, "steps": steps, "marks": str(marks)}, **kw), marks


def _term_mark(world: dict) -> str:
    return str(world["tmp"] / "term-{id}")


def _termed(world: dict, inv: str) -> bool:
    return Path(_term_mark(world).replace("{id}", inv)).exists()


class _StoreOutage:
    """The real store; while `down`, every method outside the stable read/admission/claim/cancel/delete/take-over API raises a connection error (the worker's own writes, whatever they are named). Notes every call."""

    ALLOWED = frozenset({"claim", "get_alert", "get_investigation", "insert_alert", "create_investigation",
                         "cancel_investigation", "delete_investigation", "take_over", "close"})

    def __init__(self, store) -> None:
        self._store, self.down, self.calls, self.refused = store, False, [], []

    def __getattr__(self, name):
        attr = getattr(self._store, name)
        if name.startswith("_") or not callable(attr):
            return attr

        async def call(*args, **kw):
            self.calls.append(name)
            if self.down and name not in self.ALLOWED:
                self.refused.append(name)
                raise ConnectionError("the database is gone")
            return await attr(*args, **kw)
        return call


class _StoreHoldingTheLaunch:
    """The real store, except the first alert read (the launch's first step, before any child exists) waits for `gate`."""

    def __init__(self, store) -> None:
        self._store, self.gate, self.waiting = store, asyncio.Event(), asyncio.Event()
        self._held = False

    def __getattr__(self, name):
        return getattr(self._store, name)

    async def get_alert(self, tenant_id, alert_id):
        if not self._held:
            self._held = True
            self.waiting.set()
            await self.gate.wait()
        return await self._store.get_alert(tenant_id, alert_id)


def _plant_running_lapsed(dsn: str, alert_id: str, *, attempt: int = 1) -> str:
    """A `running` row nobody holds, its lease lapsed a minute ago by the database clock."""
    inv = str(uuid.uuid4())
    execute(dsn, "INSERT INTO jobs.investigations (id, tenant_id, alert_id, request_key, attempt, stage, created_at, "
                 "started_at, cost_usd, lease_expires_at) VALUES (%s, %s, %s, 'planted', %s, 'running', %s, %s, 0, "
                 "now() - interval '1 minute')", (inv, T1, alert_id, attempt, NOW, NOW))
    return inv


def _lapsed(dsn: str, inv: str) -> bool:
    left = lease_left(dsn, inv)
    return left is not None and left <= 0


def _handed_back(dsn: str, inv: str, *, cost: float | None = None, knowledge: object = "any") -> None:
    """The row a stopping worker gave up: still `running`, lease lapsed, final accounting marked; optionally its final cost and knowledge."""
    handed = row(dsn, inv)
    assert handed["stage"] == "running", f"a stopping worker gave the row a stage: {handed['stage']}"
    left = lease_left(dsn, inv)
    assert left is not None, "the running row has no lease"
    assert left <= 0, f"the handed-back row's lease is not lapsed: {left}"
    assert accounting_written(dsn, inv) is not None, "the hand-back did not mark the final accounting written"
    if cost is not None:
        assert handed["cost_usd"] == pytest.approx(cost), "the hand-back lost the run's final cost"
    if knowledge != "any":
        assert handed["knowledge"] == knowledge




async def _stop_all(*tasks) -> None:
    for task in tasks:
        task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)


def test_b_the_ratified_defaults_are_a_thirty_second_lease_renewed_each_second_cost_every_fifteen_and_take_over_every_five():
    """The seams' defaults: lease 30 s, renewal 1 s, cost tick 15 s, take-over 5 s. (B1, B2, B7, r5 item 11)"""
    from defender.jobs import JobStore
    from defender.worker import Worker

    lease = inspect.signature(JobStore.__init__).parameters["lease"].default
    worker = inspect.signature(Worker.__init__).parameters
    assert (lease, worker["renewal_interval"].default, worker["cost_interval"].default,
            worker["takeover_interval"].default) == (30.0, 1.0, 15.0, 5.0)


# --- B1: renewal ----------------------------------------------------------------------------------------

async def test_b1_a_held_row_keeps_a_fresh_lease_while_its_child_runs(world):
    """A 2 s lease, renewed each 0.2 s: 4 s into the run the lease has not lapsed. (B1)"""
    release = world["tmp"] / "release"
    child = _child(world, files=_committed(), wait_for=release)
    async with job_store(world["dsn"], lease=2.0) as store:
        inv = await _queued(store)
        drained = asyncio.create_task(_worker(world, store, child, **_FAST).drain())
        try:
            await _until(lambda: child.seen(inv), "the child to start")
            await asyncio.sleep(4.0)
            left = lease_left(world["dsn"], inv)
            assert left is not None
            assert left > 0, f"the held row's lease lapsed while its child ran: {left}"
        finally:
            release.touch()
            await asyncio.wait_for(drained, timeout=60)
    assert row(world["dsn"], inv)["stage"] == "completed"


async def test_b1_every_held_row_is_renewed_by_one_store_call_per_tick(world):
    """Three held rows, a 0.2 s tick: over 2 s the worker makes about one store call per tick, not one per row (30). (B1: one statement for all held rows)"""
    release = world["tmp"] / "release"
    child = _child(world, files=_committed(), wait_for=release)
    async with job_store(world["dsn"]) as inner:
        store = _StoreOutage(inner)
        ids = [await _queued(inner, ticket=f"T-{n}", key=f"k{n}") for n in range(3)]
        drained = asyncio.create_task(_worker(world, store, child, slots=3, renewal_interval=0.2,
                                              cost_interval=60.0, takeover_interval=60.0).drain())
        try:
            await _until(lambda: len(child.seen_all()) == 3, "three children")
            await asyncio.sleep(0.5)
            before = len(store.calls)
            await asyncio.sleep(2.0)
            made = len(store.calls) - before
            assert all((lease_left(world["dsn"], i) or 0) > 0 for i in ids)
        finally:
            release.touch()
            await asyncio.wait_for(drained, timeout=60)
    assert 5 <= made <= 15, f"{made} store calls in 10 ticks of three held rows"


async def test_b1_a_late_renewal_of_a_row_nobody_took_over_succeeds(world):
    """A held row whose lease lapsed (a stalled renewal) and was not taken over is made fresh again by the next renewal; its child runs on. (B1: conditional on `running`, not on a fresh lease)"""
    release = world["tmp"] / "release"
    child = _child(world, files=_committed(), wait_for=release)
    dsn = world["dsn"]
    async with job_store(dsn) as store:
        inv = await _queued(store)
        drained = asyncio.create_task(_worker(world, store, child, **_FAST).drain())
        try:
            await _until(lambda: child.seen(inv), "the child to start")
            lapse_lease(dsn, inv)
            await _until(lambda: (lease_left(dsn, inv) or -1) > 10, "the late renewal", timeout=3)
            assert row(dsn, inv)["stage"] == "running"
        finally:
            release.touch()
            await asyncio.wait_for(drained, timeout=60)
    assert row(dsn, inv)["stage"] == "completed"


async def test_b1_a_deliberate_stop_keeps_renewing_until_the_rows_last_write_so_nothing_is_taken_over_during_teardown(world):
    """A child that ignores SIGTERM for the whole 3 s grace: a taker polling take-over never gets the row (1 s lease) while the stop runs; afterwards the hand-back, not a lapse, ended it. (B1, B11, r5 item 1)"""
    release = world["tmp"] / "release"
    child = _child(world, files=_committed(), wait_for=release, term="ignore")
    dsn = world["dsn"]
    async with job_store(dsn, lease=1.0) as store_a, job_store(dsn, lease=1.0) as store_b:
        inv = await _queued(store_a)
        serving = asyncio.create_task(_worker(world, store_a, child, stop_grace=3.0, **_FAST).serve())

        async def taker() -> None:
            while True:
                await store_b.take_over(held=frozenset())
                await asyncio.sleep(0.1)
        taking = asyncio.create_task(taker())
        try:
            await _until(lambda: child.seen(inv), "the child to start")
            began = time.monotonic()
            assert not serving.done()
            os.kill(os.getpid(), signal.SIGTERM)
            while not serving.done() and accounting_written(dsn, inv) is None:  # the mark: the hand-back landed
                assert row(dsn, inv)["stage"] == "running", "the row was taken over while its worker was stopping"
                assert (lease_left(dsn, inv) or 0) > 0, "the stopping worker let the row's lease lapse"
                await asyncio.sleep(0.1)
            await asyncio.wait_for(serving, timeout=10)
            assert time.monotonic() - began >= 2.5, "premise: the stop waited out the child's grace"
            await _until(lambda: row(dsn, inv)["failure_reason"] == "lease_lapsed", "the handed-back row to be taken over")
        finally:
            release.touch()
            await _stop_all(taking, serving)
    assert accounting_written(dsn, inv) is not None, "the row was lost to a lapse, not handed back"
    _kill_whatever_remains(child.seen(inv))


async def test_b_drain_renews_its_rows_takes_nothing_over_and_ends_only_when_they_are_done(world):
    """`drain()` over one running row beside a stranger's lapsed one: the held lease stays fresh, the stranger stays `running`, and drain returns after the child's end. (r5 item 10, B1, B7)"""
    release = world["tmp"] / "release"
    child = _child(world, files=_committed(), wait_for=release)
    dsn = world["dsn"]
    async with job_store(dsn, lease=1.0) as store:
        inv = await _queued(store)
        stranger = _plant_running_lapsed(dsn, (await an_alert(store, T1, ticket="T-9")).alert_id)
        drained = asyncio.create_task(_worker(world, store, child, **_FAST).drain())
        try:
            await _until(lambda: child.seen(inv), "the child to start")
            for _ in range(20):
                assert (lease_left(dsn, inv) or 0) > -0.3, "drain stopped renewing its row"
                await asyncio.sleep(0.1)
            assert row(dsn, stranger)["stage"] == "running", "drain took over a lapsed row"
            assert not drained.done()
        finally:
            release.touch()
            await asyncio.wait_for(drained, timeout=60)
    assert (row(dsn, inv)["stage"], row(dsn, stranger)["stage"]) == ("completed", "running")


# --- B2: cost so far ------------------------------------------------------------------------------------

async def test_b2_b6_cost_so_far_is_copied_while_the_live_child_writes_its_session_database(world):
    """Each response the live child appends shows as cost so far within the cost tick, knowledge stays unset, the child's writes are not blocked; finish sets the final figures. (B2, claim B6, B4)"""
    child, marks = _spending(world, [(SONNET, {"input_tokens": 1_000_000}), (SONNET, {"output_tokens": 1_000_000})],
                             files=_committed())
    dsn = world["dsn"]
    async with job_store(dsn) as store:
        inv = await _queued(store)
        drained = asyncio.create_task(_worker(world, store, child, **_FAST).drain())
        try:
            for step, so_far in ((0, SONNET_IN), (1, SONNET_IN + SONNET_OUT)):
                await _until(lambda s=step: (marks / f"wrote-{s}").exists(), f"the child's append {step}")
                await _until(lambda f=so_far: row(dsn, inv)["cost_usd"] == pytest.approx(f), f"cost so far {so_far}",
                             timeout=5.0)
                live = row(dsn, inv)
                assert (live["stage"], live["knowledge"]) == ("running", None), "knowledge was written mid-run"
                (marks / f"go-{step}").touch()
        finally:
            for step in (0, 1):
                (marks / f"go-{step}").touch()
            await asyncio.wait_for(drained, timeout=60)

    took = [float((marks / f"wrote-{n}").read_text(encoding="utf-8")) for n in (0, 1)]
    assert max(took) < 1.0, f"the worker's reads blocked the child's appends: {took}"
    final = row(dsn, inv)
    assert (final["stage"], final["cost_usd"]) == ("completed", pytest.approx(SONNET_IN + SONNET_OUT))
    assert final["knowledge"] is not None
    assert accounting_written(dsn, inv) is not None, "finish did not mark the final accounting written"


@pytest.mark.parametrize("end", ["finish", "cancel", "stop"])
async def test_b2_a_failed_cost_read_keeps_the_last_good_figure_mid_run_and_writes_null_in_the_end_write(world, end):
    """The pointer goes unreadable after one copied figure: the row keeps 3.0 for several ticks while still renewed; the end write (finish, final accounting or hand-back) then carries cost NULL, not 3.0. (B2, R2)"""
    child, marks = _spending(world, _SPEND, files=_committed(), term="mark", term_mark=_term_mark(world))
    dsn = world["dsn"]
    async with job_store(dsn) as store:
        inv = await _queued(store)
        serving = asyncio.create_task(_worker(world, store, child, **_FAST).serve())
        try:
            await _until(lambda: (marks / "wrote-0").exists(), "the child's spend")
            await _until(lambda: row(dsn, inv)["cost_usd"] == pytest.approx(SONNET_IN), "the first copy", timeout=5)
            (world["runs"] / f"{inv}.session-pointer.json").write_text("not json", encoding="utf-8")
            for _ in range(15):  # about five cost ticks
                await asyncio.sleep(0.1)
                assert row(dsn, inv)["cost_usd"] == pytest.approx(SONNET_IN), "a failed read replaced the last good figure"
                assert (lease_left(dsn, inv) or 0) > 0
            if end == "cancel":
                await store.cancel_investigation(T1, inv, actor="u-1")
            elif end == "finish":
                (marks / "go-0").touch()
            else:
                assert not serving.done()
                os.kill(os.getpid(), signal.SIGTERM)
            await _until(lambda: accounting_written(dsn, inv) is not None, "the end write", timeout=10)
        finally:
            (marks / "go-0").touch()
            if not serving.done():
                os.kill(os.getpid(), signal.SIGTERM)
            await _stop_all(serving)

    final = row(dsn, inv)
    assert final["cost_usd"] is None, "an unreadable final cost was written as a figure"
    assert final["stage"] == {"finish": "completed", "cancel": "aborted", "stop": "running"}[end]


async def test_b2_a_cost_read_that_hangs_never_delays_the_lease_renewal(world):
    """The session database is locked, so the cost read waits on SQLite for the whole window: a 1 s lease is still fresh at every sample for 3 s; once unlocked the cost shows. (B2, r5 item 4)"""
    release = world["tmp"] / "release"
    dsn, runs = world["dsn"], world["runs"]
    child = _child(world, files=_committed(), wait_for=release)
    plant_sessions(runs, CASE, [("main", SONNET, {"input_tokens": 1_000_000})])
    async with job_store(dsn, lease=1.0) as store:
        inv = await _queued(store)
        (runs / f"{inv}.session-pointer.json").write_text(session_pointer(CASE), encoding="utf-8")
        drained = asyncio.create_task(_worker(world, store, child, **_FAST).drain())
        try:
            with session_database_held_locked(runs, CASE):
                await _until(lambda: child.seen(inv), "the child to start")
                for _ in range(30):
                    left = lease_left(dsn, inv)
                    assert left is not None
                    assert left > 0, f"a blocked cost read delayed the renewal: {left}"
                    await asyncio.sleep(0.1)
                assert row(dsn, inv)["cost_usd"] == 0, "premise: the read has not returned"
            await _until(lambda: row(dsn, inv)["cost_usd"] == pytest.approx(SONNET_IN), "the cost once unlocked", timeout=10)
        finally:
            release.touch()
            await asyncio.wait_for(drained, timeout=60)


# --- B3/B4/B9: a fenced row ends its child; one end path -------------------------------------------------

@pytest.mark.parametrize("how", ["cancel", "delete"])
async def test_b9_b3_b4_a_cancelled_or_deleted_running_row_has_its_child_ended_within_a_renewal_and_the_holder_writes_what_is_left(
        world, how):
    """Cancel answers `aborted` at once (a deleted row vanishes); within ~1 s (default renewal) the child gets SIGTERM; after it exits a cancelled row keeps its stage and gains final cost and the mark, a deleted row stays gone. (B9, B3, B4)"""
    child, marks = _spending(world, _SPEND, term="mark", term_mark=_term_mark(world))
    dsn = world["dsn"]
    async with job_store(dsn) as store:
        inv = await _queued(store)
        drained = asyncio.create_task(_worker(world, store, child, cost_interval=60.0).drain())
        try:
            await _until(lambda: (marks / "wrote-0").exists(), "the child's spend")
            if how == "cancel":
                got = await store.cancel_investigation(T1, inv, actor="u-1")
                assert (got.stage, got.failure_reason) == ("aborted", "cancelled")
            else:
                execute(dsn, "DELETE FROM jobs.investigations WHERE id = %s", (inv,))
            await _until(lambda: _termed(world, inv), "the fenced row's child to get SIGTERM", timeout=3.0)
        finally:
            (marks / "go-0").touch()
            await asyncio.wait_for(drained, timeout=60)

    final = row(dsn, inv)
    if how == "delete":
        assert final is None, "the worker wrote a row that was deleted"
        return
    assert (final["stage"], final["failure_reason"], final["finished_at"]) == ("aborted", "cancelled", NOW)
    assert final["cost_usd"] == pytest.approx(SONNET_IN), "the holder's final cost was not written after the cancel"
    assert accounting_written(dsn, inv) is not None


@pytest.mark.parametrize("how", ["cancel", "delete", "take_over"])
async def test_b3_a_row_fenced_before_its_child_exists_is_never_launched_and_still_gets_its_final_accounting(world, how):
    """Claimed, then cancelled/deleted/taken over while the launch is held before any child: the child is never started; a surviving row ends with cost 0, no knowledge and the mark, its stage untouched. (B3, B4, r5 item 5)"""
    child = _child(world, files=_committed())
    dsn = world["dsn"]
    async with job_store(dsn) as inner, job_store(dsn) as taker:
        store = _StoreHoldingTheLaunch(inner)
        inv = await _queued(inner)
        drained = asyncio.create_task(_worker(world, store, child, **_FAST).drain())
        try:
            await asyncio.wait_for(store.waiting.wait(), timeout=10)
            if how == "cancel":
                await inner.cancel_investigation(T1, inv, actor="u-1")
            elif how == "delete":
                execute(dsn, "DELETE FROM jobs.investigations WHERE id = %s", (inv,))
            else:
                async def lapsed() -> bool:
                    lapse_lease(dsn, inv)
                    await taker.take_over(held=frozenset())
                    return row(dsn, inv)["stage"] == "failed"
                for _ in range(100):
                    if await lapsed():
                        break
                    await asyncio.sleep(0.01)
            await asyncio.sleep(1.0)  # five renewal ticks: the fence is seen while the launch is still held
        finally:
            store.gate.set()
            await asyncio.wait_for(drained, timeout=30)

    assert [e for e in child.events() if e[1] == inv] == [], "a fenced row's child was launched"
    final = row(dsn, inv)
    if how == "delete":
        assert final is None
        return
    assert final["stage"] == {"cancel": "aborted", "take_over": "failed"}[how]
    assert (final["cost_usd"], final["knowledge"]) == (0, None)
    assert accounting_written(dsn, inv) is not None


# --- B5: an end write that errors -----------------------------------------------------------------------

async def test_b5_a_failing_end_write_is_retried_until_it_lands_and_nothing_new_is_claimed_meanwhile(world):
    """The finish fails four times: tried each second until it lands (`completed`); a row queued meanwhile waits until then. (B5, r4 item 3)"""
    child = _child(world, files=_committed())
    dsn = world["dsn"]
    async with job_store(dsn) as store:
        bad = await _queued(store, ticket="T-1", key="k1")
        used = _StoreWhoseFinishFails(store, bad, ConnectionError("the database is gone"), fails=4)
        serving = asyncio.create_task(_worker(world, used, child, slots=2, **_FAST).serve())
        try:
            await _until(lambda: used.tries(bad), "the first failed end write")
            later = await _queued(store, ticket="T-2", key="k2")
            await _until(lambda: len(used.tries(bad)) >= 3, "a third try of the end write", timeout=10)
            assert row(dsn, later)["stage"] == "queued", "a row was claimed while an end write was failing"
            await _until(lambda: row(dsn, bad)["stage"] == "completed", "the end write to land", timeout=15)
            await _until(lambda: row(dsn, later)["stage"] == "completed", "the waiting row to run", timeout=15)
        finally:
            if not serving.done():
                os.kill(os.getpid(), signal.SIGTERM)
            await asyncio.wait_for(serving, timeout=60)
    assert [t[0] for t in used.tries(bad)] == ["completed"] * 5


async def test_b5_a_final_accounting_write_that_hits_an_outage_is_retried_until_it_lands_and_nothing_is_claimed_meanwhile(world):
    """A cancelled row whose child ends by itself during an outage: its final accounting is refused for a few seconds, claims wait, then it lands with the cost and the stage untouched. (B5, B4)"""
    release = world["tmp"] / "release"
    child, marks = _spending(world, _SPEND, files=_committed(), released=True, wait_for=release)
    dsn = world["dsn"]
    async with job_store(dsn) as inner:
        store = _StoreOutage(inner)
        inv = await _queued(inner)
        serving = asyncio.create_task(_worker(world, store, child, renewal_interval=30.0, cost_interval=60.0,
                                              takeover_interval=30.0).serve())
        try:
            await _until(lambda: (marks / "wrote-0").exists(), "the child's spend")
            store.down = True
            await inner.cancel_investigation(T1, inv, actor="u-1")
            release.touch()  # the child ends by itself while the database is down
            await _until(lambda: store.refused, "the worker's first refused write", timeout=40)
            later = await _queued(inner, ticket="T-2", key="k2")
            await asyncio.sleep(2.5)
            assert len(store.refused) >= 2, "a refused end write was not retried"
            assert row(dsn, later)["stage"] == "queued", "a row was claimed while the worker's writes were failing"
            assert accounting_written(dsn, inv) is None
            store.down = False
            await _until(lambda: accounting_written(dsn, inv) is not None, "the final accounting to land", timeout=10)
            await _until(lambda: row(dsn, later)["stage"] == "completed", "the waiting row to run", timeout=15)
        finally:
            release.touch()
            if not serving.done():
                os.kill(os.getpid(), signal.SIGTERM)
            await asyncio.wait_for(serving, timeout=60)
    final = row(dsn, inv)
    assert (final["stage"], final["failure_reason"], final["cost_usd"]) == ("aborted", "cancelled", pytest.approx(SONNET_IN))


# --- B7: take-over ---------------------------------------------------------------------------------------

async def test_b_p3_b6_b3_a_worker_never_takes_over_a_row_it_holds_another_does_and_the_holder_ends_its_child_and_records_its_spend(world):
    """Holder A (0.5 s lease, renewing every 2 s, one slot) never takes its own lapsed row over while it takes over a stranger's; worker B does, A then ends its child and writes its spend to the old row, B's retry starts at 0. (B-P3, B7, B6, B3, B4)"""
    release = world["tmp"] / "release"
    child, marks = _spending(world, _SPEND, files=_committed(), released=True, wait_for=release,
                             term="mark", term_mark=_term_mark(world))
    dsn = world["dsn"]
    async with job_store(dsn, lease=0.5) as store_a, job_store(dsn) as store_b:
        held = await _queued(store_a, ticket="T-1", key="k1")
        stranger = _plant_running_lapsed(dsn, (await an_alert(store_a, T1, ticket="T-9")).alert_id)
        a = asyncio.create_task(_worker(world, store_a, child, slots=1, renewal_interval=2.0,
                                        takeover_interval=0.1).serve())
        b = None
        try:
            await _until(lambda: child.seen(held), "A's child")
            await _until(lambda: row(dsn, stranger)["stage"] == "failed", "A to take over the stranger's row", timeout=5)
            seen_lapsed = False
            for _ in range(60):  # 3 s, about 20 of A's take-over passes while its own lease is lapsed
                seen_lapsed |= (lease_left(dsn, held) or 0) < 0
                assert row(dsn, held)["stage"] == "running", "a worker took over a row it holds"
                await asyncio.sleep(0.05)
            assert seen_lapsed, "premise: the held row's lease was never seen lapsed"
            b = asyncio.create_task(_worker(world, store_b, child, slots=1, renewal_interval=1.0,
                                            takeover_interval=0.1).serve())
            await _until(lambda: row(dsn, held)["failure_reason"] == "lease_lapsed", "B to take the row over", timeout=5)
            await _until(lambda: _termed(world, held), "A to end its child", timeout=5)
            await _until(lambda: accounting_written(dsn, held) is not None, "A's final accounting", timeout=5)
        finally:
            release.touch()
            await _stop_all(*(t for t in (a, b) if t is not None))

    old = row(dsn, held)
    assert old["stage"] == "failed", "the holder's final accounting changed the stage"
    assert old["cost_usd"] == pytest.approx(SONNET_IN), "the cut-off holder's spend was not recorded on its own row"
    assert execute(dsn, "SELECT attempt FROM jobs.investigations WHERE request_key = 'k1' ORDER BY attempt") == [(1,), (2,)]


async def test_b7_b5_a_worker_takes_a_lapsed_row_over_though_its_own_end_write_keeps_failing_but_claims_nothing(world):
    """One row's end write fails as an outage for good: the same worker still takes a stranger's lapsed row over (`lease_lapsed`, retry queued), yet claims nothing, the retry included. (B7: independent of failing writes; B5: no claims meanwhile)"""
    child = _child(world, files=_committed())
    dsn = world["dsn"]
    async with job_store(dsn) as store:
        bad = await _queued(store, ticket="T-1", key="k1")
        stranger = _plant_running_lapsed(dsn, (await an_alert(store, T1, ticket="T-9")).alert_id)
        used = _StoreWhoseFinishFails(store, bad, ConnectionError("the database is gone"), fails=10**6)
        serving = asyncio.create_task(_worker(world, used, child, **_FAST).serve())
        try:
            await _until(lambda: len(used.tries(bad)) >= 2, "the end write to be failing")
            await _until(lambda: row(dsn, stranger)["failure_reason"] == "lease_lapsed", "the stranger's row to be taken over", timeout=5)
            await _until(lambda: execute(dsn, "SELECT stage FROM jobs.investigations WHERE request_key = 'planted' "
                                               "AND attempt = 2") == [("queued",)], "the stranger's retry to be queued", timeout=5)
            await asyncio.sleep(2.5)
            assert execute(dsn, "SELECT stage FROM jobs.investigations WHERE request_key = 'planted' "
                                "AND attempt = 2") == [("queued",)], "a row was claimed while a write was failing"
        finally:
            if not serving.done():
                os.kill(os.getpid(), signal.SIGTERM)
            await asyncio.wait_for(serving, timeout=60)
    assert row(dsn, bad)["stage"] == "running", "premise: the end write never landed"


# --- B11: the deliberate stop ----------------------------------------------------------------------------

@pytest.mark.parametrize("term", ["default", "mark"])
async def test_b11_a_deliberate_stop_hands_a_running_row_back_with_its_final_cost_and_its_retry_is_a_new_row(world, term):
    """SIGTERM while a child runs (killed by it, or exiting at once with no records: R1): the row stays `running`, lease lapsed, final cost, marked; never claimed again; a take-over queues attempt 2. (B11, r4 item 2, r5 R1)"""
    child, marks = _spending(world, _SPEND, term=term, term_mark=_term_mark(world))
    dsn = world["dsn"]
    async with job_store(dsn) as store:
        inv = await _queued(store)
        serving = asyncio.create_task(_worker(world, store, child, **_FAST).serve())
        try:
            await _until(lambda: (marks / "wrote-0").exists(), "the child's spend")
            assert not serving.done()
            os.kill(os.getpid(), signal.SIGTERM)
            await asyncio.wait_for(serving, timeout=60)
        finally:
            (marks / "go-0").touch()
            await _stop_all(serving)

        _handed_back(dsn, inv, cost=SONNET_IN)
        assert await store.claim() is None, "a handed-back row was claimed again"
        await store.take_over(held=frozenset())
        retry = await store.claim()
    assert (row(dsn, inv)["stage"], row(dsn, inv)["failure_reason"]) == ("failed", "lease_lapsed")
    assert retry is not None, "the take-over queued no retry"
    assert (retry.record.investigation_id != inv, retry.record.attempt) == (True, 2)


async def test_b11_a_child_that_completes_on_its_own_as_the_stop_signals_it_is_finished_not_handed_back(world):
    """The child writes its committed report as SIGTERM lands and exits 0: the row is `completed` with its cost and knowledge and the mark, and no retry exists. (B11, r5 item 3)"""
    child, marks = _spending(world, _SPEND, files=_committed(), term="finish", term_mark=_term_mark(world))
    dsn = world["dsn"]
    async with job_store(dsn) as store:
        inv = await _queued(store)
        serving = asyncio.create_task(_worker(world, store, child, **_FAST).serve())
        try:
            await _until(lambda: (marks / "wrote-0").exists(), "the child's spend")
            assert not serving.done()
            os.kill(os.getpid(), signal.SIGTERM)
            await asyncio.wait_for(serving, timeout=60)
        finally:
            (marks / "go-0").touch()
            await _stop_all(serving)
        assert await store.claim() is None, "a retry was queued for a finished run"
    final = row(dsn, inv)
    assert (final["stage"], final["cost_usd"]) == ("completed", pytest.approx(SONNET_IN))
    assert final["knowledge"] is not None
    assert accounting_written(dsn, inv) is not None
    assert execute(dsn, "SELECT count(*) FROM jobs.investigations WHERE request_key = 'k1'") == [(1,)]


async def test_b11_a_row_that_became_terminal_before_the_stop_gets_its_final_accounting_not_a_hand_back(world):
    """Cancelled just before SIGTERM (the worker has not seen it): at the stop the row keeps `aborted` and gains its final cost and the mark. (B11, B4, r5 item 2)"""
    child, marks = _spending(world, _SPEND, term="mark", term_mark=_term_mark(world))
    dsn = world["dsn"]
    async with job_store(dsn) as store:
        inv = await _queued(store)
        serving = asyncio.create_task(_worker(world, store, child, renewal_interval=60.0, cost_interval=60.0,
                                              takeover_interval=60.0).serve())
        try:
            await _until(lambda: (marks / "wrote-0").exists(), "the child's spend")
            await store.cancel_investigation(T1, inv, actor="u-1")
            assert not serving.done()
            os.kill(os.getpid(), signal.SIGTERM)
            await asyncio.wait_for(serving, timeout=60)
        finally:
            (marks / "go-0").touch()
            await _stop_all(serving)
    final = row(dsn, inv)
    assert (final["stage"], final["failure_reason"], final["cost_usd"]) == ("aborted", "cancelled", pytest.approx(SONNET_IN))
    assert accounting_written(dsn, inv) is not None


@pytest.mark.parametrize("fails", [1, 10**6])
async def test_b11_a_pending_end_write_gets_one_try_during_the_stop_then_the_stop_gives_up_on_it(world, fails):
    """The child ended by itself and its finish is being retried when SIGTERM lands: the stop tries it once more and returns promptly; it lands if the database is back, else the row stays `running` for its lease to lapse. (B11, B5, r5 item 3)"""
    child = _child(world, files=_committed())
    dsn = world["dsn"]
    async with job_store(dsn, lease=1.0) as store:
        bad = await _queued(store)
        used = _StoreWhoseFinishFails(store, bad, ConnectionError("the database is gone"), fails=fails)
        serving = asyncio.create_task(_worker(world, used, child, **_FAST).serve())
        try:
            await _until(lambda: used.tries(bad), "the first failed end write")
            assert not serving.done()
            os.kill(os.getpid(), signal.SIGTERM)
            await asyncio.wait_for(serving, timeout=10)
        finally:
            await _stop_all(serving)
        tries = len(used.tries(bad))
        assert tries <= 3, f"the stop kept retrying a failing write: {tries} tries"
        if fails == 1:
            assert row(dsn, bad)["stage"] == "completed"
        else:
            assert row(dsn, bad)["stage"] == "running"
            await _until(lambda: _lapsed(dsn, bad), "the abandoned row's lease to lapse", timeout=5)
        assert len(used.tries(bad)) == tries, "the write was tried after the stop returned"


async def test_b11_a_redeploy_mid_run_hands_the_row_back_and_another_worker_runs_attempt_2(world):
    """A stops with its child mid-run; B, started afterwards, takes the row over within seconds and runs attempt 2 to `completed`; attempt 1 is `failed`/`lease_lapsed` with the cost it reached. (B11, B6, B7)"""
    child, marks = _spending(world, _SPEND, files=_committed(), term="mark", term_mark=_term_mark(world))
    dsn = world["dsn"]
    async with job_store(dsn) as store_a, job_store(dsn) as store_b:
        inv = await _queued(store_a)
        a = asyncio.create_task(_worker(world, store_a, child, **_FAST).serve())
        b = None
        try:
            await _until(lambda: (marks / "wrote-0").exists(), "the child's spend")
            assert not a.done()
            os.kill(os.getpid(), signal.SIGTERM)
            await asyncio.wait_for(a, timeout=60)
            (marks / "go-0").touch()
            b = asyncio.create_task(_worker(world, store_b, child, **_FAST).serve())
            await _until(lambda: row(dsn, inv)["failure_reason"] == "lease_lapsed", "B to take the row over", timeout=10)
            await _until(lambda: execute(dsn, "SELECT stage FROM jobs.investigations WHERE request_key = 'k1' "
                                               "AND attempt = 2") == [("completed",)], "attempt 2 to complete", timeout=30)
        finally:
            (marks / "go-0").touch()
            await _stop_all(*(t for t in (a, b) if t is not None))
    old = row(dsn, inv)
    assert (old["stage"], old["failure_reason"], old["cost_usd"]) == ("failed", "lease_lapsed", pytest.approx(SONNET_IN))


# --- repair round: renewal errors, the stop's one try, a real outage, take-over survival, spawn fence --------

class _StoreWhoseEndWritesReachNobody:
    """The real store, except that while `down` its `finish` goes to a second store whose database address is a closed port: the driver's own refusal, not an exception the test builds. Notes each try and what it raised."""

    def __init__(self, store, unreachable) -> None:
        self._store, self._dead, self.down = store, unreachable, False
        self.tries, self.errors = 0, []

    def __getattr__(self, name):
        return getattr(self._store, name)

    async def finish(self, *args, **kw):
        self.tries += 1
        try:
            return await (self._dead if self.down else self._store).finish(*args, **kw)
        except Exception as fault:
            self.errors.append(fault)
            raise


def _closed_port_dsn(dsn: str) -> str:
    import socket
    from urllib.parse import urlsplit

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]  # closed again when the probe is: nothing listens there
    parts = urlsplit(dsn)
    userinfo = parts.netloc.rpartition("@")[0]
    return parts._replace(netloc=f"{userinfo + '@' if userinfo else ''}127.0.0.1:{port}").geturl()


async def test_b5_r5_13_an_end_write_to_a_database_that_does_not_answer_is_retried_until_it_lands(world):
    """The end write reaches a closed port (a real refusal): retried each second, claims blocked, then it lands once the database answers. (B5, r5 item 13)"""
    child = _child(world, files=_committed())
    dsn = world["dsn"]
    async with job_store(dsn) as inner, job_store(_closed_port_dsn(dsn)) as unreachable:
        used = _StoreWhoseEndWritesReachNobody(inner, unreachable)
        used.down = True
        inv = await _queued(inner, ticket="T-1", key="k1")
        serving = asyncio.create_task(_worker(world, used, child, **_FAST).serve())
        try:
            await _until(lambda: bool(used.errors), "the first failed end write", timeout=20)
            later = await _queued(inner, ticket="T-2", key="k2")
            await _until(lambda: used.tries >= 3, "the end write to be tried again and again", timeout=20)
            assert used.errors, "premise: the unreachable database raised nothing"
            assert row(dsn, inv)["stage"] == "running"
            assert row(dsn, later)["stage"] == "queued", "a row was claimed while the end write was failing"
            used.down = False
            await _until(lambda: row(dsn, inv)["stage"] == "completed", "the end write to land", timeout=10)
            await _until(lambda: row(dsn, later)["stage"] == "completed", "the waiting row to run", timeout=15)
        finally:
            if not serving.done():
                os.kill(os.getpid(), signal.SIGTERM)
            await asyncio.wait_for(serving, timeout=60)


async def test_b5_t2_a_renewal_that_errors_fences_nothing_claims_nothing_and_the_next_tick_recovers(world):
    """The store is down about a second under a running child with a row queued: the child is not ended, the row stays `running` unmarked, the queued row is not claimed; once up the lease is renewed and the queued row runs. (r5 item 14, B5)"""
    release = world["tmp"] / "release"
    child = _child(world, files=_committed(), wait_for=release, term="mark", term_mark=_term_mark(world))
    dsn = world["dsn"]
    async with job_store(dsn) as inner:
        store = _StoreOutage(inner)
        inv = await _queued(inner)
        serving = asyncio.create_task(_worker(world, store, child, slots=2, **_FAST).serve())
        try:
            await _until(lambda: child.seen(inv), "the child to start")
            store.down = True
            await _until(lambda: store.refused, "a renewal to be refused")
            later = await _queued(inner, ticket="T-2", key="k2")
            await asyncio.sleep(1.0)
            assert len(store.refused) >= 2, "premise: renewals were not failing tick after tick"
            assert not _termed(world, inv), "a renewal that errored ended the child"
            assert row(dsn, inv)["stage"] == "running"
            assert accounting_written(dsn, inv) is None
            assert row(dsn, later)["stage"] == "queued", "a row was claimed while renewals were failing"
            down_left = lease_left(dsn, inv)
            store.down = False
            await _until(lambda: lease_left(dsn, inv) > down_left + 0.5, "the next tick to renew the lease")
            await _until(lambda: child.seen(later), "the queued row to run")
            assert not _termed(world, inv)
            release.touch()
            await _until(lambda: row(dsn, inv)["stage"] == "completed", "the first row to complete", timeout=15)
            await _until(lambda: row(dsn, later)["stage"] == "completed", "the second row to complete", timeout=15)
        finally:
            release.touch()
            if not serving.done():
                os.kill(os.getpid(), signal.SIGTERM)
            await asyncio.wait_for(serving, timeout=60)


async def test_b11_a_hand_back_that_errors_gets_one_try_and_the_stop_returns_promptly_the_lease_lapsing_on_its_own(world):
    """SIGTERM with the store down and a child running: `serve()` returns promptly, the hand-back is tried once, the row stays `running` unmarked and its lease lapses by itself. (B11, r5 item 3)"""
    release = world["tmp"] / "release"  # never touched: the child is still running when the stop lands
    child = _child(world, files=_committed(), wait_for=release, term="mark", term_mark=_term_mark(world))
    dsn = world["dsn"]
    async with job_store(dsn, lease=3.0) as inner:
        store = _StoreOutage(inner)
        inv = await _queued(inner)
        serving = asyncio.create_task(_worker(world, store, child, **_FAST).serve())
        try:
            await _until(lambda: child.seen(inv), "the child to start")
            store.down = True
            await _until(lambda: store.refused, "a renewal to be refused")
            periodic, before = set(store.refused), len(store.refused)
            began = time.monotonic()
            assert not serving.done()
            os.kill(os.getpid(), signal.SIGTERM)
            await asyncio.wait_for(serving, timeout=15)
            assert time.monotonic() - began < 10, "the stop waited on writes that were failing"
        finally:
            if not serving.done():
                os.kill(os.getpid(), signal.SIGTERM)
            await _stop_all(serving)
        hand_back = [name for name in store.refused[before:] if name not in periodic]
        assert len(hand_back) == 1, f"the hand-back was tried {len(hand_back)} times, not once: {hand_back} (renewals {sorted(periodic)} excluded)"
        assert _termed(world, inv)
        assert row(dsn, inv)["stage"] == "running"
        assert accounting_written(dsn, inv) is None
        await _until(lambda: _lapsed(dsn, inv), "the abandoned row's lease to lapse", timeout=6)


class _StoreWhoseTakeOverFailsOnce:
    def __init__(self, store, fault: Exception) -> None:
        self._store, self._fault, self.raised = store, fault, False

    def __getattr__(self, name):
        return getattr(self._store, name)

    async def take_over(self, **kw):
        if not self.raised:
            self.raised = True
            raise self._fault
        return await self._store.take_over(**kw)


@pytest.mark.parametrize("fault", [ConnectionError("the database is gone"), _NobodyPlannedThis("a bug")], ids=["outage", "bug"])
async def test_b7_the_take_over_task_survives_a_pass_that_raised(world, fault):
    """One take-over pass raises; a row that lapses afterwards is still taken over (`lease_lapsed`) by the same worker. (B7)"""
    dsn = world["dsn"]
    async with job_store(dsn) as inner:
        used = _StoreWhoseTakeOverFailsOnce(inner, fault)
        alert_id = (await an_alert(inner, T1, ticket="T-9")).alert_id
        serving = asyncio.create_task(_worker(world, used, _child(world, files=_committed()), **_FAST).serve())
        try:
            await _until(lambda: used.raised, "the first take-over pass to raise")
            stranger = _plant_running_lapsed(dsn, alert_id)
            await _until(lambda: row(dsn, stranger)["failure_reason"] == "lease_lapsed",
                         "the later lapsed row to be taken over", timeout=10)
            assert not serving.done(), "a raised take-over pass ended the worker"
        finally:
            if not serving.done():
                os.kill(os.getpid(), signal.SIGTERM)
            await asyncio.wait_for(serving, timeout=60)


async def test_b3_a_fence_landing_while_the_spawn_is_prepared_ends_the_child_as_soon_as_it_exists(world):
    """The row is deleted inside `child_argv`, after the worker's last look before the spawn: the child that then exists is ended by the next renewal, not left to run. (B3, r5 item 5)"""
    release = world["tmp"] / "release"
    child = _child(world, files=_committed(), wait_for=release, term="mark", term_mark=_term_mark(world))
    pidfile = world["tmp"] / "child.pid"
    dsn = world["dsn"]

    def argv(launch):
        execute(dsn, "DELETE FROM jobs.investigations WHERE id = %s", (launch.investigation_id,))
        return ["sh", "-c", 'echo $$ > "$0"; exec "$@"', str(pidfile), *child(launch)]

    async with job_store(dsn) as store:
        inv = await _queued(store)
        serving = asyncio.create_task(_worker(world, store, argv, **_FAST).serve())
        pid = None
        try:
            await _until(pidfile.exists, "the child to be spawned")
            pid = int(pidfile.read_text())
            await _until(lambda: _gone(pid), "the fenced row's child to be ended", timeout=10)
        finally:
            release.touch()
            if pid is not None and not _gone(pid):
                os.kill(pid, signal.SIGKILL)
            if not serving.done():
                os.kill(os.getpid(), signal.SIGTERM)
            await asyncio.wait_for(serving, timeout=60)
    assert row(dsn, inv) is None


# --- repair round: what a stop does with a child that failed ------------------------------------------------

_FAILING_RECORD = job_end(setup="crashed", box="not_started", report_committed=False, scrub_verified=False)


@pytest.mark.parametrize("record", [_FAILING_RECORD, "{not json"], ids=["failing-record", "unparseable-record"])
async def test_b11_a_child_that_writes_a_failing_ending_as_the_stop_lands_is_handed_back_with_its_cost_not_failed(world, record):
    """The signal makes the child leave a failing or unparseable job-end and exit: the row is handed back (still `running`, lapsed, cost, marked) and its retry is a new row. (B11, r5 R1)"""
    child, marks = _spending(world, _SPEND, files={"{id}.job-end.json": record}, term="finish", term_mark=_term_mark(world))
    dsn = world["dsn"]
    async with job_store(dsn) as store:
        inv = await _queued(store)
        serving = asyncio.create_task(_worker(world, store, child, **_FAST).serve())
        try:
            await _until(lambda: (marks / "wrote-0").exists(), "the child's spend")
            assert not serving.done()
            os.kill(os.getpid(), signal.SIGTERM)
            await asyncio.wait_for(serving, timeout=60)
        finally:
            (marks / "go-0").touch()
            await _stop_all(serving)
        assert _termed(world, inv), "premise: the stop signalled the child"
        _handed_back(dsn, inv, cost=SONNET_IN)
        await store.take_over(held=frozenset())
        retry = await store.claim()
    assert retry is not None, "the handed-back run was not retried"
    assert retry.record.attempt == 2


async def test_b11_a_child_that_failed_on_its_own_before_the_stop_signalled_it_ends_failed_and_is_not_retried(world):
    """The child exits 7 by itself, its end write is pending when SIGTERM lands: the stop's one try lands it `failed`/`no_report` with the mark; no retry exists. (B11, r5 item 3 'otherwise B4')"""
    child = _child(world, files={"{id}.job-end.json": _FAILING_RECORD}, exit=7, term="mark", term_mark=_term_mark(world))
    dsn = world["dsn"]
    async with job_store(dsn) as store:
        inv = await _queued(store)
        used = _StoreWhoseFinishFails(store, inv, ConnectionError("the database is gone"), fails=1)
        serving = asyncio.create_task(_worker(world, used, child, **_FAST).serve())
        try:
            await _until(lambda: used.tries(inv), "the first failed end write")
            assert not serving.done()
            os.kill(os.getpid(), signal.SIGTERM)
            await asyncio.wait_for(serving, timeout=15)
        finally:
            await _stop_all(serving)
        assert not _termed(world, inv), "premise: the child had already exited when the stop came"
        final = row(dsn, inv)
        assert (final["stage"], final["failure_reason"]) == ("failed", "no_report")
        assert accounting_written(dsn, inv) is not None
        await store.take_over(held=frozenset())
        assert await store.claim() is None, "a run that failed by itself was retried"
    assert execute(dsn, "SELECT count(*) FROM jobs.investigations WHERE request_key = 'k1'") == [(1,)]
