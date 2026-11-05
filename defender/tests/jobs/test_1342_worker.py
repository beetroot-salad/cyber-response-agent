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
    seed_alert_mapping,
    session_db,
    session_pointer,
    tree,
)
from defender.tests.support.shared._postgres1339 import execute
from defender.tests.support.tenancy._mapping1345 import mapping_value

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

@pytest.mark.parametrize("moved", ["failed", "cancelled", "completed", "queued"])
async def test_o5_a_row_moved_while_its_child_runs_is_left_alone_and_logged(world, caplog, moved):
    """After SQL moves a running row to any other stage, the finish changes nothing, is logged, emits no finish event for it; the worker carries on. (O5)"""
    caplog.set_level(logging.INFO, logger=WORKER_LOGGER)
    audit = JobsAudit(caplog)
    release = world["tmp"] / "release"
    child = _child(world, files=_committed(), wait_for=release)
    sql = {"failed": "stage = 'failed', failure_reason = 'worker_error', failure_message = 'moved by test', finished_at = %s",
           "cancelled": "stage = 'aborted', failure_reason = 'cancelled', finished_at = %s",
           "completed": "stage = 'completed', disposition = 'benign', finished_at = %s",
           "queued": "stage = 'queued', started_at = NULL, finished_at = NULL"}[moved]
    async with job_store(world["dsn"]) as store:
        fenced = await _queued(store, ticket="T-1", key="k1")
        other = await _queued(store, ticket="T-2", key="k2")
        drained = asyncio.create_task(_worker(world, store, child).drain())
        for _ in range(1500):
            if len(child.seen_all()) == 2:
                break
            await asyncio.sleep(0.01)
        assert len(child.seen_all()) == 2, "the children never started"
        execute(world["dsn"], f"UPDATE jobs.investigations SET {sql} WHERE id = %s",  # noqa: S608
                (fenced,) if moved == "queued" else (NOW, fenced))
        snapshot = row(world["dsn"], fenced)
        if moved in ("failed", "cancelled"):
            assert snapshot["disposition"] is None, "premise: the moved row carries no disposition"
        release.touch()
        await asyncio.wait_for(drained, timeout=60)

    final = row(world["dsn"], fenced)
    if moved != "queued":
        assert final == snapshot, "the worker's terminal write overwrote the moved row"
    # A row put back to `queued` is claimed again by the draining worker (its launch files then
    # exist, so that second go ends `worker_error`); what it must never carry is the first child's finish.
    assert final["disposition"] == snapshot["disposition"]
    assert moved == "completed" or final["stage"] != "completed", "the first child's finish overwrote the moved row"
    assert _warned(caplog, fenced), "the refused write was not logged"
    assert not _warned(caplog, other), "a clean finish was logged as a fault"
    assert row(world["dsn"], other)["stage"] == "completed", "the worker stopped working on every row"
    finishes = [e for e in audit.events() if e.action == "investigation.finish" and e.target == fenced]
    if moved == "queued":
        assert not any("completed" in (e.detail or "") for e in finishes), finishes
    else:
        assert finishes == [], "a finish was audited for a write that changed nothing"
    assert [e.target for e in audit.events() if e.action == "investigation.finish" and e.target == other] == [other]


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



@pytest.mark.parametrize(("mapping", "label"), [
    ({"title": "rule.description"}, TITLE),   # control: a mapped title is the label
    ({"title": "a"}, "\u00e9"),                 # whatever the mapping derives, not a fixed string
    ({"title": None, "description": "rule.id"}, "T-1"),   # title unmapped: the vendor ticket id
    ({"title": "no.such.path"}, "T-1"),        # title absent from the alert
    ({"title": "z"}, "T-1"),                   # title a float: no value
    ({}, "T-1"),
], ids=["mapped", "other-path", "unmapped", "absent", "float", "empty-mapping"])
async def test_1345_o2_the_launch_label_is_the_alerts_title_or_its_vendor_ticket_id_when_the_title_is_null(
        world, mapping, label):
    """The launch record's label is the alert's stored title, else the vendor's ticket id (`T-1`). (#1345 O2, worker)"""
    seed_alert_mapping(world["dsn"], T1, mapping)
    inv, _ = await _run_one(world, _child(world))

    launch = json.loads((world["runs"] / f"{inv}.launch.json").read_text(encoding="utf-8"))
    assert launch["label"] == label


async def test_1345_o2_the_label_is_the_title_at_launch_not_at_queueing(world):
    """A mapping saved after the investigation is queued and before it launches decides the label: the launch reads the
    alert as it then is. (#1345 O2, M3)"""
    async with job_store(world["dsn"]) as store:
        inv = await _queued(store)
        await store.put_alert_mapping(T1, mapping_value({"title": "a"}), actor="u-1")
        await _worker(world, store, _child(world)).drain()

    launch = json.loads((world["runs"] / f"{inv}.launch.json").read_text(encoding="utf-8"))
    assert launch["label"] == "\u00e9"


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

    def __getattr__(self, name):
        return getattr(self._store, name)

    async def get_alert(self, tenant_id, alert_id):
        if self._alert_missing and alert_id == (await self._store.get_investigation(tenant_id, self._inv)).alert_id:
            return None
        return await self._store.get_alert(tenant_id, alert_id)

    async def finish(self, tenant_id, investigation_id, **kw):
        self.finishes.append((investigation_id, kw))
        if investigation_id == self._inv and self._fails > 0:
            self._fails -= 1
            if self._commit:
                await self._store.finish(tenant_id, investigation_id, **kw)
            raise self._fault
        return await self._store.finish(tenant_id, investigation_id, **kw)

    def tries(self, inv: str) -> list[tuple]:
        return [(kw["stage"], kw["failure_reason"], kw["cost_usd"]) for i, kw in self.finishes if i == inv]


async def _run_with_failing_finish(world, fault, **kw) -> tuple[str, str, _StoreWhoseFinishFails]:
    child = _child(world, files=_committed())
    async with job_store(world["dsn"]) as store:
        bad = await _queued(store, ticket="T-1", key="k1")
        good = await _queued(store, ticket="T-2", key="k2")
        used = _StoreWhoseFinishFails(store, bad, fault, **kw)
        await _worker(world, used, child).drain()
    assert row(world["dsn"], good)["stage"] == "completed", "one row's failed finish stopped the others"
    return bad, good, used


@pytest.mark.parametrize("fault_type", [ConnectionError, RuntimeError, _NobodyPlannedThis])
async def test_o6_a_decided_ending_whose_write_fails_once_is_written_again_unchanged(world, fault_type):
    """The ending is decided (`completed`) and its write fails without committing: the worker writes the same ending again, never another verdict. (#1378)"""
    bad, _, used = await _run_with_failing_finish(world, fault_type("the connection dropped"), fails=1)

    tries = used.tries(bad)
    assert [t[:2] for t in tries] == [("completed", None)] * 2, "the decided ending was replaced"
    assert tries[0] == tries[1]
    assert row(world["dsn"], bad)["stage"] == "completed"


async def test_o6_a_decided_ending_whose_write_keeps_failing_is_tried_a_bounded_number_of_times_and_the_row_left_running(
        world):
    """Every write of the decided ending fails: exactly `FINISH_ATTEMPTS` tries, all the same ending, and the row stays running for the reclaim (#1343); the worker goes on. (#1378)"""
    from defender.worker._worker import FINISH_ATTEMPTS

    bad, _, used = await _run_with_failing_finish(world, ConnectionError("the database is gone"), fails=99)

    assert FINISH_ATTEMPTS > 1
    assert [t[0] for t in used.tries(bad)] == ["completed"] * FINISH_ATTEMPTS
    assert row(world["dsn"], bad)["stage"] == "running"


async def test_o6_a_decided_ending_that_committed_but_lost_its_answer_is_not_changed_by_the_retry(world):
    """The first write commits and only its answer is lost: the retry changes nothing, the row keeps that ending. (#1378)"""
    bad, _, used = await _run_with_failing_finish(world, ConnectionError("the answer was lost"), fails=1, commit=True)

    assert [t[0] for t in used.tries(bad)] == ["completed", "completed"]
    stored = row(world["dsn"], bad)
    assert (stored["stage"], stored["failure_reason"]) == ("completed", None)


@pytest.mark.parametrize("path", ["worker-fault", "catch-all"])
async def test_o6_a_worker_error_ending_whose_write_fails_is_retried_unchanged_and_never_rewritten(world, path):
    """A `failed`/`worker_error` ending (from a worker fault before the child, or from the catch-all) whose write fails: retried with the same values, then the row is left running; no other ending is written. (#1378)"""
    from defender.worker._worker import FINISH_ATTEMPTS

    child = _child(world, files=_committed())
    async with job_store(world["dsn"]) as store:
        bad = await _queued(store, ticket="T-1", key="k1")
        if path == "worker-fault":
            used = _StoreWhoseFinishFails(store, bad, ConnectionError("dropped"), fails=99, alert_missing=True)
        else:
            alert_id = (await store.get_investigation(T1, bad)).alert_id
            used = _StoreWhoseFinishFails(_StoreWhoseAlertReadFails(store, alert_id, _NobodyPlannedThis("x")),
                                          bad, ConnectionError("dropped"), fails=99)
        await _worker(world, used, child).drain()

    expect_cost = 0.0 if path == "worker-fault" else None
    assert used.tries(bad) == [("failed", "worker_error", expect_cost)] * FINISH_ATTEMPTS
    assert row(world["dsn"], bad)["stage"] == "running"
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


async def test_o4_a_store_fault_in_drain_ends_every_running_child_reaps_every_box_and_writes_no_row(world):
    """`drain()` leaving by a store fault with two children running: both are dead, both boxes (each under its claim's token) removed, and no row is written. (O4, r5 drain()/serve() as one loop, D3, D-w)"""
    async with _a_drain_that_lost_its_store_with_children_running(world) as left:
        for inv, name in zip(left.ids, left.names, strict=True):
            assert _gone(left.child.seen(inv)["pid"]), f"the fault left {inv}'s child running"
            assert not left.containers.held(name), f"the fault left {inv}'s box behind"
            assert set(left.containers.reaped(name)) == {_claim_token(world, inv)}
            assert row(world["dsn"], inv)["stage"] == "running", "a worker leaving by a fault wrote the row"


async def test_o7_a_drain_cancelled_while_two_children_run_ends_both_and_reaps_both_boxes(world):
    """`drain()` cancelled with two children running: both are dead and both boxes (each under its claim's token) removed, the rows left running. (O7, r5 each row's task owns its child)"""
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
            assert row(world["dsn"], inv)["stage"] == "running"


async def test_o7_a_drain_cancelled_while_a_child_that_ignores_sigterm_runs_still_reaps_its_box(world):
    """A cancelled drain whose child ignores SIGTERM: the child is group-killed after `stop_grace`, and its box is reaped all the same (the backstop does not depend on how the child died). (O7, D3)"""
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
        assert row(world["dsn"], inv)["stage"] == "running"


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
    assert done.stage == "running", "a stopping worker wrote the row"


async def test_d3_a_child_spawned_while_the_stop_is_under_way_that_ignores_sigterm_is_group_killed(world, monkeypatch):
    """Same stop, but the child (and a grandchild in its group) ignore SIGTERM: after the short `stop_grace` the whole group is killed. (D3, M8)"""
    child = _child(world, files=_committed(), wait_for=world["tmp"] / "release", term="ignore", grandchild=True)
    done = await _serve_with_a_stop_landing_while_the_child_is_spawned(world, monkeypatch, child, stop_grace=0.5)

    assert not done.left_running, f"after the stop, {' and '.join(done.left_running)} still ran"
    assert done.stage == "running", "a stopping worker wrote the row"


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
            assert row(world["dsn"], inv)["stage"] == "running", "a worker leaving by a fault wrote the row"
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
    """`serve()` stopped by SIGTERM while a child (default SIGTERM) and its grandchild run: the child ends on the SIGTERM, and the grandchild left in its session is dead when `serve()` returns; the row is left running. (D-ac, D3)"""
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
            os.kill(os.getpid(), signal.SIGTERM)
            await asyncio.wait_for(serving, timeout=60)
            await _the_group_to_be_gone(seen, "the grandchild to be gone after serve() returned")
        finally:
            release.touch()
            if not serving.done():
                serving.cancel()
                await asyncio.gather(serving, return_exceptions=True)
            _kill_whatever_remains(seen)
    assert row(world["dsn"], inv)["stage"] == "running", "a stopping worker wrote the row"


async def test_d_ac_a_grandchild_is_gone_after_a_drain_cancelled_while_a_child_that_honours_sigterm_runs(world):
    """`drain()` cancelled (a claim fault ends the same way) after the child is up, the child taking SIGTERM and leaving a grandchild in its session: both are dead afterwards, the row is left running. (D-ac)"""
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
    assert row(world["dsn"], inv)["stage"] == "running"


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
    assert row(world["dsn"], inv)["stage"] == "running"


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
        rows = [t for t in asyncio.all_tasks() if t not in before and t is not asyncio.current_task() and t is not draining]
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
            assert row(world["dsn"], inv)["stage"] == "running"
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


async def test_d3_a_row_claimed_while_the_stop_lands_is_left_running_with_nothing_launched(world):
    """SIGTERM while `serve()` is claiming: the row it claimed stays `running` with no launch record,
    no alert file and no child, so nothing marks it launched when it is taken up again. (D3, D-af; finalize #1354)"""
    child = _child(world, files=_committed())
    async with job_store(world["dsn"]) as store:
        inv = await _queued(store)
        await asyncio.wait_for(_worker(world, _StopDuringClaim(store), child).serve(), timeout=30)

    assert row(world["dsn"], inv)["stage"] == "running"
    assert not (world["runs"] / f"{inv}.launch.json").exists(), "a stopping worker launched the row"
    assert not (world["runs"] / f"{inv}.alert.json").exists(), "a stopping worker wrote the row's alert"
    assert child.events() == [], "a stopping worker started a child"
