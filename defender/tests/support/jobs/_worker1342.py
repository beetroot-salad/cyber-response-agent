"""Shared setup of the #1342 worker tests (`defender/tests/jobs/test_worker*.py`): the world of two registered tenants,
the worker and child builders, the host records a run leaves, and the ending-rule cases and stand-ins more than one of
those files reads."""
from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import re
import sys
import time
from pathlib import Path

import pytest

from defender.tests.support.jobs._jobs1342 import (
    CLOSING_KEY,
    GOLDEN_REPORT,
    closing_plan,
    T1,
    T2,
    WORKER_LOGGER,
    ScriptedChild,
    an_alert,
    job_end,
    job_store,
    knowledge_record,
    lower_limit,
    make_worker,
    move_tenant,
    register_tenant,
    row,
)
from defender.tests.support.jobs._jobs1342 import (  # noqa: E402
    accounting_written,
    lease_left,
)


_LINUX_ONLY = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="reads /proc/<pid>")


COMMIT = "c" * 40


OTHER_COMMIT = "d" * 40


MARKER = "ATTACKER-TEXT-1342"


CASE = "a1" * 16


#: A `report.md` that says `inconclusive`: planted beside a record, it must change nothing (#1534: no dual read).
GOOD = GOLDEN_REPORT.read_text(encoding="utf-8")  # lint-run-records: ok — a decoy the worker must not read  # lint-report-file: ok — the golden fixture's file, a decoy


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


async def _run_one(world: dict, child: ScriptedChild, *, then_state: str | None = None, **kw) -> tuple[str, dict]:
    """Queue one row, run the worker. `then_state` moves the tenant there after the row is queued (a claim overlapping a lifecycle step)."""
    async with job_store(world["dsn"]) as store:
        inv = await _queued(store)
        if then_state:
            move_tenant(world["dsn"], T1, state=then_state)
        await _worker(world, store, child, **kw).drain()
    if getattr(child, "dsn", None) and getattr(child, "seen", lambda: None)() is not None:  # a staging child that ran
        from defender.tests.support.jobs._evidence_flows1546 import claim_of, facts

        token = claim_of(world["dsn"], "investigation", inv)
        assert token, "premise: the worker's claim wrote no claim row"
        assert "started" in facts(world["dsn"], token), (
            "premise: the stand-in helper staged nothing under the worker's claim (a vacuous no_report)")
    return inv, row(world["dsn"], inv)


def _child(world: dict, **kw) -> ScriptedChild:
    return ScriptedChild(world["tmp"] / "child", world["runs"], **kw)


def _helper_child(world: dict, **kw) -> ScriptedChild:
    """A scripted investigation child that also plays the helper (#1546 PR2): as it leaves its records it stages, under the
    worker's claim, `started` and the facts its host records stand for (`ScriptedChild.dsn`); its files are decoys."""
    kw.setdefault("dsn", world["dsn"])
    return ScriptedChild(world["tmp"] / "child", world["runs"], **kw)


def closing(disposition: str | None = "inconclusive", *, fault: str | None = None, then: str | None = None) -> str:
    """The plan a child follows to leave the run's closing record (`disposition` None: the table and no row); `then` is SQL
    it runs on the database afterwards (`closing_plan`)."""
    return closing_plan(CASE, None if disposition is None else {"disposition": disposition}, fault=fault, then=then)


def _committed(**overrides) -> dict[str, str]:
    """Host records for a run the host committed and whose tree the scrub walked: its closing record is `inconclusive`.
    An override of `None` leaves that record out (a shape whose file the case makes another way)."""
    files = {"{id}.job-end.json": job_end(), CLOSING_KEY: closing(),
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


#: A helper's non-zero exit (#1170: the helper exits 0 once it served the job, whatever its container's status, so a
#: stand-in child that models a job which ran exits 0). No digit of a UUID, timestamp or stage word can stand for it.
EXIT = 77


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
    body["cut_short"] = JSON_NULL  # the fifth fact reads null on a run nothing cut short (#1421); r7.3 T1: there is no sixth, the ledger's seal says the rest
    body.update(changes)
    return json.dumps({k: (None if v is JSON_NULL else v) for k, v in body.items() if v is not None})


MARKED_REPORT = GOOD + f"\n{MARKER}\n"




CASES = {
    # rule 1: no job-end record; the run folder, the exit and the report decide nothing
    "1-no-job-end": _spec(files={"{id}/report.md": MARKED_REPORT}, exit=0,
                          expect=("failed", "no_report", None)),
    "1-no-job-end-helper-failed": _spec(files={"{id}/report.md": MARKED_REPORT}, exit=EXIT,
                                        expect=("failed", "worker_error", None), says=("helper",), code=EXIT),
    # #1546 (A-O2, PR2): the worker parses no job-end record, so the malformed-record cases (`1-job-end-*`: unreadable,
    # empty, an array, a string, words of the wrong type, case or spacing, extra or missing keys, out-of-vocabulary
    # `cut_short`) retired with that parse; the helper stages such a record `refused/outcome`, which ends `bad_record`
    # (test_1546_helper_records.py::test_a_malformed_record_of_any_kind_and_name_is_staged_refused_and_a_refused_outcome_or_result_reads_bad_record).
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
        files=_committed(**{CLOSING_KEY: closing("malicious")}), exit=4, expect=("completed", None, "malicious")),
    "4-completed-beside-a-contrary-report": _spec(
        files=_committed(**{CLOSING_KEY: closing("malicious"), "{id}/report.md": GOOD}),
        expect=("completed", None, "malicious")),
    "4-never-closed": _spec(files=_committed(**{CLOSING_KEY: closing(None)}), expect=("unparseable", None, None)),
    "4-never-closed-no-pointer": _spec(files=_committed(**{CLOSING_KEY: closing(None, fault="no-pointer")}),
                                       expect=("unparseable", None, None)),
    "4-report-only": _spec(files=_committed(**{CLOSING_KEY: None, "{id}/report.md": GOOD}),
                           expect=("unparseable", None, None)),
    "4-record-unreadable": _spec(files=_committed(**{CLOSING_KEY: closing(fault="row-invalid")}),
                                 expect=("unparseable", None, None)),  # a fault in reading the record (V-READERS, worker)
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


class _NobodyPlannedThis(Exception):  # noqa: N818 — derives directly from Exception, in no list of expected faults
    """A fault type no handler in the worker can know by name."""


def _decided(decision) -> dict:
    """An `apply` decision's terminal values as a dict (a `HandBack` has no stage)."""
    names = ("stage", "failure_reason", "disposition", "cost_usd", "cost_is_lower_limit", "knowledge", "evidence_state")
    return {name: getattr(decision, name, None) for name in names} | {"kind": type(decision).__name__}


class _StoreWhoseFinishFails:
    """The real store, except that one row's first `fails` end writes raise, and every end write is noted. #1546 PR9: the
    end write is `apply(tenant, owner, decision)` (the only writer of terminal columns), so that is the seam; `finishes`
    holds each decision's values. With `commit`, each failing write first writes, then loses its answer; with
    `alert_missing`, that row's alert reads as absent."""

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

    async def apply(self, tenant_id, owner_id, decision, *args, **kw):
        owner = str(owner_id)
        self.finishes.append((owner, _decided(decision)))
        self.at.append((owner, time.monotonic()))
        if owner == self._inv and self._fails > 0:
            self._fails -= 1
            if self._commit:
                await self._store.apply(tenant_id, owner_id, decision, *args, **kw)
            raise self._fault
        return await self._store.apply(tenant_id, owner_id, decision, *args, **kw)

    def tries(self, inv: str) -> list[tuple]:
        return [(kw["stage"], kw["failure_reason"], kw["cost_usd"]) for i, kw in self.finishes if i == inv]

    def gaps(self, inv: str) -> list[float]:
        times = [t for i, t in self.at if i == inv]
        return [b - a for a, b in zip(times, times[1:], strict=False)]


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


def _kill_whatever_remains(seen: dict | None) -> None:
    """Whatever the worker did, nothing outlives the test."""
    import signal

    for pid in (seen or {}).get("pid"), (seen or {}).get("grandchild"):
        if pid and not _gone(pid):
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.killpg(pid, signal.SIGKILL)


_FAST = {"renewal_interval": 0.2, "cost_interval": 0.3, "takeover_interval": 0.1}


def _handed_back(dsn: str, inv: str, *, cost: float | None = None, knowledge: object = "any",
                 at_least: bool | None = None, unknown_cost: bool = False) -> None:
    """The row a stopping worker gave up: still `running`, lease lapsed, final accounting marked; optionally its final cost, knowledge and lower-limit mark.
    `unknown_cost`: a child launched and no live figure was read, so the cost is NULL and unmarked (r6 S2/S4: a lower limit stands only beside a number)."""
    handed = row(dsn, inv)
    assert handed["stage"] == "running", f"a stopping worker gave the row a stage: {handed['stage']}"
    left = lease_left(dsn, inv)
    assert left is not None, "the running row has no lease"
    assert left <= 0, f"the handed-back row's lease is not lapsed: {left}"
    assert accounting_written(dsn, inv) is not None, "the hand-back did not mark the final accounting written"
    if unknown_cost:
        assert (handed["cost_usd"], lower_limit(dsn, inv)) == (None, False), (
            "a hand-back with no live cost read stored a number or a mark (r6 S4): it must store NULL, unmarked")
    if cost is not None:
        assert handed["cost_usd"] == pytest.approx(cost), "the hand-back lost the run's final cost"
    if knowledge != "any":
        assert handed["knowledge"] == knowledge
    if at_least is not None:
        assert lower_limit(dsn, inv) is at_least, f"the hand-back's lower-limit mark is not {at_least}"


def _delete_out_of_band(dsn: str, inv: str) -> None:
    """A running investigation row deleted from under its worker, by SQL in one transaction: #1546 (design: Claims
    lifecycle, "deleting an investigation removes its claims, staged facts and uploads in the same transaction") its
    claims' facts and upload rows, its claims, then the row (the store's own delete refuses a running row)."""
    import psycopg

    with psycopg.connect(dsn) as conn, conn.transaction():
        tokens = "SELECT token FROM jobs.claims WHERE investigation_id = %s"
        conn.execute(f"DELETE FROM jobs.staged_facts WHERE token IN ({tokens})", (inv,))  # noqa: S608
        conn.execute(f"DELETE FROM jobs.uploads WHERE token IN ({tokens})", (inv,))  # noqa: S608
        conn.execute("DELETE FROM jobs.claims WHERE investigation_id = %s", (inv,))
        conn.execute("DELETE FROM jobs.investigations WHERE id = %s", (inv,))
