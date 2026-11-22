"""#1546 sketch (r6), flow "Investigation end" step 4-5 through the worker's real end path (A-O1, A-O2, A-O3, A-O4,
A-O10): the worker drains one claimed row; its child (`ScriptedChild`) stands for the helper, as in
`tests/jobs/test_worker*`. What the helper leaves for the worker (steps 1-3) is done by this file's `child_argv`
callable in the test process after the claim: it reads the claim token off the row (r6: "Owner rows carry
`claim_token`") and stages, by SQL, the facts and one upload row per object under that token. The worker sees rows.

FORCED CHOICE (exposed by `Helping._launch`): r6 says the claim row is "inserted in the claim's own transaction" and
its token is "the claim id the worker already mints per child" (`worker/_worker.py:1063`, `CLAIM_ENV`). That id is
minted in `_run_child`, after `store.claim()` has committed. Either the store mints the token in the claim's SQL and
the worker hands that to the child, or the worker mints it before claiming and passes it in, or the claim row is a
second write (not "the claim's own transaction"). The cases read the token from the row.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from defender.tests.evidence_1546._support import (
    KNOWLEDGE,
    KNOWLEDGE_SERVED,
    RUN_PAGE,
    STARTED,
    accepted,
    claim_row,
    claim_token,
    evidence_state,
    inv_outcome,
    job_inputs,
    job_root,
    job_spool,
    owner,
    stage_fact,
    stage_upload,
)
from defender.tests.support.jobs import _worker1342 as _shared
from defender.tests.support.jobs._jobs1342 import MALICIOUS_REPORT, T1, job_end, job_store, row
from defender.tests.support.jobs._worker1342 import _child, _queued, _worker
from defender.tests.support.shared._opened_paths import opened, opened_paths
from defender.tests.support.shared._postgres1339 import execute

pytestmark = [pytest.mark.anyio, pytest.mark.postgres]
world = _shared.world
_no_database_address_in_the_workers_environment = _shared._no_database_address_in_the_workers_environment

BUNDLE = b"bundle bytes (opaque to the worker)"
PAGE = b"<html>the renderer's page</html>"

_sqlite_opened: list[str] = []


def _sqlite_hook(event: str, args: tuple) -> None:
    if event == "sqlite3.connect" and args:
        _sqlite_opened.append(os.fsdecode(args[0]))


sys.addaudithook(_sqlite_hook)


class Helping:
    """The worker's `child_argv`: after the claim it stages what the helper would, under the row's claim token, then
    runs the scripted child. `outcome` None: no outcome staged; `objects`: object -> bytes, or None for `refused`;
    `folders`: make the claim's root, inputs and spool folders (as the helper would) with a file each;
    `before(token, root)` runs first."""

    def __init__(self, world: dict, *, outcome: dict | None, objects: dict[str, bytes | None],
                 folders: bool = False, before=None, **child) -> None:
        self.world, self.outcome, self.objects, self.folders, self.before = world, outcome, objects, folders, before
        self.child = _child(world, **child)
        self.token: str | None = None
        self.raised: BaseException | None = None

    def __call__(self, launch) -> list[str]:
        try:
            return self._launch(launch)
        except BaseException as e:  # the worker turns a fault here into `worker_error`; kept so a case names it
            self.raised = e
            raise

    def _launch(self, launch) -> list[str]:
        dsn, inv = self.world["dsn"], launch.investigation_id
        self.token = claim_token(dsn, "investigations", inv)
        assert self.token, "the claim stored no claim token on the row"
        root = job_root(self.world["root"], self.token)
        if self.folders:
            for folder in (root, job_inputs(self.world["root"], self.token), job_spool(self.world["root"], self.token)):
                folder.mkdir(parents=True)
                (folder / "left.txt").write_text("the helper's", encoding="utf-8")
        if self.before is not None:
            self.before(self.token, root)
        stage_fact(dsn, self.token, "started", STARTED)
        stage_fact(dsn, self.token, "knowledge", KNOWLEDGE)
        if self.outcome is not None:
            stage_fact(dsn, self.token, "outcome", self.outcome)
        for obj, data in self.objects.items():
            stage_upload(dsn, self.token, obj, data, status="refused" if data is None else "uploaded",
                         wrapped_key=f"wrapped:{obj}")
        return self.child(launch)


async def _drain(world: dict, helping: Helping) -> tuple[str, dict]:
    async with job_store(world["dsn"]) as store:
        inv = await _queued(store)
        await _worker(world, store, helping).drain()
    assert helping.raised is None, f"the stand-in helper's launch failed (a missing seam?): {helping.raised!r}"
    return inv, row(world["dsn"], inv)


def _learning_jobs(dsn: str, inv: str) -> int:
    [(n,)] = execute(dsn, "SELECT count(*) FROM jobs.learning_jobs WHERE investigation_id = %s", (inv,))
    return int(n)


async def test_a_normal_end_is_complete_clean_and_accepts_exactly_its_claims_uploads(world):
    """Outcome completed/benign/0.42 with scrub clean, bundle and page uploaded: the row completes with the staged
    verdict, cost and knowledge; `scrub = clean`, evidence `complete`; exactly the two uploads are promoted; the claim
    row is the investigation's own; one learning job is queued (flow step 5). (A-O3, A-O4, A-O10)"""
    helping = Helping(world, outcome=inv_outcome(), objects={"bundle": BUNDLE, RUN_PAGE: PAGE})
    inv, stored = await _drain(world, helping)

    assert (stored["stage"], stored["disposition"]) == ("completed", "benign"), stored
    assert stored["cost_usd"] == pytest.approx(0.42)
    assert stored["knowledge"] == KNOWLEDGE_SERVED
    assert owner(world["dsn"], "investigations", inv, "scrub", "evidence_state") == ("clean", "complete")
    assert accepted(world["dsn"], helping.token) == sorted(["bundle", RUN_PAGE])
    claim = claim_row(world["dsn"], helping.token)
    assert (claim["tenant_id"], claim["kind"], claim["investigation_id"]) == (T1, "investigation", inv)
    assert _learning_jobs(world["dsn"], inv) == 1


async def test_a_tainted_investigation_fails_with_scrub_tainted_partial_and_its_bundle_accepted(world):
    """"Done when": a tainted investigation ends `failed` with `scrub = tainted`, evidence `partial`, and its bundle
    accepted; it queues no learning job (only `complete` does). (A-O10, D2, PR6)"""
    helping = Helping(world, outcome=inv_outcome(scrub="tainted"), objects={"bundle": BUNDLE, RUN_PAGE: PAGE})
    inv, stored = await _drain(world, helping)

    assert stored["stage"] == "failed", stored
    assert stored["disposition"] is None, "a tainted run's verdict reached the row"
    assert owner(world["dsn"], "investigations", inv, "scrub", "evidence_state") == ("tainted", "partial")
    assert "bundle" in accepted(world["dsn"], helping.token)
    assert _learning_jobs(world["dsn"], inv) == 0


async def test_a_refused_page_is_lost_keeps_the_verdict_and_queues_no_learning_job(world):
    """The store refused the page (after the helper's retries): the row keeps its verdict, evidence `lost`, the bundle
    alone promoted, no learning job (flow step 5: only `complete`). (A-O4 rule 5)
    FORCED CHOICE: `finish(stage="completed")` queues the auto learning job in the same transaction today
    (`jobs/store.py:651-658`); r6 moves the gate to the learning insert ("requires it `complete`"). Whether a `lost`
    completed investigation queues nothing, or a job refused/skipped at the insert, with what row."""
    helping = Helping(world, outcome=inv_outcome(), objects={"bundle": BUNDLE, RUN_PAGE: None})
    inv, stored = await _drain(world, helping)

    assert (stored["stage"], stored["disposition"]) == ("completed", "benign"), stored
    assert evidence_state(world["dsn"], "investigations", inv) == "lost"
    assert accepted(world["dsn"], helping.token) == ["bundle"]
    assert _learning_jobs(world["dsn"], inv) == 0


async def test_another_claims_uploads_for_the_same_owner_are_never_promoted(world):
    """Beside its own claim's rows, a second claim naming the same owner (stale) has a bundle uploaded: the end
    promotes only its own claim's. (A-O3: exactly the `uploaded` rows under its claim)"""
    stale = "f" * 32

    def plant_stale(token: str, _root: Path) -> None:
        [(inv,)] = execute(world["dsn"], "SELECT id FROM jobs.investigations WHERE claim_token = %s", (token,))
        from defender.tests.evidence_1546._support import insert_claim

        insert_claim(world["dsn"], token=stale, tenant=T1, kind="investigation", ref=str(inv))
        stage_upload(world["dsn"], stale, "bundle", b"stale claim's bundle")

    helping = Helping(world, outcome=inv_outcome(), objects={"bundle": BUNDLE, RUN_PAGE: PAGE}, before=plant_stale)
    await _drain(world, helping)
    assert accepted(world["dsn"], stale) == []
    assert accepted(world["dsn"], helping.token) == sorted(["bundle", RUN_PAGE])


async def test_the_worker_opens_no_job_written_file_and_reads_the_row_from_staged_facts(world):
    """The job's root holds today's job-end record (no report), a malicious report and a session database; the tenant's
    runs folder holds today's records too. The row follows the staged outcome (completed, benign, 0.42) and the worker
    opened none of the planted files, nor any SQLite database. (A-O2, PR2, PR4)"""
    planted: list[Path] = []

    def plant(token: str, root: Path) -> None:
        [(inv,)] = execute(world["dsn"], "SELECT id FROM jobs.investigations WHERE claim_token = %s", (token,))
        runs = root / "runs"
        files = {runs / f"{inv}.job-end.json": job_end(report_committed=False).encode(),
                 runs / str(inv) / "report.md": MALICIOUS_REPORT.read_bytes(),
                 root / "sessions" / "a1.db": b""}
        _write_outside(files)  # in a subprocess: the test's own writes must not read as the worker's opens
        planted.extend(files)

    in_runs = {"{id}.job-end.json": job_end(report_committed=False),
               "{id}/report.md": MALICIOUS_REPORT.read_text(encoding="utf-8")}
    helping = Helping(world, outcome=inv_outcome(), objects={"bundle": BUNDLE, RUN_PAGE: PAGE}, before=plant,
                      files=in_runs)
    _sqlite_opened.clear()
    with opened_paths() as seen:
        inv, stored = await _drain(world, helping)

    assert (stored["stage"], stored["disposition"], stored["failure_reason"]) == ("completed", "benign", None), stored
    job_written = [*planted, world["runs"] / f"{inv}.job-end.json", world["runs"] / inv / "report.md"]
    assert planted, "premise: the root was planted"
    assert [p for p in job_written if opened(seen, p)] == [], "the worker opened a job-written file"
    under_root = [p for p in _sqlite_opened if Path(p).is_relative_to(world["root"])]
    assert under_root == [], f"the worker opened a SQLite database of the job's: {under_root}"


async def test_the_claims_root_inputs_and_spool_are_gone_after_the_end(world):
    """The helper left the claim's root, inputs and spool (as a crash would): after the child and the end, the worker
    removed all three; nothing of the job remains on the host. (A-O1, A-O2: the three roots join `CLAIM_ROOTS`)"""
    helping = Helping(world, outcome=inv_outcome(), objects={"bundle": BUNDLE, RUN_PAGE: PAGE}, folders=True)
    await _drain(world, helping)
    for folder in (job_root(world["root"], helping.token), job_inputs(world["root"], helping.token),
                   job_spool(world["root"], helping.token)):
        assert not folder.exists(), f"{folder} outlived the job"


def _write_outside(files: dict[Path, bytes]) -> None:
    import subprocess

    code = ("import sys, pathlib\n"
            "for i in range(1, len(sys.argv), 2):\n"
            "    p = pathlib.Path(sys.argv[i]); p.parent.mkdir(parents=True, exist_ok=True)\n"
            "    p.write_bytes(bytes.fromhex(sys.argv[i + 1]))\n")
    args = [a for path, data in files.items() for a in (str(path), data.hex())]
    subprocess.run([sys.executable, "-c", code, *args], check=True)
