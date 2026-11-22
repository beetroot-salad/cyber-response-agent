"""#1546 (design r8) readiness, adoption and drain through the worker: the result comes from the staged `result`/`knowledge`
rows, never a file (A-O2, D5); a malformed one is a staged `refused/result` and reads `bad_record`; the drain is a
host-request kind (D7): queued by the operator command, one live per tenant, never retried. The child stands for the
helper (`Staging`); the files it leaves contradict the rows. Per-record shape rules of the old file readers
(`test_1471_host_request_worker.py`) are conflicts, flagged in the slice return."""
from __future__ import annotations

import json

import psycopg
import pytest

from defender.tests.support.jobs import _worker1342 as _shared
from defender.tests.support.jobs._evidence_flows1546 import (
    INPUTS,
    KNOWLEDGE,
    ROOTS,
    SPOOL,
    Staging,
    audited,
    claim_row,
    claims_of,
    files_opened_under,
    job_written_places,
)
from defender.tests.support.jobs._host_requests1471 import (
    ADOPTION,
    FRESH_SERVED,
    READINESS,
    STALE_OPERATOR,
    adopted,
    failed,
    host_child,
    host_row,
    host_rows,
    host_worker,
    lapse,
)
from defender.tests.support.jobs._jobs1342 import T1, T2, job_store
from defender.tests.support.shared._postgres1339 import execute

pytestmark = [pytest.mark.anyio, pytest.mark.postgres]
world = _shared.world
_no_database_address_in_the_workers_environment = _shared._no_database_address_in_the_workers_environment

KINDS = ("readiness", "adoption", "drain")
RESULTS = {"readiness": {"outcome": "ready", "warnings": []}, "adoption": {"outcome": "opened", "pr_number": 7},
           "drain": {"outcome": "drained"}}
#: A file that contradicts the staged result, per kind (and a stale knowledge record for readiness).
DECOYS = {"readiness": {READINESS: failed("handover"), "{id}.knowledge-source.json": STALE_OPERATOR},
          "adoption": {ADOPTION: adopted("nothing_to_adopt")}, "drain": {"{id}.drain.json": '{"outcome": "failed"}'}}


async def _queue(store, kind: str):
    if kind == "readiness":
        return (await store.create_readiness(T1, actor="u-1"))[0]
    if kind == "adoption":
        return (await store.create_adoption(T1, "ticket", actor="u-1"))[0]
    return (await store.create_drain(T1, actor="u-1"))[0]  # SEAM (missing): the operator command's store call (D7)


def _worker_for(world, store, staging: Staging, kind: str):
    """A host worker whose command for `kind` is `staging` (the drain's is `drain_argv`, a seam pick)."""
    own = {"drain": {"drain_argv": staging}}.get(kind, {kind: staging})
    return host_worker(world, store, **own)


async def _run(world, kind: str, *, staged: dict, files: dict | None = None, exit: int = 0, folders: bool = False,  # noqa: A002
               **kw):
    child = host_child(world, files=DECOYS[kind] if files is None else files, exit=exit)
    staging = Staging(world["dsn"], world["root"], kind, lambda launch: launch.request_id, child, staged=staged,
                      folders=folders, **kw)
    async with job_store(world["dsn"]) as store:
        rec = await _queue(store, kind)
        await _worker_for(world, store, staging, kind).drain()
    return rec.request_id, host_row(world["dsn"], rec.request_id), staging


async def test_a_readiness_request_finishes_from_its_staged_result_and_knowledge_not_its_files(world):
    """Staged `result` ready and `knowledge` current; the child leaves a `failed` record and a stale knowledge record: the
    row completes from the rows, its claim has no inputs. (D5, A-O2, PR4)"""
    _, stored, staging = await _run(world, "readiness", staged={"result": RESULTS["readiness"], "knowledge": KNOWLEDGE})
    staging.assert_ran()
    assert (stored["stage"], stored["failure_reason"]) == ("completed", None), stored
    assert stored["result"] == {"outcome": "ready", "knowledge": FRESH_SERVED, "warnings": []}
    assert staging.inputs == []


async def test_an_adoption_request_finishes_from_its_staged_result_not_its_file(world):
    """Staged `opened` PR 7; the child's file says `nothing_to_adopt`: the row completes `opened`, 7; no inputs. (D5, A-O2)"""
    _, stored, staging = await _run(world, "adoption", staged={"result": RESULTS["adoption"]})
    staging.assert_ran()
    assert (stored["stage"], stored["result"]) == ("completed", {"outcome": "opened", "pr_number": 7}), stored
    assert staging.inputs == []


async def test_a_drain_request_finishes_from_its_staged_result_and_is_never_retried(world):
    """Staged `result`; the child's file says failed: the row completes; the claim references the request row, not the
    tenant's hold; a later pass claims nothing. (D7, A-O2, G15)"""
    rid, stored, staging = await _run(world, "drain", staged={"result": RESULTS["drain"]})
    staging.assert_ran()
    assert stored["kind"] == "drain", stored
    assert stored["stage"] == "completed", stored
    assert claim_row(world["dsn"], staging.token)["host_request_id"] == rid
    async with job_store(world["dsn"]) as store:
        assert await store.claim_host_request() is None


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("reason", ["not json", "over the cap", "", "x" * 300, "multi\nline"])
async def test_a_result_the_helper_refused_reads_bad_record_and_a_missing_one_no_record(world, kind, reason):
    """A staged `refused/result{reason}` (whatever its reason) ends the request failed `bad_record`, though a valid-looking
    file lies beside it; no fact and a clean exit ends it `no_record`. The reason text never reaches the row. (D11, PR2,
    A-O2)"""
    _, bad, staging = await _run(world, kind, staged={"refused/result": {"reason": reason}})
    staging.assert_ran()
    assert (bad["stage"], bad["failure_reason"]) == ("failed", "bad_record"), bad
    assert reason == "" or reason not in json.dumps(bad, default=str)
    _, none, _ = await _run(world, kind, staged={}, files={})
    assert (none["stage"], none["failure_reason"]) == ("failed", "no_record"), none


@pytest.mark.parametrize("kind", KINDS)
async def test_the_worker_opens_no_job_written_file_for_a_host_request_of_any_kind(world, kind):
    """With a contradicting file in the tenant's runs folder and the claim's root, inputs and spool made: the worker opens no
    file under any claim folder or tenant folder, SQLite databases included; the request still completes from its rows.
    (A-O2, A-O1)"""
    places = job_written_places(world["root"], T1, T2)
    staged = {"result": RESULTS[kind], **({"knowledge": KNOWLEDGE} if kind == "readiness" else {})}
    with audited() as seen:
        _, stored, staging = await _run(world, kind, staged=staged, folders=True,
                                        plant=lambda token: {world["root"] / ROOTS / token / T1 / "runs" / "r.json": b"{}"})
        opened = files_opened_under(seen, *places)
    staging.assert_ran()
    assert stored["stage"] == "completed", stored
    assert opened == [], f"the worker opened job-written files: {opened}"
    for base in (ROOTS, INPUTS, SPOOL):
        assert not (world["root"] / base / staging.token).exists(), "a claim folder outlived the request"


# --- the drain host-request kind (D7) -----------------------------------------------------------------------------------

async def test_the_operator_command_queues_one_drain_row_and_never_a_second_live_one(world):
    """Queued: a `drain` row with the tenant's key. A second command while it is queued, and one while it runs, make no
    second row (at most one queued or running per tenant, by the database); once it ends, a new one queues. (D7)"""
    dsn = world["dsn"]
    async with job_store(dsn) as store:
        first = await _queue(store, "drain")
        again = await _queue(store, "drain")
        assert again.request_id == first.request_id
        assert (await store.claim_host_request()).record.request_id == first.request_id
        await _queue(store, "drain")  # while running: dedupes or is refused, never a second live row
        live = [r for r in host_rows(dsn, T1) if r["kind"] == "drain" and r["stage"] in ("queued", "running")]
        assert [r["id"] for r in live] == [first.request_id]
        with pytest.raises(psycopg.errors.UniqueViolation):  # the database's partial unique index, not the store's check
            execute(dsn, "INSERT INTO jobs.host_requests (id, tenant_id, kind, dedupe_key, requester, created_at, stage) "
                         "VALUES (gen_random_uuid(), %s, 'drain', %s, 'u', now(), 'queued')", (T1, f"{T1}/other"))
    # the control: another tenant is unaffected
    async with job_store(dsn) as store:
        other = (await store.create_drain(T2, actor="u-1"))[0]
    assert other.request_id != first.request_id


async def test_a_lapsed_drain_is_taken_over_worker_lost_and_never_retried_or_claimed_again(world):
    """A drain whose worker was lost ends `failed` / `worker_lost` and queues nothing; the next claim finds nothing. (D7,
    G15: host requests are never retried)"""
    async with job_store(world["dsn"]) as store:
        rec = await _queue(store, "drain")
        await store.claim_host_request()
        lapse(world["dsn"], rec.request_id)
        assert await store.take_over() == [rec.request_id]
        assert await store.claim_host_request() is None
    stored = host_row(world["dsn"], rec.request_id)
    assert (stored["stage"], stored["failure_reason"]) == ("failed", "worker_lost")
    assert [r["stage"] for r in host_rows(world["dsn"], T1)].count("queued") == 0


async def test_a_drain_claim_names_its_request_row_and_carries_an_inputs_list(world):
    """The drain's claim names the request row (not the hold) and carries an `inputs` list (the helper fixes its content at
    launch: the writer is not pinned here, see the slice return); (D7, PR7)"""
    rid, stored, staging = await _run(world, "drain", staged={"result": RESULTS["drain"]})
    staging.assert_ran()
    assert claims_of(world["dsn"], "drain", rid) == [staging.token]
    assert isinstance(claim_row(world["dsn"], staging.token)["inputs"], list)
