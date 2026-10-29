"""#1342 the worker in-process over a real database and real child processes: the job lane files
(O6), the ending rules 1–5 read from host-held records (O8), cost over every session, knowledge
mapping, the fence (O5), a missing runs container, and system-actor audit (O13).

Entry: `defender.worker.Worker(store, data_root=, child_argv=, containers=, slots=, clock=)` and
`await worker.drain()` (claim until nothing is queued, then wait for every slot's task). The child is
`ScriptedChild`: it writes the host records a case names and exits; the worker decides the stage."""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
from pathlib import Path

import pytest

from defender.tests.support.jobs._jobs1342 import (
    ALERT_BYTES,
    ALERT_DIGEST,
    GOLDEN_REPORT,
    NOW,
    T1,
    WORKER_LOGGER,
    JobsAudit,
    ScriptedChild,
    StandInContainers,
    an_alert,
    job_end,
    job_store,
    knowledge_record,
    make_worker,
    plant_sessions,
    register_tenant,
    row,
    scrub_verdict,
    session_pointer,
)
from defender.tests.support.shared._postgres1339 import execute

pytestmark = [pytest.mark.anyio, pytest.mark.postgres]

COMMIT = "c" * 40
MARKER = "ATTACKER-TEXT-1342"
GOLDEN_DISPOSITION = "inconclusive"  # golden-v2sshd/report.md's front matter


@pytest.fixture
def world(migrated_database: str, tmp_path: Path) -> dict:
    register_tenant(migrated_database, T1)
    root = tmp_path / "data"
    runs = root / T1 / "runs"
    runs.mkdir(parents=True)
    return {"dsn": migrated_database, "root": root, "runs": runs, "tmp": tmp_path}


async def _queued(store) -> str:
    alert = await an_alert(store, T1)
    inv, _ = await store.create_investigation(T1, alert.alert_id, "k1", actor="u-1")
    return inv.investigation_id


async def _run_one(world: dict, child: ScriptedChild, **kw) -> tuple[str, dict]:
    async with job_store(world["dsn"]) as store:
        inv = await _queued(store)
        await make_worker(store, world["root"], child, **kw).drain()
    return inv, row(world["dsn"], inv)


def _committed(**overrides) -> dict[str, str]:
    """Host records for a run whose report the host committed and whose tree the scrub walked."""
    return {"{id}.job-end.json": job_end(), "{id}.scrub-verdict.json": scrub_verdict(ran=True),
            "{id}/report.md": GOLDEN_REPORT.read_text(encoding="utf-8"),
            "{id}.knowledge-source.json": knowledge_record(COMMIT), **overrides}


# --- O6 ------------------------------------------------------------------------------------------

async def test_o6_the_worker_writes_the_launch_record_and_alert_file_before_the_child(world):
    """`<id>.launch.json` and `<id>.alert.json` exist when the child starts; argv carries id, tenant, worker pid. (O6)"""
    child = ScriptedChild(world["tmp"] / "child", world["runs"], files=_committed())
    inv, _ = await _run_one(world, child)

    seen = child.seen()
    assert seen is not None, "the child never ran"
    assert seen["argv"] == ["--job", inv, "--tenant", T1, "--parent-pid", str(os.getpid())]
    assert (seen["launch_at_start"], seen["alert_at_start"]) == (True, True)
    assert (world["runs"] / f"{inv}.alert.json").read_bytes() == ALERT_BYTES
    launch = json.loads((world["runs"] / f"{inv}.launch.json").read_text(encoding="utf-8"))
    assert {k: launch[k] for k in ("investigation_id", "tenant_id", "digest")} == {
        "investigation_id": inv, "tenant_id": T1, "digest": ALERT_DIGEST}
    assert launch["alert_id"]
    assert launch["label"] == "SSH success after failures"  # SG: label = the alert's title


async def test_o6_a_tenant_with_no_runs_container_fails_as_a_worker_error_and_nothing_is_made(world):
    """No `<root>/<T>/runs` → `failed`/`worker_error`, no child, no folder made for the tenant. (O6)"""
    (world["runs"]).rmdir()
    child = ScriptedChild(world["tmp"] / "child", world["runs"], files=_committed())
    _, stored = await _run_one(world, child)

    assert (stored["stage"], stored["failure_reason"]) == ("failed", "worker_error")
    assert child.seen() is None, "a child was started without a runs container"
    assert not world["runs"].exists()


# --- O8: the worker's rule, one case per branch ------------------------------------------------------

RULES = {
    "1-no-job-end": ({"{id}/report.md": f"---\ndisposition: benign\n---\n{MARKER}\n"}, 7,
                     ("failed", "no_report", None)),
    "2-setup-refused": ({"{id}.job-end.json": job_end(setup="refused", box="not_started",
                                                      report_committed=False, scrub_verified=False)}, 1,
                        ("failed", "setup_refused", None)),
    "3-box-start-failed": ({"{id}.job-end.json": job_end(box="start_failed", report_committed=False,
                                                         scrub_verified=False)}, 1,
                           ("failed", "worker_error", None)),
    "4-committed-and-verified": (_committed(), 0, ("completed", None, GOLDEN_DISPOSITION)),
    "4-unparseable-report": (_committed(**{"{id}/report.md": f"no front matter {MARKER}\n"}), 0,
                             ("unparseable", None, None)),
    "5-box-planted-report": (_committed(**{
        "{id}.job-end.json": job_end(report_committed=False),
        "{id}/report.md": f"---\ndisposition: benign\n---\n{MARKER}\n"}), 4,
        ("failed", "no_report", None)),
    "5-tainted-tree": (_committed(**{"{id}.job-end.json": job_end(scrub_verified=False),
                                     "{id}.scrub-verdict.json": scrub_verdict(ran=False)}), 0,
                       ("failed", "no_report", None)),
}


@pytest.mark.parametrize("case", list(RULES))
async def test_o8_the_stage_comes_from_host_held_records(world, case):
    """Rules 1–5: stage, reason and disposition from the job-end record, never the folder or the exit. (O8)"""
    files, code, (stage, reason, disposition) = RULES[case]
    child = ScriptedChild(world["tmp"] / "child", world["runs"], files=files, exit=code)
    _, stored = await _run_one(world, child)

    assert (stored["stage"], stored["failure_reason"], stored["disposition"]) == (stage, reason, disposition)
    assert stored["finished_at"] == NOW
    if stage == "failed":
        assert stored["failure_message"], "a failed row carries our own message"
        assert MARKER not in stored["failure_message"], "run text reached the row"
    if case == "1-no-job-end":
        assert "7" in stored["failure_message"], "rule 1 names the exit code"


# --- cost and knowledge ------------------------------------------------------------------------------

async def test_o8_cost_is_the_sum_over_every_session_of_the_pointers_database(world):
    """MAIN + a gather lead + lead zero, priced from `PRICING`; located by case id, not `store_path`. (O8 cost)"""
    case_id = hashlib.sha256(b"case-1342").hexdigest()[:32]
    # claude-sonnet-4-6: $3/M in, $15/M out; claude-haiku-4-5: $1/M in.
    plant_sessions(world["runs"], case_id, [
        ("main", "claude-sonnet-4-6", {"input_tokens": 1_000_000}),
        ("l-001", "claude-sonnet-4-6", {"output_tokens": 1_000_000}),
        ("l-000", "claude-haiku-4-5", {"input_tokens": 1_000_000}),
    ])
    child = ScriptedChild(world["tmp"] / "child", world["runs"],
                          files=_committed(**{"{id}.session-pointer.json": session_pointer(case_id)}))
    _, stored = await _run_one(world, child)

    assert stored["stage"] == "completed"
    assert stored["cost_usd"] == pytest.approx(3.0 + 15.0 + 1.0)


async def test_o8_no_session_pointer_costs_nothing_and_knowledge_maps_fresh_to_current(world):
    """No pointer → cost 0; a fresh knowledge record → `{current, commit}`. (O8 cost, knowledge)"""
    child = ScriptedChild(world["tmp"] / "child", world["runs"], files=_committed())
    _, stored = await _run_one(world, child)

    assert stored["cost_usd"] == 0
    assert stored["knowledge"] == {"status": "current", "commit": COMMIT, "stale_kind": None}


@pytest.mark.parametrize(("case", "files", "expected"), [
    ("refused-before-the-run", {"{id}.job-end.json": job_end(
        setup="refused", box="not_started", report_committed=False, scrub_verified=False)}, None),
    ("started-but-no-record", {k: v for k, v in _committed().items()
                               if not k.endswith(".knowledge-source.json")},
     {"status": "stale", "stale_kind": "operator", "commit": None}),
])
async def test_o8_knowledge_is_null_before_a_run_and_stale_operator_when_its_record_is_missing(
        world, case, files, expected):
    """Setup refused → null; the run started but left no record → `{stale, operator, null}`. (O8 knowledge)"""
    child = ScriptedChild(world["tmp"] / "child", world["runs"], files=files)
    _, stored = await _run_one(world, child)
    assert stored["knowledge"] == expected


# --- O5 ------------------------------------------------------------------------------------------

async def test_o5_a_row_moved_while_its_child_runs_is_not_overwritten(world, caplog):
    """The terminal write is conditional on `running`: after SQL moves the row, the finish changes nothing and is logged. (O5)"""
    caplog.set_level(logging.INFO, logger=WORKER_LOGGER)
    release = world["tmp"] / "release"
    child = ScriptedChild(world["tmp"] / "child", world["runs"], files=_committed(), wait_for=release)
    async with job_store(world["dsn"]) as store:
        inv = await _queued(store)
        drained = asyncio.create_task(make_worker(store, world["root"], child).drain())
        for _ in range(1000):
            if child.seen() is not None:
                break
            await asyncio.sleep(0.01)
        assert child.seen() is not None, "the child never started"
        execute(world["dsn"], "UPDATE jobs.investigations SET stage = 'failed', "
                              "failure_reason = 'worker_error', failure_message = 'moved by test' "
                              "WHERE id = %s", (inv,))
        release.touch()
        await asyncio.wait_for(drained, timeout=60)

    stored = row(world["dsn"], inv)
    assert (stored["stage"], stored["failure_message"], stored["disposition"]) == (
        "failed", "moved by test", None)
    assert any(inv in r.getMessage() for r in caplog.records if r.name.startswith(WORKER_LOGGER)), (
        "the refused write was not logged")


# --- O7 backstop (in-process half) and O13 ------------------------------------------------------------

async def test_o7_after_the_child_exits_the_backstop_removes_a_leftover_box_only_if_present(world, tmp_path):
    """`defender-run-<id>` is removed when it exists; an absent one is looked at, never an error. (O7)"""
    containers = StandInContainers(tmp_path / "containers")
    child = ScriptedChild(world["tmp"] / "child", world["runs"], files=_committed())
    async with job_store(world["dsn"]) as store:
        alert = await an_alert(store, T1, ticket="T-1")
        left, _ = await store.create_investigation(T1, alert.alert_id, "k1", actor="u-1")
        other = await an_alert(store, T1, ticket="T-2")
        clean, _ = await store.create_investigation(T1, other.alert_id, "k2", actor="u-1")
        containers.plant(f"defender-run-{left.investigation_id}")
        await make_worker(store, world["root"], child, containers=containers).drain()

    assert ("remove", f"defender-run-{left.investigation_id}") in containers.calls
    assert ("exists", f"defender-run-{clean.investigation_id}") in containers.calls
    assert ("remove", f"defender-run-{clean.investigation_id}") not in containers.calls
    assert row(world["dsn"], clean.investigation_id)["stage"] == "completed"


async def test_o13_claim_and_finish_are_audited_as_the_system(world, caplog):
    """`investigation.claim` then `investigation.finish` (detail: stage), actor `system`. (O13)"""
    audit = JobsAudit(caplog)
    child = ScriptedChild(world["tmp"] / "child", world["runs"], files=_committed())
    inv, _ = await _run_one(world, child)

    worker_events = [e for e in audit.events() if e.action in ("investigation.claim", "investigation.finish")]
    assert [(e.action, e.actor, e.tenant_id, e.target) for e in worker_events] == [
        ("investigation.claim", "system", T1, inv), ("investigation.finish", "system", T1, inv)]
    assert "completed" in (worker_events[1].detail or "")
