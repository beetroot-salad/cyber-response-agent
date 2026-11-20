"""#1471 slice A, the worker over host requests (R13-1.1, .5, R13-4, R13-5, R13-6, B1, B2): real store, real child processes
that leave the records a helper or container would write (slice B owns the real launch). Postgres-gated."""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import signal

import pytest

from defender.tests.support.jobs import _worker1342 as _shared
from defender.tests.support.jobs._host_requests1471 import (
    ADOPTION,
    ADOPTION_OUTCOMES,
    ADOPTION_REASONS,
    COMMIT,
    FRESH,
    FRESH_SERVED,
    KNOWLEDGE,
    MALFORMED_KNOWLEDGE,
    MARK,
    READINESS,
    READINESS_CONTAINER_REASONS,
    READINESS_HELPER_REASONS,
    STALE_OPERATOR,
    STALE_OPERATOR_SERVED,
    STEPS_WITH_KNOWLEDGE,
    STEPS_WITHOUT_KNOWLEDGE,
    WARNING_KINDS,
    WITH_NUMBER,
    adopted,
    failed,
    host_child,
    host_row,
    host_rows,
    host_worker,
    lapse,
    lease_left,
    ready,
    refused,
    set_created,
    warning,
)
from defender.tests.support.jobs._jobs1342 import NOW, T1, job_store, row
from defender.tests.support.jobs._worker1342 import _FAST, EXIT, _child, _names_code, _queued, _until

pytestmark = [pytest.mark.anyio, pytest.mark.postgres]
world = _shared.world
_no_database_address_in_the_workers_environment = _shared._no_database_address_in_the_workers_environment

SYSTEM = "ticket"


async def _run(world, kind: str, files: dict, *, exit: int = 0, system: str = SYSTEM, **worker_kw):  # noqa: A002
    """One request of `kind` queued and run to its end by a draining worker whose child leaves `files`; (id, row, child)."""
    child = host_child(world, files=files, exit=exit)
    async with job_store(world["dsn"]) as store:
        rec, _ = await (store.create_readiness(T1, actor="u-1") if kind == "readiness"
                        else store.create_adoption(T1, system, actor="u-1"))
        await host_worker(world, store, child, **worker_kw).drain()
    return rec.request_id, host_row(world["dsn"], rec.request_id), child


def _rfiles(record: str | None, knowledge: str | None = None) -> dict:
    return {k: v for k, v in {READINESS: record, KNOWLEDGE: knowledge}.items() if v is not None}


async def _readiness(world, record, knowledge=None, **kw):
    return await _run(world, "readiness", _rfiles(record, knowledge), **kw)


async def _adoption(world, record, **kw):
    return await _run(world, "adoption", {} if record is None else {ADOPTION: record}, **kw)


def _bad(stored: dict) -> None:
    assert (stored["stage"], stored["failure_reason"], stored["result"]) == ("failed", "bad_record", None)
    assert stored["failure_message"]
    assert MARK not in json.dumps(stored, default=str), "container-written text reached the row"


# --- R13-1.5: the record wins over the exit status --------------------------------------------------------------------

@pytest.mark.parametrize("exit_status", [0, EXIT])
async def test_r13_1_5_a_ready_record_decides_whatever_the_helpers_exit(world, exit_status):
    """A `ready` record completes the request with its warnings and the knowledge record's status, exit 0 or not. (R13-1.5)"""
    warnings = [warning("case_system", "the case system is absent"), warning("verb_undecided", "grep is withheld")]
    rid, stored, child = await _readiness(world, ready(warnings), FRESH, exit=exit_status)
    assert child.started() == [rid]
    assert (stored["stage"], stored["failure_reason"]) == ("completed", None)
    assert stored["result"] == {"outcome": "ready", "knowledge": FRESH_SERVED, "warnings": warnings}
    assert stored["finished_at"] is not None
    assert stored["lease_expires_at"] is None


@pytest.mark.parametrize("exit_status", [0, EXIT])
async def test_r13_1_5_a_failed_record_decides_whatever_the_exit(world, exit_status):
    """A valid `failed` record ends the row `failed` with its reason, not `worker_error`. (R13-1.5)"""
    _, stored, _ = await _readiness(world, failed("handover"), exit=exit_status)
    assert (stored["stage"], stored["failure_reason"], stored["result"]) == ("failed", "handover", None)
    assert stored["failure_message"]


async def test_r13_1_5_a_nonzero_exit_with_no_record_is_worker_error_naming_the_exit(world):
    """No record and a helper that failed: `worker_error`, with the status in our words. (R13-1.5)"""
    rid, stored, _ = await _readiness(world, None, exit=EXIT)
    assert (stored["stage"], stored["failure_reason"]) == ("failed", "worker_error")
    assert _names_code(stored, rid, EXIT)


@pytest.mark.parametrize("kind", ["readiness", "adoption"])
async def test_r13_1_5_exit_zero_with_no_record_is_no_record(world, kind):
    """The helper served the job to its end and left nothing: `no_record`. (R13-1.5)"""
    _, stored, _ = await (_readiness(world, None) if kind == "readiness" else _adoption(world, None))
    assert (stored["stage"], stored["failure_reason"], stored["result"]) == ("failed", "no_record", None)


async def test_r13_1_5_adoption_nonzero_exit_with_no_record_is_worker_error(world):
    """Adoption reads its record the same way. (R13-1.5)"""
    _, stored, _ = await _adoption(world, None, exit=EXIT)
    assert (stored["stage"], stored["failure_reason"]) == ("failed", "worker_error")


async def test_r13_1_5_each_kind_is_launched_with_its_own_command_and_the_request_id(world):
    """A readiness row runs `readiness_argv` and an adoption row `adoption_argv`, each handed its request, tenant and, for
    adoption, the system. (R13-6, surface §4)"""
    r_child, a_child = host_child(world, "r", files={READINESS: ready()}), host_child(world, "a", files={ADOPTION: adopted("nothing_to_adopt")})
    async with job_store(world["dsn"]) as store:
        r, _ = await store.create_readiness(T1, actor="u")
        a, _ = await store.create_adoption(T1, SYSTEM, actor="u")
        await host_worker(world, store, readiness=r_child, adoption=a_child).drain()
    assert [(launch.request_id, launch.tenant_id) for launch in r_child.launches] == [(r.request_id, T1)]
    assert [(launch.request_id, launch.tenant_id, launch.system_id) for launch in a_child.launches] == [
        (a.request_id, T1, SYSTEM)]
    assert [host_row(world["dsn"], i)["stage"] for i in (r.request_id, a.request_id)] == ["completed", "completed"]


def test_r13_6_the_real_argv_functions_build_the_helpers_command_for_each_kind():
    """`readiness_argv` and `adoption_argv` give exactly the helper command of surface §4, `--system` for adoption only.
    (R13-6, surface §4)"""
    import sys

    from defender.worker import AdoptionLaunch, ReadinessLaunch, adoption_argv, readiness_argv

    base = [sys.executable, "-m", "defender.job_host"]
    assert readiness_argv(ReadinessLaunch("req-1", T1, 4242)) == [
        *base, "--kind", "readiness", "--job", "req-1", "--tenant", T1, "--parent-pid", "4242"]
    assert adoption_argv(AdoptionLaunch("req-2", T1, 4242, SYSTEM)) == [
        *base, "--kind", "adoption", "--job", "req-2", "--tenant", T1, "--parent-pid", "4242", "--system", SYSTEM]


# --- readiness validation -----------------------------------------------------------------------------------------------

MARKUP = 'system "a<b>&c" is not a well-formed name'


async def test_d7_a_sentence_holding_markup_is_stored_byte_for_byte(world):
    """A record's sentence with `<`, `&` and `"` is stored unchanged: no escaping, stripping or rewriting; escaping is the page's. (D7, P-2)"""
    _, stored, _ = await _readiness(world, refused("tenant", MARKUP))
    assert stored["stage"] == "completed"
    assert stored["result"]["sentence"] == MARKUP


@pytest.mark.parametrize("step", STEPS_WITHOUT_KNOWLEDGE)
async def test_r13_1_5_a_refusal_before_the_publish_carries_no_knowledge_and_the_knowledge_record_is_not_read(world, step):
    """Refused at a step up to `publish`: completed, `knowledge` null, even beside a malformed knowledge record. (R3, R13-1.5)"""
    _, stored, _ = await _readiness(world, refused(step, "the tenant is not active"), "{not json")
    assert stored["stage"] == "completed"
    assert stored["result"] == {"outcome": "refused", "step": step, "sentence": "the tenant is not active",
                                "knowledge": None}


@pytest.mark.parametrize("step", STEPS_WITH_KNOWLEDGE)
async def test_r13_1_5_a_refusal_after_the_publish_carries_the_knowledge_record(world, step):
    """Refused at a later step, a container step included: the knowledge record's status rides on the result. (R3, R13-1.5)"""
    _, stored, _ = await _readiness(world, refused(step, "no usable system"), STALE_OPERATOR)
    assert stored["stage"] == "completed"
    assert stored["result"] == {"outcome": "refused", "step": step, "sentence": "no usable system",
                                "knowledge": STALE_OPERATOR_SERVED}


@pytest.mark.parametrize("record", [ready(), refused("systems")], ids=["ready", "refused-at-systems"])
async def test_r13_1_5_an_absent_knowledge_record_where_it_is_carried_is_bad_record(world, record):
    """`ready` or a late refusal with no knowledge record fails `bad_record`. (R13-1.5)"""
    _, stored, _ = await _readiness(world, record, None)
    _bad(stored)


@pytest.mark.parametrize("text", MALFORMED_KNOWLEDGE)
@pytest.mark.parametrize("record", [ready(), refused("first_pass")], ids=["ready", "refused-at-first_pass"])
async def test_r13_1_5_a_malformed_knowledge_record_where_it_is_carried_is_bad_record(world, record, text):
    """Any text at the knowledge path that is not a status fails `bad_record`. (R13-1.5)"""
    _, stored, _ = await _readiness(world, record, text)
    _bad(stored)


@pytest.mark.parametrize("record", [failed("handover"), failed("census_unavailable")])
async def test_r13_1_5_a_failed_record_never_reads_the_knowledge_record(world, record):
    """A malformed knowledge record beside a `failed` record changes nothing. (R13-1.5)"""
    _, stored, _ = await _readiness(world, record, "{not json")
    assert stored["failure_reason"] == json.loads(record)["reason"]


@pytest.mark.parametrize("kind", WARNING_KINDS)
async def test_r13_4_every_warning_kind_is_accepted_and_kept_in_order(world, kind):
    """Each closed warning kind passes, with its sentence. (P-2, R4)"""
    warnings = [warning("system_down", "first"), warning(kind, f"a {kind} sentence")]
    _, stored, _ = await _readiness(world, ready(warnings), FRESH)
    assert stored["result"]["warnings"] == warnings


@pytest.mark.parametrize("reason", [*READINESS_HELPER_REASONS, *READINESS_CONTAINER_REASONS])
async def test_r13_1_every_readiness_reason_ends_the_row_failed_with_that_reason_and_our_words(world, reason):
    """Closed helper and container reasons become `failure_reason`; the message is the worker's, never record text. (R13-1.2, .3)"""
    _, stored, _ = await _readiness(world, failed(reason))
    assert (stored["stage"], stored["failure_reason"], stored["result"]) == ("failed", reason, None)
    assert stored["failure_message"]


_BAD_READINESS = {
    "unknown-step": refused("systems_check"),
    "runs-folder-is-no-step": refused("runs_folder"),
    "step-in-other-case": refused("Tenant"),
    "step-with-space": refused("tenant "),
    "empty-sentence": refused("tenant", ""),
    "sentence-not-text": json.dumps({"outcome": "refused", "step": "tenant", "sentence": 7}),
    "missing-sentence": json.dumps({"outcome": "refused", "step": "tenant"}),
    "refused-with-knowledge": refused("systems", "s", knowledge={"status": "current", "commit": COMMIT,
                                                                  "stale_kind": None}),
    "refused-with-commit": refused("systems", "s", commit=COMMIT),
    "ready-with-commit": ready(commit=COMMIT),
    "ready-with-knowledge": ready(knowledge={"status": "current", "commit": COMMIT, "stale_kind": None}),
    "ready-warnings-not-a-list": json.dumps({"outcome": "ready", "warnings": {"kind": "case_system"}}),
    "ready-without-warnings": json.dumps({"outcome": "ready"}),
    "warning-unknown-kind": ready([warning("census_gap")]),
    "warning-kind-in-other-case": ready([warning("Case_System")]),
    "warning-empty-sentence": ready([warning("case_system", "")]),
    "warning-extra-key": ready([{"kind": "case_system", "sentence": "s", "detail": "d"}]),
    "warning-not-an-object": ready(["case_system"]),
    "unknown-outcome": json.dumps({"outcome": "skipped"}),
    "failed-unknown-reason": failed("lease_lapsed"),
    "failed-worker-written-reason": failed("bad_record"),
    "failed-adoption-reason": failed("system_gone"),
    "failed-reason-in-other-case": failed("Handover"),
    "failed-with-a-sentence": failed("handover", sentence="s"),
    "failed-without-reason": json.dumps({"outcome": "failed"}),
    "not-an-object": "[]",
    "empty-file": "",
    "truncated": '{"outcome": "ready", "warn',
    "refused-step-null": json.dumps({"outcome": "refused", "step": None, "sentence": "s"}),
}


@pytest.mark.parametrize("record", list(_BAD_READINESS.values()), ids=list(_BAD_READINESS))
async def test_p2_a_readiness_record_outside_its_shapes_is_bad_record_naming_none_of_its_text(world, record):
    """Anything but the surface's exact shapes fails `bad_record` with the worker's words only, even with a valid
    knowledge record present. (P-2, R13-1.5)"""
    _, stored, _ = await _readiness(world, record, FRESH)
    _bad(stored)


async def test_p2_the_sentence_a_valid_record_carries_is_kept_verbatim_and_never_in_a_failure(world):
    """Control for the class above: a valid refusal carrying `MARK` completes and keeps it; a bad one never does. (P-2)"""
    _, kept, _ = await _readiness(world, refused("systems", f"no usable system {MARK}"), FRESH)
    assert kept["result"]["sentence"] == f"no usable system {MARK}"
    _, dropped, _ = await _readiness(world, refused("nope", f"no usable system {MARK}"), FRESH)
    _bad(dropped)


# --- R13-4: one cap over the whole record's text ---------------------------------------------------------------------

def _cap() -> int:
    from defender.records import job_lane

    return job_lane.READINESS_RECORD_TEXT_CAP_BYTES


async def test_r13_4_one_sentence_over_the_cap_is_bad_record(world):
    """A refusal whose sentence alone exceeds the cap fails `bad_record`. (R13-4)"""
    _, stored, _ = await _readiness(world, refused("systems", MARK + "x" * _cap()), FRESH)
    _bad(stored)


async def test_r13_4_the_cap_covers_the_whole_record_not_each_sentence(world):
    """Warnings each far under the cap but together over it fail; a large one alone under the cap, and very many small
    ones under it together, complete: no per-sentence cap and none on the count. (R13-4)"""
    cap = _cap()
    over = [warning("system_down", MARK + "y" * (cap // 3)) for _ in range(4)]
    _, stored, _ = await _readiness(world, ready(over), FRESH)
    _bad(stored)
    one_big = [warning("system_down", "z" * (cap // 2))]
    _, big, _ = await _readiness(world, ready(one_big), FRESH)
    assert big["stage"] == "completed"
    assert big["result"]["warnings"] == one_big
    many = [warning("tacit_registry", f"problem {n}") for n in range(300)]
    _, plenty, _ = await _readiness(world, ready(many), FRESH)
    assert plenty["stage"] == "completed"
    assert len(plenty["result"]["warnings"]) == 300


async def test_r13_4_a_helpers_refusal_is_under_the_same_cap(world):
    """The cap covers every readiness record, whichever step it refuses at. (R13-4)"""
    _, stored, _ = await _readiness(world, refused("tenant", "w" * (_cap() + 1)))
    _bad(stored)


# --- adoption validation ------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("outcome", ADOPTION_OUTCOMES)
async def test_a3_each_adoption_outcome_completes_with_its_number_exactly_where_it_has_one(world, outcome):
    """The four outcomes complete; the number is an integer for `opened`, `already_open`, `rejected`, null otherwise. (A3)"""
    number = 41 if outcome in WITH_NUMBER else None
    _, stored, _ = await _adoption(world, adopted(outcome, number))
    assert (stored["stage"], stored["failure_reason"]) == ("completed", None)
    assert stored["result"] == {"outcome": outcome, "pr_number": number}


@pytest.mark.parametrize("reason", ADOPTION_REASONS)
async def test_a3_every_adoption_reason_ends_the_row_failed_with_it(world, reason):
    """Closed helper and container reasons become `failure_reason`. (A3, R13-1.2, §9 addendum)"""
    _, stored, _ = await _adoption(world, failed(reason))
    assert (stored["stage"], stored["failure_reason"], stored["result"]) == ("failed", reason, None)
    assert stored["failure_message"]


_BAD_ADOPTION = {
    "opened-without-number": adopted("opened", None),
    "already-open-without-number": adopted("already_open", None),
    "rejected-without-number": adopted("rejected", None),
    "nothing-with-number": adopted("nothing_to_adopt", 3),
    "number-as-text": adopted("opened", "12"),
    "number-as-float": adopted("opened", 1.5),
    "number-as-bool": adopted("opened", True),
    "number-as-list": adopted("opened", [12]),
    "number-missing": json.dumps({"outcome": "opened"}),
    "unknown-outcome": adopted("merged", 4),
    "outcome-in-other-case": adopted("Opened", 4),
    "extra-key": adopted("opened", 4, pr_url="http://x"),
    "failed-unknown-reason": failed("census_unavailable"),
    "failed-worker-written-reason": failed("no_record"),
    "failed-with-text": failed("handover", message="m"),
    "not-an-object": "[1]",
    "empty-file": "",
    "truncated": '{"outcome": "opened", "pr_n',
}


@pytest.mark.parametrize("record", list(_BAD_ADOPTION.values()), ids=list(_BAD_ADOPTION))
async def test_a3_an_adoption_record_outside_its_shapes_is_bad_record(world, record):
    """Unknown outcome or reason, a number where none belongs or none where one does, a non-integer, extra keys: `bad_record`. (A3, P-2)"""
    _, stored, _ = await _adoption(world, record)
    _bad(stored)


async def test_a3_the_kinds_records_are_read_from_their_own_files(world):
    """A readiness record beside an adoption request, and the reverse, is no record. (R13-1.5)"""
    _, adoption, _ = await _run(world, "adoption", {READINESS: ready()})
    assert adoption["failure_reason"] == "no_record"
    _, readiness, _ = await _run(world, "readiness", {ADOPTION: adopted("nothing_to_adopt")})
    assert readiness["failure_reason"] == "no_record"


async def test_a3_an_adoption_never_reads_a_knowledge_record(world):
    """A malformed knowledge record beside a valid adoption record is ignored. (R13-1.5)"""
    _, stored, _ = await _run(world, "adoption", {ADOPTION: adopted("opened", 5), KNOWLEDGE: "{not json"})
    assert stored["stage"] == "completed"


# --- R13-1.1: the lane is opened before any helper starts ------------------------------------------------------------

@pytest.mark.parametrize("kind", ["readiness", "adoption"])
async def test_r13_1_1_an_unusable_runs_container_ends_the_row_worker_error_with_no_helper_started(world, kind):
    """With `<T>/runs` gone, the request fails `worker_error` in the investigation's words and nothing is started; with it
    back, the same request runs. (R13-1.1)"""
    shutil.rmtree(world["runs"])
    files = {READINESS: ready(), KNOWLEDGE: FRESH} if kind == "readiness" else {ADOPTION: adopted("nothing_to_adopt")}
    _, stored, child = await _run(world, kind, files)
    assert (stored["stage"], stored["failure_reason"], stored["result"]) == ("failed", "worker_error", None)
    assert "the tenant's runs container cannot be used on this host" in stored["failure_message"]
    assert child.launches == []
    assert child.events() == [], "a helper was started over an unusable lane"
    assert not world["runs"].exists(), "the worker made the runs folder"
    world["runs"].mkdir()
    _, again, ran = await _run(world, kind, files)
    assert again["stage"] == "completed"
    assert len(ran.started()) == 1


async def test_r13_1_1_the_words_are_the_investigations_own(world):
    """An investigation over the same damage fails with the message a host request gets. (R13-1.1)"""
    shutil.rmtree(world["runs"])
    async with job_store(world["dsn"]) as store:
        inv = await _queued(store)
        await host_worker(world, store).drain()
    investigation = row(world["dsn"], inv)
    _, hosted, _ = await _readiness(world, ready(), FRESH)
    assert investigation["failure_message"] == hosted["failure_message"]


# --- R13-6: one shared cap, oldest first ----------------------------------------------------------------------------

async def test_r13_6_by_default_one_host_request_runs_at_a_time_oldest_first_across_kinds(world):
    """Three queued requests of both kinds run one by one in the order they were made; the others stay queued while one
    runs. (R13-6)"""
    dsn = world["dsn"]
    release = world["tmp"] / "release"
    child = host_child(world, files={READINESS: ready(), KNOWLEDGE: FRESH, ADOPTION: adopted("nothing_to_adopt")},
                       wait_for=release)
    async with job_store(dsn) as store:
        a, _ = await store.create_adoption(T1, SYSTEM, actor="u")
        r, _ = await store.create_readiness(T1, actor="u")
        a2, _ = await store.create_adoption(T1, "elastic", actor="u")
        for n, rid in enumerate((a.request_id, r.request_id, a2.request_id)):
            set_created(dsn, rid, NOW.replace(minute=n))
        serving = asyncio.create_task(host_worker(world, store, child, **_FAST).serve())
        try:
            await _until(lambda: child.started(), "the first child")
            await asyncio.sleep(1.0)
            assert child.started() == [a.request_id], "a second host request started beside the first"
            assert [x["stage"] for x in host_rows(dsn)].count("queued") == 2
            release.touch()
            await _until(lambda: {x["stage"] for x in host_rows(dsn)} == {"completed"}, "all three to complete")
        finally:
            if not serving.done():
                os.kill(os.getpid(), signal.SIGTERM)
            await asyncio.wait_for(serving, timeout=60)
    assert child.started() == [a.request_id, r.request_id, a2.request_id]
    assert child.max_alive() == 1


async def test_r13_6_host_request_slots_is_the_cap_shared_by_both_kinds(world):
    """With `host_request_slots=2`, two requests run at once, of either kind, and the third waits. (R13-6)"""
    dsn = world["dsn"]
    release = world["tmp"] / "release"
    child = host_child(world, files={READINESS: ready(), KNOWLEDGE: FRESH, ADOPTION: adopted("nothing_to_adopt")},
                       wait_for=release)
    async with job_store(dsn) as store:
        ids = []
        for n, make in enumerate((store.create_readiness(T1, actor="u"), store.create_adoption(T1, SYSTEM, actor="u"),
                                  store.create_adoption(T1, "elastic", actor="u"))):
            rec, _ = await make
            set_created(dsn, rec.request_id, NOW.replace(minute=n))
            ids.append(rec.request_id)
        serving = asyncio.create_task(host_worker(world, store, child, host_request_slots=2, **_FAST).serve())
        try:
            await _until(lambda: len(child.started()) == 2, "two children")
            await asyncio.sleep(1.0)
            assert child.started() == ids[:2], "the third started, or the first two were not the oldest"
            release.touch()
            await _until(lambda: {x["stage"] for x in host_rows(dsn)} == {"completed"}, "all three")
        finally:
            if not serving.done():
                os.kill(os.getpid(), signal.SIGTERM)
            await asyncio.wait_for(serving, timeout=60)
    assert child.max_alive() == 2


async def test_r13_6_host_requests_run_outside_the_total_slots_in_both_directions(world):
    """With one total slot taken by a running investigation a host request still runs, and a running host request does
    not keep a queued investigation from a slot. (R13-6)"""
    dsn = world["dsn"]
    release = world["tmp"] / "release-inv"
    blocking = _child(world, wait_for=release, files={})
    host = host_child(world, files={READINESS: ready(), KNOWLEDGE: FRESH})
    async with job_store(dsn) as store:
        inv = await _queued(store)
        rec, _ = await store.create_readiness(T1, actor="u")
        serving = asyncio.create_task(host_worker(world, store, host, investigation=blocking, slots=1, **_FAST).serve())
        try:
            await _until(lambda: blocking.seen(inv), "the investigation's child")
            await _until(lambda: host_row(dsn, rec.request_id)["stage"] == "completed", "the host request beside it")
            assert row(dsn, inv)["stage"] == "running"
        finally:
            release.touch()
            await _until(lambda: row(dsn, inv)["stage"] != "running", "the investigation to end")
            if not serving.done():
                os.kill(os.getpid(), signal.SIGTERM)
            await asyncio.wait_for(serving, timeout=60)

    hold = world["tmp"] / "release-host"
    slow_host = host_child(world, "slow", files={READINESS: ready(), KNOWLEDGE: FRESH}, wait_for=hold)
    quick = _child(world, files={})
    async with job_store(dsn) as store:
        rec, _ = await store.create_readiness(T1, actor="u")
        inv2 = await _queued(store, ticket="T-2", key="k2")
        serving = asyncio.create_task(host_worker(world, store, slow_host, investigation=quick, slots=1, **_FAST).serve())
        try:
            await _until(lambda: slow_host.started(), "the host request's child")
            await _until(lambda: quick.seen(inv2), "the investigation beside a running host request")
        finally:
            hold.touch()
            await _until(lambda: host_row(dsn, rec.request_id)["stage"] != "running", "the host request to end")
            if not serving.done():
                os.kill(os.getpid(), signal.SIGTERM)
            await asyncio.wait_for(serving, timeout=60)


@pytest.mark.parametrize("bad", [0, -1])
async def test_r13_6_a_worker_with_a_host_request_cap_below_one_is_refused(world, bad):
    """`Worker(host_request_slots=<1)` raises `ValueError` naming the setting; 1 builds. (R13-6)"""
    async with job_store(world["dsn"]) as store:
        host_worker(world, store, host_request_slots=1)
        with pytest.raises(ValueError, match="at least one host-request slot"):
            host_worker(world, store, host_request_slots=bad)


@pytest.mark.parametrize(("raw", "refused_start"), [("0", True), ("-2", True), ("1", False), ("4", False)])
def test_r13_6_the_start_refuses_a_cap_below_one_and_reads_the_rest(tmp_path, raw, refused_start):
    """`DEFENDER_WORKER_HOST_REQUEST_SLOTS` below 1 refuses the start naming it; otherwise it is `Settings.host_request_slots`. (R13-6)"""
    from defender.worker import WorkerStartRefused
    from defender.worker._start import read_settings

    base = {"DEFENDER_API_FRONTEND_ORIGIN": "https://app.defender.test", "DEFENDER_BUILD_COMMIT": COMMIT,
            "DEFENDER_DATABASE_DSN": "postgresql://x@localhost/x", "DEFENDER_DATA_ROOT": str(tmp_path)}
    if refused_start:
        with pytest.raises(WorkerStartRefused, match="DEFENDER_WORKER_HOST_REQUEST_SLOTS"):
            read_settings({**base, "DEFENDER_WORKER_HOST_REQUEST_SLOTS": raw})
    else:
        assert read_settings({**base, "DEFENDER_WORKER_HOST_REQUEST_SLOTS": raw}).host_request_slots == int(raw)
    assert read_settings(base).host_request_slots == 1, "the default is one"


# --- R13-5: stop and take-over ------------------------------------------------------------------------------------------

@pytest.mark.parametrize("kind", ["readiness", "adoption"])
async def test_r13_5_a_stopping_worker_ends_the_request_it_holds_worker_stopped_not_handed_back(world, kind):
    """SIGTERM while a helper runs with no record: the row is `failed`/`worker_stopped`, finished, lease cleared, never
    `running` or queued again. (R13-5, B2)"""
    dsn = world["dsn"]
    child = host_child(world, term="mark", term_mark=str(world["tmp"] / "termed"), wait_for=world["tmp"] / "never")
    async with job_store(dsn) as store:
        rec, _ = await (store.create_readiness(T1, actor="u") if kind == "readiness"
                        else store.create_adoption(T1, SYSTEM, actor="u"))
        serving = asyncio.create_task(host_worker(world, store, child, **_FAST).serve())
        try:
            await _until(lambda: child.started(), "the child")
        finally:
            if not serving.done():
                os.kill(os.getpid(), signal.SIGTERM)
            await asyncio.wait_for(serving, timeout=60)
    stored = host_row(dsn, rec.request_id)
    assert (stored["stage"], stored["failure_reason"], stored["result"]) == ("failed", "worker_stopped", None)
    assert stored["failure_message"]
    assert stored["finished_at"] is not None
    assert stored["lease_expires_at"] is None
    assert [x["stage"] for x in host_rows(dsn)] == ["failed"], "a retry row was made"


@pytest.mark.parametrize(("record", "stage", "reason"), [
    pytest.param(ready(), "completed", None, id="ready"),
    pytest.param(failed("handover"), "failed", "handover", id="failed-record"),
])
async def test_r13_5_a_valid_record_present_once_the_child_has_ended_wins_over_the_stop(world, record, stage, reason):
    """The child records as the SIGTERM lands: the record stands. (R13-5)"""
    dsn = world["dsn"]
    child = host_child(world, files={READINESS: record, KNOWLEDGE: FRESH}, term="finish",
                       term_mark=str(world["tmp"] / "termed"), wait_for=world["tmp"] / "never")
    async with job_store(dsn) as store:
        rec, _ = await store.create_readiness(T1, actor="u")
        serving = asyncio.create_task(host_worker(world, store, child, **_FAST).serve())
        try:
            await _until(lambda: child.started(), "the child")
        finally:
            if not serving.done():
                os.kill(os.getpid(), signal.SIGTERM)
            await asyncio.wait_for(serving, timeout=60)
    stored = host_row(dsn, rec.request_id)
    assert (stored["stage"], stored["failure_reason"]) == (stage, reason)


async def test_r13_5_a_request_claimed_but_not_yet_started_is_ended_worker_stopped_too(world):
    """A stop landing while the child is still being spawned ends the held row `worker_stopped`. (R13-5)"""
    dsn = world["dsn"]
    gate = asyncio.Event()
    entered = asyncio.Event()

    async def stuck_spawn(*_a, **_kw):
        entered.set()
        await gate.wait()
        raise AssertionError("the spawn was let through")

    child = host_child(world)
    async with job_store(dsn) as store:
        rec, _ = await store.create_readiness(T1, actor="u")
        serving = asyncio.create_task(host_worker(world, store, child, spawn=stuck_spawn, **_FAST).serve())
        try:
            await asyncio.wait_for(entered.wait(), timeout=30)
            assert host_row(dsn, rec.request_id)["stage"] == "running", "premise: claimed"
        finally:
            if not serving.done():
                os.kill(os.getpid(), signal.SIGTERM)
            await asyncio.wait_for(serving, timeout=60)
            gate.set()
    stored = host_row(dsn, rec.request_id)
    assert (stored["stage"], stored["failure_reason"]) == ("failed", "worker_stopped")
    assert child.launches == [] or child.events() == []


@pytest.mark.parametrize("kind", ["readiness", "adoption"])
async def test_r13_5_a_lapsed_row_of_a_lost_worker_is_taken_over_by_a_serving_worker_worker_lost(world, kind):
    """A row some other worker claimed and lost ends `worker_lost` on a serving worker's pass, with no retry. (R13-5, B2)"""
    dsn = world["dsn"]
    child = host_child(world)
    async with job_store(dsn) as store:
        rec, _ = await (store.create_readiness(T1, actor="u") if kind == "readiness"
                        else store.create_adoption(T1, SYSTEM, actor="u"))
        assert (await store.claim_host_request()).record.request_id == rec.request_id
        lapse(dsn, rec.request_id)
        serving = asyncio.create_task(host_worker(world, store, child, **_FAST).serve())
        try:
            await _until(lambda: host_row(dsn, rec.request_id)["stage"] != "running", "the take-over")
        finally:
            if not serving.done():
                os.kill(os.getpid(), signal.SIGTERM)
            await asyncio.wait_for(serving, timeout=60)
    stored = host_row(dsn, rec.request_id)
    assert (stored["stage"], stored["failure_reason"]) == ("failed", "worker_lost")
    assert len(host_rows(dsn)) == 1
    assert child.started() == []


# --- leases and fences: written once for both kinds ------------------------------------------------------------------

async def test_b2_a_running_host_request_keeps_its_lease_renewed(world):
    """While the helper runs, the worker renews the row's lease. (claim and renewal for all kinds)"""
    dsn = world["dsn"]
    release = world["tmp"] / "release"
    child = host_child(world, files={READINESS: ready(), KNOWLEDGE: FRESH}, wait_for=release)
    async with job_store(dsn, lease=2) as store:
        rec, _ = await store.create_readiness(T1, actor="u")
        serving = asyncio.create_task(host_worker(world, store, child, **_FAST).serve())
        try:
            await _until(lambda: child.started(), "the child")
            await asyncio.sleep(4.5)  # past two leases: only renewal keeps it
            left = lease_left(dsn, rec.request_id)
            assert host_row(dsn, rec.request_id)["stage"] == "running"
            assert left is not None
            assert left > 0, "the lease lapsed under a live helper"
            release.touch()
            await _until(lambda: host_row(dsn, rec.request_id)["stage"] == "completed", "the end")
        finally:
            if not serving.done():
                os.kill(os.getpid(), signal.SIGTERM)
            await asyncio.wait_for(serving, timeout=60)


@pytest.mark.parametrize("kind", ["readiness", "adoption"])
async def test_b1_a_request_ended_by_offboarding_while_its_helper_runs_keeps_that_ending_and_the_child_is_ended(world, kind):
    """The fence: the row moved under a running helper is not written over, and its child is ended. (B1, fenced finish)"""
    dsn = world["dsn"]
    child = host_child(world, files={READINESS: ready(), KNOWLEDGE: FRESH, ADOPTION: adopted("opened", 3)},
                       term="mark", term_mark=str(world["tmp"] / "termed"), wait_for=world["tmp"] / "never")
    async with job_store(dsn) as store:
        rec, _ = await (store.create_readiness(T1, actor="u") if kind == "readiness"
                        else store.create_adoption(T1, SYSTEM, actor="u"))
        serving = asyncio.create_task(host_worker(world, store, child, **_FAST).serve())
        try:
            await _until(lambda: child.started(), "the child")
            await store.offboard_tenant(T1, actor="op")
            await _until(lambda: (world["tmp"] / "termed").exists(), "the fenced child to be signalled")
        finally:
            if not serving.done():
                os.kill(os.getpid(), signal.SIGTERM)
            await asyncio.wait_for(serving, timeout=60)
    stored = host_row(dsn, rec.request_id)
    assert (stored["stage"], stored["failure_reason"], stored["result"]) == ("failed", "tenant_offboarded", None)


async def test_b2_a_failed_request_is_not_retried_by_a_later_worker(world):
    """A row that ended `failed` is claimed by no later pass; the next request is a new row. (B2)"""
    _, stored, child = await _readiness(world, None, exit=EXIT)
    assert stored["stage"] == "failed"
    async with job_store(world["dsn"]) as store:
        await host_worker(world, store, child).drain()
    assert len(child.started()) == 1
    assert len(host_rows(world["dsn"])) == 1
