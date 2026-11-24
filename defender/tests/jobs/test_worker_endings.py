"""#1342 O8: the worker's ending rules 1-5, one case per branch, through the real worker. #1546 (A-O2, PR2, PR9): the
worker decides from the facts the helper staged, so the `ScriptedChild` plays the helper and stages the `outcome` its
job-end record and closing lookup stand for (`_jobs1342.facts_of_records`); the files it leaves are decoys. The worker's
parse of a job-end record (malformed words, junk characters, out-of-vocabulary `cut_short`) retired with it: the helper
stages such a record `refused/outcome` (`test_1546_helper_records.py`). Shared setup: `_worker1342`."""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
from types import SimpleNamespace

import pytest

from defender.records import job_lane, run_end
from defender import _vocab
from defender.tests.support.evidence._facts1546 import LAUNCH_ALERT, LAUNCH_BOX_TOKEN, LAUNCH_DIGEST, LAUNCH_LABEL
from defender.tests.support.jobs._jobs1342 import launch_facts
from defender.tests.support.jobs._jobs1342 import (
    CLOSING_KEY,
    NOW,
    T1,
    T2,
    WORKER_LOGGER,
    an_alert,
    is_box_token,
    job_end,
    job_store,
)
from defender.tests.support.jobs._worker1342 import (
    CASES,
    MARKER,
    _helper_child as _child,
    _committed,
    closing,
    _job_end_with,
    _names_code,
    _no_run_text,
    _run_one,
)
from defender.tests.support.jobs import _worker1342 as _shared

pytestmark = [pytest.mark.anyio, pytest.mark.postgres]
# The shared fixtures, bound in this module so pytest finds them here (an import of `world` would be shadowed by
# every test's parameter of that name).
world = _shared.world
_no_database_address_in_the_workers_environment = _shared._no_database_address_in_the_workers_environment


@pytest.mark.parametrize("case", list(CASES))
async def test_o8_the_stage_comes_from_the_staged_outcome_and_never_the_report(world, caplog, case):
    """Rules 1-5: stage, reason and disposition from the staged `outcome` (#1546 PR9: `decide` over the rows), never the
    report the child leaves; no run text reaches the row. (O8)"""
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


def _job_end_cut_short(cut_short: str, *, report_committed: bool, scrub_verified: bool) -> str:
    """The job-end facts with the fifth set (#1421), which the stand-in helper stages as the `outcome`."""
    return job_end(report_committed=report_committed, scrub_verified=scrub_verified, cut_short=cut_short)


def test_p1_r7_3_a_job_end_record_is_exactly_its_five_facts_and_names_no_spend_fact():
    """CONFLICT-UPDATED (r7.3 T1; was r5 P1: the five old keys parse as `spend_write_failed=False`): the record the host writes
    has the five facts and parses; a missing or an extra key does not. (r7.3 T1; P1)"""
    five = json.loads(job_end())
    assert sorted(five) == ["box", "cut_short", "report_committed", "scrub_verified", "setup"], "premise: the five keys"
    parsed = job_lane.JobEnd.parse(json.dumps(five))
    assert parsed is not None
    assert json.loads(parsed.text()) == five, "the record writes keys the host's fact table does not have, or drops one"
    for unreadable in (_job_end_with(extra="x"), _job_end_with(cut_short=None), _job_end_with(scrub_verified=None)):
        assert job_lane.JobEnd.parse(unreadable) is None, unreadable


_CUT_SHORT_WORDS = sorted({*run_end.TRUNCATED_BY_VALUES, "box-lost", "box-output-limit", "proxy-access"})  # #1363 B6: named, not only derived


@pytest.mark.parametrize(("cut_short", "verified"), [(word, True) for word in _CUT_SHORT_WORDS] + [
    ("box-lost", False),  # the scrub also did not verify
])
async def test_o8_o9_a_failed_jobs_message_names_its_class_beside_the_existing_words(world, cut_short, verified):
    """Fixed words, `no_report`, not decided by the run, so a worker stop re-queues. (O8, O9)"""
    record = _job_end_cut_short(cut_short, report_committed=False, scrub_verified=verified)
    _inv, stored = await _run_one(world, _child(world, exit=5, printed=MARKER, files={"{id}.job-end.json": record}))
    assert (stored["stage"], stored["failure_reason"]) == ("failed", "no_report")
    assert cut_short in stored["failure_message"], stored["failure_message"]
    assert "the host committed no report" in stored["failure_message"], stored["failure_message"]
    _no_run_text(stored)


async def test_o8_a_committed_and_verified_report_still_completes_when_the_box_was_lost_after(world):
    """The model had closed: the job reads as completed whatever the run's exit was. (O8)"""
    record = _job_end_cut_short("box-lost", report_committed=True, scrub_verified=True)
    _inv, stored = await _run_one(world, _child(world, exit=5, files=_committed(**{"{id}.job-end.json": record})))
    assert (stored["stage"], stored["failure_reason"]) == ("completed", None)


async def test_o8_a_model_closed_run_whose_teardown_faulted_reads_as_failed_and_names_the_class(world):
    """The accepted cost: closed, then no proof the box died, so a failed job naming the class. (O8)"""
    record = _job_end_cut_short("box-lost", report_committed=True, scrub_verified=False)
    _inv, stored = await _run_one(world, _child(world, exit=5, files=_committed(**{"{id}.job-end.json": record})))
    assert (stored["stage"], stored["failure_reason"]) == ("failed", "no_report")
    assert "box-lost" in stored["failure_message"]


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


# --- #1534: the disposition is the run's closing record, read through the job lane -------------------------------------

@pytest.mark.parametrize("disposition", _vocab.DISPOSITION_VALUES)
async def test_1534_a_committed_run_completes_with_the_disposition_of_its_closing_record(world, disposition):
    """Every member of `DISPOSITION_VALUES` copies from the record in the database the pointer's case id names. (V-READERS, worker)"""
    inv, stored = await _run_one(world, _child(world, files=_committed(**{CLOSING_KEY: closing(disposition)})))
    assert (stored["stage"], stored["disposition"], stored["failure_reason"]) == ("completed", disposition, None), inv


@pytest.mark.parametrize("fault", ["database-missing", "recorded-before-1534", "row-invalid", "pointer-unreadable"])
async def test_1534_a_record_that_cannot_be_looked_up_is_unparseable_with_the_kinds_fixed_words(world, fault):
    """`CouldNotLook` ends the row `unparseable`, `failure_message` is `FAULT_WORDING[kind]` and no detail or path. (V-READERS, worker)"""
    from defender.records import closing as C

    _inv, stored = await _run_one(world, _child(world, printed=MARKER, files=_committed(**{CLOSING_KEY: closing(fault=fault)})))
    assert (stored["stage"], stored["disposition"]) == ("unparseable", None)
    assert C.FAULT_WORDING[fault] in (stored["failure_message"] or ""), stored["failure_message"]
    _no_run_text(stored)
    assert str(world["tmp"]) not in json.dumps(stored, default=str), "a path (the lookup's detail) reached the row"
    for other, wording in C.FAULT_WORDING.items():
        if other != fault and wording not in C.FAULT_WORDING[fault]:
            assert wording not in stored["failure_message"], f"{fault} reads as {other}"


@pytest.mark.parametrize("committed", [True, False], ids=["committed", "not-committed"])
@pytest.mark.parametrize("plan", [closing(None), closing(None, fault="no-pointer")], ids=["no-row", "no-pointer"])
async def test_1534_a_run_with_no_record_is_unparseable_when_committed_and_no_report_when_not(world, plan, committed):
    """`NeverClosed` with the report committed is `unparseable`; not committed, `failed/no_report`, as today. (V-READERS, worker)"""
    files = _committed(**{CLOSING_KEY: plan, "{id}.job-end.json": job_end(report_committed=committed)})
    _inv, stored = await _run_one(world, _child(world, files=files))
    if committed:
        from defender.records import closing as C

        assert (stored["stage"], stored["disposition"]) == ("unparseable", None)
        assert stored["failure_message"] == C.FAULT_WORDING["committed-without-record"], stored["failure_message"]
    else:
        assert (stored["stage"], stored["failure_reason"]) == ("failed", "no_report")


async def test_1534_a_record_beside_a_not_committed_job_end_is_never_read(world):
    """The job-end record decides first: a record in the database does not make an uncommitted run complete. (V-READERS, worker)"""
    _inv, stored = await _run_one(world, _child(world, files=_committed(**{
        CLOSING_KEY: closing("malicious"), "{id}.job-end.json": job_end(report_committed=False)})))
    assert (stored["stage"], stored["disposition"], stored["failure_reason"]) == ("failed", None, "no_report")
# --- #1471: the worker's half of a job's ticket write-back (P-5, W3) ---------------------------------------------
# The Worker's origin is C-6's required `frontend_origin=`; the helper's start carries the flag, the digest and the link
# as C-1's `--post-ticket`, `--alert-digest <hex>`, `--ticket-link <url>`. The tests spell the origin and pass it
# themselves, so they hold whether or not the shared `make_worker` defaults it.

ORIGIN_1471 = "https://app.defender.test"
#: `ALERT_BYTES`' fields plus the ticket the fixture mapping's `case_key` (`alert_id`) reads: a flagged create needs one (W1).
KEYED_1471 = (b'{"rule": {"id": "r-1342",  "description": "sketch"},\n'
              b' "alert_id": "SEC-1471", "alert_timestamp": "2026-10-29T00:00:00Z"}\n')
DIGEST_1471 = hashlib.sha256(KEYED_1471).hexdigest()
#: The launch facts every investigation claim carries (#1546: the launch record's names, now on the claim row; design: Claim).
LAUNCH_FIELDS = {LAUNCH_ALERT, LAUNCH_DIGEST, LAUNCH_LABEL, LAUNCH_BOX_TOKEN}


def _worker_1471(world, store, child, **kw):
    from defender.tests.support.jobs._jobs1342 import make_worker

    return make_worker(store, world["root"], child, **{"frontend_origin": ORIGIN_1471, **kw})


async def _queued_1471(store, *, update_ticket: bool, tenant: str = T1, key: str = "k1") -> str:
    alert = await an_alert(store, tenant, ticket=f"V-{key}", raw=KEYED_1471)
    inv, _ = await store.create_investigation(tenant, alert.alert_id, key, actor="u-1", update_ticket=update_ticket)
    return inv.investigation_id


def _values(argv: list[str], flag: str) -> list[str]:
    return [argv[i + 1] for i, word in enumerate(argv[:-1]) if word == flag]


class _Spawned:
    """The worker's process door: records the argv the worker built for each helper, then runs the scripted stand-in
    child for that job in its place. Fakes only inject; nothing here decides what the argv holds."""

    def __init__(self, child) -> None:
        self.child, self.argvs = child, {}

    async def __call__(self, *argv, **kw):
        argv = list(argv)
        job = _values(argv, "--job")[0]
        self.argvs[job] = argv
        stand = self.child(SimpleNamespace(investigation_id=job, tenant_id=_values(argv, "--tenant")[0],
                                           parent_pid=int(_values(argv, "--parent-pid")[0])))
        return await asyncio.create_subprocess_exec(*stand, **kw)


async def _drain_spawned(world, rows, child):
    """Queue each `(tenant, flagged, key)` row, drain a worker whose default helper argv is recorded; the ids and the door."""
    from defender.worker import run_argv

    door = _Spawned(child)
    async with job_store(world["dsn"]) as store:
        ids = [await _queued_1471(store, update_ticket=flag, tenant=tenant, key=key) for tenant, flag, key in rows]
        await _worker_1471(world, store, run_argv, spawn=door).drain()
    return ids, door


async def test_1471_p5_each_helper_is_started_with_its_own_flag_digest_and_link(world):
    """The helper's argv carries `--post-ticket` and `--ticket-link <origin>/t/<tenant>/investigations/<id>` only for a
    flagged row, `--alert-digest` always, each row its own tenant and id. (P-5 worker side, W3)"""
    rows = [(T1, True, "k1"), (T1, False, "k2"), (T2, True, "k3")]
    ids, door = await _drain_spawned(world, rows, _child(world, exit=0, files=_committed()))

    assert sorted(door.argvs) == sorted(ids), "premise: every row's helper was started"
    for inv, (tenant, flagged, _key) in zip(ids, rows, strict=True):
        argv = door.argvs[inv]
        assert ("--post-ticket" in argv) is flagged, (inv, argv)
        assert _values(argv, "--alert-digest") == [DIGEST_1471], (inv, argv)
        assert _values(argv, "--ticket-link") == ([f"{ORIGIN_1471}/t/{tenant}/investigations/{inv}"] if flagged else []), (inv, argv)
        assert _values(argv, "--tenant") == [tenant]
        assert _values(argv, "--job") == [inv]


def _masked_facts(facts: dict, tenant: str, inv: str) -> str:
    """A claim's launch facts as sorted JSON, its own row, alert, box token and tenant masked."""
    text = json.dumps(facts, sort_keys=True)
    for n, value in enumerate([inv, facts[LAUNCH_ALERT], facts[LAUNCH_BOX_TOKEN], tenant]):
        text = text.replace(value, f"<v{n}>")
    return text


async def test_1471_p5_a_flagged_rows_tenant_folder_and_launch_facts_change_exactly_as_an_unflagged_rows_do(world):
    """UPDATED (#1546 census: the launch record beside the run -> the claim row, whose launch facts the helper copies for
    the job; design: Claim): two tenant folders that differ only in their row's flag change alike under the worker, entry
    for entry (added, altered or removed; by kind, mode and decoded text) once each folder's own ids are masked, and the
    two claims' launch facts carry the same names, each its own row's digest, and no word of the flag: nothing a job can
    see depends on the flag, which travels on the helper's argv alone. (P-5; the stand-in job writes nothing)"""
    rows = [(T1, True, "k1"), (T2, False, "k1")]
    folders = {tenant: world["root"] / tenant for tenant, _flag, _key in rows}

    def snapshot(folder) -> dict:
        """Every entry by kind and mode: a directory or a link is as visible to a job as a file's bytes."""
        def entry(p):
            kind = "link:" + os.readlink(p) if p.is_symlink() else "dir" if p.is_dir() else "file"
            body = p.read_bytes() if kind == "file" else kind.encode()
            return b"%o " % (p.lstat().st_mode & 0o7777) + body
        return {p.relative_to(folder): entry(p) for p in folder.rglob("*")}

    before = {tenant: snapshot(folder) for tenant, folder in folders.items()}
    (flagged_id, plain_id), door = await _drain_spawned(world, rows, _child(world, exit=0, files={}))
    after = {tenant: snapshot(folder) for tenant, folder in folders.items()}
    #: Each folder's change: every path whose entry the drain added, altered or removed, as (before, after).
    changed = {tenant: {p: (before[tenant].get(p), after[tenant].get(p)) for p in before[tenant].keys() | after[tenant].keys()
                        if before[tenant].get(p) != after[tenant].get(p)} for tenant in folders}

    assert _values(door.argvs[flagged_id], "--ticket-link") == [f"{ORIGIN_1471}/t/{T1}/investigations/{flagged_id}"], \
        "premise: the flag reached the worker"
    assert "--post-ticket" not in door.argvs[plain_id], "premise: the unflagged row carries no flag"
    launch = {T1: launch_facts(world["dsn"], flagged_id), T2: launch_facts(world["dsn"], plain_id)}
    assert all(isinstance(facts, dict) for facts in launch.values()), f"premise: both claims carry launch facts: {launch}"

    def masked(tenant, inv):
        values = [inv, launch[tenant][LAUNCH_ALERT], launch[tenant][LAUNCH_BOX_TOKEN], tenant]

        def mask(text):
            for n, value in enumerate(values):
                text = text.replace(value, f"<v{n}>")
            return text

        return {mask(str(path)): tuple(None if e is None else mask(e.decode("utf-8", "replace")) for e in pair)
                for path, pair in changed[tenant].items()}

    assert [is_box_token(launch[t][LAUNCH_BOX_TOKEN]) for t in (T1, T2)] == [True, True], \
        "a box token is not of the decided form, which the mask would hide"
    flagged, plain = masked(T1, flagged_id), masked(T2, plain_id)
    assert sorted(flagged) == sorted(plain), "the flagged folder changed at other paths than the unflagged one"
    assert {n: c for n, c in flagged.items() if c != plain[n]} == {}, "an entry of the flagged folder changed otherwise"
    assert set(launch[T1]) == set(launch[T2]), "the flagged claim's launch facts carry other names than the unflagged one's"
    assert _masked_facts(launch[T1], T1, flagged_id) == _masked_facts(launch[T2], T2, plain_id), \
        "a launch fact differs with the flag"
    assert set(launch[T1]) >= LAUNCH_FIELDS, launch[T1]
    for tenant in (T1, T2):
        assert launch[tenant][LAUNCH_DIGEST] == DIGEST_1471, "premise: the facts are this row's"
        text = json.dumps(launch[tenant]).encode()
        assert not any(w in text for w in (b"app.defender.test", b"update_ticket", b"ticket_link", b"post_ticket")), \
            launch[tenant]
    for tenant in (T1, T2):
        for path, (_old, data) in changed[tenant].items():
            assert not any(w in (data or b"") for w in (b"app.defender.test", b"update_ticket", b"ticket_link", b"post_ticket")), path
