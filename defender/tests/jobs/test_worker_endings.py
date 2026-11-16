"""#1342 O8: the worker's ending rules 1-5, one case per branch, read from the job-end record and the report a
`ScriptedChild` leaves (setup words, cut-short facts, junk in a job-end word). Shared setup: `_worker1342`."""
from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import logging
import os
import signal
from types import SimpleNamespace

import pytest

from defender.records import job_lane, run_end
from defender.tests.support.jobs._jobs1342 import (
    NOW,
    T1,
    T2,
    WORKER_LOGGER,
    an_alert,
    job_end,
    job_store,
    row,
)
from defender.tests.support.jobs._worker1342 import (
    CASES,
    MARKER,
    _child,
    _committed,
    _job_end_with,
    _names_code,
    _no_run_text,
    _queued,
    _run_one,
    _spec,
    _worker,
)
from defender.tests.support.jobs import _worker1342 as _shared

pytestmark = [pytest.mark.anyio, pytest.mark.postgres]
# The shared fixtures, bound in this module so pytest finds them here (an import of `world` would be shadowed by
# every test's parameter of that name).
world = _shared.world
_no_database_address_in_the_workers_environment = _shared._no_database_address_in_the_workers_environment


_SPELLINGS = {"trailing space": lambda w: w + " ", "trailing newline": lambda w: w + "\n",
              "trailing tab": lambda w: w + "\t", "trailing carriage return and newline": lambda w: w + "\r\n",
              "full-width": lambda w: w.translate({ord(c): ord(c) + 0xFEE0 for c in w if c.isascii() and c.isalpha()}),
              "leading newline": lambda w: "\n" + w, "leading tab": lambda w: "\t" + w,
              "leading carriage return and newline": lambda w: "\r\n" + w, "leading nul": lambda w: "\x00" + w,
              "leading space": lambda w: " " + w, "leading zero-width space": lambda w: "\u200b" + w,
              "leading byte-order mark": lambda w: "\ufeff" + w,
              "zero-width space inside": lambda w: w[:2] + "\u200b" + w[2:]}


for _key, _words in (("setup", ("refused", "crashed", "done")), ("box", ("not_started", "start_failed", "started")),
                     ("cut_short", ("box-lost", "box-output-limit", "provider-down", "budget", "proxy-access"))):
    for _word in _words:
        for _how, _spell in _SPELLINGS.items():
            CASES[f"1-job-end-{_key}-word-{_word}-{_how.replace(' ', '-')}"] = _spec(
                files=_committed(**{"{id}.job-end.json": _job_end_with(**{_key: _spell(_word)})}), exit=0,
                expect=("failed", "no_report", None))


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


def _job_end_cut_short(cut_short: str, *, report_committed: bool, scrub_verified: bool) -> str:
    """The real record's own text with the fifth fact set (#1421)."""
    return job_lane.JobEnd(setup="done", box="started", report_committed=report_committed,
                           scrub_verified=scrub_verified, cut_short=cut_short).text()


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


@pytest.mark.parametrize("text", [f"box-lost {MARKER}", MARKER, "box-lost\n" + MARKER], ids=["suffixed", "bare", "multiline"])
async def test_o8_child_text_in_the_cut_short_fact_never_reaches_the_job_message(world, text):
    """The record is refused outside the vocabulary, so the fixed message cannot carry a child's words. (O8)"""
    record = _job_end_with(cut_short=text)
    _inv, stored = await _run_one(world, _child(world, exit=0, files=_committed(**{"{id}.job-end.json": record})))
    assert (stored["stage"], stored["failure_reason"]) == ("failed", "no_report")
    _no_run_text(stored)
    assert "box-lost" not in stored["failure_message"], "a refused record was still read for its word"


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


@pytest.mark.parametrize("junk", _JUNK, ids=lambda c: f"U{ord(c):04X}")
async def test_o8_a_job_end_word_with_junk_anywhere_is_a_failed_run_with_no_report(world, junk):
    """Per junk character, one worker drain over leading, trailing and interior (the word rotating with the character): failed/no_report. The helper served each job (exit 0, #1170), so no exit code is the run's to name. (O8, M3)"""
    base = _JUNK.index(junk)
    variants = [(*_JOB_END_WORDS[(base + n) % len(_JOB_END_WORDS)], where) for n, where in enumerate(_JUNK_SPELLINGS)]
    child = _child(world, exit=0, printed=MARKER)
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
        _no_run_text(stored)


# --- #1471 r8: the worker's half of a job's ticket write-back (P-5, W3, W6) ------------------------------------
# The Worker's origin is C-6's required `frontend_origin=`; the helper's start carries the flag, the digest and the link
# as C-1's `--post-ticket`, `--alert-digest <hex>`, `--ticket-link <url>`. The tests spell the origin and pass it
# themselves, so they hold whether or not the shared `make_worker` defaults it.

ORIGIN_1471 = "https://app.defender.test"
#: `ALERT_BYTES`' fields plus the ticket the fixture mapping's `case_key` (`alert_id`) reads: a flagged create needs one (W1).
KEYED_1471 = (b'{"rule": {"id": "r-1342",  "description": "sketch"},\n'
              b' "alert_id": "SEC-1471", "alert_timestamp": "2026-10-29T00:00:00Z"}\n')
DIGEST_1471 = hashlib.sha256(KEYED_1471).hexdigest()
LAUNCH_FIELDS = {"investigation_id", "tenant_id", "alert_id", "digest", "label", "box_token"}


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


async def test_1471_p5_the_worker_writes_the_same_files_for_a_flagged_row_as_for_an_unflagged_one_and_hand_the_link_only_by_argv(world):
    """A flagged row's writes differ from an unflagged row's in nothing but its own values, the launch record keeps its
    six fields, and no file holds the origin or a flag word. (P-5)"""
    tenant_dir = world["root"] / T1

    def snapshot() -> dict:
        return {p: p.read_bytes() for p in tenant_dir.rglob("*") if p.is_file()}

    before = snapshot()
    rows = [(T1, True, "k1"), (T1, False, "k2")]
    (flagged_id, plain_id), door = await _drain_spawned(world, rows, _child(world, exit=0, files=_committed()))
    after = snapshot()
    written = {p: data for p, data in after.items() if before.get(p) != data}

    assert _values(door.argvs[flagged_id], "--ticket-link") == [f"{ORIGIN_1471}/t/{T1}/investigations/{flagged_id}"], \
        "premise: the flag reached the worker"
    assert "--post-ticket" not in door.argvs[plain_id], "premise: the unflagged row carries no flag"

    def launch_of(inv):
        return json.loads((world["runs"] / f"{inv}.launch.json").read_text(encoding="utf-8"))

    def normalised(inv, key):
        launch = launch_of(inv)
        values = [inv, launch["alert_id"], launch["box_token"], f"V-{key}", key]
        out = {}
        for path, data in written.items():
            if inv not in str(path.relative_to(tenant_dir)) and inv.encode() not in data:
                continue
            name, text = str(path.relative_to(tenant_dir)), data.decode("utf-8", "replace")
            for n, value in enumerate(values):
                name, text = name.replace(value, f"<v{n}>"), text.replace(value, f"<v{n}>")
            out[name] = text
        return out

    flagged, plain = normalised(flagged_id, "k1"), normalised(plain_id, "k2")
    assert len(plain) >= 2, "premise: the worker wrote files for the row"
    assert set(flagged) == set(plain), (sorted(flagged), sorted(plain))
    assert {n: t for n, t in flagged.items() if t != plain[n]} == {}, "a flagged row's write differs from the unflagged row's"
    for inv in (flagged_id, plain_id):
        assert set(launch_of(inv)) == LAUNCH_FIELDS, launch_of(inv)
        assert launch_of(inv)["digest"] == DIGEST_1471, "premise: the record is this row's"
    for path, data in written.items():
        text = data.decode("utf-8", "replace")
        assert not any(word in text for word in (ORIGIN_1471, "app.defender.test", "update_ticket", "ticket_link", "post_ticket")), path


def _receipt(status) -> str:
    return json.dumps({"key": "SEC-1471", "status": status, "url": None, "ok": status in ("commented", "escalated"),
                       "reason": None if status in ("commented", "escalated") else f"{MARKER} the store said no"})


_RECEIPT = "{id}.ticket-write.json"
_BAD_RECEIPTS = {
    "status-outside-the-set": _receipt("refused"),
    "status-of-the-old-words": _receipt("not_sent"),
    "status-another-word-of-ticket_write": _receipt("no_receipt"),
    "status-the-null-word-not_read": _receipt("not_read"),
    "status-in-capitals": _receipt("Commented"),
    "status-with-a-trailing-newline": _receipt("commented\n"),
    "status-empty": _receipt(""),
    "status-a-number": _receipt(1),
    "status-null": _receipt(None),
    "status-a-list": _receipt(["commented"]),
    "no-status": json.dumps({"key": "SEC-1471", "ok": True}),
    "not-json": "commented",
    "empty-file": "",
    "json-list": json.dumps(["commented"]),
    "json-string": json.dumps("commented"),
    "truncated": _receipt("commented")[:30],
}


@pytest.mark.parametrize("word", ["commented", "escalated", "error", "unknown"])
async def test_1471_w6_the_word_is_the_receipts_own_status_verbatim(world, word):
    """A flagged job's row reads the receipt's status when it is one of the four, and only the word. (W6)"""
    child = _child(world, exit=0, files=_committed(**{_RECEIPT: _receipt(word)}))
    async with job_store(world["dsn"]) as store:
        inv = await _queued_1471(store, update_ticket=True)
        await _worker_1471(world, store, child).drain()
        record = await store.get_investigation(T1, inv)

    assert child.seen() is not None, "the stand-in child never ran"
    assert (record.stage, record.ticket_write) == ("completed", word), record
    _no_run_text(row(world["dsn"], inv))


@pytest.mark.parametrize("name", list(_BAD_RECEIPTS))
async def test_1471_w6_a_receipt_that_says_nothing_in_the_set_or_cannot_be_read_is_unknown(world, name):
    """An out-of-set status, another word of the column, or a receipt that is not a readable object: `unknown`, not a
    failure of the row and not the child's text. (W6)"""
    child = _child(world, exit=0, files=_committed(**{_RECEIPT: _BAD_RECEIPTS[name]}))
    async with job_store(world["dsn"]) as store:
        inv = await _queued_1471(store, update_ticket=True)
        await _worker_1471(world, store, child).drain()
        record = await store.get_investigation(T1, inv)

    assert (record.stage, record.ticket_write) == ("completed", "unknown"), record
    _no_run_text(row(world["dsn"], inv))


@pytest.mark.parametrize("how", ["not-utf8", "a-directory"])
async def test_1471_w6_a_receipt_of_bytes_or_a_kind_that_cannot_be_read_is_unknown(world, how):
    """Bytes that are not text, or a directory where the receipt belongs: `unknown`. (W6)"""
    spec = {"binary": {_RECEIPT: b'{"status": "comm\xff\xfe"}'.hex()}} if how == "not-utf8" else {"dirs": [_RECEIPT]}
    child = _child(world, exit=0, files=_committed(), **spec)
    async with job_store(world["dsn"]) as store:
        inv = await _queued_1471(store, update_ticket=True)
        await _worker_1471(world, store, child).drain()
        record = await store.get_investigation(T1, inv)

    assert (record.stage, record.ticket_write) == ("completed", "unknown"), record


@pytest.mark.parametrize("ending", ["silent", "no-report"])
async def test_1471_w6_a_flagged_run_that_left_no_receipt_reads_no_receipt(world, ending):
    """No receipt in a folder the worker read (a silent ending, a run that died before its record step): `no_receipt`. (W6)"""
    files = _committed() if ending == "silent" else {"{id}.job-end.json": job_end(report_committed=False)}
    child = _child(world, exit=0, files=files)
    async with job_store(world["dsn"]) as store:
        inv = await _queued_1471(store, update_ticket=True)
        await _worker_1471(world, store, child).drain()
        record = await store.get_investigation(T1, inv)

    assert child.seen() is not None, "the stand-in child never ran"
    assert record.ticket_write == "no_receipt", record


@pytest.mark.parametrize("receipt", [None, "commented", "escalated", "error"], ids=["none", "commented", "escalated", "error"])
async def test_1471_w6_an_unflagged_row_reads_null_whatever_the_folder_holds(world, receipt):
    """Control: an unflagged row's `ticket_write` stays null, with or without a receipt beside it. (W6, W4)"""
    child = _child(world, exit=0, files=_committed(**({} if receipt is None else {_RECEIPT: _receipt(receipt)})))
    async with job_store(world["dsn"]) as store:
        inv = await _queued_1471(store, update_ticket=False)
        await _worker_1471(world, store, child).drain()
        record = await store.get_investigation(T1, inv)

    assert (record.stage, record.ticket_write) == ("completed", None), record


def _plant_fifo(path):
    os.mkfifo(path)


def _plant_host_link(path):
    host = path.parent.parent / "host-secret.json"
    host.write_text(_receipt("commented"), encoding="utf-8")
    path.symlink_to(host)


def _plant_over_cap(path):
    path.write_text(_receipt("commented").ljust(64 * 1024 + 1), encoding="utf-8")


def _plant_unparsable(path):
    path.write_text('{"key": "SEC-1471", "status": "comm', encoding="utf-8")


def _plant_plain(path):
    path.write_text(_receipt("commented").ljust(32 * 1024), encoding="utf-8")


_ENTRIES_AT_THE_RECEIPT = {
    "symlink-to-a-host-file": (_plant_host_link, "unknown"), "fifo": (_plant_fifo, "unknown"),
    "file-over-64-KiB": (_plant_over_cap, "unknown"), "unparsable-json": (_plant_unparsable, "unknown"),
    "control-plain-32-KiB-file": (_plant_plain, "commented"),
}


@pytest.mark.parametrize("entry", list(_ENTRIES_AT_THE_RECEIPT))
async def test_1471_c8_a_bad_entry_at_the_receipt_path_reads_unknown_and_the_row_still_ends(world, entry):
    """A link to a host file, a FIFO, a file over 64 KiB or unparsable JSON where the receipt belongs reads `unknown`
    and the row ends without the worker hanging; a plain small receipt still reads. (C-8, W6)"""
    plant, word = _ENTRIES_AT_THE_RECEIPT[entry]
    child = _child(world, exit=0, files=_committed())
    async with job_store(world["dsn"]) as store:
        inv = await _queued_1471(store, update_ticket=True)
        path = world["runs"] / _RECEIPT.format(id=inv)
        plant(path)
        try:
            await asyncio.wait_for(_worker_1471(world, store, child).drain(), timeout=30)
        finally:
            if entry == "fifo":  # frees a reader a hung worker left blocked in its open
                with contextlib.suppress(OSError):
                    os.close(os.open(path, os.O_WRONLY | os.O_NONBLOCK))
        record = await store.get_investigation(T1, inv)

    assert child.seen() is not None, "the stand-in child never ran"
    assert (record.stage, record.ticket_write) == ("completed", word), record


class _Ends:
    """The real store with each end write's keywords noted, and optionally the first `refuse` finishes refused as a
    value the database will never take (a real `DataError`)."""

    def __init__(self, store, *, refuse: int = 0, get_alert_outages: int = 0) -> None:
        self._store, self.refuse, self.outages, self.calls = store, refuse, get_alert_outages, []

    def __getattr__(self, name):
        return getattr(self._store, name)

    async def get_alert(self, *args, **kw):
        if self.outages > 0:
            from sqlalchemy.exc import OperationalError

            self.outages -= 1
            raise OperationalError("SELECT", {}, Exception("connection refused"))
        return await self._store.get_alert(*args, **kw)

    async def finish(self, *args, **kw):
        self.calls.append(("finish", kw))
        if self.refuse > 0:
            from sqlalchemy.exc import DataError

            self.refuse -= 1
            raise DataError("UPDATE jobs.investigations", {}, Exception("value too long"))
        return await self._store.finish(*args, **kw)

    async def hand_back(self, *args, **kw):
        self.calls.append(("hand_back", kw))
        return await self._store.hand_back(*args, **kw)

    async def write_accounting(self, *args, **kw):
        self.calls.append(("write_accounting", kw))
        return await self._store.write_accounting(*args, **kw)

    def of(self, name):
        return [kw.get("ticket_write", "<absent>") for n, kw in self.calls if n == name]


async def test_1471_w6_the_word_rides_every_try_of_the_end_down_to_the_barest(world):
    """The end refused twice (with its knowledge, then with the marker) is written a third time as the barest end, and
    each try carries the receipt's word. (W6, `_lesser_ends`)"""
    child = _child(world, exit=0, files=_committed(**{_RECEIPT: _receipt("escalated")}))
    async with job_store(world["dsn"]) as store:
        ends = _Ends(store, refuse=2)
        inv = await _queued_1471(store, update_ticket=True)
        await _worker_1471(world, ends, child).drain()
        record = await store.get_investigation(T1, inv)

    assert ends.of("finish") == ["escalated"] * 3, ends.calls
    assert (record.stage, record.failure_reason, record.ticket_write) == ("failed", "worker_error", "escalated"), record


async def test_1471_w6_an_unflagged_rows_ends_carry_no_word(world):
    """Control: every try of an unflagged row's end carries null (or no) word. (W6)"""
    child = _child(world, exit=0, files=_committed(**{_RECEIPT: _receipt("commented")}))
    async with job_store(world["dsn"]) as store:
        ends = _Ends(store, refuse=2)
        inv = await _queued_1471(store, update_ticket=False)
        await _worker_1471(world, ends, child).drain()
        record = await store.get_investigation(T1, inv)

    assert len(ends.of("finish")) == 3, ends.calls
    assert all(w in (None, "<absent>") for w in ends.of("finish")), ends.calls
    assert record.ticket_write is None


async def test_1471_w6_an_outage_before_the_folder_is_read_hands_the_row_back_carrying_not_read(world):
    """The store unreachable when the worker reads the alert: nothing looked at the run folder, so the hand-back
    carries `not_read` for a flagged row and nothing for an unflagged one. (W6)"""
    child = _child(world, exit=0, files=_committed())
    async with job_store(world["dsn"]) as store:
        flagged_calls = _Ends(store, get_alert_outages=1)
        await _queued_1471(store, update_ticket=True)
        await _worker_1471(world, flagged_calls, child).drain()
    assert flagged_calls.of("hand_back")[:1] == ["not_read"], flagged_calls.calls


@pytest.mark.parametrize("flagged", [True, False], ids=["flagged", "unflagged"])
@pytest.mark.parametrize("fault", ["lane-cannot-open", "child-cannot-start", "unplanned-fault"])
async def test_1471_w6_a_row_the_worker_ends_without_reading_the_run_folder_reads_not_read(world, fault, flagged):
    """The tenant folder is a symlink, the helper cannot be started, or the worker fails on its own: the row ends
    `worker_error` and a flagged one reads `not_read` (the comment may or may not exist); an unflagged one reads null. (W6)"""
    child = _child(world, exit=0, files=_committed())
    kw = {}
    if fault == "lane-cannot-open":
        real = world["tmp"] / "real"
        (world["root"] / T1).rename(real)
        (world["root"] / T1).symlink_to(real)
    elif fault == "child-cannot-start":
        async def cannot(*_argv, **_kw):
            raise FileNotFoundError("no such interpreter")
        kw["spawn"] = cannot
    async with job_store(world["dsn"]) as store:
        inv = await _queued_1471(store, update_ticket=flagged)
        target = store
        if fault == "unplanned-fault":
            target = _Ends(store)
            async def broken(*_a, **_k):
                raise RuntimeError("a seam fell over")
            target.get_alert = broken
        await _worker_1471(world, target, child, **kw).drain()
        record = await store.get_investigation(T1, inv)

    assert (record.stage, record.failure_reason) == ("failed", "worker_error"), record
    assert child.seen() is None, "premise: no child ran, so no folder was read"
    assert record.ticket_write == ("not_read" if flagged else None), record


async def test_1471_w6_a_row_cancelled_while_it_ran_ends_with_the_word_the_worker_read(world):
    """A flagged run cancelled while its container runs: the worker's accounting write carries the receipt's word, and the
    row reads it, not the `not_read` the cancel wrote. (W6, write_accounting; e2e with the store)"""
    release = world["tmp"] / "release"
    child = _child(world, exit=0, files=_committed(**{_RECEIPT: _receipt("commented")}), wait_for=release)
    async with job_store(world["dsn"]) as store:
        ends = _Ends(store)
        inv = await _queued_1471(store, update_ticket=True)
        drained = asyncio.create_task(_worker_1471(world, ends, child).drain())
        try:
            for _ in range(1500):
                if child.seen() is not None:
                    break
                await asyncio.sleep(0.01)
            assert child.seen() is not None, "premise: the child is running"
            await store.cancel_investigation(T1, inv, actor="u-1")
        finally:
            release.touch()
        await asyncio.wait_for(drained, timeout=60)
        record = await store.get_investigation(T1, inv)

    assert ends.of("write_accounting") == ["commented"], ends.calls
    assert (record.stage, record.ticket_write) == ("aborted", "commented"), record


# --- R4 (G4): every writer of W6's word, flagged or not ---------------------------------------------------------------

_FAST = {"renewal_interval": 0.2, "cost_interval": 0.3, "takeover_interval": 0.1}
_STOPPED_RUN = job_end(setup="crashed", box="not_started", report_committed=False, scrub_verified=False)


def _word(dsn: str, investigation_id: str):
    """The stored `ticket_write` column (the read serves null while the row is live)."""
    from defender.tests.support.shared._postgres1339 import execute

    return execute(dsn, "SELECT ticket_write FROM jobs.investigations WHERE id = %s", (investigation_id,))[0][0]


async def _served(store, inv):
    return (await store.get_investigation(T1, inv)).ticket_write


async def _end_by_finish(world, flagged):
    child = _child(world, exit=0, files=_committed(**{_RECEIPT: _receipt("commented")}))
    async with job_store(world["dsn"]) as store:
        inv = await _queued_1471(store, update_ticket=flagged)
        await _worker_1471(world, store, child).drain()
        end = await _served(store, inv)
        return _word(world["dsn"], inv), end, end


async def _end_by_barest_write(world, flagged):
    child = _child(world, exit=0, files=_committed(**{_RECEIPT: _receipt("escalated")}))
    async with job_store(world["dsn"]) as store:
        inv = await _queued_1471(store, update_ticket=flagged)
        await _worker_1471(world, _Ends(store, refuse=2), child).drain()
        end = await _served(store, inv)
        assert (await store.get_investigation(T1, inv)).failure_reason == "worker_error", "premise: the barest end ran"
        return _word(world["dsn"], inv), end, end


async def _end_by_accounting_after_a_cancel(world, flagged):
    release = world["tmp"] / "release"
    child = _child(world, exit=0, files=_committed(**{_RECEIPT: _receipt("commented")}), wait_for=release)
    async with job_store(world["dsn"]) as store:
        inv = await _queued_1471(store, update_ticket=flagged)
        drained = asyncio.create_task(_worker_1471(world, store, child).drain())
        try:
            for _ in range(1500):
                if child.seen() is not None:
                    break
                await asyncio.sleep(0.01)
            assert child.seen() is not None, "premise: the child is running"
            await store.cancel_investigation(T1, inv, actor="u-1")
        finally:
            release.touch()
        await asyncio.wait_for(drained, timeout=60)
        end = await _served(store, inv)
        return _word(world["dsn"], inv), end, end


async def _hand_back_before_the_read(world, flagged):
    async with job_store(world["dsn"]) as store:
        inv = await _queued_1471(store, update_ticket=flagged)
        await _worker_1471(world, _Ends(store, get_alert_outages=1), _child(world, exit=0, files=_committed())).drain()
        stored, live = _word(world["dsn"], inv), await _served(store, inv)
        assert await store.take_over(held=frozenset()) == [inv], "premise: the handed-back row was taken over"
        return stored, live, await _served(store, inv)


async def _hand_back_after_the_read(world, flagged):
    term = str(world["tmp"] / "term-{id}")
    child = _child(world, files={"{id}.job-end.json": _STOPPED_RUN, _RECEIPT: _receipt("commented")},
                   wait_for=world["tmp"] / "never", term="finish", term_mark=term)
    async with job_store(world["dsn"]) as store:
        ends = _Ends(store)
        inv = await _queued_1471(store, update_ticket=flagged)
        serving = asyncio.create_task(_worker_1471(world, ends, child, **_FAST).serve())
        try:
            for _ in range(1500):
                if child.seen() is not None:
                    break
                await asyncio.sleep(0.01)
            assert child.seen() is not None, "premise: the child is running"
            os.kill(os.getpid(), signal.SIGTERM)
            await asyncio.wait_for(serving, timeout=60)
        finally:
            serving.cancel()
            await asyncio.gather(serving, return_exceptions=True)
        assert os.path.exists(term.replace("{id}", inv)), "premise: the stop signalled the child"
        assert [n for n, _ in ends.calls if n in ("hand_back", "finish")] == ["hand_back"], ends.calls
        stored, live = _word(world["dsn"], inv), await _served(store, inv)
        assert await store.take_over(held=frozenset()) == [inv], "premise: the handed-back row was taken over"
        return stored, live, await _served(store, inv)


async def _taken_over_by_the_store(world, flagged):
    from defender.tests.support.jobs._jobs1342 import lapse_lease

    async with job_store(world["dsn"]) as store:
        inv = await _queued_1471(store, update_ticket=flagged)
        assert (await store.claim()).record.investigation_id == inv, "premise: claimed"
        lapse_lease(world["dsn"], inv)
        assert await store.take_over(held=frozenset()) == [inv], "premise: taken over"
        retry = await store.claim()
        assert retry is not None, "premise: the lapse was retried"
        assert retry.record.attempt == 2
        assert _word(world["dsn"], retry.record.investigation_id) is None, "the retry row carries a word"
        end = await _served(store, inv)
        return _word(world["dsn"], inv), end, end


#: writer -> (driver, flagged row's (stored word, served while live, served at the end))
_W6_WRITERS = {
    "hand-back-before-the-read": (_hand_back_before_the_read, ("not_read", None, "not_read")),
    "hand-back-after-the-read": (_hand_back_after_the_read, ("commented", None, "commented")),
    "finish": (_end_by_finish, ("commented", "commented", "commented")),
    "write-accounting-after-a-cancel": (_end_by_accounting_after_a_cancel, ("commented", "commented", "commented")),
    "barest-end": (_end_by_barest_write, ("escalated", "escalated", "escalated")),
    "store-take-over": (_taken_over_by_the_store, ("not_read", "not_read", "not_read")),
}


@pytest.mark.parametrize("flagged", [True, False], ids=["flagged", "unflagged"])
@pytest.mark.parametrize("writer", list(_W6_WRITERS))
async def test_1471_w6_every_writer_of_a_rows_end_leaves_the_word_precedence_says(world, writer, flagged):
    """Each way a row ends, flagged: the stored word and then the served word are W6's; unflagged: served null. (W6)"""
    drive, expected = _W6_WRITERS[writer]
    stored, live, end = await drive(world, flagged)
    if flagged:
        assert (stored, live, end) == expected, writer
    else:
        assert (live, end) == (None, None), writer
