"""#1342 O8: the worker's ending rules 1-5, one case per branch, read from the job-end record and the report a
`ScriptedChild` leaves (setup words, cut-short facts, junk in a job-end word). Shared setup: `_worker1342`."""
from __future__ import annotations

import json
import logging

import pytest

from defender.records import job_lane, run_end
from defender.tests.support.jobs._jobs1342 import (
    NOW,
    WORKER_LOGGER,
    job_end,
    job_store,
    row,
)
from defender.tests.support.jobs._worker1342 import (
    CASES,
    EXIT,
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
    _inv, stored = await _run_one(world, _child(world, exit=5, files=_committed(**{"{id}.job-end.json": record})))
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
