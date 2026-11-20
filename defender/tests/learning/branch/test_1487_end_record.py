"""#1487 (design r5, Data model): the learning end record's optional `findings` field and the shared cap measure.
The envelope never looks inside `findings`: a record whose `findings` is any JSON value still reads (the worker then
refuses the findings, never the ending). No database."""
from __future__ import annotations

import json

import pytest

BASE = {"status": "completed", "reason": None, "message": None, "fork_message_id": "m-1", "stage": "judge",
        "sibling_cost_usd": 0.0}
OK = {"state": "ok", "text": json.dumps({"finding": [], "questioner_finding": []})}


def _end():
    from defender.records.job_lane import LearningEnd

    return LearningEnd


def test_a_record_without_findings_still_reads_with_none():
    """The field is optional: an older record or a skipped/failed one reads, findings `None`. (Data model)"""
    end = _end().parse(json.dumps(BASE))
    assert end is not None and end.findings is None  # noqa: PT018


@pytest.mark.parametrize("found", [OK, {"state": "unreadable"}, {"state": "over_cap"}, {"state": "malformed"}])
def test_a_record_with_findings_round_trips_through_text_and_parse(found):
    """What the entry writes is what the worker reads. (Data model)"""
    cls = _end()
    end = cls(status="completed", reason=None, message=None, fork_message_id="m-1", stage="judge", findings=found)
    again = cls.parse(end.text())
    assert again is not None and again.findings == found  # noqa: PT018
    assert json.loads(end.text())["findings"] == found


@pytest.mark.parametrize("value", [None, "ok", 5, 1.5, True, [], [OK], {}, {"state": 1}, {"state": "ok", "text": 5},
                                   {"state": "bogus", "text": "x"}, {"state": "ok", "extra": 1, "text": "[]"},
                                   {"state": "ok", "text": "\ud800"}, {"a": {"b": [1, {"c": None}]}}])
def test_the_envelope_does_not_look_inside_findings(value):
    """Any JSON value of `findings` leaves the record readable. (P4: container side; O2: only an
    unreadable envelope is "no readable end record")"""
    end = _end().parse(json.dumps({**BASE, "findings": value}))
    assert end is not None, "the findings field made the whole ending unreadable"
    assert (end.status, end.reason) == ("completed", None)


def test_an_unknown_field_still_makes_the_record_unreadable():
    """The exact-fields rule stays for everything but `findings`. (Data model)"""
    assert _end().parse(json.dumps({**BASE, "findings": OK, "surprise": 1})) is None


def test_the_cap_is_eight_mib_of_utf8_bytes_measured_by_one_shared_function():
    """`FINDINGS_CAP_BYTES` is 8 MiB; `findings_text_bytes` counts UTF-8 bytes, not characters. (Data model)"""
    from defender.records.job_lane import FINDINGS_CAP_BYTES, findings_text_bytes

    assert FINDINGS_CAP_BYTES == 8 * 1024 * 1024
    assert [findings_text_bytes(t) for t in ("", "a", "é", "€", "\U0001F600", "aé€\U0001F600")] == [0, 1, 2, 3, 4, 10]


# --- #1589: the end record carries no findings count ----------------------------------------------------------------

#: The end record's envelope as #1589 decided it: the count is gone, `findings` stays optional.
FIELDS_1589 = {"status", "reason", "message", "fork_message_id", "stage", "sibling_cost_usd"}


def test_1589_a_record_without_a_count_reads():
    """The envelope is exactly the six fields (with or without `findings`). (#1589)"""
    end = _end().parse(json.dumps({**BASE, "findings": OK}))
    assert end is not None, "a record in the new shape was refused"
    assert (end.status, end.fork_message_id, end.stage, end.findings) == ("completed", "m-1", "judge", OK)


def test_1589_the_record_the_entry_writes_has_no_count():
    """`text()` writes the six fields and `findings` when it says something; never a count. (#1589)"""
    end = _end()(status="completed", reason=None, message=None, fork_message_id="m-1", stage="judge", findings=OK)
    assert set(json.loads(end.text())) == FIELDS_1589 | {"findings"}
    assert not hasattr(end, "findings_count"), "the record still models a findings count"


@pytest.mark.parametrize("count", [0, 7, 2**31 - 1, 2**31, -1, None, True, 1.5, "7", [], {}])
def test_1589_an_older_entrys_count_is_accepted_whatever_its_value_and_ignored(count):
    """A record from an entry before #1589 still carries `findings_count`: it reads, the value never looked at, and
    nothing of it survives into what is read. (#1589, option B)"""
    end = _end().parse(json.dumps({**BASE, "findings_count": count, "findings": OK}))
    assert end is not None, f"an older entry's count {count!r} made the ending unreadable"
    assert (end.status, end.findings) == ("completed", OK)
    assert set(json.loads(end.text())) == FIELDS_1589 | {"findings"}


def test_1589_another_unknown_field_beside_an_old_count_is_still_refused():
    """Only `findings_count` is let through; the exact-fields rule holds for anything else. (#1589)"""
    assert _end().parse(json.dumps({**BASE, "findings_count": 0, "surprise": 1})) is None
    assert _end().parse(json.dumps({**BASE, "surprise": 1})) is None


@pytest.mark.parametrize("missing", sorted(FIELDS_1589))
def test_1589_a_record_missing_an_envelope_field_is_refused(missing):
    """Dropping the count did not make the other fields optional. (#1589)"""
    body = {k: v for k, v in BASE.items() if k != missing}
    assert _end().parse(json.dumps(body)) is None
    assert _end().parse(json.dumps({**body, "findings_count": 0})) is None
