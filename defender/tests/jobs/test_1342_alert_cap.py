"""#1342 M5: the alert byte cap at the store's insert (admission owns one cap, `READ_LIMIT`)."""
from __future__ import annotations

import re

import pytest

from defender.tests.support.jobs._jobs1342 import T1, an_alert, job_store, register_tenant
from defender.tests.support.shared._postgres1339 import execute

pytestmark = [pytest.mark.anyio, pytest.mark.postgres]


@pytest.fixture
def dsn(migrated_database: str) -> str:
    register_tenant(migrated_database, T1)
    return migrated_database


def _json_of_size(size: int) -> bytes:
    head, tail = b'{"a": "', b'"}'
    return head + b"x" * (size - len(head) - len(tail)) + tail


def _multibyte_over_the_cap() -> bytes:
    """A valid alert of fewer characters than the cap and more bytes than it."""
    from defender._io import READ_LIMIT

    head, tail = b'{"a": "', b'"}'
    raw = head + "\u00e9".encode() * (READ_LIMIT // 2 + 1) + tail
    assert len(raw.decode()) < READ_LIMIT < len(raw), "premise: under the cap in characters, over it in bytes"
    return raw


async def test_m5_an_alert_of_exactly_the_cap_is_stored_whole_and_one_byte_more_is_refused(dsn):
    """At `READ_LIMIT` the bytes round-trip; at `READ_LIMIT + 1` the insert refuses and stores nothing. (M5, O2)"""
    from defender._io import READ_LIMIT
    from defender.records._alert_input import REFUSE_SIZE
    from defender.records.formats import AlertRefused

    at_cap = _json_of_size(READ_LIMIT)
    async with job_store(dsn) as store:
        stored = await an_alert(store, T1, ticket="AT", raw=at_cap)  # control: the cap itself is admitted
        read = await store.get_alert(T1, stored.alert_id)
        assert len(read.raw) == READ_LIMIT
        assert read.raw == at_cap
        del read
        with pytest.raises(AlertRefused, match=re.escape(REFUSE_SIZE)):  # D-b: the size reason
            await an_alert(store, T1, ticket="OVER", raw=_json_of_size(READ_LIMIT + 1))
    assert execute(dsn, "SELECT count(*), max(length(raw)) FROM jobs.alerts") == [(1, READ_LIMIT)]


def test_m5_admission_owns_the_cap_it_accepts_the_cap_and_refuses_one_byte_more():
    """`admit` itself refuses `READ_LIMIT + 1` bytes with the size reason and accepts `READ_LIMIT`. (M5)"""
    from defender._io import READ_LIMIT
    from defender.records.formats import REFUSE_SIZE, AlertRefused, admit

    admit(_json_of_size(READ_LIMIT))  # control: the cap itself
    with pytest.raises(AlertRefused, match=re.escape(REFUSE_SIZE)):
        admit(_json_of_size(READ_LIMIT + 1))


def test_m5_the_operator_read_accepts_a_file_of_exactly_the_cap_and_refuses_one_byte_more(tmp_path):
    """`read_operator_alert` returns a `READ_LIMIT`-byte file whole and refuses a longer one as too big. (M5)"""
    from defender._io import READ_LIMIT
    from defender.records.formats import REFUSE_SIZE, AlertRefused, read_operator_alert

    at_cap, over = tmp_path / "at.json", tmp_path / "over.json"
    at_cap.write_bytes(_json_of_size(READ_LIMIT))
    over.write_bytes(_json_of_size(READ_LIMIT + 1))
    assert len(read_operator_alert(at_cap)) == READ_LIMIT
    with pytest.raises(AlertRefused, match=re.escape(REFUSE_SIZE)):
        read_operator_alert(over)


def test_m5_the_cap_counts_bytes_not_characters_at_admission():
    """`admit` refuses a multibyte alert over `READ_LIMIT` bytes with the size reason though it has fewer characters. (M5)"""
    from defender.records.formats import REFUSE_SIZE, AlertRefused, admit

    with pytest.raises(AlertRefused, match=re.escape(REFUSE_SIZE)):
        admit(_multibyte_over_the_cap())


async def test_m5_the_cap_counts_bytes_not_characters_at_the_insert(dsn):
    """The store's insert refuses a multibyte alert over `READ_LIMIT` bytes with the size reason and stores nothing. (M5, D-b)"""
    from defender.records.formats import REFUSE_SIZE, AlertRefused

    async with job_store(dsn) as store:
        with pytest.raises(AlertRefused, match=re.escape(REFUSE_SIZE)):
            await an_alert(store, T1, ticket="WIDE", raw=_multibyte_over_the_cap())
    assert execute(dsn, "SELECT count(*) FROM jobs.alerts") == [(0,)]
