"""#1342 M5: the alert byte cap at the store's insert (admission owns one cap, `READ_LIMIT`)."""
from __future__ import annotations

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


async def test_m5_an_alert_of_exactly_the_cap_is_stored_whole_and_one_byte_more_is_refused(dsn):
    """At `READ_LIMIT` the bytes round-trip; at `READ_LIMIT + 1` the insert refuses and stores nothing. (M5, O2)"""
    from defender._io import READ_LIMIT
    from defender.records.formats import AlertRefused

    at_cap = _json_of_size(READ_LIMIT)
    async with job_store(dsn) as store:
        stored = await an_alert(store, T1, ticket="AT", raw=at_cap)  # control: the cap itself is admitted
        read = await store.get_alert(T1, stored.alert_id)
        assert len(read.raw) == READ_LIMIT
        assert read.raw == at_cap
        del read
        with pytest.raises(AlertRefused):
            await an_alert(store, T1, ticket="OVER", raw=_json_of_size(READ_LIMIT + 1))
    assert execute(dsn, "SELECT count(*), max(length(raw)) FROM jobs.alerts") == [(1, READ_LIMIT)]
