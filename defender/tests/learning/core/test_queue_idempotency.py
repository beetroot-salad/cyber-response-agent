"""#1241: queue identity is finding_id, across retries and within an append, now the learning store's.

#1278 (design r8 Schema: "a finding id is unique for good", Flows): the judge's sink inserts into the store, whose unique key
(tenant, kind, finding id) replaces the file queue's persistent-identity scan. The same obligations are observed through
`enqueue.StoreFindings` over the real store: a retry keeps the first row and adds distinct ids, a batch's duplicates land
once, concurrent retries insert one, a duplicate does not bypass validation, and a retried report counts only new rows.

Retired from this file: `test_existing_queue_identity_survives_torn_tail` and `test_another_process_append_is_seen_by_existing_handle`
(a torn trailing line and a handle's cached read of a file queue: the file and its handle are gone, A1/O10; the other-process
case is the unique key itself, taken by the concurrent test below).
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pytest

from defender.learning.judge import enqueue
from defender.learning.judge._errors import JudgeRefused
from defender.learning.core.state import FINDINGS, QUESTIONER_FINDINGS
from defender.learning.store import blocking
from defender.tests.learning.judge.contrast_contracts import _spec1234 as S
from defender.tests.support.learning.branch import _world_1007 as W
from defender.tests.support.learning.core._store1278 import migrated_database  # noqa: F401 — fixture
from defender.tests.support.shared._fixture_uuid import fixture_uuid

pytestmark = pytest.mark.postgres

TENANT = fixture_uuid("tenant:1241")
FID = f"{W.EPISODE_ID}/b/0/0"


def queue_row(**over) -> dict:
    """One defender queue row as `enqueue.build_finding_row` mints it."""
    over.setdefault("type", "lead-set")
    return S.defender_row(over.pop("finding_id", FID), **over)


def world_row(**over) -> dict:
    return S.world_row(over.pop("finding_id", FID), **over)


@pytest.fixture
def dsn(migrated_database):  # noqa: F811 — the imported fixture
    from defender.tests.support.jobs._jobs1342 import register_tenant

    register_tenant(migrated_database, TENANT)
    return migrated_database


@pytest.fixture(params=[False, True], ids=["defender", "questioner"])
def channel_case(request, dsn):
    if request.param:
        return dsn, QUESTIONER_FINDINGS, world_row, enqueue.append_world_rows_report
    return dsn, FINDINGS, queue_row, enqueue.append_rows_report


def _append(dsn, append, rows):
    """One append through a store of its own, as one worker's sink."""
    with blocking(dsn) as store:
        return append("episode", rows, state=enqueue.StoreFindings(store, TENANT, "run-1241"))


def _queued(dsn, channel):
    with blocking(dsn) as store:
        return enqueue.StoreFindings(store, TENANT, "run-1241").rows(channel)


def _by_id(rows):
    return {r["finding_id"]: r for r in rows}


def test_retry_keeps_first_row_and_appends_distinct_ids(channel_case):
    dsn, channel, build, append = channel_case
    first = build(finding_id="episode/b/0/0", finding="first content")
    changed = dict(first, finding="retry content must not replace the first")
    other = build(finding_id="episode/b/1/0", finding=first["finding"])
    assert _append(dsn, append, [first]) == (1, 0)
    assert _append(dsn, append, [changed, other]) == (1, 0)
    assert _by_id(_queued(dsn, channel)) == {first["finding_id"]: first, other["finding_id"]: other}
    assert _append(dsn, append, [changed, other]) == (0, 0)
    assert _by_id(_queued(dsn, channel)) == {first["finding_id"]: first, other["finding_id"]: other}


def test_same_batch_duplicates_land_once_and_the_first_of_them_wins(channel_case):
    dsn, channel, build, append = channel_case
    first = build(finding_id="episode/b/0/0", finding="first")
    other = build(finding_id="episode/b/0/1", finding="second")
    assert _append(dsn, append, [first, other, dict(first, finding="changed"), other]) == (2, 0)
    assert _by_id(_queued(dsn, channel)) == {first["finding_id"]: first, other["finding_id"]: other}


def test_concurrent_retries_share_persistent_identity(channel_case):
    dsn, channel, build, append = channel_case
    row = build(finding_id="episode/b/0/0")

    with ThreadPoolExecutor(max_workers=4) as pool:
        reports = list(pool.map(lambda _: _append(dsn, append, [row]), range(8)))
    assert sorted(reports) == [(0, 0)] * 7 + [(1, 0)]
    assert _queued(dsn, channel) == [row]


def test_duplicate_does_not_bypass_validation(channel_case):
    dsn, channel, build, append = channel_case
    row = build(finding_id="episode/b/0/0")
    assert _append(dsn, append, [row]) == (1, 0)
    with pytest.raises(JudgeRefused):
        _append(dsn, append, [dict(row, subject_anchor="")])
    assert _queued(dsn, channel) == [row]


def test_enqueue_report_retry_counts_only_new_findings(dsn):
    first = queue_row(finding_id="episode/b/0/0")
    second = queue_row(finding_id="episode/b/1/0")

    def report(rows):
        with blocking(dsn) as store:
            return enqueue.enqueue_report(
                "episode", {"world": "b"}, state=enqueue.StoreFindings(store, TENANT, "run-1241"),
                drawn=enqueue.DrawnRows(defender=rows, world=[]))

    one = report([first, first])
    assert (one.appended, one.malformed) == (1, 0)
    two = report([first, second])
    assert (two.appended, two.malformed) == (1, 0)
    assert _by_id(_queued(dsn, FINDINGS)) == {first["finding_id"]: first, second["finding_id"]: second}
