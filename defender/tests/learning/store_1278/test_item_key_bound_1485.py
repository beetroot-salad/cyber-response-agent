"""#1485 O1 key bound: the store takes an item key of at most `MAX_ITEM_KEY_BYTES` (200) UTF-8 bytes and refuses a
longer one with `ItemRefused`, writing nothing, through each write path that inserts items.
"""
from __future__ import annotations

import pytest

from defender.tests.support.jobs._jobs1342 import register_tenant
from defender.tests.support.learning.core._set_aside1485 import held_by_close, page_through, pitfall
from defender.tests.support.learning.core._store1278 import finding, learning_store, store_mod, world_finding
from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.tests.support.shared._postgres1339 import execute

pytestmark = [pytest.mark.anyio, pytest.mark.postgres]

BLUE = fixture_uuid("tenant:1485-key-blue")
#: Exactly 200 UTF-8 bytes, in one-, two-, three- and four-byte characters.
FITS = ["a" * 200, "é" * 100, "€" * 66 + "ab", "😀" * 50, "é" * 99 + "ab"]
#: 201 bytes or more: one byte over at a character boundary, mid-count, and 200 characters that are 400 bytes.
OVER = ["a" * 201, "é" * 100 + "a", "é" * 101, "😀" * 50 + "x", "é" * 200, "€" * 67]


async def _finding(store, tenant, key):
    return await store.publish_findings(tenant, "run-1", [finding(key)], kind="finding")


async def _questioner(store, tenant, key):
    return await store.publish_findings(tenant, "run-1", [world_finding(key)], kind="questioner_finding")


async def _pitfall(store, tenant, key):
    return await store.add_pitfall(tenant, pitfall(key))


async def _request(store, tenant, key):
    return await store.enqueue_request(tenant, key, "case-1", {"case": "c"})


#: Every public write path that inserts an item with a key a caller chose: kind -> verb.
WRITERS = {"finding": _finding, "questioner_finding": _questioner, "pitfall": _pitfall, "curation_request": _request}


@pytest.fixture
def dsn(migrated_database):
    register_tenant(migrated_database, BLUE)
    return migrated_database


def _rows(dsn):
    return execute(dsn, "SELECT kind, item_key, status FROM learning.work_items WHERE tenant_id = %s ORDER BY 1, 2", (BLUE,))


def test_the_bound_is_exported_by_the_store_and_is_200():
    """`MAX_ITEM_KEY_BYTES` is a public name of `defender.learning_store` and equals 200. (O1, Names)"""
    assert store_mod().MAX_ITEM_KEY_BYTES == 200


@pytest.mark.parametrize("kind", sorted(WRITERS))
@pytest.mark.parametrize("key", FITS)
async def test_a_key_of_exactly_the_bound_is_accepted_through_every_write_path(dsn, kind, key):
    """A key of exactly 200 UTF-8 bytes, however its characters are sized, is stored. (O1, key bound)"""
    assert len(key.encode()) == 200
    async with learning_store(dsn) as store:
        assert await WRITERS[kind](store, BLUE, key) in {(1, 0), True}
        assert [(i.kind, i.key, i.status) for i in await store.work(BLUE, kind=kind)] == [(kind, key, "waiting")]


@pytest.mark.parametrize("kind", sorted(WRITERS))
@pytest.mark.parametrize("key", OVER)
async def test_a_longer_key_is_refused_through_every_write_path_and_writes_nothing(dsn, kind, key):
    """A key over 200 UTF-8 bytes raises `ItemRefused` and leaves every row as it was; a 200-byte key through the
    same path is taken. (O1, key bound)"""
    assert len(key.encode()) > 200
    async with learning_store(dsn) as store:
        await WRITERS[kind](store, BLUE, "é" * 100)
        before = _rows(dsn)
        assert len(before) == 1, "control: the same path takes a key of exactly the bound"
        with pytest.raises(store_mod().ItemRefused):
            await WRITERS[kind](store, BLUE, key)
        assert _rows(dsn) == before


async def test_one_oversized_row_refuses_a_whole_publish_and_writes_none_of_it(dsn):
    """A publish of three findings, the last over the bound, stores none of them. (O1, key bound)"""
    async with learning_store(dsn) as store:
        with pytest.raises(store_mod().ItemRefused):
            await store.publish_findings(BLUE, "run-1", [finding("ok-1"), finding("ok-2"), finding("x" * 201)], kind="finding")
        assert _rows(dsn) == []
        assert await store.publish_findings(BLUE, "run-1", [finding("ok-1"), finding("ok-2")], kind="finding") == (2, 0)


async def test_a_refused_request_supersedes_nothing(dsn):
    """An oversized request for a case leaves the case's earlier waiting request waiting. (O1, key bound)"""
    async with learning_store(dsn) as store:
        assert await _request(store, BLUE, "run-1") is True
        with pytest.raises(store_mod().ItemRefused):
            await _request(store, BLUE, "r" * 201)
        assert [(i.key, i.status) for i in await store.work(BLUE, kind="curation_request")] == [("run-1", "waiting")]
        assert await _request(store, BLUE, "run-2") is True, "control: a later in-bound request does supersede"
        assert [(i.key, i.status) for i in await store.work(BLUE, kind="curation_request")][0] == ("run-1", "skipped")


async def test_items_with_keys_at_the_bound_are_listed_and_page_one_at_a_time(dsn):
    """Held items whose keys are exactly 200 bytes are set aside, listed and paged by `set_aside`. (O1, key bound)"""
    async with learning_store(dsn) as store:
        await held_by_close(store, BLUE, [("finding", k) for k in FITS])
        got = await page_through(store, BLUE, limit=1)
    assert sorted(i.key for i in got) == sorted(FITS)
    assert [i.key for i in got] == sorted(FITS, key=lambda k: k.encode("utf-8"), reverse=True), "codepoint order"
