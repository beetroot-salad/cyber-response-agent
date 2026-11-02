"""#1214 attack-2 D1: a malformed tenant id is an unknown tenant to the repository, on both twins (r9 Endpoints '404 unknown
tenant'): the read answers None, every request NotFound, and the repository gains no row. Fails on 99bf432d1 on PostgreSQL."""
from __future__ import annotations

import pytest

from defender.tests.tenancy.lifecycle_1214.test_1214_repository_contract import (  # noqa: F401 — fixtures and helpers
    NOW,
    T1,
    _refused,
    store,
)

pytestmark = pytest.mark.anyio

#: Not a UUID: a NUL, text, an over-long id (64 is the grammar's bound), empty, non-ASCII, a 100k-character one.
MALFORMED = ["a\x00b", "not-a-tenant-id", "a" * 65, "", "é" * 8, "a" * 100_000]


@pytest.mark.parametrize("bad", MALFORMED, ids=["nul", "text", "65", "empty", "non-ascii", "100k"])
async def test_a_malformed_tenant_id_is_unknown_to_every_read_and_request(store, bad):  # noqa: F811
    """`tenant` answers None and `request_resume/rotate/offboard` NotFound for a malformed id; the one real row stays alone;
    a real tenant is answered on the same channel (control) (RC-3, O2)."""
    await store.seed(T1)
    assert (await store.repo.tenant(T1)).id == T1, "control: a real id is found"
    assert await store.repo.tenant(bad) is None
    await _refused(store.repo.request_resume(bad), "NotFound")
    await _refused(store.repo.request_rotate(bad), "NotFound")
    await _refused(store.repo.request_offboard(bad, now=NOW), "NotFound")
    assert [t.id for t in await store.repo.tenants()] == [T1]
    assert (await store.repo.tenant(T1)).id == T1, "control: the connection still answers after the malformed ones"
