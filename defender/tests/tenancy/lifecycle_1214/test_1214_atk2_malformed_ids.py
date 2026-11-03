"""#1214 attack-2 D1, as #1382 P-ID restates it: a malformed tenant id never reaches the repository past the API (which
answers 422), and the PostgreSQL repository refuses one loudly, naming it, before any query: the read and every request
raise, and the repository gains no row. (D1's "an unknown tenant" answer is withdrawn with D-a; the in-memory twin does
not check ids, #1382 O6.)"""
from __future__ import annotations

import pytest

from defender.tests.tenancy.lifecycle_1214.test_1214_repository_contract import (  # noqa: F401 — fixtures and helpers
    NOW,
    T1,
    pg_store,
)

pytestmark = pytest.mark.anyio

#: Not a UUID: a NUL, text, an over-long id, empty, non-ASCII, a 100k-character one.
MALFORMED = ["a\x00b", "not-a-tenant-id", "a" * 65, "", "é" * 8, "a" * 100_000]


@pytest.mark.parametrize("bad", MALFORMED, ids=["nul", "text", "65", "empty", "non-ascii", "100k"])
async def test_a_malformed_tenant_id_is_refused_by_every_read_and_request(pg_store, bad):  # noqa: F811
    """`tenant` and `request_resume/rotate/offboard` raise the tenant refusal for a malformed id; the one real row stays
    alone; a real tenant is answered on the same channel (control) (RC-3, O2, #1382 P-ID)."""
    from sqlalchemy.exc import StatementError

    from defender.records.formats import TenantRefused

    store = pg_store
    await store.seed(T1)
    assert (await store.repo.tenant(T1)).id == T1, "control: a real id is found"
    for call in (store.repo.tenant(bad), store.repo.request_resume(bad), store.repo.request_rotate(bad),
                 store.repo.request_offboard(bad, now=NOW)):
        with pytest.raises(StatementError) as refused:
            await call
        assert isinstance(refused.value.orig, TenantRefused)
    assert [t.id for t in await store.repo.tenants()] == [T1]
    assert (await store.repo.tenant(T1)).id == T1, "control: the connection still answers after the malformed ones"
