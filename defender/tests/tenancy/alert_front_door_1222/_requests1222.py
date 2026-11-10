"""The learning store a run start files its curation request in, as a recording stand-in (#1278).

`run_common.enqueue_curation` files a request through `learning.store.blocking(dsn)` (rows, no `author-queue` folder). The
front door's cases judge WHICH runs production files a request for and under what key; the store's own rows and rules
are `tests/learning/store_1278`'s. So the store verb a run start calls (`enqueue_request`) records into `FILED`, reached
through the database address the entrypoint reads."""
from __future__ import annotations

import contextlib
from typing import Any

import pytest


class RequestStore:
    def __init__(self) -> None:
        self.requests: dict[str, dict[str, Any]] = {}

    def enqueue_request(self, tenant_id: str, run_id: str, case_id: str, payload: dict[str, Any]) -> None:
        self.requests[case_id] = {**payload, "tenant_id": tenant_id, "run_id": run_id}


FILED = RequestStore()


@pytest.fixture(autouse=True)
def a_store_that_records_requests(monkeypatch: pytest.MonkeyPatch) -> RequestStore:
    from defender import tenancy
    from defender.learning import store

    FILED.requests.clear()

    @contextlib.contextmanager
    def blocking(_dsn: str, **_knobs: Any):
        yield FILED

    monkeypatch.setenv(tenancy.database_address_variable(), "postgresql://a-store-that-records/requests")
    monkeypatch.setattr(store, "blocking", blocking)
    return FILED
