"""The lifecycle world's learning database (#1278 O6). Offboarding purges the tenant's learning rows and refuses where
`DEFENDER_DATABASE_DSN` is unset, so every case in this folder runs with one: a migrated database of its own where the
test server is configured, else a store stand-in that purges nothing. A case that tests the unset refusal deletes the
variable itself."""
from __future__ import annotations

import os
from collections.abc import Iterator

import pytest

from defender.tests.support.shared import _postgres1339 as pg

DSN_ENV = "DEFENDER_DATABASE_DSN"


class _NoStore:
    """Where no test server is configured: offboarding's store call, which has nothing to purge."""

    def __init__(self, dsn: str) -> None:
        self.dsn = dsn

    async def offboard(self, tenant: str, *, wait: float) -> None:
        return None

    async def close(self) -> None:
        return None


@pytest.fixture(autouse=True)
def _the_world_has_a_learning_database(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    if os.environ.get(pg.DSN_ENV):
        with pg.database(migrated=True) as dsn:
            monkeypatch.setenv(DSN_ENV, dsn)
            yield
        return
    import defender.learning.store as store

    monkeypatch.setattr(store, "LearningStore", _NoStore)  # lint-monkeypatch: ok — the host actor imports the store inside its offboarding step; no seam carries one in
    monkeypatch.setenv(DSN_ENV, "postgresql://stand-in/none")
    yield
