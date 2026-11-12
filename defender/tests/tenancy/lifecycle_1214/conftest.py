"""The lifecycle world's learning database (#1278 O6): see `_support.learning_database`. Every case in this folder runs with
one; a case that tests the unset refusal deletes the variable itself."""
from __future__ import annotations

from collections.abc import Iterator

import pytest

from defender.tests.tenancy.lifecycle_1214._support import learning_database


@pytest.fixture(autouse=True)
def _the_world_has_a_learning_database(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    with learning_database(monkeypatch):
        yield
