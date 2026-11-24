"""Fixtures for the #1618 contract: the scenes (`_support.scene`) and the Postgres-backed delivery fixtures P3 serves.
Every module is named by its absolute name (`defender/tests` has no `__init__.py`)."""
from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from defender.tests.tenancy.knowledge_1618 import _support as K
from defender.tests.tenancy.tenant_1108_delivery._revert_store import migrated_database as migrated_database
from defender.tests.tenancy.tenant_1108_delivery._revert_store import store as store
from defender.tests.tenancy.tenant_1108_delivery._support import repo as repo


@pytest.fixture
def t(tmp_path: Path, data_root: Path) -> Iterator[Any]:
    """The default scene: the upgrade step done (no clone, no `exports/`, no `current`), `main` at the seed."""
    with K.scene(tmp_path, data_root) as scene:
        yield scene


@pytest.fixture
def decoy(tmp_path: Path, data_root: Path) -> Iterator[Any]:
    """The decoy scene: a stale clone, `exports/<seed>/` and `current` the reader must ignore; `main` has moved on."""
    with K.scene(tmp_path, data_root, decoy=True) as scene:
        yield scene
