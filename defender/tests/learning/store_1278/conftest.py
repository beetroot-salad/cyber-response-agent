"""#1278 a database of each test's own, at head."""
from __future__ import annotations

from defender.tests.support.shared._postgres1339 import (  # noqa: F401 — fixtures for this directory
    empty_database,
    migrated_database,
)
