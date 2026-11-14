"""#1083 a database of each test's own, at head or empty, for the real server's tests."""
from __future__ import annotations

from defender.tests.support.shared._postgres1339 import (  # noqa: F401 — fixtures for this directory
    empty_database,
    migrated_database,
)
from defender.tests.support.api._config1470 import (  # noqa: F401 — fixtures for this directory (#1470)
    configured,
    scripted,
)
from defender.tests.support.shared._openbao1163 import openbao  # noqa: F401 — the real-OpenBao runs of `configured`
