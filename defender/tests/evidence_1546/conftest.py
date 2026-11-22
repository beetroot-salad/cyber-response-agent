"""#1546 sketch (design r6): a database of each test's own, at head (#1342's fixtures), and this test's OpenBao slice."""
from __future__ import annotations

from defender.tests.support.shared._openbao1163 import openbao  # noqa: F401 — fixture for this directory
from defender.tests.support.shared._postgres1339 import (  # noqa: F401 — fixtures for this directory
    empty_database,
    migrated_database,
)
