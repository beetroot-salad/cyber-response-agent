"""#1243 suite fixtures: the learning-state root points under the test's own `tmp_path` (as in
`alert_front_door_1222/conftest.py`), so nothing here writes outside it. `monkeypatch.setenv`
only, never `setattr`.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from defender.tests.support.learning.branch import _triplet_947 as T


@pytest.fixture(autouse=True)
def _isolated_roots_1243(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    T.isolate_learning_state(tmp_path, monkeypatch)
