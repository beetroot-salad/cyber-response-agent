"""#1243 suite fixtures: the configured roots a scenario must never share with the host.

The `alert_front_door_1222/conftest.py` shape: the learning-state root and the launcher's
episodes root are pointed under the test's own `tmp_path`, so the front-door runs and the
launcher scenario here write nothing outside it. `monkeypatch.setenv` only — never `setattr`.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from defender.tests import _triplet_947 as T


@pytest.fixture(autouse=True)
def _isolated_roots_1243(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "episodes-root"
    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(root))
    T.isolate_learning_state(tmp_path, monkeypatch)
    return root
