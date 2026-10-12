"""#1234 suite fixtures: the configured roots every scenario needs.

The judge opens its episode by id under the configured episodes root (`DEFENDER_EPISODES_BASE`,
no default), appends to the learning-state queues under `DEFENDER_LEARNING_STATE_DIR` (by
default inside the checkout), and a real-path sibling reads its oracle rate from `ORACLE_RATE`.
All three are pointed under the test's own `tmp_path` for every test in this directory, so no
scenario passes or fails on the ambient environment and none writes outside its tmp dir. The
data root (`DEFENDER_DATA_ROOT`) is already a fresh tmp dir per test (`defender/tests/conftest.py`).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from defender.tests.judge_contrast_1234 import _spec1234 as S


@pytest.fixture(autouse=True)
def _configured_roots_1234(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "episodes-root"
    root.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv(S.EPISODES_BASE_ENV, str(root))
    S.isolate_learning_state(tmp_path, monkeypatch)
    # The default oracle rate (5/s) really sleeps between oracle-side queries; a real-path
    # sibling would pay it on every call.
    monkeypatch.setenv(S.KNOB_RATE, "1e6")
    return root
