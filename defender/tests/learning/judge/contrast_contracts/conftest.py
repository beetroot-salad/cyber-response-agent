"""#1234 suite fixtures: the configured roots every scenario needs.

Episodes live under the per-test `DEFENDER_DATA_ROOT` (`defender/tests/conftest.py`). Here every
test also points the learning-state queues (`DEFENDER_LEARNING_STATE_DIR`, by default inside the
checkout) under its own `tmp_path` and sets a fast `ORACLE_RATE` for real-path siblings, so no
scenario depends on or writes to the ambient environment.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from defender.tests.learning.judge.contrast_contracts import _spec1234 as S


@pytest.fixture(autouse=True)
def _configured_roots_1234(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    S.isolate_learning_state(tmp_path, monkeypatch)
    # The default oracle rate (5/s) really sleeps between oracle-side queries; a real-path
    # sibling would pay it on every call.
    monkeypatch.setenv(S.KNOB_RATE, "1e6")
