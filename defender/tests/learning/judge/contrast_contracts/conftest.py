"""#1234 suite fixtures: the configured roots every scenario needs.

The judge opens its episode by id under its tenant's `<data root>/<T>/episodes/` (#1187 O9: no
configured episodes root; the data root, `DEFENDER_DATA_ROOT`, is already a fresh tmp dir per
test, `defender/tests/conftest.py`), appends to the learning-state queues under
`DEFENDER_LEARNING_STATE_DIR` (by default inside the checkout), and a real-path sibling reads its
oracle rate from `ORACLE_RATE`. Both are pointed under the test's own `tmp_path` for every test in
this directory, so no scenario passes or fails on the ambient environment and none writes outside
its tmp dir.
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
