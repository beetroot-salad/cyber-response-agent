"""#1224 suite fixtures: the configured roots every launcher scenario needs.

An accepted launch ends in the judge, which appends to the learning-state queues under
`DEFENDER_LEARNING_STATE_DIR` — by default inside the checkout. It is pointed under the test's own
`tmp_path` for every test in this directory, so no scenario passes or fails on the ambient
environment, and none writes outside its tmp dir. The launcher's episodes live under the tenant
(`<data root>/<T>/episodes/`, #1187 O9) — the data root is already a fresh tmp dir per test — so
no episodes root is configured.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from defender.tests.learning.oracle.live_contracts import _spec1224 as S


@pytest.fixture(autouse=True)
def _configured_roots_1224(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    S.T.isolate_learning_state(tmp_path, monkeypatch)
    # The default oracle rate (5/s) really sleeps between oracle-side queries, so every launch
    # paid it. A test about the rate sets its own (`rate=`, its own limiter, or this knob).
    monkeypatch.setenv(S.KNOB_RATE, "1e6")
