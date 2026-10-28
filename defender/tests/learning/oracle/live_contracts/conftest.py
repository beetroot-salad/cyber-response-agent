"""#1224 suite fixtures: per-test scratch roots and a fast oracle rate.

`DEFENDER_LEARNING_STATE_DIR` names a per-test scratch root for helpers that open it
(`_state1135.env_state`); launchers use the tenant's own learning state. Episodes live under the
tenant (`<data root>/<T>/episodes/`) in the per-test data root, so no episodes root is configured.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from defender.tests.learning.oracle.live_contracts import _spec1224 as S


@pytest.fixture(autouse=True)
def _configured_roots_1224(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    S.T.isolate_learning_state(tmp_path, monkeypatch)
    # The default oracle rate (5/s) really sleeps between oracle-side queries. A test about the
    # rate sets its own (`rate=`, its own limiter, or this knob).
    monkeypatch.setenv(S.KNOB_RATE, "1e6")
