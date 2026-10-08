"""#1224 suite fixtures: the configured roots every launcher scenario needs.

The launcher reads its episodes root from configuration (`DEFENDER_EPISODES_BASE`, no default:
`cli.episodes_root` refuses an unset one), and an accepted launch ends in the judge, which
appends to the learning-state queues under `DEFENDER_LEARNING_STATE_DIR` — by default inside the
checkout. Both are pointed under the test's own `tmp_path` for every test in this directory, so
no scenario passes or fails on the ambient environment, and none writes outside its tmp dir.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from defender.tests.live_oracle_1224 import _spec1224 as S


@pytest.fixture(autouse=True)
def _configured_roots_1224(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "episodes-root"
    monkeypatch.setenv(S.T.EPISODES_BASE_ENV, str(root))
    S.T.isolate_learning_state(tmp_path, monkeypatch)
    return root
