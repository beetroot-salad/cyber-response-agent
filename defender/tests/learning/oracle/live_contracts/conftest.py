"""#1224 suite fixtures: per-test scratch roots and a fast oracle rate.

Judge passes insert their findings into an in-memory findings store of the test's own (#1278; see
`test_1224_judge.env_state`). Episodes live under the
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
    # A launched episode's judge pass inserts into the learning store at the host's database address (#1278):
    # the in-memory stand-in, so no scenario needs a database to be graded.
    S.J.install_launcher_store(monkeypatch)
