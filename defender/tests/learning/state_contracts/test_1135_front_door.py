"""#1135/#1186 — tenant-selected state and explicit scratch roots preserve handle I/O routes."""
from __future__ import annotations

from pathlib import Path

import pytest

from defender.tests.learning.state_contracts import _spec1135 as S


def test_the_kept_root_routes_still_resolve(
    data_root: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from defender.learning.core import config
    from defender.tests.support.shared.contracts._data_root_1078 import set_up_tenant

    tenant = set_up_tenant(data_root)
    tenant.learning.mkdir(parents=True, exist_ok=True)
    # Overlapping ambient values formerly refused tenant acceptance. They are now inert.
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(data_root))
    paths = config.LoopPaths.for_tenant(tenant)
    assert paths.state_root == tenant.learning
    other = tmp_path / "explicit-scratch-state"
    assert config.LoopPaths(repo_root=tmp_path / "repo", state_dir=other).state_root == other

    with S.LearningState.open(paths) as state:
        channel = S.coined("FINDINGS")
        described = state.describe(channel)
        assert described == str(tenant.learning / channel.queue)
        row = {"finding_id": "front-door/0", "run_id": "front-door"}
        assert state.append(channel, [row]) == (1, 0)
        assert state.rows(channel) == [row]
    assert not (data_root / channel.queue).exists(), "the old ambient root received the queue"
