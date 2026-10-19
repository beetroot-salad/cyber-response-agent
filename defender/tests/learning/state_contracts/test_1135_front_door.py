"""#1135 — the front door: the kept root routes (env var, LoopPaths(state_dir=)) still resolve."""
from __future__ import annotations

from pathlib import Path

import pytest

from defender.tests.learning.state_contracts import _spec1135 as S


def test_the_kept_root_routes_still_resolve(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from defender.tenancy import _tenant
    from defender.learning.core import config

    root = tmp_path / "learning-state"
    root.mkdir()
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(root))
    resolved = config.loop_paths()
    assert resolved.state_root == root.resolve(), (
        f"loop_paths() did not resolve the env's root at call time: {resolved.state_root}")
    other = tmp_path / "elsewhere"
    assert config.LoopPaths(repo_root=tmp_path / "repo", state_dir=other).state_root == other, (
        "LoopPaths(state_dir=...) no longer names its root")

    data_root = tmp_path / "data"
    data_root.mkdir()
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(data_root / "t" / "learning"))
    refused = S.caught(lambda: _tenant._refuse_widened_learning_state_overlap(data_root))
    assert isinstance(refused, _tenant.TenantRefused), (
        f"an overlapping state dir was not refused: {refused!r}")
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(root))
    clear = S.caught(lambda: _tenant._refuse_widened_learning_state_overlap(data_root))
    assert clear is None, f"a disjoint state dir was refused: {clear!r}"

    state = S.LearningState.open(config.loop_paths())
    described = state.describe(S.coined("FINDINGS"))
    assert isinstance(described, str), f"describe must give a display string: {described!r}"
    assert Path(described).is_relative_to(root.resolve()), (
        f"the handle on loop_paths() does not hold the env's root: describe gave {described!r}")
