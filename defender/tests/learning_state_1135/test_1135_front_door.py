"""#1135 — the front door: the kept root routes (env var, LoopPaths(state_dir=)) still resolve."""
from __future__ import annotations

from pathlib import Path

import pytest

from defender.tests.learning_state_1135 import _spec1135 as S


def test_the_kept_root_routes_still_resolve(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The routes the design keeps still work: config.loop_paths() resolves the root from
    DEFENDER_LEARNING_STATE_DIR at call time; LoopPaths(state_dir=...) still names a root;
    _tenant._refuse_widened_learning_state_overlap still reads DEFENDER_LEARNING_STATE_DIR
    directly and still refuses an overlapping data root (D4 "Kept").

    And the handle opened on loop_paths() holds that root: describe of a channel queue is under
    it (JF8 reading A: an absolute path string)."""
    from defender import _tenant
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


# ---------------------------------------------------------------------------------------------
# O4: the root-route scan
# ---------------------------------------------------------------------------------------------


# ---------------------------------------------------------------------------------------------
# D28: a removed name still imported by a lazily loaded module
# ---------------------------------------------------------------------------------------------


