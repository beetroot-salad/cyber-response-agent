"""#665 — box delivery: `CuratorDeps.for_run` requires a box."""
from __future__ import annotations


import pytest


pytest.importorskip("pydantic_ai")

from defender import box as box_mod

pytestmark = pytest.mark.e2e

SALT = "s665"


def _curator_for_run(tmp_path, *, box):
    """Build a curator's deps through the REAL production wrapper CuratorDeps.for_run with
    the future required `box=`. TypeError at HEAD. Sets up a real worktree defender tree so
    the wrapped bind() actually resolves (the future green path)."""
    from defender.learning.author.curator_engine import (
        SHIPPED_LESSON_CORPORA,
        CuratorDeps,
    )

    repo = tmp_path / "repo"
    dtree = repo / "defender"
    for name in SHIPPED_LESSON_CORPORA:
        (dtree / name).mkdir(parents=True, exist_ok=True)
    run_dir = tmp_path / "lrd"
    run_dir.mkdir(exist_ok=True)  # both curator helpers may run against one tmp_path
    return CuratorDeps.for_run(
        run_dir,
        repo,
        dtree / "lessons",
        box=box,
    )


def test_box_delivery_absence_does_not_silently_re_dead_the_lane(tmp_path):
    with pytest.raises(TypeError):
        _curator_for_run_no_box(tmp_path)

    delivered = box_mod.BoxExecutor(name="box")
    assert _curator_for_run(tmp_path, box=delivered).box is delivered


def _curator_for_run_no_box(tmp_path):
    from defender.learning.author.curator_engine import (
        SHIPPED_LESSON_CORPORA,
        CuratorDeps,
    )

    repo = tmp_path / "repo"
    dtree = repo / "defender"
    for name in SHIPPED_LESSON_CORPORA:
        (dtree / name).mkdir(parents=True, exist_ok=True)
    run_dir = tmp_path / "lrd"
    run_dir.mkdir(exist_ok=True)  # both curator helpers may run against one tmp_path
    return CuratorDeps.for_run(
        run_dir,
        repo,
        dtree / "lessons",
    )
