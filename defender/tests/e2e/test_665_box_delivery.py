"""#665 — box delivery: `CuratorDeps.for_run` requires a box."""
from __future__ import annotations


import pytest


pytest.importorskip("pydantic_ai")

from defender import box as box_mod

pytestmark = pytest.mark.e2e

_OMITTED = object()


def _curator_for_run(tmp_path, *, box=_OMITTED):
    """Curator deps through the real `CuratorDeps.for_run`, over a real worktree defender tree
    so the wrapped `bind()` resolves. `box=` is passed only when given."""
    from defender.learning.author.curator_engine import (
        SHIPPED_LESSON_CORPORA,
        CuratorDeps,
    )

    repo = tmp_path / "repo"
    dtree = repo / "defender"
    for name in SHIPPED_LESSON_CORPORA:
        (dtree / name).mkdir(parents=True, exist_ok=True)
    run_dir = tmp_path / "lrd"
    run_dir.mkdir(exist_ok=True)  # both arms of the test run against one tmp_path
    kw = {} if box is _OMITTED else {"box": box}
    return CuratorDeps.for_run(run_dir, repo, dtree / "lessons", **kw)


def test_box_delivery_absence_does_not_silently_re_dead_the_lane(tmp_path):
    with pytest.raises(TypeError):
        _curator_for_run(tmp_path)

    delivered = box_mod.BoxExecutor(name="box")
    assert _curator_for_run(tmp_path, box=delivered).box is delivered
