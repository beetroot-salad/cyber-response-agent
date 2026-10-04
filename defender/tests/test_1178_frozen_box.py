"""#1178 D1' against a real box: `runtime.box.frozen` holds a live writer still.

A drain box is started the way the lead-author drain starts one (`_drain_box_request`: the
worktree read-only, `defender/skills` read-write) over a temp git worktree. A writer loop inside
it appends to a file under `skills/`. While `frozen(box)` holds, the gate's read of that file
(`read_at` through the lane's held mount), a read a second later, and the committed blob are the
same bytes; once it is left, the file grows again.

Self-skips like the other real-box suites (`requires_real_box`: no daemon, a docker-outside-of-
Docker tree no bind source resolves under, or the levered runtime not registered). CI's `test`
job runs it under runsc.
"""
from __future__ import annotations

import shlex
import shutil
import time
import uuid
from pathlib import Path

import pytest

from defender import _git
from defender.learning.author import shared as _author_shared
from defender.learning.core import drains
from defender.learning.core.config import LEAD_AUTHOR_DRAIN_LABEL, LoopPaths
from defender.learning.core.lane_trees import open_drain_trees, read_at
from defender.runtime import box as box_mod
from defender.tests._declared869 import commit_all, init_git
from defender.tests._lead_author_1134 import write
from defender.tests.e2e._spec771 import DEFENDER, requires_real_box

#: The file the box's writer appends to, below the `skills/` mount.
WRITTEN = "elastic/_draft/w1178.md"
REL = f"defender/skills/{WRITTEN}"

#: The three files the box image's name is a function of: copied into the temp worktree's
#: `defender/` so the drain request resolves the image this checkout's CI built.
IMAGE_INPUTS = ("box.Dockerfile", "uv.lock", "pyproject.toml")


def _worktree(tmp_path: Path) -> Path:
    wt = init_git(tmp_path / "wt")
    write(wt / "defender" / "skills" / WRITTEN, "seed\n")
    commit_all(wt, "seed")
    for name in IMAGE_INPUTS:
        shutil.copyfile(DEFENDER / name, wt / "defender" / name)
    return wt


def _grew(path: Path, past: int, *, within: float = 10.0) -> bool:
    """Whether `path` grows past `past` bytes within `within` seconds."""
    deadline = time.monotonic() + within
    while time.monotonic() < deadline:
        if path.stat().st_size > past:
            return True
        time.sleep(0.1)
    return False


@requires_real_box
@pytest.mark.box
def test_a_frozen_box_writes_nothing_between_the_gates_read_and_the_commit(
        tmp_path: Path, monkeypatch):
    from defender.runtime.box import frozen

    # A startup fault must fail this test, never degrade to a host executor nothing freezes.
    monkeypatch.delenv("DEFENDER_ALLOW_UNSANDBOXED", raising=False)
    wt = _worktree(tmp_path)
    paths = LoopPaths(repo_root=wt, state_dir=tmp_path / "state")
    assert box_mod.image_tag(wt / "defender") == box_mod.image_tag(DEFENDER)
    target = paths.skills_dir / WRITTEN
    request = drains._drain_box_request(
        wt, f"f1178-{uuid.uuid4().hex[:8]}", LEAD_AUTHOR_DRAIN_LABEL, paths,
    )
    box = box_mod.start_box(request)
    try:
        assert box.sandboxed, "start_box handed back a host executor"
        loop = f"while :; do printf X >> {shlex.quote(str(target))}; sleep 0.05; done"
        started = box_mod._docker(["docker", "exec", "-d", box.name, "sh", "-c", loop])
        assert started.returncode == 0, started.stderr
        # Control: the writer is live, so "unchanged while frozen" is not vacuous.
        assert _grew(target, target.stat().st_size), "the writer inside the box never wrote"

        with open_drain_trees(paths, LEAD_AUTHOR_DRAIN_LABEL) as trees, frozen(box):
            judged, reason = read_at(wt, trees.tree_for, REL)
            time.sleep(1.0)
            sha = _author_shared.commit_corpus(
                wt, wt / "defender" / "skills", "learning(lead-author): frozen gate",
            )
            again, _ = read_at(wt, trees.tree_for, REL)
        assert judged is not None, reason
        assert again == judged, "the box wrote while frozen"
        assert sha is not None, "nothing was committed"
        assert _git.git_show_file(wt, "HEAD", REL) == judged
        assert _grew(target, len(judged.encode("utf-8"))), "the box did not resume after the freeze"
    finally:
        # Best effort: a box left paused by a failed assertion is still torn down.
        box_mod._docker(["docker", "unpause", box.name])
        box_mod.stop_box(box)
