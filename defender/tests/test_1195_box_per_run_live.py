"""#1195 amendment (2026-10-06), O3' against a real box: a process an agent leaves behind does not
outlive that agent's run. Replaces #1178's frozen-box row.

A box source is built the way the drain builds one (`_drain_box_request`: the worktree
read-only, `defender/skills` read-write, the lead-author lane's mounts) over a temp git
worktree, with the real `start_box`/`stop_box`. Run 1 leaves a writer loop running inside its
box, appending to a file under `skills/`:

- during run 1 the file grows (the positive control: the writer is live);
- after run 1's teardown it does not grow;
- during run 2 — the same source, so the same container name — it still does not grow: the
  writer did not survive into run 2's box. A writer run 2 starts does grow (run 2's box runs);
- after the batch-end teardown no container holds the name, and the file run 1's writer left
  is what the production committer commits.

Self-skips like the other real-box suites (`requires_real_box`: no daemon, a
docker-outside-of-Docker tree no bind source resolves under, or the levered runtime not
registered). CI's `test` job runs it under runsc.
"""
from __future__ import annotations

import shlex
import time
import uuid
from pathlib import Path

import pytest

from defender import _git
from defender.learning.core import drains
from defender.learning.core.config import LEAD_AUTHOR_DRAIN_LABEL, LoopPaths
from defender.runtime import box as box_mod
from defender.tests import _box1195 as X
from defender.tests._claim1175 import claim_git
from defender.tests._declared869 import commit_all, init_git
from defender.tests._lead_author_1134 import write
from defender.tests.e2e._spec771 import DEFENDER, requires_real_box

#: The files the boxes' writers append to, below the `skills/` mount.
LEFT = "elastic/_draft/left1195.md"
FRESH = "elastic/_draft/fresh1195.md"

#: How long a writer that must be gone is watched for a write it must not make.
STILL_FOR = 1.0


def _worktree(tmp_path: Path) -> Path:
    wt = init_git(tmp_path / "wt")
    write(wt / "defender" / "skills" / LEFT, "seed\n")
    write(wt / "defender" / "skills" / FRESH, "seed\n")
    commit_all(wt, "seed")
    X.plant_image_inputs(wt)
    return wt


def _grew(path: Path, past: int, *, within: float = 10.0) -> bool:
    """Whether `path` grows past `past` bytes within `within` seconds."""
    deadline = time.monotonic() + within
    while time.monotonic() < deadline:
        if path.stat().st_size > past:
            return True
        time.sleep(0.1)
    return False


def _held_still(path: Path) -> bool:
    """Whether `path`'s size stays put for `STILL_FOR` seconds."""
    before = path.stat().st_size
    time.sleep(STILL_FOR)
    return path.stat().st_size == before


def _leave_a_writer(box: object, target: Path) -> None:
    """A detached loop inside `box` appending to `target`: what an agent leaves running."""
    loop = f"while :; do printf X >> {shlex.quote(str(target))}; sleep 0.05; done"
    started = box_mod._docker(["docker", "exec", "-d", box.name, "sh", "-c", loop])
    assert started.returncode == 0, started.stderr


@requires_real_box
@pytest.mark.box
def test_a_writer_an_agent_leaves_dies_with_its_run_and_never_writes_in_the_next(
        tmp_path: Path, monkeypatch):
    # A startup fault must fail this test, never degrade to a host executor no teardown removes.
    X.clear_opt_out(monkeypatch)
    wt = _worktree(tmp_path)
    paths = LoopPaths(repo_root=wt, state_dir=tmp_path / "state")
    assert box_mod.image_tag(wt / "defender") == box_mod.image_tag(DEFENDER)
    left, fresh = paths.skills_dir / LEFT, paths.skills_dir / FRESH
    request = drains._drain_box_request(
        wt, f"t1195-{uuid.uuid4().hex[:8]}", LEAD_AUTHOR_DRAIN_LABEL, paths,
    )
    source = X.box_source(request)
    try:
        with source.run() as box:
            assert box.sandboxed, "start_box handed back a host executor"
            _leave_a_writer(box, left)
            # Control: the writer is live, so "gone after the run" is not vacuous.
            assert _grew(left, left.stat().st_size), "the writer inside run 1's box never wrote"
        assert _held_still(left), "a writer run 1 left wrote after run 1's teardown"
        judged = left.read_text(encoding="utf-8")

        with source.run() as box:
            assert box.sandboxed, box
            assert box.name == request.name, "run 2 asked for some other container name"
            assert _held_still(left), "run 1's writer wrote during run 2"
            _leave_a_writer(box, fresh)
            assert _grew(fresh, fresh.stat().st_size), "run 2's own box never ran its writer"
        assert _held_still(fresh), "a writer run 2 left wrote after run 2's teardown"
    finally:
        source.teardown()

    probe = box_mod._docker(["docker", "inspect", "-f", "{{.State.Status}}", request.name])
    assert probe.returncode != 0, f"a container still holds {request.name}: {probe.stdout}"
    rel = f"defender/skills/{LEFT}"
    sha = claim_git(wt).commit([rel], "learning(lead-author): what run 1 left")
    assert sha is not None, "nothing was committed"
    assert _git.git_show_file(wt, "HEAD", rel) == judged
    assert left.read_text(encoding="utf-8") == judged, "the file changed after the commit"
