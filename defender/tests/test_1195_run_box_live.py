"""#1195 design amendment 3 (2026-10-06) against a real box: the batch's one box, stopped between
agent runs, keeps nothing a run left running or left in its scratch space, and keeps its link
ban. Replaces #1178's frozen-box row (`test_1178_frozen_box.py`).

The box is created the way the lead-author drain creates one, by the real `start_box` over the
real `_drain_box_request` (the worktree read-only, `defender/skills` read-write) on a temp git
worktree, wrapped in the lanes' handle (`runtime.box.BoxRuns`) and stopped at once
(`runs.stop()`, as `_run_worktree_batch` does), every call through the real docker the executor
carries. Each run is the spawn sites' `box_for_run(handle)`, which yields the executor:

- run 1 leaves a writer loop running inside the box, appending to a file under `skills/`, and
  leaves a marker in `/tmp` and in `/dev/shm`. During run 1 the file grows, the writer is in the
  box's process table and both markers are there (the positive controls);
- after run 1's stop the file does not grow;
- during run 2 (the same container, started again) the file still does not grow, no process
  carries the writer's command, and neither marker is there; `ln -s` and `ln` in the writable
  mount are still refused, while an ordinary create there succeeds;
- `box_for_run` refuses a box someone started outside a run, naming its status: its body never
  runs, and the box is stopped again;
- the batch-end `stop_box` leaves no container holding the name, and the file run 1's writer
  left is what the production committer commits.

Self-skips like the other real-box suites (`requires_real_box`: no daemon, a docker-outside-of-
Docker tree no bind source resolves under, or the levered runtime not registered). CI's `test`
job runs it under runsc.
"""
from __future__ import annotations

import os
import shlex
import time
import uuid
from pathlib import Path

import pytest

from defender import _git
from defender.learning.core import drains
from defender.learning.core.config import LEAD_AUTHOR_DRAIN_LABEL, LoopPaths
from defender.runtime import box as box_mod
from defender.runtime.box import BoxFault
from defender.tests import _box1195 as X
from defender.tests._claim1175 import claim_git
from defender.tests._declared869 import commit_all, init_git
from defender.tests._lead_author_1134 import write
from defender.tests.e2e._spec771 import DEFENDER, requires_real_box

#: The file run 1's writer appends to, below the `skills/` mount.
LEFT = "elastic/_draft/left1195.md"

#: What run 1 leaves in the box's scratch space: a run 2 that finds either kept it.
MARKERS = ("/tmp/m1195", "/dev/shm/m1195")

#: How long a writer that must be gone is watched for a write it must not make.
STILL_FOR = 1.0

#: Counts the processes whose command line carries the writer's file name, built from two
#: halves so this script's own command line never matches.
_COUNT_WRITERS = """
import os
needle = ("left" + "1195").encode()
n = 0
for pid in os.listdir("/proc"):
    if pid.isdigit():
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                if needle in f.read():
                    n += 1
        except OSError:
            pass
print(n)
"""


def _worktree(tmp_path: Path) -> Path:
    wt = init_git(tmp_path / "wt")
    write(wt / "defender" / "skills" / LEFT, "seed\n")
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


def _exec(box: box_mod.BoxExecutor, *argv: str, cwd: Path | None = None) -> tuple[int, str]:
    flags = ["-w", str(cwd)] if cwd is not None else []
    proc = box_mod._docker(["docker", "exec", *flags, box.name, *argv])
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def _status(name: str) -> str:
    return box_mod._docker(["docker", "inspect", "-f", "{{.State.Status}}", name]).stdout.strip()


def _writers(box: box_mod.BoxExecutor) -> int:
    rc, out = _exec(box, "python3", "-c", _COUNT_WRITERS)
    assert rc == 0, out
    return int(out.strip())


def _leave_a_writer(box: box_mod.BoxExecutor, target: Path) -> None:
    """A detached loop inside `box` appending to `target`: what an agent leaves running."""
    loop = f"while :; do printf X >> {shlex.quote(str(target))}; sleep 0.05; done"
    started = box_mod._docker(["docker", "exec", "-d", box.name, "sh", "-c", loop])
    assert started.returncode == 0, started.stderr


def _one_run(runs: object, ran: list[bool]) -> None:
    with X.box_for_run(runs):
        ran.append(True)


@requires_real_box
@pytest.mark.box
def test_a_stopped_box_keeps_nothing_a_run_left_and_keeps_its_link_ban(  # noqa: PLR0915 — one box's whole life
        tmp_path: Path, monkeypatch):
    # A startup fault must fail this test, never degrade to a host executor no stop holds.
    X.clear_opt_out(monkeypatch)
    wt = _worktree(tmp_path)
    paths = LoopPaths(repo_root=wt, state_dir=tmp_path / "state")
    assert box_mod.image_tag(wt / "defender") == box_mod.image_tag(DEFENDER)
    left = paths.skills_dir / LEFT
    request = drains._drain_box_request(
        wt, f"t1195-{uuid.uuid4().hex[:8]}", LEAD_AUTHOR_DRAIN_LABEL, paths,
    )
    box = box_mod.start_box(request)
    try:
        assert box.sandboxed, "start_box handed back a host executor"
        assert box.docker is not None, "start_box handed back an executor that carries no docker"
        runs = X.box_runs(box)
        runs.stop()
        assert _status(box.name) == "exited", "the post-create stop left the box up"

        with X.box_for_run(runs) as run_box:
            assert run_box is box, "a run handed its spawn something but the batch's executor"
            _leave_a_writer(box, left)
            for marker in MARKERS:
                rc, out = _exec(box, "sh", "-c", f"printf m > {marker}")
                assert rc == 0, f"run 1 could not leave {marker}: {out}"
            # Controls: the writer is live and listed, the markers stand.
            assert _grew(left, left.stat().st_size), "the writer inside run 1's box never wrote"
            assert _writers(box) >= 1, "the writer is not in the box's process table"
            for marker in MARKERS:
                assert _exec(box, "test", "-e", marker)[0] == 0, f"{marker} is not there in run 1"
        assert _status(box.name) == "exited", "run 1 left the box up"
        assert _held_still(left), "a writer run 1 left wrote after run 1's stop"
        judged = left.read_text(encoding="utf-8")

        with X.box_for_run(runs):
            assert _status(box.name) == "running", "run 2 did not start the box"
            assert _held_still(left), "run 1's writer wrote during run 2"
            assert _writers(box) == 0, "run 1's writer is still in the box's process table"
            for marker in MARKERS:
                assert _exec(box, "test", "-e", marker)[0] != 0, f"run 1's {marker} survived its stop"
            draft = paths.skills_dir / "elastic" / "_draft"
            rc, out = _exec(box, "sh", "-c", "printf x > plain1195", cwd=draft)
            assert rc == 0, f"an ordinary create in the writable mount failed (control): {out}"
            for argv in (["ln", "-s", "plain1195", "sym1195"], ["ln", "plain1195", "hard1195"]):
                rc, out = _exec(box, *argv, cwd=draft)
                assert rc != 0, f"`{' '.join(argv)}` was allowed after a restart: {out}"
                assert not os.path.lexists(draft / argv[-1]), f"`{' '.join(argv)}` left a link"
            (draft / "plain1195").unlink()

        assert box_mod._docker(["docker", "start", box.name]).returncode == 0
        assert _status(box.name) == "running"
        ran: list[bool] = []
        got = X.caught(lambda: _one_run(runs, ran))
        assert isinstance(got, BoxFault), got
        assert "running" in str(got), f"the refusal does not name the status it saw: {got}"
        assert ran == [], "a run's spawn ran in a box someone else had started"
        assert _status(box.name) == "exited", "the refused run left the box up"
    finally:
        box_mod.stop_box(box)

    probe = box_mod._docker(["docker", "inspect", "-f", "{{.State.Status}}", request.name])
    assert probe.returncode != 0, f"a container still holds {request.name}: {probe.stdout}"
    rel = f"defender/skills/{LEFT}"
    sha = claim_git(wt).commit([rel], "learning(lead-author): what run 1 left")
    assert sha is not None, "nothing was committed"
    assert _git.git_show_file(wt, "HEAD", rel) == judged
    assert left.read_text(encoding="utf-8") == judged, "the file changed after the commit"
