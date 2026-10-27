"""#665 — live box mechanism confirmations against a real Docker daemon (all live-marked): read-only mounts refuse writes, nested mounts, shared tmpfs, granted-repertoire startup probe, pinned lesson scripts resist hostile argv."""
from __future__ import annotations

import dataclasses
import os
import shutil
from pathlib import Path

import pytest

from _box665 import (  # noqa: E402
    DEFENDER,
    REPO_ROOT,
    BoxRequest,
    Mount,
    make_run_dir,
    requires_live_box,
    run_cycle_mounts,
    start_box_request,
)

pytest.importorskip("pydantic_ai")

from defender.execution import bash_exec  # noqa: E402
from defender import box as box_mod  # noqa: E402

pytestmark = [pytest.mark.e2e, pytest.mark.live, requires_live_box]

EXEC_TIMEOUT = 60.0


def _run(box, cmd: str, cwd: Path):
    return box.run_parsed(bash_exec.parse(cmd), command=cmd, cwd=cwd, timeout=EXEC_TIMEOUT)


def _run_cycle_box(tmp_path):
    """Start a real run-cycle box over the caller-composed geography (BoxRequest)."""
    run_dir = make_run_dir(tmp_path)
    (run_dir / "gather_raw").mkdir(exist_ok=True)
    req = BoxRequest(
        name="defender-runcycle-live", workdir=REPO_ROOT, env={},
        mounts=run_cycle_mounts(run_dir),
    )
    return run_dir, start_box_request(req, docker=box_mod._docker)


# Read-only mounts and traversal containment
def test_single_non_overlapping_readonly_mount_refuses_a_direct_in_box_write(tmp_path):
    run_dir = make_run_dir(tmp_path)
    box = box_mod.start_box(run_dir, DEFENDER, docker=box_mod._docker)
    try:
        res = _run(box, "printf x > /defender/spec-probe", cwd=Path("/runs/current"))
        assert res.rc != 0, "a write to the ro defender mount was NOT refused"
    finally:
        box_mod.stop_box(box)


def test_judge_granted_program_computes_an_output_path_that_resolves_inside_gather_raw(tmp_path):
    """A write resolving inside the ro-mounted gather_raw is blocked by the mount itself,
    whatever the program does."""
    run_dir, box = _run_cycle_box(tmp_path)
    try:
        res = _run(box, f"printf x > {run_dir / 'gather_raw' / 'out'}", cwd=run_dir)
        assert res.rc != 0, "a write into the ro gather_raw mount was NOT refused"
    finally:
        box_mod.stop_box(box)


# Nested mounts and tmpfs
def test_two_mounts_with_nested_or_overlapping_sources_and_targets(tmp_path):
    """The deeper mount governs its subtree: rw inside ro works (the drain's shape, a read-only
    worktree with a writable corpus)."""
    outer = tmp_path / "wt"
    inner = outer / "defender" / "lessons"
    inner.mkdir(parents=True)
    # The outer worktree is a `code` mount, so it carries the committed check file at
    # `<workdir>/defender`, as a checkout does.
    check = box_mod.CODE_CHECK_FILE
    shutil.copyfile(DEFENDER / check, outer / "defender" / check)
    req = BoxRequest(
        name="defender-nested-live", workdir=outer, env={},
        mounts=(Mount(source=outer, target=outer, writable=False, kind="code"),
                Mount(source=inner, target=inner, writable=True)),
        spec=dataclasses.replace(box_mod.BoxSpec.from_env(os.environ), rootfs=box_mod.image_tag(DEFENDER)),
    )
    box = start_box_request(req, docker=box_mod._docker)
    try:
        assert _run(box, f"printf x > {outer / 'o'}", cwd=outer).rc != 0, "outer ro not enforced"
        assert _run(box, f"printf x > {inner / 'n'}", cwd=outer).rc == 0, "inner rw override lost"
    finally:
        box_mod.stop_box(box)


def test_tmpfs_contents_persist_across_execs_within_one_box_lifetime(tmp_path):
    run_dir = make_run_dir(tmp_path)
    box = box_mod.start_box(run_dir, DEFENDER, docker=box_mod._docker)
    try:
        _run(box, "printf shared > /tmp/spec-shared", cwd=Path("/runs/current"))
        res = _run(box, "cat /tmp/spec-shared", cwd=Path("/runs/current"))
        assert res.rc == 0, "the tmpfs read-back exec failed"
        assert b"shared" in res.out, "tmpfs did not persist across execs"
    finally:
        box_mod.stop_box(box)


@pytest.mark.parametrize(("case", "cmd", "rc_why", "contains", "contains_why"), [
    # the granted repertoire itself imports: a broken one fails the box
    ("granted-repertoire-runs-clean",
     "python3 -c 'import defender.execution.bash_exec'",
     "the granted interpreter/repertoire did not run clean at startup", None, None),

    # no `.venv` in the box: `python3` is the owned image's own interpreter (#1092)
    ("venv-interpreter-matches-the-image",
     "python3 --version", "the interpreter probe exec failed",
     b"3.11", "the box interpreter did not match the image minor"),

    # a broken native dependency in the image fails too, not only an interpreter mismatch
    ("native-dependency-inside-the-venv-imports",
     "python3 -c 'import duckdb'",
     "a native dependency the granted repertoire needs did not import", None, None),
], ids=lambda v: v if isinstance(v, str) and len(v) < 60 and " " not in v else "")
def test_box_start_probes_the_granted_repertoire_by_running_it(
    tmp_path, case, cmd, rc_why, contains, contains_why
):
    run_dir = make_run_dir(tmp_path)
    box = box_mod.start_box(run_dir, DEFENDER, docker=box_mod._docker)
    try:
        res = _run(box, cmd, cwd=Path("/runs/current"))
        assert res.rc == 0, rc_why
        if contains is not None:
            assert contains in res.out, contains_why
    finally:
        box_mod.stop_box(box)


def test_pinned_lesson_scripts_reject_arbitrary_argv_read(tmp_path):
    run_dir = make_run_dir(tmp_path)
    box = box_mod.start_box(run_dir, DEFENDER, docker=box_mod._docker)
    try:
        allowed = _run(box, "/defender/bin/defender-lessons .", cwd=Path("/runs/current"))
        assert allowed.rc == 0, "the pinned lesson script did not run on its intended operand (positive control)"
        assert allowed.out, "the pinned lesson script returned no corpus content on its intended operand"
        hostile = _run(box, "/defender/bin/defender-lessons /etc/passwd",
                       cwd=Path("/runs/current"))
        assert b"root:" not in hostile.out, "a pinned lesson script leaked an arbitrary file via argv"
    finally:
        box_mod.stop_box(box)
