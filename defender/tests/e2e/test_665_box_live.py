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
        mounts=(
            Mount(source=run_dir, target=run_dir, writable=False, kind="data"),
            Mount(source=DEFENDER, target=DEFENDER, writable=False, kind="code"),
            Mount(source=run_dir / "gather_raw", target=run_dir / "gather_raw", writable=False,
                  kind="data"),
        ),
    )
    return run_dir, start_box_request(req, docker=box_mod._docker)


# ro-mount / traversal containment (po63 / c13)
def test_single_non_overlapping_readonly_mount_refuses_a_direct_in_box_write(tmp_path):
    run_dir = make_run_dir(tmp_path)
    box = box_mod.start_box(run_dir, DEFENDER, docker=box_mod._docker)
    try:
        res = _run(box, "printf x > /defender/spec-probe", cwd=Path("/runs/current"))
        assert res.rc != 0, "a write to the ro defender mount was NOT refused"
    finally:
        box_mod.stop_box(box)


def test_judge_granted_program_computes_an_output_path_that_resolves_inside_gather_raw(tmp_path):
    """Any write whose path resolves inside the ro-mounted gather_raw is mechanically blocked
    by the read-only mount itself, regardless of program convention (S1; po63)."""
    run_dir, box = _run_cycle_box(tmp_path)
    try:
        res = _run(box, f"printf x > {run_dir / 'gather_raw' / 'out'}", cwd=run_dir)
        assert res.rc != 0, "a write into the ro gather_raw mount was NOT refused"
    finally:
        box_mod.stop_box(box)


# nested / overlapping mounts + tmpfs (po19 / po46)
def test_two_mounts_with_nested_or_overlapping_sources_and_targets(tmp_path):
    """The deeper (more-specific) mount governs its subtree with its own flags — rw-inside-ro
    works, the drain's shape (outer worktree ro + a triggered-corpus rw override) (po19)."""
    outer = tmp_path / "wt"
    inner = outer / "defender" / "lessons"
    inner.mkdir(parents=True)
    # The outer worktree is the drain's `code` mount (#1108 D7 amended): it carries the
    # product's committed check file at its legacy `<workdir>/defender`, as a checkout does.
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
    """A file written to /tmp by one exec is readable (not executable) by a later exec in the
    same box, across the batch's turns (po46)."""
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
    # the granted repertoire itself imports — a broken repertoire fails the box (c12)
    ("granted-repertoire-runs-clean",
     "python3 -c 'import defender.execution.bash_exec'",
     "the granted interpreter/repertoire did not run clean at startup", None, None),

    # superseded by #1092: there is no `.venv` inside the box to resolve — `python3` IS the
    # owned image's own /usr/local interpreter (c12: minor matched)
    ("venv-interpreter-matches-the-image",
     "python3 --version", "the interpreter probe exec failed",
     b"3.11", "the box interpreter did not match the image minor"),

    # the probe also catches a broken NATIVE dependency inside the owned image — a non-clean
    # exit of a granted program, not only an interpreter-minor mismatch (c12: duckdb imports)
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
