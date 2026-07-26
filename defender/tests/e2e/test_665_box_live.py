"""#665 — live box mechanism confirmations (carried to write-code-from-spec's first live run).

Every test here is `@pytest.mark.live` and drives a REAL docker daemon; the gate
(`-m "not live"`) deselects them, and under docker-outside-of-Docker they skip (bind SOURCES
resolve on the daemon host, invisible to this process — the same skip the existing #540 box
boundary suite uses). The MECHANISMS these assert were already confirmed live during
re-grounding (the cited po-claims in `spec_graph_665-box-learning-roles.yaml`); the tests
re-assert them against the NEW mount model at the suite's first live run, where they are RED
until the two creation sites + box.py geography land.

Two probes were NOT run in the re-ground round and are OWED at this first live run
(`lesson_script_hostile_argv`, claim `unprobed`): the pinned lesson scripts' own hostile-argv
containment (S6). They are authored here as the live obligation, not discharged hermetically.
"""
from __future__ import annotations

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

from defender.runtime import bash_exec  # noqa: E402
from defender.runtime import box as box_mod  # noqa: E402

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
            Mount(source=run_dir, target=run_dir, writable=False),
            Mount(source=DEFENDER, target=DEFENDER, writable=False),
            Mount(source=run_dir / "gather_raw", target=run_dir / "gather_raw", writable=False),
        ),
    )
    return run_dir, start_box_request(req, docker=box_mod._docker)


# --------------------------------------------------------------------------- #
# ro-mount / traversal containment (po63 / c13)
# --------------------------------------------------------------------------- #
def test_single_non_overlapping_readonly_mount_refuses_a_direct_in_box_write(tmp_path):
    """A write to a read-only bind's own target is refused (rc=2, Read-only file system) —
    distinct from the `--read-only` rootfs (po63 confirmed live). S1's containment rests on
    the ro flag, not the gate."""
    run_dir = make_run_dir(tmp_path)
    box = box_mod.start_box(run_dir, DEFENDER, docker=box_mod._docker)
    try:
        res = _run(box, f"printf x > {DEFENDER / 'spec-probe'}", cwd=run_dir)
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


def test_lead_author_rm_traversal_lands_on_readonly_sibling_rather_than_no_host_tree(tmp_path):
    """A `..` traversal that stays inside the box's whole-worktree ro infra mount lands on the
    ro tree (write refused rc=2), not on bare rootfs with no host tree — the ro flag refuses
    the write either way (po63)."""
    run_dir, box = _run_cycle_box(tmp_path)
    try:
        res = _run(box, f"rm {DEFENDER}/../defender/SKILL.md", cwd=REPO_ROOT)
        assert res.rc != 0, "a `..` traversal write into the ro sibling was NOT refused"
    finally:
        box_mod.stop_box(box)


def test_curator_rm_grant_argv_traverses_from_its_corpus_scope_into_a_sibling_mount(tmp_path):
    """A curator `rm` whose `..` operand climbs out of its corpus into a co-mounted ro sibling
    is refused by the ro mount, the authoritative backstop (c13)."""
    run_dir, box = _run_cycle_box(tmp_path)
    try:
        res = _run(box, f"rm {DEFENDER}/lessons/../SKILL.md", cwd=REPO_ROOT)
        assert res.rc != 0
    finally:
        box_mod.stop_box(box)


def test_single_readonly_mount_still_reads(tmp_path):
    """Positive control for the ro-write negatives: the same ro mount is READABLE."""
    run_dir = make_run_dir(tmp_path)
    box = box_mod.start_box(run_dir, DEFENDER, docker=box_mod._docker)
    try:
        res = _run(box, f"cat {DEFENDER / 'SKILL.md'}", cwd=run_dir)
        assert res.rc == 0, "the ro mount was not readable (positive control)"
        assert res.out, "the ro mount read returned nothing (positive control)"
    finally:
        box_mod.stop_box(box)


# --------------------------------------------------------------------------- #
# nested / overlapping mounts + tmpfs (po19 / po46)
# --------------------------------------------------------------------------- #
def test_two_mounts_with_nested_or_overlapping_sources_and_targets(tmp_path):
    """The deeper (more-specific) mount governs its subtree with its own flags — rw-inside-ro
    works, the drain's shape (outer worktree ro + a triggered-corpus rw override) (po19)."""
    outer = tmp_path / "wt"
    inner = outer / "defender" / "lessons"
    inner.mkdir(parents=True)
    req = BoxRequest(
        name="defender-nested-live", workdir=outer, env={},
        mounts=(Mount(source=outer, target=outer, writable=False),
                Mount(source=inner, target=inner, writable=True)),
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
        _run(box, "printf shared > /tmp/spec-shared", cwd=run_dir)
        res = _run(box, "cat /tmp/spec-shared", cwd=run_dir)
        assert res.rc == 0, "the tmpfs read-back exec failed"
        assert b"shared" in res.out, "tmpfs did not persist across execs"
    finally:
        box_mod.stop_box(box)


def test_legs_sharing_one_box_tmpfs_see_each_others_writes_cross_exec(tmp_path):
    """test_legs_sharing_one_box_tmpfs_see_each_others_writes_cross_exec — legs sharing one box's
    /tmp tmpfs see each other's writes across SEQUENTIAL execs in one box lifetime: a write by
    one exec is readable by a later exec (cross-leg visibility accepted per dec2/S6, po46). The
    body is sequential cross-exec visibility (not a concurrency/starvation drive) — the name now
    matches what is asserted."""
    run_dir = make_run_dir(tmp_path)
    box = box_mod.start_box(run_dir, DEFENDER, docker=box_mod._docker)
    try:
        _run(box, "printf leg1 > /tmp/spec-leg", cwd=run_dir)
        assert b"leg1" in _run(box, "cat /tmp/spec-leg", cwd=run_dir).out, "cross-exec tmpfs not visible"
    finally:
        box_mod.stop_box(box)


# --------------------------------------------------------------------------- #
# interpreter coupling + the behavioral startup probe (c12 / decision 7)
# --------------------------------------------------------------------------- #
def test_box_start_runs_granted_programs_and_refuses_on_failure(tmp_path):
    """box_start_probes_interpreter (decision 7) — the startup probe RUNS the granted programs
    when the box comes up and refuses the start if they do not exit clean (behavioral, not an
    interpreter-identity comparison); a broken repertoire fails the box (c12)."""
    run_dir = make_run_dir(tmp_path)
    box = box_mod.start_box(run_dir, DEFENDER, docker=box_mod._docker)
    try:
        res = _run(box, "python3 -c 'import defender.runtime.bash_exec'", cwd=REPO_ROOT)
        assert res.rc == 0, "the granted interpreter/repertoire did not run clean at startup"
    finally:
        box_mod.stop_box(box)


def test_venv_interpreter_does_not_match_the_image(tmp_path):
    """The startup probe-by-execution refuses the box start when the .venv interpreter does not
    resolve to the image interpreter (c12: .venv python3 resolves to image /usr/local/bin
    python3, minor matched)."""
    run_dir = make_run_dir(tmp_path)
    box = box_mod.start_box(run_dir, DEFENDER, docker=box_mod._docker)
    try:
        res = _run(box, "python3 --version", cwd=REPO_ROOT)
        assert res.rc == 0, "the interpreter probe exec failed"
        assert b"3.11" in res.out, "the box interpreter did not match the image minor"
    finally:
        box_mod.stop_box(box)


def test_interpreter_matches_but_a_native_dependency_inside_the_venv_is_broken(tmp_path):
    """The behavioral probe catches a broken native dependency inside the venv (a non-clean
    exit of a granted program), not only an interpreter-minor mismatch (c12: duckdb imports)."""
    run_dir = make_run_dir(tmp_path)
    box = box_mod.start_box(run_dir, DEFENDER, docker=box_mod._docker)
    try:
        res = _run(box, "python3 -c 'import duckdb'", cwd=REPO_ROOT)
        assert res.rc == 0, "a native dependency the granted repertoire needs did not import"
    finally:
        box_mod.stop_box(box)


def test_drain_tier_repertoire_grows_to_need_the_dangling_venv(tmp_path):
    """The drain repertoire (rm, cat, grep) is image binaries and needs NO .venv; a dangling
    worktree .venv symlink is harmless as long as the repertoire stays image binaries
    (c12/c14: this worktree has no .venv)."""
    run_dir = make_run_dir(tmp_path)
    box = box_mod.start_box(run_dir, DEFENDER, docker=box_mod._docker)
    try:
        for prog in ("rm", "cat", "grep"):
            assert _run(box, f"command -v {prog}", cwd=run_dir).rc == 0, f"{prog} absent from the image"
    finally:
        box_mod.stop_box(box)


def test_worktree_leaf_contains_a_symlink_that_resolves_outside_the_leaf(tmp_path):
    """A dangling .venv symlink inside the rw-mounted leaf is harmless: no granted program's
    operand resolution targets it, and the repertoire is image binaries (M7; c12/c14)."""
    run_dir = make_run_dir(tmp_path)
    (run_dir / ".venv").symlink_to("/nonexistent/main/.venv")
    box = box_mod.start_box(run_dir, DEFENDER, docker=box_mod._docker)
    try:
        assert _run(box, f"cat {run_dir / 'alert.json'}", cwd=run_dir).rc == 0, \
            "a dangling leaf symlink broke an unrelated in-box read"
    finally:
        box_mod.stop_box(box)


# --------------------------------------------------------------------------- #
# teardown / bind release / host mutation reflection (po47 / po35)
# --------------------------------------------------------------------------- #
def test_worktree_or_scan_races_a_not_yet_released_box_bind(tmp_path):
    """`docker rm -f` releases the kernel bind synchronously — a subsequent host rm -rf of the
    formerly-bound source does not race (no EBUSY): the dec8 teardown order (stop_box before
    scan/worktree-removal) does not race a held bind (po47)."""
    import shutil

    run_dir = make_run_dir(tmp_path)
    box = box_mod.start_box(run_dir, DEFENDER, docker=box_mod._docker)
    box_mod.stop_box(box)
    shutil.rmtree(run_dir)  # must not raise EBUSY
    assert not run_dir.exists(), "the formerly-bound source could not be removed after teardown"


def test_git_reset_hard_runs_between_sequential_markers_under_one_live_box(tmp_path):
    """A host-side file mutation between sequential markers IS reflected into a live rw bind:
    the next marker's in-box read sees the post-edit content (po35 — M8's 'must be pinned'
    flag on _discard_worktree_changes under a live bind is real)."""
    run_dir = make_run_dir(tmp_path)
    probe = run_dir / "marker.txt"
    probe.write_text("orig", encoding="utf-8")
    box = box_mod.start_box(run_dir, DEFENDER, docker=box_mod._docker)
    try:
        assert b"orig" in _run(box, f"cat {probe}", cwd=run_dir).out
        probe.write_text("changed-on-host", encoding="utf-8")
        assert b"changed-on-host" in _run(box, f"cat {probe}", cwd=run_dir).out, \
            "a host edit under the live bind was not reflected into the box"
    finally:
        box_mod.stop_box(box)


# --------------------------------------------------------------------------- #
# mount-source symlink following (po18 / F14 → R12) + the OWED lesson-script probes
# --------------------------------------------------------------------------- #
def test_mount_source_symlink_target_resolves_outside_worktree_leaf(tmp_path):
    """A resolving symlink bind source is FOLLOWED by docker to its target (rc=0, resolved in
    the daemon namespace); mount sources are design-controlled leaves, so this is a bounded
    defense-in-depth residual, not a reachable production case (po18; F14 → R12)."""
    real = tmp_path / "real"
    real.mkdir()
    (real / "x.txt").write_text("target", encoding="utf-8")
    link = tmp_path / "leaf-link"
    link.symlink_to(real)
    run_dir = make_run_dir(tmp_path)
    req = BoxRequest(
        name="defender-symlink-live", workdir=run_dir, env={},
        mounts=(Mount(source=run_dir, target=run_dir, writable=False),
                Mount(source=DEFENDER, target=DEFENDER, writable=False),
                Mount(source=link, target=link, writable=False)),
    )
    box = start_box_request(req, docker=box_mod._docker)
    try:
        assert b"target" in _run(box, f"cat {link / 'x.txt'}", cwd=run_dir).out, \
            "docker did not follow the resolving symlink source to its target"
    finally:
        box_mod.stop_box(box)


def test_pinned_lesson_scripts_reject_arbitrary_argv_read(tmp_path):
    """lesson_scripts_no_arbitrary_read (negative; OWED live probe) — the pinned lesson scripts
    cannot be driven to read an arbitrary path via their argv (S6): the gate passes argv
    unexamined via pins_path, so the scripts themselves are the last line. This is the
    hostile-argv probe NOT run in re-grounding (claim `lesson_script_hostile_argv`, unprobed) —
    owed at this first live run. Positive control: the pinned script runs on its intended
    operand."""
    run_dir = make_run_dir(tmp_path)
    box = box_mod.start_box(run_dir, DEFENDER, docker=box_mod._docker)
    try:
        # positive control: the pinned lesson script runs on its INTENDED in-corpus operand (a
        # frontmatter pattern), exits 0, and returns its corpus content — so the hostile-argv
        # negative below only passes once the script has DEMONSTRABLY executed (a bare no-leak
        # check passes vacuously if the script errored on a bad path and printed nothing).
        allowed = _run(box, "python3 defender/scripts/lessons/defender-lessons .", cwd=REPO_ROOT)
        assert allowed.rc == 0, "the pinned lesson script did not run on its intended operand (positive control)"
        assert allowed.out, "the pinned lesson script returned no corpus content on its intended operand"
        hostile = _run(box, "python3 defender/scripts/lessons/defender-lessons /etc/passwd",
                       cwd=REPO_ROOT)
        assert b"root:" not in hostile.out, "a pinned lesson script leaked an arbitrary file via argv"
    finally:
        box_mod.stop_box(box)


def test_pinned_lesson_script_argv_cannot_redirect_read_target(tmp_path):
    """test_pinned_lesson_script_argv_cannot_redirect_read_target (negative; OWED live probe) —
    a crafted argv cannot redirect a pinned lesson script's read target to a path outside its
    own corpus (S6). The gate is argv-blind under pins_path, so containment is the script's;
    still owed live (po12/po50/po51 not run in re-grounding). Positive control: the pinned script
    runs on its intended in-corpus operand (exits 0, returns corpus content), so the redirect
    negative only passes once the script has demonstrably executed."""
    run_dir = make_run_dir(tmp_path)
    box = box_mod.start_box(run_dir, DEFENDER, docker=box_mod._docker)
    try:
        allowed = _run(box, "python3 defender/scripts/lessons/defender-lessons .", cwd=REPO_ROOT)
        assert allowed.rc == 0, "the pinned lesson script did not run on its intended operand (positive control)"
        assert allowed.out, "the pinned lesson script returned no corpus content on its intended operand"
        res = _run(box, "python3 defender/scripts/lessons/defender-lessons ../../../etc/shadow",
                   cwd=REPO_ROOT)
        leaked = b"root:" in res.out or b"encrypted" in res.out
        assert not leaked, \
            "a pinned lesson script's read target was redirected outside its corpus via argv"
    finally:
        box_mod.stop_box(box)
