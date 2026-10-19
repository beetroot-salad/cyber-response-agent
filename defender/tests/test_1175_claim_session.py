from __future__ import annotations

import dataclasses
import hashlib
import os
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from defender._env import FatalConfigError
from defender._git import GitError
from defender.tests._declared869 import ADAPTERS_REL, GIT_IGNORE, git, write
from defender.tests._declared870 import consumed_by_id
from defender.tests._spec791 import author_markers, marker_body
from defender.tests._state1135 import curation_row
from defender.tests.test_1134_curator_git_bounds import _Shim
from defender.tests.test_1175_leads_git_liveness import (
    BOUND,
    CURATE,
    EDIT_LIFT,
    EDITED_LIFT,
    EXEC,
    LIFT,
    LIFT_TEXT,
    NOTES,
    PID,
    PYC,
    STALL_SECONDS,
    _assert_lead_claim_held,
    _assert_lead_served,
    _assert_rows_consumed,
    _assert_rows_untouched,
    _edits,
    _failed,
    _inflight,
    _lead_scene,
    _LeadLane,
    _no_claim,
    _no_curation,
    _pitfalls_scene,
    _PitfallsLane,
    _put,
    _put_bytes,
    _remove,
    _curating,
    _raising,
    _Scene,
    _serving,
    _tick,
)

#: A tracked file outside `skills/`: the elastic adapter `seed_tree` commits.
ADAPTER = f"{ADAPTERS_REL}elastic_adapter.py"
#: A tracked non-`.md` file under `skills/`: the `invlang` package's `__init__.py`.
INVLANG_INIT = "defender/skills/invlang/__init__.py"

#: HEAD's root `.gitignore` for the O6a scenes: the fixture's rules, the real repo's Python
#: rules, and `*.log`.
LOG_IGNORE = GIT_IGNORE + "__pycache__/\n*.py[cod]\n*.log\n"


def _git_path(wt: Path, name: str) -> Path:
    """Where git itself looks for `name` in `wt`'s repository (`rev-parse --git-path`): the
    common git dir for a linked worktree's hooks and objects, `core.hooksPath` honoured."""
    out = git(wt, "rev-parse", "--git-path", name).stdout.strip()
    return (wt / out) if not os.path.isabs(out) else Path(out)


#: What the agent leaves inside the folder at `LIFT`: files HEAD's `LOG_IGNORE` ignores.
FOLDER_FILES = (f"{LIFT}/notes.log", f"{LIFT}/__pycache__/x.cpython-312.pyc")


@pytest.mark.parametrize("folder", [False, True], ids=["control", "folder"])
def test_o6a_a_folder_at_a_deleted_drafts_path_commits_as_the_deletion_alone(
    tmp_path, monkeypatch, folder,
):
    sc = _lead_scene(tmp_path, monkeypatch, committed={".gitignore": LOG_IGNORE})
    ignored: list[int] = []

    def plant_folder(root: Path) -> None:
        _put(FOLDER_FILES[0], "agent notes\n")(root)
        _put_bytes(FOLDER_FILES[1], PYC)(root)
        ignored.extend(
            git(root, "check-ignore", "-q", "--no-index", rel, check=False).returncode
            for rel in FOLDER_FILES
        )

    lane = _LeadLane(_edits(_remove(LIFT), *([plant_folder] if folder else [])))

    got = _tick(sc, run_lead_author=lane, run_pitfalls=_no_curation)

    assert [r["pending"] for r in lane.reached] == [[LIFT]], "the claim never reached the agent"
    if folder:
        assert ignored == [0, 0], "HEAD's rules do not ignore the folder's files: scene unarmed"
    assert got == ("value", 0), got
    _assert_lead_served(sc, {f"D\t{LIFT}"})
    assert git(sc.wt, "ls-tree", "-r", "--name-only", "HEAD", "--", LIFT).stdout == "", \
        "something at the deleted draft's path was committed"


def _stage_new_under_skills(wt: Path) -> str:
    write(wt / NOTES, "left here before the claim\n")
    git(wt, "add", "--", NOTES)
    return f"A\t{NOTES}"


def _stage_tracked_edit_outside_skills(wt: Path) -> str:
    write(wt / ADAPTER, "VERBS = {}  # edited and staged before the claim\n")
    git(wt, "add", "--", ADAPTER)
    return f"M\t{ADAPTER}"


def _stage_removal_under_skills(wt: Path) -> str:
    git(wt, "rm", "--cached", "-q", "--", INVLANG_INIT)
    return f"D\t{INVLANG_INIT}"


STAGINGS: dict[str, Callable[[Path], str] | None] = {
    "control": None,
    "new-under-skills": _stage_new_under_skills,
    "tracked-edit-outside-skills": _stage_tracked_edit_outside_skills,
    "removal-under-skills": _stage_removal_under_skills,
}


def _staged(sc: _Scene, staging: str) -> None:
    """Apply `staging` to the scene's index, and check that a plain `git commit` would now carry
    it (the plant is armed)."""
    stage = STAGINGS[staging]
    if stage is None:
        return
    record = stage(sc.wt)
    cached = git(sc.wt, "diff", "--cached", "--name-status").stdout.splitlines()
    assert cached == [record], cached


@pytest.mark.parametrize("staging", list(STAGINGS))
def test_o6b_a_path_already_staged_is_not_in_the_lead_author_commit(
    tmp_path, monkeypatch, staging,
):
    sc = _lead_scene(tmp_path, monkeypatch)
    _staged(sc, staging)

    got = _tick(sc, run_lead_author=_LeadLane(EDIT_LIFT), run_pitfalls=_no_curation)

    assert got == ("value", 0), got
    _assert_lead_served(sc, {f"M\t{LIFT}"})


@pytest.mark.parametrize("staging", list(STAGINGS))
def test_o6b_a_path_already_staged_is_not_in_the_curation_commit(
    tmp_path, monkeypatch, staging,
):
    """O6 (b), pitfalls: the same staged changes before the curation; the curator adds a pitfall
    to `EXEC`. The row is consumed against a commit of exactly `M EXEC`."""
    sc = _pitfalls_scene(tmp_path, monkeypatch)
    _staged(sc, staging)

    got = _tick(sc, run_lead_author=_no_claim, run_pitfalls=_PitfallsLane(CURATE))

    assert got == ("value", 0), got
    _assert_rows_consumed(sc, {f"M\t{EXEC}"})


@dataclasses.dataclass(frozen=True)
class _Hook:
    """A hook armed in a scene repo: each run appends its name to `ran`; a `stall` hook records
    its pid in `pids` and sleeps `STALL_SECONDS` (stdio closed, so no pipe waits on it), a
    failing one exits 1."""

    name: str
    stall: bool
    ran: Path
    pids: Path

    def install(self, wt: Path) -> None:
        hooks = _git_path(wt, "hooks")
        hooks.mkdir(parents=True, exist_ok=True)
        tail = (f"echo $$ >> '{self.pids}'\nexec sleep {STALL_SECONDS} >/dev/null 2>&1 </dev/null"
                if self.stall else "exit 1")
        hook = hooks / self.name
        hook.write_text(f"#!/bin/sh\necho {self.name} >> '{self.ran}'\n{tail}\n", encoding="utf-8")
        hook.chmod(0o755)

    @property
    def shim(self) -> _Shim:
        """For `_within`'s deadline and the test's teardown: kills each stalled run's `sleep`."""
        return _Shim(log=self.ran.with_name("no-shim.log"), pids=self.pids)

    def runs(self) -> list[str]:
        return self.ran.read_text(encoding="utf-8").split() if self.ran.is_file() else []

    def assert_armed(self, wt: Path) -> None:
        """The positive control: a plain `git commit` in `wt` runs the hook, and the hook bites
        (the commit fails, or does not answer within `BOUND`)."""
        before = len(self.runs())
        argv = ["git", "-C", str(wt), "commit", "--allow-empty", "-q", "-m", "hook probe"]
        if self.stall:
            with pytest.raises(subprocess.TimeoutExpired):
                subprocess.run(argv, capture_output=True, timeout=BOUND * 2)
        else:
            assert subprocess.run(argv, capture_output=True).returncode != 0, \
                f"a plain commit passed the failing {self.name} hook"
        assert self.runs()[before:] == [self.name], f"a plain commit did not run {self.name}"


#: `id: (hook, stalls)`. `prepare-commit-msg` and `post-commit` run under `--no-verify` too.
HOOKS = {
    "pre-commit-fails": ("pre-commit", False),
    "prepare-commit-msg-fails": ("prepare-commit-msg", False),
    "commit-msg-fails": ("commit-msg", False),
    "pre-commit-stalls": ("pre-commit", True),
    "post-commit-stalls": ("post-commit", True),
}


def _armed_hook(tmp: Path, wt: Path, case: str) -> _Hook:
    name, stall = HOOKS[case]
    hook = _Hook(name, stall, ran=tmp / "hook-ran", pids=tmp / "hook-pids")
    hook.install(wt)
    return hook


@pytest.mark.parametrize("case", list(HOOKS))
def test_o7_no_repo_hook_runs_in_the_lead_author_commit(tmp_path, monkeypatch, case):
    sc = _lead_scene(tmp_path, monkeypatch)
    hook = _armed_hook(tmp_path, sc.wt, case)
    lane = _LeadLane(EDIT_LIFT, git_timeout=BOUND)
    try:
        got = _tick(sc, run_lead_author=lane, run_pitfalls=_no_curation,
                    shim=hook.shim)
        runs = hook.runs()

        assert got == ("value", 0), got
        assert runs == [], f"the {hook.name} hook ran in the claim's commit"
        _assert_lead_served(sc, {f"M\t{LIFT}"})
        hook.assert_armed(sc.wt)
    finally:
        hook.shim.kill_stalls()


@pytest.mark.parametrize("case", list(HOOKS))
def test_o7_no_repo_hook_runs_in_the_curation_commit(tmp_path, monkeypatch, case):
    sc = _pitfalls_scene(tmp_path, monkeypatch)
    hook = _armed_hook(tmp_path, sc.wt, case)
    lane = _PitfallsLane(CURATE, git_timeout=BOUND)
    try:
        got = _tick(sc, run_lead_author=_no_claim, run_pitfalls=lane,
                    shim=hook.shim)
        runs = hook.runs()

        assert got == ("value", 0), got
        assert runs == [], f"the {hook.name} hook ran in the curation's commit"
        _assert_rows_consumed(sc, {f"M\t{EXEC}"})
        hook.assert_armed(sc.wt)
    finally:
        hook.shim.kill_stalls()


def _arm_auto_gc(wt: Path) -> None:
    """Make the next `git commit` in `wt` run `gc --auto` in the foreground: `gc.auto=1` (so two
    loose objects in `objects/17/` cross the threshold), detaching off, and two such objects."""
    for key, value in (("gc.auto", "1"), ("gc.autoDetach", "false"),
                       ("maintenance.autoDetach", "false")):
        git(wt, "config", key, value)
    planted, n = 0, 0
    while planted < 2:
        data = f"loose object {n}\n".encode()
        n += 1
        if hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest().startswith("17"):
            subprocess.run(["git", "-C", str(wt), "hash-object", "-w", "--stdin"], input=data,
                           capture_output=True, check=True)
            planted += 1


def _packs(wt: Path) -> list[str]:
    pack_dir = _git_path(wt, "objects/pack")
    return sorted(p.name for p in pack_dir.glob("*.pack")) if pack_dir.is_dir() else []


def _assert_gc_armed(wt: Path) -> None:
    """The positive control: a plain `git commit` in `wt` runs `gc --auto`, which packs."""
    git(wt, "commit", "--allow-empty", "-q", "-m", "gc probe")
    assert _packs(wt), "a plain commit ran no gc: the scene was unarmed"


def test_o7_no_automatic_maintenance_runs_in_the_lead_author_commit(tmp_path, monkeypatch):
    sc = _lead_scene(tmp_path, monkeypatch)
    _arm_auto_gc(sc.wt)
    assert _packs(sc.wt) == []

    got = _tick(sc, run_lead_author=_LeadLane(EDIT_LIFT), run_pitfalls=_no_curation)

    assert got == ("value", 0), got
    assert _packs(sc.wt) == [], "automatic maintenance ran in the claim's commit"
    _assert_lead_served(sc, {f"M\t{LIFT}"})
    _assert_gc_armed(sc.wt)


def test_o7_no_automatic_maintenance_runs_in_the_curation_commit(tmp_path, monkeypatch):
    """O7, pitfalls: as the lead-author scene; the row is consumed against `M EXEC`, no pack."""
    sc = _pitfalls_scene(tmp_path, monkeypatch)
    _arm_auto_gc(sc.wt)
    assert _packs(sc.wt) == []

    got = _tick(sc, run_lead_author=_no_claim, run_pitfalls=_PitfallsLane(CURATE))

    assert got == ("value", 0), got
    assert _packs(sc.wt) == [], "automatic maintenance ran in the curation's commit"
    _assert_rows_consumed(sc, {f"M\t{EXEC}"})
    _assert_gc_armed(sc.wt)


def _no_runnable_git(tmp: Path, how: str) -> Path:
    """A `PATH` directory from which `git` cannot start: `missing` holds none
    (`FileNotFoundError`); `not-executable` holds a `git` file without an execute bit
    (`PermissionError`). Either way `subprocess` raises an `OSError` before git runs."""
    at = tmp / f"path-{how}"
    at.mkdir()
    if how == "not-executable":
        (at / "git").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        (at / "git").chmod(0o644)
    return at


#: How git is made unable to start; `None` leaves it able (the control).
UNSTARTABLE = ["missing", "not-executable", None]
UNSTARTABLE_IDS = ["missing", "not-executable", "control"]

#: The systemic faults a claim propagates: a git one and a non-git one.
FAULTS = {
    "git-error": lambda: GitError(["status"], 128, "the claim's own git fault"),
    "fatal-config": lambda: FatalConfigError("the claim's own config fault"),
}


def _leaving(rel: str, text: str, patch: pytest.MonkeyPatch, path_dir: Path | None,
             then: Callable[..., Any]) -> Callable[..., Any]:
    """A work step (either lane's call shape: the worktree's `LoopPaths` first) that leaves an
    edit of `rel` behind, points `PATH` at `path_dir` (when given) so no git can start, and then
    hands over to `then(*args, **kwargs)`."""

    def step(*args: Any, **kwargs: Any) -> Any:
        write(args[0].repo_root / rel, text)
        if path_dir is not None:
            patch.setenv("PATH", str(path_dir))
        return then(*args, **kwargs)

    return step


def _assert_leftover(wt: Path, rel: str, text: str, *, cleaned: bool, committed: str) -> None:
    """Whether the cleanup put `rel` back to HEAD (`committed`): with git unable to start it
    cannot have, so the leftover `text` still stands; with git able, it was reset."""
    now = (wt / rel).read_text(encoding="utf-8")
    if cleaned:
        assert now == committed, "the cleanup did not reset the claim's leftover"
    else:
        assert now == text, "the cleanup reset the leftover: git could start, the scene is unarmed"


def _oserror_in(exc: BaseException | None) -> bool:
    seen: set[int] = set()
    while exc is not None and id(exc) not in seen:
        if isinstance(exc, OSError):
            return True
        seen.add(id(exc))
        exc = exc.__cause__ or exc.__context__
    return False


@pytest.mark.parametrize("fault_kind", list(FAULTS))
@pytest.mark.parametrize("how", UNSTARTABLE, ids=UNSTARTABLE_IDS)
def test_o8_unstartable_git_at_cleanup_keeps_the_lead_author_claims_fault(
    tmp_path, monkeypatch, how, fault_kind,
):
    sc = _lead_scene(tmp_path, monkeypatch)
    fault = FAULTS[fault_kind]()
    path_dir = _no_runnable_git(tmp_path, how) if how else None

    with monkeypatch.context() as patch:
        step = _leaving(LIFT, EDITED_LIFT, patch, path_dir, _raising(fault))
        got = _tick(sc, run_lead_author=step, run_pitfalls=_no_curation, git_timeout=BOUND)

    assert got[0] == "raised", got
    assert got[1] is fault, repr(got[1])
    _assert_lead_claim_held(sc)
    _assert_leftover(sc.wt, LIFT, EDITED_LIFT, cleaned=how is None, committed=LIFT_TEXT)


@pytest.mark.parametrize("fault_kind", list(FAULTS))
@pytest.mark.parametrize("how", UNSTARTABLE, ids=UNSTARTABLE_IDS)
def test_o8_unstartable_git_at_cleanup_keeps_the_curations_fault(
    tmp_path, monkeypatch, how, fault_kind,
):
    sc = _pitfalls_scene(tmp_path, monkeypatch)
    committed = (sc.wt / EXEC).read_text(encoding="utf-8")
    leftover = committed + "\n- a pitfall the faulted curation left behind\n"
    fault = FAULTS[fault_kind]()
    path_dir = _no_runnable_git(tmp_path, how) if how else None

    with monkeypatch.context() as patch:
        step = _leaving(EXEC, leftover, patch, path_dir, _raising(fault))
        got = _tick(sc, run_lead_author=_no_claim, run_pitfalls=step, git_timeout=BOUND)

    assert got[0] == "raised", got
    assert got[1] is fault, repr(got[1])
    _assert_rows_untouched(sc)
    assert "finish" not in sc.branch.events
    _assert_leftover(sc.wt, EXEC, leftover, cleaned=how is None, committed=committed)


@pytest.mark.parametrize("how", UNSTARTABLE, ids=UNSTARTABLE_IDS)
def test_o8_control_unstartable_git_after_a_clean_lead_author_claim_ends_the_tick(
    tmp_path, monkeypatch, how,
):
    sc = _lead_scene(tmp_path, monkeypatch, cases=("case-a", "case-b"))
    served: list[Path] = []
    path_dir = _no_runnable_git(tmp_path, how) if how else None
    run_a, run_b = sc.run_dirs

    with monkeypatch.context() as patch:
        tampering = _leaving(LIFT, EDITED_LIFT, patch, path_dir, _serving(served))
        plain = _serving(served)

        def step(paths: Any, state: Any, run: Any, **kw: Any) -> None:
            (tampering if run.run_dir == run_a else plain)(paths, state, run, **kw)

        got = _tick(sc, run_lead_author=step, run_pitfalls=_no_curation, git_timeout=BOUND)

    if how is None:
        assert got == ("value", 0), got
        assert served == [run_a, run_b]
        assert _inflight(sc.paths) == {}
        assert author_markers(sc.paths) == []
        _assert_leftover(sc.wt, LIFT, EDITED_LIFT, cleaned=True, committed=LIFT_TEXT)
        return
    result, exc = got
    assert result == "raised", got
    assert _oserror_in(exc), repr(exc)
    assert served == [run_a], "the next claim was served over the first one's leftovers"
    assert _inflight(sc.paths) == {"case-a.json": {
        **curation_row("case-a", run_a), "attempts": 1}}, _inflight(sc.paths)
    assert author_markers(sc.paths) == ["case-b.json"]
    assert marker_body(sc.paths.state_root / "author-queue" / "case-b.json") == \
        curation_row("case-b", run_b)
    assert _failed(sc.paths) == []
    assert "finish" not in sc.branch.events
    _assert_leftover(sc.wt, LIFT, EDITED_LIFT, cleaned=False, committed=LIFT_TEXT)


@pytest.mark.parametrize("how", UNSTARTABLE, ids=UNSTARTABLE_IDS)
def test_o8_control_unstartable_git_after_a_clean_curation_ends_the_tick(
    tmp_path, monkeypatch, how,
):
    sc = _pitfalls_scene(tmp_path, monkeypatch)
    committed = (sc.wt / EXEC).read_text(encoding="utf-8")
    leftover = committed + "\n- a pitfall the curation left behind\n"
    path_dir = _no_runnable_git(tmp_path, how) if how else None

    with monkeypatch.context() as patch:
        step = _leaving(EXEC, leftover, patch, path_dir, _curating)
        got = _tick(sc, run_lead_author=_no_claim, run_pitfalls=step, git_timeout=BOUND)

    if how is None:
        assert got == ("value", 0), got
        assert consumed_by_id(sc.paths)[PID]["consumed_commit"] == "abc1175"
        assert "finish" in sc.branch.events
        _assert_leftover(sc.wt, EXEC, leftover, cleaned=True, committed=committed)
        return
    result, exc = got
    assert result == "raised", got
    assert _oserror_in(exc), repr(exc)
    _assert_rows_untouched(sc)
    assert "finish" not in sc.branch.events
    _assert_leftover(sc.wt, EXEC, leftover, cleaned=False, committed=committed)
