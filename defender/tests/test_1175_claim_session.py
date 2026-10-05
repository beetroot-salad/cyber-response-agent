"""#1175 design amendment 1 ("a claim-scoped git session"): the claim's commit and the cleanup
after it.

The amendment keeps O1-O5 / N1-N5 (pinned in `test_1175_leads_git_liveness.py` and
`test_1175_adversary_holes.py`) and adds three obligations, pinned here:

- O6 the commit reads nothing from the worktree: it carries exactly the admitted change
  records. (a) The lead-author agent deletes the pending draft `LIFT` (admitted) and leaves a
  FOLDER at the same path holding files HEAD's committed ignore rules ignore (`*.log`,
  `__pycache__/`): the commit is exactly `D LIFT`, nothing from inside the folder. Lead-author
  only: the pitfalls rule refuses every deletion, so no admitted pitfalls path can be replaced
  by a folder. (b) An unrelated path already STAGED in the worktree's index before the commit
  (a new file under `skills/`, an edit of a tracked file outside it, a removal under it, each a
  baseline stray the scope check tolerates without admitting) is not in the commit. Both lanes.
- O7 the commit is a local operation only: no repo hook (`pre-commit`, `prepare-commit-msg`,
  `commit-msg`, `post-commit`) runs in it, whether it would fail the commit or stall past the
  lane's bound, and no automatic maintenance (`gc --auto`) runs in it. Both lanes. Each scene's
  positive control runs a plain `git commit` in the same repo afterwards and sees the hook run
  (or the pack appear), so the plant was armed.
- O8 no cleanup error of any kind displaces a propagating fault: while a systemic fault
  propagates out of a claim, git cannot START for the cleanup (`PATH` holds no runnable `git`:
  `FileNotFoundError` / `PermissionError` from `subprocess`, an `OSError`, not a `GitError`).
  The tick raises the claim's fault, the very object. Both lanes. Positive control: the same
  unstartable git after a CLEAN claim ends the tick (an `OSError` raised, the next claim not
  served, nothing consumed).

Every scene is a real drain tick (`drains.lead_author_drain`) over a real committed repo, under
`test_1134_curator_git_bounds._within`'s deadline (through the liveness suite's `_tick`), with
the real scrub; the lanes are the real ones (`_LeadLane` / `_PitfallsLane`: only the agent
spawn, `extract` and the queue lock replaced) except in O8, whose work steps are fakes that
leave an edit behind and raise. Only the public seams `LeadAuthorDeps.git_timeout` and
`run_pitfalls(git_timeout=)` are used; nothing is `setattr`-patched (`PATH` is set with
`monkeypatch.setenv`).

O8's plant is `PATH` changed inside the work step, so it reaches the cleanup only if git is
looked up on `PATH` when each git call starts (as `subprocess` does with the environment
`_git.committed_view_env()` builds per call today). Each O8 scene checks the cleanup really
could not run (its leftover edit still stands): an implementation that pinned the git binary or
its `PATH` earlier fails that check, which then reports the plant, not O8.

Red on the branch as written for the original design (fa849d3b), observed:

- O6a `folder`: the tick raises a `GitError`. The commit judges the admitted `LIFT` present
  (`kind_at` finds the folder), `add -f` stages the folder's ignored files, and
  `commit -- <LIFT>` then fails ("does not have a commit checked out"). Nothing is committed.
- O7: each failing hook refuses the commit (`GitError`, rc 1); each stalling hook overruns
  `BOUND` (`GitOverran`). The hook ran either way. For maintenance, the claim's commit runs
  `gc --auto` and a pack appears.
- O8 in-flight scenes (`missing`, `not-executable`): the cleanup's `FileNotFoundError` /
  `PermissionError` replaces the claim's fault, because the cleanup drops only `GitError`.

Green on it, pinning behaviour the session must keep: O6a `control`; every O6b scene (today's
`commit -- <paths>` already leaves other staged entries out; they pin the amendment's
no-pathspec commit against a missing reset of the index to HEAD); O8's `control` variants and
both clean-claim positive controls. O7's positive controls run after the scene's own assertions,
so they only run once those pass; each was checked separately on this branch.
"""
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


# ---------------------------------------------------------------------------------------
# O6a: a folder standing at a deleted draft's path rides nothing into the commit
# ---------------------------------------------------------------------------------------

#: What the agent leaves inside the folder at `LIFT`: files HEAD's `LOG_IGNORE` ignores.
FOLDER_FILES = (f"{LIFT}/notes.log", f"{LIFT}/__pycache__/x.cpython-312.pyc")


@pytest.mark.parametrize("folder", [False, True], ids=["control", "folder"])
def test_o6a_a_folder_at_a_deleted_drafts_path_commits_as_the_deletion_alone(
    tmp_path, monkeypatch, folder,
):
    """O6 (a), lead-author. HEAD's root `.gitignore` ignores `*.log` and `__pycache__/`. The agent
    removes the pending draft `LIFT` (a removal the scope check admits) and, in `folder`, makes
    a folder at that same path holding `notes.log` and `__pycache__/x.cpython-312.pyc`. Both are
    ignored by HEAD's rules (checked: that is why the scope check lists neither), so the claim's
    one admitted record is `D LIFT`. The tick lands and the commit is exactly `D LIFT`: nothing
    from inside the folder rides in, and the folder does not turn the deletion into an error.

    `control`: the same removal, no folder: the commit is `D LIFT`.

    Catches: a commit that re-asks the filesystem what stands at an admitted path (a folder
    there is "present", and `add -f` of it stages its ignored files) or commits with that path as
    a pathspec (git refuses a folder where the index holds a file)."""
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


# ---------------------------------------------------------------------------------------
# O6b: an unrelated path already staged is not in the commit
# ---------------------------------------------------------------------------------------


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


#: How the index already carries an unrelated change when the claim starts: each a baseline
#: stray (the before-agent listing carries the same record), so the scope check tolerates it
#: without admitting it. Each returns the staged record as `git diff --cached --name-status`
#: spells it.
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
    """O6 (b), lead-author. Before the claim, the worktree's index already carries an unrelated
    staged change (`staging`; checked to be what `git diff --cached` shows). The agent edits
    `LIFT`. The claim lands and its commit is exactly `M LIFT`: the staged change does not ride
    in. `control`: nothing staged, the same commit.

    Catches: a commit of the index as it stands (no reset to HEAD before staging the admitted
    records)."""
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


# ---------------------------------------------------------------------------------------
# O7: no repo hook and no automatic maintenance runs in the commit
# ---------------------------------------------------------------------------------------


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
    """O7, lead-author. A commit hook is armed in the scene repo's hooks dir (`case`: one that
    exits 1, or one that sleeps far past the lane's bound `LeadAuthorDeps.git_timeout=BOUND`).
    The agent edits `LIFT`. The claim lands (no overrun, no git error) with exactly `M LIFT`, and
    the hook never ran. Positive control, afterwards: a plain `git commit` in the same repo runs
    the hook and is failed or stalled by it.

    Catches: a commit that runs repo hooks (the failing hook refuses it as a `GitError`; the
    stalling one overruns `BOUND`); `--no-verify` alone (`prepare-commit-msg` and `post-commit`
    still run)."""
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
    """O7, pitfalls: the same hooks, `run_pitfalls(git_timeout=BOUND)`; the curator adds a pitfall
    to `EXEC`. The row is consumed against a commit of exactly `M EXEC` and the hook never ran;
    afterwards a plain `git commit` runs it."""
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
    """O7, lead-author: the scene repo is set so that any `git commit` runs `gc --auto` in the
    foreground (which writes a pack). The claim lands with exactly `M LIFT` and no pack exists:
    no maintenance ran in its commit. Positive control, afterwards: a plain `git commit` packs.

    Catches: a commit that leaves `gc.auto` / `maintenance.auto` to the repo's config."""
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


# ---------------------------------------------------------------------------------------
# O8: git that cannot start at cleanup displaces no propagating fault
# ---------------------------------------------------------------------------------------


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
    """O8, lead-author. The claim's work step leaves an edit of `LIFT` behind, makes git unable
    to start (`how`: `PATH` holds no runnable `git`) and raises a systemic fault (`fault_kind`).
    The cleanup that follows cannot start git: an `OSError`, raised while the claim's fault
    propagates. The tick raises the claim's fault, the very object, not the `OSError`; the claim
    waits in `inflight/` with `attempts: 1`, neither dead-lettered nor re-queued; the leftover
    edit still stands (checked: the cleanup really could not run).

    `control`: git can start; the same fault comes out and the cleanup resets the leftover.

    Catches: a cleanup that drops only git errors under a propagating fault (the `OSError`
    replaces the fault, which survives only as its `__context__`)."""
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
    """O8, pitfalls: the curation's work step leaves an edit of `EXEC` behind, makes git unable to
    start and raises a systemic fault. The tick raises that fault, the very object; the row is
    untouched (not consumed, retired or bumped) and the batch never finishes; the leftover still
    stands. `control`: the same fault, the leftover reset."""
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
    """O8's positive control, lead-author. Two claims (`case-a`, `case-b`). The first is served
    cleanly, but its step leaves an edit of `LIFT` behind and makes git unable to start (`how`).
    No fault propagates, so the cleanup's `OSError` is the tick's: raised, `case-b` never served
    (it would run, and commit, over `case-a`'s leftover) and still queued as enqueued, `case-a`
    waiting in `inflight/` with `attempts: 1`, not dead-lettered; the leftover still stands.

    `control`: git can start: both claims are served and consumed, the leftover reset."""
    sc = _lead_scene(tmp_path, monkeypatch, cases=("case-a", "case-b"))
    served: list[Path] = []
    path_dir = _no_runnable_git(tmp_path, how) if how else None
    run_a, run_b = sc.run_dirs

    with monkeypatch.context() as patch:
        tampering = _leaving(LIFT, EDITED_LIFT, patch, path_dir, _serving(served))
        plain = _serving(served)

        def step(paths: Any, run_dir: Path, **kw: Any) -> None:
            (tampering if run_dir == run_a else plain)(paths, run_dir, **kw)

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
        "case_id": "case-a", "run_dir": str(run_a.resolve()), "attempts": 1}}, _inflight(sc.paths)
    assert author_markers(sc.paths) == ["case-b.json"]
    assert marker_body(sc.paths.author_queue_dir / "case-b.json") == {
        "case_id": "case-b", "run_dir": str(run_b.resolve())}
    assert _failed(sc.paths) == []
    assert "finish" not in sc.branch.events
    _assert_leftover(sc.wt, LIFT, EDITED_LIFT, cleaned=False, committed=LIFT_TEXT)


@pytest.mark.parametrize("how", UNSTARTABLE, ids=UNSTARTABLE_IDS)
def test_o8_control_unstartable_git_after_a_clean_curation_ends_the_tick(
    tmp_path, monkeypatch, how,
):
    """O8's positive control, pitfalls. The curation ends cleanly, but its step leaves an edit of
    `EXEC` behind and makes git unable to start. The cleanup's `OSError` is the tick's: raised,
    the curation's disposition never applied (the row queued byte for byte), the batch never
    finished, the leftover still standing. `control`: the row is consumed against the
    curation's commit and the leftover reset."""
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
