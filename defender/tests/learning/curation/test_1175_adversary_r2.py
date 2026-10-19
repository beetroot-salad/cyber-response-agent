from __future__ import annotations

import dataclasses
import subprocess
from pathlib import Path
from typing import Any

import pytest

from defender.learning.core import drains
from defender.tests.support.runtime.engine._declared869 import git
from defender.tests.support.sandbox._spec791 import author_markers, marker_body
from defender.tests.support.learning.core._state1135 import curation_row
from defender.tests.learning.curation.test_1134_curator_git_bounds import _Shim
from defender.tests.learning.curation.test_1175_claim_session import (
    _assert_leftover,
    _git_path,
    _leaving,
    _no_runnable_git,
    _oserror_in,
    _packs,
)
from defender.tests.learning.curation.test_1175_leads_git_liveness import (
    BOUND,
    CURATE,
    EDIT_LIFT,
    EDITED_LIFT,
    EXEC,
    LIFT,
    LIFT_TEXT,
    STALL_SECONDS,
    _assert_lead_served,
    _assert_rows_consumed,
    _failed,
    _lead_scene,
    _LeadLane,
    _no_claim,
    _no_curation,
    _pitfalls_scene,
    _PitfallsLane,
    _serving,
    _tick,
)


#: The subcommands that make up the claim's commit (S3: reset the index, stage, commit), in
#: whatever spelling an implementation picks.
COMMIT_STEP = ("read-tree", "add", "rm", "update-index", "write-tree", "commit", "commit-tree",
               "update-ref")


@dataclasses.dataclass(frozen=True)
class _IndexHook:
    """A hook that records the git command that ran it (its parent's argv) and, when that
    command is one of the commit's own steps, stalls `STALL_SECONDS` (stdio closed)."""

    name: str
    ran: Path
    pids: Path

    def install(self, wt: Path) -> None:
        hooks = _git_path(wt, "hooks")
        hooks.mkdir(parents=True, exist_ok=True)
        words = " ".join(COMMIT_STEP)
        script = f"""#!/bin/sh
argv=$(tr '\\0' ' ' < /proc/$PPID/cmdline)
sub=""; skip=0; first=1
for a in $argv; do
  if [ "$first" = 1 ]; then first=0; continue; fi
  if [ "$skip" = 1 ]; then skip=0; continue; fi
  case "$a" in -c|-C) skip=1 ;; -*) ;; *) sub="$a"; break ;; esac
done
echo "$sub" >> '{self.ran}'
case " {words} " in
  *" $sub "*) echo $$ >> '{self.pids}'; exec sleep {STALL_SECONDS} >/dev/null 2>&1 </dev/null ;;
esac
exit 0
"""
        hook = hooks / self.name
        hook.write_text(script, encoding="utf-8")
        hook.chmod(0o755)

    @property
    def shim(self) -> _Shim:
        return _Shim(log=self.ran.with_name("no-shim.log"), pids=self.pids)

    def runs(self) -> list[str]:
        return self.ran.read_text(encoding="utf-8").split() if self.ran.is_file() else []

    def assert_armed(self, wt: Path, rel: str) -> None:
        """Positive control: a plain `git add` of an edited file in `wt` runs the hook and is
        stalled by it."""
        (wt / rel).write_text("# touched by the positive control\n", encoding="utf-8")
        before = len(self.runs())
        argv = ["git", "-C", str(wt), "add", "--", rel]
        with pytest.raises(subprocess.TimeoutExpired):
            subprocess.run(argv, capture_output=True, timeout=BOUND * 2)
        assert "add" in self.runs()[before:], f"a plain add did not run {self.name}"


@pytest.mark.parametrize("name", ["post-index-change"])
def test_r2a_no_index_hook_runs_in_the_lead_author_commit(tmp_path, monkeypatch, name):
    sc = _lead_scene(tmp_path, monkeypatch)
    hook = _IndexHook(name, ran=tmp_path / "hook-ran", pids=tmp_path / "hook-pids")
    hook.install(sc.wt)
    lane = _LeadLane(EDIT_LIFT, git_timeout=BOUND)
    try:
        got = _tick(sc, run_lead_author=lane, run_pitfalls=_no_curation, shim=hook.shim)
        in_commit = [r for r in hook.runs() if r in COMMIT_STEP]

        assert got == ("value", 0), got
        assert in_commit == [], f"the {name} hook ran in the claim's commit: {in_commit}"
        _assert_lead_served(sc, {f"M\t{LIFT}"})
        hook.assert_armed(sc.wt, LIFT)
    finally:
        hook.shim.kill_stalls()


@pytest.mark.parametrize("name", ["post-index-change"])
def test_r2a_no_index_hook_runs_in_the_curation_commit(tmp_path, monkeypatch, name):
    """O7, pitfalls: as the lead-author scene; the row is consumed against `M EXEC`."""
    sc = _pitfalls_scene(tmp_path, monkeypatch)
    hook = _IndexHook(name, ran=tmp_path / "hook-ran", pids=tmp_path / "hook-pids")
    hook.install(sc.wt)
    lane = _PitfallsLane(CURATE, git_timeout=BOUND)
    try:
        got = _tick(sc, run_lead_author=_no_claim, run_pitfalls=lane, shim=hook.shim)
        in_commit = [r for r in hook.runs() if r in COMMIT_STEP]

        assert got == ("value", 0), got
        assert in_commit == [], f"the {name} hook ran in the curation's commit: {in_commit}"
        _assert_rows_consumed(sc, {f"M\t{EXEC}"})
        hook.assert_armed(sc.wt, EXEC)
    finally:
        hook.shim.kill_stalls()


def _arm_loose_objects_maintenance(wt: Path) -> None:
    """Make the next `git commit` in `wt` run `git maintenance run --auto`'s `loose-objects`
    task in the foreground (it packs loose objects into `pack/loose-*.pack`): enabled, its auto
    threshold 1, gc's own threshold untouched, detaching off."""
    for key, value in (("maintenance.loose-objects.enabled", "true"),
                       ("maintenance.loose-objects.auto", "1"),
                       ("maintenance.autoDetach", "false"), ("gc.autoDetach", "false")):
        git(wt, "config", key, value)


def test_r2b_no_maintenance_task_runs_in_the_lead_author_commit(tmp_path, monkeypatch):
    sc = _lead_scene(tmp_path, monkeypatch)
    _arm_loose_objects_maintenance(sc.wt)
    assert _packs(sc.wt) == []

    got = _tick(sc, run_lead_author=_LeadLane(EDIT_LIFT), run_pitfalls=_no_curation)

    assert got == ("value", 0), got
    assert _packs(sc.wt) == [], "a maintenance task ran in the claim's commit"
    _assert_lead_served(sc, {f"M\t{LIFT}"})
    git(sc.wt, "commit", "--allow-empty", "-q", "-m", "maintenance probe")
    assert _packs(sc.wt), "a plain commit ran no maintenance: the scene was unarmed"


def test_r2b_no_maintenance_task_runs_in_the_curation_commit(tmp_path, monkeypatch):
    sc = _pitfalls_scene(tmp_path, monkeypatch)
    _arm_loose_objects_maintenance(sc.wt)
    assert _packs(sc.wt) == []

    got = _tick(sc, run_lead_author=_no_claim, run_pitfalls=_PitfallsLane(CURATE))

    assert got == ("value", 0), got
    assert _packs(sc.wt) == [], "a maintenance task ran in the curation's commit"
    _assert_rows_consumed(sc, {f"M\t{EXEC}"})
    git(sc.wt, "commit", "--allow-empty", "-q", "-m", "maintenance probe")
    assert _packs(sc.wt), "a plain commit ran no maintenance: the scene was unarmed"


@pytest.mark.parametrize("how", ["missing", "not-executable", None],
                         ids=["missing", "not-executable", "control"])
def test_r2c_unstartable_git_after_a_requeued_claim_ends_the_tick(tmp_path, monkeypatch, how):
    sc = _lead_scene(tmp_path, monkeypatch, cases=("case-a", "case-b"))
    run_a, run_b = sc.run_dirs
    served: list[Path] = []
    path_dir = _no_runnable_git(tmp_path, how) if how else None

    def retry(*_a: Any, **_kw: Any) -> None:
        raise drains._LeadAuthorRetry("transient: the agent spawn failed")

    with monkeypatch.context() as patch:
        transient = _leaving(LIFT, EDITED_LIFT, patch, path_dir, retry)
        plain = _serving(served)

        def step(paths: Any, state: Any, run: Any, **kw: Any) -> None:
            (transient if run.run_dir == run_a else plain)(paths, state, run, **kw)

        got = _tick(sc, run_lead_author=step, run_pitfalls=_no_curation, git_timeout=BOUND)

    if how is None:
        assert got == ("value", 0), got
        assert served == [run_b]
        _assert_leftover(sc.wt, LIFT, EDITED_LIFT, cleaned=True, committed=LIFT_TEXT)
        return
    result, exc = got
    assert result == "raised", got
    assert _oserror_in(exc), repr(exc)
    assert served == [], "the next claim was served over the re-queued claim's leftovers"
    assert "case-b.json" in author_markers(sc.paths)
    assert marker_body(sc.paths.state_root / "author-queue" / "case-b.json") == \
        curation_row("case-b", run_b)
    assert _failed(sc.paths) == []
    assert "finish" not in sc.branch.events
    _assert_leftover(sc.wt, LIFT, EDITED_LIFT, cleaned=False, committed=LIFT_TEXT)


def _install_fsmonitor_hook(wt: Path, ran: Path, pids: Path) -> None:
    """`<hooks>/fsmonitor-watchman`, wired in through `core.fsmonitor` as githooks(5) documents.
    It records the git command that ran it and stalls when that is one of the commit's steps;
    otherwise it exits 1, which tells git to fall back to a full scan (so it hides nothing)."""
    hooks = _git_path(wt, "hooks")
    hooks.mkdir(parents=True, exist_ok=True)
    words = " ".join(COMMIT_STEP)
    hook = hooks / "fsmonitor-watchman"
    hook.write_text(f"""#!/bin/sh
argv=$(tr '\\0' ' ' < /proc/$PPID/cmdline)
sub=""; skip=0; first=1
for a in $argv; do
  if [ "$first" = 1 ]; then first=0; continue; fi
  if [ "$skip" = 1 ]; then skip=0; continue; fi
  case "$a" in -c|-C) skip=1 ;; -*) ;; *) sub="$a"; break ;; esac
done
echo "$sub" >> '{ran}'
case " {words} " in
  *" $sub "*) echo $$ >> '{pids}'; exec sleep {STALL_SECONDS} >/dev/null 2>&1 </dev/null ;;
esac
exit 1
""", encoding="utf-8")
    hook.chmod(0o755)
    git(wt, "config", "core.fsmonitor", str(hook))


def test_r2e_no_fsmonitor_hook_runs_in_the_lead_author_commit(tmp_path, monkeypatch):
    sc = _lead_scene(tmp_path, monkeypatch)
    ran, pids = tmp_path / "fsm-ran", tmp_path / "fsm-pids"
    _install_fsmonitor_hook(sc.wt, ran, pids)
    shim = _Shim(log=tmp_path / "no-shim.log", pids=pids)
    lane = _LeadLane(EDIT_LIFT, git_timeout=BOUND)
    try:
        got = _tick(sc, run_lead_author=lane, run_pitfalls=_no_curation, shim=shim)
        runs = ran.read_text(encoding="utf-8").split() if ran.is_file() else []
        in_commit = [r for r in runs if r in COMMIT_STEP]

        assert got == ("value", 0), got
        assert in_commit == [], f"the fsmonitor hook ran in the claim's commit: {in_commit}"
        _assert_lead_served(sc, {f"M\t{LIFT}"})
        # Positive control: a plain `git add` in the same repo runs (and is stalled by) it.
        (sc.wt / LIFT).write_text("# touched by the positive control\n", encoding="utf-8")
        before = len(ran.read_text(encoding="utf-8").split()) if ran.is_file() else 0
        with pytest.raises(subprocess.TimeoutExpired):
            subprocess.run(["git", "-C", str(sc.wt), "add", "--", LIFT], capture_output=True,
                           timeout=BOUND * 2)
        assert "add" in ran.read_text(encoding="utf-8").split()[before:]
    finally:
        shim.kill_stalls()
