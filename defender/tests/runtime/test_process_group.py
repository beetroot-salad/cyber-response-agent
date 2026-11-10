"""A run's end is its whole process group gone, not its child's exit (`end_group`).

A SIGKILL lands when each member is next scheduled, so "the kill was sent" and "nothing of
the group runs" are a moment apart; callers that clean up after a run, or report it ended,
need the second."""
from __future__ import annotations

import contextlib
import os
import signal
import subprocess
import sys
import time

import pytest

from defender.execution import end_group, group_running

pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="reads /proc")


def _runs(pid: int) -> bool:
    """Whether `pid` still runs, as `ps` reports it (gone, or exited awaiting a wait, is not running): an oracle apart
    from the /proc parse it checks."""
    out = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True, check=False).stdout
    return bool(out.strip()) and not out.strip().startswith("Z")


def test_end_group_returns_only_once_no_member_of_a_real_group_runs():
    """A child that leaves two grandchildren in its group and exits: once `end_group` returns, neither grandchild runs;
    the control shows both ran after the child had gone."""
    child = subprocess.Popen(["sh", "-c", "sleep 60 & echo $!; sleep 60 & echo $!; exit 0"],
                             stdout=subprocess.PIPE, start_new_session=True)
    grandchildren: list[int] = []
    try:
        assert child.stdout is not None
        grandchildren = [int(child.stdout.readline()), int(child.stdout.readline())]
        child.wait(timeout=10)
        assert all(_runs(g) for g in grandchildren), "control: the grandchildren run after the child exits"
        assert group_running(child.pid)

        assert end_group(child.pid) is True

        assert not [g for g in grandchildren if _runs(g)], "end_group returned while a grandchild ran"
        assert not group_running(child.pid)
    finally:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(child.pid, signal.SIGKILL)
        if child.stdout is not None:
            child.stdout.close()


#: Signal stand-ins for a fake /proc's made-up pids: every group and member exists and is this user's to signal.
_DOORS = {"killpg": lambda _pgid, _sig: None, "kill": lambda _pid, _sig: None}


def _fake_proc(root, rows: dict[int, bytes]):
    """A /proc stand-in: one `<pid>/stat` per row, holding exactly those bytes."""
    for pid, stat in rows.items():
        (root / str(pid)).mkdir(parents=True)
        (root / str(pid) / "stat").write_bytes(stat)
    (root / "self").mkdir()
    return str(root)


def test_the_group_is_read_after_the_last_parenthesis_of_a_command_name_holding_spaces_and_parentheses(tmp_path):
    """`pid (comm) state ppid pgrp ...`: a name like `a) b (c` must not shift the fields. Member 11 of group 7 runs;
    12 is a zombie of 7; 13 runs in group 8."""
    proc = _fake_proc(tmp_path / "proc", {
        11: b"11 (a) b (c) S 1 7 7 0",
        12: b"12 (zz) Z 1 7 7 0",
        13: b"13 (x) R 1 8 8 0",
    })
    assert group_running(7, proc=proc, **_DOORS)
    assert not group_running(9, proc=proc, **_DOORS), "a group with no member runs nothing"

    zombie_only = _fake_proc(tmp_path / "proc2", {12: b"12 (a) b (c) Z 1 7 7 0", 13: b"13 (x) R 1 8 8 0"})
    assert not group_running(7, proc=zombie_only, **_DOORS), "a group of zombies only runs nothing"


def test_a_member_this_user_cannot_signal_is_not_waited_for(tmp_path):
    """The kill never reached a member this user may not signal (a setuid program, say): waiting cannot see it end, so
    it does not count."""
    def kill(pid: int, _sig: int) -> None:
        if pid == 21:
            raise PermissionError

    proc = _fake_proc(tmp_path / "proc", {21: b"21 (sudo) S 1 7 7 0"})
    assert not group_running(7, proc=proc, killpg=_DOORS["killpg"], kill=kill)
    proc_with_ours = _fake_proc(tmp_path / "proc2", {21: b"21 (sudo) S 1 7 7 0", 22: b"22 (sh) S 1 7 7 0"})
    assert group_running(7, proc=proc_with_ours, killpg=_DOORS["killpg"], kill=kill), "control: a member this user can signal still counts"


def test_without_proc_a_group_that_still_exists_is_not_waited_for(tmp_path):
    """No /proc: a zombie cannot be told from a live member, so the wait does not spend its limit on one (a git timeout
    would otherwise cost the whole limit on every call)."""
    assert not group_running(7, proc=str(tmp_path / "no-proc-here"), **_DOORS)


def test_end_group_waits_while_a_member_still_runs_after_the_kill():
    """The kill is sent first, then the wait lasts as long as the liveness test says a member runs: three polls here."""
    asked: list[int] = []

    def running(pgid: int) -> bool:
        asked.append(pgid)
        return len(asked) <= 3

    assert end_group(999_999_999, running=running) is True
    assert asked == [999_999_999] * 4


def test_end_group_gives_up_at_its_limit_and_says_so(caplog):
    """A member that never stops running does not hang the caller: False at the limit, logged as an error."""
    began = time.monotonic()
    assert end_group(999_999_999, limit=0.2, running=lambda _pgid: True) is False
    assert time.monotonic() - began < 2.0
    assert any("still ran" in r.getMessage() and r.levelname == "ERROR" for r in caplog.records), caplog.records


def test_a_group_with_no_member_left_is_not_running():
    """No member at all: the cheap check answers without reading /proc."""
    child = subprocess.Popen(["true"], start_new_session=True)
    child.wait(timeout=10)
    assert not group_running(child.pid)
    assert end_group(child.pid) is True
