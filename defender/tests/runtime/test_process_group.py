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


def _members(pgid: int) -> list[tuple[int, str]]:
    """Every process in group `pgid` with its state letter, read from /proc."""
    found = []
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        try:
            stat = open(f"/proc/{name}/stat", "rb").read()  # noqa: SIM115, PTH123 — one short read
        except OSError:
            continue
        fields = stat[stat.rindex(b")") + 2:].split()
        if int(fields[2]) == pgid:
            found.append((int(name), fields[0].decode()))
    return found


def test_end_group_returns_only_once_no_member_of_a_real_group_runs():
    """A child that leaves two grandchildren in its group and exits: once `end_group` returns, no member runs (zombies
    awaiting a wait may remain); the control shows the grandchildren ran after the child had gone."""
    child = subprocess.Popen(["sh", "-c", "sleep 60 & sleep 60 & echo up; exit 0"],
                             stdout=subprocess.PIPE, start_new_session=True)
    try:
        assert child.stdout is not None
        assert child.stdout.readline() == b"up\n"
        child.wait(timeout=10)
        assert [s for _, s in _members(child.pid) if s != "Z"], "control: the grandchildren run after the child exits"
        assert group_running(child.pid)

        assert end_group(child.pid) is True

        assert not [m for m in _members(child.pid) if m[1] != "Z"], _members(child.pid)
        assert not group_running(child.pid)
    finally:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(child.pid, signal.SIGKILL)
        if child.stdout is not None:
            child.stdout.close()


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
