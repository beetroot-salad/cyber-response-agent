"""#1618 K7 through a real run process: the copy is owned by the run process until it dies, then swept."""
from __future__ import annotations

import json
import signal

import pytest

from defender.tests.tenancy.knowledge_1618 import _slice_a as A
from defender.tests.tenancy.knowledge_1618 import _support as K

pytestmark = pytest.mark.e2e


def test_a4_a17_a_real_run_process_owns_its_copy_until_killed_then_a_sweep_removes_it(decoy, tmp_path):
    """The run's copy names the run process as owner, survives a sweep from another process, and goes once it is dead (F1, K7)."""
    t = decoy
    proc, run_dir = A.start_run_process(t, tmp_path, A.child_command(t, tmp_path))
    try:
        copy = A.run_copies(t) / run_dir.name
        assert json.loads((copy / "owner").read_text())["pid"] == proc.pid
        assert A.listing(A.run_copies(t)) == [run_dir.name]
        K.sweep(t)
        assert copy.is_dir(), "a live run's copy was swept"
        proc.send_signal(signal.SIGKILL)
        proc.wait(timeout=30)
        K.sweep(t)
        assert not copy.exists(), "a dead run's copy was not swept"
    finally:
        proc.kill()
