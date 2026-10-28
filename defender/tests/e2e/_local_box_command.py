"""Run an in-box Python command locally as a host stand-in for Docker tests."""
from __future__ import annotations

import os
import subprocess
import sys

from defender.tests.support.shared.contracts._by_path import WORKTREE


def run_box_python_command(command: list[str]) -> subprocess.CompletedProcess[str]:
    """Run the command's script/operands under the test interpreter with this worktree on
    `PYTHONPATH`: pytest's sys.path injection does not reach a subprocess, and fake product
    mounts may hold only fixtures rather than the runnable package the image would mount.
    """
    return subprocess.run(
        [sys.executable, *command[1:]],
        env={**os.environ, "PYTHONPATH": str(WORKTREE)},
        capture_output=True, text=True, check=False,
        encoding="utf-8", errors="replace", timeout=10,
    )
