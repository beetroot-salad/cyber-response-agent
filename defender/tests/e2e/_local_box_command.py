"""Run an in-box Python command locally as a host stand-in for Docker tests."""
from __future__ import annotations

import os
import subprocess
import sys

from defender.tests.support.shared.contracts._by_path import WORKTREE


def run_box_python_command(command: list[str]) -> subprocess.CompletedProcess[str]:
    """Keep the supplied script/operands, using the test runtime and this worktree's imports.

    Docker exec inherits the image's Python and mounted package. The local stand-in needs
    the test interpreter's dependencies and an explicit import root: pytest's sys.path
    injection is not a subprocess environment variable, and fake product mounts may hold
    only geography fixtures rather than a runnable package.
    """
    return subprocess.run(
        [sys.executable, *command[1:]],
        env={**os.environ, "PYTHONPATH": str(WORKTREE)},
        capture_output=True, text=True, check=False,
        encoding="utf-8", errors="replace", timeout=10,
    )
