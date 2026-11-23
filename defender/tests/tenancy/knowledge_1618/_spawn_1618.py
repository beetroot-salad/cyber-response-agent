"""The fetch launcher's spawn seam as a recorder (moved here from the retired `tenant_1108_p4/test_publish_child.py`)."""
from __future__ import annotations

import os
import subprocess
import sys
from typing import Any


class RecordingSpawn:
    """`launch_publish`'s spawn seam (`subprocess.Popen`'s signature): records the argv and environment the launcher would
    start its child with, then starts a harmless process (which prints no report line)."""

    def __init__(self) -> None:
        self.calls: list[tuple[list[str], dict]] = []

    def __call__(self, argv: Any, **kw: Any) -> subprocess.Popen:
        env = kw.get("env")
        self.calls.append((list(map(str, argv)), dict(os.environ if env is None else env)))
        return subprocess.Popen([sys.executable, "-c", "pass"],  # noqa: S603 — a test double
                                stdout=kw.get("stdout"), stderr=kw.get("stderr"), stdin=kw.get("stdin"))
