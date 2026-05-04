"""In-memory replacement for `subprocess.run` used by tests that exercise the
subagent wrapper. Captures the kwargs the wrapper passes (argv, stdin payload,
env, cwd) and returns a canned `CompletedProcess`, so tests can assert on the
shape of the spawn without spawning anything.

Pass an instance (or `.run`) into `invoke_subagent(_runner=...)`.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field


@dataclass
class RecordingRunner:
    """Drop-in for `subprocess.run` with the kwargs `_subagent` actually uses."""

    stdout: str = "ok\n"
    stderr: str = ""
    returncode: int = 0
    calls: list[dict] = field(default_factory=list)

    def __call__(
        self,
        argv,
        input=None,
        capture_output=False,
        text=False,
        timeout=None,
        env=None,
        cwd=None,
    ) -> subprocess.CompletedProcess:
        self.calls.append({
            "argv": list(argv),
            "input": input,
            "env": env,
            "cwd": cwd,
            "timeout": timeout,
        })
        return subprocess.CompletedProcess(
            args=argv,
            returncode=self.returncode,
            stdout=self.stdout,
            stderr=self.stderr,
        )

    @property
    def last(self) -> dict:
        if not self.calls:
            raise AssertionError("RecordingRunner: no calls recorded yet")
        return self.calls[-1]
