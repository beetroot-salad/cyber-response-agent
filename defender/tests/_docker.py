"""Is there a docker daemon this process can actually use.

The fact several suites need before they can decide whether to run at all, and which had
been hand-copied four times across the e2e tree and the top-level tree. Neutral home rather
than either harness's, because the callers straddle both: `e2e/_box665`, `e2e/_spec771`,
`e2e/test_540_box_boundary` and `tests/test_store_boundary_705` all ask the same question.

It also carried an ambient-engine-key primer, for the run cycle #922 deleted; the primer went
with its one caller.

What deliberately does NOT live here: the pytest MARKERS built on these predicates. Those
differ genuinely between suites — one skips on no-daemon-or-DooD, one on no-daemon alone,
one adds a shared-mount coverage condition — and each reason string names the specific
capability its own tests need. A shared marker would flatten three different reasons into
one wrong one.

Underscore-prefixed so pytest does not collect it; it defines no tests.
"""
from __future__ import annotations

import subprocess
from pathlib import Path


def daemon_reachable() -> bool:
    """A docker daemon answers `version`. Never raises — an absent binary is a `False`."""
    try:
        return subprocess.run(
            ["docker", "version", "--format", "{{.Server.Version}}"],
            capture_output=True, timeout=30,
        ).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def is_dood() -> bool:
    """Docker-outside-of-Docker: a reachable daemon whose root dir is not OUR root dir.

    This is the case that matters and the one a bare `daemon_reachable()` misses. Inside a
    container talking to the host's daemon, `docker run -v` binds resolve against the
    HOST's filesystem, so a bind source that exists here is invisible there — the container
    starts and the test then fails on missing files rather than skipping. The probe is
    exactly that: the daemon reports a root directory this process cannot see.
    """
    if not Path("/.dockerenv").exists():
        return False
    probe = subprocess.run(
        ["docker", "info", "--format", "{{.DockerRootDir}}"],
        capture_output=True, text=True, encoding="utf-8", timeout=30,
    )
    root = probe.stdout.strip()
    return probe.returncode == 0 and bool(root) and not Path(root).exists()
