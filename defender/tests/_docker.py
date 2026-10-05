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

It also answers the two questions the live-box suites ask before starting a box: which
runtimes the daemon registers (`docker_runtimes`, probed once per process however many cases
ask), and, under DooD, where a bind source must live for the daemon to see it
(`dood_anchor`). Both had been near-copied between `e2e/test_540_box_boundary` and
`e2e/test_1188_box_fsize`.

Underscore-prefixed so pytest does not collect it; it defines no tests.
"""
from __future__ import annotations

import functools
import subprocess
from pathlib import Path

#: The tree the live suites bind into their boxes; its parent is the repo root.
_DEFENDER = Path(__file__).resolve().parents[1]


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


@functools.cache
def docker_runtimes() -> frozenset[str]:
    """The runtimes the daemon registers (`docker info` Runtimes), asked once per process: a
    suite parametrized over runtimes would otherwise pay one `docker info` per case. Empty
    when the daemon cannot say. Never raises."""
    try:
        probe = subprocess.run(
            ["docker", "info", "--format", "{{range $k, $v := .Runtimes}}{{$k}} {{end}}"],
            capture_output=True, text=True, encoding="utf-8", timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return frozenset()
    return frozenset(probe.stdout.split()) if probe.returncode == 0 else frozenset()


def dood_anchor() -> Path | None:
    """Where a live box's bind sources must live under DooD, or None if the topology is
    unobservable here.

    A bind SOURCE has to lie on a path this container shares with the daemon, and pytest's
    `tmp_path` is a private `/tmp` that does not. The repo tree does — the defender dir is
    bound out of it — so the anchor is the gitignored `.defender-runs/` beside it. If even
    the repo is uncovered, `start_box` would refuse (C46) and there is nothing to observe, so
    the caller skips instead of asserting into the dark. Only meaningful under DooD
    (`is_dood()`); the box package is imported here, not at module top, so the suites that
    only ask `daemon_reachable` do not pay for it."""
    from defender.runtime import box as box_mod

    mounts = box_mod._shared_mounts(box_mod._docker)
    if not mounts or not box_mod._covered(_DEFENDER, mounts):
        return None
    return _DEFENDER.parent / ".defender-runs"
