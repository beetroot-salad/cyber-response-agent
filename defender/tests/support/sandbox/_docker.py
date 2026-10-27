"""Is there a docker daemon this process can actually use."""
from __future__ import annotations

import functools
import subprocess
from pathlib import Path

#: The tree the live suites bind into their boxes; its parent is the repo root.
_DEFENDER = Path(__file__).resolve().parents[3]


@functools.cache
def daemon_reachable() -> bool:
    """A docker daemon answers `version`. Never raises — an absent binary is a `False`."""
    try:
        return subprocess.run(
            ["docker", "version", "--format", "{{.Server.Version}}"],
            capture_output=True, timeout=30,
        ).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


@functools.cache
def is_dood() -> bool:
    """Docker-outside-of-Docker: a reachable daemon whose root dir is not OUR root dir.

    `docker run -v` binds then resolve on the HOST, so a bind source that exists here is
    invisible to the daemon: the box starts and the test fails on missing files instead of
    skipping. `daemon_reachable()` alone misses this.
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
    """The runtimes the daemon registers (`docker info` Runtimes); empty when it answers non-zero.

    RAISES when `docker` cannot run or times out, on purpose: an empty set skips every
    runtime-gated live test, so one slow `docker info` would turn those suites green while they
    test nothing. Callers ask only after `daemon_reachable()`."""
    probe = subprocess.run(
        ["docker", "info", "--format", "{{range $k, $v := .Runtimes}}{{$k}} {{end}}"],
        capture_output=True, text=True, encoding="utf-8", timeout=30,
    )
    return frozenset(probe.stdout.split()) if probe.returncode == 0 else frozenset()


def dood_anchor() -> Path | None:
    """Where a live box's bind sources must live under DooD, or None if the topology is
    unobservable here."""
    from defender import box as box_mod

    mounts = box_mod._shared_mounts(box_mod._docker)
    if not mounts or not box_mod._covered(_DEFENDER, mounts):
        return None
    return _DEFENDER.parent / ".defender-runs"
