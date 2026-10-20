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
    """The runtimes the daemon registers (`docker info` Runtimes). Empty when the daemon
    answers non-zero.

    RAISES when `docker` cannot be run or does not answer in time, and that is the point: an
    empty set here skips every runtime-gated live test, so a `docker info` that timed out once
    under load would otherwise turn those suites green while they test nothing. Every caller
    asks only after `daemon_reachable()`, so a raise is a daemon that stopped answering, and it
    fails where it was asked: collection for a module-level gate, the case for a per-case one."""
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
