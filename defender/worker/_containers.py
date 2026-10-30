"""The worker's container backstop seam (#1342 O7): after a child is gone, is its box
`defender-run-<id>` still there, and remove it. An absent container is the normal case."""
from __future__ import annotations

import subprocess
from typing import Protocol

from defender.box import DockerFn, run_docker


class Containers(Protocol):
    """What the backstop asks of a container runtime."""

    def exists(self, name: str) -> bool: ...

    def remove(self, name: str) -> None: ...


class ContainerUnanswered(Exception):
    """The daemon could not be asked, or did not answer, about a container."""


class DockerContainers:
    """The default seam: the daemon, through a docker function of the box package's call shape
    (`docker(argv) -> CompletedProcess`)."""

    def __init__(self, docker: DockerFn = run_docker) -> None:
        self._docker = docker

    def _call(self, argv: list[str]) -> subprocess.CompletedProcess:
        try:
            return self._docker(argv)
        except (OSError, subprocess.SubprocessError) as e:
            raise ContainerUnanswered(f"could not invoke docker ({argv[:2]}): {e}") from e

    def exists(self, name: str) -> bool:
        """Whether the daemon holds a container of this name, in any state, running included.
        Decided by `inspect`'s exit code; a non-zero one is "no such container" only when the
        daemon itself answers, otherwise `ContainerUnanswered`."""
        if self._call(["docker", "inspect", "-f", "{{.State.Status}}", name]).returncode == 0:
            return True
        alive = self._call(["docker", "version", "-f", "{{.Server.Version}}"])
        if alive.returncode != 0:
            raise ContainerUnanswered(
                f"docker could not say whether {name} exists, and could not answer for the daemon "
                f"either ({(alive.stderr or '').strip()[:200]!r})")
        return False

    def remove(self, name: str) -> None:
        """Remove the container, running or not. A paused one under runsc may survive the first
        `rm -f` until it has exited (`box._docker`'s removal, #1202), so wait and try once more."""
        argv = ["docker", "rm", "-f", name]
        first = self._call(argv)
        if first.returncode == 0:
            return
        self._call(["docker", "wait", name])
        second = self._call(argv)
        if second.returncode != 0:
            raise ContainerUnanswered(
                f"could not remove {name}: {(first.stderr or '').strip()[:200]}; after waiting: "
                f"{(second.stderr or '').strip()[:200]}")
