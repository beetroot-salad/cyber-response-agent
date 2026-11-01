"""The worker's container backstop seam (#1342 O7, r5 C1): after a child is gone, remove its box
`defender-run-<id>` only if it carries the token this claim handed the child's box start. An
absent container is the normal case; a container with another token, or none, is not this
job's and is left in place."""
from __future__ import annotations

from typing import Protocol

from defender.box import DockerFn, reap_if_owned, run_docker


class Containers(Protocol):
    """What the backstop asks of a container runtime: `reap(name, token)` answers `"removed"`
    (the container carried the token and is gone), `"absent"`, or `"not_ours"` (left in place).
    A runtime that cannot answer raises."""

    def reap(self, name: str, token: str) -> str: ...


class DockerContainers:
    """The default seam: the daemon, through a docker function of the box package's call shape
    (`docker(argv) -> CompletedProcess`), and the box package's own removal-if-owned
    (`box.reap_if_owned`), so there is one removal step for every site. A daemon that cannot
    answer, or an owned container that survives the forced removal even after waiting, raises
    `BoxFault`."""

    def __init__(self, docker: DockerFn = run_docker) -> None:
        self._docker = docker

    def reap(self, name: str, token: str) -> str:
        return reap_if_owned(self._docker, name, token)
