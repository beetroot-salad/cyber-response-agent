"""The worker's container seam (#1342 O7, #1446 review): after every child of any kind, remove
every container its process tree started (`box.CLAIM_LABEL`), the one removal step; then, for an
investigation, ask whether its box's name `defender-run-<id>` is still held. A container the sweep
left under that name is not this job's and is left in place (r5 C1).

At start the worker also removes every leftover job container, by the label every per-job host
helper stamps on its container (`job_socket.JOB_LABEL`, #1170 A5), sparing each whose helper still
runs (`job_socket.HELPER_LABEL`: its `tenancy.process_mark`), so a worker sharing a daemon with another
never removes that worker's live jobs. A helper in another pid namespace than this worker's reads as
gone: the daemon is shared only by workers on one host."""
from __future__ import annotations

from typing import Protocol

from defender.box import (
    BoxFault,
    DockerFn,
    container_present,
    labelled_containers,
    remove_claimed_containers,
    remove_containers,
    run_docker,
)
from defender.job_socket import HELPER_LABEL, JOB_LABEL
from defender.tenancy import mark_alive


class Containers(Protocol):
    """What the worker asks of a container runtime. A runtime that cannot answer raises."""

    def present(self, name: str) -> bool:
        """Whether a container holds the name `name`, in any state."""
        ...

    def remove_claimed(self, claim: str) -> None:
        """Remove every container carrying the claim label `claim`, whatever its state; raises
        when the runtime cannot list or remove them."""
        ...

    def remove_job_containers(self) -> None:
        """Remove every container carrying the job-container label (`job_socket.JOB_LABEL`) whose
        helper no longer runs, whatever its state and whoever's claim it names; raises when the
        runtime cannot list or remove them."""
        ...


class DockerContainers:
    """The default seam: the daemon, through a docker function of the box package's call shape
    (`docker(argv) -> CompletedProcess`). A daemon that cannot answer, or a claimed container
    that survives the forced removal, raises `BoxFault`."""

    def __init__(self, docker: DockerFn = run_docker) -> None:
        self._docker = docker

    def present(self, name: str) -> bool:
        return container_present(name, docker=self._docker)

    def remove_claimed(self, claim: str) -> None:
        reason = remove_claimed_containers(claim, docker=self._docker)
        if reason is not None:
            raise BoxFault(reason)

    def remove_job_containers(self) -> None:
        gone = [name for name, helper in labelled_containers(JOB_LABEL, read=HELPER_LABEL, docker=self._docker)
                if not mark_alive(helper)]
        reason = remove_containers(gone, docker=self._docker, whose="the job")
        if reason is not None:
            raise BoxFault(reason)

