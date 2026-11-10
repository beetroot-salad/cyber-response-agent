"""The worker's container seam (#1342 O7, #1446 review): after every child of any kind, remove
every container its process tree started (`box.CLAIM_LABEL`), the one removal step; then, for an
investigation, ask whether its box's name `defender-run-<id>` is still held. A container the sweep
left under that name is not this job's and is left in place (r5 C1).

At start the worker also removes every leftover job container, by the label every per-job host
helper stamps on its container (`job_host.JOB_LABEL`, #1170 A5): the helper that held it died with
the previous worker, and so did the claim token that named it."""
from __future__ import annotations

import subprocess
from typing import Protocol

from defender import job_host
from defender.box import BoxFault, DockerFn, container_present, remove_claimed_containers, run_docker


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
        """Remove every container carrying the job-container label (`job_host.JOB_LABEL`), whatever
        its state and whoever's claim it names; raises when the runtime cannot list or remove them."""
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
        try:
            listed = self._docker(["docker", "ps", "-aq", "--filter", f"label={job_host.JOB_LABEL}"])
        except FileNotFoundError:  # a host with no docker binary has no job container to remove
            return
        except (OSError, subprocess.SubprocessError) as fault:
            raise BoxFault(f"could not invoke docker: {fault}") from fault
        if listed.returncode != 0:
            raise BoxFault(f"docker could not list the job containers: {(listed.stderr or '').strip()}")
        left = [name for name in listed.stdout.split() if not self._removed(name)]
        if left:
            raise BoxFault(f"docker could not remove the job containers {', '.join(left)}")

    def _removed(self, name: str) -> bool:
        """`docker rm -f` of one container; a paused one under runsc is killed but left, so `wait`
        proves it exited and a second removal takes it (the box package's own step, #1202). A container someone
        else removed meanwhile is gone."""
        try:
            argv = ["docker", "rm", "-f", name]
            if self._docker(argv).returncode == 0:
                return True
            self._docker(["docker", "wait", name])
            return self._docker(argv).returncode == 0 or not self.present(name)
        except (OSError, subprocess.SubprocessError, BoxFault):
            return False
