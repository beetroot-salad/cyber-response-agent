"""Stopping what works for a tenant on the execution host before its folder goes (#1214 P3, O4,
Flow 2.3): the processes recorded under the tenant's host lock, and its box containers (labelled
`defender.tenant=<T>`). Blocking; the host actor runs it in a worker thread."""
from __future__ import annotations

import logging
import os
import signal
import subprocess
from collections.abc import Callable
from pathlib import Path

from defender.box import TENANT_LABEL
from defender.lifecycle._job import StepFailed
from defender.tenancy import host_lock, process_start

_logger = logging.getLogger(__name__)

_DOCKER_TIMEOUT = 120

Containers = Callable[[str], None]


def stop_containers(tenant_id: str) -> None:
    """Remove every container labelled with the tenant. A host with no docker has no box to stop;
    a docker that answers with an error fails the step."""
    try:
        listed = subprocess.run(["docker", "ps", "-aq", "--filter", f"label={TENANT_LABEL}={tenant_id}"],  # noqa: S603, S607 — fixed argv
                                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=_DOCKER_TIMEOUT, check=False)
    except FileNotFoundError:
        return
    if listed.returncode != 0:
        raise StepFailed(f"docker could not list the tenant's containers: {listed.stderr.strip()}")
    ids = listed.stdout.split()
    if not ids:
        return
    removed = subprocess.run(["docker", "rm", "-f", *ids], capture_output=True, text=True, encoding="utf-8", errors="replace",  # noqa: S603, S607 — fixed argv
                             timeout=_DOCKER_TIMEOUT, check=False)
    if removed.returncode != 0:
        raise StepFailed(f"docker could not remove the tenant's containers: {removed.stderr.strip()}")


def _signal(data_root: Path, tenant_id: str, sig: signal.Signals) -> list[int]:
    sent = []
    for holder in host_lock.holders(data_root, tenant_id):
        if process_start(holder.pid) != holder.start:
            continue  # gone since it was listed; the pid may already name another process
        try:
            os.kill(holder.pid, sig)
        except ProcessLookupError:
            continue
        sent.append(holder.pid)
    return sent


def take_exclusive(data_root: Path, tenant_id: str, *, wait: float,
                   containers: Containers) -> int:
    """The tenant's host lock, exclusive, once nothing works for the tenant: the recorded processes
    get SIGTERM and the tenant's containers are removed; after `wait` seconds without the lock the
    processes still recorded get SIGKILL; still held after another `wait`, the step fails loudly.
    Returns the lock's descriptor (`host_lock.release_lock` it)."""
    fd = host_lock.acquire(data_root, tenant_id, exclusive=True, timeout=0)
    if fd is None:
        terminated = _signal(data_root, tenant_id, signal.SIGTERM)
        _logger.info("tenant %s: teardown sent SIGTERM to %s", tenant_id, terminated)
    containers(tenant_id)
    if fd is None:
        fd = host_lock.acquire(data_root, tenant_id, exclusive=True, timeout=wait)
    if fd is None:
        killed = _signal(data_root, tenant_id, signal.SIGKILL)
        _logger.warning("tenant %s: teardown sent SIGKILL to %s after %ss", tenant_id, killed, wait)
        fd = host_lock.acquire(data_root, tenant_id, exclusive=True, timeout=wait)
    if fd is None:
        still = [h.pid for h in host_lock.holders(data_root, tenant_id)]
        raise StepFailed(f"the tenant's host lock is still held after SIGKILL (recorded processes: {still or 'none'})")
    return fd
