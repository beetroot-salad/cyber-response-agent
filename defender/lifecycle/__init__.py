"""Tenant lifecycle as a service (#1214): the management service and the execution-host actor that
work each tenant's one job (create, rotate, offboard, the repo deletion), the lab's adoption, and
the process that drives them (`python -m defender.lifecycle serve|adopt <T>`).

The service alone holds the forge and OpenBao admin powers; the API never loads this package
(`API_FORBIDDEN`), and reaches the job only through the tenant's row."""

from __future__ import annotations

from defender.lifecycle._adopt import AdoptRefused, adopt
from defender.lifecycle._host import HostActor
from defender.lifecycle._job import StepFailed
from defender.lifecycle._process import git_runner, integration_runner, serve
from defender.lifecycle._service import ManagementService
from defender.lifecycle.config import ConfigRefused, LifecycleConfig

__all__ = [
    "AdoptRefused", "ConfigRefused", "HostActor", "LifecycleConfig", "ManagementService", "StepFailed", "adopt",
    "git_runner", "integration_runner", "serve",
]
