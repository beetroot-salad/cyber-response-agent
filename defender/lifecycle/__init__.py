"""Tenant lifecycle as a service (#1214): the management service and the execution-host actor that
work each tenant's one job (create, rotate, offboard, the repo deletion), and the
process that drives them (`python -m defender.lifecycle serve`), and the request worker that keeps Forgejo's people in
line with the product's memberships (#1592).

The service alone holds the forge and OpenBao admin powers; the API never loads this package
(`API_FORBIDDEN`), and reaches the job only through the tenant's row."""

from __future__ import annotations

from defender.lifecycle._host import HostActor
from defender.lifecycle._job import StepFailed
from defender.lifecycle._people import PeopleWorker
from defender.lifecycle._process import git_runner, integration_runner, serve
from defender.lifecycle._runs import RunsFoldersRefused, make_runs_folders
from defender.lifecycle._service import ManagementService
from defender.lifecycle._sessions import (
    UID_ENTRY,
    InMemoryForgeSessions,
    PostgresForgeSessions,
    SessionRow,
    UnreadableSession,
    session_uid,
)
from defender.lifecycle.config import ConfigRefused, LifecycleConfig

__all__ = [
    "UID_ENTRY", "ConfigRefused", "HostActor", "InMemoryForgeSessions", "LifecycleConfig", "ManagementService",
    "PeopleWorker", "PostgresForgeSessions", "RunsFoldersRefused", "SessionRow", "StepFailed", "UnreadableSession",
    "git_runner", "integration_runner", "make_runs_folders", "serve", "session_uid",
]
