"""The deployment bootstrap file: who the platform administrators are, and which existing
tenants have which first members. Plain data; the service applies it at start."""

from __future__ import annotations

import datetime as _dt
from collections.abc import Mapping

from defender._model import model
from defender.records._tenant_id import TenantId

from .ports import IdentityRepository
from .models import Email


@model(frozen=True)
class Bootstrap:
    administrators: tuple[Email, ...]
    tenants: Mapping[str, tuple[Email, ...]]


async def register_tenant(repo: IdentityRepository, tenant_id: TenantId, *, now: _dt.datetime) -> None:
    """Register a tenant so memberships can refer to it. The one function #1214's tenant
    creation takes over."""
    await repo.register_tenant(tenant_id, now=now)
