"""The deployment bootstrap file: who the platform administrators are, and which existing
tenants have which first members. Plain data; the service applies it at start."""

from __future__ import annotations

from collections.abc import Mapping

from defender._model import model
from defender.tenancy._tenant import TenantId

from .ports import IdentityRepository


@model(frozen=True)
class Bootstrap:
    administrators: tuple[str, ...]
    tenants: Mapping[str, tuple[str, ...]]


def register_tenant(repo: IdentityRepository, tenant_id: TenantId) -> None:
    """Register a tenant so memberships can refer to it. The one function #1214's tenant
    creation takes over."""
    repo.register_tenant(tenant_id)
