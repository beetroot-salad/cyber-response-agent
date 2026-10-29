"""Tenant lifecycle as a service (#1214): the management service, the execution-host actor,
adoption and the process that drives them. PLACEHOLDER: these names exist so the contract's test
modules collect; the lifecycle worker replaces each with the real thing."""

from __future__ import annotations

from typing import Any


class _Placeholder:
    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        raise NotImplementedError(f"{type(self).__name__} is not implemented yet (#1214)")


class LifecycleConfig(_Placeholder):
    """Placeholder."""


class ManagementService(_Placeholder):
    """Placeholder."""


class HostActor(_Placeholder):
    """Placeholder."""


async def adopt(*_args: Any, **_kwargs: Any) -> None:
    raise NotImplementedError("adopt is not implemented yet (#1214)")


async def serve(*_args: Any, **_kwargs: Any) -> None:
    raise NotImplementedError("serve is not implemented yet (#1214)")


__all__ = ["HostActor", "LifecycleConfig", "ManagementService", "adopt", "serve"]
