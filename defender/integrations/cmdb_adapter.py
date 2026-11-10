
from __future__ import annotations

from typing import TYPE_CHECKING

import sys as _sys
from pathlib import Path as _Path

if (_root := str(_Path(__file__).resolve().parents[2])) not in _sys.path:
    _sys.path.insert(0, _root)

from defender.kit.verbs import VerbContext
from defender.kit import transport

if TYPE_CHECKING:  # pragma: no cover — typing only
    from defender.kit.verbs import TenantRecord

SYSTEM = "cmdb"
PREFIX = "CMDB"
#: The system's name in the catalog listing (#1366 O2).
DISPLAY_NAME = "CMDB (lab)"
#: A lab stub (#1366 O2): an example adapter, not a real system's.
EXAMPLE = True
#: The keys its settings hold (prefix stripped): the transport's template, required, no default.
REQUIRED_CONFIG_KEYS = (*transport.REQUIRED_CONFIG_KEYS_TEMPLATE,)
#: No setting goes in a request path.
PATH_KEYS: tuple[str, ...] = ()


def _config(ctx: VerbContext) -> dict[str, str]:  # lint-dup: ok — per-module alias over the shared transport.load_config
    return transport.load_config(ctx, SYSTEM, PREFIX, REQUIRED_CONFIG_KEYS)


def _timeout(ctx: VerbContext) -> int:  # lint-dup: ok — per-module alias over the shared transport.timeout_of
    return transport.timeout_of(_config(ctx))


def check_settings(tenant: TenantRecord) -> None:  # lint-dup: ok — every adapter declares its own settings check (#1256 O-5)
    """This system's settings check (#1256 O-5): every `ConfigFault` a verb here can raise —
    `_config`'s keys and the access declaration — raised over the run's record, or None when
    the system is usable."""
    transport.check_settings_of(tenant, SYSTEM, PREFIX, REQUIRED_CONFIG_KEYS)


def health_check(ctx: VerbContext) -> dict:
    return transport.health_check(ctx, SYSTEM, timeout_sec=_timeout(ctx))


def get_host(ctx: VerbContext, *, host: str) -> dict:
    return transport.request(ctx, SYSTEM, "GET", "/hosts/{host}", {"host": host},
                             timeout_sec=_timeout(ctx))


def list_hosts(
    ctx: VerbContext,
    *,
    role: str | None = None,
    criticality: str | None = None,
    owner: str | None = None,
) -> dict | list:
    params = {k: v for k, v in
              (("role", role), ("criticality", criticality), ("owner", owner)) if v}
    return transport.request(ctx, SYSTEM, "GET", "/hosts", query=params or None,
                             timeout_sec=_timeout(ctx), answer="any")


def list_roles(ctx: VerbContext) -> dict | list:  # lint-dup: ok — distinct service
    return transport.request(ctx, SYSTEM, "GET", "/roles", timeout_sec=_timeout(ctx), answer="any")


VERBS = {
    "health-check": health_check,
    "get-host": get_host,
    "list-hosts": list_hosts,
    "list-roles": list_roles,
}
