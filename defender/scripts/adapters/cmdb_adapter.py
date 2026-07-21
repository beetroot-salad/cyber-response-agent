
from __future__ import annotations

import sys as _sys
from pathlib import Path as _Path

if (_root := str(_Path(__file__).resolve().parents[3])) not in _sys.path:
    _sys.path.insert(0, _root)

from defender.runtime.verbs import VerbContext
from defender.scripts.adapters import _stub_transport as transport

SYSTEM = "cmdb"
PREFIX = "CMDB"


def _config(ctx: VerbContext) -> dict[str, str]:  # lint-dup: ok — per-module alias over the shared transport.load_config
    return transport.load_config(ctx, SYSTEM, PREFIX)


def health_check(ctx: VerbContext) -> dict:
    return transport.health_check(ctx, _config(ctx), SYSTEM)


def get_host(ctx: VerbContext, *, host: str) -> dict:
    return transport.http_get_obj(ctx, _config(ctx), f"/hosts/{host}")


def list_hosts(
    ctx: VerbContext,
    *,
    role: str | None = None,
    criticality: str | None = None,
    owner: str | None = None,
) -> dict | list:
    params = {k: v for k, v in
              (("role", role), ("criticality", criticality), ("owner", owner)) if v}
    return transport.http_get(ctx, _config(ctx), "/hosts", params=params or None)


def list_roles(ctx: VerbContext) -> dict | list:  # lint-dup: ok — distinct service
    return transport.http_get(ctx, _config(ctx), "/roles")


VERBS = {
    "health-check": health_check,
    "get-host": get_host,
    "list-hosts": list_hosts,
    "list-roles": list_roles,
}
