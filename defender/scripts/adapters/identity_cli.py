"""Identity stub adapter — the `identity` VERBS registry.

Wraps the v2 playground identity stub (FastAPI over keycloak/realm.yaml ×
hosts/inventory.yaml). Load-bearing for legitimacy checks: "is dev.dana
authorized on db-1?" answers off `can-access`, not `/etc/passwd`.

Verbs (`VERBS` is the whole model-facing surface — there is no CLI):
    health-check
    can-access             user, host
    get-user               user
    list-authorized-hosts  user
    list-users             [role] [enabled]
    list-roles

Faults (`faults.py`): ConfigFault/TransportFault = infra (2), UpstreamFault = query
error (1, carrying the stub's own `detail`).
"""

from __future__ import annotations

# Put the workspace root on sys.path so `defender.*` namespace imports resolve when the
# verb registry loads this module BY PATH (see cmdb_cli.py).
import sys as _sys
from pathlib import Path as _Path

if (_root := str(_Path(__file__).resolve().parents[3])) not in _sys.path:
    _sys.path.insert(0, _root)

from defender.runtime.verbs import VerbContext
from defender.scripts.adapters import _stub_transport as transport

SYSTEM = "identity"
PREFIX = "IDENTITY"


def _config(ctx: VerbContext) -> dict[str, str]:
    return transport.load_config(ctx, SYSTEM, PREFIX)


def health_check(ctx: VerbContext) -> dict:
    return transport.health_check(ctx, _config(ctx), SYSTEM)


def can_access(ctx: VerbContext, *, user: str, host: str) -> dict:
    return transport.http_get_obj(
        ctx, _config(ctx), f"/users/{user}/can_access", params={"host": host},
    )


def get_user(ctx: VerbContext, *, user: str) -> dict:
    return transport.http_get_obj(ctx, _config(ctx), f"/users/{user}")


def list_authorized_hosts(ctx: VerbContext, *, user: str) -> dict | list:
    return transport.http_get(ctx, _config(ctx), f"/users/{user}/authorized_hosts")


def list_users(
    ctx: VerbContext, *, role: str | None = None, enabled: bool | None = None
) -> dict | list:
    params: dict[str, str] = {}
    if role:
        params["role"] = role
    if enabled is not None:
        params["enabled"] = "true" if enabled else "false"
    return transport.http_get(ctx, _config(ctx), "/users", params=params or None)


def list_roles(ctx: VerbContext) -> dict | list:
    return transport.http_get(ctx, _config(ctx), "/roles")


VERBS = {
    "health-check": health_check,
    "can-access": can_access,
    "get-user": get_user,
    "list-authorized-hosts": list_authorized_hosts,
    "list-users": list_users,
    "list-roles": list_roles,
}
