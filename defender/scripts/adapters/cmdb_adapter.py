"""CMDB stub adapter — the `cmdb` VERBS registry.

Wraps the v2 playground CMDB stub (FastAPI over hosts/inventory.yaml).
Reads the merged BASE + OVERLAY view — overlay endpoints are chaos-mode
scaffolding and are not exposed by this adapter.

Verbs (`VERBS` is the whole model-facing surface — there is no CLI):
    health-check
    get-host      host
    list-hosts    [role] [criticality] [owner]
    list-roles

Faults (`faults.py`): ConfigFault/TransportFault = infra (2), UpstreamFault = query
error (1, carrying the stub's own `detail`).
"""

from __future__ import annotations

# Put the workspace root on sys.path so `defender.*` namespace imports resolve when the
# verb registry loads this module BY PATH (importlib.spec_from_file_location), not as a
# package member — the registry keys on the path precisely so two trees' modules stay two
# module objects.
import sys as _sys
from pathlib import Path as _Path

if (_root := str(_Path(__file__).resolve().parents[3])) not in _sys.path:
    _sys.path.insert(0, _root)

from defender.runtime.verbs import VerbContext
from defender.scripts.adapters import _stub_transport as transport

SYSTEM = "cmdb"
PREFIX = "CMDB"


# Same name in each stub adapter, closing over that module's SYSTEM/PREFIX: the shared
# body already lives once in `transport.load_config`, so this is a zero-argument alias,
# not a copy of any logic.
def _config(ctx: VerbContext) -> dict[str, str]:  # lint-dup: ok — per-module alias over the shared transport.load_config
    return transport.load_config(ctx, SYSTEM, PREFIX)


def health_check(ctx: VerbContext) -> dict:
    return transport.health_check(ctx, _config(ctx), SYSTEM)


def get_host(ctx: VerbContext, *, host: str) -> dict:
    """The effective record for one host. The param is `host` (not the CLI's old
    positional `name`): the query-template corpus binds `${host}`, and a placeholder that
    does not match a declared param is a template the model cannot fill."""
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


# Same spelling as identity's `list_roles`, different service: each resolves its own
# URL_BASE from its own config, so merging them would be a behavior change.
def list_roles(ctx: VerbContext) -> dict | list:  # lint-dup: ok — distinct service
    return transport.http_get(ctx, _config(ctx), "/roles")


VERBS = {
    "health-check": health_check,
    "get-host": get_host,
    "list-hosts": list_hosts,
    "list-roles": list_roles,
}
