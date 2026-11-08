
from __future__ import annotations

import sys as _sys
from pathlib import Path as _Path

if (_root := str(_Path(__file__).resolve().parents[4])) not in _sys.path:
    _sys.path.insert(0, _root)

from typing import TYPE_CHECKING, Any

from defender.kit.verbs import VerbContext, verb
from defender import integrations
from defender.kit import faults

if TYPE_CHECKING:  # pragma: no cover — typing only
    from defender.kit.verbs import TenantRecord

SYSTEM = "example"
#: The prefix this system's `config.env` keys carry: the folder name, upper-cased
#: (`systems/example/config.env` holds `EXAMPLE_TIMEOUT_SEC=...`).
PREFIX = "EXAMPLE"
#: The keys every verb here reads (`_config`), and the only ones its `config.env` may hold: any
#: other key there is a settings fault naming it. The system's address is not one of them — it is
#: the `base` of `systems/example/access.yaml`, the declaration the credential proxy reaches the
#: system by.
REQUIRED_KEYS = ("TIMEOUT_SEC",)


def _config(ctx: VerbContext) -> dict[str, str]:
    """This system's settings, from the run's record (`ctx.tenant.systems`) — resolved once when
    the run began. Never the settings folder as it is now and never the process environment: an
    adapter reads its configuration from the record, so an exported variable changes nothing a
    run addresses.
    `load_config` strips the prefix, adds `URL_BASE` (the access declaration's base) and raises
    `ConfigFault` for a system with no config or no declaration, a missing or blank required key,
    or a key it does not read — which `check_settings` below raises first, at run start."""
    return integrations.load_config(ctx, SYSTEM, PREFIX, REQUIRED_KEYS)


def check_settings(tenant: TenantRecord) -> None:
    """This system's settings check, which EVERY adapter declares (#1256): a pure function of
    the run's tenant record that raises `ConfigFault` naming what is wrong — covering every
    `ConfigFault` any verb here can raise — or returns None when the system is usable. The run
    calls it once at start; a system whose check raises is down for the whole run (the agent is
    told why, and no verb of it is called). An adapter declaring none, or whose check raises
    anything else, is down as broken. A system needing no settings still declares one that never
    raises. This system's verbs fault only in `_config`, so the check is `_config`'s, over the
    record."""
    integrations.record_config(tenant, SYSTEM, PREFIX, REQUIRED_KEYS)


def _request(ctx: VerbContext, path: str, params: dict[str, str] | None = None) -> Any:
    """GET `path` from this system, through the credential proxy: the only way an adapter reaches
    its system. The proxy holds the credential, refuses any URL outside the declaration, and
    answers; `http_get` raises `TransportFault` for an unreachable system or a 5xx and
    `UpstreamFault` (the system's own detail) for a 4xx."""
    return integrations.http_get(ctx, _config(ctx), path, system=SYSTEM, params=params)


def health_check(ctx: VerbContext) -> dict:
    _request(ctx, "/health")
    return {"system": SYSTEM, "status": "connected"}


@verb(engine="lucene", body_param="native_query")
def query(ctx: VerbContext, *, native_query: str, limit: int = 100) -> dict | list:
    return _request(ctx, "/events", {"q": native_query, "limit": str(limit)})


def get_record(ctx: VerbContext, *, id: str) -> dict:
    got = _request(ctx, f"/records/{id}")
    if not isinstance(got, dict):  # parse the answer to the API's own contract
        raise faults.UpstreamFault(f"{SYSTEM}: record {id} answered {type(got).__name__}, not an object")
    return got


VERBS = {
    "health-check": health_check,
    "query": query,
    "get-record": get_record,
}
