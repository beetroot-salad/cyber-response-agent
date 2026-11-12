
from __future__ import annotations

import sys as _sys
from pathlib import Path as _Path

if (_root := str(_Path(__file__).resolve().parents[4])) not in _sys.path:
    _sys.path.insert(0, _root)

from typing import TYPE_CHECKING, Any

from defender.kit.verbs import VerbContext, verb
from defender.kit import faults, transport

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
REQUIRED_CONFIG_KEYS = ("TIMEOUT_SEC",)
#: The keys whose values the adapter puts in a request path (each must be one segment): none here.
PATH_KEYS: tuple[str, ...] = ()
#: How the operator's catalog listing names the system (#1366 O2).
DISPLAY_NAME = "Example system"
#: True only for a lab stub; an adapter connect writes for a real system says False (#1366 O2).
EXAMPLE = False
#: The most events one `query` may ask for.
MAX_LIMIT = 1000


def _config(ctx: VerbContext) -> dict[str, str]:
    """This system's settings, from the run's record (`ctx.tenant.systems`) — resolved once when
    the run began. Never the settings folder as it is now and never the process environment: an
    adapter reads its configuration from the record, so an exported variable changes nothing a
    run addresses.
    `load_config` strips the prefix and raises `ConfigFault` for a system with no config or no
    declaration, a missing, blank or still-`CHANGE-ME` required key, or a key it does not read —
    which `check_settings` below raises first, at run start."""
    return transport.load_config(ctx, SYSTEM, PREFIX, REQUIRED_CONFIG_KEYS)


def check_settings(tenant: TenantRecord) -> None:
    """This system's settings check, which EVERY adapter declares (#1256): a pure function of
    the run's tenant record that raises `ConfigFault` naming what is wrong — covering every
    `ConfigFault` any verb here can raise — or returns None when the system is usable. The run
    calls it once at start; a system whose check raises is down for the whole run (the agent is
    told why, and no verb of it is called). An adapter declaring none, or whose check raises
    anything else, is down as broken. A system needing no settings still declares one that never
    raises. This system's verbs fault only in `_config`, so the check is `_config`'s, over the
    record."""
    transport.record_config(tenant, SYSTEM, PREFIX, REQUIRED_CONFIG_KEYS)


def _get(ctx: VerbContext, template: str, values: dict[str, str] | None = None, *,
         query: dict[str, str] | None = None, answer: transport.Answer = "object") -> Any:
    """GET `template` from this system, through the credential proxy: the only way an adapter
    reaches its system. Never build a URL: name the path as a template (`"/records/{id}"`) and
    hand the values. Each value must be exactly one path segment, or the call is refused before
    it is sent (`ConfinementFault`); a value that may hold a `/` goes in `query`. The base is the
    access declaration's. The proxy holds the credential and answers; the transport raises
    `TransportFault` for an unreachable system, a 5xx or an answer of the wrong shape (`answer`),
    and `UpstreamFault` (the system's own detail) for a 4xx."""
    return transport.request(ctx, SYSTEM, "GET", template, values, query=query,
                             timeout_sec=transport.timeout_of(_config(ctx)), answer=answer)


def health_check(ctx: VerbContext) -> dict:
    _get(ctx, "/health")
    return {"system": SYSTEM, "status": "connected"}


@verb(engine="lucene", body_param="native_query")
def query(ctx: VerbContext, *, native_query: str, limit: int = 100) -> dict | list:
    if not 1 <= limit <= MAX_LIMIT:  # the agent's to fix: an `UpstreamFault`, exit 1
        raise faults.UpstreamFault(f"limit must be between 1 and {MAX_LIMIT}, got {limit}")
    return _get(ctx, "/events", query={"q": native_query, "limit": str(limit)}, answer="any")


def get_record(ctx: VerbContext, *, id: str) -> dict:
    return _get(ctx, "/records/{id}", {"id": id})


VERBS = {
    "health-check": health_check,
    "query": query,
    "get-record": get_record,
}
