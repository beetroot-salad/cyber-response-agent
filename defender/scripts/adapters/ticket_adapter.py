"""Ticket-server stub adapter — the `ticket` VERBS registry.

Wraps the v2 ticket-server (the v1 FastAPI app reused under playground-v2's compose),
read-only. The adapter is a verbs registry only: the query tool dispatches `list-tickets`,
`get-ticket` and `key-pattern` through the verb registry, with the run's tenant record on its
`VerbContext` (#1107). It has no command-line mode (D7): nothing in the tree ran it as a program,
and a CLI had to find its own settings, which no code outside a process entry point may do.
"""

from __future__ import annotations

import urllib.parse

# Workspace root on sys.path so `defender.*` namespace imports resolve when the verb registry
# loads this module BY PATH.
import sys as _sys
from pathlib import Path as _Path

if (_root := str(_Path(__file__).resolve().parents[3])) not in _sys.path:
    _sys.path.insert(0, _root)

from defender.runtime.verbs import VerbContext, verb
from defender.scripts.adapters import _stub_transport as transport
from defender.scripts.adapters.faults import TransportFault, UpstreamFault

SYSTEM = "ticket"
PREFIX = "TICKET"

#: The transport template plus the store's key grammar (`TICKET_KEY_PATTERN`). The grammar is
#: an environment fact, so it lives in the tenant config and is required: absent means the
#: system is down (`ConfigFault`), never a built-in default.
REQUIRED_CONFIG_KEYS = (*transport.REQUIRED_CONFIG_KEYS_TEMPLATE, "KEY_PATTERN")


# A per-module zero-argument alias over `transport.load_config`.
def _config(ctx: VerbContext) -> dict[str, str]:  # lint-dup: ok — per-module alias over the shared transport.load_config
    return transport.load_config(ctx, SYSTEM, PREFIX, REQUIRED_CONFIG_KEYS)


def key_pattern(ctx: VerbContext) -> str:
    """This environment's ticket-key grammar, as an unanchored regex source string.

    A verb rather than an import so consumers reach it through the registry seam (and tests
    can fake it). Consumers anchor it themselves. The screen using it lives at the consumer
    (the benign judge's `get_closed_ticket`), which owes a retry-class response with no store
    attempt, whereas a fault raised here is an exit-code envelope.
    """
    return _config(ctx)["KEY_PATTERN"]


def case_opened_at(ctx: VerbContext, *, key: str) -> str:
    """When the case `key` was opened, as the store's own `created` timestamp — never the
    record.

    The one verb that reads a ticket without `require_closed`, since the case under judgment is
    still open. The return type is the defense: a `str` cannot carry a summary, resolution or
    comment. Dating against the store's own clock avoids cross-machine skew.

    A 404 is an `UpstreamFault` (exit 1): the case was never filed. A ticket without a string
    `created` fails as infra, so the recency screen never silently stands down.
    """
    payload = transport.http_get_obj(
        ctx, _config(ctx), f"/tickets/{urllib.parse.quote(key, safe='')}", system=SYSTEM,
    )
    created = payload.get("created")
    if not isinstance(created, str) or not created:
        raise TransportFault(
            f"ticket {key} carries no string 'created' timestamp "
            f"(got {type(created).__name__}) — the case-opened boundary is unreadable"
        )
    return created


def health_check(ctx: VerbContext) -> dict:
    return transport.health_check(ctx, _config(ctx), SYSTEM)


@verb(wrapper_only=("require_closed",))
def list_tickets(
    ctx: VerbContext,
    *,
    status: str | None = None,
    label: str | None = None,
    q: str | None = None,
    require_closed: bool = False,
) -> dict | list:
    """Tickets, filterable.

    `require_closed` pins status=closed regardless of `status`, so a duplicate `--status open`
    cannot widen the offline benign judge's scoped list to the in-flight ticket. It is
    `wrapper_only`: the judge's tool hard-codes it off the model-facing schema. Gather must not
    set it, or it would drop the open siblings it is meant to correlate.
    """
    params: dict[str, str] = {}
    if status:
        params["status"] = status
    if require_closed:
        params["status"] = "closed"
    if label:
        params["label"] = label
    if q:
        params["q"] = q
    return transport.http_get(ctx, _config(ctx), "/tickets", system=SYSTEM, params=params or None)


@verb(wrapper_only=("require_closed",))
def get_ticket(ctx: VerbContext, *, key: str, require_closed: bool = False) -> dict:
    """One ticket by key, incl. comments.

    `require_closed` confirms a cited closed case; refusing here (exit 1) means the scoped read
    cannot reach the in-flight ticket even by key.

    The key is percent-encoded into the path, matching `ticket_writer`. Raw interpolation
    would send minted keys to the wrong URL, and a key with `?`/`#`/CR-LF would reshape the
    HTTP request.
    """
    payload = transport.http_get_obj(
        ctx, _config(ctx), f"/tickets/{urllib.parse.quote(key, safe='')}", system=SYSTEM,
    )
    if require_closed and payload.get("status") != "closed":
        raise UpstreamFault(
            f"{key} is status={payload.get('status')!r}, not 'closed' (--require-closed)"
        )
    return payload


VERBS = {
    "health-check": health_check,
    "list-tickets": list_tickets,
    "get-ticket": get_ticket,
    "key-pattern": key_pattern,
    "case-opened-at": case_opened_at,
}
