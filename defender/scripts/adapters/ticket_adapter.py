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

#: The shared transport template PLUS the store's KEY GRAMMAR. The grammar is an ENVIRONMENT
#: fact — what a ticket key looks like in the deployed store — so it is declared in
#: the tenant's `settings/systems/ticket/config.env` (`TICKET_KEY_PATTERN`), not hardcoded in
#: a consumer, and it is REQUIRED: absent means the system is down (`ConfigFault`, exit 2),
#: never a built-in default screening keys against a grammar this environment never agreed to.
REQUIRED_CONFIG_KEYS = (*transport.REQUIRED_CONFIG_KEYS_TEMPLATE, "KEY_PATTERN")


# Same name in each stub adapter, closing over that module's SYSTEM/PREFIX: a zero-argument
# alias over `transport.load_config`, not a copy of its logic.
def _config(ctx: VerbContext) -> dict[str, str]:  # lint-dup: ok — per-module alias over the shared transport.load_config
    return transport.load_config(ctx, SYSTEM, PREFIX, REQUIRED_CONFIG_KEYS)


def key_pattern(ctx: VerbContext) -> str:
    """This environment's ticket-key grammar, as an unanchored regex source string.

    A verb rather than an import so every consumer reaches it through the ONE registry seam
    (`verbs=`), and so a screen built on it can be driven with a fake registry instead of a
    real config file. Consumers anchor it themselves — the config declares the key SHAPE, not
    where the match starts and ends.

    The screen that uses it lives at the consumer (the benign judge's `get_closed_ticket`)
    rather than here, because that screen owes a RETRY-class response with zero store
    attempts, and a fault raised from this module is by contract an exit-code envelope.
    """
    return _config(ctx)["KEY_PATTERN"]


def case_opened_at(ctx: VerbContext, *, key: str) -> str:
    """When the case `key` was opened, as the store's own `created` timestamp — NEVER the
    record.

    This is the one verb that reaches a ticket without `require_closed`, because the case
    under judgment is by definition still in flight. The answer-key defense is the RETURN
    TYPE, not a status filter: a `str` cannot carry a summary, a resolution, or a comment, so
    no caller — however wired — can read the in-flight ticket through it. The record is a
    local here, discarded unreturned.

    It lets the judge date its recency screen against the ticket store's OWN clock, so the
    boundary does not depend on skew between two machines.

    A 404 is an `UpstreamFault` (exit 1) like any other missing ticket: the case was never
    filed, which is a real answer. A ticket carrying no string `created` is malformed and
    fails as INFRA — the recency screen must never quietly stand down on a missing field.
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

    `require_closed` is the structural closed-only guard for the offline benign judge's
    scoped list: it pins status=closed regardless of any `status` value, so a stray or
    duplicate `--status open` (argparse keeps the last) cannot widen the read to the
    in-flight OPEN ticket.

    It is `wrapper_only`: the judge's closed-ticket tool hard-codes it and keeps it off its
    model-facing schema, so NO model in either role binds it. Gather shares this verb and must
    not — the pin only narrows, and a lead that set it would silently drop the open and
    in-progress siblings it is dispatched to correlate.
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

    `require_closed` confirms a *cited* closed case, never the in-flight (open) ticket for the
    alert under judgment. Refusing HERE means the read scope can't reach the in-flight ticket
    even by key — a query error (exit 1), the same code the CLI callers pin.

    The key is PERCENT-ENCODED into the path, matching how `ticket_writer` encodes the keys it
    mints. Raw interpolation is wrong in both directions: a legitimately-minted key needing
    encoding round-trips to a different URL, and a key carrying `?`/`#`/CR-LF reshapes the
    REQUEST — a query string, a fragment, or a header break where a path segment was meant.
    Not a shell surface (the transport passes the URL as one argv element, no `shell=True`);
    this is HTTP semantics.
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
