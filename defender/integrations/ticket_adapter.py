"""Ticket-server stub adapter — the `ticket` VERBS registry.

Wraps the v2 ticket-server (the v1 FastAPI app reused under playground-v2's compose),
read-only. The adapter is a verbs registry only: the query tool dispatches `list-tickets`,
`get-ticket` and `key-pattern` through the verb registry, with the run's tenant record on its
`VerbContext` (#1107). It has no command-line mode (D7): nothing in the tree ran it as a program,
and a CLI had to find its own settings, which no code outside a process entry point may do.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING

# Workspace root on sys.path so `defender.*` namespace imports resolve when the verb registry
# loads this module BY PATH.
import sys as _sys
from pathlib import Path as _Path

if (_root := str(_Path(__file__).resolve().parents[2])) not in _sys.path:
    _sys.path.insert(0, _root)

from defender.kit.verbs import CaseComments, VerbContext, verb
from defender.kit import transport
from defender.kit.faults import TransportFault, UpstreamFault

if TYPE_CHECKING:  # pragma: no cover — typing only
    from defender.kit.verbs import TenantRecord

SYSTEM = "ticket"
PREFIX = "TICKET"
DISPLAY_NAME = "Ticket store (lab)"
#: A lab stub (#1366 O2): an example adapter, not a real system's.
EXAMPLE = True

#: The transport template plus the store's key grammar (`TICKET_KEY_PATTERN`). The grammar is
#: an environment fact, so it lives in the tenant config and is required: absent means the
#: system is down (`ConfigFault`), never a built-in default.
REQUIRED_CONFIG_KEYS = (*transport.REQUIRED_CONFIG_KEYS_TEMPLATE, "KEY_PATTERN")
#: No setting goes in a request path.
PATH_KEYS: tuple[str, ...] = ()
#: The route `add_case_comment` sends (#1366 C1): a comment on the ticket, whatever the settings.
COMMENT_ROUTE = ("POST", "/tickets/*/comments")


# A per-module zero-argument alias over `transport.load_config`.
def _config(ctx: VerbContext) -> dict[str, str]:  # lint-dup: ok — per-module alias over the shared transport.load_config
    return transport.load_config(ctx, SYSTEM, PREFIX, REQUIRED_CONFIG_KEYS)


def _timeout(ctx: VerbContext) -> int:  # lint-dup: ok — per-module alias over the shared transport.timeout_of
    return transport.timeout_of(_config(ctx))


def comment_route(settings: Mapping[str, str]) -> tuple[str, str]:  # lint-dup: ok — every case-recording adapter declares its comment route under this one name (#1366 C1)
    """The route `add_case_comment` sends (#1366 C1): the same for every record."""
    return COMMENT_ROUTE


def check_settings(tenant: TenantRecord) -> None:  # lint-dup: ok — every adapter declares its own settings check (#1256 O-5)
    """This system's settings check (#1256 O-5): every `ConfigFault` a verb here can raise —
    `_config`'s keys and the access declaration — raised over the run's record, or None when
    the system is usable."""
    transport.check_settings_of(tenant, SYSTEM, PREFIX, REQUIRED_CONFIG_KEYS)


def key_pattern(ctx: VerbContext) -> str:
    """This environment's ticket-key grammar, as an unanchored regex source string.

    A verb rather than an import so consumers reach it through the registry seam (and tests
    can fake it). Consumers anchor it themselves. The screen using it lives at the consumer
    (the benign judge's `get_closed_ticket`), which owes a retry-class response with no store
    attempt, whereas a fault raised here is an exit-code envelope.
    """
    return _config(ctx)["KEY_PATTERN"]


def _fetch_ticket(ctx: VerbContext, key: str) -> dict:
    """Ticket `key` as the store answers it: the one read of a ticket. The key is a case key
    (#1359 P3), escaped into its segment and refused only for what could split one, so every
    read and the comment action reach the same ticket for the same key."""
    return transport.request(ctx, SYSTEM, "GET", "/tickets/{key}", {"key": transport.CaseKey(key)},
                             timeout_sec=_timeout(ctx))


def case_opened_at(ctx: VerbContext, *, key: str) -> str:
    """When the case `key` was opened, as the store's own `created` timestamp — never the
    record.

    The one verb that reads a ticket without `require_closed`, since the case under judgment is
    still open. The return type is the defense: a `str` cannot carry a summary, resolution or
    comment. Dating against the store's own clock avoids cross-machine skew.

    A 404 is an `UpstreamFault` (exit 1): the case was never filed. A ticket without a string
    `created` fails as infra, so the recency screen never silently stands down.
    """
    payload = _fetch_ticket(ctx, key)
    created = payload.get("created")
    if not isinstance(created, str) or not created:
        raise TransportFault(
            f"ticket {key} carries no string 'created' timestamp "
            f"(got {type(created).__name__}) — the case-opened boundary is unreadable"
        )
    return created


def health_check(ctx: VerbContext) -> dict:
    return transport.health_check(ctx, SYSTEM, timeout_sec=_timeout(ctx))


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
    return transport.request(ctx, SYSTEM, "GET", "/tickets", query=params or None,
                             timeout_sec=_timeout(ctx), answer="any")


@verb(wrapper_only=("require_closed",))
def get_ticket(ctx: VerbContext, *, key: str, require_closed: bool = False) -> dict:
    """One ticket by key, incl. comments.

    `require_closed` confirms a cited closed case; refusing here (exit 1) means the scoped read
    cannot reach the in-flight ticket even by key.

    The key is escaped into one path segment, and one holding `/`, `\\`, `;`, whitespace or a
    control character is refused unsent, so no key can reshape the request.
    """
    payload = _fetch_ticket(ctx, key)
    if require_closed and payload.get("status") != "closed":
        raise UpstreamFault(
            f"{key} is status={payload.get('status')!r}, not 'closed' (--require-closed)"
        )
    return payload


#: The author the playground's stub store attributes the host's comment to (a real store's author
#: is the credential's user, so the product's case-record file carries none).
COMMENT_AUTHOR = "defender"


def _ticket_link(ctx: VerbContext, key: str) -> str:
    return transport.link(ctx.tenant, SYSTEM, "/tickets/{key}", {"key": transport.CaseKey(key)})


def add_case_comment(ctx: VerbContext, *, key: str, body: str) -> str | None:  # lint-dup: ok — every case-recording adapter exports the host's comment action under this one name (#1359)
    """The host's one write to a case (#1359): add the plain-text `body` as a comment on ticket
    `key`, and return the ticket's web link. Not a verb (never in `VERBS`): no role or query tool
    can reach it. The key is one path segment, so it cannot reshape the request. Faults are the
    shared classes: a 4xx is an `UpstreamFault` carrying the status."""
    transport.comment_write(ctx, SYSTEM, comment_route(transport.record_entry(ctx.tenant, SYSTEM)), key=key,
                            body={"author": COMMENT_AUTHOR, "body": body}, timeout_sec=_timeout(ctx))
    return _ticket_link(ctx, key)


def read_case_comments(ctx: VerbContext, *, key: str) -> CaseComments:  # lint-dup: ok — every case-recording adapter's read goes by this one name (#1374)
    """The case's comments, for the host's read-back after a comment whose answer was lost. Not a
    verb (never in `VERBS`). A comment it cannot read is left out. A read with no comment list is
    a `TransportFault`."""
    ticket = _fetch_ticket(ctx, key)
    comments = ticket.get("comments")
    if not isinstance(comments, list):
        raise TransportFault(f"ticket {key}'s read carries no comment list")
    texts = tuple(c["body"] for c in comments if isinstance(c, dict) and isinstance(c.get("body"), str))
    return CaseComments(texts=texts, link=_ticket_link(ctx, key))


VERBS = {
    "health-check": health_check,
    "list-tickets": list_tickets,
    "get-ticket": get_ticket,
    "key-pattern": key_pattern,
    "case-opened-at": case_opened_at,
}
