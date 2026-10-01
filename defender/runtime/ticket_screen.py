"""The ticket answer-key screen: withholding the case a reader is itself working on.

This holds the protocol: envelope-shape checks, the ``(payload, exit_code, detail)`` contract,
and the split between a policy withhold (a business refusal, which never feeds the circuit
breaker) and a malformed envelope (an infra fault, which does). The per-consumer predicate is
injected by the caller. Gather (``runtime/query_tool.py``) excludes its own case by record
identity and keeps every other lifecycle state: open and in-progress siblings are correlation
evidence, so it must not grow a recency filter.

A leaf module (imports nothing from its consumers), so any consumer can depend on it.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from defender.runtime.tools import AgentDeps

TICKET_SYSTEM = "ticket"
TICKET_GET = "get-ticket"
TICKET_LIST = "list-tickets"

#: A malformed store envelope is an infra fault (a broken data source, not a model mistake).
#: It uses the adapter infra code, like ``query_tool.DEFAULT_FAULT_EXIT``, so a persistently
#: broken store trips the ``ticket`` circuit breaker.
MALFORMED_EXIT = 2

#: A policy withhold is a business refusal: the store answered and this boundary withheld it.
#: Must stay outside ``circuit_breaker.INFRA_EXIT_CODES`` (brushing one's own case must not trip
#: the breaker), and distinct from the generic business code 1 (e.g. a 404), so
#: ``executed_queries`` readers can tell a withheld self-read from a missing ticket.
POLICY_REFUSAL_EXIT = 3

def self_case_key(deps: AgentDeps) -> str:
    """The key of the case this leg is working on, shared by every consumer.

    ``deps.run_id``, not ``run_dir.name``: they coincide today only because
    ``AgentDeps._for_run`` seeds one from the other.
    """
    return deps.run_id


def screen_get(
    payload: Any,
    *,
    withhold: Callable[[dict[str, Any]], str | None],
    require_key: bool = False,
) -> tuple[Any, int, str]:
    """Screen one fetched ticket → ``(payload, exit_code, detail)``.

    A non-object body — or, under ``require_key``, one carrying no string ``key`` — is a
    malformed envelope: such a record cannot be identity-screened at all, so it is withheld as
    an infra fault rather than passed through unscreened. ``withhold`` then decides the policy
    question, returning the model-facing detail to refuse with, or ``None`` to serve the ticket.
    """
    if not isinstance(payload, dict):
        return None, MALFORMED_EXIT, (
            "malformed ticket store response: expected a ticket object"
        )
    if require_key and not isinstance(payload.get("key"), str):
        return None, MALFORMED_EXIT, (
            "malformed ticket store response: expected a ticket object with a string key"
        )
    detail = withhold(payload)
    if detail is not None:
        return None, POLICY_REFUSAL_EXIT, detail
    return payload, 0, ""


def _screen_one_ticket(
    ticket: dict[str, Any], *, is_released: Callable[[Any], bool],
) -> dict[str, Any]:
    """An unreleased ticket serves no comments; a released one is served whole.

    Decided by lifecycle state only, never a comment's `author` (client-controlled, so it
    cannot tell an agent's note from a person's). Other fields are untouched and no marker is
    added. `comments` is emptied whatever its shape; a ticket without the key is unchanged.
    """
    if "comments" not in ticket or is_released(ticket):
        return ticket
    return {**ticket, "comments": []}


def screen_release_get(payload: Any, *, is_released: Callable[[Any], bool]) -> Any:
    """The release screen for `get-ticket`, applied after the own-case exclusion answered `0`.
    `payload` is a single ticket object."""
    if not isinstance(payload, dict):
        return payload
    return _screen_one_ticket(payload, is_released=is_released)


def screen_release_list(payload: Any, *, is_released: Callable[[Any], bool]) -> Any:
    """The release screen for `list-tickets`, applied after the own-case exclusion. Removes no
    tickets (unreleased records stay visible for correlation), so `total` is unchanged."""
    if not (isinstance(payload, dict) and isinstance(payload.get("tickets"), list)):
        return payload
    tickets = [
        _screen_one_ticket(t, is_released=is_released) if isinstance(t, dict) else t
        for t in payload["tickets"]
    ]
    return {**payload, "tickets": tickets}


def screen_list(
    payload: Any,
    *,
    keep: Callable[[dict[str, Any]], bool],
) -> tuple[Any, int, str]:
    """Screen a ticket listing per item → ``(payload, exit_code, detail)``.

    The envelope must be the documented ``{"total", "tickets"}`` object; anything else (e.g. a
    bare array, which the transport's ``dict | list`` type allows) is malformed.

    Non-dict items are dropped, ``keep`` decides the rest, and ``total`` is restated so it
    never counts removed records. Duplicates survive.
    """
    if not (isinstance(payload, dict) and isinstance(payload.get("tickets"), list)):
        return None, MALFORMED_EXIT, (
            "malformed ticket store response: 'tickets' is not a list"
        )
    kept = [t for t in payload["tickets"] if isinstance(t, dict) and keep(t)]
    return {**payload, "tickets": kept, "total": len(kept)}, 0, ""


__all__ = [
    "MALFORMED_EXIT",
    "POLICY_REFUSAL_EXIT",
    "TICKET_GET",
    "TICKET_LIST",
    "TICKET_SYSTEM",
    "screen_release_get",
    "screen_release_list",
    "screen_get",
    "screen_list",
    "self_case_key",
]
