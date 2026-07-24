"""The shared ticket answer-key screen — one protocol, two consumers.

Gather (``runtime/query_tool.py``) and the benign judge
(``learning/pipeline/judge/closed_ticket_tool.py``) both read the ticket store, and both must
withhold the case they are themselves working on. The *protocol* is identical across the two:
the same envelope-shape checks, the same ``(payload, exit_code, detail)`` return contract, and
the same split between a policy withhold (a BUSINESS refusal, which never feeds the circuit
breaker) and a malformed envelope (an INFRA fault, which does). Only the *predicate* differs:

  - gather excludes its own case by RECORD IDENTITY and keeps every other lifecycle state —
    open and in-progress siblings are correlation evidence it is entitled to read;
  - the judge additionally keeps only genuinely-closed records, and on ``get`` withholds a
    payload that merely NAMES the case under judgment (Fork H) — for the judge, the case's own
    ticket is the answer key it is scoring against.

Holding the protocol here means an envelope change — a renamed ``tickets``/``key``, a different
malformed classification — is made ONCE, rather than in two places that must be kept in step.
The per-consumer predicate is injected by the caller.

This module is deliberately a LEAF: it imports nothing from ``query_tool`` or the judge, so
either side can depend on it without a cycle.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from defender.runtime.tools import AgentDeps

TICKET_SYSTEM = "ticket"
TICKET_GET = "get-ticket"
TICKET_LIST = "list-tickets"

#: A malformed store envelope is an INFRA fault: the store answered a shape it does not
#: document, which is a broken data source rather than a mistake the model can correct. It
#: carries the adapter infra code (2) — matching ``query_tool.DEFAULT_FAULT_EXIT`` and
#: ``ConfigFault``/``TransportFault`` — so it contributes to the ``ticket`` circuit breaker and
#: a persistently broken store trips it instead of being paid for on every call.
MALFORMED_EXIT = 2

#: A policy withhold is a BUSINESS refusal, never infra: the store answered correctly and this
#: boundary chose not to pass the answer on. Two properties are load-bearing, and both are
#: pinned by tests. It must stay OUTSIDE ``circuit_breaker.INFRA_EXIT_CODES``, so a run that
#: legitimately brushes its own case never trips the ticket breaker for the rest of the run.
#: And it is deliberately DISTINCT from the adapter's generic business code (1, carried by a
#: 404 or a non-closed refusal), so a reader of ``executed_queries`` can tell a withheld
#: self-read from a ticket that simply is not there — without parsing the free-text detail.
POLICY_REFUSAL_EXIT = 3

def self_case_key(deps: AgentDeps) -> str:
    """The key of the case this leg is working on — THE definition, shared by both consumers.

    The identity is ``deps.run_id``, carried explicitly on deps, and is deliberately NOT
    re-derived from ``run_dir.name``. The two coincide today only because ``AgentDeps._for_run``
    seeds ``run_id=run_dir.name``; pinning both screens to the deps field means a later
    decoupling of run-dir naming from the run id (the area #697/#698 already churned) cannot
    silently split gather's self-exclusion from the judge's.
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


def screen_list(
    payload: Any,
    *,
    keep: Callable[[dict[str, Any]], bool],
) -> tuple[Any, int, str]:
    """Screen a ticket listing per item → ``(payload, exit_code, detail)``.

    The store's list endpoint answers with a JSON OBJECT envelope — ``{"total", "tickets"}`` —
    never a bare array. ``transport.http_get`` is typed ``dict | list`` because it also serves
    endpoints that genuinely ARE arrays, and ``list_tickets`` calls it rather than
    ``http_get_obj`` to get query-string urlencoding, so the object shape is a CONTRACT this
    screen enforces rather than a guarantee the type system already supplies. Anything else is
    malformed: reading a bare array as the ticket list would invent a shape the store does not
    document, and inventing one on the answer-key path is the wrong trade.

    Every surviving item is a dict the caller's ``keep`` predicate admitted — a non-dict item is
    dropped as unreadable rather than passed through — and ``total`` is restated to what the
    envelope now actually carries, so the count can never advertise records the screen removed.
    Duplicates survive: this is a screen, not a dedup.
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
    "screen_get",
    "screen_list",
    "self_case_key",
]
