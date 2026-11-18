"""The post-step's store requests (#1487 Flow 2): the tick's store, answered over the job socket.

Registered for the post-step kind alone (P6: a learning job or an investigation is answered `not-for-kind`), each still
answered after the stop signal (the relay itself refuses new leases then). The helper binds every trusted value (P1):
the adapter is over the learning store at the helper's own database address (the worker's environment, which `_spawn`
passes it), bound to the claim's tenant, the author lane, an owner of the helper's and the thresholds and store settings
of that environment. The wire and the batch-reference registry are `learning_store.tick_port`'s; one `TickRelay` per
session, made at its first store request and closed with what the post-step opened."""
from __future__ import annotations

import os
from typing import Any

from ._container import STOP_GRACE
from ._session import Registry, Session


def _bound_adapter(session: Session, opened: Any) -> Any:
    """The adapter the helper answers with: `blocking` over its own database address, entered on `opened`."""
    from defender.learning.core.store_tick import AUTHOR_LANE, DSN_ENV, owner_name, store_knobs, thresholds
    from defender.learning_store import blocking
    from defender.learning_store.tick import StoreAdapter, StoreUnavailable

    dsn = os.environ.get(DSN_ENV)
    if not dsn:
        raise StoreUnavailable(f"the helper has no learning store address ({DSN_ENV} is not set)")
    limits, knobs = thresholds(), store_knobs()
    store = opened.enter_context(blocking(dsn, **knobs))
    return StoreAdapter(store, tenant=str(session.tenant_id), lane=AUTHOR_LANE,
                        owner=owner_name(f"post-step:{session.claim}"), thresholds=limits)


def _relay(session: Session) -> Any:
    from defender.learning.core.drains import AUTHOR_DRAIN_RECONCILES
    from defender.learning_store.tick_port import TickRelay

    from ._learning import post_step_state

    state = post_step_state(session)
    with session.lock:
        if state.relay is None:
            state.relay = TickRelay(lambda: _bound_adapter(session, state.opened), signalled=session.signalled.is_set,
                                    stop_window=STOP_GRACE, reconcile_lanes=AUTHOR_DRAIN_RECONCILES)
        return state.relay


def _store_handler(name: str) -> Any:
    def handler(session: Session, fields: dict[str, Any]) -> dict[str, Any]:
        return _relay(session).answer(name, fields)
    return handler


def register_store(registry: Registry) -> None:
    """Every request of the tick's store, for the post-step kind, answered after the signal too."""
    from defender.learning_store.tick_port import REQUESTS

    from ._learning import POST_STEP

    for name, fields in REQUESTS.items():
        registry.add(name, kinds=(POST_STEP,), handler=_store_handler(name), required=fields, after_signal=True)
