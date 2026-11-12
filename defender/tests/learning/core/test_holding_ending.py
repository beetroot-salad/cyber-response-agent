"""#1476 review (second round), finding 3: a holder that ends its own lease is not stopped by its renewer.

The renewer renews the batch's lease every `renew_every` seconds and turns a lost lease into a stop (SIGTERM to the
main thread). A store verb that ends the lease (in review, ended, abandoned, a person's, expired for a takeover) makes
the next renewal fail as a lost lease, so a renewal between that verb and the holding's exit would stop a holder that
finished. `Holding.ending` halts the renewer before the verb."""
from __future__ import annotations

import signal
import threading
import time
from types import SimpleNamespace

import pytest

from defender.learning.core.store_tick import Holding, TickStopped
from defender.learning.store import LeaseLost

RENEW_EVERY = 0.05


class _Lease:
    """A store whose lease is live until `end` is called; a renewal after that is a lost lease, as `_guard` makes it."""

    renew_every = RENEW_EVERY

    def __init__(self) -> None:
        self.ended = threading.Event()
        self.renewals_after_end = 0

    def renew(self, _held: object) -> None:
        if self.ended.is_set():
            self.renewals_after_end += 1
            raise LeaseLost("the batch is no longer working")

    def end(self, _held: object) -> str:
        self.ended.set()
        return "ended"


HELD = SimpleNamespace(batch_id="b-1", tenant_id="t-1")


def test_a_verb_made_through_ending_is_not_followed_by_a_lost_lease_stop():
    """The holder ends its lease and lingers past several renewal intervals: no stop, no renewal after the end."""
    store = _Lease()
    with Holding(store, HELD) as hold:
        assert hold.ending(store.end, HELD) == "ended"
        time.sleep(RENEW_EVERY * 6)
    assert store.renewals_after_end == 0
    assert hold.why is None


def test_control_a_verb_made_around_the_renewer_is_followed_by_a_lost_lease_stop():
    """The case `ending` exists for: the same verb called directly, with the renewer still running, stops the
    holder as a lost lease."""
    store = _Lease()
    previous = signal.getsignal(signal.SIGTERM)

    def end_around_the_renewer() -> None:
        with Holding(store, HELD):
            store.end(HELD)
            time.sleep(RENEW_EVERY * 6)

    try:
        with pytest.raises(TickStopped) as stopped:
            end_around_the_renewer()
    finally:
        signal.signal(signal.SIGTERM, previous)  # a fired stop leaves SIGTERM ignored, as a tick's process would
    assert stopped.value.why == "lease"
