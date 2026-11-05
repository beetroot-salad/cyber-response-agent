"""One proxied request's deadline (#1163 r7 A21, #1364 O1): the system's own timeout, capped by
the proxy's, plus a fixed allowance for the proxy's own calls. Every network leg the request
makes runs under it as one whole (`Deadline.run`): a leg still going when the deadline passes is
cut, so the proxy answers by its deadline whatever an upstream or OpenBao does, and the caller
waits at most that deadline plus a grace (`kit.access.caller_wait_sec`) for each stretch of the
reply, not for all of it (#1412). No single wait is longer
than the system's timeout either (`per_wait`)."""
from __future__ import annotations

import contextlib
import contextvars
import math
import time
from collections.abc import Awaitable, Callable, Iterator
from dataclasses import dataclass
from typing import TypeVar

import anyio
import anyio.from_thread

from defender.credential_proxy._refusal import TRANSPORT, Refused

_T = TypeVar("_T")


@dataclass(frozen=True)
class Deadline:
    """When the request must be answered by, on the monotonic clock, and the longest one wait on
    the network may be (`per_wait`)."""

    at: float
    per_wait: float = math.inf

    @classmethod
    def after(cls, seconds: float) -> Deadline:
        return cls(time.monotonic() + seconds)

    def left(self, what: str) -> float:
        """The seconds left for `what`; `Refused` (`TransportFault`) when none are."""
        left = self.at - time.monotonic()
        if left <= 0:
            raise Refused(TRANSPORT, f"the request ran out of time before {what}")
        return left

    def wait(self, what: str) -> float:
        """The timeout for one network call of `what`: what is left, at most `per_wait`."""
        return min(self.per_wait, self.left(what))

    def run(self, what: str, leg: Callable[[], Awaitable[_T]], *, system_side: bool = False) -> _T:
        """`leg()` run on the event loop from this worker thread, cut when the deadline passes
        (`Refused`, `TransportFault`; `system_side` when `leg` is the target system's own call,
        #1404: only the cut is, not a deadline spent before the leg began). Called only from a
        thread anyio started (the proxy's requests run on one)."""
        left = self.left(what)

        async def bounded() -> _T:
            with anyio.fail_after(left):
                return await leg()

        try:
            return anyio.from_thread.run(bounded)
        except TimeoutError:
            raise Refused(TRANSPORT, f"the request ran out of time during {what}",
                          system_side=system_side) from None


_CURRENT: contextvars.ContextVar[Deadline | None] = contextvars.ContextVar(
    "credential_proxy_deadline", default=None)


def current() -> Deadline | None:
    """The deadline of the request this thread is answering, if any: how the proxy's OpenBao
    calls, made through ports that take no deadline, come under it."""
    return _CURRENT.get()


@contextlib.contextmanager
def answering(deadline: Deadline) -> Iterator[None]:
    """Make `deadline` the current one while the request is answered."""
    token = _CURRENT.set(deadline)
    try:
        yield
    finally:
        _CURRENT.reset(token)


__all__ = ["Deadline", "answering", "current"]
