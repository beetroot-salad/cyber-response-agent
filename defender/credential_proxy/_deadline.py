"""One proxied request's deadline (#1163 r7 A21): the system's own timeout, capped by the
proxy's, plus a fixed allowance for the proxy's own calls. Every call the request makes gets what
is left, and no single wait on the network is longer than the system's timeout; with nothing left
the call is not made. A wait that began before the deadline may end after it, by at most that
timeout, which the caller allows for (`kit.access.caller_wait_sec`)."""
from __future__ import annotations

import math
import time
from dataclasses import dataclass

from defender.credential_proxy._refusal import TRANSPORT, Refused


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


__all__ = ["Deadline"]
