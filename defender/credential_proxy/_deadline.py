"""One proxied request's deadline (#1163 r7 A21): the system's own timeout, capped by the
proxy's, plus a fixed allowance for the proxy's own calls. Every call the request makes gets what
is left; with nothing left the call is not made."""
from __future__ import annotations

import time
from dataclasses import dataclass

from defender.credential_proxy._refusal import TRANSPORT, Refused


@dataclass(frozen=True)
class Deadline:
    """When the request must be answered by, on the monotonic clock."""

    at: float

    @classmethod
    def after(cls, seconds: float) -> Deadline:
        return cls(time.monotonic() + seconds)

    def left(self, what: str) -> float:
        """The seconds left for `what`; `Refused` (`TransportFault`) when none are."""
        left = self.at - time.monotonic()
        if left <= 0:
            raise Refused(TRANSPORT, f"the request ran out of time before {what}")
        return left


__all__ = ["Deadline"]
