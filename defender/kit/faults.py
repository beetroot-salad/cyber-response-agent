
from __future__ import annotations

USAGE_EXIT_CODE = 64

#: Whose failure a proxy-path fault is (#1363 O4). `system`: the target system answered, or the
#: proxy saw its own call to it fail. `request`: this call was outside what the token and the
#: declaration allow, or the caller cut it short. `setup`: ours, for one system. `access`: ours,
#: for the whole process.
ORIGIN_SYSTEM = "system"
ORIGIN_REQUEST = "request"
ORIGIN_SETUP = "setup"
ORIGIN_ACCESS = "access"
ORIGINS = (ORIGIN_SYSTEM, ORIGIN_REQUEST, ORIGIN_SETUP, ORIGIN_ACCESS)
#: The origins the proxy labels on the wire; a system's own answer carries none.
PROXY_LABELS = (ORIGIN_REQUEST, ORIGIN_SETUP, ORIGIN_ACCESS)


class AdapterFault(Exception):

    exit_code: int = 1
    #: Whose failure a proxy-path fault is (`ORIGINS`), set once, by the proxy client where the
    #: fault is raised (#1363 B2). None for a fault that never touched the proxy: a missing origin
    #: is not read as `access`.
    origin: str | None = None
    #: The system a `setup` fault is about, when it names one (#1363 B1).
    system: str | None = None

    @property
    def proxy_own(self) -> bool:
        """True when the fault is the credential proxy's own (#1404): the proxy refused or failed,
        or could not be used at all. Derived from `origin`, never set: False for a fault that
        never touched the proxy and for one the target system caused, so a reader names the proxy
        only for its own faults."""
        return self.origin in PROXY_LABELS

    def __init__(self, detail: str):
        super().__init__(detail)
        self.detail = detail


class ConfigFault(AdapterFault):

    exit_code = 2


class ConfinementFault(AdapterFault):
    """A target-fidelity refusal: never an infra fault (not in circuit_breaker's
    INFRA_EXIT_CODES), and refused before any transport is attempted."""

    exit_code = 1


class TransportFault(AdapterFault):
    """No usable answer. `maybe_delivered` (#1374): may the request have reached the system? True
    unless the transport proved it did not (it was never sent, or the connection to the system was
    never made), from data, never from a message's text."""

    exit_code = 2

    def __init__(self, detail: str, *, maybe_delivered: bool = True):
        super().__init__(detail)
        self.maybe_delivered = maybe_delivered


class UpstreamFault(AdapterFault):
    """The system answered and refused. `status` is its HTTP status when the refusal came from
    an HTTP answer (#1359: data for callers to branch on, never text to be parsed)."""

    exit_code = 1

    def __init__(self, detail: str, status: int | None = None):
        super().__init__(detail)
        self.status = status


__all__ = [
    "ORIGINS",
    "ORIGIN_ACCESS",
    "ORIGIN_REQUEST",
    "ORIGIN_SETUP",
    "ORIGIN_SYSTEM",
    "PROXY_LABELS",
    "USAGE_EXIT_CODE",
    "AdapterFault",
    "ConfigFault",
    "ConfinementFault",
    "TransportFault",
    "UpstreamFault",
]
