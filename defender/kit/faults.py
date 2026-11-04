
from __future__ import annotations

USAGE_EXIT_CODE = 64


class AdapterFault(Exception):

    exit_code: int = 1
    #: True when the credential proxy itself named this fault class in its answer
    #: (`raise_proxy_fault`, #1398), so a caller can tell the proxy's refusal from a fault the
    #: adapter raised itself on the same route. Not set for every fault on the proxy route: a
    #: status the proxy relays, an unreadable answer, or failing to reach the proxy leave it False.
    from_proxy: bool = False

    def __init__(self, detail: str):
        super().__init__(detail)
        self.detail = detail


class ConfigFault(AdapterFault):

    exit_code = 2


class TransportFault(AdapterFault):

    exit_code = 2


class UpstreamFault(AdapterFault):
    """The system answered and refused. `status` is its HTTP status when the refusal came from
    an HTTP answer (#1359: data for callers to branch on, never text to be parsed)."""

    exit_code = 1

    def __init__(self, detail: str, status: int | None = None):
        super().__init__(detail)
        self.status = status


__all__ = [
    "USAGE_EXIT_CODE",
    "AdapterFault",
    "ConfigFault",
    "TransportFault",
    "UpstreamFault",
]
