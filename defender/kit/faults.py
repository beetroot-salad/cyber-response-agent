
from __future__ import annotations

USAGE_EXIT_CODE = 64


class AdapterFault(Exception):

    exit_code: int = 1
    #: True when the fault is the credential proxy's own (#1404): the proxy refused or failed, or
    #: could not be used at all (unreachable, an unusable answer, no address handed to the call).
    #: False for a fault that never touched the proxy and for one where the proxy saw the target
    #: system's own call fail or answer, so a reader names the proxy only for its own faults.
    proxy_own: bool = False

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
