
from __future__ import annotations

USAGE_EXIT_CODE = 64


class AdapterFault(Exception):

    exit_code: int = 1

    def __init__(self, detail: str):
        super().__init__(detail)
        self.detail = detail


class ConfigFault(AdapterFault):

    exit_code = 2


class TransportFault(AdapterFault):

    exit_code = 2


class UpstreamFault(AdapterFault):

    exit_code = 1


__all__ = [
    "USAGE_EXIT_CODE",
    "AdapterFault",
    "ConfigFault",
    "TransportFault",
    "UpstreamFault",
]
