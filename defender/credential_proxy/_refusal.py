"""The fault classes the proxy answers with (#1163 O7, A9), by name: an answer carries the class's
name, never the class, and the adapter side raises the class an answer names."""
from __future__ import annotations

from defender.kit.faults import (
    ORIGIN_ACCESS,
    ORIGIN_REQUEST,
    ORIGIN_SETUP,
    ORIGIN_SYSTEM,
    AdapterFault,
    ConfigFault,
    TransportFault,
    UpstreamFault,
)

CONFIG = ConfigFault.__name__
TRANSPORT = TransportFault.__name__
UPSTREAM = UpstreamFault.__name__
#: `kit.faults.ConfinementFault`: a path escaping the base, an undeclared route,
#: a write without a write grant.
CONFINEMENT = "ConfinementFault"


def labelled(fault: AdapterFault, origin: str) -> AdapterFault:
    """`fault` with the origin it is raised under (#1363 B3), for the proxy's modules that raise a
    plain fault rather than a refusal. The label is set where the fault is raised, never by the
    proxy's top-level handler."""
    fault.origin = origin
    return fault


class Refused(Exception):
    """One request ends here with the fault class `fault`; `detail` says why and never holds a
    secret value. `system_side` when the target system's own call failed, not the proxy (#1404):
    set only where the proxy calls that system.

    Every refusal says whose failure it is (`origin`, #1363 O4), where it is raised: `request` for
    this call, `setup` for one system's setup, `access` for the proxy's own access as a whole. A
    `system_side` refusal is the system's (`system`); any other must name its origin, so a raise
    site added later cannot fall silently to the catch-all."""

    def __init__(self, fault: str, detail: str, *, origin: str | None = None,
                 system_side: bool = False) -> None:
        super().__init__(f"{fault}: {detail}")
        if system_side:
            origin = ORIGIN_SYSTEM
        elif origin not in (ORIGIN_REQUEST, ORIGIN_SETUP, ORIGIN_ACCESS):
            raise ValueError(f"a refusal names whose failure it is: origin {origin!r}")
        self.fault = fault
        self.detail = detail
        self.system_side = system_side
        self.origin = origin
