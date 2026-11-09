"""The fault classes the proxy answers with (#1163 O7, A9), by name: an answer carries the class's
name, never the class, and the adapter side raises the class an answer names."""
from __future__ import annotations

from defender.kit.faults import ConfigFault, TransportFault, UpstreamFault

CONFIG = ConfigFault.__name__
TRANSPORT = TransportFault.__name__
UPSTREAM = UpstreamFault.__name__
#: `kit.faults.ConfinementFault`: a path escaping the base, an undeclared route,
#: a write without a write grant.
CONFINEMENT = "ConfinementFault"


class Refused(Exception):
    """One request ends here with the fault class `fault`; `detail` says why and never holds a
    secret value. `system_side` when the target system's own call failed, not the proxy (#1404):
    set only where the proxy calls that system."""

    def __init__(self, fault: str, detail: str, *, system_side: bool = False) -> None:
        super().__init__(f"{fault}: {detail}")
        self.fault = fault
        self.detail = detail
        self.system_side = system_side
