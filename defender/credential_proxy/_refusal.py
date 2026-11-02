"""The fault classes the proxy answers with (#1163 O7, A9), by name: the proxy sits below
`integrations`, where `ConfinementFault` lives, so it names classes rather than raising them. The
adapter side raises the class an answer names."""
from __future__ import annotations

from defender.kit.faults import ConfigFault, TransportFault, UpstreamFault

CONFIG = ConfigFault.__name__
TRANSPORT = TransportFault.__name__
UPSTREAM = UpstreamFault.__name__
#: `integrations.confinement.ConfinementFault`: a path escaping the base, an undeclared route,
#: a write without a write grant.
CONFINEMENT = "ConfinementFault"


class Refused(Exception):
    """One request ends here with the fault class `fault`; `detail` says why and never holds a
    secret value."""

    def __init__(self, fault: str, detail: str) -> None:
        super().__init__(f"{fault}: {detail}")
        self.fault = fault
        self.detail = detail
