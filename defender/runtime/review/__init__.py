"""#796 — the blind lenses and the composer that review a confident close.

The package is the reviewer's own half of the gate: the projections each lens reads
(`projector`), the roles they run under, and the reading of what they return.
`challenge_gate` keeps the harness — bounds, the review state, the stage deadline, the
trace rows and the routing — and dispatches into this package.
"""

from __future__ import annotations

__all__: list[str] = []
