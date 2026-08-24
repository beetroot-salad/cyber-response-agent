"""Which systems have a corpus stager, and which module knows how.

The one place the estate names a vendor. It lives INSIDE the per-vendor directory, which is
carved out of the shippable-surface gate, so `estate/applier.py` beside it stays vendor-free
and the gate keeps enforcing that rather than trusting it — a vendor name appearing in the
agnostic seam is still a failure.

A system absent from this table has no staging path and is patched instead. Adding a stager is
one entry here, never a branch in the seam.
"""

from __future__ import annotations

from typing import Any

from . import elastic

STAGERS: dict[str, Any] = {"elastic": elastic}
