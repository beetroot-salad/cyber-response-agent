"""Which systems have a corpus stager, and which module knows how.

The one place the estate names a vendor. It lives inside the per-vendor directory (carved out
of the shippable-surface gate), so the gate still enforces that `estate/applier.py` stays
vendor-free.

A system absent from this table is patched instead. Adding a stager is one entry here.
"""

from __future__ import annotations

from typing import Any

from . import elastic

STAGERS: dict[str, Any] = {"elastic": elastic}
