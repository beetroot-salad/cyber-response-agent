"""The single canonical wall-clock string shared by runtime/, scripts/, and learning/.

One contract for "the loop's UTC timestamp, seconds precision", so the identical
``datetime.now(UTC).isoformat(timespec="seconds")`` line stops being copy-pasted
across layers and drifting (one copy in ``hooks/budget_enforcer.py`` already omits
``timespec`` — a deliberate exception left in place).

Lives at the ``defender.`` namespace root (no ``__init__.py`` — PEP 420 namespace
package) so every layer imports it without a ``sys.path`` dance (see the
``_frontmatter`` precedent, #322/#323).
"""
from __future__ import annotations

import datetime as _dt


def now_iso() -> str:
    """UTC timestamp, seconds precision (the loop's canonical clock string)."""
    return _dt.datetime.now(_dt.UTC).isoformat(timespec="seconds")
