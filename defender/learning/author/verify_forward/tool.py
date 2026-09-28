"""Intentionally empty: the forward check is run by the drain (`author/drain.py`), not by a
curator tool. Kept so a stale reference to a name here (`run_forward_check`, `Pair`,
`register_forward_check_tool`) fails with an `AttributeError` naming it rather than an
`ImportError` on the module.
"""
from __future__ import annotations
