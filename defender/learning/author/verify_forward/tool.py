"""#773 M1: the forward-check tool the curator used to call is gone.

The verdict is no longer a fact the writer self-reports — the drain runs the check itself,
between `_project` and the commit (`author/drain.py`'s M3 pipeline). `register_forward_check_tool`,
`Pair`, `run_forward_check` and the module-level `_CHECK_SEQ` counter (the drain owns its own
per-tick counter now) are all gone with it. This module is kept, empty, as the address the tool
used to live at, so a stale reference to it fails loudly with an `AttributeError` naming what is
missing rather than an `ImportError` on the module itself.
"""
from __future__ import annotations
