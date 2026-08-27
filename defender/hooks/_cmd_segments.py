#!/usr/bin/env python3
"""The shim-name constants the permission gate classifies a command's program by.

The wrapper-recognition logic that used to live here — the standalone `bash -c`/`timeout`
unpacking step and its helpers — is GONE, and gone rather than moved. #959 M3/C4 folded it into
`runtime/bash_exec.py`'s one scanner, and #971 then deleted the fold outright: `parse` now says
"NO WORD IS PARSED SPECIALLY HERE", `bash`/`sh`/`timeout` are ordinary ungranted words, and no
function anywhere unwraps a payload before the gate decides. Nothing to look for elsewhere. The
three constants below stay here for their own consumers, which are not part of that change.
"""
from __future__ import annotations

import re

NON_ADAPTER_SHIMS = frozenset(
    {"defender-invlang", "defender-lessons", "defender-sql"}
)

OPERATOR_TOOLS = frozenset({"defender-policy"})

ADAPTER_RE = re.compile(r"scripts/adapters/\w+_adapter\.py\b")

