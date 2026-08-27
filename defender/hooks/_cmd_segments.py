#!/usr/bin/env python3
"""The shim-name constants the permission gate classifies a command's program by.

The wrapper-recognition logic that used to live here — the standalone `bash -c`/`timeout`
unpacking step and its helpers — has been ABSORBED into `runtime/bash_exec.py` (#959 M3/C4):
one scanner now decides where a bash word ends, folding what was a second, independent parse
of the raw text into the same token stream `bash_exec.parse` builds. The three constants below
stay here for their own consumers, which are not part of that change.
"""
from __future__ import annotations

import re

NON_ADAPTER_SHIMS = frozenset(
    {"defender-invlang", "defender-lessons", "defender-sql"}
)

OPERATOR_TOOLS = frozenset({"defender-policy"})

ADAPTER_RE = re.compile(r"scripts/adapters/\w+_adapter\.py\b")

