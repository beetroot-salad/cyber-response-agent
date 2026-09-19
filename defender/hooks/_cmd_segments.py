#!/usr/bin/env python3
"""The shim-name constants the permission gate classifies a command's program by."""
from __future__ import annotations

import re

NON_ADAPTER_SHIMS = frozenset(
    {"defender-invlang", "defender-lessons", "defender-sql"}
)

OPERATOR_TOOLS = frozenset({"defender-policy"})

ADAPTER_RE = re.compile(r"scripts/adapters/\w+_adapter\.py\b")

