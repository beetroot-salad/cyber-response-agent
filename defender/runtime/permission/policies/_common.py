"""Shared regex builders for the runtime-agent policy files (main/gather).

The mechanism (compile a per-program anchored pattern) is shared; the *policy*
(which programs, which capability bits, which deny reason) stays per-agent.
"""

from __future__ import annotations

import re

from defender.hooks._cmd_segments import NON_ADAPTER_SHIMS
from defender.runtime import bash_policy


def viewer_patterns() -> tuple[re.Pattern[str], ...]:
    """Anchored per-program patterns for the read-only viewers + non-adapter
    `defender-*` shims — the main/gather reader allowlist (`bash_policy.json`'s
    `viewers` plus the taxonomy's `NON_ADAPTER_SHIMS`, the same set the old
    `_allowed_programs` used). Each program is allowed with any trailing args:
    the argv is already de-quoted and expansion-free, `shell=False` keeps the args
    inert, and the substitution guard (`bash._stage_unsafe`) still rejects a
    `$(...)`/backtick/`VAR=` stage. Data-source adapters are NOT here — they route
    structurally (`command_shape` / `bash._decide_adapter`)."""
    names = sorted(set(bash_policy.viewers()) | set(NON_ADAPTER_SHIMS))
    return tuple(re.compile(rf"^{re.escape(n)}(?: .*)?$") for n in names)
