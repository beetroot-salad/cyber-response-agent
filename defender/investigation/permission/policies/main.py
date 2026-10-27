
from __future__ import annotations

FALLTHROUGH_DENY_REASON = (
    "Blocked: only the defender-* shims and read-only viewers (cat/grep/head/tail/wc) are "
    "permitted from the main loop, and only `cat` opens a file — the rest read STDIN, so pipe "
    "into them: `cat <path> | grep <pattern>`. Dispatch gather for data-source access; do not "
    "run arbitrary shell."
)
