"""Keep host-known branch identities out of model-visible faults.

The caller supplies the episode, world and sibling run UUIDs it actually knows. Unknown UUIDs
remain ordinary data: their shape alone never establishes a branch identity. Timestamp-shaped
names likewise pass unchanged unless the host explicitly declares them as known identities.
"""

from __future__ import annotations

import re
from collections.abc import Collection

#: The replacement marker. Named rather than blank, so the model can tell "your run was
#: refused" from a sentence missing a word (a blank invites a retry). Worded as a thing every
#: run has, so the marker itself does not reveal that worlds exist.
_TOKEN_MARK = "[a run id]"


def redact_model_visible(detail: str, known_ids: Collection[str]) -> str:
    """`detail` with every episode and world token removed, and nothing else touched."""
    text = detail if isinstance(detail, str) else str(detail)
    names = sorted({str(n) for n in known_ids if n}, key=len, reverse=True)
    if names:
        known = re.compile("|".join(map(re.escape, names)), re.IGNORECASE)
        text = known.sub(_TOKEN_MARK, text)
    return text
