"""Keep host-known branch identities out of model-visible faults.

The caller supplies the episode, world and sibling run UUIDs it actually knows. Unknown UUIDs
remain ordinary data: their shape alone never establishes a branch identity. The historical
stamp pattern also screens old diagnostics without inferring identities from UUIDs.
"""

from __future__ import annotations

import re
from collections.abc import Collection

#: Historical timestamp-derived identifiers in old diagnostics. This never matches a UUID
#: or an ISO timestamp, so unknown UUIDs and useful time windows survive.
_TOKEN = re.compile(r"(?<![A-Za-z0-9])\d{8}[tT]\d{6}[zZ](?:[.\-][A-Za-z0-9_]+)*")

#: The replacement marker. Named rather than blank, so the model can tell "your run was
#: refused" from a sentence missing a word (a blank invites a retry). Worded as a thing every
#: run has, so the marker itself does not reveal that worlds exist.
_TOKEN_MARK = "[a run id]"


def redact_model_visible(detail: str, known_ids: Collection[str]) -> str:
    """`detail` with every episode and world token removed, and nothing else touched.

    `known_ids` is every branch identity the caller's process knows (`family_identities`), or
    an empty set for a natural run. Required, so no caller can forget it silently. Matched as
    literal text, case-insensitively, longest first. The historical stamp rule runs after.

    Called from `runtime/query_tool.py` at `_model_view` (the model's copy) and
    `QueryCapture._record` (the failure digest), and from the comparator's prompt; that wiring
    is pinned by a driven run.

    A non-string is passed through `str`, and an empty member is dropped (it would match
    between every character): this runs inside fault handlers, which must not raise.
    """
    text = detail if isinstance(detail, str) else str(detail)
    names = sorted({str(n) for n in known_ids if n}, key=len, reverse=True)
    if names:
        known = re.compile("|".join(map(re.escape, names)), re.IGNORECASE)
        text = known.sub(_TOKEN_MARK, text)
    return _TOKEN.sub(_TOKEN_MARK, text)
