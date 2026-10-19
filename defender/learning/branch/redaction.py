"""Remove the host's known branch identities from model-visible text.

Fault details reach the model inside the untrusted wrap and in the query table's failure
digest; comparator payloads and axes can carry the same identities. Match only the identities
supplied by the host: the episode id and token, world tokens, and arm run ids. Their spelling
has no significance. A natural run supplies an empty set and its text passes unchanged.

Keep the surrounding error actionable: configured patterns, timestamps, and unrelated ids
remain intact, while a known identity becomes the neutral marker `[a run id]`.
"""

from __future__ import annotations

import re
from collections.abc import Collection

#: The replacement marker. Named rather than blank, so the model can tell "your run was
#: refused" from a sentence missing a word (a blank invites a retry). Worded as a thing every
#: run has, so the marker itself does not reveal that worlds exist.
_TOKEN_MARK = "[a run id]"


def redact_model_visible(detail: str, known_ids: Collection[str]) -> str:
    """`detail` with every episode and world token removed, and nothing else touched.

    `known_ids` is every branch identity the caller's process knows (`family_identities`), or
    an empty set for a natural run. Required, so no caller can forget it silently. Matched as
    literal text, case-insensitively, longest first, so a world token is removed whole rather
    than leaving its label behind its episode token's marker. No shape-based matching is used.

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
    return text
