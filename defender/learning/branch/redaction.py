"""What a fault may tell the model about a branched episode.

A sibling's run, its episode and its world are named by tokens (`episode_token_for`): the
episode's UTC stamp plus a label. The model driving a sibling must not learn it is one of
several worlds, nor spell a sibling's token. A fault's text is the one channel no serving seam
owns.

That channel is `AdapterFault.detail`. It reaches the model verbatim inside the untrusted wrap,
and is also written into `executed_queries.jsonl`'s failure digest, within the gather agent's
read scope.

It is a filter over the detail, not per-site wording, because one of the sources on this
channel is the system's own error relayed verbatim, which we do not author.

It must stay actionable: an empty or truncated refusal makes the model repeat the call. So only
tokens are removed; the sentence, configured patterns like `logs-*`, and every other name pass
through unchanged.
"""

from __future__ import annotations

import re

#: An episode or world token, matched by shape, since the filter is never told which world is
#: serving (faults also come from the launcher and the oracle). The shape is what
#: `episode_token_for` derives: a casefolded UTC stamp, then dotted or hyphenated segments. A
#: world token is the episode token plus a segment, and the greedy tail removes both.
#:
#: `_` is in the segment class because `episode_token_for` escapes `_` in the run id as `__`;
#: without it only half the token would be removed.
#:
#: An ISO timestamp (`2026-07-28T16:18:45Z`) does not match, so time windows in system errors
#: survive.
_TOKEN = re.compile(r"(?<![A-Za-z0-9])\d{8}[tT]\d{6}[zZ](?:[.\-][A-Za-z0-9_]+)*")

#: The replacement marker. Named rather than blank, so the model can tell "your run was
#: refused" from a sentence missing a word (a blank invites a retry). Worded as a thing every
#: run has, so the marker itself does not reveal that worlds exist.
_TOKEN_MARK = "[a run id]"


def redact_model_visible(detail: str) -> str:
    """`detail` with every episode and world token removed, and nothing else touched.

    Called from `runtime/query_tool.py` at `_model_view` (the model's copy) and
    `QueryCapture._record` (the failure digest); that wiring is pinned by a driven run.

    A non-string is passed through `str`: this runs inside fault handlers, which must not raise.
    """
    text = detail if isinstance(detail, str) else str(detail)
    return _TOKEN.sub(_TOKEN_MARK, text)
