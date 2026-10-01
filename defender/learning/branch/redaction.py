"""What a fault may tell the model about a branched episode.

A sibling reads a private view of the corpus, named outside every configured pattern
(`confinement.world_view`). The model driving it must not learn the scheme exists: it asks for
`logs-*`, the applier retargets the call, and the payload is restored before the model sees it.
A fault's text is the one channel none of those seams own.

That channel is `AdapterFault.detail`. It reaches the model verbatim inside the untrusted wrap,
and is also written into `executed_queries.jsonl`'s failure digest, within the gather agent's
read scope. It can carry the namespace prefix, the `wv-{world}-{stem}` template and the world's
id; with those the model could spell a sibling's view name and attempt a cross-world read.

It is a filter over the detail, not per-site wording, because one of the three sources on this
channel is the cluster's own error relayed verbatim, which we do not author.

It must stay actionable: an empty or truncated refusal makes the model repeat the call. So only
names are removed; the sentence, configured patterns like `logs-*`, and refusals naming nothing
staged pass through unchanged.

The namespace is imported from its one home so the filter always matches the names the stager
builds.
"""

from __future__ import annotations

import re

from defender.scripts.adapters.confinement import VIEW_NAMESPACE

#: A staged view name, or the bare namespace prefix a refusal quotes on its own (`'wv-*'`). The
#: tail covers every index-expression character, so a doubled name (`wv-{a}-wv-{c}-logs-`) is
#: removed whole. The lookbehind anchors at a token boundary; `.` and `-` are deliberately not
#: in it, since in index expressions they are separators (`[logs-*,-wv-<token>-logs-]`).
#: Concatenated rather than an f-string: `lint_stage_prompt_frames` refuses module-level
#: f-strings.
_STAGED_NAME = re.compile(
    r"(?<![A-Za-z0-9_])" + re.escape(VIEW_NAMESPACE) + r"-[A-Za-z0-9_.*\-]*")

#: An episode or world token, matched by shape, since the filter is never told which world is
#: serving (faults also come from the launcher, reviewer and stager). The shape is what
#: `episode_token_for` derives: a casefolded UTC stamp, then dotted or hyphenated segments. A
#: world token is the episode token plus a segment, and the greedy tail removes both.
#:
#: `_` is in the segment class because `episode_token_for` escapes `_` in the run id as `__`;
#: without it only half the token would be removed.
#:
#: An ISO timestamp (`2026-07-28T16:18:45Z`) does not match, so time windows in cluster errors
#: survive.
_TOKEN = re.compile(r"(?<![A-Za-z0-9])\d{8}[tT]\d{6}[zZ](?:[.\-][A-Za-z0-9_]+)*")

#: Replacement markers. Named rather than blank, so the model can tell "your index was refused"
#: from a sentence missing a word (a blank invites a retry). Worded as things every run has
#: (an index, a run id), so the marker itself does not reveal that worlds or staging exist.
_VIEW_MARK = "[an index]"
_TOKEN_MARK = "[a run id]"


def redact_model_visible(detail: str) -> str:
    """`detail` with every staged name and world id removed, and nothing else touched.

    Called from `runtime/query_tool.py` at `_model_view` (the model's copy) and
    `QueryCapture._record` (the failure digest); that wiring is pinned by a driven run.

    View names are removed before tokens: a view name contains the token, so the reverse order
    would leave `wv-[a run id]-logs-` exposing the prefix and template.

    A non-string is passed through `str`: this runs inside fault handlers, which must not raise.
    """
    text = detail if isinstance(detail, str) else str(detail)
    return _TOKEN.sub(_TOKEN_MARK, _STAGED_NAME.sub(_VIEW_MARK, text))
