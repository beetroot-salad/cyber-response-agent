"""What a fault may tell the model about a branched episode (§7 NEW-DECISION-1).

A sibling reads a PRIVATE view of the corpus, named outside every configured pattern so the
base run and the worlds that stage nothing cannot reach it (`confinement.world_view`). The
model driving that sibling is not supposed to learn the scheme exists at all: it asks for
`logs-*`, the applier retargets the call, and the payload is restored before the model sees it.
Every one of those seams is careful with the name — and then a fault carries it out on the one
channel none of them own.

That channel is `AdapterFault.detail`. It reaches the model verbatim inside the untrusted wrap,
and the same string is written into `executed_queries.jsonl`'s failure digest, which sits in the
gather agent's own read scope. An executed probe answered a five-character query with the
namespace prefix, the `wv-{world}-{stem}` template AND the world's own id, none of which the
model asked for. Once it holds those three it can spell a sibling's view name itself, and the
cross-world read the serve point refuses becomes a thing worth attempting.

**A FILTER OVER THE DETAIL, not per-site wording.** Three kinds of text arrive on this one
channel: the stager's own refusal, confinement's refusal, and the CLUSTER's error relayed
verbatim. Only the first two are ours to word, and whether a live cluster names the index in the
third could not be settled from the session that raised the decision — so the safe half of the
channel is the half that is filtered rather than the half that is authored. Wording every site
we own leaves the relayed reason, which is exactly the one that carried the 404 the probe saw.

**AND IT MUST STAY ACTIONABLE.** The model reasons from a refusal: an empty channel makes it
repeat the same call, and a run that loops is a run that measures nothing. So the filter removes
NAMES and leaves the sentence — "falls outside the configured patterns" survives, `logs-*`
survives, an ordinary refusal that names nothing staged comes through byte for byte. Redacting
by truncation, or by replacing the whole detail with a fixed line, would satisfy the negative
demand and destroy the channel; the positive control beside it is what pins that.

The namespace itself is imported rather than spelled here, for the same reason `view_name`
delegates to `world_view`: the prefix has ONE home, and a filter that stopped matching the names
the stager builds would leak every one of them while still passing its own test.
"""

from __future__ import annotations

import re

from defender.scripts.adapters.confinement import VIEW_NAMESPACE

#: A staged view name, or the bare namespace prefix a refusal quotes on its own (`'wv-*'`,
#: "under the wv- namespace"). The tail is every character an index expression may carry, so a
#: doubled name — `wv-{a}-wv-{c}-logs-`, which is what the staging refusal quotes when a model
#: names a view that then gets staged again — is removed WHOLE rather than leaving its inner
#: half behind. The lookbehind keeps the match anchored at a token boundary: a word merely
#: ending in the prefix's letters is not a view name and is not this filter's business.
#: Concatenated rather than interpolated: `lint_stage_prompt_frames` refuses a module-level
#: f-string outright, because an interpolated boundary grammar assembled at import time is how
#: an unreviewed prompt frame got established once. This is a regex and not a frame, and the
#: rule is still the cheaper one to keep than to argue with.
_STAGED_NAME = re.compile(
    r"(?<![A-Za-z0-9_.\-])" + re.escape(VIEW_NAMESPACE) + r"-[A-Za-z0-9_.*\-]*")

#: An episode or world token, by SHAPE rather than by value — this filter is handed a string and
#: never the world that is serving, and a filter that had to be told which world to hide would be
#: wrong for every fault raised outside a serving frame (the launcher's, the reviewer's, the
#: stager's own). The shape is the one `episode_token_for` derives and `refuse_bad_episode_id`
#: holds an id to: a casefolded UTC stamp, then dotted or hyphenated segments. The world token is
#: the episode token plus one more segment, so the greedy tail removes both spellings at once and
#: an assertion for the episode token inside a world token cannot pass on half a match.
#:
#: An ISO timestamp (`2026-07-28T16:18:45Z`) does not match — it carries separators inside both
#: halves — so an ordinary cluster error naming a time window keeps it.
_TOKEN = re.compile(r"(?<![A-Za-z0-9])\d{8}[tT]\d{6}[zZ](?:[.\-][A-Za-z0-9]+)*")

#: What each removal leaves behind. Named rather than blank, because the model has to be able to
#: tell "the index you named was refused" from "the sentence lost a word": a refusal reading
#: `index '' falls outside …` invites the model to retry with the same expression.
_VIEW_MARK = "[a staged view]"
_TOKEN_MARK = "[a world id]"


def redact_model_visible(detail: str) -> str:
    """`detail` with every staged name and world id removed, and nothing else touched.

    Called on the two model-visible channels the decision was raised about, both in
    `runtime/query_tool.py`: `_model_view`, which hands a fault's detail to the model inside the
    untrusted wrap, and `QueryCapture._record`, which writes the same text into the run's own
    queries table as the failure digest. A filter that ships and is never called from those two
    sites passes every unit test written about the filter, which is why the wiring is pinned by
    a driven run rather than by this function's own tests.

    THE VIEW NAMES FIRST, THEN THE TOKENS, and the order is load-bearing: a view name CONTAINS
    the world token, so removing tokens first would leave `wv-[a world id]-logs-` — the prefix
    and the template, which are two of the three things the probe observed leaking, still intact
    and now advertising that something was hidden inside them.

    A non-string is handed back through `str`, because the caller is a fault handler: the one
    place a `TypeError` must never be raised is the frame that exists to report another failure.
    """
    text = detail if isinstance(detail, str) else str(detail)
    return _TOKEN.sub(_TOKEN_MARK, _STAGED_NAME.sub(_VIEW_MARK, text))
