"""One canonicalization for the two wire digests.

Two capture points digest a message list: `observe.RequestLogger.log` stamps `wire_sha` on
every logged request, and `selection.render` stamps one on the pending row a fold is about
to write.

**They are not expected to agree, and no test asserts they do.** Three transforms sit
between the renderer returning and the bytes leaving — `fill_run_metadata` mutating
`messages[-1]` in place, `_clean_message_history` merging the post-fold pair, and
`prepare_messages` reshaping again — so the digests differ in both the fold and the no-fold
case. The difference is the signal, not the match.

Which is why the FUNCTION is shared: a recorded difference only means "the message set
changed between these two points" if both points canonicalize the same way. Two
hand-identical bodies in modules that do not import each other would drift silently, and
then report a difference for every request.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

from pydantic_ai.messages import ModelMessagesTypeAdapter


def wire_digest(messages: list[Any]) -> str:
    """SHA-256 over the canonical JSON dump of `messages`.

    `sort_keys=True` and `ensure_ascii=True` are load-bearing, not style: without them the
    same message set digests differently depending on dict insertion order and on whether a
    non-ASCII character survived as itself or as an escape. Both capture points must make the
    same choice on both, or their digests are not comparable at all.
    """
    dumped = ModelMessagesTypeAdapter.dump_python(messages, mode="json")
    text = json.dumps(dumped, sort_keys=True, ensure_ascii=True)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
