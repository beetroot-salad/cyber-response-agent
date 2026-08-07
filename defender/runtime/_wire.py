"""One canonicalization for the two wire digests.

Two capture points compute a digest of a message list: the request logger stamps `wire_sha`
onto every logged request (`observe.RequestLogger.log`), and the session selection layer
stamps one onto the pending row a fold is about to write (`selection.render`).

**They are not expected to agree, and no test asserts they do.** Three transforms sit
between the renderer returning and the bytes leaving — `fill_run_metadata` mutating
`messages[-1]` in place, `_clean_message_history` merging the post-fold pair, and
`prepare_messages` reshaping again — so the two digests differ in both the fold and the
no-fold case. `test_wire_log_705.py`'s two-digest join records that history; it is the
difference that is the signal, not the match.

Which is exactly why the FUNCTION has to be shared. A recorded difference only means "the
message set changed between these two points" if both points canonicalize the same way. The
two bodies were byte-identical by hand, under names spelled in opposite orders
(`_wire_digest` / `_digest_wire`), in modules that do not import each other — and nothing
would have failed if one had drifted. It would just have started reporting a difference for
every request, indistinguishable from the transform it exists to detect.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

from pydantic_ai.messages import ModelMessagesTypeAdapter


def wire_digest(messages: list[Any]) -> str:
    """SHA-256 over the canonical JSON dump of `messages`.

    `sort_keys=True` and `ensure_ascii=True` are load-bearing for the comparison, not style:
    without them the same message set digests differently depending on dict insertion order
    and on whether a non-ASCII character survived as itself or as an escape. Both capture
    points must make the same choice on both, or their two digests are not comparable at all.
    """
    dumped = ModelMessagesTypeAdapter.dump_python(messages, mode="json")
    text = json.dumps(dumped, sort_keys=True, ensure_ascii=True)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
