"""One canonicalization for the two wire digests.

`observe.RequestLogger.log` stamps `wire_sha` on every logged request and `selection.render`
stamps one on the pending row. They are not expected to agree: framework transforms between
render and send (`fill_run_metadata`, `_clean_message_history`, `prepare_messages`) change the
messages, and that difference is the signal. Sharing the function keeps the canonicalization
identical, so a difference means the message set actually changed.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

from pydantic_ai.messages import ModelMessagesTypeAdapter


def wire_digest(messages: list[Any]) -> str:
    """SHA-256 over the canonical JSON dump of `messages`.

    `sort_keys` and `ensure_ascii` make the digest independent of dict insertion order and
    of how non-ASCII characters were escaped.
    """
    dumped = ModelMessagesTypeAdapter.dump_python(messages, mode="json")
    text = json.dumps(dumped, sort_keys=True, ensure_ascii=True)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
