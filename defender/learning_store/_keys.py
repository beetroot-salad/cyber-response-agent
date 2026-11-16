"""The identity of a queued learning item's mistake (#1278, #1485): pure rules over a row, with no database, so the
learning loop's light paths (the queue's merge, the curator's routing) ask them without loading the store."""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from typing import Any

from defender._text import is_content_less
from defender.knowledge import BASH_SHIM_QUERY_ID


def digest(value: Any) -> str:
    """A short, stable digest of a JSON-able value."""
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()[:32]


#: The envelope `record_query.payload_digest` wraps every failing call in (`exit={code}; `);
#: shared by every failure, so not itself a diagnosis.
_EXIT_ENVELOPE = re.compile(r"^\s*exit=-?\d+\s*;\s*")


def _digest_diagnosis(digest: str) -> str:
    return _EXIT_ENVELOPE.sub("", digest, count=1)


def is_reducer_row(row: dict) -> bool:
    """Is this queued row the reducer's mistake rather than a system's? The one spelling, shared by the curator's
    routing, the lane's arrival gate and the merge key."""
    return str(row.get("query_id") or "") == BASH_SHIM_QUERY_ID


def pitfall_key(row: dict) -> tuple[str, str]:
    """The identity of a mistake, which is not the identity of a failing row."""
    owner = BASH_SHIM_QUERY_ID if is_reducer_row(row) else str(row.get("system") or "").strip()
    digest = str(row.get("stderr_digest") or "")
    if is_content_less(_digest_diagnosis(digest)):
        return (owner, "\x00" + str(row.get("pitfall_id") or ""))
    return (owner, digest)


def mistake_key_of(row: Mapping[str, Any], item_key: str) -> str:
    """The identity of a pitfall's mistake (its owner and diagnosis; a diagnosis-less failure is its own mistake),
    stored on the row so the store's claim counts distinct mistakes in SQL. The one definition the queue's merge uses."""
    return digest(list(pitfall_key({**row, "pitfall_id": item_key})))
