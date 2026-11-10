from __future__ import annotations

import re
import threading

from defender._text import is_content_less
# The reducer lane's routing key, imported from its owner so every seam asking "is this the
# reducer's row" compares the same literal.
from defender.knowledge import BASH_SHIM_QUERY_ID




def _slugify(s: str) -> str:
    out = []
    prev_dash = False
    for ch in str(s).lower():
        if ch.isalnum():
            out.append(ch)
            prev_dash = False
        elif not prev_dash:
            out.append("-")
            prev_dash = True
    return "".join(out).strip("-") or "unkeyed"


def derive_alert_rule_key(alert: dict) -> str:
    rule = alert.get("rule")
    if isinstance(rule, dict) and rule.get("id") not in (None, ""):
        return f"rule-{rule['id']}"
    sig = alert.get("signature")
    if isinstance(sig, str) and sig.strip():
        return _slugify(sig)
    top_id = alert.get("id")
    if isinstance(top_id, (str, int)) and str(top_id).strip():
        return _slugify(str(top_id))
    return "unkeyed"







_SHARED_INPUTS_LOCK = threading.Lock()



















#: The envelope `record_query.payload_digest` wraps every failing call in (`exit={code}; `);
#: shared by every failure, so not itself a diagnosis.
_EXIT_ENVELOPE = re.compile(r"^\s*exit=-?\d+\s*;\s*")


def _digest_diagnosis(digest: str) -> str:
    return _EXIT_ENVELOPE.sub("", digest, count=1)


def is_reducer_row(row: dict) -> bool:
    """Is this queued row the reducer's mistake rather than a system's?

    The one spelling, shared by the curator's routing, the lane's arrival gate and the merge
    key, so a row can't be routed one way and counted another.

    Equality with the reserved sentinel — the `query_id` half of what
    `lead_extraction.collect_general_failures` routes on (`is_sentinel` isn't a queue field).
    Ignores the row's `system`: a `defender-sql` mistake belongs to `defender-sql` however the
    reduce was attributed, and older rows still carry an attributed system.
    """
    return str(row.get("query_id") or "") == BASH_SHIM_QUERY_ID


def pitfall_key(row: dict) -> tuple[str, str]:
    """The identity of a mistake, which is not the identity of a failing row."""
    owner = (
        BASH_SHIM_QUERY_ID if is_reducer_row(row)
        else str(row.get("system") or "").strip()
    )
    digest = str(row.get("stderr_digest") or "")
    if is_content_less(_digest_diagnosis(digest)):
        return (owner, "\x00" + str(row.get("pitfall_id") or ""))
    return (owner, digest)


def _occurrences(row: dict) -> int:
    # A queue row is one occurrence; a merged record carries its count, so re-merging is a
    # no-op.
    n = row.get("occurrences")
    return n if isinstance(n, int) and not isinstance(n, bool) and n > 0 else 1


def merge_pitfalls(rows: list[dict]) -> list[dict]:
    """Collapse repeats of one mistake into one record carrying `occurrences: N`.

    The count tells the curator which bullet is worth the context. The first row of a key is
    the exemplar and keeps every other field; later rows contribute only their count. Order is
    first-seen, and the result re-merges to itself, so either consuming seam can merge.
    """
    out: list[dict] = []
    by_key: dict[tuple[str, str], dict] = {}
    for row in rows:
        key = pitfall_key(row)
        if (exemplar := by_key.get(key)) is not None:
            exemplar["occurrences"] += _occurrences(row)
            continue
        rec = dict(row)
        rec["occurrences"] = _occurrences(row)
        by_key[key] = rec
        out.append(rec)
    return out
