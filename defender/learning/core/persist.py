from __future__ import annotations

import re
import threading

from defender.learning_store import is_reducer_row, pitfall_key  # noqa: F401 — is_reducer_row re-exported for the curator




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


def pitfalls_lane_is_open(records: list[dict], threshold: int) -> bool:
    """The one arrival condition, shared by the store's claim and wake gate and `pitfalls_curator.run_pitfalls`' tick
    gate: the lane has work only when distinct mistakes, not rows, reach the threshold.

    Strict, with no second route: one unchanging error repeated past the threshold is one merged record and
    opens nothing, reducer rows included (#1278 ruling; the store counts the same thing in SQL by `mistake_key`)."""
    return len(records) >= max(1, threshold)
