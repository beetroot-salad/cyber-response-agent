from __future__ import annotations

import re
import threading

from defender._text import is_content_less
from defender.learning.core.state import PITFALLS, LearningState
# The reducer lane's routing key, imported from its owner so every seam asking "is this the
# reducer's row" compares the same literal.
from defender._query_rules import BASH_SHIM_QUERY_ID




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
    """The identity of a mistake, which is not the identity of a failing row.

    `(owner, stderr_digest)`, where the owner is the surface the lesson would be taught on:
    the reducer sentinel for a reducer row (collision-free, since `is_system_name` admits no
    `∅`), else the stripped system name (matching `_build_pitfalls_handoffs`' grouping).
    Keying on `system` alone would split one reducer mistake across attributed systems and
    merge a system row with a reducer row sharing a digest.

    The digest is the adapter's diagnosis, which the curator uses to name the mistake, so
    rows sharing it under one owner are one lesson however the query was phrased; `query_id`
    only decides the owner.

    A row whose digest carries no diagnosis (absent, blank, or only the `exit=N;` envelope)
    keys to itself: merging on the absence of a verdict would fold unrelated mistakes behind
    one exemplar and consume the rest as though curated. `is_content_less`, not `.strip()`, so
    zero-width filler doesn't count as a diagnosis.
    """
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


def pitfalls_lane_is_open(records: list[dict], threshold: int) -> bool:
    """The one arrival condition, shared by `pitfalls_curator.run_pitfalls`' tick gate and
    `drains._has_lead_author_work`' wake gate.

    True when the distinct count of merged records reaches the threshold, or when some reducer
    record (`is_reducer_row`, so routing and gating agree) has `occurrences >= threshold` on
    its own.

    The second disjunct exists because the count alone is anti-correlated with evidence on the
    reducer lane: one unchanging error across many attempts is one merged record, while N
    diagnosis-less failures are N records. Those key per row (`(owner, "\\x00" + pitfall_id)`),
    so they can never satisfy the disjunct.
    """
    if len(records) >= threshold:
        return True
    return any(is_reducer_row(r) and _occurrences(r) >= threshold for r in records)


def append_pitfalls(rows: list[dict], *, state: LearningState) -> int:
    """Append the failing rows verbatim, one line per failure; `merge_pitfalls` collapses them
    at the consuming seams.

    Not deduplicated here: bumping a count on a row already on disk would be a second
    wholesale queue rewriter, racing the drain's read-modify-write window.
    """
    if not rows:
        return 0
    return state.append(PITFALLS, rows)[0]


def read_pitfalls(state: LearningState) -> list[dict]:
    return state.rows(PITFALLS)


def rotate_pitfalls(
    batch_ids: list[str], commit_sha: str | None, *, state: LearningState,
    category: str = "consumed_committed", timeout_seconds: int | None = None,
) -> None:
    """`timeout_seconds` is the append lock's deadline: the drain passes its configured wait,
    since it holds the tick's locks meanwhile; a by-hand caller passes none."""
    ids = set(batch_ids)
    consumed = [
        {**r, "consumed_category": category}
        for r in state.rows(PITFALLS)
        if r.get("pitfall_id") in ids
    ]
    state.rotate(PITFALLS, [], consumed, commit_sha, timeout=timeout_seconds)
