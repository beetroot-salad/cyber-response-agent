from __future__ import annotations

import contextlib
import json
import re
import threading
from pathlib import Path


# Aliased to `_lockfile` so this module can keep `_flock` as its own name for `queue_lock`.
from defender import _flock as _lockfile
from defender._clock import now_iso
from defender._text import is_content_less
from defender._io import append_jsonl, read_jsonl_rows, write_atomic
from defender.learning.core.config import (
    DEFAULT_PATHS,
    LoopPaths,
    make_logger,
)
# The reducer lane's routing key, at its owner (#870). Imported for the VALUE, the same way
# `lead_extraction` and `pitfalls_curator` take it: the three seams that ask "is this the
# reducer's row" have to compare the same literal, and a second spelling of it here is exactly
# the drift `is_reducer_row` was introduced to end.
from defender.scripts.gather_tools.record_query import BASH_SHIM_QUERY_ID




@contextlib.contextmanager
def queue_lock(lock_path: Path, *, timeout_seconds: int | None = None):
    """Exclusive hold of a queue's append-role lock.

    APPENDERS pass no deadline and wait forever: an append that gave up would lose the row
    it is carrying, and it waits on nothing but other appenders and the short rewrite window.

    THE DRAIN must pass one. It reaches this holding the repo lock, which serialises all four
    corpus channels — so a wedged appender on one channel would otherwise stall every sibling
    channel's tick unboundedly. Expiry raises `TimeoutError`, deliberately NOT in the drain's
    retire set: the batch is recorded stuck, never bumped, since a busy lock is not its fault.
    """
    fh = _lockfile.open_lock(lock_path)
    try:
        taken = _lockfile.take(fh, timeout_seconds=timeout_seconds)
    except BaseException:
        fh.close()
        raise
    if not taken:
        fh.close()
        raise TimeoutError(
            f"queue lock {lock_path} held by an appender for >{timeout_seconds}s"
        )
    try:
        yield
    finally:
        _lockfile.release(fh)


#: In-module callers and the lock suites reach for this spelling.
_flock = queue_lock


def _load_jsonl_ids(path: Path, key: str) -> set[str]:
    ids: set[str] = set()
    for obj in read_jsonl_rows(path):
        v = obj.get(key)
        if isinstance(v, str):
            ids.add(v)
    return ids


def _rewrite_queue(
    pending_file: Path,
    consumed_file: Path,
    id_key: str,
    held: list[dict],
    consumed: list[dict],
    commit_sha: str | None,
) -> None:
    # ALWAYS merges: a non-merging rewrite would drop any row appended between the batch's
    # read and its rewrite. `.get`, not `[...]`: a row carrying no value under `id_key`
    # cannot be matched, and the drain routes such rows here deliberately so they leave.
    processed = {e.get(id_key) for e in held} | {e.get(id_key) for e in consumed}
    current = read_jsonl_rows(pending_file)
    survivors = list(held) + [r for r in current if r.get(id_key) not in processed]
    write_atomic(pending_file, "".join(json.dumps(entry) + "\n" for entry in survivors))
    if consumed:
        now = now_iso()
        rows = []
        for entry in consumed:
            rec = dict(entry)
            rec.setdefault("consumed_at", now)
            if rec.get("consumed_category") == "consumed_committed" and commit_sha:
                rec["consumed_commit"] = commit_sha
            rows.append(rec)
        append_jsonl(consumed_file, rows)


def rotate_queue_locked(
    *,
    pending_file: Path,
    consumed_file: Path,
    lock_file: Path,
    id_key: str,
    held: list[dict],
    consumed: list[dict],
    commit_sha: str | None,
    timeout_seconds: int | None = None,
) -> None:
    pending_file.parent.mkdir(parents=True, exist_ok=True)
    with queue_lock(lock_file, timeout_seconds=timeout_seconds):
        _rewrite_queue(pending_file, consumed_file, id_key, held, consumed, commit_sha)


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

_persist_log = make_logger("persist")


















#: The envelope `record_query.payload_digest` wraps EVERY failing call in (`exit={code}; `).
#: It is shared by every failure of a system, so it is not itself a diagnosis.
_EXIT_ENVELOPE = re.compile(r"^\s*exit=-?\d+\s*;\s*")


def _digest_diagnosis(digest: str) -> str:
    return _EXIT_ENVELOPE.sub("", digest, count=1)


def is_reducer_row(row: dict) -> bool:
    """Is this queued row the REDUCER's mistake rather than a system's?

    THE ONE SPELLING, and it lives here because three seams ask it and they were three
    different questions until #870's review: `pitfalls_curator._is_reducer_row` asked the
    sentinel, `pitfalls_lane_is_open` asked `system == ""`, and `pitfall_key` did not ask at
    all. The three disagreed on exactly one population — a row queued BEFORE M5′ deployed,
    which carries the system its payload was attributed to AND the sentinel id — so the same
    row was routed to the reducer surface by one reader, refused the lane by another, and
    split into a record per attributed system by the third.

    EQUALITY with the reserved sentinel (U3). It is the `query_id` half of the predicate
    `lead_extraction.collect_general_failures` routes on; the `is_sentinel` half is the
    projection's verdict on a QUERIES-TABLE row and is not a field the queue carries, so this
    is the strongest form a queue reader can ask. Unconditional in the row's `system`, because
    a `defender-sql` mistake belongs to `defender-sql` however the reduce happened to be
    attributed (F1) — which is the whole content of the disagreement above.
    """
    return str(row.get("query_id") or "") == BASH_SHIM_QUERY_ID


def pitfall_key(row: dict) -> tuple[str, str]:
    """The identity of a MISTAKE, which is not the identity of a failing row.

    `(owner, stderr_digest)`, where the OWNER is the surface the lesson would be taught on:
    the reducer sentinel for a reducer row, the stripped system name otherwise. Keying on
    `system` alone splits and merges the wrong rows in both directions once the reducer
    surface is a second target — two reducer rows spelling their attributed system
    differently become two records of ONE `defender-sql` mistake, and a system row sharing a
    digest with a reducer row becomes one record whose fate falls to whichever the merge kept
    as exemplar. The sentinel is collision-free as an owner name because `is_system_name`
    admits no `∅`.

    The digest is the adapter's own diagnosis and is what `lead_pitfalls.md` step 2 reads to
    name the mistake and its fix, so two rows carrying the same one under the same owner are
    one lesson however differently the query was phrased. `query_id` is deliberately out of
    the key as an IDENTITY: two coined queries earning the identical rejection teach one
    bullet. It is read only to answer WHICH SURFACE owns the lesson — the question
    `is_reducer_row` exists for.

    The system name is STRIPPED to match `_build_pitfalls_handoffs`' grouping; a coarser key
    would hand the curator two entries it reads as two bullets. The reducer half needs no
    such agreement — the builder collects every reducer record into ONE entry.

    A row whose digest carries NO diagnosis — absent, blank, or nothing but the adapter's
    `exit=N;` envelope — keys to ITSELF. Merging on the absence of a verdict would fold
    unrelated mistakes behind one exemplar, hand the curator only that exemplar's query, and
    rotate the rest into `consumed` as though curated. `is_content_less`, not `.strip()`, so
    a digest of zero-width filler cannot read as a diagnosis either.
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
    # A queue row IS one occurrence and carries no count of its own; a record already
    # merged carries the count it was merged from, so re-merging a merged set is a no-op.
    n = row.get("occurrences")
    return n if isinstance(n, int) and not isinstance(n, bool) and n > 0 else 1


def merge_pitfalls(rows: list[dict]) -> list[dict]:
    """Collapse repeats of one mistake into one record carrying `occurrences: N`.

    The count survives the collapse: it tells the curator which bullet is worth the context
    tax. The FIRST row of a key is the exemplar and keeps every other field (`pitfall_id`,
    `source_run`, any queue bookkeeping the drain stamped on it); later rows contribute their
    count and nothing else. Order is first-seen, and the result re-merges to itself, so either
    consuming seam can merge without caring whether the other already did.
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
    """ONE arrival condition, at both readers (#870 FK-3) — `pitfalls_curator.run_pitfalls`'
    tick gate and `drains._has_lead_author_work`' wake gate.

    The DISTINCT COUNT of merged records reaching the threshold, every record included and
    systemless ones with them, EXACTLY AS BEFORE — **or** some REDUCER record carrying
    `occurrences >= threshold` on its own.

    "Reducer record" is `is_reducer_row`, the lane's one spelling, and FK-3's own `system == ""`
    is what that replaces. The two agree on every row `collect_general_failures` has minted
    since M5′, which normalizes `system` to `""`; they disagree on the population `run_pitfalls`
    names in its own comment — rows queued BEFORE M5′ deployed, which still carry the system
    their payload was attributed to. Under the narrower spelling such a row was routed to the
    reducer surface by every other seam and yet could never open the lane on its own
    occurrences, so the round's own motivating incident (one unchanging `Binder Error` under
    eight varied attempts against one attributed envelope) sat in the queue untaught — the exact
    unreachability FK-3 was added to close. Asking the routing predicate is what makes the gate
    and the routing one decision.

    The disjunct is ADDED; nothing is removed. It exists because the count alone was
    anti-correlated with evidence quality on the reducer lane: the round's motivating incident
    is ONE merged record (one unchanging `Binder Error` under eight varied attempts), which
    could never clear a threshold of 3 alone, while N silent failures carrying no diagnosis
    ARE N records and did. And the narrower encoding — a systemless record leaving the count
    entirely — was rejected: it would silently raise the SYSTEM lane's own bar, which this is
    not the decision to make. A content-less digest keys to `(system, "\\x00" + pitfall_id)`,
    unique per row, so no number of silent failures ever satisfies the new disjunct.
    """
    if len(records) >= threshold:
        return True
    return any(is_reducer_row(r) and _occurrences(r) >= threshold for r in records)


def append_pitfalls(rows: list[dict], *, paths: LoopPaths = DEFAULT_PATHS) -> int:
    """Append the failing rows verbatim. The COLLAPSE happens on the way out.

    Deliberately not deduplicating here: exactly one function in `learning/` rewrites a queue
    file wholesale — the merging rotation — so an appender that bumped a count on a row
    already on disk would be the second, racing the drain's read-modify-write window for no
    gain. The queue stays the evidence, one line per failure.

    `merge_pitfalls` collapses it at both consuming seams — the curation threshold
    (`pitfalls_curator.run_pitfalls`, `drains._has_lead_author_work`) and the curator's
    handoff. A reader that counts these rows is counting failures, never lessons.
    """
    if not rows:
        return 0
    with queue_lock(paths.pitfalls.append_lock):
        return append_jsonl(paths.pitfalls.file, rows)


def read_pitfalls(paths: LoopPaths = DEFAULT_PATHS) -> list[dict]:
    return read_jsonl_rows(paths.pitfalls.file)


def rotate_pitfalls(
    batch_ids: list[str], commit_sha: str | None, *, paths: LoopPaths = DEFAULT_PATHS,
    category: str = "consumed_committed",
) -> None:
    ids = set(batch_ids)
    consumed = [
        {**r, "consumed_category": category}
        for r in read_jsonl_rows(paths.pitfalls.file)
        if r.get("pitfall_id") in ids
    ]
    rotate_queue_locked(
        pending_file=paths.pitfalls.file,
        consumed_file=paths.pitfalls.consumed,
        lock_file=paths.pitfalls.append_lock,
        id_key=paths.pitfalls.id_key,
        held=[],
        consumed=consumed,
        commit_sha=commit_sha,
    )
















