"""#1278 Migration: today's file learning state, planted as base writes it, for the import and the cutover.

Chosen: BYTES, not `LearningState`. A1/O10 delete the handle at cutover, so a planter calling it would
break the day the code stage lands. Record names below are state.py:64-170 (`_QUEUE`, `_INFLIGHT`, `_FAILED`,
`_DELIVERY`, the three `Channel`s); row shapes are what `author/drain.py` (`_bump_rows` nests the row under
`row`, `_retire_unkeyable` spreads it flat), `state.rotate` (`consumed_at`, `consumed_commit` only for
`consumed_committed`), `drains._record_pending_delivery` and `version_control/record._record_made` write.
Git and forge state is planted with git plumbing and the delivery fake's rows, never the delivery objects
whose writes the code stage moves into the database. Nothing here implements import policy.
"""
from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

PENDING = "_pending"
PENDING_LEADS = "_pending_leads"
PENDING_PITFALLS = "_pending_pitfalls"
QUEUE = "author-queue"
DELIVERY = "_pending_delivery"
COMMIT_RECORD = "commit-maker.jsonl"
STAMP = "2026-11-01T00:00:00Z"

#: kind -> (queue, consumed ledger, dead-letter, stuck report, row key) record names (state.py:126-170).
CHANNELS: dict[str, dict[str, str]] = {
    "finding": {"queue": f"{PENDING}/findings.jsonl", "consumed": f"{PENDING}/consumed.jsonl",
                "deadletter": f"{PENDING}/findings.deadletter.jsonl", "stuck": f"{PENDING}/findings.stuck.jsonl",
                "key": "finding_id"},
    "questioner_finding": {"queue": f"{PENDING}/questioner_findings.jsonl",
                           "consumed": f"{PENDING}/questioner_consumed.jsonl",
                           "deadletter": f"{PENDING}/questioner_findings.deadletter.jsonl",
                           "stuck": f"{PENDING}/questioner_findings.stuck.jsonl", "key": "finding_id"},
    "pitfall": {"queue": f"{PENDING_PITFALLS}/pitfalls.jsonl", "consumed": f"{PENDING_PITFALLS}/pitfalls.consumed.jsonl",
                "deadletter": f"{PENDING_PITFALLS}/pitfalls.deadletter.jsonl",
                "stuck": f"{PENDING_PITFALLS}/pitfalls.stuck.jsonl", "key": "pitfall_id"},
}


def _append(root: Path, name: str, rows: Iterable[dict[str, Any]]) -> None:
    path = Path(root) / name
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as out:
        out.writelines(json.dumps(row) + "\n" for row in rows)


def _write_json(root: Path, name: str, body: dict[str, Any]) -> None:
    path = Path(root) / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(body) + "\n", encoding="utf-8")


def world_finding(fid: str) -> dict[str, Any]:
    """A questioner-channel (world) finding row."""
    from defender.tests.support.learning.curation._spec773 import world_row

    return world_row(fid)


def pitfall(pid: str) -> dict[str, Any]:
    """A pitfalls-queue row (`_drain719.row_for`)."""
    from defender.tests.support.learning.curation._drain719 import row_for

    return row_for("pitfalls", pid)


def queue(root: Path, kind: str, rows: Iterable[dict[str, Any]]) -> None:
    """Append `rows` to the kind's queue file (a held row is simply a row with `held_reason`)."""
    _append(root, CHANNELS[kind]["queue"], rows)


def consumed(root: Path, kind: str, rows: Iterable[dict[str, Any]], category: str, *,
             commit: str | None = None, **extra: Any) -> None:
    """Append `rows` to the kind's consumed ledger under `category`; `extra` is the category's own field
    (`skip_reason`, `held_reason`)."""
    stamped = {"consumed_category": category, "consumed_at": STAMP, **extra}
    if category == "consumed_committed":
        stamped["consumed_commit"] = commit or "0" * 40
    _append(root, CHANNELS[kind]["consumed"], ({**row, **stamped} for row in rows))


def deadletter(root: Path, kind: str, rows: Iterable[dict[str, Any]], reason: str, *, attempts: int = 3,
               flat: bool = False) -> None:
    """Append dead-letter records. Nested (`_bump_rows`): `{<key>, attempts, deadletter_reason, retired_at,
    row}`. Flat (`_retire_unkeyable`): the row's fields at top level beside `attempts`, the reason and the stamp."""
    key = CHANNELS[kind]["key"]
    stamp = {"deadletter_reason": reason, "retired_at": STAMP}
    if flat:
        records = [{**row, "attempts": attempts, **stamp} for row in rows]
    else:
        records = [{key: row.get(key), "attempts": attempts, **stamp, "row": row} for row in rows]
    _append(root, CHANNELS[kind]["deadletter"], records)


def stuck(root: Path, kind: str, ids: Sequence[str]) -> None:
    """A stuck-report record naming `ids` (`author/drain._record_stuck`)."""
    _append(root, CHANNELS[kind]["stuck"], [{
        "fault_class": "AuthorError", "row_ids": list(ids), "consecutive_ticks": 2,
        "reason": "planted", "recorded_at": STAMP}])


def request(root: Path, case_id: str, run_id: str, tenant_id: str, *, where: str = "queued",
            failed: str | None = None) -> None:
    """A curation request `{case_id, tenant_id, run_id}` at `author-queue/<case>.json` (`where` queued),
    `author-queue/inflight/` or `author-queue/failed/` (which adds `failed`: the reason)."""
    folder = {"queued": QUEUE, "inflight": f"{QUEUE}/inflight", "failed": f"{QUEUE}/failed"}[where]
    body: dict[str, Any] = {"case_id": case_id, "tenant_id": tenant_id, "run_id": run_id}
    if failed is not None:
        body["failed"] = failed
    _write_json(root, f"{folder}/{case_id}.json", body)


def pending_delivery(root: Path, batch_id: str, branch: str, *, label: str = "author_drain",
                     failed: str | None = None) -> str:
    """A retained delivery record (`drains._record_pending_delivery`); with `failed`, its quarantined form
    under `_pending_delivery/failed/` (`{failed: reason}` only, `state.quarantine_delivery`). Returns its id."""
    slug = "lessons" if label == "author_drain" else "lead-author"
    record_id = f"{slug}-{batch_id}"
    if failed is not None:
        _write_json(root, f"{DELIVERY}/failed/{record_id}.json", {"failed": failed})
    else:
        _write_json(root, f"{DELIVERY}/{record_id}.json", {
            "branch": branch, "batch_id": batch_id, "label": label, "reason": "push refused", "at": STAMP})
    return record_id


def commit_row(commit: str, branch: str, base: str, start: str, *, lanes: Sequence[str] = ("lessons",),
               changes: Sequence[tuple[str, str | None, str | None]] = (),
               reverts: tuple[dict[str, str], str] | None = None) -> dict[str, Any]:
    """One commit-maker record row (`record._record_made`); `reverts` is `(target batch key, path)`."""
    row: dict[str, Any] = {
        "commit": commit, "batch": {"branch": branch, "base": base, "start": start}, "lanes": list(lanes),
        "changes": [{"path": p, "before": b, "after": a} for p, b, a in changes]}
    if reverts is not None:
        row["reverts"] = {"batch": reverts[0], "path": reverts[1]}
    return row


def commit_record(root: Path, rows: Iterable[dict[str, Any]]) -> None:
    """Append rows to `<root>/commit-maker.jsonl`, sorted keys, as `_record_made` writes them."""
    path = Path(root) / COMMIT_RECORD
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as out:
        out.writelines(json.dumps(row, sort_keys=True) + "\n" for row in rows)


def leftovers(root: Path, *, trace: bytes, worktree: bytes) -> None:
    """What else base leaves in the tree: lock files, per-call traces under both stage folders (`wire_logs/`),
    a batch worktree with a file of `worktree` bytes."""
    root = Path(root)
    for name in (".author-drain.lock", ".lead-author-drain.lock", "_author.lock", f"{PENDING}/.lock",
                 f"{PENDING_LEADS}/.lock", f"{PENDING}/.findings.lock"):
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_bytes(b"")
    for stage in (PENDING, PENDING_LEADS):
        (root / stage / "wire_logs").mkdir(parents=True, exist_ok=True)
        (root / stage / "wire_logs" / "curator.jsonl").write_bytes(trace)
    (root / "worktrees" / "b1").mkdir(parents=True, exist_ok=True)
    (root / "worktrees" / "b1" / "draft.md").write_bytes(worktree)


# -- git and forge state of a published tenant `t` (tests/tenancy/tenant_1108_p4/_support.PublishedTenant) -----


def land_on_main(t: Any, files: dict[str, str]) -> str:
    """A merged change: `files` (repo-relative path -> text) committed on `main` of the clone and the origin.
    Returns the new `main`."""
    from defender.tests.tenancy.tenant_1108_delivery._support import plant_raw_commit
    from defender.tests.tenancy.tenant_1108_p4._support import git

    tip = ""
    for path, text in files.items():
        tip = plant_raw_commit(t.clone, "refs/heads/main", path, text.encode("utf-8"))
    git(t.clone, "push", "-q", t.remote, "refs/heads/main:refs/heads/main")
    return tip


def local_branch(t: Any, branch: str, files: dict[str, str], *, push: bool = False) -> str:
    """`branch` (a ref in the clone) one commit past `main` writing `files`; pushed to the origin when `push`.
    Returns its tip."""
    from defender.tests.tenancy.tenant_1108_delivery._support import plant_raw_commit
    from defender.tests.tenancy.tenant_1108_p4._support import git

    ref, tip = f"refs/heads/{branch}", ""
    for path, text in files.items():
        tip = plant_raw_commit(t.clone, ref, path, text.encode("utf-8"), base="refs/heads/main")
    if push:
        git(t.clone, "push", "-q", t.remote, f"{ref}:{ref}")
    return tip


def open_pr(t: Any, number: int, branch: str, files: dict[str, str]) -> str:
    """An open PR of ours numbered `number` from a pushed `branch` carrying `files`. Returns the branch tip."""
    from defender.tests.tenancy.tenant_1108_delivery._support import pr_row

    tip = local_branch(t, branch, files, push=True)
    t.forge.add_pr(pr_row(number, branch, sha=tip))
    return tip


def closed_pr(t: Any, number: int, branch: str, *, merged: bool) -> None:
    """A PR of ours already closed (merged or rejected) on `branch`."""
    from defender.tests.tenancy.tenant_1108_delivery._support import pr_row

    t.forge.add_pr(pr_row(number, branch, merged=merged, state="closed"))
