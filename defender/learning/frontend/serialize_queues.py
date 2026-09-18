"""The queue-state view (#903): what the learning loop gave up on, parked, or set aside.

The lessons view (`serialize.py`) reads the checked-in corpus and describes the loop's
POSTURE; this one reads the host-local state root and describes its BACKLOG — the three
channels' dead letters, stuck records and held rows, plus what the drains quarantined. It is
per-host and stale the moment it is built, which is why the contract names the state root
and the CLI stamps the time.

THE CHANNELS ARE A LITERAL LIST, never derived. #922's cutover records the trap: a stage
that discovered its channels by iterating another table was silently narrowed when that
table was deleted, with no error and no failing test. `_CHANNELS` is this page's own census;
`drains._curator_queue_checks` answers a different question ("which queues wake the drain")
and keeps its own.

Every JSONL sidecar goes through the canonical tolerant reader, and a line it cannot parse is
COUNTED rather than dropped — a page that silently skipped a torn dead letter would lose
exactly the evidence it exists to show.
"""
from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from defender._io import (
    TEXT_READ_ERRORS,
    load_json_artifact,
    read_jsonl_rows_report,
    read_text_utf8,
)
from defender.learning.author import drain
from defender.learning.author.branch import AuthorBranch
from defender.learning.core.config import LoopPaths, QueueChannel, loop_paths
from defender.learning.core.markers import FAILED_MARKER_DIRNAME
from defender.learning.core.quarantine import quarantine_cap
from defender.learning.frontend.serialize import dump_contract
from defender.learning.leads.pitfalls_curator import OFFERS_DECLINED_KEY

__all__ = ["build_view", "stamped_view", "dump_contract"]


def _held_by_reason(row: dict) -> bool:
    """The findings-shaped lanes' marker: PRESENCE of `held_reason`, never truthiness — the
    same rule `drains._pending_queue_counts` applies, because a holder with no wording to give
    stamps `""` and is still holding the row."""
    return "held_reason" in row


def _held_by_declined_offer(row: dict) -> bool:
    """The pitfalls lane's marker: a row the curator was OFFERED and declined. `attempts` is
    that lane's fault counter and says nothing about holds."""
    return int(row.get(OFFERS_DECLINED_KEY) or 0) > 0


@dataclass(frozen=True)
class _ChannelSpec:
    name: str
    #: The run-visualizer accent the card takes (`section.stage-<accent>` in styles.css).
    accent: str
    #: Whether this lane writes a stuck record at all. The pitfalls lane retires the whole
    #: batch on any non-systemic fault, so its `stuck: null` is structural, not "no fault yet".
    has_stuck_record: bool
    is_held: Any


_CHANNELS: tuple[tuple[_ChannelSpec, Any], ...] = (
    (_ChannelSpec("findings", "defender", True, _held_by_reason), lambda p: p.findings),
    (_ChannelSpec("questioner_findings", "learning", True, _held_by_reason),
     lambda p: p.questioner_findings),
    (_ChannelSpec("pitfalls", "oracle", False, _held_by_declined_offer), lambda p: p.pitfalls),
)

#: The three bookkeeping fields a FLAT graveyard record carries beside the row's own content.
#: Nested records keep them at the top level too, but there the row is under `row`.
_GRAVEYARD_FIELDS = ("deadletter_reason", "attempts", "retired_at")


def _dead_letter(record: dict, id_key: str) -> dict:
    """One graveyard record, either writer's shape, as the contract's four fields.

    A record WITH `row` is the nested shape (`drain.retire`, `_graveyard_dropped_rows`): the
    id sits beside it under the channel's key. One WITHOUT is `_retire_unkeyable`'s flat
    shape — the row had no id, so the content is the record and `id` is null. `when` is the
    writer's `retired_at`, null on a record older than that stamp."""
    if "row" in record:
        rid = record.get(id_key)
        row = record["row"]
    else:
        rid = None
        row = {k: v for k, v in record.items() if k not in _GRAVEYARD_FIELDS}
    return {
        "id": rid if isinstance(rid, str) else None,
        "reason": str(record.get("deadletter_reason") or ""),
        "when": record.get("retired_at") if isinstance(record.get("retired_at"), str) else None,
        "row": row if isinstance(row, dict) else {"value": row},
    }


def _channel_view(spec: _ChannelSpec, channel: QueueChannel) -> dict:
    rows, unreadable = read_jsonl_rows_report(channel.file)
    held_ids = [str(r[channel.id_key]) for r in rows
                if spec.is_held(r) and isinstance(r.get(channel.id_key), str)]
    graveyard, dead_unreadable = read_jsonl_rows_report(drain.graveyard_file(channel))
    unreadable += dead_unreadable
    stuck: dict | None = None
    if spec.has_stuck_record:
        records, stuck_unreadable = read_jsonl_rows_report(drain.stuck_report_file(channel))
        unreadable += stuck_unreadable
        stuck = records[-1] if records else None
    return {
        "name": spec.name,
        "accent": spec.accent,
        "has_stuck_record": spec.has_stuck_record,
        "depth": {"queued": len(rows)},
        "unreadable": unreadable,
        "held": {"count": len(held_ids), "ids": held_ids},
        "deadletter": [_dead_letter(rec, channel.id_key) for rec in reversed(graveyard)],
        "stuck": stuck,
    }


def _json_files(directory: Path) -> tuple[list[tuple[Path, dict]], int]:
    """Every readable `*.json` mapping directly under `directory`, plus how many were not.

    A file that does not decode, or decodes to something other than a mapping, is one
    unreadable — the same tolerance the sidecar reader gives a torn line."""
    if not directory.is_dir():
        return [], 0
    out: list[tuple[Path, dict]] = []
    unreadable = 0
    for path in sorted(directory.glob("*.json")):
        try:
            value, err = load_json_artifact(read_text_utf8(path))
        except TEXT_READ_ERRORS:
            unreadable += 1
            continue
        if err is not None or not isinstance(value, dict):
            unreadable += 1
            continue
        out.append((path, value))
    return out, unreadable


def _opt_str(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _markers(paths: LoopPaths) -> dict:
    """Both failed-marker directories. `quarantine_marker` writes under its CALLER's queue dir,
    and it has two callers: the lead-author claim (`author_queue_dir`) and the pending-delivery
    scan (`pending_delivery_dir`). A page reading one omits the other's terminal records."""
    rows: list[dict] = []
    unreadable = 0
    for queue, directory in (
        ("lead_author", paths.author_queue_dir / FAILED_MARKER_DIRNAME),
        ("delivery", paths.pending_delivery_dir / FAILED_MARKER_DIRNAME),
    ):
        found, bad = _json_files(directory)
        unreadable += bad
        rows += [
            {"queue": queue, "identity": path.stem, "failed": str(spec.get("failed") or ""),
             "run_dir": _opt_str(spec.get("run_dir"))}
            for path, spec in found
        ]
    rows.sort(key=lambda r: (r["queue"], r["identity"]))
    return {"rows": rows, "unreadable": unreadable}


def _deliveries(paths: LoopPaths) -> dict:
    found, unreadable = _json_files(paths.pending_delivery_dir)
    rows = [
        {"branch": str(spec.get("branch") or ""), "batch_id": str(spec.get("batch_id") or ""),
         "label": str(spec.get("label") or ""), "at": _opt_str(spec.get("at")),
         "reason": str(spec.get("reason") or "")}
        for _path, spec in found
    ]
    rows.sort(key=lambda r: str(r["at"] or ""), reverse=True)
    return {"rows": rows, "unreadable": unreadable}


def _tainted(paths: LoopPaths) -> dict:
    """The tainted-worktree archive, by manifest only — the tarball beside each is inert and
    stays that way; unpacking is a deliberate operator act (#747). `verdict` is carried as the
    writer stored it: `{}` means no scan was recorded, which must not read as clean."""
    found, unreadable = _json_files(AuthorBranch(repo_root=paths.repo_root).quarantine_dir)
    rows: list[dict] = []
    for _path, m in found:
        findings = m.get("findings")
        verdict = m.get("verdict")
        rows.append({
            "batch_id": str(m.get("batch_id") or ""),
            "archive": str(m.get("archive") or ""),
            "quarantined_at": _opt_str(m.get("quarantined_at")),
            "label": str(m.get("label") or ""),
            "taint": str(m.get("taint") or ""),
            "cause": _opt_str(m.get("cause")),
            "verdict": verdict if isinstance(verdict, dict) else {},
            "findings": len(findings) if isinstance(findings, list) else 0,
        })
    rows.sort(key=lambda r: str(r["quarantined_at"] or ""), reverse=True)
    return {"cap": quarantine_cap(), "rows": rows, "unreadable": unreadable}


def build_view(paths: LoopPaths) -> dict:  # lint-dup: ok — serialize.build_view walks the checked-in corpus for the lessons page; this walks the host-local state root for the queue page. Same name by design: the two are the frontend's two api layers, and build.py calls each by module.
    """The contract, pure over the filesystem under `paths`. No clock: `stamped_view` adds
    `generated_at` so a test of the shape is not a test of the time."""
    return {
        "state_root": str(paths.state_root),
        "channels": [_channel_view(spec, pick(paths)) for spec, pick in _CHANNELS],
        "quarantine": {
            "markers": _markers(paths),
            "deliveries": _deliveries(paths),
            "tainted": _tainted(paths),
        },
    }


def stamped_view() -> dict:  # lint-dup: ok — serialize.stamped_view stamps the lessons view; this stamps the queue view over loop_paths(). Same name by design, see build_view.
    """`build_view` over the state root resolved NOW — `loop_paths()`, not the import-time
    constant, because the CLI is exactly the caller that must honour a root set after
    import — plus the build time."""
    view = build_view(loop_paths())
    view["generated_at"] = _dt.datetime.now(_dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    return view

