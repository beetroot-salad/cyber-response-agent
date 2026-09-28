"""The queue-state view: what the learning loop gave up on, parked, or set aside.

Reads the host-local state root (unlike `serialize.py`, which reads the checked-in corpus):
the three channels' dead letters, stuck records and held rows, plus what the drains
quarantined. Per-host and stale once built, so the contract names the state root and the CLI
stamps the time.

The channels are a literal list, never derived from another table, so deleting that table
cannot silently narrow this page. `drains._curator_queue_checks` answers a different question
("which queues wake the drain") and keeps its own.

A JSONL line that cannot be parsed is counted, not dropped (a torn dead letter is exactly the
evidence this page shows); an unreadable file counts as one.

The contract is the typed boundary: state-root files may be hand-edited, so every emitted value
is coerced to its contract type (string, int, list of strings, mapping, or null) and degrades to
the empty value on a mismatch. Nothing raises on content, and the renderer never converts.
"""
from __future__ import annotations

import datetime as _dt
from collections.abc import Callable
from defender._model import model
from pathlib import Path

from defender._clock import z_seconds
from defender._io import (
    TEXT_READ_ERRORS,
    load_json_artifact,
    read_jsonl_rows_report,
    read_text_utf8,
)
from defender.learning.author import drain
from defender.learning.core.config import LoopPaths, QueueChannel, loop_paths
from defender.learning.core.markers import FAILED_MARKER_DIRNAME
from defender.learning.core.quarantine import held_archives, quarantine_cap
from defender.learning.frontend.serialize import _json_safe, dump_contract
from defender.learning.core.pitfalls_disposition import OFFERS_DECLINED_KEY

__all__ = ["build_view", "stamped_view", "dump_contract"]


def _held_by_reason(row: dict) -> bool:
    """The findings-shaped lanes' marker: presence of `held_reason`, never truthiness (a holder
    may stamp `""`) — the rule `drains._pending_queue_counts` applies."""
    return "held_reason" in row


def _held_by_declined_offer(row: dict) -> bool:
    """The pitfalls lane's marker: a row the curator was offered and declined (`attempts` is a
    fault counter, not a hold)."""
    return _int_or_zero(row.get(OFFERS_DECLINED_KEY)) > 0


# The coercions. Each answers with the contract's type or its empty value, never raises.
def _str(value: object) -> str:
    return value if isinstance(value, str) else ""


def _opt_str(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _int_or_zero(value: object) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _str_list(value: object) -> list[str]:
    return [v for v in value if isinstance(v, str)] if isinstance(value, list) else []


@model(frozen=True)
class _ChannelSpec:
    name: str
    #: The run-visualizer accent the card takes (`.q-card.t-<accent>` in the page's CSS).
    accent: str
    #: Whether this lane writes a stuck record at all. The pitfalls lane retires the whole
    #: batch on any non-systemic fault, so its `stuck: null` is structural, not "no fault yet".
    has_stuck_record: bool
    #: What a hold means in this lane, as the page says it (the lanes' holds end differently).
    hold_means: str
    is_held: Callable[[dict], bool]
    channel: Callable[[LoopPaths], QueueChannel]


_CHANNELS: tuple[_ChannelSpec, ...] = (
    _ChannelSpec(
        "findings", "defender", True,
        "held until a person moves them — nothing retries a hold",
        _held_by_reason, lambda p: p.findings,
    ),
    _ChannelSpec(
        "questioner_findings", "learning", True,
        "held until a person moves them — nothing retries a hold",
        _held_by_reason, lambda p: p.questioner_findings,
    ),
    _ChannelSpec(
        "pitfalls", "oracle", False,
        "declined by the curator — offered again every tick, retired at the offer ceiling",
        _held_by_declined_offer, lambda p: p.pitfalls,
    ),
)

#: The three bookkeeping fields a FLAT graveyard record carries beside the row's own content.
#: Nested records keep them at the top level too, but there the row is under `row`.
_GRAVEYARD_FIELDS = ("deadletter_reason", "attempts", "retired_at")


def _dead_letter(record: dict, id_key: str) -> dict:
    """One graveyard record, either writer's shape, as the contract's four fields.

    With `row`: the nested shape, id beside it under the channel's key. Without: the flat shape
    of an unkeyable row, so `id` is null. `when` is null on records older than `retired_at`."""
    if "row" in record:
        rid = record.get(id_key)
        row = record["row"]
    else:
        rid = None
        row = {k: v for k, v in record.items() if k not in _GRAVEYARD_FIELDS}
    return {
        "id": _opt_str(rid),
        "reason": _str(record.get("deadletter_reason")),
        "when": _opt_str(record.get("retired_at")),
        # The one untyped mapping in the contract; JSON-safed because `json.loads` accepts a
        # bare `NaN`, which would make `queues.json` unreadable to strict readers.
        "row": _json_safe(row if isinstance(row, dict) else {"value": row}),
    }


def _stuck(record: dict) -> dict:
    """`drain._record_stuck`'s record as the contract's five typed fields. `recorded_at` is
    null on a record older than that stamp."""
    return {
        "fault_class": _str(record.get("fault_class")),
        "row_ids": _str_list(record.get("row_ids")),
        "consecutive_ticks": _int_or_zero(record.get("consecutive_ticks")),
        "reason": _str(record.get("reason")),
        "recorded_at": _opt_str(record.get("recorded_at")),
    }


def _rows(path: Path) -> tuple[list[dict], int]:
    """The canonical tolerant reader, plus: a sidecar that cannot be read at all counts as one
    unreadable rather than aborting the page."""
    try:
        return read_jsonl_rows_report(path)
    except TEXT_READ_ERRORS:
        return [], 1


def _channel_view(spec: _ChannelSpec, channel: QueueChannel) -> dict:
    rows, unreadable = _rows(channel.file)
    # Counted by the lane's marker alone (matching the drain's wake gate); only string ids are
    # listed, but a held row without one is still counted.
    held_rows = [r for r in rows if spec.is_held(r)]
    held_ids = [r[channel.id_key] for r in held_rows if isinstance(r.get(channel.id_key), str)]
    graveyard, dead_unreadable = _rows(drain.graveyard_file(channel))
    unreadable += dead_unreadable
    stuck: dict | None = None
    if spec.has_stuck_record:
        records, stuck_unreadable = _rows(drain.stuck_report_file(channel))
        unreadable += stuck_unreadable
        stuck = _stuck(records[-1]) if records else None
    return {
        "name": spec.name,
        "accent": spec.accent,
        "has_stuck_record": spec.has_stuck_record,
        "hold_means": spec.hold_means,
        "depth": {"queued": len(rows)},
        "unreadable": unreadable,
        "held": {"count": len(held_rows), "ids": held_ids},
        "deadletter": [_dead_letter(rec, channel.id_key) for rec in reversed(graveyard)],
        "stuck": stuck,
    }


def _json_files(directory: Path) -> tuple[list[tuple[Path, dict]], int]:
    """Every readable `*.json` mapping directly under `directory`, plus how many were not.

    An unlistable directory counts as one unreadable — listed with `iterdir` because
    `Path.glob` swallows the `PermissionError` and answers "empty"."""
    try:
        if not directory.is_dir():
            return [], 0
        found = sorted(p for p in directory.iterdir() if p.name.endswith(".json"))
    except OSError:
        return [], 1
    out: list[tuple[Path, dict]] = []
    unreadable = 0
    for path in found:
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


def _markers(paths: LoopPaths) -> dict:
    """Both failed-marker directories: `quarantine_marker` writes under its caller's queue dir,
    and it has two callers (the lead-author claim and the pending-delivery scan)."""
    rows: list[dict] = []
    unreadable = 0
    for queue, directory in (
        ("lead_author", paths.author_queue_dir / FAILED_MARKER_DIRNAME),  # lint-run-records: ok — the lead-author role/drain/module's own name, not the `lead_author/` record dir
        ("delivery", paths.pending_delivery_dir / FAILED_MARKER_DIRNAME),
    ):
        found, bad = _json_files(directory)
        unreadable += bad
        rows += [
            {"queue": queue, "identity": path.stem, "failed": _str(spec.get("failed")),
             "run_dir": _opt_str(spec.get("run_dir"))}
            for path, spec in found
        ]
    rows.sort(key=lambda r: (r["queue"], r["identity"]))
    return {"rows": rows, "unreadable": unreadable}


def _deliveries(paths: LoopPaths) -> dict:
    found, unreadable = _json_files(paths.pending_delivery_dir)
    rows = [
        {"branch": _str(spec.get("branch")), "batch_id": _str(spec.get("batch_id")),
         "label": _str(spec.get("label")), "at": _opt_str(spec.get("at")),
         "reason": _str(spec.get("reason"))}
        for _path, spec in found
    ]
    rows.sort(key=lambda r: r["at"] or "", reverse=True)
    return {"rows": rows, "unreadable": unreadable}


def _tainted(paths: LoopPaths) -> dict:
    """The tainted-worktree archive.

    Rows come from manifests (tarballs stay inert; unpacking is an operator act), but `held` is
    the writer's own archive count against its cap: an archive with a missing or torn manifest
    still spends a slot. `held` is null when unlistable, so the page shows "?". `verdict: {}`
    means no scan was recorded, not clean. `dir` is included because it lives off the repo root,
    not the state root."""
    found, unreadable = _json_files(paths.quarantine_dir)
    try:
        held: int | None = held_archives(paths.quarantine_dir)
    except OSError:
        held = None
    rows: list[dict] = []
    for _path, m in found:
        findings = m.get("findings")
        verdict = m.get("verdict")
        rows.append({
            "batch_id": _str(m.get("batch_id")),
            "archive": _str(m.get("archive")),
            "quarantined_at": _opt_str(m.get("quarantined_at")),
            "label": _str(m.get("label")),
            "taint": _str(m.get("taint")),
            "cause": _opt_str(m.get("cause")),
            "verdict": verdict if isinstance(verdict, dict) else {},
            "findings": len(findings) if isinstance(findings, list) else 0,
        })
    rows.sort(key=lambda r: r["quarantined_at"] or "", reverse=True)
    return {
        "dir": str(paths.quarantine_dir), "cap": quarantine_cap(), "held": held,
        "rows": rows, "unreadable": unreadable,
    }


def build_view(paths: LoopPaths) -> dict:  # lint-dup: ok — serialize.build_view builds the lessons page from the corpus; this builds the queue page from the state root. Same name by design: build.py calls each by module.
    """The contract, pure over the filesystem under `paths`; no clock (see `stamped_view`)."""
    return {
        "state_root": str(paths.state_root),
        "channels": [_channel_view(spec, spec.channel(paths)) for spec in _CHANNELS],
        "quarantine": {
            "markers": _markers(paths),
            "deliveries": _deliveries(paths),
            "tainted": _tainted(paths),
        },
    }


def stamped_view(paths: LoopPaths | None = None) -> dict:  # lint-dup: ok — serialize.stamped_view stamps the lessons view; this stamps the queue view. Same name by design, see build_view.
    """`build_view` plus the build time. With no `paths`, the state root is resolved now
    (`loop_paths()`, not the import-time constant), so a root set after import is honoured."""
    view = build_view(paths if paths is not None else loop_paths())
    view["generated_at"] = z_seconds(_dt.datetime.now(_dt.UTC))
    return view

