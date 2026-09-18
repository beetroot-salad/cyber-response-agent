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
exactly the evidence it exists to show. A file that cannot be read at all counts as one.

THE CONTRACT IS THE TYPED BOUNDARY. Everything under the state root is disk a person or a
foreign copy may have edited, so every value this module emits is coerced to the type the
contract names — a string, an int, a list of strings, a mapping, or null — and the renderer
never converts, slices or `.get()`s a value off disk. A record that carries the wrong type
degrades to its typed shape (`""`, `0`, `[]`, `{}`, null); nothing here raises on content.
"""
from __future__ import annotations

import datetime as _dt
from collections.abc import Callable
from dataclasses import dataclass
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
    that lane's fault counter and says nothing about holds. A counter that is not an int is a
    row nothing has counted."""
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


@dataclass(frozen=True)
class _ChannelSpec:
    name: str
    #: The run-visualizer accent the card takes (`.q-card.t-<accent>` in the page's CSS).
    accent: str
    #: Whether this lane writes a stuck record at all. The pitfalls lane retires the whole
    #: batch on any non-systemic fault, so its `stuck: null` is structural, not "no fault yet".
    has_stuck_record: bool
    #: What a hold MEANS in this lane, as the page says it. The two lanes' holds end
    #: differently: a findings hold waits on a fact with no writer and nothing retries it; a
    #: pitfalls hold is re-offered to the curator every tick and retires at the offer ceiling.
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
        "id": _opt_str(rid),
        "reason": _str(record.get("deadletter_reason")),
        "when": _opt_str(record.get("retired_at")),
        "row": row if isinstance(row, dict) else {"value": row},
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
    """The canonical tolerant reader, plus the one tolerance it does not have: a sidecar that
    cannot be READ (permissions, a bad disk) is one unreadable, not an aborted page."""
    try:
        return read_jsonl_rows_report(path)
    except TEXT_READ_ERRORS:
        return [], 1


def _channel_view(spec: _ChannelSpec, channel: QueueChannel) -> dict:
    rows, unreadable = _rows(channel.file)
    held_ids = [r[channel.id_key] for r in rows
                if spec.is_held(r) and isinstance(r.get(channel.id_key), str)]
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
        "held": {"count": len(held_ids), "ids": held_ids},
        "deadletter": [_dead_letter(rec, channel.id_key) for rec in reversed(graveyard)],
        "stuck": stuck,
    }


def _json_files(directory: Path) -> tuple[list[tuple[Path, dict]], int]:
    """Every readable `*.json` mapping directly under `directory`, plus how many were not.

    A file that does not decode, or decodes to something other than a mapping, is one
    unreadable — the same tolerance the sidecar reader gives a torn line. A directory that
    cannot be listed is one unreadable and no files."""
    try:
        if not directory.is_dir():
            return [], 0
        found = sorted(directory.glob("*.json"))
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
    """The tainted-worktree archive. The ROWS are read by manifest — the tarball beside each
    is inert and stays that way; unpacking is a deliberate operator act (#747) — but `held`
    is the writer's own count of ARCHIVES against its cap, because the two differ in exactly
    the case the page exists to show: an archive whose manifest was never written or is torn
    still spends a slot. `held` is null when the directory cannot be listed, so the page says
    "?" rather than a headroom that may not exist. `verdict` is carried as the writer stored
    it: `{}` means no scan was recorded, which must not read as clean. The directory is named
    because it lives off the repo root, not the state root, and the header names only the
    latter."""
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


def build_view(paths: LoopPaths) -> dict:  # lint-dup: ok — serialize.build_view walks the checked-in corpus for the lessons page; this walks the host-local state root for the queue page. Same name by design: the two are the frontend's two api layers, and build.py calls each by module.
    """The contract, pure over the filesystem under `paths`. No clock: `stamped_view` adds
    `generated_at` so a test of the shape is not a test of the time."""
    return {
        "state_root": str(paths.state_root),
        "channels": [_channel_view(spec, spec.channel(paths)) for spec in _CHANNELS],
        "quarantine": {
            "markers": _markers(paths),
            "deliveries": _deliveries(paths),
            "tainted": _tainted(paths),
        },
    }


def stamped_view(paths: LoopPaths | None = None) -> dict:  # lint-dup: ok — serialize.stamped_view stamps the lessons view; this stamps the queue view over loop_paths(). Same name by design, see build_view.
    """`build_view` plus the build time. With no `paths`, the state root is resolved NOW —
    `loop_paths()`, not the import-time constant, because the CLI is exactly the caller that
    must honour a root set after import. A test hands its own `LoopPaths` so nothing here
    reads the developer's real quarantine directory."""
    view = build_view(paths if paths is not None else loop_paths())
    view["generated_at"] = z_seconds(_dt.datetime.now(_dt.UTC))
    return view

