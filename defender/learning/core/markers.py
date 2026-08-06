from __future__ import annotations

import contextlib
import json
from pathlib import Path

from defender._io import write_atomic
from defender.learning.core.config import DEFAULT_PATHS, LoopPaths, _log


def _enqueue_marker(run_dir: Path, queue_dir: Path, label: str) -> None:
    queue_dir.mkdir(parents=True, exist_ok=True)
    marker = queue_dir / f"{run_dir.name}.json"
    write_atomic(
        marker,
        json.dumps({"run_id": run_dir.name, "run_dir": str(run_dir.resolve())}) + "\n",
    )
    _log(f"enqueued for {label}: {marker}")


def enqueue_for_authoring(run_dir: Path, paths: LoopPaths) -> None:
    _enqueue_marker(run_dir, paths.author_queue_dir, "authoring")


def enqueue_case_for_curation(case_id: str, run_dir: Path, paths: LoopPaths) -> None:
    """The curation trigger's own marker (#791) — keyed on the CASE rather than the run id,
    so two investigations of the same case coalesce onto one request (an atomic replace of
    the same path) instead of leaving one per retry. The later run always wins: whichever
    call lands last is the one the curator serves."""
    queue_dir = paths.author_queue_dir
    queue_dir.mkdir(parents=True, exist_ok=True)
    marker = queue_dir / f"{case_id}.json"
    write_atomic(
        marker,
        json.dumps({"case_id": case_id, "run_dir": str(run_dir.resolve())}) + "\n",
    )
    _log(f"enqueued for curation: {marker}")


def enqueue_for_learning(run_dir: Path, paths: LoopPaths = DEFAULT_PATHS) -> None:
    _enqueue_marker(run_dir, paths.learn_queue_dir, "learning")


def rewrite_marker(marker: Path, spec: dict) -> None:
    write_atomic(marker, json.dumps(spec) + "\n")


def marker_identity(spec: dict, marker: Path) -> str:
    """The id an operator greps for when a queued request is dropped or deferred.

    The queue carries TWO row shapes — the run-keyed marker (`run_id`) and #791's case-keyed
    curation request (`case_id`) — and a log line that names one key reads `None` for every
    row of the other shape, which is exactly the case a dead-letter line exists to surface.
    The marker's own filename is the identity under both shapes, so it is the last resort for
    a row too damaged to carry either key."""
    for key in ("case_id", "run_id"):
        value = spec.get(key)
        if isinstance(value, str) and value:
            return value
    return marker.stem


def quarantine_marker(spec: dict, marker: Path, queue_dir: Path, reason: str) -> None:
    failed_dir = queue_dir / "failed"
    failed_dir.mkdir(parents=True, exist_ok=True)
    rec = dict(spec)
    rec["failed"] = reason
    (failed_dir / marker.name).write_text(json.dumps(rec) + "\n", encoding="utf-8")
    with contextlib.suppress(OSError):
        marker.unlink()
    _log(f"quarantined {marker_identity(spec, marker)} — {reason}")
