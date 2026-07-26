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


def enqueue_for_learning(run_dir: Path, paths: LoopPaths = DEFAULT_PATHS) -> None:
    _enqueue_marker(run_dir, paths.learn_queue_dir, "learning")


def rewrite_marker(marker: Path, spec: dict) -> None:
    write_atomic(marker, json.dumps(spec) + "\n")


def quarantine_marker(spec: dict, marker: Path, queue_dir: Path, reason: str) -> None:
    failed_dir = queue_dir / "failed"
    failed_dir.mkdir(parents=True, exist_ok=True)
    rec = dict(spec)
    rec["failed"] = reason
    (failed_dir / marker.name).write_text(json.dumps(rec) + "\n", encoding="utf-8")
    with contextlib.suppress(OSError):
        marker.unlink()
    _log(f"quarantined {spec.get('run_id')} — {reason}")
