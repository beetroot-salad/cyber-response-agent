from __future__ import annotations

import contextlib
import json
import logging
import os
from collections.abc import Iterator
from defender._model import model
from pathlib import Path

from defender._io import write_atomic
from defender.learning.core.config import DrainLabel, LoopPaths

_logger = logging.getLogger(__name__)


def _enqueue_marker(run_dir: Path, queue_dir: Path, label: str) -> None:
    queue_dir.mkdir(parents=True, exist_ok=True)
    marker = queue_dir / f"{run_dir.name}.json"
    write_atomic(
        marker,
        json.dumps({"run_id": run_dir.name, "run_dir": str(run_dir.resolve())}) + "\n",
    )
    _logger.info(f"enqueued for {label}: {marker}")


def enqueue_for_authoring(run_dir: Path, paths: LoopPaths) -> None:
    _enqueue_marker(run_dir, paths.author_queue_dir, "authoring")


def enqueue_case_for_curation(case_id: str, run_dir: Path, paths: LoopPaths) -> None:
    """The curation trigger's marker, keyed on the case rather than the run id, so repeat
    investigations of one case coalesce onto one request (atomic replace). The later run
    always wins."""
    queue_dir = paths.author_queue_dir
    queue_dir.mkdir(parents=True, exist_ok=True)
    marker = queue_dir / f"{case_id}.json"
    write_atomic(
        marker,
        json.dumps({"case_id": case_id, "run_dir": str(run_dir.resolve())}) + "\n",
    )
    _logger.info(f"enqueued for curation: {marker}")




def rewrite_marker(marker: Path, spec: dict) -> None:
    write_atomic(marker, json.dumps(spec) + "\n")


def requeue_marker(marker: Path, spec: dict) -> bool:
    """Put a claimed request back on the queue; `False` if the slot was no longer free.

    Create-if-absent rather than replace: a fresher request for the same case may have landed
    in the freed slot mid-serve, and the later run wins, so the caller drops its re-queue.

    Hard-linked from a staged temp file rather than `O_CREAT|O_EXCL`, so the slot goes from
    absent to fully written in one step. A later enqueue still wins by rename."""
    marker.parent.mkdir(parents=True, exist_ok=True)
    staged = marker.with_name(f".{marker.name}.requeue.{os.getpid()}")
    try:
        write_atomic(staged, json.dumps(spec) + "\n")
        try:
            os.link(staged, marker)
        except FileExistsError:
            return False
        return True
    finally:
        with contextlib.suppress(OSError):
            staged.unlink()


def marker_identity(spec: dict, marker: Path) -> str:
    """The id an operator greps for when a queued request is dropped or deferred.

    The queue carries run-keyed (`run_id`) and case-keyed (`case_id`) rows; the filename is
    the fallback for a row too damaged to carry either."""
    for key in ("case_id", "run_id"):
        value = spec.get(key)
        if isinstance(value, str) and value:
            return value
    return marker.stem


@model(frozen=True)
class ClaimedMarker:
    """One request this pass owns: already moved out of the queue, read, and servable."""

    path: Path
    """Where the marker sits now, under ``inflight/``. Unlinked once the request is consumed
    (for the lead-author drain, in `BatchDisposition.apply` after the scrub), not at serve."""

    queued_path: Path
    """The top-level slot the claim freed; a transient retry is re-queued here, never at
    ``path``."""

    spec: dict
    run_dir: Path


def claim_markers(
    queue_dir: Path, *, identity_key: str, label: DrainLabel, noun: str, extra: str = ""
) -> Iterator[ClaimedMarker]:
    """Claim every queued request and yield the servable ones, in orphans-first order.

    Claiming moves the marker out of the queue (``os.replace``) before serving, so a re-ask
    landing mid-serve gets a free top-level slot. Orphans in ``inflight/`` from a dead pass
    are reclaimed unconditionally — sound only because both callers hold the drainer flock, so
    no live pass can own a claim.

    An unreadable marker is quarantined rather than skipped, or it would be reclaimed and fail
    every tick while keeping the has-work predicate true. `identity_key` names its dead letter
    (`run_id` or `case_id`), since the row's own keys couldn't be read.
    """
    markers = sorted(queue_dir.glob("*.json")) if queue_dir.is_dir() else []
    inflight_dir = queue_dir / "inflight"
    orphans = sorted(inflight_dir.glob("*.json")) if inflight_dir.is_dir() else []
    _logger.info(
        f"{label}: {len(markers)} run(s) queued for {noun}, "
        f"{len(orphans)} reclaimed from a prior claim{extra}"
    )
    # A pass holding only orphans still writes into `inflight/`.
    if markers or orphans:
        inflight_dir.mkdir(parents=True, exist_ok=True)

    for marker in [*orphans, *markers]:
        already_claimed = marker.parent == inflight_dir
        claimed = marker if already_claimed else inflight_dir / marker.name
        if not already_claimed:
            try:
                os.replace(marker, claimed)
            except FileNotFoundError:
                continue
        spec, reason = _read_spec(claimed)
        if spec is None:
            quarantine_marker({identity_key: claimed.stem}, claimed, queue_dir, reason)
            continue
        raw_run_dir = spec.get("run_dir")
        if not isinstance(raw_run_dir, str) or not Path(raw_run_dir).is_absolute():
            # A non-string would raise TypeError out of this generator and wedge the drain; a
            # relative path would be served against the CWD, a worktree about to be
            # `reset --hard`. Both writers store an absolute path.
            quarantine_marker(
                spec, claimed, queue_dir, "unreadable: run_dir is not an absolute path"
            )
            continue
        run_dir = Path(raw_run_dir)
        if not run_dir.is_dir():
            quarantine_marker(spec, claimed, queue_dir, "artifact-missing")
            continue
        yield ClaimedMarker(claimed, queue_dir / marker.name, spec, run_dir)


def _read_spec(claimed: Path) -> tuple[dict | None, str]:
    """The claimed marker's spec row, or ``(None, reason)`` for one that cannot be served.

    A row that parses but isn't a mapping counts as unreadable too; asking it for ``run_dir``
    would raise ``AttributeError`` past every dead-letter path.
    """
    try:
        spec = json.loads(claimed.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        return None, f"unreadable: {e!r}"
    if not isinstance(spec, dict):
        return None, f"unreadable: not a mapping ({type(spec).__name__})"
    return spec, ""


#: Where `quarantine_marker` parks a request it couldn't serve, under the caller's queue dir;
#: the queue page reads all of them.
FAILED_MARKER_DIRNAME = "failed"


def quarantine_marker(spec: dict, marker: Path, queue_dir: Path, reason: str) -> None:
    failed_dir = queue_dir / FAILED_MARKER_DIRNAME
    failed_dir.mkdir(parents=True, exist_ok=True)
    rec = dict(spec)
    rec["failed"] = reason
    (failed_dir / marker.name).write_text(json.dumps(rec) + "\n", encoding="utf-8")
    with contextlib.suppress(OSError):
        marker.unlink()
    _logger.warning(f"quarantined {marker_identity(spec, marker)} — {reason}")
