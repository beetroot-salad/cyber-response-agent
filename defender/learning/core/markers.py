from __future__ import annotations

import contextlib
import json
import os
from collections.abc import Iterator
from dataclasses import dataclass
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


@dataclass(frozen=True)
class ClaimedMarker:
    """One request this pass owns: already moved out of the queue, read, and servable."""

    path: Path
    """Where the marker sits now — under ``inflight/``. Unlink this when the serve succeeds."""

    queued_path: Path
    """The top-level slot the claim freed. A transient retry is re-queued HERE, never at
    ``path`` — which the claim is about to unlink."""

    spec: dict
    run_dir: Path


def claim_markers(
    queue_dir: Path, *, identity_key: str, label: str, noun: str, extra: str = ""
) -> Iterator[ClaimedMarker]:
    """Claim every queued request and yield the servable ones, in orphans-first order.

    This is the claim-and-serve protocol both drains run, and it had been written twice.
    That cost was not hypothetical: the poison-marker fix (#795) had to be applied to both
    copies, and its follow-up — the row that PARSES but is not a mapping — had to be applied
    to both copies again, four hand-carries for one defect.

    Claiming is an ``os.replace`` OUT of the queue before the request is served. Two things
    depend on it. A re-ask that lands while this pass is serving needs the top-level path
    free, or it would be destroyed by an unlink-after-read (case-keyed identity, #791 P2).
    And an orphan left in ``inflight/`` by a pass that died mid-serve is a request LOST, not
    deferred — nothing globbing the top level can see it — so this reclaims unconditionally.
    That is only sound under the drainer flock: a claim is evidence of a DEAD pass only if no
    live pass can be holding one. Both callers hold it.

    A marker that cannot be read is QUARANTINED here rather than skipped. Skipping leaves it
    in ``inflight/`` for the next tick's reclaim to hand back, fail on, and log again,
    forever — while the queue's has-work predicate stays true on its presence. `identity_key`
    is the key its dead letter is written under (`run_id` for the run-keyed queue, `case_id`
    for #791's case-keyed one), because the row's own keys are exactly what could not be read
    and the filename is the identity under both shapes.
    """
    markers = sorted(queue_dir.glob("*.json")) if queue_dir.is_dir() else []
    inflight_dir = queue_dir / "inflight"
    orphans = sorted(inflight_dir.glob("*.json")) if inflight_dir.is_dir() else []
    _log(
        f"{label}: {len(markers)} run(s) queued for {noun}, "
        f"{len(orphans)} reclaimed from a prior claim{extra}"
    )
    # On EITHER — a pass holding only orphans still writes into `inflight/` (it is where they
    # already are), and the union is the one form that is correct for both callers.
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
        run_dir = Path(spec.get("run_dir", ""))
        if not run_dir.is_dir():
            quarantine_marker(spec, claimed, queue_dir, "artifact-missing")
            continue
        yield ClaimedMarker(claimed, queue_dir / marker.name, spec, run_dir)


def _read_spec(claimed: Path) -> tuple[dict | None, str]:
    """The claimed marker's spec row, or ``(None, reason)`` for one that cannot be served.

    A row that PARSES but is not a mapping is unreadable in exactly the same way a torn one
    is: the caller goes on to ask it for ``run_dir``, and a list/scalar/``null`` answers with
    an ``AttributeError`` that unwinds the whole drain past every dead-letter path. Both
    shapes therefore report the same way.
    """
    try:
        spec = json.loads(claimed.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        return None, f"unreadable: {e!r}"
    if not isinstance(spec, dict):
        return None, f"unreadable: not a mapping ({type(spec).__name__})"
    return spec, ""


def quarantine_marker(spec: dict, marker: Path, queue_dir: Path, reason: str) -> None:
    failed_dir = queue_dir / "failed"
    failed_dir.mkdir(parents=True, exist_ok=True)
    rec = dict(spec)
    rec["failed"] = reason
    (failed_dir / marker.name).write_text(json.dumps(rec) + "\n", encoding="utf-8")
    with contextlib.suppress(OSError):
        marker.unlink()
    _log(f"quarantined {marker_identity(spec, marker)} — {reason}")
