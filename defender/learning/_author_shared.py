"""Shared primitives for the two learning-loop authors.

Both ``defender/learning/author.py`` (defender corpus) and
``defender/learning/author_actor.py`` (actor corpus) read from disjoint
``_pending/`` queues and write into disjoint corpora, but they share
the working tree: HEAD, the index, and the commit sequence. Per
``defender/docs/learning-loop-actor-learning.md`` §Concurrency, both
authors must acquire their per-author queue lock first, then the
shared repo lock (``defender/learning/_author.lock``) before launching
their child agent — and hold both through the entire fold-and-commit
flow.

This module exposes the shared repo-lock acquire/release pair and the
actor-generation counter helper. Queue locks remain per-author because
the queue paths differ. Both ``author.py`` and ``author_actor.py``
acquire this lock after their queue lock and hold it across the
child-agent invocation through queue rotation.
"""
from __future__ import annotations

import fcntl
import os
import subprocess
import time
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
LEARNING_DIR = REPO_ROOT / "defender" / "learning"

# Resolve the shared repo lock from DEFAULT_PATHS so it honors
# DEFENDER_LEARNING_STATE_DIR (out-of-repo under concurrent runs) — the single
# location every curator serializes on.
try:
    from defender.learning._loop_config import DEFAULT_PATHS
except ImportError:  # pragma: no cover — direct-script execution fallback
    import sys as _sys
    _sys.path.insert(0, str(Path(__file__).resolve().parent))
    try:
        from _loop_config import DEFAULT_PATHS  # type: ignore[no-redef]
    finally:
        _sys.path.pop(0)
REPO_LOCK_FILE = DEFAULT_PATHS.author_lock_file
LESSONS_ACTOR_DIR_REL = "defender/lessons-actor/"

REPO_LOCK_WAIT_SECONDS = int(
    os.environ.get("LEARNING_REPO_LOCK_WAIT_SECONDS", "1800")
)


def acquire_repo_lock(timeout_seconds: int | None = None) -> Any:
    """Blocking-with-timeout acquire of the shared repo lock.

    Returns the open file handle. Callers must release with
    ``release_repo_lock`` in reverse order with respect to the queue
    lock.

    Raises ``TimeoutError`` if the lock cannot be acquired within
    ``timeout_seconds``. The caller is expected to leave its queue
    lock intact in that case so the batch is retried later.
    """
    if timeout_seconds is None:
        timeout_seconds = REPO_LOCK_WAIT_SECONDS
    # mkdir the lock's own parent — the out-of-repo state_dir when
    # DEFENDER_LEARNING_STATE_DIR is set, not LEARNING_DIR.
    REPO_LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
    fh = REPO_LOCK_FILE.open("a+")
    deadline = time.monotonic() + max(1, timeout_seconds)
    while True:
        try:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            return fh
        except BlockingIOError as exc:
            if time.monotonic() >= deadline:
                fh.close()
                raise TimeoutError(
                    f"repo lock {REPO_LOCK_FILE} held by another author "
                    f"for >{timeout_seconds}s"
                ) from exc
            time.sleep(0.2)


def release_repo_lock(fh: Any) -> None:
    if fh is None:
        return
    try:
        fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
    finally:
        fh.close()


def _generation_count(trailer_label: str) -> int:
    """Generation a commit carrying a ``{trailer_label}:`` trailer would assert:
    1 + the count of prior commits bearing that trailer.

    The trailer is the canonical manifest — counting path-touching commits would
    miscount corpus-structure/template commits that predate the author flow, and
    no-op author runs produce no commit so they don't advance it. The grep anchors
    on the trailer key with **no** required space after the colon, so it counts
    exactly the commits ``author_*.assert_head_trailers`` accepts (whose regex also
    tolerates a zero-space trailer) — a stricter ``^label: `` would skip a no-space
    commit, letting two batches assert the same generation. Labels are disjoint, so
    a counter never crosses streams (``^Actor-Model:`` cannot match a
    ``Benign-Actor-Model:`` line, which starts with ``Benign-``).
    """
    proc = subprocess.run(
        ["git", "rev-list", "--count", f"--grep=^{trailer_label}:", "HEAD"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return int(proc.stdout.strip() or "0") + 1


def actor_generation_count() -> int:
    """Generation for a tradecraft (``Actor-Model:``) ``lessons-actor/`` commit."""
    return _generation_count("Actor-Model")


def benign_generation_count() -> int:
    """Generation for an FP-env (``Benign-Actor-Model:``) ``lessons-environment/``
    commit — the false-positive-direction analog of ``actor_generation_count``."""
    return _generation_count("Benign-Actor-Model")


def actor_env_generation_count() -> int:
    """Generation for an adversarial-env (``Actor-Env-Model:``) ``lessons-environment/``
    commit (issue #298) — a third counter disjoint from the other two, so per-stream
    generation analytics stay clean even though adversarial-env and FP-env commits
    land in the same corpus."""
    return _generation_count("Actor-Env-Model")


def without_consumed_category(rec: dict) -> dict:
    """A queue row stripped of the ``consumed_*`` stamp — for re-holding a
    just-committed row in the pending queue (``hold_committed``) so it reads
    clean on the next batch."""
    return {k: v for k, v in rec.items() if k != "consumed_category"}


def partition_committed(
    committed: list[dict], *, hold_committed: bool
) -> tuple[list[dict], list[dict]]:
    """Split the just-committed rows into ``(held, rotated)`` for ``rotate_queue``.

    Under the serial author drain (``hold_committed``) the commit lands on an
    unmerged PR branch, so committed rows stay queued — stripped of the consumed
    stamp — instead of rotating to ``consumed.jsonl``; a merged PR filters them
    via ``existing_*_ids`` next batch, a rejected PR re-authors them. Standalone
    callers rotate them straight out (today's commit-and-rotate behavior).
    """
    if hold_committed:
        return [without_consumed_category(c) for c in committed], []
    return [], committed
