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
    LEARNING_DIR.mkdir(parents=True, exist_ok=True)
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


def actor_generation_count() -> int:
    """Return the generation number this commit would assert.

    Equals 1 + the count of prior author commits, identified by the
    ``Actor-Model:`` trailer they're required to carry. The first
    author commit asserts ``Generation: 1``. No-op author runs do not
    advance the counter because they produce no commit. The trailer is
    the canonical manifest — counting path-touching commits would
    miscount corpus-structure and template commits that predate the
    author flow.
    """
    proc = subprocess.run(
        ["git", "rev-list", "--count", "--grep=^Actor-Model: ", "HEAD"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    prior = int(proc.stdout.strip() or "0")
    return prior + 1


def benign_generation_count() -> int:
    """Generation this environment-lesson commit would assert.

    The false-positive-direction analog of ``actor_generation_count`` —
    counts prior environment-lesson commits by their required
    ``Benign-Actor-Model:`` trailer. The two directions advance independent
    generation counters off disjoint trailers.
    """
    proc = subprocess.run(
        ["git", "rev-list", "--count", "--grep=^Benign-Actor-Model: ", "HEAD"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    prior = int(proc.stdout.strip() or "0")
    return prior + 1
