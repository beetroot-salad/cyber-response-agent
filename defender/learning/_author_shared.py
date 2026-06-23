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

This module exposes the shared repo-lock acquire/release pair, the
generation counters, and the shared git transaction layer the two
authors run after their child agent exits: the stray scope-gate
(``changes_outside``), the corpus-clean predicate (``corpus_dir_clean``),
the loop-owned committer (``commit_corpus`` — pathspec-scoped, with
optional provenance trailers), the HEAD-sha reader (``git_head_sha``),
the working-tree cross-check (``verify_agent_state``), and the shared
``AuthorError`` they all raise. ``author.py`` (``defender/lessons/``, no
trailers) and ``_author_curator.py`` (the actor/env corpora, with
``Generation:``/``{trailer_label}:`` trailers) reach this plumbing through
thin, corpus-pinning adapters rather than hand-mirroring it. Queue locks
remain per-author because the queue paths differ, but the flock dance itself
is shared here too (``acquire_flock``/``release_flock``, plus the scoped
``flock_or_skip`` context-manager twin for inline lock→work→unlock call sites
such as the author-drain and lesson-revert paths) — each author just
supplies its own lock-file path. Both ``author.py`` and
``author_actor.py`` acquire this lock after their queue lock and hold it
across the child-agent invocation through queue rotation.
"""
from __future__ import annotations

import contextlib
import fcntl
import os
import re
import subprocess
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
LEARNING_DIR = REPO_ROOT / "defender" / "learning"

# Resolve the shared repo lock from DEFAULT_PATHS so it honors
# DEFENDER_LEARNING_STATE_DIR (out-of-repo under concurrent runs) — the single
# location every curator serializes on.
from defender.learning._loop_config import DEFAULT_PATHS
REPO_LOCK_FILE = DEFAULT_PATHS.author_lock_file
LESSONS_ACTOR_DIR_REL = "defender/lessons-actor/"

REPO_LOCK_WAIT_SECONDS = int(
    os.environ.get("LEARNING_REPO_LOCK_WAIT_SECONDS", "1800")
)


class AuthorError(Exception):
    """Fatal pre/post-flight error — caller should abort, queue stays intact."""


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


def acquire_flock(path: Path) -> Any | None:
    """Non-blocking exclusive flock on ``path``; the open handle, or ``None`` if contended.

    The per-author queue-lock primitive: where ``acquire_repo_lock`` above is
    blocking-with-timeout (one shared repo lock every author serializes on),
    this never waits — a tick that loses the race simply skips its batch. Each
    author wraps it with its own lock-file path (queue paths differ per author);
    the flock dance lives here once so it can't drift between the three corpora
    (issue #360). mkdir's the lock file's parent so callers needn't. Release with
    ``release_flock``.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fh = path.open("a+")
    try:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        fh.close()
        return None
    except BaseException:
        # A genuine lock-subsystem failure (e.g. ENOLCK) propagates — fail loud
        # (issue #367) — but close the handle first so the propagation path
        # doesn't leak the fd. The inline dances this replaced closed it in a
        # `finally`; here the raise escapes before any `flock_or_skip` body runs,
        # so acquire_flock must clean up its own handle.
        fh.close()
        raise
    return fh


def release_flock(fh: Any) -> None:
    if fh is None:
        return
    try:
        fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
    finally:
        fh.close()


@contextlib.contextmanager
def flock_or_skip(path: Path) -> Iterator[bool]:
    """Hold the non-blocking flock on ``path`` for the block; yield whether it was acquired.

    The scoped twin of ``acquire_flock`` (and built on it, so the dance still
    lives in one place): for call sites that lock → do work → unlock inline
    rather than handing the handle back. Yields ``True`` when the lock was taken
    (released on block exit), ``False`` when another holder has it (nothing
    acquired, nothing to release):

        with flock_or_skip(path) as locked:
            if not locked:
                return  # someone else is in here
            ...

    Like ``acquire_flock``, contention is detected by ``BlockingIOError`` only —
    a genuine lock-subsystem failure (e.g. ``ENOLCK`` on a filesystem without
    working locks) propagates rather than masquerading as a busy lock (issue
    #367). The author-drain and lesson-revert paths route through here.
    """
    fh = acquire_flock(path)
    try:
        yield fh is not None
    finally:
        release_flock(fh)


def _generation_count(trailer_label: str) -> int:
    """Generation a commit carrying a ``{trailer_label}:`` trailer would assert:
    1 + the count of prior commits bearing that trailer.

    The trailer is the canonical manifest — counting path-touching commits would
    miscount corpus-structure/template commits that predate the author flow, and
    no-op author runs produce no commit so they don't advance it. The grep anchors
    on the trailer key with **no** required space after the colon, so a differently-
    spaced or hand-written trailer still counts — the curator commits a canonical
    ``Label: value`` (``_author_curator.commit_corpus``), but a stricter
    ``^label: `` would skip a no-space commit, letting two batches assert the same
    generation. Labels are disjoint, so
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


def by_id(rows: list[dict], id_key: str) -> dict[str, dict]:
    """Index a list of queue rows by their id field — the author keys on
    ``finding_id``, the curator on ``observation_id`` (one body, two corpora).
    Subscripts ``row[id_key]`` (a missing key is a real break, not silently
    dropped), so behavior matches the per-module copies it replaces."""
    return {r[id_key]: r for r in rows}


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


# ---------------------------------------------------------------------------
# Git transaction layer — the loop is the sole committer; the agent runs no
# git. Both authors reach these through thin, corpus-pinning adapters
# (``author.py`` / ``_author_curator.py``); the plumbing lives here once so a
# fix to the porcelain parsing or the commit/no-op contract can't drift between
# the two corpora (issue #330). ``repo_root`` (the worktree the git commands run
# in) is passed in, not read from a module global — so the layer is exercised by
# injection: tests point it at a tmp repo directly, no monkeypatching of module
# state. The adapters supply their module's ``REPO_ROOT`` as the production root.
# ---------------------------------------------------------------------------


def git_head_sha(repo_root: Path) -> str:
    proc = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repo_root, capture_output=True, text=True, check=True,
    )
    return proc.stdout.strip()


def changes_outside(repo_root: Path, prefix: str) -> list[str]:
    """Repo-wide uncommitted paths that are *not* a corpus ``*.md`` file under ``prefix``.

    The agent runs no git, so at verify time its edits sit in the working tree
    (un-committed); the scope gate runs over ``git status`` instead of a HEAD commit.
    Covers staged, unstaged, and untracked paths so a stray ``Write`` or improvised shim
    outside the corpus is caught. ``--untracked-files=all`` lists each untracked file
    individually rather than collapsing whole untracked directories, so a single stray
    file is reported as itself (and a fresh corpus file isn't mis-collapsed to its dir).
    The caller diffs against a pre-agent baseline so unrelated leftovers (a sibling
    author's uncommitted work earlier in the same batch) aren't blamed on the curator
    agent."""
    proc = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=all"],
        cwd=repo_root, capture_output=True, text=True, check=True,
    )
    stray: list[str] = []
    for line in proc.stdout.splitlines():
        if not line.strip():
            continue
        path = line[3:]
        if " -> " in path:  # rename: XY orig -> new
            path = path.split(" -> ", 1)[1]
        path = path.strip().strip('"')
        if not (path.startswith(prefix) and path.endswith(".md")):
            stray.append(path)
    return stray


def corpus_dir_clean(repo_root: Path, corpus_dir: Path) -> bool:
    proc = subprocess.run(
        ["git", "status", "--porcelain", "--", str(corpus_dir)],
        cwd=repo_root, capture_output=True, text=True, check=True,
    )
    return not proc.stdout.strip()


def _result_list(result: dict, key: str) -> list[Any]:
    value = result.get(key, [])
    if value is None:
        return []
    if not isinstance(value, list):
        raise AuthorError(f"AUTHOR_RESULT field {key!r} must be a list")
    return value


def _commit_message(result: dict, noun: str) -> str:
    """The agent-authored commit message the loop passes to ``git commit -F-``.

    Required (and non-empty) whenever the batch committed anything — the loop owns the
    commit, but the agent still authors the human-readable message body. ``noun`` is the
    corpus's unit of work (``findings`` / ``observations``) for the error string."""
    msg = result.get("commit_message")
    if not isinstance(msg, str) or not msg.strip():
        raise AuthorError(
            f"AUTHOR_RESULT reported committed {noun} without a non-empty "
            "commit_message; refusing to commit"
        )
    return msg


def commit_corpus(
    repo_root: Path,
    corpus_dir: Path,
    corpus_dir_rel: str,
    message: str,
    *,
    trailers: list[tuple[str, str]] | None = None,
) -> str | None:
    """Stage the corpus, commit it pathspec-scoped, return the new sha (or ``None``).

    The agent authors lesson content + a commit message but runs no git: the loop is the
    **sole committer**. The ``git commit`` is **pathspec-scoped** to the corpus
    (``-- <corpus_dir>``): staging alone does not bound a commit — a plain index-global
    ``git commit`` sweeps in whatever else sits staged in the shared worktree (e.g. a
    sibling author's ``_draft/`` deposits from ``lead_author._stage_pending_drafts``), so
    the pathspec is what keeps anything *outside* the corpus out of the lesson commit.
    Returns the new sha, or ``None`` when the agent authored nothing (empty index → no
    commit).

    When ``trailers`` is given (the actor/env curators pass ``Generation:`` /
    ``{trailer_label}:``), the loop owns that provenance — it already computes both values,
    so they can't drift off a hand-typed literal, and the trailers go on at creation time
    rather than via a follow-up ``--amend`` (no commit→stamp split that could leave an
    un-stamped lesson commit behind, issue #321). A guard refuses a ``commit_message`` that
    already carries one of those trailer keys: ``git --trailer`` *appends*, so a
    hand-written one would survive alongside ours and shadow it for first-match readers
    (``eval_secondary.parse_trailers``). ``author.py`` passes no trailers — the findings
    corpus carries none — so neither the guard nor the ``--trailer`` args apply."""
    trailers = trailers or []  # normalize None→[] once; both the guard and args below
    if trailers:
        keys = "|".join(re.escape(key) for key, _ in trailers)
        if re.search(rf"(?m)^(?:{keys}):", message):
            labels = "/".join(f"{key}:" for key, _ in trailers)
            raise AuthorError(
                f"agent commit_message already carries {labels} "
                "trailers; the loop owns provenance and git --trailer would append "
                "duplicates — refusing to commit (queue intact for retry)"
            )
    add = subprocess.run(
        ["git", "add", "--", str(corpus_dir)],
        cwd=repo_root, capture_output=True, text=True,
    )
    if add.returncode != 0:
        raise AuthorError(
            f"failed to stage {corpus_dir_rel} batch: {add.stderr.strip()}"
        )
    staged = subprocess.run(
        ["git", "diff", "--cached", "--quiet", "--", str(corpus_dir)],
        cwd=repo_root, capture_output=True, text=True,
    )
    if staged.returncode == 0:
        return None  # nothing staged — no commit
    if staged.returncode != 1:  # 0=no diff, 1=diff, >1=git error (don't commit blind)
        raise AuthorError(
            f"git diff --cached failed for {corpus_dir_rel}: {staged.stderr.strip()}"
        )
    trailer_args: list[str] = []
    for key, val in trailers:
        trailer_args += ["--trailer", f"{key}: {val}"]
    proc = subprocess.run(
        ["git", "commit", "-F", "-", *trailer_args, "--", str(corpus_dir)],
        cwd=repo_root, input=message, capture_output=True, text=True,
    )
    if proc.returncode != 0:
        raise AuthorError(
            f"failed to commit {corpus_dir_rel} batch: {proc.stderr.strip()}"
        )
    return git_head_sha(repo_root)


def verify_agent_state(
    repo_root: Path,
    result: dict,
    corpus_dir: Path,
    corpus_dir_rel: str,
    noun: str,
    baseline_stray: list[str],
) -> None:
    """Cross-check the agent's reported state against the working tree before the loop
    commits + rotates. The agent runs no git, so its edits sit un-committed in the working
    tree: (1) the agent introduced no *new* change outside ``<corpus>``*.md (scope gate —
    a plain ``git add <corpus>`` already won't stage strays, but a new one means the agent
    misbehaved, so fail loud; diffed against ``baseline_stray`` captured before the agent
    ran so pre-existing leftovers aren't blamed on it); (2) ``committed`` non-empty ⇒ the
    corpus has edits to commit; (3) ``committed`` empty ⇒ the corpus is clean (an all-skip
    batch leaves no diff — a forward-BAD revert is re-edited back to its pre-batch bytes).
    Any provenance trailers are added by ``commit_corpus`` afterward, not verified here.
    ``noun`` is the corpus's unit of work (``findings`` / ``observations``)."""
    new_stray = sorted(
        set(changes_outside(repo_root, corpus_dir_rel)) - set(baseline_stray)
    )
    if new_stray:
        raise AuthorError(
            f"agent changed files outside {corpus_dir_rel}*.md: {new_stray}; "
            "refusing to commit/rotate"
        )
    committed = _result_list(result, "committed")
    corpus_dirty = not corpus_dir_clean(repo_root, corpus_dir)
    if committed and not corpus_dirty:
        raise AuthorError(
            f"author reported committed {noun} but left {corpus_dir_rel} "
            "unchanged; refusing to rotate queue"
        )
    if not committed and corpus_dirty:
        raise AuthorError(
            f"author reported no commits but left edits in {corpus_dir_rel}; "
            "refusing to rotate queue"
        )
