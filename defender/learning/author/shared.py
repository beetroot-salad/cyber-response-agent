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
import json
import random
import re
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import yaml

from defender import _git
from defender._corpus import iter_lessons
from defender.learning.core.config import REPO_LOCK_WAIT_SECONDS  # noqa: F401 — re-export

# REPO_LOCK_WAIT_SECONDS (the env-derived ceiling each curator config sources as its
# ``repo_lock_wait_seconds``) now lives in core.config and is re-exported here so the
# existing ``_shared.REPO_LOCK_WAIT_SECONDS`` consumers are unchanged. The lock file
# and repo root are not module globals: every caller threads them from its
# ``LoopPaths``/config so a test rooted at a tmp tree injects instead of patching
# (issue #389). The lock path itself is ``LoopPaths.author_lock_file``, which honors
# DEFENDER_LEARNING_STATE_DIR — the single location every curator serializes on.


class AuthorError(Exception):
    """Fatal pre/post-flight error — caller should abort, queue stays intact."""


def acquire_repo_lock(lock_file: Path, *, timeout_seconds: int) -> Any:
    """Blocking-with-timeout acquire of the shared repo lock.

    Returns the open file handle. Callers must release with
    ``release_repo_lock`` in reverse order with respect to the queue lock — or,
    better, drive both through the ``repo_lock`` context manager. ``lock_file`` is
    the per-config ``author_lock_file`` and ``timeout_seconds`` its wait ceiling,
    both threaded from a ``LoopPaths``/config rather than read off a module global.

    Raises ``TimeoutError`` if the lock cannot be acquired within
    ``timeout_seconds``. The caller is expected to leave its queue
    lock intact in that case so the batch is retried later.
    """
    # mkdir the lock's own parent — the out-of-repo state_dir when
    # DEFENDER_LEARNING_STATE_DIR is set, not the repo's learning dir.
    lock_file.parent.mkdir(parents=True, exist_ok=True)
    fh = lock_file.open("a+", encoding="utf-8")
    deadline = time.monotonic() + max(1, timeout_seconds)
    while True:
        try:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            return fh
        except BlockingIOError as exc:
            if time.monotonic() >= deadline:
                fh.close()
                raise TimeoutError(
                    f"repo lock {lock_file} held by another author "
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


@contextlib.contextmanager
def repo_lock(lock_file: Path, *, timeout_seconds: int) -> Iterator[Any]:
    """Hold the shared repo lock for the block (acquire on enter, release on exit).

    The scoped twin of ``acquire_repo_lock``/``release_repo_lock`` — the three
    curator entrypoints (``author`` / ``_author_curator`` / ``lead_author``) drive
    the repo lock through this instead of a hand-rolled ``repo_lock = None`` +
    try/finally. Propagates ``TimeoutError`` from the acquire so the caller can
    leave its queue lock intact and retry the batch later::

        try:
            with repo_lock(cfg.repo_lock_file, timeout_seconds=cfg.repo_lock_wait_seconds):
                ...
        except TimeoutError:
            return 0  # queue intact, batch retried next tick
    """
    fh = acquire_repo_lock(lock_file, timeout_seconds=timeout_seconds)
    try:
        yield fh
    finally:
        release_repo_lock(fh)


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
    fh = path.open("a+", encoding="utf-8")
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


def _generation_count(trailer_label: str, *, repo_root: Path) -> int:
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
    return _git.git_rev_list_count(repo_root, grep=f"^{trailer_label}:") + 1


def actor_generation_count(repo_root: Path) -> int:
    """Generation for a tradecraft (``Actor-Model:``) ``lessons-actor/`` commit."""
    return _generation_count("Actor-Model", repo_root=repo_root)


def benign_generation_count(repo_root: Path) -> int:
    """Generation for an FP-env (``Benign-Actor-Model:``) ``lessons-environment/``
    commit — the false-positive-direction analog of ``actor_generation_count``."""
    return _generation_count("Benign-Actor-Model", repo_root=repo_root)


def actor_env_generation_count(repo_root: Path) -> int:
    """Generation for an adversarial-env (``Actor-Env-Model:``) ``lessons-environment/``
    commit (issue #298) — a third counter disjoint from the other two, so per-stream
    generation analytics stay clean even though adversarial-env and FP-env commits
    land in the same corpus."""
    return _generation_count("Actor-Env-Model", repo_root=repo_root)


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
# state. The adapters supply their config's ``repo_root`` (``AuthorConfig`` /
# ``CuratorConfig``, built from a ``LoopPaths``) as the production root — and as of
# #389 the repo lock + generation counters take it by param the same way.
# ---------------------------------------------------------------------------


def git_head_sha(repo_root: Path) -> str:
    return _git.git_head_sha(repo_root)


def changes_outside(repo_root: Path, prefix: str) -> list[str]:
    """Repo-wide uncommitted paths that are *not* a corpus ``*.md`` file under ``prefix``.

    The agent runs no git, so at verify time its edits sit in the working tree
    (un-committed); the scope gate runs over ``git status`` instead of a HEAD commit.
    Covers staged, unstaged, and untracked paths so a stray ``Write`` or improvised shim
    outside the corpus is caught. ``--untracked-files=all`` lists each untracked file
    individually rather than collapsing whole untracked directories, so a single stray
    file is reported as itself (and a fresh corpus file isn't mis-collapsed to its dir).
    The ``-z`` reader (``_git.git_status``) is correct for spaced paths and needs no
    ``" -> "`` rename split — a staged rename's source field reads as its own record. The
    caller diffs against a pre-agent baseline so unrelated leftovers (a sibling author's
    uncommitted work earlier in the same batch) aren't blamed on the curator agent."""
    return [
        path
        for _xy, path in _git.git_status(repo_root)
        if not (path.startswith(prefix) and path.endswith(".md"))
    ]


def corpus_dir_clean(repo_root: Path, corpus_dir: Path) -> bool:
    return not _git.git_status(repo_root, pathspec=corpus_dir)


def assert_clean_corpus_dir(repo_root: Path, corpus_dir: Path, corpus_dir_rel: str) -> None:
    """Pre-flight scope check — refuse to author if the corpus has uncommitted changes.

    Atomicity assumes a clean baseline so a failed batch rolls back to it. ``mkdir``s the
    corpus so a first-ever run on a not-yet-existing corpus passes rather than erroring on
    a missing path. The raising twin of ``corpus_dir_clean``; both authors call it through
    ``run_batch_envelope`` so the dirty-corpus refusal lives once (was the parallel
    ``assert_clean_corpus_dir``/``assert_clean_lessons_dir`` pair)."""
    corpus_dir.mkdir(parents=True, exist_ok=True)
    records = _git.git_status(repo_root, pathspec=corpus_dir)
    if records:
        listing = "\n".join(f"{xy} {path}" for xy, path in records)
        raise AuthorError(
            f"{corpus_dir_rel} has uncommitted changes — refusing to author. "
            f"Output:\n{listing}"
        )


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


def _result_entry_id(bucket: str, entry: Any, id_key: str) -> str:
    """The id of a single AUTHOR_RESULT entry. ``committed`` entries are bare id strings
    (the agent reports just the id it committed); every other bucket is an object carrying
    ``id_key`` (+ a ``reason``/``skip_reason``). ``id_key`` is the corpus's id field
    (``finding_id`` / ``observation_id``)."""
    if bucket == "committed":
        if not isinstance(entry, str) or not entry:
            raise AuthorError(
                f"AUTHOR_RESULT committed entries must be non-empty {id_key} strings"
            )
        return entry
    if not isinstance(entry, dict):
        raise AuthorError(f"AUTHOR_RESULT {bucket} entries must be objects")
    rid = entry.get(id_key)
    if not isinstance(rid, str) or not rid:
        raise AuthorError(
            f"AUTHOR_RESULT {bucket} entries must include a non-empty {id_key}"
        )
    return rid


def validate_agent_result_partition(
    result: dict,
    to_author: list[dict],
    *,
    id_key: str,
    buckets: tuple[str, ...],
    noun: str,
) -> None:
    """Require each authored row to land in exactly one result bucket — no unknown, no
    duplicate-across-buckets, none missing. Shared by both authors (was a parallel copy
    per corpus); they differ only in ``id_key`` (``finding_id``/``observation_id``), the
    ``buckets`` they expose (the findings author adds ``held_forward_bad``), and the
    ``noun`` for error strings (``findings``/``observations``). ``expected`` is the id set
    the agent was handed."""
    expected = {row[id_key] for row in to_author}
    occurrences: dict[str, list[str]] = {}
    for bucket in buckets:
        for entry in _result_list(result, bucket):
            rid = _result_entry_id(bucket, entry, id_key)
            occurrences.setdefault(rid, []).append(bucket)

    unknown = sorted(rid for rid in occurrences if rid not in expected)
    if unknown:
        raise AuthorError(f"author result contains unknown {noun}: {unknown}")
    repeated = {
        rid: where for rid, where in sorted(occurrences.items()) if len(where) != 1
    }
    if repeated:
        raise AuthorError(
            f"author result classified {noun} more than once: "
            + json.dumps(repeated, sort_keys=True)
        )
    unseen = sorted(expected - occurrences.keys())
    if unseen:
        raise AuthorError(f"author result missing {noun}: {unseen}")


def commit_corpus(
    repo_root: Path,
    corpus_dir: Path,
    message: str,
    *,
    trailers: list[tuple[str, str]] | None = None,
) -> str | None:
    """Stage the corpus, commit it pathspec-scoped, return the new sha (or ``None``).

    The agent authors lesson content + a commit message but runs no git: the loop is the
    **sole committer**. The ``git commit`` is **pathspec-scoped** to the corpus
    (``-- <corpus_dir>``): staging alone does not bound a commit — a plain index-global
    ``git commit`` sweeps in whatever else sits staged in the batch worktree (e.g. a sibling
    curator's own corpus edits earlier in the same drain), so the pathspec is what keeps
    anything *outside* this corpus out of the commit. Returns the new sha, or ``None`` when
    the agent authored nothing (empty index → no commit).

    When ``trailers`` is given (the actor/env curators pass ``Generation:`` /
    ``{trailer_label}:``), the loop owns that provenance — it already computes both values,
    so they can't drift off a hand-typed literal, and the trailers go on at creation time
    rather than via a follow-up ``--amend`` (no commit→stamp split that could leave an
    un-stamped lesson commit behind, issue #321). A guard refuses a ``commit_message`` that
    already carries one of those trailer keys: ``git --trailer`` *appends*, so a
    hand-written one would survive alongside ours and shadow it for first-match readers
    (``evals/secondary.py`` ``parse_trailers``). ``author.py`` passes no trailers — the findings
    corpus carries none — so neither the guard nor the ``--trailer`` args apply.

    The trailer-duplicate guard is a domain refusal (``AuthorError`` — queue intact for
    retry); the staging/commit themselves go through ``_git.git_commit``, so a git failure
    there raises ``GitError`` (a systemic fault → the drain's exit 2), not an ``AuthorError``."""
    trailers = trailers or []  # normalize None→[] once; both the guard and the helper below
    if trailers:
        keys = "|".join(re.escape(key) for key, _ in trailers)
        if re.search(rf"(?m)^(?:{keys}):", message):
            labels = "/".join(f"{key}:" for key, _ in trailers)
            raise AuthorError(
                f"agent commit_message already carries {labels} "
                "trailers; the loop owns provenance and git --trailer would append "
                "duplicates — refusing to commit (queue intact for retry)"
            )
    return _git.git_commit(repo_root, corpus_dir, message, trailers=trailers)


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


# ---------------------------------------------------------------------------
# Batch lock envelope — the lock dance every author runs around its inner batch
# ---------------------------------------------------------------------------


def run_batch_envelope(
    *,
    queue_lock_file: Path,
    repo_lock_file: Path,
    repo_lock_wait_seconds: int,
    repo_root: Path,
    corpus_dir: Path,
    corpus_dir_rel: str,
    log: Callable[[str], None],
    inner: Callable[[], int],
) -> int:
    """The lock skeleton shared by every author's ``run_batch``: take the non-blocking
    per-author queue lock (skip the tick if contended), then the blocking-with-timeout
    shared repo lock, clean-scope the corpus, and run ``inner`` under both. Returns
    ``inner``'s rc, ``0`` on a skipped/un-acquirable lock (queue left intact for retry),
    or ``2`` if the corpus is dirty.

    Queue lock first, repo lock second; released in reverse (the repo lock by ``repo_lock``
    on block exit, the queue lock in the ``finally``). The inner batch driver diverges per
    corpus (different partition gate, result buckets, and queue concurrency model), so it
    stays a per-author callable — only this envelope is shared."""
    queue_lock = acquire_flock(queue_lock_file)
    if queue_lock is None:
        log("queue lock held by another process — skipping this tick")
        return 0
    try:
        with repo_lock(repo_lock_file, timeout_seconds=repo_lock_wait_seconds):
            try:
                assert_clean_corpus_dir(repo_root, corpus_dir, corpus_dir_rel)
            except AuthorError as e:
                log(f"FATAL: {e}")
                return 2
            return inner()
    except TimeoutError as e:
        log(f"repo lock unavailable: {e}; queue intact")
        return 0
    finally:
        release_flock(queue_lock)


# The provenance frontmatter the corpus manifest DROPS: bookkeeping the curator does not need to
# fold against (source ids + timestamps), and the drop is PARTIAL per corpus (findings carry
# ``source_finding_ids``+``created_at``; actor/env carry ``source_observation_ids``+``recorded_at``),
# so the filter is set membership, never ``fm.pop(k)`` — which KeyErrors on a field a corpus lacks.
_MANIFEST_PROVENANCE_DROP = frozenset(
    {"source_finding_ids", "source_observation_ids", "created_at", "recorded_at"}
)


def build_corpus_manifest(corpus_dir: Path, *, seed: str | None = None) -> str:
    """Render the existing-corpus manifest a lesson curator folds against: one ``## <stem>``
    section per non-``_`` lesson in ``corpus_dir``, carrying that lesson's frontmatter MINUS the
    provenance drop-set, re-emitted from the PARSED dict via ``yaml.safe_dump``. Re-emitting from
    the dict (not a raw-line filter) is what makes the drop total — a multi-line block field
    (``source_finding_ids:`` + its ``- id`` continuations) leaves no orphan line — AND what makes
    the VALUES injection-safe: ``safe_dump`` indents/quotes every one, so a crafted frontmatter
    scalar (``\\n## other`` / ``\\n---`` / YAML metachars) cannot forge a sibling ``## `` header or
    a ``---`` break. That holds for a LIST-valued field too (the actor corpus's ``techniques`` /
    ``applies_to``, whose values trace back to alert data): safe_dump quotes and indents each
    element, so no element reaches column 0.

    The STEM is untrusted too, and ``safe_dump`` never sees it. A lesson filename is model-chosen
    (the curator authors the corpus with ``write_file``) and ``build_write_allow``'s ``[^\\x00]*``
    tail is a char class that matches a NEWLINE — so ``lessons/x\\n## other\\n….md`` is a
    gate-approved path whose stem would forge exactly the sibling section the value-quoting above
    closes. Collapse the stem's whitespace so a slug can never leave its own ``## `` line.

    The walk itself is ``defender._corpus.iter_lessons`` — the same reader the three lesson CLIs
    stream to the actor — so the manifest cannot drift from it the way the hand-rolled copy did
    (the ``UnicodeDecodeError`` hole had to be closed twice). Section ORDER is therefore the
    iterator's full-path order, not a stem sort: taking the shared order is the point, and the
    shuffle below is what the curator actually sees in production anyway.

    ``seed`` shuffles the sections with a local ``random.Random`` (never the module-level
    ``random``, whose global stream ``ticket_seeds``/``malicious_actor`` draw from). The curator's
    job is fold-into-an-existing-lesson vs author-a-new-one, and this manifest is the menu it picks
    from: under a fixed order the same lessons sit at the top on every batch forever, so any
    position bias in the model compounds into a systematic tilt instead of averaging out. Seeded
    (from ``batch_id``) rather than free-running, so a drain stays replayable and the prompt prefix
    stays cacheable. ``random.Random(<str>)`` seeds via sha512 — NOT ``hash()``, which is
    PYTHONHASHSEED-salted and would reorder in every new process. ``seed=None`` (the default) keeps
    the deterministic sorted path for every other caller; ``seed=""`` is a seed, not an absence —
    hence ``is not None``, never ``if seed:``.

    Reads the PASSED ``corpus_dir`` (the author-drain threads its throwaway worktree's corpus —
    #562), never a module global, so the manifest reflects the tree the curator actually edits.
    Dropping ``created_at``/``recorded_at`` also removes the YAML-parsed ``datetime`` before
    ``safe_dump`` ever sees it.

    Tolerant: a missing / empty / non-directory ``corpus_dir`` yields ``''`` (a first-ever run in a
    fresh worktree), and a single malformed ``.md`` is warned to stderr and skipped — one bad file
    never aborts the manifest and loses its well-formed siblings. Skipped is not DROPPED, though:
    a warn-skipped lesson still claims its ``## <stem>`` section, with a fixed marker body in
    place of the frontmatter it doesn't have (#590's rule, the manifest half). The manifest is the
    menu the curator folds against — losing a discovered stem from it is precisely how the curator
    authors an overlapping lesson it cannot see (the drift ``iter_lesson_paths``' docstring calls
    one-directionally dangerous). The marker body is a literal, so nothing model-authored reaches
    it; the stem gets the same whitespace collapse as a well-formed section's."""
    sections: list[str] = []
    skipped: list[Path] = []
    for lesson in iter_lessons(
        corpus_dir, warn_label=lambda p: f"corpus manifest: {p.name}", on_skip=skipped.append
    ):
        kept = {k: v for k, v in lesson.fm.items() if k not in _MANIFEST_PROVENANCE_DROP}
        rendered = yaml.safe_dump(
            kept, sort_keys=True, default_flow_style=False, allow_unicode=True
        )
        # a model-chosen stem is not a safe protocol field
        slug = " ".join(lesson.path.stem.split())
        sections.append(f"## {slug}\n{rendered}")
    for path in skipped:
        slug = " ".join(path.stem.split())
        sections.append(
            f"## {slug}\n(unavailable: this lesson file is malformed or unreadable, so its "
            "frontmatter cannot be shown. The stem is taken — repair this lesson rather than "
            "authoring an overlapping one.)\n"
        )
    if seed is not None:
        random.Random(seed).shuffle(sections)
    return "\n".join(sections)


def build_curator_user_prompt(
    rows: list[dict], batch_id: str, *, corpus_dir: Path, corpus_dir_rel: str, label: str,
    manifest_seed: str | None = None,
) -> str:
    """The user payload every curator sends its agent: the existing-corpus frontmatter manifest,
    the batch, its corpus display path, and the queued rows verbatim. ``label`` names the row kind
    (``findings`` / ``observations``) — the only thing that varied between the four curators'
    hand-rolled copies.

    The manifest is built from the ABSOLUTE ``corpus_dir`` (the worktree corpus each caller
    already holds — #562), so the curator folds against what it already has without cat-ing each
    lesson; ``corpus_dir_rel`` is the human-readable display path ONLY, never the glob root. The
    manifest (existing lessons) is disjoint from the queued rows (findings/observations to author).

    It carries NO forward-check command line. The check is an in-process tool bound to the
    curator's deps at spawn (#558), so there is nothing here for the agent to substitute an
    interpreter path or a script operand into; each row's own id and direction ride in the
    rows below, where they already were.

    The manifest's section order is seeded from ``batch_id`` (see ``build_corpus_manifest``) — the
    default every production curator takes, and the reason ``batch_id`` is echoed into the prompt:
    it is what replays the order. ``manifest_seed`` overrides that with a fixed seed, and this is
    the ONE place the override-else-batch_id choice is made, so the four curators cannot drift on
    it. Its only caller is the author eval (``evals/harness.py``), which drives the real curator
    against a temp tree: ``batch_id`` is a fresh uuid4 per drain, so without a pin the eval would
    draw a different menu order every run — and that eval is the instrument you would measure the
    position bias with."""
    # An empty corpus (the first-ever drain) renders as a blank section, which reads as a
    # truncated prompt rather than a fact. Say the fact.
    seed = manifest_seed if manifest_seed is not None else batch_id
    manifest = build_corpus_manifest(corpus_dir, seed=seed) or "(none — the corpus is empty)"
    return (
        f"batch_id: {batch_id}\n"
        f"lessons_dir: {corpus_dir_rel}\n"
        f"\nexisting lessons (frontmatter manifest):\n{manifest}\n\n"
        f"{label} ({len(rows)}):\n"
        f"{json.dumps(rows, indent=2)}\n"
    )
