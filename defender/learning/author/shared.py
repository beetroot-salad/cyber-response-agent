from __future__ import annotations

import contextlib
import fcntl
import json
import random
import re
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from uuid import uuid4
from typing import Any

import yaml

from defender import _git
from defender.learning.pipeline._prompt import stage_user_message, structured_json_body
from defender._untrusted import wrap
from defender._corpus import iter_lessons
from defender.learning.core.config import REPO_LOCK_WAIT_SECONDS  # noqa: F401 — re-export



class AuthorError(Exception):
    pass


def acquire_repo_lock(lock_file: Path, *, timeout_seconds: int) -> Any:
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
    fh = acquire_repo_lock(lock_file, timeout_seconds=timeout_seconds)
    try:
        yield fh
    finally:
        release_repo_lock(fh)


def acquire_flock(path: Path) -> Any | None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fh = path.open("a+", encoding="utf-8")
    try:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        fh.close()
        return None
    except BaseException:
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
    fh = acquire_flock(path)
    try:
        yield fh is not None
    finally:
        release_flock(fh)


def _generation_count(trailer_label: str, *, repo_root: Path) -> int:
    return _git.git_rev_list_count(repo_root, grep=f"^{trailer_label}:") + 1


def actor_generation_count(repo_root: Path) -> int:
    return _generation_count("Actor-Model", repo_root=repo_root)


def benign_generation_count(repo_root: Path) -> int:
    return _generation_count("Benign-Actor-Model", repo_root=repo_root)


def actor_env_generation_count(repo_root: Path) -> int:
    return _generation_count("Actor-Env-Model", repo_root=repo_root)


def without_consumed_category(rec: dict) -> dict:
    return {k: v for k, v in rec.items() if k != "consumed_category"}


def by_id(rows: list[dict], id_key: str) -> dict[str, dict]:
    return {r[id_key]: r for r in rows}


def partition_committed(
    committed: list[dict], *, hold_committed: bool
) -> tuple[list[dict], list[dict]]:
    if hold_committed:
        return [without_consumed_category(c) for c in committed], []
    return [], committed




def git_head_sha(repo_root: Path) -> str:
    return _git.git_head_sha(repo_root)


def changes_outside(repo_root: Path, prefix: str) -> list[str]:
    return [
        path
        for _xy, path in _git.git_status(repo_root)
        if not (path.startswith(prefix) and path.endswith(".md"))
    ]


def corpus_dir_clean(repo_root: Path, corpus_dir: Path) -> bool:
    return not _git.git_status(repo_root, pathspec=corpus_dir)


def assert_clean_corpus_dir(repo_root: Path, corpus_dir: Path, corpus_dir_rel: str) -> None:
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
    msg = result.get("commit_message")
    if not isinstance(msg, str) or not msg.strip():
        raise AuthorError(
            f"AUTHOR_RESULT reported committed {noun} without a non-empty "
            "commit_message; refusing to commit"
        )
    return msg


def _result_entry_id(bucket: str, entry: Any, id_key: str) -> str:
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
    trailers = trailers or []
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


_MANIFEST_PROVENANCE_DROP = frozenset(
    {"source_finding_ids", "source_observation_ids", "created_at", "recorded_at"}
)


def build_corpus_manifest(corpus_dir: Path, *, seed: str | None = None) -> str:
    sections: list[str] = []
    skipped: list[Path] = []
    for lesson in iter_lessons(
        corpus_dir, warn_label=lambda p: f"corpus manifest: {p.name}", on_skip=skipped.append
    ):
        kept = {k: v for k, v in lesson.fm.items() if k not in _MANIFEST_PROVENANCE_DROP}
        rendered = yaml.safe_dump(
            kept, sort_keys=True, default_flow_style=False, allow_unicode=True
        )
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
    salt: str | None = None,
) -> str:
    seed = manifest_seed if manifest_seed is not None else batch_id
    manifest = build_corpus_manifest(corpus_dir, seed=seed) or "(none — the corpus is empty)"
    manifest_stems = "\n".join(
        line.removeprefix("## ")
        for line in manifest.splitlines()
        if line.startswith("## ")
    )
    context = (
        f"batch_id: {batch_id}\n"
        f"lessons_dir: {corpus_dir_rel}\n"
        f"{label} ({len(rows)}):\n\n"
        f"existing lessons (frontmatter manifest):\n{manifest}"
    )
    stage_salt = salt if salt is not None else uuid4().hex
    return stage_user_message(
        stage_salt,
        wrap(context, "curator_context", stage_salt),
        wrap(manifest_stems, "corpus_manifest", stage_salt),
        wrap(structured_json_body(rows) if rows else "", "lesson_rows", stage_salt),
    )
