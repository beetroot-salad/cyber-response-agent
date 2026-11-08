"""The worker's real start (#1344 O15, D8): its settings, the one-worker-per-machine lock on the
data root, and the code copy its children and their boxes run from.

Order: the settings are read and judged first (a build stamp that is not a commit, bad slots), so a refused start
touches nothing; then an exclusive kernel lock on the data root, so a refused second worker never
touches the first one's live copy; then the copy is replaced. The lock lives as long as the process
(the kernel drops it with the descriptor), across containers that share the mount.

The copy is one folder on the data mount (`<data root>/.defender-code`), with the repository root's
shape: `defender/` inside it beside a marker file, `.defender-code-copy.json` (`{"commit": ...}`),
which children stamp as the build commit (`records` reads the marker before asking git). Replaced
whole at every start: no `.venv`, no bytecode, every file and folder without write bits. Box mounts
need a path the Docker daemon can see; baked image code is on none.

The copy is built in place, not in a staging folder renamed over it: the lock already keeps every
other worker out, no child starts before the copy is whole, and a rename would pull a tree out from
under anything walking the data root. The marker appears last, whole (written beside and renamed),
so a folder without it is an unfinished copy that the next start removes."""
from __future__ import annotations

import fcntl
import json
import os
import re
import shutil
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from defender import _io
from defender.records.formats import BUILD_COMMIT_ENV, CODE_COPY_MARKER, is_build_commit

#: The variables the deployed worker reads (`BUILD_COMMIT_ENV` is the stamp's own, from `records`).
DSN_ENV = "DEFENDER_DATABASE_DSN"
DATA_ROOT_ENV = "DEFENDER_DATA_ROOT"
SLOTS_ENV = "DEFENDER_WORKER_SLOTS"
LEARNING_SLOTS_ENV = "DEFENDER_WORKER_LEARNING_SLOTS"
LEARNING_CHECK_ENV = "DEFENDER_WORKER_LEARNING_CHECK_SECONDS"
DEFAULT_SLOTS = 3
#: How long a tenant goes without a post-step before the worker checks it without a family (#1344
#: amendment 1).
DEFAULT_LEARNING_CHECK_SECONDS = 300

#: The marker at the copy's root (the one name a run's stamp reads, `records.formats`), and the
#: copy's and the lock's names on the data root.
MARKER = CODE_COPY_MARKER
COPY_NAME = ".defender-code"
LOCK_NAME = ".defender-worker.lock"
#: What a copy never carries: the virtual environment, bytecode and tool caches.
_LEFT_OUT = (".venv", "__pycache__", "*.pyc", ".pytest_cache", ".mypy_cache", ".ruff_cache")
_NO_WRITE = ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH)


class WorkerStartRefused(Exception):
    """The worker will not start: the message names the setting, the lock or the copy."""


@dataclass(frozen=True)
class Settings:
    dsn: str
    root: Path
    build_commit: str
    slots: int
    learning_slots: int
    learning_check_seconds: int = DEFAULT_LEARNING_CHECK_SECONDS


def _setting_count(environ: Mapping[str, str], name: str, default: int) -> int:
    raw = environ.get(name)
    if raw is None:
        return default
    if not re.fullmatch(r"-?[0-9]+", raw.strip()):
        raise WorkerStartRefused(f"{name}={raw!r} is not a whole number")
    return int(raw.strip())


def build_commit(environ: Mapping[str, str]) -> str:
    """The build stamp in `environ`, exactly as given, when it is a commit as a code copy's marker
    is read (`records.formats.is_build_commit`: lowercase hex, 7 to 64 characters); anything else
    (unset, empty, a tag or branch name, uppercase, a `-dirty` suffix, whitespace) is
    `WorkerStartRefused`. Children stamp the copy's marker as their build commit, so a stamp the
    marker reader would not take is refused here, before anything is touched."""
    raw = environ.get(BUILD_COMMIT_ENV)
    if raw is None or not raw.strip():
        raise WorkerStartRefused(
            f"{BUILD_COMMIT_ENV} is empty or unset: the worker's code copy is stamped with the build's commit, "
            "and there is no other source for it")
    if not is_build_commit(raw):
        raise WorkerStartRefused(
            f"{BUILD_COMMIT_ENV}={raw!r} is not a commit: the code copy's marker names the build's commit as "
            "7 to 64 lowercase hex characters, nothing else (no tag, branch name, suffix or whitespace)")
    return raw


def read_settings(environ: Mapping[str, str]) -> Settings:
    """The worker's settings, judged before any work: a build stamp that is a commit
    (`build_commit`), slots of at least one, learning slots between 0 and slots - 1 (default
    min(1, slots - 1)), and the family-less check's interval, whole seconds of at least 1
    (default 300). Learning is on by default in production (#1344 D3); 0 is the off switch."""
    commit = build_commit(environ)
    slots = _setting_count(environ, SLOTS_ENV, DEFAULT_SLOTS)
    if slots < 1:
        raise WorkerStartRefused(f"{SLOTS_ENV}={slots} must be at least 1")
    learning = _setting_count(environ, LEARNING_SLOTS_ENV, min(1, slots - 1))
    if not 0 <= learning <= slots - 1:
        raise WorkerStartRefused(
            f"{LEARNING_SLOTS_ENV}={learning} must be between 0 and {SLOTS_ENV} - 1 ({slots - 1}): "
            "investigations always keep a slot")
    check = _setting_count(environ, LEARNING_CHECK_ENV, DEFAULT_LEARNING_CHECK_SECONDS)
    if check < 1:
        raise WorkerStartRefused(f"{LEARNING_CHECK_ENV}={check} must be at least 1 (seconds)")
    dsn = environ.get(DSN_ENV, "")
    if not dsn:
        raise WorkerStartRefused(f"{DSN_ENV} is not set: the worker claims its work from the job store")
    raw_root = environ.get(DATA_ROOT_ENV, "")
    if not raw_root or not os.path.isabs(raw_root):
        raise WorkerStartRefused(f"{DATA_ROOT_ENV}={raw_root!r} must be an absolute path: there is no default")
    root = Path(raw_root).resolve()
    if not root.is_dir():
        raise WorkerStartRefused(f"{DATA_ROOT_ENV}={raw_root!r} is not a folder")
    return Settings(dsn=dsn, root=root, build_commit=commit, slots=slots, learning_slots=learning,
                    learning_check_seconds=check)


def hold_start_lock(data_root: Path) -> int:
    """An exclusive kernel lock on the data root, held by the returned descriptor for the life of
    the process. Another worker holding it is `WorkerStartRefused`, and nothing is touched."""
    fd = os.open(Path(data_root) / LOCK_NAME, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        raise WorkerStartRefused(
            f"another worker already holds the lock on the data root {data_root}: one worker per machine; "
            "this one did not start") from None
    except OSError:
        os.close(fd)
        raise
    return fd


def refresh_code_copy(data_root: Path, *, source: Path, environ: Mapping[str, str]) -> Path:
    """Replace the code copy on the data root with a fresh read-only copy of `source` (the parent
    of the running `defender/`), marked with the build stamp from `environ`, and return its root.
    The caller holds the start lock. A stamp that is not a commit, or a copy that cannot be made,
    is `WorkerStartRefused`."""
    commit = build_commit(environ)
    package = Path(source) / "defender"
    if not (package / "run.py").is_file():
        raise WorkerStartRefused(f"{source} has no defender/run.py: it is not a code tree to copy")
    target = Path(data_root) / COPY_NAME
    try:
        _clear_old_copy(target)
        _io.guarded_mkdir(target, base=Path(data_root))
        shutil.copytree(package, target / "defender", symlinks=True, ignore=shutil.ignore_patterns(*_LEFT_OUT))
        _read_only(target / "defender")
        _io.write_guarded(target / MARKER, json.dumps({"commit": commit}), encoding="utf-8")
        _read_only(target / MARKER)
        os.chmod(target, os.lstat(target).st_mode & _NO_WRITE & 0o7777)
    except OSError as fault:
        raise WorkerStartRefused(f"the code copy at {target} could not be made: {fault}") from None
    return target


def _clear_old_copy(tree: Path) -> None:
    """Remove a previous copy, whose folders carry no write bits."""
    if not tree.exists() and not tree.is_symlink():
        return
    if tree.is_symlink() or not tree.is_dir():
        tree.unlink()
        return
    for folder, dirs, _files in os.walk(tree):
        for name in (folder, *(os.path.join(folder, d) for d in dirs)):
            if not os.path.islink(name):
                os.chmod(name, stat.S_IRWXU)
    shutil.rmtree(tree)


def _read_only(tree: Path) -> None:
    """Every file and folder of a tree (or one file), the root included, without write bits; links
    untouched. Folders are walked bottom up, and a folder's own bits go last."""
    for folder, dirs, files in os.walk(tree, topdown=False):
        for name in (*files, *dirs):
            path = os.path.join(folder, name)
            if not os.path.islink(path):
                os.chmod(path, os.lstat(path).st_mode & _NO_WRITE & 0o7777)
    os.chmod(tree, os.lstat(tree).st_mode & _NO_WRITE & 0o7777)
