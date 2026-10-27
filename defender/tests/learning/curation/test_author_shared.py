"""Unit tests for the author's shared result gates and the state lock (``_author_shared``)."""
from __future__ import annotations

import errno
from pathlib import Path

import pytest

from defender import _flock
from defender.learning.author import shared as shared  # type: ignore[import-not-found]
from defender.learning.core import state as state_mod
from defender.learning.core.state import TRY_ONCE, LockRole
from defender.tests.support.learning.core import _state1135


@pytest.mark.parametrize("noun", ["findings", "observations"])
def test_commit_message_rejects_empty_with_corpus_noun(noun):
    """The missing-message error names the corpus's unit of work, the one token that differs
    between channels."""
    with pytest.raises(shared.AuthorError, match=f"committed {noun} without"):
        shared.commit_message({"commit_message": ""}, noun)


def test_result_list_normalizes_and_validates():
    assert shared.result_list({}, "committed") == []
    assert shared.result_list({"committed": None}, "committed") == []
    assert shared.result_list({"committed": ["a"]}, "committed") == ["a"]
    with pytest.raises(shared.AuthorError, match="must be a list"):
        shared.result_list({"committed": "x"}, "committed")


def _role(name: str = ".lock") -> LockRole:
    return LockRole("test-role", name, _flock.FAST_POLL)


def test_flock_or_skip_acquires_then_releases(tmp_path: Path):
    """Yields True when uncontended, makes the holding folder, and releases on exit."""
    state = _state1135.state_over(tmp_path / "root")
    role = _role("sub/.lock")
    with state.lock(role, wait=TRY_ONCE) as locked:
        assert locked is True
        assert (tmp_path / "root" / "sub").is_dir()
    with state.lock(role, wait=TRY_ONCE) as again:
        assert again is True


def test_flock_or_skip_yields_false_when_held(tmp_path: Path):
    """A second entrant on a held lock yields False (skip) rather than blocking."""
    state = _state1135.state_over(tmp_path / "root")
    role = _role()
    with state.lock(role, wait=TRY_ONCE) as holder:
        assert holder is True
        with state.lock(role, wait=TRY_ONCE) as locked:
            assert locked is False


def test_flock_or_skip_propagates_non_contention_oserror(tmp_path: Path, monkeypatch):
    """A genuine lock-subsystem failure (ENOLCK) propagates instead of reading as contention."""
    state = _state1135.state_over(tmp_path / "root")

    def _no_locks(_fd, _op):
        raise OSError(errno.ENOLCK, "No locks available")

    monkeypatch.setattr(_flock.fcntl, "flock", _no_locks)
    with pytest.raises(OSError, match="No locks available") as excinfo, \
            state.lock(_role(), wait=TRY_ONCE):
        pass
    assert excinfo.value.errno == errno.ENOLCK


def test_acquire_flock_closes_handle_when_error_propagates(tmp_path: Path, monkeypatch):
    """When ENOLCK propagates, the lock-file handle is still closed: no fd leaks."""
    state = _state1135.state_over(tmp_path / "root")
    opened: list = []
    real_open = state_mod.open_lock_at

    def _tracking_open(held, name):
        fh = real_open(held, name)
        opened.append(fh)
        return fh

    def _no_locks(_fd, _op):
        raise OSError(errno.ENOLCK, "No locks available")

    monkeypatch.setattr(state_mod, "open_lock_at", _tracking_open)  # lint-monkeypatch: ok — an fd-leak spy on the module-level lock opener; the handle has no seam for it
    monkeypatch.setattr(_flock.fcntl, "flock", _no_locks)
    with pytest.raises(OSError, match="No locks available"), state.lock(_role(), wait=TRY_ONCE):
        pass
    assert opened, "the handle never opened the lock file"
    assert all(fh.closed for fh in opened), "the handle leaked the lock-file handle"


# content-less gates (#722) on the author's own result fields

_CONTENT_LESS = [
    ("ascii-space", " "),
    ("U+00A0-no-break-space", " "),
    ("U+200B-zero-width-space", "​"),
    ("U+FEFF-byte-order-mark", "﻿"),
    ("U+0000-nul", "\x00"),
]
_CL_IDS = [t for t, _ in _CONTENT_LESS]


@pytest.mark.parametrize(("tag", "text"), _CONTENT_LESS, ids=_CL_IDS)
def test_commit_message_rejects_a_message_that_renders_as_nothing(tag, text):
    """The last gate before a lesson edit is committed with no explanation: `.strip()` alone
    would pass the zero-width, BOM and NUL cases."""
    with pytest.raises(shared.AuthorError, match="without a non-empty"):
        shared.commit_message({"commit_message": text}, "findings")


@pytest.mark.parametrize(("tag", "text"), _CONTENT_LESS, ids=_CL_IDS)
def test_result_entry_ids_that_render_as_nothing_are_rejected(tag, text):
    """Both arms of `_result_entry_id` (a bare `committed` id, a bucket entry's id field) refuse
    text that renders as nothing."""
    with pytest.raises(shared.AuthorError, match="committed entries must be non-empty"):
        shared._result_entry_id("committed", text, "finding_id")
    with pytest.raises(shared.AuthorError, match="must include a non-empty"):
        shared._result_entry_id("skipped", {"finding_id": text}, "finding_id")


