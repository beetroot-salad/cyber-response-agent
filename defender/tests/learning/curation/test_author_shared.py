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


# #1108 P4 OD12(i): the worktree commit layer this file pinned is gone (O7: the commit-maker is the
# one maker of tenant commits; S-D's tenant_1108_p4/test_writers.py::test_o7_no_production_writer_commits_or_delivers_outside_the_tenant_commit_maker
# bans `commit_corpus`). Deleted, each with what covers it now:
#  - test_commit_corpus_commits_only_corpus / _stages_only_corpus / _no_op_when_nothing_authored /
#    _commit_failure_is_atomic: P3 tenant_1108_delivery/test_changes.py
#    ::test_change_set_is_the_draft_against_the_batch_base_and_commits_as_plain_files,
#    ::test_the_commit_maker_takes_no_lock_and_leaves_main_the_index_and_the_checkout_alone and
#    ::test_the_first_commit_makes_the_branch_and_never_takes_one_over; the author-level outcome
#    in test_author_postflight.py::test_committed_finding_consumed.
#  - test_commit_corpus_appends_trailers / _rejects_message_carrying_trailers /
#    _no_trailers_skips_the_dup_guard: the trailer path had no production caller left (its users
#    were the retired actor/environment corpora, U5); the commit-maker composes no trailers.
#  - test_changes_outside_flags_only_non_corpus_paths / test_verify_rejects_change_outside_corpus /
#    test_verify_tolerates_baseline_stray / test_corpus_dir_clean: `git status` scope over the
#    worktree. Out-of-lane box output now refuses the claim whole: P3 test_changes.py
#    ::test_a_claim_holding_anything_but_in_lane_regular_files_is_refused_whole and
#    ::test_no_change_set_commits_outside_the_lanes_or_touches_a_forbidden_name; author-level in
#    test_author_postflight.py::test_agent_writes_outside_lessons_aborts.
#  - test_verify_rejects_no_commit_with_corpus_edits / _committed_with_clean_corpus_using_noun:
#    the report-against-tree cross-check is kept at the author's entry point,
#    test_author_postflight.py::test_no_commit_but_left_corpus_edits_aborts and
#    ::test_committed_but_corpus_clean_aborts (over a draft).


@pytest.mark.parametrize("noun", ["findings", "observations"])
def test_commit_message_rejects_empty_with_corpus_noun(noun):
    """The missing/empty-message error names the corpus's unit of work — the single token that differs between..."""
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
    """Yields True when uncontended, makes the holding folder, and releases on exit. (Re-spelled from..."""
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
    """A genuine lock-subsystem failure (e.g. ENOLCK) propagates — it is NOT swallowed as contention. This is the..."""
    state = _state1135.state_over(tmp_path / "root")

    def _no_locks(_fd, _op):
        raise OSError(errno.ENOLCK, "No locks available")

    monkeypatch.setattr(_flock.fcntl, "flock", _no_locks)
    with pytest.raises(OSError, match="No locks available") as excinfo, \
            state.lock(_role(), wait=TRY_ONCE):
        pass
    assert excinfo.value.errno == errno.ENOLCK


def test_acquire_flock_closes_handle_when_error_propagates(tmp_path: Path, monkeypatch):
    """The fail-loud path (e.g. ENOLCK) must still close the lock-file handle: propagating must not leak the fd...."""
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


# content-less gates — the #722 defect class on the author's own result fields

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
    """This gate is what stands between the loop and committing a lesson edit with no explanation. `not..."""
    with pytest.raises(shared.AuthorError, match="without a non-empty"):
        shared.commit_message({"commit_message": text}, "findings")


@pytest.mark.parametrize(("tag", "text"), _CONTENT_LESS, ids=_CL_IDS)
def test_result_entry_ids_that_render_as_nothing_are_rejected(tag, text):
    """Both arms of `_result_entry_id`. The old truthiness check (`not entry`) was even blinder than `.strip()`:..."""
    with pytest.raises(shared.AuthorError, match="committed entries must be non-empty"):
        shared._result_entry_id("committed", text, "finding_id")
    with pytest.raises(shared.AuthorError, match="must include a non-empty"):
        shared._result_entry_id("skipped", {"finding_id": text}, "finding_id")


