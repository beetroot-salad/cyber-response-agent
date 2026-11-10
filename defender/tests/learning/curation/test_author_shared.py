"""Unit tests for the author's shared result gates (``_author_shared``).

Retired with the file queue (design r8 Locks): the `state.lock` / `flock_or_skip` tests (acquire then release, False when
held, a non-contention `OSError` propagating, the lock-file handle closed when it does): the handle's lock is deleted;
the claim's exclusion is the store's (`tests/tenancy/tenant_1108_p4/test_1278_tick.py`)."""
from __future__ import annotations

import pytest

from defender.learning.author import shared as shared  # type: ignore[import-not-found]


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


