"""The curator corpus-name domain: single-segment names only, never a whole-tree authoring scope."""
from __future__ import annotations

import pytest

pytest.importorskip("pydantic_ai")

from defender.tests.support.learning.curation._curator_691_harness import (  # noqa: E402
    bind_curator,
    corpus,
    make_worktree,
    pending_run_dir,
    write_file,
)

# A refusal must be about the name; the permissive disjunction avoids over-fitting the wording.
_NAME_REJECT_TOKENS = (
    "corpus", "segment", "relative", "single", "name", "membership", "shipped", "clean",
)


def _assert_bind_rejects_name(wt, run_dir, name: str) -> None:
    """Binding the curator with `name` raises a ValueError about the name, not an unrelated
    crash."""
    with pytest.raises(ValueError) as exc:  # noqa: PT011 - message shape asserted below
        bind_curator(wt, run_dir, name)
    msg = str(exc.value)
    assert any(tok in msg.lower() for tok in _NAME_REJECT_TOKENS) or repr(name) in msg, (
        f"bind rejected {name!r} but the message is not name-related: {exc.value!r}"
    )


def _assert_bind_accepts(wt, run_dir, name: str, expect_corpus_name: str):
    """Binding with `name` resolves the spawn's corpus to ``<wt>/defender/<expect_corpus_name>``."""
    deps = bind_curator(wt, run_dir, name)
    assert deps.corpus_dir.resolve() == corpus(wt, expect_corpus_name).resolve()
    return deps


@pytest.mark.parametrize(("case", "name"), [
    ("corpus_name has a leading dot slash", "./lessons"),
    # a trailing slash normalises away and the name is still one segment
    ("corpus_name has a trailing slash", "lessons/"),
], ids=lambda v: v if isinstance(v, str) else "")
def test_a_corpus_name_that_normalises_to_one_segment_binds_the_same_dir(tmp_path, case, name):
    """Normalisation is part of the ``corpus_name`` domain: a spelling that reduces to one
    segment binds the same corpus_dir as the bare name."""
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    deps = _assert_bind_accepts(wt, rd, name, "lessons")
    assert deps.corpus_dir.resolve() == bind_curator(wt, rd, "lessons").corpus_dir.resolve()


def test_the_standing_prohibition_on_a_whole_tree_authoring_scope(tmp_path):
    """The names that resolve to the tree itself are refused; an accepted corpus lies strictly
    below the tree, and a write at the tree's top level is refused."""
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    _assert_bind_rejects_name(wt, rd, "")
    _assert_bind_rejects_name(wt, rd, ".")
    deps = _assert_bind_accepts(wt, rd, "lessons", "lessons")
    assert deps.corpus_dir.resolve() != (wt / "defender").resolve()
    write_file(deps, "defender/lessons/lesson.md")  # in-corpus write lands (positive control)
    assert (wt / "defender" / "lessons" / "lesson.md").is_file()
    with pytest.raises(Exception):  # noqa: PT011, B017 - the write surface may raise ModelRetry or ValueError
        write_file(deps, "defender/toplevel.md")
