"""Curator read scope: confined to the three lesson corpora plus its own run dir; binding requires an explicit non-main tree."""
from __future__ import annotations

import pytest

pytest.importorskip("pydantic_ai")


from defender._paths import PATHS  # noqa: E402
from defender.runtime.agent_definition import RunScope, bind  # noqa: E402
from defender.learning.author.curator_engine import CORPUS_AUTHOR_DEF  # noqa: E402

from defender.tests.support.learning.curation._curator_691_harness import (  # noqa: E402
    confine,
    corpus,
    curator_deps,
    make_worktree,
    pending_run_dir,
    read_decision,
    rel,
    write_file,
)


def _reads(deps, path: str) -> bool:
    """Whether the lesson-read lane (``decide_read`` — roots + shapes) admits ``path``."""
    return read_decision(deps, path).allow


# O6 / R4 — the read confine


def test_a_read_inside_the_spawns_tree_but_outside_every_lesson_corpus(tmp_path):
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    (rd / "note.md").write_text("x\n", encoding="utf-8")
    deps = curator_deps(wt, rd, "lessons")
    assert not _reads(deps, "defender/docs/design.md")           # negative: docs
    assert not _reads(deps, "defender/SKILL.md")                 # negative: SKILL
    assert _reads(deps, str(rd / "note.md"))                     # positive control: own run dir


def test_a_spawn_reads_the_queue_it_was_spawned_over(tmp_path):
    """A read of the spawn's OWN run dir is ALLOW, before and after the change — the run dir is a
    read root independent of the confine (P2d). A file dropped in the run dir is readable."""
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    (rd / "queued.json").write_text("{}\n", encoding="utf-8")
    deps = curator_deps(wt, rd, "lessons")
    assert _reads(deps, str(rd / "queued.json"))


# M3 — the explicit worktree tree (the binding seam raises without one)

_EXPLICIT_TREE = r"explicit NON-PATHS defender_dir"


def _bind_no_tree(wt, rd, defender_dir):
    """Bind the curator through the seam with the given (mis-scoped) tree, no corpus_name field in
    play — isolates the M3 tree check. A bare-confine RunScope avoids the not-yet-built corpus_name
    field so the raise under test is the TREE refusal, not a missing-field error."""
    return bind(CORPUS_AUTHOR_DEF, rd, scope=RunScope(read_confine=confine(wt)), defender_dir=defender_dir)


def test_binding_the_curator_without_an_explicit_tree_raises(tmp_path):
    """The main-checkout-authoring state is UNBUILDABLE: binding the curator with no explicit NON-
    PATHS ``defender_dir`` raises, naming the tree requirement."""
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    with pytest.raises(ValueError, match=_EXPLICIT_TREE):
        _bind_no_tree(wt, rd, None)
    write_file(curator_deps(wt, rd, "lessons"), rel("lessons", "ok.md"), "body\n")  # control: authors
    assert (corpus(wt, "lessons") / "ok.md").read_text() == "body\n"


def test_defender_dir_is_the_main_checkout_paths_value(tmp_path):
    """``defender_dir=PATHS.defender_dir`` (the MAIN checkout) raises IDENTICALLY to the ``None`` case
    — the two collapse to the same refusal, so the curator can never anchor on the main tree (g16/P10)."""
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    with pytest.raises(ValueError, match=_EXPLICIT_TREE):
        _bind_no_tree(wt, rd, PATHS.defender_dir)
