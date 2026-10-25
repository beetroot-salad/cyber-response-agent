"""Curator write lanes: .md-only writes and single-operand rm confined to its own corpus, symlink escapes denied, write scope within the read confine."""
from __future__ import annotations

import pytest

pytest.importorskip("pydantic_ai")

from pydantic_ai.exceptions import ModelRetry  # noqa: E402

from defender.tests.support.learning.curation._curator_691_harness import (  # noqa: E402
    bash_decision,
    bind_curator,
    corpus,
    curator_deps,
    edit_file,
    lesson_read,
    make_worktree,
    pending_run_dir,
    rel,
    write_file,
)


# The both-surfaces pairing lives in the file (not the harness) so the intent — a policy tight on
# write_file but loose on edit_file is the fail-open — stays visible at each call site.
def _denied_on_both_write_surfaces(deps, path: str) -> None:
    with pytest.raises(ModelRetry):
        write_file(deps, path, "body\n")
    with pytest.raises(ModelRetry):
        edit_file(deps, path, "", "body\n")


def _admitted_in_corpus(wt, deps, corpus_name: str, stem: str = "lesson") -> None:
    r = rel(corpus_name, f"{stem}.md")
    landed = corpus(wt, corpus_name) / f"{stem}.md"
    write_file(deps, r, "body\n")               # admitted → lands
    assert landed.read_text() == "body\n"
    edit_file(deps, r, "body\n", "edited\n")     # admitted → real in-place edit
    assert landed.read_text() == "edited\n"


# O2 / S1 / S4 — the write scope roots at the worktree corpus, not run_dir

def test_write_allow_roots_at_the_worktree_corpus_not_run_dir(tmp_path):
    """The compiled write scope roots at <worktree>/defender/<corpus>, NOT run_dir: an in-corpus .md
    write LANDS on both write surfaces, a run_dir .md write is DENIED on both."""
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    deps = curator_deps(wt, rd, "lessons")
    _admitted_in_corpus(wt, deps, "lessons")                  # roots at the worktree corpus
    _denied_on_both_write_surfaces(deps, str(rd / "scratch.md"))  # NOT run-dir-rooted


def test_the_curator_cannot_write_outside_its_own_corpus(tmp_path):
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    deps = curator_deps(wt, rd, "lessons")
    _denied_on_both_write_surfaces(deps, rel("lessons-questioner", "x.md"))    # a sibling corpus
    _denied_on_both_write_surfaces(deps, str(rd / "x.md"))                # run_dir
    _denied_on_both_write_surfaces(deps, "defender/skills/x.md")          # MAIN checkout, not the corpus
    assert not (corpus(wt, "lessons-questioner") / "x.md").exists()            # nothing landed cross-corpus
    _admitted_in_corpus(wt, deps, "lessons")                             # positive control


def test_the_curator_cannot_write_a_non_md_path(tmp_path):
    """A non-.md write UNDER the corpus (.py, .txt, no extension) is DENIED on both surfaces
    (build_write_allow suffix='.md'); the sibling .md write succeeds (control)."""
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    deps = curator_deps(wt, rd, "lessons")
    for bad in ("note.py", "note.txt", "noext"):
        _denied_on_both_write_surfaces(deps, rel("lessons", bad))
    _admitted_in_corpus(wt, deps, "lessons")


def test_a_write_operand_filename_extension_differs_only_in_letter_case_from_md(tmp_path):
    """`.MD` is refused on both surfaces — the compiled tail is a literal `\\.md` with no case flag
    (g8's observed pattern); the lowercase `.md` write succeeds (control)."""
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    deps = curator_deps(wt, rd, "lessons")
    _denied_on_both_write_surfaces(deps, rel("lessons", "LESSON.MD"))
    _admitted_in_corpus(wt, deps, "lessons")


def test_a_write_operand_path_is_given_relative_with_a_leading_dot_slash(tmp_path):
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    deps = curator_deps(wt, rd, "lessons")
    write_file(deps, "./" + rel("lessons", "dot.md"), "body\n")
    assert (corpus(wt, "lessons") / "dot.md").read_text() == "body\n"


# MD-1 (RG-1 / D1) — a mis-scoped curator is unbuildable (refuse at bind)

def test_a_non_shipped_corpus_name_write_is_denied_by_confine_containment(tmp_path):
    """MD-1 / D1: a curator whose write scope roots OUTSIDE its own read confine is UNBUILDABLE —
    bind REFUSES a name (e.g."""
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    with pytest.raises(ValueError, match=r"confine|scope|outside|author|contain"):
        bind_curator(wt, rd, "skills")                       # skills ∉ the three-corpus confine
    deps = bind_curator(wt, rd, "lessons")                    # in-confine → buildable (control)
    write_file(deps, rel("lessons", "ok.md"), "body\n")
    assert (corpus(wt, "lessons") / "ok.md").read_text() == "body\n"


def test_a_shipped_corpus_write_is_denied_when_its_read_confine_excludes_it(tmp_path):
    """MD-1 / D1 ISOLATED from MD-6 (the F18 scenario)."""
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    excludes_lessons = (
        corpus(wt, "lessons-questioner").resolve(),
    )                                                              # a confine that omits `lessons`
    with pytest.raises(ValueError, match=r"confine|scope|outside|author|contain"):
        bind_curator(wt, rd, "lessons", read_confine=excludes_lessons)  # write scope ⊄ the confine
    includes_lessons = (corpus(wt, "lessons").resolve(),)        # a confine that CONTAINS `lessons`
    deps = bind_curator(wt, rd, "lessons", read_confine=includes_lessons)  # buildable (control)
    write_file(deps, rel("lessons", "ok.md"), "body\n")
    assert (corpus(wt, "lessons") / "ok.md").read_text() == "body\n"


# S3 / MD-3 / MD-4 / MD-5 — the rm lane and the four-lane parity

def test_the_rm_lane_is_scoped_to_the_same_corpus_as_the_write_lane(tmp_path):
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    deps = curator_deps(wt, rd, "lessons")
    assert bash_decision(deps, "rm defender/lessons/draft.md").allow          # own corpus (control)
    assert not bash_decision(deps, "rm defender/lessons-questioner/draft.md").allow  # sibling
    assert not bash_decision(deps, "rm -rf defender/lessons/draft.md").allow    # a flag
    assert not bash_decision(deps, "rm defender/lessons/a.md defender/lessons/b.md").allow  # two paths


def test_all_write_lanes_deny_a_symlink_out_of_corpus(tmp_path):
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    deps = curator_deps(wt, rd, "lessons")
    # a symlink inside the corpus pointing at the sibling corpus
    (corpus(wt, "lessons") / "escape").symlink_to(corpus(wt, "lessons-questioner"))
    escape = "defender/lessons/escape/secret.md"          # resolves to lessons-questioner/secret.md
    # every lane must DENY the escaping operand
    with pytest.raises(ModelRetry):
        write_file(deps, escape, "body\n")
    with pytest.raises(ModelRetry):
        edit_file(deps, escape, "", "body\n")
    assert not bash_decision(deps, f"rm {escape}").allow   # RED today: the rm grant deletes it
    assert not (corpus(wt, "lessons-questioner") / "secret.md").exists()  # the escape wrote nothing
    # positive control: an in-corpus operand admitted by every lane
    (corpus(wt, "lessons") / "real.md").write_text("body\n", encoding="utf-8")
    write_file(deps, rel("lessons", "real.md"), "body\n")
    edit_file(deps, rel("lessons", "real.md"), "body\n", "edited\n")
    assert bash_decision(deps, "rm " + rel("lessons", "real.md")).allow


def test_the_rm_grant_matches_the_shell_tokenized_argv(tmp_path):
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    deps = curator_deps(wt, rd, "lessons")
    assert not bash_decision(deps, "rm defender/lessons/$(whoami).md").allow
    assert not bash_decision(deps, "rm defender/lessons/`whoami`.md").allow
    assert not bash_decision(deps, "rm defender/lessons/x.md; echo hi").allow
    assert bash_decision(deps, "rm defender/lessons/draft.md").allow          # positive control


def test_a_single_operand_in_corpus_rm_is_admitted(tmp_path):
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    deps = curator_deps(wt, rd, "lessons")
    assert bash_decision(deps, "rm defender/lessons/draft.md").allow


def test_a_single_rm_naming_two_corpora_is_denied(tmp_path):
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    deps = curator_deps(wt, rd, "lessons")
    assert not bash_decision(
        deps, "rm defender/lessons/x.md defender/lessons-questioner/y.md"
    ).allow
    assert not bash_decision(deps, "rm defender/lessons/x.md defender/lessons/y.md").allow
    assert bash_decision(deps, "rm defender/lessons/single.md").allow          # positive control


# MD-7 / F77 / f7 — the write lane and the read lane admit the same names

def test_a_lesson_the_curator_can_write_it_can_read_back(tmp_path):
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    deps = curator_deps(wt, rd, "lessons")
    out_of_class = rel("lessons", "my lesson.md")   # a space — outside the read segment class
    # the read lane (the cat scope's `[\w.@=+-]+` segment class) already refuses the space today;
    # the write lane MUST refuse it too so the two lanes admit the same names (the correction).
    assert not bash_decision(deps, "cat " + out_of_class).allow
    with pytest.raises(ModelRetry):
        write_file(deps, out_of_class, "body\n")     # RED today: the write tail admits the space
    write_file(deps, rel("lessons", "good.md"), "hello\n")
    assert bash_decision(deps, "cat " + rel("lessons", "good.md")).allow
    reader = curator_deps(wt, rd, "lessons")
    assert "hello" in lesson_read(reader, rel("lessons", "good.md"))
