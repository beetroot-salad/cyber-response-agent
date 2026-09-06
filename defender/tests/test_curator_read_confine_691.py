"""#691 curator-bindable — the read scope (O6/R4) and the explicit-tree requirement (M3).

RED against HEAD by design. Two mechanisms this file pins:

* **R4 read confine.** The curator declares ``requires_confine=True`` with the confine set to the
  three shipped lesson corpora; ``_resolved_read_roots`` REPLACES the ``defender_dir`` base with the
  confine. Observable matrix (P2d executed): a SIBLING corpus ``lesson_read`` ALLOWs (the confine
  spans all three), ``defender/docs`` and ``defender/SKILL.md`` flip ALLOW→DENY, the spawn's OWN
  run dir stays ALLOW, and the bash ``cat`` scope stays own-corpus (sibling ``cat`` DENY — the
  deliberate divergence from ``lesson_read``). Today ``for_run``'s policy carries ``read_confine=()``
  so a ``docs`` read is ALLOWED through the wide ``defender_dir`` base — that is the RED, each
  read-negative failing on its own assertion (the confine correction is unbuilt).

  REFUTED, not pinned: c17/g10 "M2 narrows read_allow to the corpus shape" (read_allow stays EMPTY,
  the confine carries the narrowing on the roots half); c20's own-corpus-only runtime-safety reading
  (the committed suite pins the CROSS-corpus reads, and R4 KEEPS them).

* **M3 explicit tree.** Binding the curator with no explicit NON-PATHS ``defender_dir`` raises — the
  main-checkout-authoring state is unbuildable. Driven through the binding seam ``bind``; RED today
  (``bindable=False`` raises first — the message assertion pins that the DEMANDED tree refusal is
  what a green #0 must surface, not the incidental unbindable error).

Gate lanes are driven through the shared harness (``read_decision`` → ``decide_read`` roots+shapes,
``bash_decision`` → ``decide_bash`` cat scope, ``forward_check_gate`` → ``decide_write``); the
CuratorDeps under test is the STABLE ``for_run`` deps whose ``.policy`` the refactor re-anchors.
"""
from __future__ import annotations

import pytest

pytest.importorskip("pydantic_ai")

from pydantic_ai.exceptions import ModelRetry  # noqa: E402

from defender._paths import PATHS  # noqa: E402
from defender.runtime.agent_definition import RunScope, bind  # noqa: E402
from defender.learning.author.curator_engine import CORPUS_AUTHOR_DEF  # noqa: E402

from _curator_691_harness import (  # noqa: E402
    bash_decision,
    confine,
    corpus,
    curator_deps,
    forward_check_gate,
    make_worktree,
    pending_run_dir,
    read_decision,
    rel,
    write_file,
)


def _reads(deps, path: str) -> bool:
    """Whether the lesson-read lane (``decide_read`` — roots + shapes) admits ``path``."""
    return read_decision(deps, path).allow


def _cats(deps, path: str) -> bool:
    """Whether the bash ``cat`` lane admits ``path`` (its grant scope, own-corpus only)."""
    return bash_decision(deps, f"cat {path}").allow


# O6 / R4 — the read confine





def test_a_read_inside_the_spawns_tree_but_outside_every_lesson_corpus(tmp_path):
    """NEGATIVE + control: a read of ``defender/docs/*.md`` and ``defender/SKILL.md`` — inside the
    worktree but outside every lesson corpus — DENYs under the confine; the spawn's OWN run-dir file
    stays ALLOW (the run dir is a read root independent of the confine). RED today: docs/SKILL are
    admitted through the wide ``defender_dir`` base the confine has not yet replaced."""
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






def test_the_curator_reads_no_longer_reach_defender_docs(tmp_path):
    """The prompt line that named ``defender/docs/…`` is denied after the confine (g13): a read of a
    ``defender/docs`` path DENYs while the curator's own-corpus read still ALLOWs (control). RED
    today: the wide ``defender_dir`` base admits docs; R5 additionally updates the prompt line."""
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    deps = curator_deps(wt, rd, "lessons")
    assert not _reads(deps, "defender/docs/learning-loop.md")    # the prompt-named docs path: DENY
    assert _reads(deps, rel("lessons", "own.md"))                # control: own corpus still reads


# M3 — the explicit worktree tree (the binding seam raises without one)

_EXPLICIT_TREE = r"explicit NON-PATHS defender_dir"


def _bind_no_tree(wt, rd, defender_dir):
    """Bind the curator through the seam with the given (mis-scoped) tree, no corpus_name field in
    play — isolates the M3 tree check. A bare-confine RunScope avoids the not-yet-built corpus_name
    field so the raise under test is the TREE refusal, not a missing-field error."""
    return bind(CORPUS_AUTHOR_DEF, rd, scope=RunScope(read_confine=confine(wt)), defender_dir=defender_dir)


def test_binding_the_curator_without_an_explicit_tree_raises(tmp_path):
    """The main-checkout-authoring state is UNBUILDABLE: binding the curator with no explicit
    NON-PATHS ``defender_dir`` raises, naming the tree requirement. Positive control: the stable
    ``for_run`` drain path (an explicit worktree tree) authors an in-corpus lesson. RED today: the
    seam raises the incidental ``bindable=False`` message, not the demanded tree refusal."""
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    with pytest.raises(ValueError, match=_EXPLICIT_TREE):
        _bind_no_tree(wt, rd, None)
    write_file(curator_deps(wt, rd, "lessons"), rel("lessons", "ok.md"), "body\n")  # control: authors
    assert (corpus(wt, "lessons") / "ok.md").read_text() == "body\n"


def test_defender_dir_is_none_for_a_role_that_requires_an_explicit_tree(tmp_path):
    """``defender_dir=None`` for the tree-requiring curator raises "requires an explicit NON-PATHS
    defender_dir" (g16/P10) — a None tree would author the MAIN checkout. RED today (bindable message)."""
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    with pytest.raises(ValueError, match=_EXPLICIT_TREE):
        _bind_no_tree(wt, rd, None)


def test_defender_dir_is_the_main_checkout_paths_value(tmp_path):
    """``defender_dir=PATHS.defender_dir`` (the MAIN checkout) raises IDENTICALLY to the ``None`` case
    — the two collapse to the same refusal, so the curator can never anchor on the main tree (g16/P10)."""
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    with pytest.raises(ValueError, match=_EXPLICIT_TREE):
        _bind_no_tree(wt, rd, PATHS.defender_dir)






