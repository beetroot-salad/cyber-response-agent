"""#773 — the drain computes everything from ONE truth, the settled corpus tree.

Regression coverage for the review of PR #1064, whose findings all shared a shape: the
drain kept a second truth alive beside the tree — a pass-1 verdict that outlived the bytes
it judged, the curator's own account of what it committed, a copy of the first spawn's
cleanup that the second spawn was held to differently. (#1166 deleted the verdict and the
second spawn; what is left here is the tree's side of each probe.) Each test here is one of those
probes, replayed against the rewrite that removed the second truth.

NOT part of the locked #773 spec suite (`test_773_*.py` committed by write-tests) — these
live beside it and drive the same scene substrate.
"""
from __future__ import annotations

import dataclasses
import os
import stat

from defender.tests import _spec773 as S
from defender.tests._curator1134 import JournalBound, JournalHeld
from defender.tests._drain719 import git

LESSON = "defender/lessons/l1.md"
LESSON2 = "defender/lessons/l2.md"


def _corpus_status(sc) -> list[str]:
    out = git(sc.repo, "status", "--porcelain", "--untracked-files=all", "--", "defender/lessons").stdout
    return [line for line in out.splitlines() if line.strip()]


# ---------------------------------------------------------------------------
# an approval never outlives the bytes it read
# ---------------------------------------------------------------------------


class _Rewriting(JournalHeld):
    """The real corpus handle, except that reading `l1.md` through its view hands back what
    the file held and then lets `edit(n)` rewrite it on disk, `n` counting those reads from 1:
    another writer moving the file between the drain's reads."""

    def __init__(self, root, edit) -> None:
        super().__init__(root, [])
        self.edit, self.reads = edit, 0

    def view(self):
        outer = self

        class View(JournalBound):
            def read(self, name, *, errors="strict"):
                got = super().read(name, errors=errors)
                if str(name) == "l1.md":
                    outer.reads += 1
                    outer.edit(outer.reads)
                return got

        return View(self._os, self._root, log=self.log, refuse=self.refuse, extra=self.extra)


def _rewriting_scene(tmp_path, edit):
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1")}),
    )
    sc.cfg = dataclasses.replace(sc.cfg, corpus=_Rewriting(sc.cfg.corpus_dir, edit))
    return sc


def test_a_concurrent_edit_that_strips_the_citations_mid_read_is_not_committed(tmp_path):
    """While the drain reads `l1.md`'s citations, another writer strips them (after the
    second read: the attributable check's is the first, the citation read's own first round
    the second). The citations the drain approved on cannot stand for bytes that cite
    nothing: the re-read sees the move, the file is not approved, not committed, and the tree
    is put back. (#1166 moved this from the deleted forward check to the citation read.)"""
    stripped = S.lesson(body="no citations any more")
    sc = _rewriting_scene(tmp_path, lambda n: n == 2 and (
        sc.corpus / "l1.md").write_text(stripped, encoding="utf-8"))

    assert sc.run() == 0
    assert sc.cfg.corpus.reads > 2, "the drain never re-read the file, so the row is vacuous"
    assert sc.head_files() == []
    assert sc.category_of("f1") != "consumed_committed"
    assert _corpus_status(sc) == []


def test_a_file_that_never_holds_still_under_the_citation_read_refuses_the_tick(tmp_path):
    """A writer that rewrites `l1.md` after every read, each version still citing f1: no
    round of the citation read sees the same bytes twice, so the tick refuses with
    `AuthorError` (rc 2, f1 charged an attempt) rather than commit bytes no citation was read
    from."""
    sc = _rewriting_scene(tmp_path, lambda n: (sc.corpus / "l1.md").write_text(
        S.lesson("f1", body=f"version {n}"), encoding="utf-8"))

    assert sc.run() == 2
    assert sc.head_files() == []
    assert sc.pending_by_id()["f1"].get("attempts") == 1
    assert any("kept changing" in str(r.get("reason"))
               for r in S.stuck_records(sc.paths, sc.channel))


# ---------------------------------------------------------------------------
# the settle puts back what no lesson needs
# ---------------------------------------------------------------------------


def test_a_mode_only_change_is_put_back_and_the_tree_is_clean_after_the_tick(tmp_path):
    """A tracked lesson whose bytes are unchanged but whose mode bit flipped is not content
    the check must judge — and it is not left dirty either. The next tick on the same
    checkout starts clean."""
    old = S.lesson("older", body="the old lesson")

    def flip_the_mode(rows, batch_id, cfg):
        target = cfg.corpus_dir / "old.md"
        target.chmod(target.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        seed_corpus={"old.md": old},
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1")}, also=flip_the_mode),
    )
    git(sc.repo, "config", "core.fileMode", "true")
    assert sc.run() == 0
    assert sc.head_files() == [LESSON]
    assert _corpus_status(sc) == []
    assert not os.stat(sc.corpus / "old.md").st_mode & stat.S_IXUSR


# ---------------------------------------------------------------------------
# a row's fate is read off the tree, not off the curator's word
# ---------------------------------------------------------------------------


def test_a_finding_the_curator_did_not_report_but_an_approved_file_cites_is_committed(tmp_path):
    """The curator writes lessons for a and b, reports only a. The tree says both landed:
    both are `consumed_committed`, and b is not left queued with no counter."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("a", run_id="a"), S.finding_row("b", run_id="b")],
        curator=S.FakeCurator(
            writes={"l1.md": S.lesson("a"), "l2.md": S.lesson("b")}, committed=["a"],
        ),
    )
    assert sc.run() == 0
    assert sc.head_files() == [LESSON, LESSON2]
    assert sc.category_of("a") == "consumed_committed"
    assert sc.category_of("b") == "consumed_committed"
    assert sc.pending_by_id() == {}


def test_a_finding_the_curator_filed_as_skipped_but_wrote_a_lesson_for_takes_the_trees_fate(tmp_path):
    """The curator says "skip x" and also writes a lesson citing x. The tree outranks the
    bucket: x is judged, and on a GOOD it is committed — once, in one category.

    `verify_agent_report` refuses a dirty corpus with an empty `committed` (the self-report
    and tree disagree), so the shape needs a second, honestly committed row beside x."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("x", run_id="x"), S.finding_row("y", run_id="y")],
        curator=S.FakeCurator(
            writes={"l1.md": S.lesson("x"), "l2.md": S.lesson("y")},
            committed=["y"],
            consumed_skip=[{"finding_id": "x", "reason": "already taught"}],
        ),
    )
    assert sc.run() == 0
    assert sc.head_files() == [LESSON, LESSON2]
    assert [r["finding_id"] for r in sc.consumed()].count("x") == 1
    assert sc.category_of("x") == "consumed_committed"
