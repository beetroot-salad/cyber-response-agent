"""#773 — the drain computes everything from ONE truth, the settled corpus tree.

#1108 P4 (O7): the tree is a batch's git-free draft; what landed is read from the batch branch,
and "clean after the tick" is the draft re-synced to that branch (`DraftScene.draft_drift`)."""
from __future__ import annotations

import dataclasses
import stat

from defender.tests.support.learning.curation import _spec773 as S
from defender.tests.support.learning.curation._curator1134 import JournalBound, JournalHeld

LESSON = "agent/lessons/l1.md"
LESSON2 = "agent/lessons/l2.md"


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
    sc = S.build_draft_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1")}),
    )
    sc.cfg = dataclasses.replace(sc.cfg, corpus=_Rewriting(sc.cfg.corpus_dir, edit))
    return sc


def test_a_concurrent_edit_that_strips_the_citations_mid_read_is_not_committed(tmp_path):
    """While the drain reads `l1.md`'s citations, another writer strips them (after the
    second read."""
    stripped = S.lesson(body="no citations any more")
    sc = _rewriting_scene(tmp_path, lambda n: n == 2 and (
        sc.corpus / "l1.md").write_text(stripped, encoding="utf-8"))

    assert sc.run() == 0
    assert sc.cfg.corpus.reads > 2, "the drain never re-read the file, so the row is vacuous"
    assert sc.head_files() == []
    assert sc.category_of("f1") != "consumed_committed"
    assert sc.draft_drift() == []


def test_a_file_that_never_holds_still_under_the_citation_read_refuses_the_tick(tmp_path):
    """A writer that rewrites `l1.md` after every read, each version still citing f1."""
    sc = _rewriting_scene(tmp_path, lambda n: (sc.corpus / "l1.md").write_text(
        S.lesson("f1", body=f"version {n}"), encoding="utf-8"))

    assert sc.run() == 2
    assert sc.head_files() == []
    assert sc.pending_by_id()["f1"].get("attempts") == 1
    assert any("kept changing" in str(r.get("reason"))
               for r in S.stuck_records(sc.paths, sc.channel))


def test_a_mode_only_change_is_put_back_and_the_tree_is_clean_after_the_tick(tmp_path):
    """A box's mode flip never lands (every tenant commit is 100644) and the draft's bytes end
    equal to the tip; only the cited lesson lands. #773 one truth, O-C."""
    old = S.lesson("older", body="the old lesson")

    def flip_the_mode(rows, batch_id, cfg):
        target = cfg.corpus_dir / "old.md"
        target.chmod(target.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    sc = S.build_draft_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        seed_corpus={"old.md": old},
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1")}, also=flip_the_mode),
    )
    assert sc.run() == 0
    assert sc.head_files() == [LESSON]
    assert sc.lane.mode_at_tip("agent/lessons/old.md") == "100644"
    assert sc.draft_drift() == []


def test_a_finding_the_curator_did_not_report_but_an_approved_file_cites_is_committed(tmp_path):
    """The curator writes lessons for a and b, reports only a. The tree says both landed:
    both are `consumed_committed`, and b is not left queued with no counter."""
    sc = S.build_draft_scene(
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
    """The curator says "skip x" and also writes a lesson citing x."""
    sc = S.build_draft_scene(
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
