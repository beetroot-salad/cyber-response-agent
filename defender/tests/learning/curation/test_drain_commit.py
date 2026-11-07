"""#773: the drain commits an explicit approved list; commit contents and tree-derived truth.

Every scene is a batch's git-free draft (`S.build_draft_scene`); what the tick committed is read
off the batch branch, spelled `agent/...`.

#773: the drain computes everything from one truth, the settled corpus tree.

The tree is a batch's git-free draft; "clean after the tick" is the draft re-synced to the batch
branch (`DraftScene.draft_drift`).

#773: the drain's vouching step — every changed lesson must cite an id of this batch.

#773: the three attacker-influenced inputs — AUTHOR_RESULT, the queue row, the bytes.
"""
from __future__ import annotations

import contextlib
import dataclasses
import stat

import pytest

from defender.tests.support.learning.curation import _curator1134 as C
from defender.tests.support.learning.curation import _spec773 as S
from defender.tests.support.learning.curation._curator1134 import JournalBound, JournalHeld


LESSON = "agent/lessons/l1.md"


OLD = "agent/lessons/old.md"


def test_the_draft_lane_observation_channel_sees_a_commit_and_a_reset(tmp_path):
    """Harness self-check: a hand commit through the batch shows in `landed()`, and `reset()`
    leaves the draft equal to the tip."""
    from defender.learning.author.version_control import ChangeSet

    lane = C.draft_lane(tmp_path)
    assert lane.landed() == []
    assert lane.commits() == []
    (lane.lessons_dir / "x.md").write_text("x\n", encoding="utf-8")
    (lane.lessons_dir / "stray.md").write_text("never committed\n", encoding="utf-8")
    change = [c for c in lane.batch.change_set() if c.path == "agent/lessons/x.md"]
    lane.batch.commit(ChangeSet(tuple(change)), "hand claim")
    assert lane.landed() == ["agent/lessons/x.md"]
    assert lane.text_at_tip("agent/lessons/x.md") == "x\n"
    assert lane.drift() == ["agent/lessons/stray.md"]  # the drift channel sees the stray
    lane.batch.reset()
    assert sorted(p.name for p in lane.lessons_dir.iterdir()) == [".gitkeep", "x.md"]
    assert lane.drift() == []
    assert lane.root / "agent" == lane.agent  # the repo-shaped root the helpers spell from


def test_approved_list_and_deletions_list_are_both_empty_773(tmp_path):
    """An empty approved list with no deletions commits nothing; the control tick, with a lesson
    to land, commits it."""
    sc = S.build_draft_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(committed=[],
                              consumed_skip=[{"finding_id": "f1", "reason": "already taught"}]),
    )
    before = sc.head_sha()
    assert sc.run() == 0
    assert sc.head_sha() == before
    assert sc.commit_count() == 1

    control = S.build_draft_scene(
        tmp_path / "control",
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1")}),
    )
    assert control.run() == 0
    assert control.commit_count() == 2
    assert control.head_files() == [LESSON]


def test_an_empty_approved_list_still_lets_the_rest_of_the_tick_complete_773(tmp_path):
    """An empty approved list is a branch of the tick, not an early exit: the skip still
    rotates and the report is written."""
    sc = S.build_draft_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(committed=[],
                              consumed_skip=[{"finding_id": "f1", "reason": "already taught"}]),
    )
    assert sc.run() == 0
    assert sc.category_of("f1") == "consumed_skip"
    assert sc.report_lines()


def test_the_commit_names_the_approved_files_and_the_curator_deletions_and_nothing_else_773(
    tmp_path,
):
    """The corpus commit names exactly the approved files plus the curator's deletions under
    the corpus, so a removal lands too — and nothing no finding vouches for."""
    sc = S.build_draft_scene(
        tmp_path,
        rows=[S.finding_row("ok", run_id="ok")],
        seed_corpus={"old.md": S.lesson("older")},
        curator=S.FakeCurator(
            writes={"l1.md": S.lesson("ok")},
            deletes=("old.md",),
            committed=["ok"],
        ),
    )
    assert sc.run() == 0
    assert sc.head_files() == [LESSON, OLD]
    assert sc.head_text(OLD) is None


def test_a_dirty_file_outside_the_corpus_never_enters_the_commit_773(tmp_path):
    """Pre-existing dirt in the product checkout never enters the tenant commit."""
    sc = S.build_draft_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1")}),
    )
    stray = sc.paths.repo_root / "defender" / "integrations" / "elastic_adapter.py"
    stray.parent.mkdir(parents=True, exist_ok=True)
    stray.write_text("VERBS = {'pre-existing': 'dirt'}\n", encoding="utf-8")
    assert sc.run() == 0
    assert sc.head_files() == [LESSON]
    assert "adapters" not in " ".join(sc.head_files())


def test_the_commit_list_is_built_in_repo_relative_paths_773(tmp_path):
    sc = S.build_draft_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={"nested/deep/l1.md": S.lesson("f1")}),
    )
    assert sc.run() == 0
    assert sc.head_files() == ["agent/lessons/nested/deep/l1.md"]


def test_a_reported_committed_finding_no_approved_file_cites_is_deferred_not_consumed_773(
    tmp_path,
):
    """A finding reported `committed` that no approved file cites is deferred, never
    consumed."""
    sc = S.build_draft_scene(
        tmp_path,
        rows=[S.finding_row("a", run_id="a"), S.finding_row("b", run_id="b")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("a")}, committed=["a", "b"]),
    )
    assert sc.run() == 0
    assert sc.category_of("a") == "consumed_committed"
    assert sc.category_of("b") is None
    assert sc.pending_by_id()["b"]["deferrals"] == 1


@pytest.mark.parametrize("fault", ["forbidden-name", "ref-locked", "control", "unrelated"])
def test_a_refused_commit_is_routed_as_a_refused_claim_773(tmp_path, fault):
    """A claim the batch's ChangeSet refuses (a `.gitattributes` in the lane) is routed: rc 0,
    nothing lands, the draft is reset, the row stays queued with one attempt. `ref-locked` (a
    held branch ref fails `update-ref`) is a commit fault, not a refusal: only "nothing lands or
    is consumed" is pinned. Controls: a clean tick lands; an unrelated fault propagates uncharged."""
    holder: dict = {}

    def act(rows, batch_id, cfg):
        sc = holder["sc"]
        if fault == "forbidden-name":
            (cfg.corpus_dir / ".gitattributes").write_text("* filter=tenant\n", encoding="utf-8")
        elif fault == "ref-locked":
            lock = sc.repo / ".git" / "refs" / "heads" / f"{sc.lane.batch.branch}.lock"
            lock.parent.mkdir(parents=True, exist_ok=True)
            lock.write_text("held by another writer\n")
        elif fault == "unrelated":
            raise RuntimeError("unrelated curator fault")

    sc = S.build_draft_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1")}, also=act),
    )
    holder["sc"] = sc

    if fault == "unrelated":
        with pytest.raises(RuntimeError, match="unrelated curator fault"):
            sc.run()
        assert sc.pending_by_id()["f1"].get("attempts") is None
        assert sc.commit_count() == 1
        return
    if fault == "ref-locked":
        # How a commit fault is routed is unspecified; only "nothing lands" is pinned.
        with contextlib.suppress(Exception):
            sc.run()
        assert sc.commit_count() == 1
        assert sc.head_files() == []
        assert sc.consumed() == []
        return

    rc = sc.run()
    if fault == "control":
        assert rc == 0
        assert sc.head_files() == [LESSON]
        assert sc.category_of("f1") == "consumed_committed"
        return
    assert rc == 0, "a refused-only tick failed the stage"
    assert sc.commit_count() == 1
    assert sc.head_files() == []
    assert sc.draft_drift() == []
    assert sc.pending_by_id()["f1"].get("attempts") == 1
    assert sc.consumed() == []
    assert all(r.get("finding_id") != "f1" for r in sc.graveyard())
    stuck = {r.get("fault_class") for r in S.stuck_records(sc.paths, sc.channel)}
    assert stuck <= {"AuthorError", "DeliveryRefused"}, stuck


def test_the_commit_step_reads_author_result_only_for_skip_reasons_and_commit_message_773(
    tmp_path,
):
    """The curator's result supplies only the commit message and the skip reasons; what lands
    follows the tree."""
    sc = S.build_draft_scene(
        tmp_path,
        rows=[S.finding_row("a", run_id="a"), S.finding_row("skip", run_id="skip")],
        curator=S.FakeCurator(
            writes={"l1.md": S.lesson("a")},
            committed=["a"],
            consumed_skip=[{"finding_id": "skip", "reason": "already taught"}],
            commit_message="the curator's own prose",
        ),
    )
    assert sc.run() == 0
    assert sc.head_files() == [LESSON]
    assert sc.category_of("a") == "consumed_committed"
    assert "the curator's own prose" in sc.head_message()
    assert "already taught" in str(sc.consumed_by_id()["skip"])


def test_author_result_committed_id_is_foreign_to_this_batch_773(tmp_path):
    """A foreign id in the `committed` bucket fails the result's partition check: rc 2,
    nothing lands or is consumed."""
    sc = S.build_draft_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(
            writes={"l1.md": S.lesson("f1")}, committed=["f1", "not-in-this-batch"]
        ),
    )
    assert sc.run() == 2
    assert "not-in-this-batch" not in sc.consumed_by_id()
    assert sc.head_files() == []


def test_a_rename_lands_as_the_new_path_and_the_old_path_deleted_773(tmp_path):
    """A rename lands as the new path plus the old path deleted."""
    def rename_it(rows, batch_id, cfg):
        (cfg.corpus_dir / "old.md").rename(cfg.corpus_dir / "new.md")
        (cfg.corpus_dir / "new.md").write_text(S.lesson("older", "f1"), encoding="utf-8")

    sc = S.build_draft_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        seed_corpus={"old.md": S.lesson("older")},
        curator=S.FakeCurator(writes={}, also=rename_it, committed=["f1"]),
    )
    assert sc.run() == 0
    assert sorted(sc.head_files()) == ["agent/lessons/new.md", OLD]
    assert sc.head_text(OLD) is None


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


def test_the_citations_are_read_from_the_bytes_the_commit_carries(tmp_path):
    """A lesson's citations are read from the bytes its commit carries (the claim's change set),
    never by re-reading the file, so no writer moving the file can make the two disagree. Were
    the file re-read, this writer would strip its citations on disk."""
    stripped = S.lesson(body="no citations any more")
    sc = _rewriting_scene(tmp_path, lambda n: (sc.corpus / "l1.md").write_text(
        stripped, encoding="utf-8"))

    assert sc.run() == 0
    assert sc.cfg.corpus.reads == 0, "the drain read the lesson's citations from the file again"
    assert sc.head_files() == [LESSON], "the cited lesson did not land"
    assert sc.category_of("f1") == "consumed_committed"
    assert sc.draft_drift() == []


def test_a_mode_only_change_is_put_back_and_the_tree_is_clean_after_the_tick(tmp_path):
    """A box's mode flip never lands (every tenant commit is 100644), the draft ends equal to
    the tip, and only the cited lesson lands."""
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
    """The curator files x as skipped but writes a lesson citing it: the tree wins, and x is
    consumed once, as committed."""
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


def test_a_changed_file_citing_no_batch_finding_raises_author_error_773(tmp_path):
    """A changed corpus file citing none of this batch's ids (another batch's, another
    channel's) is unvouched: `AuthorError`, the draft reset, the row charged an attempt."""
    sc = S.build_draft_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={"stray.md": S.lesson("someone-elses-id")},
                              committed=["f1"]),
    )
    assert sc.run() == 2
    assert sc.corpus_files() == []
    assert sc.pending_by_id()["f1"]["attempts"] == 1


def test_a_file_whose_citations_match_head_no_longer_passes_vouching_773(tmp_path):
    """An edit of a base lesson that still cites only an earlier batch is unvouched: ids
    already in HEAD vouch for nothing. The control also cites this batch and lands."""
    seeded = {"old.md": S.lesson("older-batch-id")}
    sc = S.build_draft_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        seed_corpus=seeded,
        curator=S.FakeCurator(
            writes={"old.md": S.lesson("older-batch-id", body="edited body")},
            committed=["f1"],
        ),
    )
    assert sc.run() == 2

    control = S.build_draft_scene(
        tmp_path / "control",
        rows=[S.finding_row("f1", run_id="f1")],
        seed_corpus=seeded,
        curator=S.FakeCurator(writes={"old.md": S.lesson("older-batch-id", "f1")}),
    )
    assert control.run() == 0
    assert "agent/lessons/old.md" in control.head_files()


def test_a_file_whose_bytes_return_to_head_after_editing_no_longer_exempts_itself_from_vouching_773(
    tmp_path,
):
    """A base lesson edited and restored byte for byte is no change; one left rewritten, still
    citing only the earlier batch, is unvouched."""
    seeded = {"old.md": S.lesson("older-batch-id", body="original")}

    def edit_then_restore(rows, batch_id, cfg):
        target = cfg.corpus_dir / "old.md"
        target.write_text(S.lesson("older-batch-id", body="scribbled"), encoding="utf-8")
        target.write_text(S.lesson("older-batch-id", body="original"), encoding="utf-8")

    unchanged = S.build_draft_scene(
        tmp_path / "restored",
        rows=[S.finding_row("f1", run_id="f1")],
        seed_corpus=seeded,
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1")}, also=edit_then_restore),
    )
    assert unchanged.run() == 0
    assert unchanged.head_files() == [LESSON]

    still_dirty = S.build_draft_scene(
        tmp_path / "dirty",
        rows=[S.finding_row("f1", run_id="f1")],
        seed_corpus=seeded,
        curator=S.FakeCurator(
            writes={"old.md": S.lesson("older-batch-id", body="rewritten")},
            committed=["f1"],
        ),
    )
    assert still_dirty.run() == 2


def test_curator_reports_no_commits_but_leaves_dirty_corpus_edits_773(tmp_path):
    """Reporting nothing committed over a well-cited edit aborts before vouching: rc 2,
    nothing lands or rotates, the draft is reset."""
    sc = S.build_draft_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1")}, committed=[]),
    )
    assert sc.run() == 2
    assert sc.head_files() == []
    assert sc.consumed() == []
    assert "f1" in sc.pending_by_id()
    assert "l1.md" not in sc.corpus_files()
    reported = " ".join(
        [r.get("deadletter_reason", "") for r in sc.graveyard()]
        + [r.get("reason", "") for r in S.stuck_records(sc.paths, sc.channel)]
    )
    assert "reported no commits but left edits" in reported


def test_curator_reports_committed_but_leaves_the_corpus_clean_773(tmp_path):
    """The same gate, the opposite mismatch: `committed` reported over an unchanged corpus."""
    sc = S.build_draft_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={}, committed=["f1"]),
    )
    assert sc.run() == 2
    assert sc.head_files() == []
    assert sc.commit_count() == 1
    assert sc.category_of("f1") is None
    reported = " ".join(
        [r.get("deadletter_reason", "") for r in sc.graveyard()]
        + [r.get("reason", "") for r in S.stuck_records(sc.paths, sc.channel)]
    )
    assert "reported committed" in reported and "unchanged" in reported  # noqa: PT018 — locked spec test (#773), suppressed not split


TRAVERSAL = "../../../../etc/passwd"


PATHY = "agent/lessons/attacker-chosen.md"


def _committing(**kw):
    """The ordinary well-formed tick every adversarial variant is measured against."""
    return S.FakeCurator(writes={"l1.md": S.lesson("f1")}, **kw)


def _assert_the_control_commits(tmp_path) -> None:
    """The control: an honest result over the same tree commits the one changed lesson."""
    control = S.build_draft_scene(
        tmp_path / "control",
        rows=[S.finding_row("f1", run_id="f1")],
        curator=_committing(),
    )
    assert control.run() == 0
    assert control.head_files() == [LESSON]
    assert control.category_of("f1") == "consumed_committed"


def test_path_like_strings_planted_in_author_result_never_reach_the_check_or_the_commit_773(
    tmp_path,
):
    sc = S.build_draft_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(
            writes={"l1.md": S.lesson("f1")},
            committed=["f1"],
            commit_message=f"folded {TRAVERSAL} into {PATHY}",
            extra_result={
                "lesson_path": PATHY,
                "source_id": TRAVERSAL,
                "run_id": TRAVERSAL,
                "paths": [TRAVERSAL, PATHY],
                "observability_gaps": [TRAVERSAL],
            },
        ),
    )
    assert sc.run() == 0
    assert sc.head_files() == [LESSON]
    assert not (tmp_path / "etc").exists()


def test_author_result_fields_filled_with_path_like_strings_773(tmp_path):
    """No model-emitted string is used as a path by the check or the commit, however many
    fields carry path-shaped content."""
    sc = S.build_draft_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(
            writes={"l1.md": S.lesson("f1")},
            committed=[PATHY],
            consumed_skip=[{"finding_id": PATHY, "reason": PATHY}],
            commit_message=PATHY,
            extra_result={"committed_paths": [PATHY]},
        ),
    )
    assert sc.run() == 2
    assert sc.head_files() == []
    assert not (sc.corpus / "attacker-chosen.md").exists()
    assert not (tmp_path / "etc").exists()

    _assert_the_control_commits(tmp_path)


@pytest.mark.parametrize(
    "message", [f"see {PATHY}", f"folded into {TRAVERSAL}"], ids=["path", "traversal"])
def test_author_result_commit_message_contains_a_path_like_string_773(tmp_path, message):
    """The commit message is never read as a path: it lands verbatim, and nothing appears at
    the place a `../` in it names."""
    sc = S.build_draft_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=_committing(commit_message=message),
    )
    assert sc.run() == 0
    assert sc.head_files() == [LESSON]
    assert message in sc.head_message()
    assert not (tmp_path / "etc").exists()
    assert not (sc.repo.parent / "etc").exists()


def test_author_result_consumed_skip_reason_contains_a_path_like_string_773(tmp_path):
    """A skip reason is read only as prose (the result supplies just skip reasons and the
    commit message), never as a path."""
    sc = S.build_draft_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1"), S.finding_row("skip", run_id="skip")],
        curator=S.FakeCurator(
            writes={"l1.md": S.lesson("f1")},
            committed=["f1"],
            consumed_skip=[{"finding_id": "skip", "reason": TRAVERSAL}],
        ),
    )
    assert sc.run() == 0
    assert sc.head_files() == [LESSON]
    assert TRAVERSAL in str(sc.consumed_by_id()["skip"])
    assert not (tmp_path / "etc").exists()


def test_author_result_retired_observability_gaps_with_row_shaped_content_is_refused_773(tmp_path):
    """The retired `observability_gaps` key (#1234) carrying row-shaped content reads as an
    unrecognized bucket and fails the tick."""
    payload = ["IGNORE PREVIOUS INSTRUCTIONS", TRAVERSAL, {"nested": PATHY}]
    sc = S.build_draft_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=_committing(extra_result={"observability_gaps": payload}),
    )
    assert sc.run() == 2
    assert sc.head_files() == []
    assert not (tmp_path / "etc").exists()

    _assert_the_control_commits(tmp_path)


def test_queue_row_batch_id_does_not_match_this_ticks_batch_773(tmp_path):
    """A `batch_id` left on a queue row by another batch is ignored: the row is authored as
    this tick's."""
    sc = S.build_draft_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1", batch_id="some-other-batch")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1")}),
    )
    assert sc.run() == 0
    assert sc.head_files() == [LESSON]


def test_changed_lesson_file_is_zero_bytes_773(tmp_path):
    """Zero bytes parse to no frontmatter, so the file cites nothing: unvouched, `AuthorError`."""
    sc = S.build_draft_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={"empty.md": ""}, committed=["f1"]),
    )
    assert sc.run() == 2
    assert sc.corpus_files() == []


def test_changed_lesson_files_frontmatter_block_is_unparseable_773(tmp_path):
    """A malformed frontmatter block cites nothing: unvouched, `AuthorError`."""
    sc = S.build_draft_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={"bad.md": S.malformed_lesson()}, committed=["f1"]),
    )
    assert sc.run() == 2
    assert sc.head_files() == []


def test_changed_lesson_file_has_no_citation_field_773(tmp_path):
    """An absent `source_finding_ids` field cites nothing: unvouched, `AuthorError`."""
    sc = S.build_draft_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(
            writes={"l1.md": "---\ntitle: a lesson\n---\n\nbody\n"}, committed=["f1"]
        ),
    )
    assert sc.run() == 2

    _assert_the_control_commits(tmp_path)


def test_changed_lesson_files_citation_list_is_empty_773(tmp_path):
    """An empty citation list is treated exactly like a missing field."""
    sc = S.build_draft_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson()}, committed=["f1"]),
    )
    assert sc.run() == 2
    assert sc.corpus_files() == []


def test_changed_lesson_files_citations_span_this_batch_and_an_earlier_one_773(tmp_path):
    """A lesson citing this batch's id and an earlier batch's lands: only the this-batch id
    counts, and the earlier one is not checked."""
    sc = S.build_draft_scene(
        tmp_path,
        rows=[S.finding_row("now", run_id="now")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("now", "from-an-earlier-batch")}),
    )
    assert sc.run() == 0
    assert sc.head_files() == [LESSON]


def test_a_tick_whose_corpus_is_already_dirty_when_it_starts_773(tmp_path):
    """A tick refuses to start on an already-dirty corpus, loudly (a named, reported
    disposition), never silently widening vouching to whatever is under the corpus."""
    sc = S.build_draft_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1")}),
        max_attempts=1,
    )
    (sc.corpus / "left-behind.md").write_text(S.lesson("some-old-batch"), encoding="utf-8")
    assert sc.run() == 2
    assert sc.curator.calls == []
    reported = " ".join(
        [r.get("deadletter_reason", "") for r in sc.graveyard()]
        + [r.get("reason", "") for r in S.stuck_records(sc.paths, sc.channel)]
    )
    assert "left-behind.md" in reported or "dirty" in reported.lower()


def test_a_non_markdown_file_left_under_the_corpus_773(tmp_path):
    """A non-`.md` file left under the corpus is dropped before vouching and reset away; the
    lesson beside it still lands."""
    sc = S.build_draft_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(
            writes={"l1.md": S.lesson("f1"), "scratch.txt": "notes to self\n"}
        ),
    )
    assert sc.run() == 0
    assert sc.head_files() == [LESSON]
    assert not (sc.corpus / "scratch.txt").exists()
