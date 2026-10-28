"""#773: the drain's vouching step — every changed lesson must cite an id of this batch."""
from __future__ import annotations

from defender.tests.support.learning.curation import _spec773 as S

LESSON = "agent/lessons/l1.md"


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
