"""#773: the drain commits an explicit approved list; commit contents and tree-derived truth.

Every scene is a batch's git-free draft (`S.build_draft_scene`); what the tick committed is read
off the batch branch, spelled `agent/...`."""
from __future__ import annotations

import contextlib

import pytest

from defender.tests.support.learning.curation import _curator1134 as C
from defender.tests.support.learning.curation import _spec773 as S

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
    assert rc == 0, "a refused-only tick is routed, not a stage failure (OD19)"
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


def test_git_status_reports_a_rename_pair_or_a_mode_or_name_only_change_773(tmp_path):
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
