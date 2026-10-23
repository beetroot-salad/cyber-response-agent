"""#773: the drain commits an explicit approved list; commit contents and tree-derived truth.

#1108 P4 (O7): every scene is a P3 batch's git-free draft (`S.build_draft_scene`); what the
tick committed is read from the batch branch the commit-maker moved, spelled `agent/...`."""
from __future__ import annotations

import contextlib

import pytest

from defender.tests.support.learning.curation import _curator1134 as C
from defender.tests.support.learning.curation import _spec773 as S

LESSON = "agent/lessons/l1.md"
OLD = "agent/lessons/old.md"


def test_the_draft_lane_observation_channel_sees_a_commit_and_a_reset(tmp_path):
    """Machinery self-check (passes before P4): a hand commit through P3's batch shows in
    `landed()`, and `reset()` leaves the draft equal to the tip. O7 scene."""
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


def test_an_empty_approved_list_commits_nothing_and_invokes_no_git_773(tmp_path):
    """An empty approved list returns `None` WITHOUT calling git."""
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


def test_approved_list_and_deletions_list_are_both_empty_773(tmp_path):
    """The one empty case."""
    sc = S.build_draft_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(committed=[],
                              consumed_skip=[{"finding_id": "f1", "reason": "already taught"}]),
    )
    assert sc.run() == 0
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
    """M5's empty-list branch is a BRANCH in the key flow, not an early exit."""
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
    """The corpus commit names exactly the approved files plus curator deletions under the
    corpus, by explicit path list — nothing no finding vouches for."""
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
    """Pre-existing dirt in the product checkout never enters the tenant commit. #773, O7."""
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


def test_a_curator_deletion_under_the_corpus_is_named_in_the_commit_list_773(tmp_path):
    """A lesson the curator deleted under the corpus is NAMED in the commit's explicit path
    list, so the removal actually lands in HEAD."""
    sc = S.build_draft_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        seed_corpus={"old.md": S.lesson("older")},
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1")}, deletes=("old.md",)),
    )
    assert sc.run() == 0
    assert OLD in sc.head_files()
    assert sc.head_text(OLD) is None


def test_git_status_reports_a_deleted_corpus_file_773(tmp_path):
    sc = S.build_draft_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        seed_corpus={"old.md": S.lesson("older")},
        curator=S.FakeCurator(
            writes={"l1.md": S.lesson("f1")}, deletes=("old.md",), committed=["f1"]
        ),
    )
    assert sc.run() == 0
    assert sorted(sc.head_files()) == [LESSON, OLD]


def test_deletions_list_names_a_path_git_status_never_reported_deleted_773(tmp_path):
    """Every path in the commit list — approved or deleted — traces to a `git status` record
    under the corpus (O5/G1)."""
    sc = S.build_draft_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        seed_corpus={"old.md": S.lesson("older")},
        curator=S.FakeCurator(
            writes={"l1.md": S.lesson("f1")}, deletes=("old.md",), committed=["f1"]
        ),
    )
    assert sc.run() == 0
    assert set(sc.head_files()) == {LESSON, OLD}


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
    """A finding the curator reports `committed` that no approved file cites is DEFERRED
    (M7), never consumed as committed."""
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
    """U10/OD18/OD19 (human, 2026-10-23): a claim the batch's ChangeSet refuses (the box left a
    `.gitattributes` in the lane, a forbidden name) is routed: rc 0, nothing lands, the draft is
    back at the base, the row stays queued with one attempt. `ref-locked` (the branch's ref is
    held, so the commit-maker's `update-ref` fails: a fault, not a content refusal, so outside
    OD18) pins #773 M5 only: the branch does not move and no row is consumed. Controls: the same
    tick lands and consumes; an unrelated curator fault propagates, row not charged (#773 O5.3).
    #773 M5, O7."""
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
        # A system commit fault's routing is not designed: only #773 M5 is pinned.
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
    """A NEGATIVE demand."""
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


def test_a_skipped_finding_lands_in_the_consumed_skip_category_773(tmp_path):
    """A finding the curator places in the `consumed_skip` bucket rotates into
    `consumed.jsonl` tagged `consumed_skip`."""
    sc = S.build_draft_scene(
        tmp_path,
        rows=[S.finding_row("a", run_id="a"), S.finding_row("skip", run_id="skip")],
        curator=S.FakeCurator(
            writes={"l1.md": S.lesson("a")},
            committed=["a"],
            consumed_skip=[{"finding_id": "skip", "reason": "already taught"}],
        ),
    )
    assert sc.run() == 0
    assert sc.category_of("skip") == "consumed_skip"
    assert sc.category_of("a") == "consumed_committed"


def test_author_result_committed_bucket_is_empty_773(tmp_path):
    """An EMPTY `committed` bucket over a dirty corpus is not an input M5 ever sees."""
    sc = S.build_draft_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1")}, committed=[]),
    )
    assert sc.run() == 2
    assert sc.head_files() == []
    assert sc.consumed() == []
    assert sc.category_of("f1") is None
    assert "f1" in sc.pending_by_id()


def test_author_result_committed_id_is_foreign_to_this_batch_773(tmp_path):
    """Pairs come from the tree's citations ∩ this batch's ids, so a FOREIGN id in the
    committed bucket changes nothing about what is checked, committed or consumed."""
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


def test_git_status_reports_no_changed_corpus_files_773(tmp_path):
    """Nothing to vouch, check or commit."""
    sc = S.build_draft_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={}, committed=["f1"]),
    )
    sc.run()
    assert sc.commit_count() == 1
    assert sc.category_of("f1") != "consumed_committed"


def test_git_status_reports_an_untracked_file_under_the_corpus_773(tmp_path):
    sc = S.build_draft_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={"brand-new.md": S.lesson("f1")}),
    )
    assert sc.run() == 0
    assert sc.head_files() == ["agent/lessons/brand-new.md"]


def test_git_status_reports_a_rename_pair_or_a_mode_or_name_only_change_773(tmp_path):
    """A rename lands as the new path plus the old path deleted. #773, O7."""
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


def test_a_mode_only_change_with_identical_bytes_is_treated_as_unchanged_773(tmp_path):
    """A mode-only change with byte-identical content is NOT "changed" for the check's
    purposes."""
    def chmod_it(rows, batch_id, cfg):
        (cfg.corpus_dir / "old.md").chmod(0o755)

    sc = S.build_draft_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        seed_corpus={"old.md": S.lesson("older")},
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1")}, also=chmod_it),
    )
    assert sc.run() == 0


# #1108 P4 OD12(i): three cases deleted that pinned git-on-a-worktree mechanism a git-free draft
# cannot have — an unmerged status code under the corpus, and a failed / index-lock-contended
# `git status` probe (GitProbeError's no-attempt carve-out). The claim is now the draft against
# the batch base's blobs: tests/tenancy/tenant_1108_delivery/test_changes.py::
# test_change_set_is_the_draft_against_the_batch_base_and_commits_as_plain_files and
# test_change_set_fuzz.py::test_derivation_keeps_its_invariant_on_random_box_output.
