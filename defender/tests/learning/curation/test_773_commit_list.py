"""#773: the drain commits an explicit approved list; commit contents and tree-derived truth."""
from __future__ import annotations

import shutil

import pytest

from defender._git import GitError
from defender.tests.support.learning.curation import _spec773 as S

LESSON = "defender/lessons/l1.md"
OLD = "defender/lessons/old.md"


def test_an_empty_approved_list_commits_nothing_and_invokes_no_git_773(tmp_path):
    """An empty approved list returns `None` WITHOUT calling git."""
    sc = S.build_scene(
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
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(committed=[],
                              consumed_skip=[{"finding_id": "f1", "reason": "already taught"}]),
    )
    assert sc.run() == 0
    assert sc.commit_count() == 1

    control = S.build_scene(
        tmp_path / "control",
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1")}),
    )
    assert control.run() == 0
    assert control.commit_count() == 2
    assert control.head_files() == [LESSON]


def test_an_empty_approved_list_still_lets_the_rest_of_the_tick_complete_773(tmp_path):
    """M5's empty-list branch is a BRANCH in the key flow, not an early exit."""
    sc = S.build_scene(
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
    sc = S.build_scene(
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
    """A NEGATIVE demand."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1")}),
    )
    stray = sc.repo / "defender" / "integrations" / "elastic_adapter.py"
    stray.write_text("VERBS = {'pre-existing': 'dirt'}\n", encoding="utf-8")
    assert sc.run() == 0
    assert sc.head_files() == [LESSON]
    assert "adapters" not in " ".join(sc.head_files())


def test_a_curator_deletion_under_the_corpus_is_named_in_the_commit_list_773(tmp_path):
    """A lesson the curator deleted under the corpus is NAMED in the commit's explicit path
    list, so the removal actually lands in HEAD."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        seed_corpus={"old.md": S.lesson("older")},
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1")}, deletes=("old.md",)),
    )
    assert sc.run() == 0
    assert OLD in sc.head_files()
    assert sc.head_text(OLD) is None


def test_git_status_reports_a_deleted_corpus_file_773(tmp_path):
    sc = S.build_scene(
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
    sc = S.build_scene(
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
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={"nested/deep/l1.md": S.lesson("f1")}),
    )
    assert sc.run() == 0
    assert sc.head_files() == ["defender/lessons/nested/deep/l1.md"]


def test_a_reported_committed_finding_no_approved_file_cites_is_deferred_not_consumed_773(
    tmp_path,
):
    """A finding the curator reports `committed` that no approved file cites is DEFERRED
    (M7), never consumed as committed."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("a", run_id="a"), S.finding_row("b", run_id="b")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("a")}, committed=["a", "b"]),
    )
    assert sc.run() == 0
    assert sc.category_of("a") == "consumed_committed"
    assert sc.category_of("b") is None
    assert sc.pending_by_id()["b"]["deferrals"] == 1


def test_disk_runs_out_of_space_partway_through_gits_own_commit_write_773(tmp_path):
    """If the commit object does not land, HEAD does not advance, so M5's tree-derived
    recompute yields an EMPTY `committed` set and no row rotates as `consumed_committed`."""
    def hide_the_git_dir(rows, batch_id, cfg):
        shutil.move(str(cfg.repo_root / ".git"), str(cfg.repo_root / ".git-gone"))

    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1")}, also=hide_the_git_dir),
    )
    with pytest.raises((GitError, S.drain.GitProbeError)):
        sc.run()
    shutil.move(str(sc.repo / ".git-gone"), str(sc.repo / ".git"))
    assert sc.consumed() == []
    assert sc.commit_count() == 1


def test_the_commit_step_reads_author_result_only_for_skip_reasons_and_commit_message_773(
    tmp_path,
):
    """A NEGATIVE demand."""
    sc = S.build_scene(
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
    sc = S.build_scene(
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
    sc = S.build_scene(
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
    sc = S.build_scene(
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
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={}, committed=["f1"]),
    )
    sc.run()
    assert sc.commit_count() == 1
    assert sc.category_of("f1") != "consumed_committed"


def test_git_status_reports_an_untracked_file_under_the_corpus_773(tmp_path):
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={"brand-new.md": S.lesson("f1")}),
    )
    assert sc.run() == 0
    assert sc.head_files() == ["defender/lessons/brand-new.md"]


def test_git_status_reports_a_rename_pair_or_a_mode_or_name_only_change_773(tmp_path):
    """A rename decomposes into new-path-changed plus old-path-deleted before anything
    downstream sees it."""
    def rename_it(rows, batch_id, cfg):
        S.git(cfg.repo_root, "mv", "defender/lessons/old.md", "defender/lessons/new.md")
        (cfg.corpus_dir / "new.md").write_text(S.lesson("older", "f1"), encoding="utf-8")

    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        seed_corpus={"old.md": S.lesson("older")},
        curator=S.FakeCurator(writes={}, also=rename_it, committed=["f1"]),
    )
    assert sc.run() == 0
    assert sorted(sc.head_files()) == ["defender/lessons/new.md", OLD]
    assert sc.head_text(OLD) is None


def test_a_mode_only_change_with_identical_bytes_is_treated_as_unchanged_773(tmp_path):
    """A mode-only change with byte-identical content is NOT "changed" for the check's
    purposes."""
    def chmod_it(rows, batch_id, cfg):
        (cfg.corpus_dir / "old.md").chmod(0o755)

    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        seed_corpus={"old.md": S.lesson("older")},
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1")}, also=chmod_it),
    )
    assert sc.run() == 0


def test_git_status_reports_an_unexpected_two_letter_status_code_773(tmp_path):
    """An UNMERGED status code under the corpus refuses the tick loudly, before vouching."""
    def make_a_real_conflict(rows, batch_id, cfg):
        repo = cfg.repo_root
        S.git(repo, "checkout", "-q", "-b", "side", "HEAD~1")
        (cfg.corpus_dir / "old.md").write_text(S.lesson("older", body="theirs"), "utf-8")
        S.git(repo, "add", "-A")
        S.git(repo, "commit", "-q", "-m", "side")
        S.git(repo, "checkout", "-q", "main")
        S.git(repo, "merge", "side", check=False)

    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        seed_corpus={"old.md": S.lesson("older", body="ours")},
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1")}, also=make_a_real_conflict),
        max_attempts=1,
    )
    assert sc.run() == 2
    assert LESSON not in sc.head_files()
    [record] = sc.graveyard()
    assert "unmerged" in record["deadletter_reason"].lower()


def test_git_status_call_the_check_steps_paths_are_derived_from_fails_773(tmp_path):
    """A failed `git status` inside the new check step aborts the tick but does NOT bump
    `attempts`."""
    def hide_the_git_dir(rows, batch_id, cfg):
        shutil.move(str(cfg.repo_root / ".git"), str(cfg.repo_root / ".git-gone"))

    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1")}, also=hide_the_git_dir),
    )
    with pytest.raises((GitError, S.drain.GitProbeError)):
        sc.run()
    shutil.move(str(sc.repo / ".git-gone"), str(sc.repo / ".git"))
    assert "attempts" not in sc.pending_by_id()["f1"]
    assert S.stuck_records(sc.paths, sc.channel)


def test_a_git_read_inside_the_new_check_step_that_loses_the_index_lock_race_773(tmp_path):
    """The same carve-out reached through the contended-index door."""
    def hide_the_git_dir(rows, batch_id, cfg):
        shutil.move(str(cfg.repo_root / ".git"), str(cfg.repo_root / ".git-gone"))

    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1")}, also=hide_the_git_dir),
    )
    with pytest.raises(S.drain.GitProbeError):
        sc.run()
    shutil.move(str(sc.repo / ".git-gone"), str(sc.repo / ".git"))
    assert sc.pending_by_id()["f1"].get("attempts") in (None, 0)
