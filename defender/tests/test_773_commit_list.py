"""#773 — M5's explicit-list commit, O2's commit contents, O4/O5's tree-derived truth.

RED AGAINST HEAD BY CONSTRUCTION. The commit today is pathspec-wide over the whole dirty
corpus (CE3), which is what O2 replaces.

**The corrected demand #0 contract** (§7 section G / FK-1) is what every commit-shaped
test here is written against: `commit_fn` and `git_commit` are byte-for-byte UNCHANGED, and
a NEW, SEPARATE function — `shared.commit_corpus_paths(message, cfg, approved_paths,
deletion_paths)` — carries the drain's explicit-list commit, called directly by M5 and
never through `cfg.commit_fn`. The provisional "widen `commit_fn` to take a path list"
reading is rejected; no test here asserts it.
"""
from __future__ import annotations

import inspect
import shutil

import pytest

from defender._git import GitError
from defender.tests import _spec773 as S

LESSON = "defender/lessons/l1.md"
LESSON2 = "defender/lessons/l2.md"
OLD = "defender/lessons/old.md"


# ---------------------------------------------------------------------------
# D0 — the commit seam, as §7 corrected it
# ---------------------------------------------------------------------------


def test_the_drains_explicit_list_commit_is_a_new_function_beside_an_unchanged_commit_fn_773(
    tmp_path,
):
    """M5's explicit-list commit is a NEW, SEPARATE function; `commit_fn`'s seam stays
    `(message, cfg) -> str | None` and `_git.git_commit` keeps its single-pathspec
    signature.

    §7 FK-1: widening the shared seam would leave all four lanes sharing a signature that
    COULD take a path list even though three never pass one — a latent coupling. A
    genuinely separate function makes "untouched" a build-time fact, not a runtime habit.
    Driven as a seam demand AND as behaviour: the tick's commit names only the approved
    path, which the unchanged pathspec-wide `commit_fn` could not produce."""
    from defender import _git

    new = inspect.signature(S.author_shared.commit_corpus_paths)
    assert list(new.parameters) == ["message", "cfg", "approved_paths", "deletion_paths"]

    old = inspect.signature(S.author_shared.commit_corpus)
    assert list(old.parameters)[:3] == ["repo_root", "corpus_dir", "message"]
    assert list(inspect.signature(_git.git_commit).parameters)[:3] == [
        "cwd", "pathspec", "message",
    ]
    assert list(inspect.signature(S.lessons_run.commit_lessons).parameters) == [
        "message", "cfg",
    ]

    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("ok", run_id="ok"), S.finding_row("bad", run_id="bad")],
        curator=S.FakeCurator(
            writes={"l1.md": S.lesson("ok"), "l2.md": S.lesson("bad")},
            committed=["ok", "bad"],
        ),
        verifier=S.FakeVerifier(verdicts={"l2.md": "BAD"}),
    )
    assert sc.run() == 0
    assert sc.head_files() == [LESSON]


def test_the_pitfalls_and_lead_author_commits_are_unchanged_773(tmp_path):
    """The three sibling lanes N4 declares untouched — questioner, lead-author, pitfalls —
    never reference the new function's name at all; each still reaches `shared.commit_corpus`
    with its own trailers.

    §7 FK-1 makes this SAFE BY CONSTRUCTION rather than merely observed: a source census
    over the three call sites is the honest form of "untouched", because a behaviour test on
    an unchanged lane passes whether or not the seam moved under it."""
    from defender.learning.author.questioner import run as questioner_run
    from defender.learning.leads import pitfalls_curator
    from defender.learning.leads import lead_author

    for module in (questioner_run, pitfalls_curator, lead_author):
        source = inspect.getsource(module)
        assert "commit_corpus_paths" not in source, module.__name__
        assert "commit_corpus" in source, module.__name__

    assert list(
        inspect.signature(questioner_run.commit_questioner_lessons).parameters
    ) == ["message", "cfg"]


def test_an_empty_approved_list_commits_nothing_and_invokes_no_git_773(tmp_path):
    """An empty approved list returns `None` WITHOUT calling git: no new commit object
    exists and HEAD has not moved.

    C15 is why this is a demand and not a nicety: `git add --` with an empty pathspec stages
    nothing but `git commit -F - --` then commits the WHOLE INDEX, so an unguarded empty
    list sweeps in any unrelated staged file. The probe observed a stray `stray.txt`
    reaching HEAD that way."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1")}),
        verifier=S.FakeVerifier(default="BAD"),
    )
    before = sc.head_sha()
    assert sc.run() == 0
    assert sc.head_sha() == before
    assert sc.commit_count() == 1


def test_approved_list_and_deletions_list_are_both_empty_773(tmp_path):
    """The one empty case: BOTH lists empty returns `None` without calling git. A tick whose
    only changed file was refused, and which deleted nothing, makes no commit at all.

    Positive control on the same address: one approved path and no deletions DOES commit, so
    the empty branch is the guard firing and not the commit path being broken."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1")}),
        verifier=S.FakeVerifier(default="BAD"),
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
    """M5's empty-list branch is a BRANCH in the key flow, not an early exit: the tick
    continues through recompute, ledger, deferral bump and rotation.

    Observable: with nothing committed, the terminal finding still gets its gap record and
    still rotates as `consumed_forward_bad`, and the report line is still written."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1")}),
        verifier=S.FakeVerifier(default="BAD"),
    )
    assert sc.run() == 0
    assert len(sc.gap_records()) == 1
    assert sc.category_of("f1") == "consumed_forward_bad"
    assert sc.report_lines()


# ---------------------------------------------------------------------------
# O2 — the commit names exactly the approved files plus curator deletions
# ---------------------------------------------------------------------------


def test_the_commit_names_the_approved_files_and_the_curator_deletions_and_nothing_else_773(
    tmp_path,
):
    """The corpus commit names exactly the approved files plus curator deletions under the
    corpus, by explicit path list — nothing the check refused, and nothing no finding
    vouches for.

    Asked of `git show --name-only HEAD`, the operator's own instrument, not of the drain's
    record of what it meant to commit."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("ok", run_id="ok"), S.finding_row("bad", run_id="bad")],
        seed_corpus={"old.md": S.lesson("older")},
        curator=S.FakeCurator(
            writes={"l1.md": S.lesson("ok"), "l2.md": S.lesson("bad")},
            deletes=("old.md",),
            committed=["ok", "bad"],
        ),
        verifier=S.FakeVerifier(verdicts={"l2.md": "BAD"}),
    )
    assert sc.run() == 0
    assert sc.head_files() == [LESSON, OLD]
    assert sc.head_text(LESSON2) is None
    assert sc.head_text(OLD) is None


def test_a_dirty_file_outside_the_corpus_never_enters_the_commit_773(tmp_path):
    """A NEGATIVE demand: nothing outside the corpus reaches the commit, on any surface —
    not the path list, not the pathspec, not by riding an index the empty-list branch would
    otherwise sweep in.

    A dirty file outside the corpus is a stray `verify_agent_state` already refuses, so the
    reachable shape is a file dirty at BASELINE — pre-existing dirt the drain did not cause
    and must not commit. Positive control on the same address: the corpus file beside it
    does commit, so the absence is not an empty commit."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1")}),
    )
    stray = sc.repo / "defender" / "scripts" / "adapters" / "elastic_adapter.py"
    stray.write_text("VERBS = {'pre-existing': 'dirt'}\n", encoding="utf-8")
    assert sc.run() == 0
    assert sc.head_files() == [LESSON]
    assert "adapters" not in " ".join(sc.head_files())


def test_a_curator_deletion_under_the_corpus_is_named_in_the_commit_list_773(tmp_path):
    """A lesson the curator deleted under the corpus is NAMED in the commit's explicit path
    list, so the removal actually lands in HEAD.

    `_changed_corpus_records` drops every `D` row (C17), so the deletion list has a source
    other than that census — the outcome is pinned here; the collector is the
    implementation's to supply (RF-2)."""
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
    """M5 puts curator deletions under the corpus into the commit's explicit path list even
    though `_changed_corpus_records` drops `D` rows (C17), and the deletion is not vouched
    for by anything — there is no file left to attribute (N6).

    Positive control: the deletion-only tick still produces a commit."""
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
    under the corpus (O5/G1). A path that does not is a violation, not a case to handle.

    Driven as a census over the tick: the commit's path set is a subset of the paths git
    itself reported dirty under the corpus, computed from the scene's own record of what the
    curator touched rather than by re-running production's own `git status` call."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        seed_corpus={"old.md": S.lesson("older")},
        curator=S.FakeCurator(
            writes={"l1.md": S.lesson("f1")}, deletes=("old.md",), committed=["f1"]
        ),
    )
    assert sc.run() == 0
    # The expected set is the FAKE's own write/delete list, spelled out here rather than
    # recovered by re-running production's own `git status` — an oracle that re-runs the
    # primitive under test cannot disagree with it.
    assert set(sc.head_files()) == {LESSON, OLD}


def test_the_commit_list_is_built_in_repo_relative_paths_773(tmp_path):
    """The explicit commit list is built in REPO-relative paths — the representation
    `_changed_corpus_records`, `_vouched_for`, `_cited_ids_at_head` and `_revert_strays`
    already use consistently — so a lesson in a corpus SUBDIRECTORY commits at the path git
    knows it by.

    §7's path-space convention (RF-3's other half): `_snapshot_corpus`/`_restore_corpus`
    keep their own internally-consistent corpus-relative pair, unchanged. A nested lesson is
    the shape where the two spellings differ by more than a prefix."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={"nested/deep/l1.md": S.lesson("f1")}),
    )
    assert sc.run() == 0
    assert sc.head_files() == ["defender/lessons/nested/deep/l1.md"]


# ---------------------------------------------------------------------------
# O4 / O5 — the tree is the truth; AUTHOR_RESULT is a hint
# ---------------------------------------------------------------------------


def test_the_committed_set_is_recomputed_after_the_commit_not_before_it_773(tmp_path):
    """The recompute runs AFTER the commit and keys on approved files that actually landed:
    a finding is `consumed_committed` iff an approved committed file cites it.

    Driven with a finding the curator reports committed whose file was refused — it is not
    consumed as committed, whatever the report said."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("ok", run_id="ok"), S.finding_row("bad", run_id="bad")],
        curator=S.FakeCurator(
            writes={"l1.md": S.lesson("ok"), "l2.md": S.lesson("bad")},
            committed=["ok", "bad"],
        ),
        verifier=S.FakeVerifier(verdicts={"l2.md": "BAD"}),
    )
    assert sc.run() == 0
    assert sc.category_of("ok") == "consumed_committed"
    assert sc.category_of("bad") != "consumed_committed"


def test_a_reported_committed_finding_no_approved_file_cites_is_deferred_not_consumed_773(
    tmp_path,
):
    """A finding the curator reports `committed` that no approved file cites is DEFERRED
    (M7), never consumed as committed.

    O4 stated as its own outcome: "consumed only when an approved file cites it". The
    failing-by column names this exact tick — B reported committed, no file cites B."""
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
    recompute yields an EMPTY `committed` set and no row rotates as `consumed_committed`.

    Consumption is keyed on the commit's own success, never on the curator's report. The
    fault is induced at the real primitive: the repo's git directory is taken away before
    the commit, so git genuinely cannot write an object."""
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
    """A NEGATIVE demand: the commit step reads AUTHOR_RESULT for exactly two things — the
    `consumed_skip` reasons and the `commit_message` — and for nothing else.

    Driven by making every OTHER field of the result useless: `committed` omits "a" (only
    "skip" rides the bucket, harmlessly, since it is filed under `consumed_skip` instead) and
    a `held_forward_bad` bucket is absent, yet the well-cited file "a" is still checked and
    committed off the tree rather than off the bucket's own say-so. `committed` still has to
    stay HONEST about the tree overall (non-empty, corpus genuinely dirty) — the pre-existing
    bidirectional self-report/tree cross-check (§7 FK-3) is a separate, earlier gate this test
    is not about; `test_curator_reports_no_commits_but_leaves_dirty_corpus_edits_773` covers
    it. Positive control on the same address: the two fields that ARE read do reach their
    sinks — the skip reason onto the rotated row and the message into `git log`."""
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
    `consumed.jsonl` tagged `consumed_skip`.

    R4 obligation g2: the third distinguished member of the consumed-category domain,
    pinned beside O3's `consumed_forward_bad` and O4's `consumed_committed` so all three are
    individually exercised rather than two being inferred from the one."""
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
    """An EMPTY `committed` bucket over a dirty corpus is not an input M5 ever sees: the tick
    ends at `verify_agent_state` (`shared.py:279-283`, called at `drain.py:427`), before
    `_project`, before the recompute, before any commit.

    O5 SCOPED CORRECTLY. "The tree is the truth, the report is a hint" governs what the drain
    SELECTS once a tick is running — which files are vouched, which pairs are checked, which
    ids come back `consumed_committed`. It is not a licence for the report to CONTRADICT the
    tree: the pre-existing bidirectional honesty gate still refuses that tick outright, and
    §7's FK-3 resolution keeps it firing first and unchanged (claim P1, executed — both
    mismatch directions raise). The bucket being ignorable and the bucket being allowed to lie
    are different claims, and only the first is this delta's.

    What the empty bucket genuinely no longer does is gate M3.2's vouching — that is the
    `if committed:` conditional at `drain.py:436-437` (G13) this delta removes, and it is a
    LATER gate than the one that fires here. `test_curator_reports_no_commits_but_leaves_dirty_corpus_edits_773`
    carries that separation; this test's own job is that nothing downstream of the gate ran:
    no commit recompute, no consumption, no rotation.

    (Rewritten at the phase-F repair, 92-reconciliation.md F-1 — it previously asserted
    `run() == 0` and `consumed_committed`, against §7's own resolution.)"""
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
    committed bucket changes nothing about what is checked, committed or consumed.

    The partition validator's own refusal of an unknown id is the surrounding machinery;
    what this pins is that the check and commit read the tree either way."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(
            writes={"l1.md": S.lesson("f1")}, committed=["f1", "not-in-this-batch"]
        ),
    )
    assert sc.run() == 2
    assert sc.verifier.call_count == 0
    assert "not-in-this-batch" not in sc.consumed_by_id()
    assert sc.head_files() == []


def test_git_status_reports_no_changed_corpus_files_773(tmp_path):
    """Nothing to vouch, check or commit: the recomputed `committed` set is empty whatever
    AUTHOR_RESULT claims (O5), no verifier call is made and no commit lands.

    The tree is the truth — a curator that reports a commit and writes nothing gets an
    empty tick, not a rotation."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={}, committed=["f1"]),
    )
    sc.run()
    assert sc.verifier.call_count == 0
    assert sc.commit_count() == 1
    assert sc.category_of("f1") != "consumed_committed"


def test_git_status_call_itself_produces_no_output_773(tmp_path):
    """The empty `git status` result is AUTHORITATIVE: the tree is the truth (O5), so
    nothing is vouched, checked or committed and the tick completes.

    The curator here writes nothing at all, which is the real primitive producing a genuinely
    empty census rather than a fake asserting one."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={}, committed=[], consumed_skip=[]),
    )
    sc.run()
    assert sc.verifier.call_count == 0
    assert sc.head_files() == []


def test_git_status_reports_an_untracked_file_under_the_corpus_773(tmp_path):
    """`git status --porcelain --untracked-files=all -z` includes `??`, and only `D` is
    filtered (G1/C17), so an untracked corpus file is a changed non-deleted record and goes
    through vouch, verdict and commit like any other.

    The file here is genuinely new to git — written by the fake into a clean tree — so the
    `??` status is produced by the real primitive."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={"brand-new.md": S.lesson("f1")}),
    )
    assert sc.run() == 0
    assert sc.verifier.pairs_seen == [("brand-new.md", "f1")]
    assert sc.head_files() == ["defender/lessons/brand-new.md"]


def test_git_status_reports_a_rename_pair_or_a_mode_or_name_only_change_773(tmp_path):
    """A rename decomposes into new-path-changed plus old-path-deleted before anything
    downstream sees it: the new path is vouched, checked and committed, the old path rides
    the deletion list, and no record ever reaches the vouch step naming two paths.

    §7 FK-32. A renamed lesson is the natural shape of "the repair spawn moved the file", so
    this is not exotic: mishandled, either the old path rides into a delete nobody approved
    or the new path is checked under the old path's citations. The rename is made with real
    `git mv`, so git's own `R100 old -> new` record is what the census meets."""
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
    assert sc.verifier.pairs_seen == [("new.md", "f1")]
    assert sorted(sc.head_files()) == ["defender/lessons/new.md", OLD]
    assert sc.head_text(OLD) is None


def test_a_mode_only_change_with_identical_bytes_is_treated_as_unchanged_773(tmp_path):
    """A mode-only change with byte-identical content is NOT "changed" for the check's
    purposes: it mints no pair, costs no verifier call, and does not fault the tick for want
    of a voucher.

    §7 FK-32's second half — "changed" has to keep meaning "content the check must judge",
    which is the only meaning M3 uses. The chmod is real, so git's own mode record is what
    the census meets. Positive control: the genuinely edited file beside it IS checked."""
    def chmod_it(rows, batch_id, cfg):
        (cfg.corpus_dir / "old.md").chmod(0o755)

    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        seed_corpus={"old.md": S.lesson("older")},
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1")}, also=chmod_it),
    )
    assert sc.run() == 0
    assert sc.verifier.pairs_seen == [("l1.md", "f1")]


def test_git_status_reports_an_unexpected_two_letter_status_code_773(tmp_path):
    """An UNMERGED status code under the corpus refuses the tick loudly, before vouching:
    nothing is checked, nothing is committed, and the failure is visible.

    §7 FK-33. `UU`/`AA` pass the `"D" not in xy` filter untouched and would otherwise be
    handed to the verdict step as ordinary changed files — committing a lesson full of
    conflict markers into the corpus the defender reads at PLAN, an O1-shaped harm the
    verifier might well pass, since conflict markers are just text. The conflict is produced
    by a real `git merge`, so the status code is git's own."""
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
    assert sc.verifier.call_count == 0
    assert LESSON not in sc.head_files()
    # NAMED, not merely loud. Today this tick already fails — the conflicted file's markers
    # break its frontmatter, so it reads as unvouched — and a test asserting only "the tick
    # refused" would be green on that unrelated reason forever. The refusal has to say what
    # it refused, which is what makes it greppable for an operator.
    [record] = sc.graveyard()
    assert "unmerged" in record["deadletter_reason"].lower()


# ---------------------------------------------------------------------------
# §7 FK-22 — the new step's git reads do not spend the batch's fault budget
# ---------------------------------------------------------------------------


def test_git_status_call_the_check_steps_paths_are_derived_from_fails_773(tmp_path):
    """A failed `git status` inside the new check step aborts the tick but does NOT bump
    `attempts`: the row keeps its budget and the tick is recorded as stuck.

    §7 FK-22, the same carve-out N5 already makes for a BAD ("a BAD is not a fault"):
    `attempts` is a budget for "this batch keeps breaking things", and an index-lock race is
    a property of the host, not of the batch. Three collisions over a queue's life would
    otherwise delete work that was fine. The failure is real — the repo's git directory is
    moved away mid-tick, so git genuinely fails."""
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
    assert S.stuck_records(sc.channel)


def test_a_git_read_inside_the_new_check_step_that_loses_the_index_lock_race_773(tmp_path):
    """The same carve-out reached through the contended-index door: the batch keeps its
    attempt count and the row stays queued for an ordinary retry.

    `GitProbeError` is deliberately not a `RETIRE_SET` member (GL2 lists the three that
    are), which is the mechanism this rides — the new step's reads must go through the same
    `_git_read` wrapper the existing ones do."""
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


def test_verify_agent_state_after_repair_spawn_depends_on_a_failing_git_read_773(tmp_path):
    """The post-repair `verify_agent_state` read takes the same carve-out: its git failure
    aborts the tick without bumping `attempts`.

    §7 FK-22 applies to every git READ the new machinery adds, not only the first one — the
    census, the post-repair state check and the recompute are all host-property failures."""
    def hide_the_git_dir(pairs, batch_id, cfg):
        shutil.move(str(cfg.repo_root / ".git"), str(cfg.repo_root / ".git-gone"))

    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1")}),
        verifier=S.FakeVerifier(default="BAD"),
        repair=S.FakeRepair(also=hide_the_git_dir),
    )
    with pytest.raises((GitError, S.drain.GitProbeError)):
        sc.run()
    shutil.move(str(sc.repo / ".git-gone"), str(sc.repo / ".git"))
    assert "attempts" not in sc.pending_by_id()["f1"]
