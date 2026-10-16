"""#773 — the drain's vouching step (M3.2), what survived the forward check's deletion (#1166).
"""
from __future__ import annotations

from defender.tests import _spec773 as S

LESSON = "defender/lessons/l1.md"

# ---------------------------------------------------------------------------
# M3.2 — vouching, on every channel, over every changed corpus file
# ---------------------------------------------------------------------------


def test_a_changed_file_citing_no_batch_finding_raises_author_error_773(tmp_path):
    """A changed corpus file whose citations do not intersect this batch's ids is unvouched,
    and M3.2's disposition for that is `AuthorError`: the tick unwinds, the corpus is
    restored, `attempts` bumps and the batch stays queued.

    The `AuthorError` is a `RETIRE_SET` member (GL2), which is what makes rc 2 the tick's
    answer rather than a stuck record."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={"stray.md": S.lesson("someone-elses-id")},
                              committed=["f1"]),
    )
    assert sc.run() == 2
    assert sc.corpus_files() == []
    assert sc.pending_by_id()["f1"]["attempts"] == 1


def test_a_file_whose_citations_match_head_no_longer_passes_vouching_773(tmp_path):
    """The HEAD-provenance exemption is gone (M3.2/C13): a changed file that cites exactly
    what HEAD's copy cites, and nothing from this batch, is unvouched and raises.

    A NEGATIVE demand — the second arm of `_vouched_for` must no longer answer yes. Its
    positive control is on the same address: a file citing a this-batch id still vouches."""
    seeded = {"old.md": S.lesson("older-batch-id")}
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        seed_corpus=seeded,
        curator=S.FakeCurator(
            writes={"old.md": S.lesson("older-batch-id", body="edited body")},
            committed=["f1"],
        ),
    )
    assert sc.run() == 2

    control = S.build_scene(
        tmp_path / "control",
        rows=[S.finding_row("f1", run_id="f1")],
        seed_corpus=seeded,
        curator=S.FakeCurator(writes={"old.md": S.lesson("older-batch-id", "f1")}),
    )
    assert control.run() == 0
    assert "defender/lessons/old.md" in control.head_files()


def test_a_file_whose_bytes_return_to_head_after_editing_no_longer_exempts_itself_from_vouching_773(
    tmp_path,
):
    """Two arms of the same removal. A tracked file whose bytes are edited and then restored
    EXACTLY does not appear in `_changed_corpus_records` at all — git reports nothing, so
    there is no record to vouch for and no pair to check. A file whose bytes differ while its
    citations still match HEAD's is a changed record with no this-batch citation, and the
    HEAD-provenance exemption that used to pass it is gone (M3.2/C13).

    The distinction matters because the removed exemption's only lessons-channel use was the
    BAD-fold revert, which D2 replaces outright."""
    seeded = {"old.md": S.lesson("older-batch-id", body="original")}

    def edit_then_restore(rows, batch_id, cfg):
        target = cfg.corpus_dir / "old.md"
        target.write_text(S.lesson("older-batch-id", body="scribbled"), encoding="utf-8")
        target.write_text(S.lesson("older-batch-id", body="original"), encoding="utf-8")

    unchanged = S.build_scene(
        tmp_path / "restored",
        rows=[S.finding_row("f1", run_id="f1")],
        seed_corpus=seeded,
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1")}, also=edit_then_restore),
    )
    assert unchanged.run() == 0
    assert unchanged.head_files() == [LESSON]

    still_dirty = S.build_scene(
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
    """A curator that reports NOTHING committed and leaves a well-cited edit never reaches
    M3 at all: `verify_agent_state` raises `AuthorError` first, so no pair is ever checked.

    TWO DIFFERENT GATES, and this test names the earlier one. `verify_agent_state`
    (`shared.py:256-283`, called at `drain.py:427`) is a pre-existing, BIDIRECTIONAL
    self-report-honesty check that runs before `_project`: `committed and not corpus_dirty`
    raises, and `not committed and corpus_dirty` raises (§7 FK-3, claim P1, executed). M3.2's
    vouching — the `if committed:`-gated `_assert_corpus_attributable` call at
    `drain.py:436-437` (G13) that this delta makes unconditional — is a LATER, separate
    mechanism. §7's FK-3 resolution keeps `verify_agent_state` firing first, UNCHANGED, and
    proposes no relaxation of it; "the tree is the truth" (O5) governs what gets checked and
    committed once the tick is past this gate, and was never offered as a replacement for it.

    So the delta's real behaviour change is that vouching stops being conditional on the
    bucket — NOT that a lying self-report becomes survivable. This shape is unreachable past
    `drain.py:427`, and the check step never runs. The discriminator is the gate's own
    message: a vouching failure would name an unvouched file instead.

    (Rewritten at the phase-F repair, 92-reconciliation.md F-1: this test previously asserted
    `run() == 0` and a commit, which contradicted the §7 resolution and was red for a reason
    an honest implementer could not fix.)"""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1")}, committed=[]),
    )
    assert sc.run() == 2
    assert sc.head_files() == []
    assert "l1.md" not in sc.corpus_files()
    reported = " ".join(
        [r.get("deadletter_reason", "") for r in sc.graveyard()]
        + [r.get("reason", "") for r in S.stuck_records(sc.paths, sc.channel)]
    )
    assert "reported no commits but left edits" in reported


def test_curator_reports_committed_but_leaves_the_corpus_clean_773(tmp_path):
    """The SAME gate, the OPPOSITE mismatch: a curator that reports `committed=["f1"]` and
    leaves the corpus untouched raises `AuthorError` at `verify_agent_state` before M3 runs.

    The reverse direction of the test above, and the one the chain had never exercised —
    §7 minted probe P1 to settle whether the gate fires on it at all, ran the probe, and
    recorded that it does (`shared.py:274-278`), but no test ever pinned it. It is
    pre-existing machinery, so this is regression protection rather than a new behaviour:
    O5's whole "the tree is the truth" story depends on the drain refusing a tick whose
    self-report and tree disagree, in EITHER direction, before it starts believing the tree.

    "Clean" here is untracked-files-included: `corpus_dir_clean` (`shared.py:152-153`) runs
    `git status` with `--untracked-files=all` (`_git.py:70`), so this fake writing nothing is
    genuinely producing an empty census through the real primitive rather than a fake
    asserting one. The message is again the discriminator — the complementary half of the
    aggregate check, not the unvouched-file path."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={}, committed=["f1"]),
    )
    assert sc.run() == 2
    assert sc.head_files() == []
    assert sc.category_of("f1") is None
    reported = " ".join(
        [r.get("deadletter_reason", "") for r in sc.graveyard()]
        + [r.get("reason", "") for r in S.stuck_records(sc.paths, sc.channel)]
    )
    assert "reported committed" in reported and "unchanged" in reported  # noqa: PT018 — locked spec test (#773), suppressed not split


def test_a_first_spawn_deletion_of_a_pre_existing_lesson_still_passes_vouching_773(tmp_path):
    """N6: deletion of a pre-existing lesson by the FIRST curator spawn stays outside the
    vouching gate, exactly as today — `_changed_corpus_records` drops `D` rows (C17), so a
    deleted file is never a changed record needing a voucher.

    The deletion still rides the commit list (M5), so the tick's outcome is the removal
    landing in HEAD, not a fault."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        seed_corpus={"old.md": S.lesson("older-batch-id")},
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1")}, deletes=("old.md",)),
    )
    assert sc.run() == 0
    assert sc.head_text("defender/lessons/old.md") is None
