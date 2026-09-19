"""#773 — the drain computes everything from ONE truth, the settled corpus tree.

Regression coverage for the review of PR #1064, whose findings all shared a shape: the
drain kept a second truth alive beside the tree — a pass-1 verdict that outlived the bytes
it judged, the curator's own account of what it committed, a copy of the first spawn's
cleanup that the second spawn was held to differently. Each test here is one of those
probes, replayed against the rewrite that removed the second truth.

NOT part of the locked #773 spec suite (`test_773_*.py` committed by write-tests) — these
live beside it and drive the same scene substrate.
"""
from __future__ import annotations

import os
import stat

from defender.tests import _spec773 as S
from defender.tests._drain719 import git

LESSON = "defender/lessons/l1.md"
LESSON2 = "defender/lessons/l2.md"


def _corpus_status(sc) -> list[str]:
    out = git(sc.repo, "status", "--porcelain", "--untracked-files=all", "--", "defender/lessons").stdout
    return [line for line in out.splitlines() if line.strip()]


# ---------------------------------------------------------------------------
# a verdict never outlives the bytes it judged
# ---------------------------------------------------------------------------


def test_a_repair_that_drops_one_of_two_citations_is_terminal_for_the_dropped_finding(tmp_path):
    """l1 cites f1 (BAD) and f2 (GOOD). The repair rewrites l1 citing only f1, which now
    clears. f2's lesson is gone from the tree: it is terminal with a gap record naming the
    drop, NOT `consumed_committed` on the strength of a pass-1 GOOD for bytes that no longer
    exist. l1 itself still commits — the dropped pair is f2's fate, not l1's approval."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1"), S.finding_row("f2", run_id="f2")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1", "f2")}, committed=["f1", "f2"]),
        verifier=S.FakeVerifier(verdicts={("l1.md", "f1"): ["BAD", "GOOD"]}),
        repair=S.FakeRepair(writes={"l1.md": S.lesson("f1", body="narrowed to f1")}),
    )
    assert sc.run() == 0
    assert sc.head_files() == [LESSON]
    assert sc.category_of("f1") == "consumed_committed"
    assert sc.category_of("f2") == "consumed_forward_bad"
    [record] = sc.gap_records()
    assert record["finding_id"] == "f2"
    assert "dropped" in record["verdicts"][-1]["reasoning"]


def test_a_concurrent_edit_that_strips_the_citations_mid_check_is_not_committed(tmp_path):
    """The file is judged GOOD; while the check runs, another writer strips its citations.
    The stale GOOD cannot stand for bytes that cite nothing: the file is not approved, not
    committed, and the tree is put back."""
    stripped = S.lesson(body="no citations any more")

    def strip_during_check(ctx):
        if ctx.lesson_text != stripped:
            (ctx.corpus_dir / "l1.md").write_text(stripped, encoding="utf-8")

    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1")}),
        verifier=S.FakeVerifier(on_call=strip_during_check),
    )
    assert sc.run() == 0
    assert sc.head_files() == []
    assert sc.category_of("f1") != "consumed_committed"
    assert _corpus_status(sc) == []


# ---------------------------------------------------------------------------
# both spawns are held to the same tree rule
# ---------------------------------------------------------------------------


def test_a_repair_spawn_orphan_file_is_restored_and_the_tree_is_clean_after_the_tick(tmp_path):
    """The repair spawn drops a file beside its fix that cites nothing from this batch.
    Pass 1 would refuse the tick over it; after the repair it is simply not approved —
    unlinked, never committed — and the corpus is clean when the tick ends, so the next tick's
    cleanliness gate has nothing to trip on."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1")}),
        verifier=S.FakeVerifier(verdicts={"l1.md": ["BAD", "GOOD"]}),
        repair=S.FakeRepair(
            writes={"l1.md": S.lesson("f1", body="fixed"), "orphan.md": S.lesson(body="noise")}
        ),
    )
    assert sc.run() == 0
    assert sc.head_files() == [LESSON]
    assert sc.corpus_files() == ["l1.md"]
    assert _corpus_status(sc) == []


def test_a_repair_spawn_edit_to_an_untouched_head_lesson_is_restored(tmp_path):
    """Same rule, other door: the repair spawn edits a lesson that was in HEAD before the
    tick and cites nothing from this batch. Restored to its HEAD bytes, not left dirty."""
    old = S.lesson("older", body="the old lesson")
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        seed_corpus={"old.md": old},
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1")}),
        verifier=S.FakeVerifier(verdicts={"l1.md": ["BAD", "GOOD"]}),
        repair=S.FakeRepair(
            writes={"l1.md": S.lesson("f1", body="fixed"), "old.md": S.lesson("older", body="drive-by")}
        ),
    )
    assert sc.run() == 0
    assert sc.head_files() == [LESSON]
    assert (sc.corpus / "old.md").read_text(encoding="utf-8") == old
    assert _corpus_status(sc) == []


def test_a_non_md_stray_after_the_repair_spawn_is_reverted_exactly_as_after_the_first(tmp_path):
    """A `notes.txt` under the corpus is a cleanup after the first spawn (§7 FK-5). It is
    the same cleanup after the repair spawn — not a tick-wide refusal."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1")}),
        verifier=S.FakeVerifier(verdicts={"l1.md": ["BAD", "GOOD"]}),
        repair=S.FakeRepair(writes={"l1.md": S.lesson("f1", body="fixed"), "notes.txt": "scratch"}),
    )
    assert sc.run() == 0
    assert sc.head_files() == [LESSON]
    assert sc.corpus_files() == ["l1.md"]
    assert "attempts" not in sc.pending_by_id().get("f1", {})


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


# ---------------------------------------------------------------------------
# a per-row data fault is a per-pair ending, never a stuck tick
# ---------------------------------------------------------------------------


def test_a_missing_investigation_in_the_cited_run_is_a_bad_pair_not_a_stuck_tick(tmp_path):
    """The real check over a run dir that has `source_refs.yaml` (so the gate passes) but no
    `investigation.md`. Before: `SystemExit` out of the fan-out, a stuck record, the row
    never retiring and the curator re-spawned every tick. Now: the pair is BAD with the
    error prefix, the finding is terminal, and the tick completes."""
    from defender.learning.author.verify_forward.checks import FINDINGS_CHECK

    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1")}),
        forward_check=FINDINGS_CHECK,
    )
    (sc.cfg.runs_dir / "f1" / "investigation.md").unlink()
    assert (sc.cfg.runs_dir / "f1" / "source_refs.yaml").is_file()
    assert sc.run() == 0
    assert sc.category_of("f1") == "consumed_forward_bad"
    assert S.stuck_records(sc.channel) == []
    [record] = sc.gap_records()
    assert record["verdicts"][-1]["reasoning"].startswith(S.ERROR_PREFIX)


# ---------------------------------------------------------------------------
# the operator CLI can explain the repair spawn's policy
# ---------------------------------------------------------------------------


def test_the_policy_cli_compiles_the_repair_roles_scope(tmp_path):
    from defender.runtime.agent_role import AgentRole
    from defender.scripts import policy_cli

    scope = policy_cli._scope_for(AgentRole.CORPUS_REPAIR, tmp_path, "lessons")
    assert scope.corpus_name == "lessons"
    assert scope.read_confine
