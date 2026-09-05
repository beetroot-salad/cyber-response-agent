"""#921 — the bucket each world falls into, the family's verdict word, and what may move them.

The bucket falls out of the five facts rather than out of an empty set. The REFUTED table's
central case (`ΔO_X != empty` on H's keys) was unreachable by construction — offline every
difference classifies as `undeclared` — which is why `decision-discipline` had no member and why
the amendment rewrote the table against the ledger's `source` column instead.

WHAT IS STRUCK AND APPEARS IN NO ASSERTION HERE: the original bucket table, N8, `delta_o`, the
mutation/undeclared membership test, the offline comparator lane, and every "post-branch key"
predicate. `delta_o` survives in the tree as a manipulation check on the EPISODE; #921 does not
consume it, and `test_921_family_pass_never_reads_served_base_and_never_calls_the_comparator`
is what keeps it out.

RED against `d1b8b06a`: `learning/judge/family.py` does not exist.
"""
from __future__ import annotations

import pytest

from defender.tests import _judge_921 as J


@pytest.fixture(autouse=True)
def _tmp_roots(tmp_path, monkeypatch):
    monkeypatch.setenv(J.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(J.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    # The learning STATE root too, so the shared findings queue this pass appends to is
    # this test's own and not the checkout's real `learning/_pending/`. Isolation belongs
    # here rather than in the appender: a production path that picks a different queue when
    # an env var is unset is a pass whose rows can land where no drain reads.
    monkeypatch.setenv(J.STATE_DIR_ENV, str(tmp_path / "learning-state"))


def _family():
    return J.mod("learning.judge.family")


def _graded(tmp_path, **kw):
    """One accepted episode graded by the mechanical half, as `(grade, rows)`."""
    ep = J.accepted_episode(tmp_path, **kw)
    grade = _family().grade_family(ep)
    return ep, grade, J.rows(grade)


# ---------------------------------------------------------------------------------------
# the five buckets
# ---------------------------------------------------------------------------------------


def test_921_never_queried_H_is_lead_set(tmp_path):
    """No row on H at all: the world never queried the holding system. Bucket `lead-set`.

    Exercised against a world whose ledger carries a row on a DIFFERENT system, so the bucket
    turns on `system == H` rather than on the file being empty — the two are separate reasons to
    answer `lead-set` and only one of them is this bucket's.
    """
    _ep, _grade, rows = _graded(tmp_path, ledgers={
        "b": [J.ledger_row(source="patched", world_label="b", system="cmdb", verb="get-host")],
        "c": [],
    })
    assert rows["b"]["bucket"] == "lead-set"
    assert rows["b"]["holding_queried"] is False


def test_921_queried_H_at_a_non_discriminating_scope_is_lead_quality(tmp_path):
    """Rows on H exist but at a scope that could not tell the worlds apart. Bucket
    `lead-quality`.

    J1's second half lands here too and is exercised as its own row: when `H` names a served
    system this world never touches, the applier's `not _touches -> PASSTHROUGH` rule (G7) makes
    every row on H a `passthrough`, so the world DID query H and the difference never reached
    it — `lead-quality`'s successor, not `lead-set`. Spelling it as its own condition is what
    keeps "never queried" and "queried and shown nothing" from collapsing into one bucket.
    """
    _ep, _grade, rows = _graded(tmp_path, ledgers={
        # queried H, but the form carries no window and no scope key.
        "b": [J.ledger_row(source="passthrough", world_label="b",
                           params={"index": J.EVENTS_PATTERN})],
        # queried H at a discriminating scope, but the world touches nothing there.
        "c": [J.ledger_row(source="passthrough", world_label="c",
                           params={"index": J.EVENTS_PATTERN, "window": "24h",
                                   "scope_key": "host.name"})],
    })
    assert rows["b"]["holding_queried"] is True
    assert rows["b"]["scope_discriminated"] is False
    assert rows["b"]["bucket"] == "lead-quality"
    assert rows["c"]["bucket"] == "lead-quality", (
        "a world whose every H row is `passthrough` was bucketed as if it never queried H")


def test_921_doctored_answer_served_and_conclusion_unmoved_is_analyze_discipline(tmp_path):
    """The doctored evidence was served (`staged`/`patched` on H) and the conclusion still did
    not move. Bucket `analyze-discipline`."""
    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.staged_row("b")], "c": []},
                            dispositions={"a": "benign", "b": "malicious", "c": "malicious"})
    (ep / "worlds" / "b" / "investigation.md").write_text(
        J.investigation_document("b", moved=False), encoding="utf-8")
    (ep / "worlds" / "b" / "report.md").write_text(J.report_text("benign"), encoding="utf-8")
    row = J.rows(_family().grade_family(ep))["b"]

    assert (row["doctored_answer_served"], row["resolution_moved"]) == (True, False)
    assert row["verdict"] != row["declared"]
    assert row["bucket"] == "analyze-discipline"


def test_921_conclusion_moved_and_verdict_still_wrong_is_decision_discipline(tmp_path):
    """The doctored evidence was served, a resolution moved past `fences_at`, and the verdict
    still disagreed with the declared disposition. Bucket `decision-discipline`.

    Reachable ONLY under the amendment: the refuted table routed this case through `ΔO_X`, whose
    central set is empty by construction offline, so the member had no reachable instance at
    all. This is the bucket the fixture exists to discriminate.
    """
    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.staged_row("b")], "c": []},
                            dispositions={"a": "benign", "b": "malicious", "c": "malicious"})
    (ep / "worlds" / "b" / "report.md").write_text(J.report_text("benign"), encoding="utf-8")
    row = J.rows(_family().grade_family(ep))["b"]

    assert (row["doctored_answer_served"], row["resolution_moved"]) == (True, True)
    assert row["verdict"] != row["declared"]
    assert row["bucket"] == "decision-discipline"


def test_921_verdict_matching_declared_gets_no_bucket(tmp_path):
    """A world whose verdict equals its declared disposition gets no bucket.

    Driven with the difference demonstrably served, so "no bucket" is the grade of a world that
    got it right rather than of a world nothing reached.
    """
    _ep, _grade, rows = _graded(tmp_path, ledgers={"b": [J.staged_row("b")], "c": []},
                               dispositions={"a": "benign", "b": "malicious",
                                             "c": "malicious"})
    assert rows["b"]["verdict"] == rows["b"]["declared"] == "malicious"
    assert rows["b"]["doctored_answer_served"] is True
    assert rows["b"]["bucket"] is None
    assert rows["b"].get("flag") != "agreed-without-evidence"


def test_921_verdict_matched_while_every_H_row_is_passthrough_is_flagged(tmp_path):
    """The verdict matched while EVERY row on H says `passthrough`: the world agreed without
    having been shown anything. No bucket, flagged `agreed-without-evidence`.

    That is the honest reading of agreeing with a declared disposition the world was never given
    evidence for, and it is a flag rather than a bucket because there is no defect to author a
    lesson from — only a result that should not be counted as a catch.
    """
    _ep, _grade, rows = _graded(tmp_path, ledgers={
        "b": [J.ledger_row(source="passthrough", world_label="b"),
              J.ledger_row(source="passthrough", world_label="b", verb="query")],
        "c": [],
    }, dispositions={"a": "benign", "b": "malicious", "c": "malicious"})

    assert rows["b"]["verdict"] == rows["b"]["declared"]
    assert rows["b"]["doctored_answer_served"] is False
    assert rows["b"]["bucket"] is None
    assert rows["b"]["flag"] == "agreed-without-evidence"


# ---------------------------------------------------------------------------------------
# the family's verdict word
# ---------------------------------------------------------------------------------------


def test_921_every_graded_verdict_equal_to_declared_is_caught(tmp_path):
    """Every graded world's verdict equals its declared disposition: family `verdict_word` is
    `caught`."""
    _ep, grade, rows = _graded(tmp_path, ledgers={"b": [J.staged_row("b")],
                                                  "c": [J.staged_row("c")]},
                               dispositions={"a": "benign", "b": "malicious",
                                             "c": "malicious"})
    assert all(row["verdict"] == row["declared"] for row in rows.values())
    assert J.word_of(grade) == "caught"


def test_921_any_graded_world_missing_its_declared_disposition_is_survived(tmp_path):
    """One graded world whose verdict differs from its declared disposition makes the family
    `survived` — the word `_gate_family` routes to AUTHOR a lesson.

    Everything upstream that can silently exclude a world moves this word, which is why J1's
    validation and J5's named-and-recorded exclusion are material rather than hygiene: a world
    quietly dropped here flips `survived` to `caught` and suppresses the lesson, or the reverse
    and authors one nobody's evidence supports.
    """
    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.staged_row("b")], "c": []},
                            dispositions={"a": "benign", "b": "malicious", "c": "malicious"})
    (ep / "worlds" / "b" / "report.md").write_text(J.report_text("benign"), encoding="utf-8")
    grade = _family().grade_family(ep)

    assert J.rows(grade)["c"]["verdict"] == J.rows(grade)["c"]["declared"]
    assert J.word_of(grade) == "survived", (
        "one disagreeing graded world did not carry the family to `survived`")


def test_921_no_contrasting_archived_world_is_undecidable(tmp_path):
    """No archived non-control world declares a disposition different from the control's, or
    none is archived at all: there is no contrast to grade and the family is `undecidable`.

    Both shapes are driven, because they are two different absences: a family whose every world
    declares what the control declares, and a family whose non-control worlds were never
    archived.
    """
    _ep, grade, _rows = _graded(tmp_path, dispositions={"a": "benign", "b": "benign",
                                                        "c": "benign"},
                                ledgers={"b": [J.staged_row("b")], "c": []})
    assert J.word_of(grade) == "undecidable", (
        "a family with no declared contrast produced a verdict about the defender")

    control_only = J.accepted_episode(tmp_path / "alone", labels=("a",),
                                      worlds=[J.world_doc("a", role="A", axis=None,
                                                          disposition_declared="benign", ov={})],
                                      dispositions={"a": "benign"})
    assert J.word_of(_family().grade_family(control_only)) == "undecidable"


def test_921_control_world_is_graded_per_world_only_and_gets_no_bucket(tmp_path):
    """The control world is graded by the per-world judge pass only and carries no bucket row in
    the family record.

    Positive control: a non-control world in the same family DOES carry one, so the negative
    cannot pass on a record with no rows at all.
    """
    _ep, _grade, rows = _graded(tmp_path, ledgers={"b": [J.staged_row("b")], "c": []})
    assert "a" not in rows, "the control world was given a mechanical bucket row"
    assert "b" in rows, "the positive control failed: no non-control world is graded at all"
    assert "bucket" in rows["b"], (
        "the positive control failed: no non-control world carries a bucket either")


def test_921_world_processing_order_does_not_change_any_per_world_fact(tmp_path):
    """All five per-world facts read X's own record plus the manifest, so grading the worlds in
    any order — including a non-control world before the control's own archive write lands —
    yields the same family record.

    Deleting ΔO removed the only cross-world input; this is the demand that keeps it removed.
    Driven by grading with the control's archived directory absent and then present: if any fact
    reached across worlds, the two records would differ on the worlds that were graded both
    times.
    """
    import shutil

    family_mod = _family()
    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.staged_row("b")],
                                               "c": [J.ledger_row(source="passthrough",
                                                                  world_label="c")]})
    control = ep / "worlds" / "a"
    stash = tmp_path / "control-stash"
    shutil.move(str(control), str(stash))
    early = J.rows(family_mod.grade_family(ep))
    shutil.move(str(stash), str(control))
    late = J.rows(family_mod.grade_family(ep))

    assert set(early) == {"b", "c"}
    for label in ("b", "c"):
        for fact in J.PER_WORLD_FACTS:
            assert early[label][fact] == late[label][fact], (
                f"{label}.{fact} moved with the CONTROL world's archive write, so some fact "
                "still reaches across worlds")
        assert early[label]["bucket"] == late[label]["bucket"]


def test_921_family_pass_never_reads_served_base_and_never_calls_the_comparator(tmp_path):
    """The family pass reads no `served/base.jsonl`, makes no base comparison and issues no
    comparator call: no archived classification, no offline comparator lane, no
    `mutation`/`undeclared` membership test.

    Driven as real input rather than as an inspection: the family capture is first DELETED and
    then written as bytes no reader can parse. Every base-comparing path in the tree goes
    through `Ledger`, which refuses a missing base outright, so a pass that touched it would
    fail on the first arm and raise on the second.

    Positive control: with the base gone the pass still produces a COMPLETE `FamilyGrade` from
    X's own record — five facts, a bucket and a verdict word — so the negative cannot pass on a
    pass that does nothing.
    """
    family_mod = _family()
    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.staged_row("b")], "c": []},
                            dispositions={"a": "benign", "b": "malicious", "c": "malicious"})
    # `decision-discipline` needs `verdict != declared` (J4's own compare); `accepted_episode`
    # drives both `report.md`'s disposition and the manifest's `disposition_declared` off the
    # same value, so the mismatch this test's own bucket needs is written explicitly here, the
    # same one-line idiom `test_921_conclusion_moved_and_verdict_still_wrong_is_decision_discipline`
    # already uses.
    (ep / "worlds" / "b" / "report.md").write_text(J.report_text("benign"), encoding="utf-8")
    base = ep / "served" / "base.jsonl"

    base.unlink()
    without = family_mod.grade_family(ep)
    base.write_text('{"system": "elastic", "verb": "esq\n\x00 torn', encoding="utf-8")
    with_torn = family_mod.grade_family(ep)

    for grade in (without, with_torn):
        rows = J.rows(grade)
        assert set(rows) == {"b", "c"}
        assert all(fact in rows["b"] for fact in J.PER_WORLD_FACTS)
        assert rows["b"]["bucket"] == "decision-discipline"
        assert J.word_of(grade) in ("caught", "survived", "undecidable")
    assert J.rows(without)["b"] == J.rows(with_torn)["b"], (
        "the family capture's bytes moved a per-world fact; nothing here may read them")


def test_921_model_findings_explain_a_bucket_and_never_assign_it(tmp_path):
    """A world's bucket is computed from the archive. A reply whose findings all claim a
    DIFFERENT bucket does not change it; the findings EXPLAIN the bucket, and each finding row
    carries its OWN bucket as `type` because that is what the lesson author acts on.

    O3's sentence is "graded by the archive, not by prose", and J13(b) settled where the archive
    stops being host-attested: the ledger is written by `registry.served` and is a per-call fact
    about what the defender saw, while `investigation.md` and `report.md` are model-authored
    bytes. A predicate reading a self-reported document yields evidence the judge EXPLAINS, not
    ground truth it is graded against — which is why a reply cannot move the bucket in either
    direction.
    """
    judge_mod = J.mod("learning.judge")
    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.staged_row("b")], "c": []},
                            dispositions={"a": "benign", "b": "malicious", "c": "malicious"})
    (ep / "worlds" / "b" / "report.md").write_text(J.report_text("benign"), encoding="utf-8")

    loud = J.as_reply_text(J.reply_doc(findings=[
        J.finding_doc(bucket="observability",
                      claim="this world is plainly lead-set and nothing else"),
        J.finding_doc(bucket="lead-quality", anchor="l-002", topic="scope"),
    ]))
    judge_mod.grade_episode(ep, judge=J.FakeJudge(default=loud),
                            runs_base=tmp_path / "defender-runs")

    record = J.judge_record(ep)
    assert J.world_rows(record)["b"]["bucket"] == "decision-discipline", (
        "the model's findings moved the archive-computed bucket")
    types = {row["type"] for row in J.enqueued_rows(record)}
    assert types == {"observability", "lead-quality"}, (
        "a finding row did not carry its OWN bucket as `type`")


def test_921_the_majority_denominator_is_completed_draws(tmp_path):
    """J6, settled with the human: the majority is over COMPLETED draws, both the completed and
    the configured counts are recorded on the family record, a draw that fails at any stage
    writes a DRAW RECORD carrying its failure reason, and a world with zero completed draws
    still gets its mechanical bucket.

    The denominator is not a detail: with `draws=4`, two failures and two completed draws that
    both answer `discard`, the completed denominator suppresses the whole episode's findings and
    the configured denominator does not. Two defensible implementations disagree on the word
    that decides whether an episode's findings exist at all.

    A silent absence is indistinguishable from a draw never requested, which is why a failed
    draw writes a record rather than nothing — and P9 (executed) is why the record cannot branch
    on exception type: a wall-clock timeout and a raw transport failure arrive as the same
    `RunUnprocessable`, separable only by message text and `__cause__`.
    """
    judge_mod = J.mod("learning.judge")
    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.staged_row("b")], "c": []})
    discard = J.as_reply_text(J.reply_doc(episode_outcome="discard"))
    # Two answers, then the seam degrades: `raise_after=2` is P9's one class, both ways.
    judge = J.FakeJudge(replies=[discard, discard], default=discard,
                        fault=J.Fault(raise_after=2))
    judge_mod.grade_episode(ep, judge=judge, runs_base=tmp_path / "defender-runs", draws=4)

    record = J.judge_record(ep)
    assert record["draws"] == {"configured": 4, "completed": 2}, (
        "the family record does not carry BOTH counts; the denominator is then unstated")
    assert record["episode_outcome"] == "discard", (
        "the majority was counted over configured draws, so two of two agreeing draws did not "
        "reach the bar")

    failed = [J.draw_doc(ep, "b", n) for n in range(4)
              if (ep / "worlds" / "b" / "judge" / f"{n}.yaml").exists()]
    reasons = [doc.get("failure_reason") for doc in failed if doc.get("failure_reason")]
    assert reasons, "a failed draw left no record at all; that is a draw never requested"
    assert all("RunUnprocessable" in str(r) or "did not complete" in str(r) or "failed" in str(r)
               for r in reasons)

    # A world with ZERO completed draws still gets its mechanical bucket. A doctored world
    # (the `staged_row` on H) with `verdict == declared` buckets `None` by design (agreement is
    # the non-failure case) — the mismatch this assertion needs is written explicitly, same as
    # `test_921_conclusion_moved_and_verdict_still_wrong_is_decision_discipline`.
    dead = J.accepted_episode(tmp_path / "dead", ledgers={"b": [J.staged_row("b")], "c": []})
    (dead / "worlds" / "b" / "report.md").write_text(J.report_text("benign"), encoding="utf-8")
    judge_mod.grade_episode(dead, judge=J.FakeJudge(fault=J.Fault(raise_after=0)),
                            runs_base=tmp_path / "dead" / "defender-runs", draws=2)
    dead_rows = J.world_rows(J.judge_record(dead))
    assert dead_rows["b"]["completed_draws"] == 0
    assert dead_rows["b"]["bucket"], (
        "a world whose every draw failed lost the bucket its own archive still supports")
