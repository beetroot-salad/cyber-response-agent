"""#921 — what may move a world's row, and who owns its bucket.

#1224 retired the mechanical bucket table and the computed family word: the judge MODEL decides
each world's bucket (O11, `run._draw_document` owns it) and the family-scope call gives the
family's `verdict_word`. What stays is what the record may and may not be moved by: no world's
row reads another world's archive, nothing reads `served/base.jsonl` or calls the comparator,
the control gets no row, the bucket is the draws' own (never the findings', never a code
path's), and the majority is counted over completed draws.
"""
from __future__ import annotations

import pytest

from defender._episode_handle import Episode
from defender.tests import _judge_921 as J
from defender.tests import _state1135
from defender.tests._state1135 import env_state


@pytest.fixture(autouse=True)
def _tmp_roots(tmp_path, monkeypatch):
    monkeypatch.setenv(J.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(J.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    # The learning STATE root too, so the shared findings queue this pass appends to is
    # this test's own and not the checkout's real `learning/_pending/`. Isolation belongs
    # here rather than in the appender: a production path that picks a different queue when
    # an env var is unset is a pass whose rows can land where no drain reads.
    _state1135.set_state_dir(monkeypatch, tmp_path / "learning-state")


def _grade(ep, **kw):
    """Grade `ep` afresh (a final `judge.yaml` short-circuits a second pass)."""
    (ep / "judge.yaml").unlink(missing_ok=True)
    return J.grade(ep, runs_base=ep.parent / "defender-runs", **kw)


# ---------------------------------------------------------------------------------------
# what the row may not be moved by
# ---------------------------------------------------------------------------------------


def test_921_control_world_is_graded_per_world_only_and_gets_no_bucket(tmp_path):
    """The control world carries no row in the family record.

    Positive control: a non-control world in the same family DOES carry one, with a bucket, so
    the negative cannot pass on a record with no rows at all.
    """
    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.oracle_row("b")], "c": []})
    rows = J.rows(_grade(ep))
    assert "a" not in rows, "the control world was given a bucket row"
    assert "b" in rows, "the positive control failed: no non-control world is graded at all"
    assert "bucket" in rows["b"], (
        "the positive control failed: no non-control world carries a bucket either")


def test_921_world_processing_order_does_not_change_any_per_world_fact(tmp_path):
    """Every per-world fact reads X's own record plus the manifest, so grading the worlds in
    any order — including a non-control world before the control's own archive write lands —
    yields the same rows.

    Driven by grading with the control's archived directory absent and then present: if any fact
    reached across worlds, the two records would differ on the worlds graded both times.
    """
    import shutil

    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.oracle_row("b")],
                                               "c": [J.ledger_row(source="passthrough",
                                                                  world_label="c")]})
    control = ep / "worlds" / "a"
    stash = tmp_path / "control-stash"
    shutil.move(str(control), str(stash))
    early = J.rows(_grade(ep))
    shutil.move(str(stash), str(control))
    late = J.rows(_grade(ep))

    assert set(early) == {"b", "c"}
    for label in ("b", "c"):
        for fact in J.PER_WORLD_FACTS:
            assert early[label][fact] == late[label][fact], (
                f"{label}.{fact} moved with the CONTROL world's archive write, so some fact "
                "still reaches across worlds")
        assert early[label]["bucket"] == late[label]["bucket"]


def test_921_family_pass_never_reads_served_base_and_never_calls_the_comparator(tmp_path):
    """The pass reads no `served/base.jsonl`, makes no base comparison and issues no comparator
    call.

    Driven as real input rather than as an inspection: the family capture is first DELETED and
    then written as bytes no reader can parse. Every base-comparing path in the tree goes
    through `Ledger`, which refuses a missing base outright, so a pass that touched it would
    fail on the first arm and raise on the second.

    Positive control: with the base gone the pass still produces a COMPLETE grade from X's own
    record — every per-world fact, the model's bucket and a family word — so the negative
    cannot pass on a pass that does nothing.
    """
    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.oracle_row("b")], "c": []},
                            dispositions={"a": "benign", "b": "malicious", "c": "malicious"})
    (ep / "worlds" / "b" / "report.md").write_text(J.report_text("benign"), encoding="utf-8")
    base = ep / "served" / "base.jsonl"

    base.unlink()
    without = _grade(ep)
    base.write_text('{"system": "elastic", "verb": "esq\n\x00 torn', encoding="utf-8")
    with_torn = _grade(ep)

    for grade in (without, with_torn):
        rows = J.rows(grade)
        assert set(rows) == {"b", "c"}
        assert all(fact in rows["b"] for fact in J.PER_WORLD_FACTS)
        assert rows["b"]["verdict"] == "benign"
        assert rows["b"]["bucket"] == J.reply_doc()["bucket"]
        assert J.word_of(grade) in ("caught", "survived", "undecidable")
    assert J.rows(without)["b"] == J.rows(with_torn)["b"], (
        "the family capture's bytes moved a per-world fact; nothing here may read them")


def test_921_model_findings_explain_a_bucket_and_never_assign_it(tmp_path):
    """A world's bucket is the judge model's own answer for the world — the reply's top-level
    `bucket` (`run._draw_document` @owns it) — never one its findings claim. Each finding row
    carries its OWN bucket as `type`, because that is what the lesson author acts on.

    #1224 inverted the owner (O11): no code path computes a bucket, so where the draws DISAGREE
    the row carries none (`draws_disagree`, every draw's answer on `draws`) rather than a bucket
    of the pass's own choosing.
    """
    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.oracle_row("b")], "c": []},
                            dispositions={"a": "benign", "b": "malicious", "c": "malicious"})
    (ep / "worlds" / "b" / "report.md").write_text(J.report_text("benign"), encoding="utf-8")

    loud = J.as_reply_text(J.reply_doc(bucket="decision-discipline", findings=[
        J.finding_doc(bucket="observability",
                      claim="this world is plainly lead-set and nothing else"),
        J.finding_doc(bucket="lead-quality", anchor="l-002", topic="scope"),
    ]))
    _grade(ep, judge=J.scripted_judge(default=loud))

    record = J.judge_record(ep)
    assert J.world_rows(record)["b"]["bucket"] == "decision-discipline", (
        "the findings' buckets moved the world's bucket the reply gave")
    types = {row["type"] for row in J.enqueued_rows(record)}
    assert types == {"observability", "lead-quality"}, (
        "a finding row did not carry its OWN bucket as `type`")

    # Two draws that disagree: the row names no bucket either draw gave, and keeps both.
    split = J.accepted_episode(tmp_path / "split", ledgers={"b": [J.oracle_row("b")], "c": []})
    one = J.as_reply_text(J.reply_doc(bucket="analyze-discipline"))
    other = J.as_reply_text(J.reply_doc(bucket="decision-discipline"))
    _grade(split, judge=J.scripted_judge(replies=[one, other], default=one), draws=2)
    row = J.world_rows(J.judge_record(split))["b"]
    assert row["bucket"] is None, (
        f"disagreeing draws were reduced to {row['bucket']!r}; no code path picks a bucket")
    assert row.get("draws_disagree") is True
    assert sorted(d["bucket"] for d in row["draws"]) == [
        "analyze-discipline", "decision-discipline"]


def test_921_the_majority_denominator_is_completed_draws(tmp_path):
    """J6, settled with the human: the majority is over COMPLETED draws, both the completed and
    the configured counts are recorded on the family record, and a draw that fails at any stage
    writes a DRAW RECORD carrying its failure reason.

    The denominator is not a detail: with `draws=4`, two failures and two completed draws that
    both answer `discard`, the completed denominator suppresses the whole episode's findings and
    the configured denominator does not.

    P9 (executed) is why the record cannot branch on exception type: a wall-clock timeout and a
    raw transport failure arrive as the same `RunUnprocessable`. And a world with ZERO completed
    draws carries no bucket at all (#1224, O11): nothing but a draw supplies one.
    """
    judge_mod = J.mod("learning.judge")
    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.oracle_row("b")], "c": []})
    discard = J.as_reply_text(J.reply_doc(episode_outcome="discard"))
    # Two answers, then the seam degrades: `raise_after=2` is P9's one class, both ways.
    judge = J.FakeJudge(replies=[discard, discard], default=discard,
                        fault=J.Fault(raise_after=2))
    judge_mod.grade_episode(ep, judge=judge, runs_base=tmp_path / "defender-runs", draws=4,
                            state=env_state())

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

    dead = J.accepted_episode(tmp_path / "dead", ledgers={"b": [J.oracle_row("b")], "c": []})
    judge_mod.grade_episode(dead, judge=J.FakeJudge(fault=J.Fault(raise_after=0)),
                            runs_base=tmp_path / "dead" / "defender-runs", draws=2,
                            state=env_state())
    dead_rows = J.world_rows(J.judge_record(dead))
    assert dead_rows["b"]["completed_draws"] == 0
    assert dead_rows["b"]["bucket"] is None, (
        "a world whose every draw failed carries a bucket no draw gave")


# ---------------------------------------------------------------------------------------
# a world that served nothing leaves a ledger saying so
# ---------------------------------------------------------------------------------------


def test_921_a_running_world_leaves_a_ledger_even_when_it_serves_nothing(tmp_path):
    """`Ledger.declare` creates the file at world setup, so serving nothing is EXPRESSIBLE.

    The rows are written by `record`, which creates the file on its first append — so a sibling
    that answered every question from the replayed capture, and made no live call at all, left
    no ledger. One missing file then stood for two facts: a world that never ran and one that
    ran perfectly and served nothing.

    Observed live: of two siblings, one issued the same 76 queries as the control, served
    nothing, closed `benign`, and was filed unjudgeable — when "closed without ever consulting
    the world it was given" is the strongest finding this design can make.

    Declared up front, that sibling leaves an EMPTY ledger, which the row reports as
    `served_nothing`.
    """
    ledger_mod = J.mod("learning.branch.ledger")
    ep_dir = J.accepted_episode(tmp_path)
    with Episode.open(ep_dir) as episode:
        fresh = ledger_mod.Ledger.for_world(episode, "newborn")
        assert not fresh.path.exists(), "the scenario started with the file already there"

        returned = fresh.declare()
        assert returned is fresh, (
            "declare did not hand back the ledger the caller must write through")
        assert fresh.path.is_file(), "a world that served nothing left no ledger"
        assert fresh.path.read_text(encoding="utf-8") == "", "declare wrote a row"


def test_921_declaring_a_ledger_twice_keeps_the_rows_already_written(tmp_path):
    """`declare` opens in APPEND and never truncates.

    It runs once at world setup, but this world's gather leads dispatch in parallel and `record`
    may already be appending. A create that truncated would silently drop the rows the table
    exists to hold — and the loss would look exactly like the world having served nothing, which
    is the very fact `declare` exists to make trustworthy.
    """
    ledger_mod = J.mod("learning.branch.ledger")
    ep_dir = J.accepted_episode(tmp_path)
    with Episode.open(ep_dir) as episode:
        led = ledger_mod.Ledger.for_world(episode, "already_writing").declare()
        led.path.write_text('{"source": "oracle"}\n', encoding="utf-8")

        led.declare()
        assert led.path.read_text(encoding="utf-8") == '{"source": "oracle"}\n', (
            "a second declare truncated rows a concurrent writer had already appended")


def test_921_an_empty_ledger_reports_served_nothing_on_the_record(tmp_path):
    """The row says whether the world served anything at all, from its own rows.

    A world that served NOTHING never made a call that reached its oracle, so its facts were
    never consulted and its verdict is not a measurement. World `c` serves one row on a system
    other than the fixture's usual one, so a `served_nothing` keyed on a particular system
    instead of on the rows fails it.
    """
    elsewhere = J.ledger_row(source="passthrough", system="cmdb", verb="lookup",
                             world_label="c")
    ep = J.accepted_episode(tmp_path, ledgers={"b": [], "c": [elsewhere]})
    rows = J.rows(_grade(ep))
    assert rows["b"]["served_nothing"] is True, "an empty ledger did not report serving nothing"
    assert rows["c"]["served_nothing"] is False, (
        "a world that served rows off the usual system was reported as having served nothing")
