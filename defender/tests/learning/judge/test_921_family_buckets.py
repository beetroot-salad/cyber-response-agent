"""#921 — what may move a world's row, and who owns its bucket."""
from __future__ import annotations

import pytest

from defender._episode_handle import Episode
from defender.tests.support.learning.judge import _judge_921 as J
from defender.tests.support.learning.core import _state1135
from defender.tests.support.learning.core._state1135 import env_state


@pytest.fixture(autouse=True)
def _tmp_roots(tmp_path, monkeypatch):
    monkeypatch.setenv(J.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(J.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    _state1135.set_state_dir(monkeypatch, tmp_path / "learning-state")


def _grade(ep, **kw):
    """Grade `ep` afresh (a final `judge.yaml` short-circuits a second pass)."""
    (ep / "judge.yaml").unlink(missing_ok=True)
    return J.grade(ep, **kw)


def test_921_control_world_is_graded_per_world_only_and_gets_no_bucket(tmp_path):
    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.oracle_row("b")], "c": []})
    rows = J.rows(_grade(ep))
    assert "a" not in rows, "the control world was given a bucket row"
    assert "b" in rows, "the positive control failed: no non-control world is graded at all"
    assert "bucket" in rows["b"], (
        "the positive control failed: no non-control world carries a bucket either")


def test_921_world_processing_order_does_not_change_any_per_world_fact(tmp_path):
    import shutil

    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.oracle_row("b")],
                                               "c": [J.ledger_row(source="passthrough",
                                                                  world_label="c")]})
    sibling = ep / "worlds" / "c"
    stash = tmp_path / "sibling-stash"
    shutil.move(str(sibling), str(stash))
    early = J.rows(_grade(ep))
    shutil.move(str(stash), str(sibling))
    late = J.rows(_grade(ep))

    assert early["c"].get("ungradable") is True, "the stash did not take world c out"
    assert late["c"].get("ungradable") is not True
    for label in ("b",):
        for fact in J.PER_WORLD_FACTS:
            assert early[label][fact] == late[label][fact], (
                f"{label}.{fact} moved with the CONTROL world's archive write, so some fact "
                "still reaches across worlds")
        assert early[label]["bucket"] == late[label]["bucket"]


def test_921_family_pass_never_reads_served_base_and_never_calls_the_comparator(tmp_path):
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
        assert grade.family["completed_draws"] == 1, "the family call did not complete"
    assert J.rows(without)["b"] == J.rows(with_torn)["b"], (
        "the family capture's bytes moved a per-world fact; nothing here may read them")


def test_921_model_findings_explain_a_bucket_and_never_assign_it(tmp_path):
    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.oracle_row("b")], "c": []},
                            dispositions={"a": "benign", "b": "malicious", "c": "malicious"})
    (ep / "worlds" / "b" / "report.md").write_text(J.report_text("benign"), encoding="utf-8")

    loud = J.as_reply_text(J.reply_doc(bucket="decision-discipline", findings=[
        J.finding_doc(bucket="lead-set",
                      claim="this world is plainly lead-set and nothing else"),
        J.finding_doc(bucket="lead-quality", anchor="l-002", topic="scope"),
    ]))
    _grade(ep, judge=J.scripted_judge(default=loud))

    record = J.judge_record(ep)
    assert J.world_rows(record)["b"]["bucket"] == "decision-discipline", (
        "the findings' buckets moved the world's bucket the reply gave")
    types = {row["type"] for row in J.enqueued_rows(record)}
    assert types == {"lead-set", "lead-quality"}, (
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
    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.oracle_row("b")], "c": []})
    discard = J.as_reply_text(J.reply_doc(findings=[
        J.finding_doc(), J.finding_doc(subject="world", bucket="incoherent")]))
    # Two answers, then the seam degrades: `raise_after=2` is P9's one class, both ways.
    judge = J.FakeJudge(replies=[discard, discard], default=discard,
                        fault=J.Fault(raise_after=2))
    J.grade_at(ep, judge=judge, draws=4, state=env_state())

    record = J.judge_record(ep)
    assert record["draws"] == {"configured": 4, "completed": 2}, (
        "the family record does not carry BOTH counts; the denominator is then unstated")
    row = J.world_rows(record)["b"]
    assert row["draws_disagree"] is False, (
        "the failed draws were counted as draws, so two of two agreeing draws disagreed")
    assert row["measured"] is False, (
        "two of two completed draws filing `incoherent` did not take the world out of "
        "measurement")

    failed = [J.draw_doc(ep, "b", n) for n in range(4)
              if (ep / "worlds" / "b" / "judge" / f"{n}.yaml").exists()]
    reasons = [doc.get("failure_reason") for doc in failed if doc.get("failure_reason")]
    assert reasons, "a failed draw left no record at all; that is a draw never requested"
    assert all("RunUnprocessable" in str(r) or "did not complete" in str(r) or "failed" in str(r)
               for r in reasons)

    dead = J.accepted_episode(tmp_path / "dead", ledgers={"b": [J.oracle_row("b")], "c": []})
    J.grade_at(dead, judge=J.FakeJudge(fault=J.Fault(raise_after=0)), draws=2,
               state=env_state())
    dead_rows = J.world_rows(J.judge_record(dead))
    assert dead_rows["b"]["completed_draws"] == 0
    assert dead_rows["b"]["bucket"] is None, (
        "a world whose every draw failed carries a bucket no draw gave")


def test_921_a_running_world_leaves_a_ledger_even_when_it_serves_nothing(tmp_path):
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
    ledger_mod = J.mod("learning.branch.ledger")
    ep_dir = J.accepted_episode(tmp_path)
    with Episode.open(ep_dir) as episode:
        led = ledger_mod.Ledger.for_world(episode, "already_writing").declare()
        led.path.write_text('{"source": "oracle"}\n', encoding="utf-8")

        led.declare()
        assert led.path.read_text(encoding="utf-8") == '{"source": "oracle"}\n', (
            "a second declare truncated rows a concurrent writer had already appended")


def test_921_an_empty_ledger_reports_served_nothing_on_the_record(tmp_path):
    elsewhere = J.ledger_row(source="passthrough", system="cmdb", verb="lookup",
                             world_label="c")
    ep = J.accepted_episode(tmp_path, ledgers={"b": [], "c": [elsewhere]})
    rows = J.rows(_grade(ep))
    assert rows["b"]["served_nothing"] is True, "an empty ledger did not report serving nothing"
    assert rows["c"]["served_nothing"] is False, (
        "a world that served rows off the usual system was reported as having served nothing")
