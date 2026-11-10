"""#921 — the queue row, the appender that writes it, and the family partition inside the gate."""
from __future__ import annotations

from defender.tests.support.learning.branch import _triplet_947 as T

from pathlib import Path

import pytest

from defender.tests.support.learning.curation import _drain719 as D
from defender.tests.support.learning.judge import _gate_1278 as G
from defender.tests.support.learning.judge import _judge_921 as J
from defender.tests.support.learning.judge._memory_store import MemoryStore


def _enqueue():
    return J.mod("learning.judge.enqueue")


def _family_row(fid: str = "ep-1/b/0/0", **over) -> dict:
    """One `FindingRow` in the `direction: family` shape the judge appends: `subject="defender"`
    (not `D.finding_row`'s placeholder), no `judge_outcome`, and the three fields the family
    gate reads as ground truth (`contrast_evidence`, `on_verdict_path`, `world_label_doubted`).
    """
    row = dict(D.finding_row(fid, run_id="ep-1", direction="family"),
               type="decision-discipline", subject="defender",
               subject_anchor="l-001", subject_topic="holding-system coverage",
               source_run_dir="episodes/ep-1/worlds/b",
               contrast_evidence=[f"worlds/{T.fixture_world_id('b')}/report.md", f"worlds/{T.fixture_world_id('a')}/report.md"],
               on_verdict_path=True, world_label_doubted=False)
    # `D.finding_row` is the adversarial channel's shape, which still spells the retired word.
    row.pop("judge_outcome", None)
    row.update(over)
    return row


def _graded(tmp_path, store=None, **kw):
    """An accepted episode, graded end to end into `store` (a fresh one by default), as `(episode_dir, family record)`."""
    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.staged_row("b")], "c": []},
                            dispositions={"a": "benign", "b": "malicious", "c": "malicious"},
                            **kw)
    (ep / "worlds" / T.world_id(ep, "b") / "report.md").write_text(J.report_text("benign"), encoding="utf-8")
    J.grade_at(
        ep, judge=J.FakeJudge(default=J.as_reply_text(J.reply_doc())),
        draws=1, store=store if store is not None else MemoryStore())
    return ep, J.judge_record(ep)


# The gate tests drive the real lessons claim (`drain.run_batch` over a git-free draft lane, #1278 D1) and read each
# row's fate off the claim's `outcomes`; only the curator's model spawn is a double.


def _claim(tmp_path, rows, agent):
    """One real lessons claim of `rows` (queued as `finding` items): `(rc, fates by finding id)`."""
    lane = G.gate_lane(tmp_path)
    rc, outcomes = G.claim(G.lessons_cfg(lane, invoke_agent=agent), rows)
    return rc, G.fates(outcomes)


def test_921_mixed_batch_routes_family_rows_and_leaves_the_rest_to_gate_findings(tmp_path):
    agent = D.recording(D.committing("mixed"))

    rc, fates = _claim(tmp_path, [
        D.finding_row("run-adv/0", run_id="run-adv", direction="adversarial"),
        _family_row("ep-1/b/0/0"),
        D.finding_row("run-held/0", run_id="run-held", direction="adversarial"),
    ], agent)

    assert rc == 0
    authored = {r["finding_id"] for r in agent.calls[0]["rows"]}
    assert authored == {"ep-1/b/0/0"}, (
        f"the two populations did not route independently: {sorted(authored)}")
    assert fates == {"run-adv/0": ("held", "retired_direction('adversarial')"),
                     "run-held/0": ("held", "retired_direction('adversarial')")}, (
        "an adversarial row stopped being held, or the family row was held with it")


def test_921_gate_family_skips_caught_and_undecidable(tmp_path):
    missing = _family_row("ep-1/c/0/1")
    del missing["world_label_doubted"]
    agent = D.recording(D.committing("hold-vs-author"))

    rc, fates = _claim(tmp_path, [
        _family_row("ep-1/b/0/0", judge_outcome="caught"),
        _family_row("ep-1/c/0/0", judge_outcome="undecidable"),
        missing,
        _family_row("ep-1/b/0/1"),
    ], agent)

    assert rc == 0
    assert agent.calls, "the positive control failed: the new-shape row authored nothing"
    assert [r["finding_id"] for r in agent.calls[0]["rows"]] == ["ep-1/b/0/1"]
    held = {fid for fid, (fate, _reason) in fates.items() if fate == "held"}
    assert held == {"ep-1/b/0/0", "ep-1/c/0/0", "ep-1/c/0/1"}, (
        f"a retired-word or incomplete row was consumed or authored instead of held: {fates}")
    assert "ep-1/b/0/1" not in fates, "the authored row was named a fate; it must stay in its batch (cited)"


def test_921_gate_family_is_idempotent_over_a_replayed_batch(tmp_path):
    lane = G.gate_lane(tmp_path)
    first = D.recording(D.committing("once"))
    rc, _ = G.claim(G.lessons_cfg(lane, invoke_agent=first), [_family_row("ep-1/b/0/0")])
    assert rc == 0, "the positive control failed: the first row authored nothing"
    assert first.calls, "the positive control failed: the first row authored nothing"

    second = D.recording(D.committing("twice"))
    rc, outcomes = G.claim(G.lessons_cfg(lane, invoke_agent=second),
                           [_family_row("ep-1/b/0/0"), _family_row("ep-1/b/0/1")])

    assert rc == 0
    assert second.calls, "the positive control failed: the NEW row authored nothing either"
    assert [r["finding_id"] for r in second.calls[0]["rows"]] == ["ep-1/b/0/1"], (
        "the replayed row authored a second lesson, or the new row stopped authoring")
    assert G.fates(outcomes)["ep-1/b/0/0"] == ("published", None), (
        "the row the corpus already cites was not recognised as published")


def test_921_finding_id_is_stable_across_a_retry_and_distinct_across_world_draw_and_index(
        tmp_path):
    first_store = MemoryStore()
    ep, record = _graded(tmp_path, first_store)

    first = J.enqueued_rows(record, first_store)
    ids = [row["finding_id"] for row in first]
    assert ids, "the graded episode enqueued nothing, so there is no id to compare"
    assert len(ids) == len(set(ids)), f"colliding finding ids inside one pass: {ids}"

    import shutil

    retry = tmp_path / "retry"
    retry.mkdir()
    ep_retry = T.tenant_episodes(retry / "data-root") / ep.name
    shutil.copytree(ep, ep_retry, symlinks=True)
    (ep_retry / "judge.yaml").unlink()
    shutil.rmtree(ep_retry / "worlds" / T.world_id(ep_retry, "b") / "judge")
    shutil.rmtree(ep_retry / "worlds" / T.world_id(ep_retry, "c") / "judge")
    retry_store = MemoryStore()
    J.grade_at(ep_retry, judge=J.FakeJudge(default=J.as_reply_text(J.reply_doc())),
               draws=1, store=retry_store)
    again = [row["finding_id"] for row in J.enqueued_rows(J.judge_record(ep_retry), retry_store)]
    assert again == ids, (
        "a retried pass minted new ids; the guard keys on the id alone, so a fresh id per "
        "retry defeats it entirely")
    # And the guard itself: a retry into the store that already holds those ids adds nothing (the store's rule,
    # a finding id is unique for good per tenant and kind). The retry is a real one: no record, no draws.
    (ep_retry / "judge.yaml").unlink()
    shutil.rmtree(ep_retry / "worlds" / T.world_id(ep_retry, "b") / "judge")
    shutil.rmtree(ep_retry / "worlds" / T.world_id(ep_retry, "c") / "judge")
    J.grade_at(ep_retry, judge=J.FakeJudge(default=J.as_reply_text(J.reply_doc())),
               draws=1, store=first_store)
    assert [r["finding_id"] for r in J.enqueued_rows(J.judge_record(ep_retry), first_store)] == ids, (
        "a retried pass queued a second row under an id the store already held")

    two = J.as_reply_text(J.reply_doc(findings=[
        J.finding_doc(topic="first"), J.finding_doc(topic="second", anchor="l-002")]))
    ep2 = J.accepted_episode(tmp_path / "two", ledgers={"b": [J.staged_row("b")], "c": []},
                             dispositions={"a": "benign", "b": "malicious", "c": "malicious"})
    (ep2 / "worlds" / T.world_id(ep2, "b") / "report.md").write_text(J.report_text("benign"), encoding="utf-8")
    own = MemoryStore()
    J.grade_at(
        ep2, judge=J.scripted_judge(default=two), draws=2, store=own)
    fresh = [row["finding_id"] for row in J.enqueued_rows(J.judge_record(ep2), own)]
    assert len(fresh) == len(set(fresh)) == 8, (
        f"two worlds x two draws x two findings did not mint eight distinct ids: {fresh}")


def test_921_a_world_filing_unreachable_or_incoherent_is_not_measured_and_enqueues_nothing(tmp_path):
    for word in ("unreachable", "incoherent"):
        ep = J.accepted_episode(tmp_path / word, ledgers={"b": [J.staged_row("b")], "c": []})
        reply = J.reply_doc(findings=[J.finding_doc(),
                                      J.finding_doc(subject="world", bucket=word)])
        store = MemoryStore()
        J.grade_at(ep, judge=J.FakeJudge(default=J.as_reply_text(reply)),
                   draws=1, store=store)
        record = J.judge_record(ep)
        rows = J.world_rows(record)
        assert rows["b"]["measured"] is False
        assert word in rows["b"]["not_measured_reason"]
        assert record["enqueued_rows"] == 0
        assert J.enqueued_rows(record, store) == [], f"a world filing {word} appended defender rows"
        lanes = {e["lane"] for e in record["dispositions"]
                 if e["finding_id"].endswith("/b/0/0")}
        assert lanes == {"not_measured"}, f"the investigator finding took {lanes}"
        assert rows["b"]["bucket"], (
            "the family record is the artifact, and it lost its per-world grading")


def test_921_enqueue_refuses_a_row_that_would_key_error_the_shared_gate(tmp_path):
    enqueue = _enqueue()
    store = MemoryStore()
    ep, record = _graded(tmp_path, store)
    before = len(J.enqueued_rows(record, store))

    for missing in ("run_id", "direction"):
        broken = _family_row()
        broken.pop(missing)
        with pytest.raises(J.refusals()) as raised:
            enqueue.append_rows(ep, [broken], state=J.findings_sink(store))
        assert missing in str(raised.value)
    assert len(J.enqueued_rows(record, store)) == before, "a refused row was appended anyway"

    # The blast radius the refusal exists to prevent: the shared gate reads `run_id` / `direction` of every row of the
    # claim unguarded, so one row without them raises out of the whole claim (the claim's items are then retried,
    # none authored; the file queue's stuck.jsonl record is retired with the file queue, design D1/Locks).
    unkeyable = _family_row("ep-1/b/0/9")
    unkeyable.pop("run_id")
    agent = D.recording(D.committing("blast"))
    with pytest.raises(KeyError):
        _claim(tmp_path / "blast", [D.finding_row("run-adv/0", run_id="run-adv"), unkeyable], agent)
    assert not agent.calls, "the curator was handed a batch containing a row the gate cannot key"


def test_921_the_judge_appender_writes_through_the_guarded_path(tmp_path):
    from defender.tests.support.shared.contracts._by_path import load_lint_gate

    enqueue = _enqueue()          # must exist: a lint that scans nothing is clean
    assert hasattr(enqueue, "append_rows")
    gate = load_lint_gate("lint_unguarded_tree_write")
    tree = tmp_path / "synthetic" / "defender" / "learning" / "judge"
    tree.mkdir(parents=True, exist_ok=True)
    (tree / "unguarded.py").write_text(
        "from defender._io import append_jsonl\n"
        "\n"
        "def enqueue(path, rows):\n"
        "    return append_jsonl(path, rows)\n", encoding="utf-8")
    (tree / "guarded.py").write_text(
        "from defender._io import write_guarded\n"
        "\n"
        "def enqueue(path, rows):\n"
        "    return write_guarded(path, rows, mode=\"append\")\n", encoding="utf-8")

    found = {f.fingerprint for f in gate._scan(tmp_path / "synthetic")}
    assert "defender/learning/judge/unguarded.py:enqueue" in found, (
        "the gate did not flag the bare `append_jsonl`; the witness proves nothing")
    assert "defender/learning/judge/guarded.py:enqueue" not in found, (
        "the gate flags the guarded spelling too, so passing it says nothing about the fix")

    defender_dir = Path(__file__).resolve().parents[3]
    assert (defender_dir / "learning" / "judge").is_dir(), (
        "control: there is no learning/judge/ package on disk for the gate to scan")
    # Rooted at the package: findings are per file, and a wider root would walk the whole tree
    # (and `.venv`) for nothing.
    real = {f.fingerprint for f in gate._scan(defender_dir / "learning" / "judge")}
    assert not real, f"the judge's own appender trips the write lint: {sorted(real)}"


# Retired: test_921_rows_are_appended_under_the_queue_lock_one_row_per_finding. It pinned the file queue's append lock
# (two threads' 20 rows of 200 kB each, one line per finding). The queue file and its lock are replaced by the store's
# insert (design r8 "Locks": the store's transaction is the only writer); that one row per finding id lands and a
# repeated id is a duplicate is the store's contract (tests/learning/store_1278/test_items_1278.py
# ::test_a_finding_id_is_unique_for_good_past_published_skipped_and_dead).


def test_921_a_store_already_holding_a_finding_does_not_change_what_a_pass_queues(tmp_path):
    """Surviving obligation of the torn-tail test: rows already queued stay, and the pass queues exactly its own, counted
    on the record (a torn queue tail is file mechanics, retired with the file queue: the store has no malformed lines)."""
    store = MemoryStore()
    store.publish_findings("tenant", "ep-0", [_family_row("ep-0/b/0/0")], kind="finding")

    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.staged_row("b")], "c": []},
                            dispositions={"a": "benign", "b": "malicious", "c": "malicious"})
    (ep / "worlds" / T.world_id(ep, "b") / "report.md").write_text(J.report_text("benign"), encoding="utf-8")
    J.grade_at(
        ep, judge=J.FakeJudge(default=J.as_reply_text(J.reply_doc())),
        draws=1, store=store)

    record = J.judge_record(ep)
    assert record["queue_malformed_rows"] == 0, "the store reported a malformed line, but it holds none"
    ids = [r["finding_id"] for r in store.rows(D.channel_of("findings"))]
    assert "ep-0/b/0/0" in ids, "the row that was already queued went missing"
    own = [i for i in ids if i != "ep-0/b/0/0"]
    assert own
    assert len(own) == record["enqueued_rows"], (
        f"the record claims {record['enqueued_rows']} enqueued rows and the store holds {len(own)} of this pass's own")


def test_921_archived_drift_reaches_the_judge_and_a_family_incoherent_finding_keeps_the_defender_lane_open(
        tmp_path):
    from defender import _yaml
    from defender.records._episode_handle import Episode
    from defender.learning.branch.outcome import write_outcome

    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.staged_row("b")], "c": []})
    (ep / "outcome.yaml").unlink()
    with Episode.open(ep) as handle:
        write_outcome(handle, "accepted", reason="")
    # An archive from before #1385 (H6) still carries pre-flight's `drift`; the writer no longer
    # does, so the old record is spelled out by hand.
    path = ep / "outcome.yaml"
    record = _yaml.safe_load(path.read_text(encoding="utf-8"))
    record["drift"] = [{
        "system": "elastic", "verb": "esql",
        "params": {"query": f"FROM {J.EVENTS_PATTERN} | LIMIT 5"},
        "reason": "DRIFT-MARKER-921"}]
    path.write_text(_yaml.safe_dump(record), encoding="utf-8")

    judge = J.scripted_judge(family_default=J.as_reply_text(J.family_reply(
        findings=[J.finding_doc(subject="world", bucket="incoherent")])))
    store = MemoryStore()
    J.grade_at(ep, judge=judge, draws=1, store=store)

    assert any("DRIFT-MARKER-921" in p for p in judge.prompts), (
        "pre-flight's recorded drift never reached the judge")
    record = J.judge_record(ep)
    family_lanes = [e["lane"] for e in record["dispositions"]
                    if "/family/" in e["finding_id"]]
    assert family_lanes == ["world"], f"the family's world finding took {family_lanes}"
    assert J.enqueued_rows(record, store), (
        "the family call's world finding closed the worlds' defender lane")
    assert J.world_rows(record)["b"]["bucket"], "the family record lost its per-world grading"


def test_921_a_world_whose_facts_a_gap_kept_back_is_not_measured_and_enqueues_nothing(tmp_path):
    gap = {"what": "elastic esql", "how": "the served system does not hold the field",
           "evidence": [f"worlds/{T.fixture_world_id('b')}/report.md"], "kept_facts_from_investigator": True}
    kept = J.as_reply_text(J.reply_doc(gaps=[gap]))
    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.staged_row("b")], "c": []},
                            labels=("a", "b"))
    store = MemoryStore()
    J.grade_at(ep, judge=J.FakeJudge(default=kept, family_default=J.as_reply_text(
        J.family_reply())), draws=2, store=store)

    record = J.judge_record(ep)
    row = J.world_rows(record)["b"]
    assert row["measured"] is False
    assert "kept the facts" in row["not_measured_reason"]
    lanes = {e["finding_id"].rsplit("/", 1)[1]: e["lane"] for e in record["dispositions"]
             if "/b/0/" in e["finding_id"]}
    assert lanes == {"0": "not_measured", "1": "user_record"}, lanes
    assert J.enqueued_rows(record, store) == [], "a world the gap kept facts from was authored"

    ok = J.accepted_episode(tmp_path / "ok", ledgers={"b": [J.staged_row("b")], "c": []},
                            dispositions={"a": "benign", "b": "malicious", "c": "malicious"})
    ok_store = MemoryStore()
    J.grade_at(
        ok, judge=J.FakeJudge(default=J.as_reply_text(J.reply_doc())),
        draws=2, store=ok_store)
    assert J.enqueued_rows(J.judge_record(ok), ok_store), "the positive control enqueued nothing"


def test_921_taking_a_world_out_of_measurement_needs_unanimous_draws(tmp_path):
    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.staged_row("b")], "c": []},
                            labels=("a", "b"))
    incoherent = J.as_reply_text(J.reply_doc(findings=[
        J.finding_doc(), J.finding_doc(subject="world", bucket="incoherent")]))
    plain = J.as_reply_text(J.reply_doc())
    minority = J.FakeJudge(replies=[incoherent, plain, plain], default=plain,
                           family_default=J.as_reply_text(J.family_reply()))
    store = MemoryStore()
    J.grade_at(ep, judge=minority, draws=3, store=store)

    record = J.judge_record(ep)
    row = J.world_rows(record)["b"]
    assert row["draws_disagree"] is True, row
    assert row["measured"] is None, row
    assert J.enqueued_rows(record, store) == [], "a world whose draws disagree queued defender rows"
    assert {e["lane"] for e in record["dispositions"]
            if e["finding_id"].rsplit("/", 1)[1] == "0"} == {"draws_disagree"}

    unanimous = J.accepted_episode(tmp_path / "unanimous",
                                   ledgers={"b": [J.staged_row("b")], "c": []},
                                   labels=("a", "b"))
    J.grade_at(unanimous, judge=J.FakeJudge(default=incoherent, family_default=J.as_reply_text(
        J.family_reply())), draws=3, store=MemoryStore())
    row = J.world_rows(J.judge_record(unanimous))["b"]
    assert row["draws_disagree"] is False, row
    assert row["measured"] is False, (
        "positive control: three draws agreeing on `incoherent` did not take the world out of "
        "measurement")
