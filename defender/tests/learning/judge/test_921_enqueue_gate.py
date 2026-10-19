"""#921 — the queue row, the appender that writes it, and the family partition inside the gate."""
from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest

from defender.tests.support.learning.curation import _drain719 as D
from defender.tests.support.learning.judge import _judge_921 as J
from defender.learning.core.config import LoopPaths
from defender.learning.core.state import LearningState
from defender.tests.support.learning.core import _state1135
from defender.tests.support.learning.core._state1135 import env_state


@pytest.fixture(autouse=True)
def _tmp_roots(tmp_path, monkeypatch):
    monkeypatch.setenv(J.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(J.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    _state1135.set_state_dir(monkeypatch, tmp_path / "learning-state")


def _enqueue():
    return J.mod("learning.judge.enqueue")


def _family_row(fid: str = "ep-1/b/0/0", **over) -> dict:
    """One `FindingRow` in the `direction: family` shape M5 appends.

    `subject="defender"` overrides `D.finding_row`'s own placeholder `"subj"` value — that
    fixture predates #1007's `subject` partition and this suite is entirely about the DEFENDER
    lane. #1234 (d00d): no `judge_outcome` (A4), and the three fields the family partition
    reads as the row's ground truth — `contrast_evidence`, `on_verdict_path`,
    `world_label_doubted`.
    """
    row = dict(D.finding_row(fid, run_id="ep-1", direction="family"),
               type="decision-discipline", subject="defender",
               subject_anchor="l-001", subject_topic="holding-system coverage",
               source_run_dir="episodes/ep-1/worlds/b",
               contrast_evidence=["worlds/b/report.md", "worlds/a/report.md"],
               on_verdict_path=True, world_label_doubted=False)
    # `D.finding_row` is the adversarial channel's shape, which still spells the retired word.
    row.pop("judge_outcome", None)
    row.update(over)
    return row


def _graded(tmp_path, **kw):
    """An accepted episode, graded end to end, as `(episode_dir, family record)`."""
    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.staged_row("b")], "c": []},
                            dispositions={"a": "benign", "b": "malicious", "c": "malicious"},
                            **kw)
    (ep / "worlds" / "b" / "report.md").write_text(J.report_text("benign"), encoding="utf-8")
    J.grade_at(
        ep, judge=J.FakeJudge(default=J.as_reply_text(J.reply_doc())),
        draws=1, state=env_state())
    return ep, J.judge_record(ep)


def test_921_family_row_is_not_held_as_no_ground_truth(tmp_path):
    paths = D.make_paths(tmp_path)
    channel = D.channel_of("findings")
    D.seed(paths, channel, [_family_row()])
    cfg = D.cfg_for(paths, "findings", invoke_agent=D.committing("family-lesson"))

    assert J.mod("learning.author.drain").run_batch(cfg=cfg) == 0
    assert D.pending(paths, channel) == [], (
        "the family row is still queued; without a gate of its own it is held forever as "
        "no_ground_truth")
    assert [r["finding_id"] for r in D.consumed(paths, channel)] == ["ep-1/b/0/0"]


def test_921_mixed_batch_routes_family_rows_and_leaves_the_rest_to_gate_findings(tmp_path):
    paths = D.make_paths(tmp_path)
    channel = D.channel_of("findings")
    D.seed(paths, channel, [
        D.finding_row("run-adv/0", run_id="run-adv", direction="adversarial"),
        _family_row("ep-1/b/0/0"),
        D.finding_row("run-held/0", run_id="run-held", direction="adversarial"),
    ])
    agent = D.recording(D.committing("mixed"))
    cfg = D.cfg_for(paths, "findings", invoke_agent=agent)

    assert J.mod("learning.author.drain").run_batch(cfg=cfg) == 0
    authored = {r["finding_id"] for r in agent.calls[0]["rows"]}
    assert authored == {"ep-1/b/0/0"}, (
        f"the two populations did not route independently: {sorted(authored)}")
    still_held = {r["finding_id"]: r["held_reason"] for r in D.pending(paths, channel)}
    assert still_held == {"run-adv/0": "retired_direction('adversarial')",
                          "run-held/0": "retired_direction('adversarial')"}, (
        "an adversarial row stopped being held, or the family row was held with it")


def test_921_gate_family_authors_a_survived_row(tmp_path):
    paths = D.make_paths(tmp_path)
    channel = D.channel_of("findings")
    D.seed(paths, channel, [_family_row()])
    agent = D.recording(D.committing("survived"))

    assert J.mod("learning.author.drain").run_batch(
        cfg=D.cfg_for(paths, "findings", invoke_agent=agent)) == 0
    assert agent.calls, "the new-shape row authored nothing; it was held, not admitted"
    assert [r["finding_id"] for r in agent.calls[0]["rows"]] == ["ep-1/b/0/0"]


def test_921_gate_family_skips_caught_and_undecidable(tmp_path):
    paths = D.make_paths(tmp_path)
    channel = D.channel_of("findings")
    missing = _family_row("ep-1/c/0/1")
    del missing["world_label_doubted"]
    D.seed(paths, channel, [
        _family_row("ep-1/b/0/0", judge_outcome="caught"),
        _family_row("ep-1/c/0/0", judge_outcome="undecidable"),
        missing,
        _family_row("ep-1/b/0/1"),
    ])
    agent = D.recording(D.committing("hold-vs-author"))

    assert J.mod("learning.author.drain").run_batch(
        cfg=D.cfg_for(paths, "findings", invoke_agent=agent)) == 0
    assert agent.calls, "the positive control failed: the new-shape row authored nothing"
    assert [r["finding_id"] for r in agent.calls[0]["rows"]] == ["ep-1/b/0/1"]
    held = {r["finding_id"] for r in D.pending(paths, channel)}
    assert held == {"ep-1/b/0/0", "ep-1/c/0/0", "ep-1/c/0/1"}, (
        f"a retired-word or incomplete row was consumed or authored instead of held: {held}")
    assert {r["finding_id"] for r in D.consumed(paths, channel)} == {"ep-1/b/0/1"}


def test_921_gate_family_is_idempotent_over_a_replayed_batch(tmp_path):
    paths = D.make_paths(tmp_path)
    channel = D.channel_of("findings")
    drain = J.mod("learning.author.drain")

    D.seed(paths, channel, [_family_row("ep-1/b/0/0")])
    first = D.recording(D.committing("once"))
    assert drain.run_batch(cfg=D.cfg_for(paths, "findings", invoke_agent=first)) == 0

    D.seed(paths, channel, [_family_row("ep-1/b/0/0"), _family_row("ep-1/b/0/1")])
    second = D.recording(D.committing("twice"))
    assert drain.run_batch(cfg=D.cfg_for(paths, "findings", invoke_agent=second)) == 0
    assert second.calls, "the positive control failed: the NEW row authored nothing either"
    assert [r["finding_id"] for r in second.calls[0]["rows"]] == ["ep-1/b/0/1"], (
        "the replayed row authored a second lesson, or the new row stopped authoring")


def test_921_finding_id_is_stable_across_a_retry_and_distinct_across_world_draw_and_index(
        tmp_path):
    ep, record = _graded(tmp_path)

    first = J.enqueued_rows(record)
    ids = [row["finding_id"] for row in first]
    assert ids, "the graded episode enqueued nothing, so there is no id to compare"
    assert len(ids) == len(set(ids)), f"colliding finding ids inside one pass: {ids}"

    import shutil

    retry = tmp_path / "retry"
    retry.mkdir()
    ep_retry = retry / ep.name
    shutil.copytree(ep, ep_retry, symlinks=True)
    (ep_retry / "judge.yaml").unlink()
    shutil.rmtree(ep_retry / "worlds" / "b" / "judge")
    shutil.rmtree(ep_retry / "worlds" / "c" / "judge")
    retry_root = retry / "queue"
    retry_root.mkdir()
    retry_state = LearningState.open(LoopPaths(repo_root=retry, state_dir=retry_root))
    J.grade_at(ep_retry, judge=J.FakeJudge(default=J.as_reply_text(J.reply_doc())),
               draws=1, state=retry_state)
    again = [row["finding_id"] for row in J.enqueued_rows(J.judge_record(ep_retry))]
    assert again == ids, (
        "a retried pass minted new ids; the guard keys on the id alone, so a fresh id per "
        "retry defeats it entirely")

    two = J.as_reply_text(J.reply_doc(findings=[
        J.finding_doc(topic="first"), J.finding_doc(topic="second", anchor="l-002")]))
    ep2 = J.accepted_episode(tmp_path / "two", ledgers={"b": [J.staged_row("b")], "c": []},
                             dispositions={"a": "benign", "b": "malicious", "c": "malicious"})
    (ep2 / "worlds" / "b" / "report.md").write_text(J.report_text("benign"), encoding="utf-8")
    own_root = tmp_path / "two" / "queue"
    own_root.mkdir(parents=True)
    own = LearningState.open(LoopPaths(repo_root=tmp_path / "two", state_dir=own_root))
    J.grade_at(
        ep2, judge=J.scripted_judge(default=two), draws=2, state=own)
    fresh = [row["finding_id"] for row in J.enqueued_rows(J.judge_record(ep2))]
    assert len(fresh) == len(set(fresh)) == 8, (
        f"two worlds x two draws x two findings did not mint eight distinct ids: {fresh}")


def test_921_enqueue_refuses_discard_and_corpus_contradiction(tmp_path):
    for word in ("unreachable", "incoherent"):
        ep = J.accepted_episode(tmp_path / word, ledgers={"b": [J.staged_row("b")], "c": []})
        reply = J.reply_doc(findings=[J.finding_doc(),
                                      J.finding_doc(subject="world", bucket=word)])
        J.grade_at(ep, judge=J.FakeJudge(default=J.as_reply_text(reply)),
                   draws=1, state=env_state())
        record = J.judge_record(ep)
        rows = J.world_rows(record)
        assert rows["b"]["measured"] is False
        assert word in rows["b"]["not_measured_reason"]
        assert record["enqueued_rows"] == 0
        assert J.enqueued_rows(record) == [], f"a world filing {word} appended defender rows"
        lanes = {e["lane"] for e in record["dispositions"]
                 if e["finding_id"].endswith("/b/0/0")}
        assert lanes == {"not_measured"}, f"the investigator finding took {lanes}"
        assert rows["b"]["bucket"], (
            "the family record is the artifact, and it lost its per-world grading")


def test_921_enqueue_refuses_a_row_that_would_key_error_the_shared_gate(tmp_path):
    enqueue = _enqueue()
    ep, record = _graded(tmp_path)
    before = len(J.enqueued_rows(record))

    for missing in ("run_id", "direction"):
        broken = _family_row()
        broken.pop(missing)
        with pytest.raises(J.refusals()) as raised:
            enqueue.append_rows(ep, [broken], state=env_state())
        assert missing in str(raised.value)
    assert len(J.enqueued_rows(record)) == before, "a refused row was appended anyway"

    # The blast radius the refusal exists to prevent, on the real channel.
    paths = D.make_paths(tmp_path / "blast")
    channel = D.channel_of("findings")
    unkeyable = _family_row("ep-1/b/0/9")
    unkeyable.pop("run_id")
    D.seed(paths, channel, [D.finding_row("run-adv/0", run_id="run-adv"), unkeyable])
    with pytest.raises(KeyError):
        J.mod("learning.author.drain").run_batch(
            cfg=D.cfg_for(paths, "findings", invoke_agent=D.committing("blast")))
    stuck = D.stuck_records(paths, channel)
    assert stuck, "the tick recorded nothing stuck at all"
    assert set(stuck[-1]["row_ids"]) >= {"run-adv/0"}, (
        "the well-formed adversarial row did not ride the malformed one into stuck.jsonl; "
        "P6 observed exactly that, and it is why the appender refuses")


def test_921_the_judge_appender_writes_through_the_guarded_path(tmp_path):
    from defender.tests.support.shared.contracts._by_path import load_lint_gate

    enqueue = _enqueue()          # RED until M5 exists: a lint that scans nothing is clean
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

    defender_dir = Path(J.__file__).resolve().parents[1]
    assert (defender_dir / "learning" / "judge").is_dir(), (
        "the positive control failed: there is no learning/judge/ package on disk for the gate "
        "to scan, so a clean result below says nothing about the shipped appender")
    # Rooted AT the package, not at `defender/` and filtered: a finding is decided per file, and
    # the wider root only walked the rest of the tree (and its `.venv`) to throw it away.
    real = {f.fingerprint for f in gate._scan(defender_dir / "learning" / "judge")}
    assert not real, f"the judge's own appender trips the write lint: {sorted(real)}"


def test_921_rows_are_appended_under_the_queue_lock_one_row_per_finding(tmp_path):
    enqueue = _enqueue()
    ep, record = _graded(tmp_path)
    before = len(J.enqueued_rows(record))
    big = "x" * 200_000

    errors: list[BaseException] = []

    def append(tag: str) -> None:
        try:
            enqueue.append_rows(ep, [
                _family_row(f"ep-1/{tag}/{n}", finding=f"{tag}-{n}-{big}") for n in range(20)], state=env_state())
        except BaseException as exc:  # noqa: BLE001 — recorded and re-raised by the assertion
            errors.append(exc)

    threads = [threading.Thread(target=append, args=(tag,)) for tag in ("p", "q")]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"an appender raised: {errors}"
    rows = J.enqueued_rows(record)
    assert len(rows) == before + 40, (
        f"{len(rows) - before} rows landed of 40; a torn line is dropped silently by "
        "`read_jsonl_rows`, which is what makes interleaving invisible without this test")
    assert len({r["finding_id"] for r in rows}) == len(rows)


def test_921_a_torn_trailing_row_in_the_findings_queue_is_skipped_and_counted(tmp_path):
    from defender._io import read_jsonl_rows_report

    paths = D.make_paths(tmp_path)
    channel = D.channel_of("findings")
    D.seed(paths, channel, [_family_row("ep-0/b/0/0")])
    queue = paths.state_root / channel.queue
    with queue.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(_family_row("ep-1/b/9/9"))[:120])   # NO newline: the tail is TORN

    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.staged_row("b")], "c": []},
                            dispositions={"a": "benign", "b": "malicious", "c": "malicious"})
    (ep / "worlds" / "b" / "report.md").write_text(J.report_text("benign"), encoding="utf-8")
    J.grade_at(
        ep, judge=J.FakeJudge(default=J.as_reply_text(J.reply_doc())),
        draws=1, state=LearningState.open(paths))

    record = J.judge_record(ep)
    assert Path(record["enqueued_to"]) == queue, (
        "the pass wrote somewhere other than the queue it was pointed at, so nothing below is "
        "about the torn tail")
    assert record["queue_malformed_rows"] == 1, (
        "the torn trailing line was dropped without a count; a silent skip and a counted skip "
        "are the same drain and different evidence, and the count is the only thing that says "
        "a writer left a row half-written")

    rows, unreadable = read_jsonl_rows_report(queue)
    assert unreadable == 1, (
        f"{unreadable} unreadable line(s) on the queue: the torn tail cost more than itself — "
        "an appended row was concatenated onto the fragment and lost with it")
    ids = [r["finding_id"] for r in rows]
    assert "ep-0/b/0/0" in ids, (
        "the family row that was already queued went with the torn tail")
    family_ids = [r["finding_id"] for r in rows
                  if r.get("direction") == "family" and r["finding_id"] != "ep-0/b/0/0"]
    assert len(family_ids) == record["enqueued_rows"], (
        f"the record claims {record['enqueued_rows']} enqueued rows and {len(family_ids)} are "
        "readable; a row of this pass's own was swallowed by the fragment")

    # The stall F-11 exists to prevent, on the real channel: the tick runs to completion and
    # drains the queue rather than stuck-recording the whole batch behind one torn line.
    agent = D.recording(D.committing("torn-tail"))
    assert J.mod("learning.author.drain").run_batch(
        cfg=D.cfg_for(paths, "findings", invoke_agent=agent)) == 0
    assert D.stuck_records(paths, channel) == [], (
        "a torn trailing row stuck-recorded the batch; P6's blast radius is every direction "
        "riding in that tick, which is the whole reason the reader must skip it")
    authored = {r["finding_id"] for call in agent.calls for r in call["rows"]}
    assert "ep-0/b/0/0" in authored, (
        "the row already queued stopped draining because of a torn line written after it")


def test_921_self_contradicting_episode_is_discard_and_the_record_is_the_artifact(tmp_path):
    from defender.episodes._episode_handle import Episode
    from defender.learning.branch.outcome import write_outcome

    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.staged_row("b")], "c": []})
    (ep / "outcome.yaml").unlink()
    with Episode.open(ep) as handle:
        write_outcome(handle, "accepted", reason="", drift=[{
            "system": "elastic", "verb": "esql",
            "params": {"query": f"FROM {J.EVENTS_PATTERN} | LIMIT 5"},
            "reason": "DRIFT-MARKER-921"}])

    judge = J.scripted_judge(family_default=J.as_reply_text(J.family_reply(
        findings=[J.finding_doc(subject="world", bucket="incoherent")])))
    J.grade_at(ep, judge=judge, draws=1, state=env_state())

    assert any("DRIFT-MARKER-921" in p for p in judge.prompts), (
        "pre-flight's recorded drift never reached the judge")
    record = J.judge_record(ep)
    family_lanes = [e["lane"] for e in record["dispositions"]
                    if "/family/" in e["finding_id"]]
    assert family_lanes == ["world"], f"the family's world finding took {family_lanes}"
    assert J.enqueued_rows(record), (
        "the family call's world finding closed the worlds' defender lane (I2: it never may)")
    assert J.world_rows(record)["b"]["bucket"], "the family record lost its per-world grading"


def test_921_world_contradicted_by_the_corpus_is_corpus_contradiction(tmp_path):
    gap = {"what": "elastic esql", "how": "the served system does not hold the field",
           "evidence": ["worlds/b/report.md"], "kept_facts_from_investigator": True}
    kept = J.as_reply_text(J.reply_doc(gaps=[gap]))
    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.staged_row("b")], "c": []},
                            labels=("a", "b"))
    J.grade_at(ep, judge=J.FakeJudge(default=kept, family_default=J.as_reply_text(
        J.family_reply())), draws=2, state=env_state())

    record = J.judge_record(ep)
    row = J.world_rows(record)["b"]
    assert row["measured"] is False
    assert "kept the facts" in row["not_measured_reason"]
    lanes = {e["finding_id"].rsplit("/", 1)[1]: e["lane"] for e in record["dispositions"]
             if "/b/0/" in e["finding_id"]}
    assert lanes == {"0": "not_measured", "1": "user_record"}, lanes
    assert J.enqueued_rows(record) == [], "a world the gap kept facts from was authored"

    ok = J.accepted_episode(tmp_path / "ok", ledgers={"b": [J.staged_row("b")], "c": []},
                            dispositions={"a": "benign", "b": "malicious", "c": "malicious"})
    J.grade_at(
        ok, judge=J.FakeJudge(default=J.as_reply_text(J.reply_doc())),
        draws=2, state=env_state())
    assert J.enqueued_rows(J.judge_record(ok)), "the positive control enqueued nothing"


def test_921_discard_needs_a_majority_of_draws(tmp_path):
    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.staged_row("b")], "c": []},
                            labels=("a", "b"))
    incoherent = J.as_reply_text(J.reply_doc(findings=[
        J.finding_doc(), J.finding_doc(subject="world", bucket="incoherent")]))
    plain = J.as_reply_text(J.reply_doc())
    minority = J.FakeJudge(replies=[incoherent, plain, plain], default=plain,
                           family_default=J.as_reply_text(J.family_reply()))
    J.grade_at(ep, judge=minority, draws=3, state=env_state())

    record = J.judge_record(ep)
    row = J.world_rows(record)["b"]
    assert row["draws_disagree"] is True, row
    assert row["measured"] is None, row
    assert J.enqueued_rows(record) == [], "a world whose draws disagree queued defender rows"
    assert {e["lane"] for e in record["dispositions"]
            if e["finding_id"].rsplit("/", 1)[1] == "0"} == {"draws_disagree"}

    unanimous = J.accepted_episode(tmp_path / "unanimous",
                                   ledgers={"b": [J.staged_row("b")], "c": []},
                                   labels=("a", "b"))
    J.grade_at(unanimous, judge=J.FakeJudge(default=incoherent, family_default=J.as_reply_text(
        J.family_reply())), draws=3, state=env_state())
    row = J.world_rows(J.judge_record(unanimous))["b"]
    assert row["draws_disagree"] is False, row
    assert row["measured"] is False, (
        "positive control: three draws agreeing on `incoherent` did not take the world out of "
        "measurement")
