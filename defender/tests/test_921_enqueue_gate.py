"""#921 — the queue row, the appender that writes it, and the family partition inside the gate.

The findings channel has ONE gate over the whole batch (`CorpusAuthorConfig.gate`, wired to
`author/lessons/run.py::_gate_findings`), called once per tick over EVERY keyed row of
`findings.jsonl`. So `_gate_family` is a PARTITION inside that gate, never a second gate, and a
mixed batch is the designed shape rather than an edge case.

P6 IS THE HARDEST CONSTRAINT HERE, and it was executed end to end rather than read: one
family-shaped row with no `run_id` raises a bare `KeyError('run_id')` out of `_gate_findings`,
`_tick` finds `KeyError` outside `RETIRE_SET`, stuck-records THE WHOLE KEYED BATCH — every
well-formed adversarial and benign row riding beside it — and then RE-RAISES, so the tick fails.
Verbatim from a real tick over a real channel:
`{"fault_class": "KeyError", "row_ids": ["f-adversarial-1", "f-benign-1", "f-family-1"], …}`.
One malformed #921 row wedges the two lanes that already work.

TWO §7 RESOLUTIONS ARE APPLIED HERE AS SETTLED:
* **J12** — family rows are EXEMPT from the forward check (their ground truth is
  `disposition_declared` on the family record, not a `source_refs.yaml` they do not have), and
  the WRITER refuses a family row lacking `run_id` / `direction` so a malformed one never
  reaches the shared gate at all.
* **J7's survivor** — the append goes through the guarded writer or carries the documented
  suppression, or it is a new blocking lint finding.

RED against `d1b8b06a`: `learning/judge/enqueue.py` and `_gate_family` do not exist,
`QUEUEABLE_FINDING_TYPES` has no `decision-discipline`, and a `direction: family` row is held
`no_ground_truth` forever.
"""
from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest

from defender.tests import _drain719 as D
from defender.tests import _judge_921 as J
from defender.learning.core.config import LoopPaths
from defender.learning.core.state import LearningState
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


# ---------------------------------------------------------------------------------------
# O2 / D6 — the family partition inside the channel's one gate
# ---------------------------------------------------------------------------------------


def test_921_family_row_is_not_held_as_no_ground_truth(tmp_path):
    """A `direction: family` row with NO `source_refs.yaml` behind it is ADMITTED by
    `_gate_family` on the ground truth the row itself carries (#1234: its contrast evidence and
    its two booleans), where `_gate_findings` would hold it `no_ground_truth` forever.

    The HELD-FOREVER state is the observable driven here, not a mocked gate: the row is seeded
    into the real findings channel and the real drain tick is run, so the assertion is about
    where the row ends up rather than about which function was called.
    """
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
    """One tick's batch carrying family rows AND adversarial/benign rows routes each population
    by its OWN rule and neither disturbs the other: the family rows take the family partition,
    the rest are held as a retired direction (#1166 deleted the per-case route they took).

    A mixed batch is the designed shape, not an edge case — the channel gate is called once per
    tick over every keyed row of the file — and it is the shape the whole tick fails on if the
    partition is written as a second gate downstream of the first.
    """
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
    """A family row in the #1234 shape (the judge queues one only for an investigator finding of
    a measured, unanimous world, A7/A13) is admitted for authoring. (Pre-#1234 this was the
    row whose `judge_outcome` said `survived`; the family word is retired, A4.)"""
    paths = D.make_paths(tmp_path)
    channel = D.channel_of("findings")
    D.seed(paths, channel, [_family_row()])
    agent = D.recording(D.committing("survived"))

    assert J.mod("learning.author.drain").run_batch(
        cfg=D.cfg_for(paths, "findings", invoke_agent=agent)) == 0
    assert agent.calls, "the new-shape row authored nothing; it was held, not admitted"
    assert [r["finding_id"] for r in agent.calls[0]["rows"]] == ["ep-1/b/0/0"]


def test_921_gate_family_skips_caught_and_undecidable(tmp_path):
    """#1234 rewrite (A4, I10): the family words `caught` / `undecidable` / `survived` are
    retired, so the partition no longer skips on a word. A pre-#1234 row carrying
    `judge_outcome` (whatever its word), or a row missing one of the three new fields, is HELD
    naming why — never authored and never consumed as though it meant what the retired design
    meant. Positive control in the same tick: a new-shape row beside them IS authored, so the
    hold cannot pass on a gate that admits nothing.
    """
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
    """A row whose `finding_id` already appears in an authored lesson's provenance is consumed
    idempotently and authors NO second lesson.

    The guard keys on `finding_id` EXACTLY — not `run_id`, not row content (P5, executed against
    both idempotency guards). Positive control: a row with a NEW id in the same replayed batch
    still authors, so idempotency cannot pass on a gate that has stopped authoring at all.
    """
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
    """Because the idempotency guard keys on `finding_id` ALONE (P5), the id must be BOTH
    deterministic across a retried enqueue of the same finding AND distinct across every
    (world, draw, finding index).

    A fresh id per retry defeats the guard and floods the corpus; a reused id across distinct
    findings suppresses real ones. Both halves are driven: re-enqueue the same replies and
    observe the same ids, and enqueue two different findings and observe two.
    """
    ep, record = _graded(tmp_path)

    first = J.enqueued_rows(record)
    ids = [row["finding_id"] for row in first]
    assert ids, "the graded episode enqueued nothing, so there is no id to compare"
    assert len(ids) == len(set(ids)), f"colliding finding ids inside one pass: {ids}"

    # #1234 A8: the bare re-enqueue path (`enqueue.enqueue` over the record) is gone — rows
    # are built only from the replies a pass just drew. The retry is therefore a second pass
    # over the same episode and the same replies (a scratch copy, its own queue), and it must
    # mint the same ids.
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
    # Its OWN queue: the appender writes to the one configured findings queue, and this second
    # fixture episode reuses the first one's episode id by construction, so sharing a sink here
    # would count the first episode's rows as this one's rather than test the id minting.
    own_root = tmp_path / "two" / "queue"
    own_root.mkdir(parents=True)
    own = LearningState.open(LoopPaths(repo_root=tmp_path / "two", state_dir=own_root))
    J.grade_at(
        ep2, judge=J.scripted_judge(default=two), draws=2, state=own)
    fresh = [row["finding_id"] for row in J.enqueued_rows(J.judge_record(ep2))]
    assert len(fresh) == len(set(fresh)) == 8, (
        f"two worlds x two draws x two findings did not mint eight distinct ids: {fresh}")


def test_921_enqueue_refuses_discard_and_corpus_contradiction(tmp_path):
    """#1234 rewrite (A7, A16, A17): the episode words `discard` / `corpus-contradiction` are
    retired; a world that cannot measure the investigator is said by the world's OWN draws
    filing an `unreachable` or `incoherent` world finding. Such a world is not measured, and its
    investigator findings take the `not_measured` lane: NOTHING reaches the defender queue,
    while the world row keeps its bucket — the record is the artifact. Both words are driven,
    because they are two members of the vocabulary and a refusal written against one is silent
    about the other.
    """
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


def test_921_gradable_episode_appends_one_row_per_finding(tmp_path):
    """The paired positive control: a `gradable` episode appends EXACTLY one row per finding per
    world per draw, so the refusal above cannot pass vacuously on a broken appender.

    "Every draw's findings become rows" is the doc's own text — flow 3 says "each finding of each
    world -> one `FindingRow`", unqualified by draw, and N3 says the spread is reported rather
    than averaged away.
    """
    two_findings = J.as_reply_text(J.reply_doc(findings=[
        J.finding_doc(topic="first"), J.finding_doc(topic="second", anchor="l-002")]))
    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.staged_row("b")], "c": []},
                            dispositions={"a": "benign", "b": "malicious", "c": "malicious"})
    (ep / "worlds" / "b" / "report.md").write_text(J.report_text("benign"), encoding="utf-8")
    J.grade_at(
        ep, judge=J.FakeJudge(default=two_findings), draws=2, state=env_state())

    record = J.judge_record(ep)
    rows = J.enqueued_rows(record)
    assert all(row["measured"] for row in record["worlds"]), "a world was not measured"
    assert len(rows) == 2 * 2 * 2, f"two worlds x two draws x two findings gave {len(rows)} rows"
    assert record["enqueued_rows"] == len(rows)


def test_921_enqueue_refuses_a_row_that_would_key_error_the_shared_gate(tmp_path):
    """A row missing `run_id` or `direction` raises a bare `KeyError` inside `_gate_findings`;
    `_tick` stuck-records THE ENTIRE KEYED BATCH — every well-formed adversarial and benign row
    in that tick — and then RE-RAISES (P6, executed).

    So M5 refuses such a row AT THE APPENDER, and the blast radius is one refusal rather than
    one tick of the corpus drain. A `_gate_family` running after `_gate_findings` has already
    indexed the row is too late.

    Both halves are driven: the appender refuses and writes nothing, AND the blast radius it
    prevents is demonstrated on the real channel — the same row seeded past the appender takes
    the whole batch to `stuck.jsonl` and the tick fails.
    """
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
    """`lint_unguarded_tree_write` resolves `append_jsonl` BY CALLEE and `learning/judge/**`
    carries no baseline entry, so M5's stated mechanism is a NEW blocking finding unless it goes
    through `write_guarded(..., mode="append")` or carries the inline suppression.

    The demand is the guarded path and the LINT RUN is its witness: the real gate is driven over
    a synthetic tree holding both spellings of the same append, so the assertion is that the
    gate distinguishes them rather than that a string appears in a file. Then the same gate is
    run over the real `learning/judge/` and required to find nothing new.
    """
    from defender.tests._by_path import load_lint_gate

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


# ---------------------------------------------------------------------------------------
# O6 / M5 — the twelve-key row
# ---------------------------------------------------------------------------------------


def test_921_finding_row_carries_the_twelve_keys_persist_writes(tmp_path):
    """One row per finding carrying the keys `persist.py:315-330` writes:
    `schema_version, finding_id, run_id, alert_rule_key, direction="family", type=<bucket>,
    subject_anchor, subject_topic, finding, citations=<resolving pointers>,
    source_run_dir=<archived world dir>` — #1234 (d00d) drops `judge_outcome` (A4) and adds
    `contrast_evidence`, `on_verdict_path` and `world_label_doubted` (`J.ROW_KEYS`).

    A row missing a key the queue's validator reads is O6's stated failing mode — and P6 makes
    two of those keys load-bearing well past validation, because `run_id` and `direction` are
    plain `dict[...]` lookups inside the shared gate.
    """
    ep, record = _graded(tmp_path)
    rows = J.enqueued_rows(record)
    assert rows, "the graded episode enqueued nothing to check"

    # Exactly the two graded (non-control) worlds' own archived dirs, in the literal
    # `episodes/<id>/worlds/<label>` form F-3's collision docstring pins — not merely a string
    # that ends with "worlds/b" or contains "worlds/" anywhere, which the colliding value F-3
    # names (a label spelled like a real run id) would satisfy just as well.
    expected_dirs = {f"episodes/{ep.name}/worlds/{label}" for label in ("b", "c")}

    for row in rows:
        # `recorded_signature` (#1222 B2) is the one key beyond the thirteen, present exactly when
        # the episode's record holds a signature.
        assert set(row) - {"recorded_signature"} == set(J.ROW_KEYS), (
            f"row keys differ from the queue's shape: {sorted(set(row) ^ set(J.ROW_KEYS))}")
        assert row["direction"] == "family"
        assert "judge_outcome" not in row
        assert isinstance(row["contrast_evidence"], list)
        assert row["contrast_evidence"]
        assert isinstance(row["on_verdict_path"], bool)
        assert isinstance(row["world_label_doubted"], bool)
        assert row["type"] in J.mod("learning.core.config").QUEUEABLE_FINDING_TYPES
        assert row["source_run_dir"] in expected_dirs, (
            f"source_run_dir must be exactly the row's own archived world dir "
            f"({sorted(expected_dirs)}), not merely something shaped like 'worlds/*': "
            f"got {row['source_run_dir']!r}")
    assert {row["source_run_dir"] for row in rows} == expected_dirs, (
        "every graded (non-control) world's archived dir must appear across the enqueued rows "
        f"exactly once each: got {sorted(row['source_run_dir'] for row in rows)}")


def test_921_decision_discipline_is_queueable_and_an_unknown_type_is_refused(tmp_path):
    """`decision-discipline` is a queueable finding type, and a type OUTSIDE the vocabulary is
    refused AT THE APPENDER.

    At base there was no production consumer of `QUEUEABLE_FINDING_TYPES` at all: the only
    membership test on a finding `type` anywhere was inside the OLD pipeline judge's document
    validator, which never saw a queue row. The appender below is the enforcement O6 named, and
    since #922 deleted that validator it is the only one left.
    """
    config = J.mod("learning.core.config")
    enqueue = _enqueue()
    ep, record = _graded(tmp_path)

    assert "decision-discipline" in config.QUEUEABLE_FINDING_TYPES
    before = len(J.enqueued_rows(record))
    with pytest.raises(J.refusals()) as raised:
        enqueue.append_rows(ep, [_family_row(type="root-cause-vibes")], state=env_state())
    assert "root-cause-vibes" in str(raised.value)
    assert len(J.enqueued_rows(record)) == before

    # Positive control: the same row with a queueable type lands.
    assert enqueue.append_rows(ep, [_family_row("ep-1/b/0/7", type="decision-discipline")], state=env_state()) == 1




def test_921_rows_are_appended_under_the_queue_lock_one_row_per_finding(tmp_path):
    """One world's rows are built as ONE list and written by ONE `append_jsonl` call — one
    `open`, one loop, one `queue_lock` hold — not N independent lock/append cycles (P3,
    executed: `append_findings` does exactly this and the shape is what M5 inherits).

    The appender's acquisition is a blocking `flock` with no deadline, and it contends only with
    other APPENDERS: the drain passes its own deadline and raises `TimeoutError` (P2, executed
    against a real second process holding the lock for 3s), so M5 introduces no unbounded wait
    behind the drain. Interleave two appenders and observe no torn line and no lost row.

    The call-shape guarantee is NOT a durability guarantee: the individual `fh.write()` calls
    are not `fsync`'d, so this pins what the writer does, not what survives a power cut.
    """
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
    """F-11, settled at the phase-F seam: the findings-queue reader TOLERATES A TORN TAIL — an
    unparseable final line is SKIPPED AND COUNTED on the family record, never raised on.

    THE TORN TAIL IS OBSERVED, NOT IMAGINED. P3's re-execution (`48-p3-p5-executed.md`, P3(d))
    SIGKILLed a real child process mid-batch-write against the real `append_findings`: most
    trials landed on a clean line boundary, but one at a 0.05s delay left 182532 bytes of a
    partially-written row on disk with no closing newline and nothing else corrupted. The
    "individual `fh.write()` calls are not `fsync`'d" caveat was on record as theoretical; it is
    now an observed, non-deterministic outcome of an ordinary hard kill. The fragment below is
    the same shape written as bytes — a real row's JSON truncated mid-record, no newline.

    WHY IT MATTERS HERE AND NOT ONLY IN GENERAL. P6 (executed) established that a bad row in
    this queue takes the WHOLE keyed batch to `stuck.jsonl` and re-raises out of `_tick`, so one
    torn row can stall the corpus drain for the two directions that already work — and #921 adds
    a SECOND writer to that same sink. The posture is not new: it is the one J3 already chose
    for the ledger reader, skip-and-count with the count on the family record, and it is
    recorded as consistent with J3 rather than as a fresh policy.

    THE ACCEPTED COST IS STATED: a torn line becomes survivable rather than loud, so a writer
    bug that produces one is QUIETER than today. The count is what buys that back — a silent
    skip and a counted skip are the same drain and different evidence — which is why the count
    is asserted here and not just the absence of a raise.

    The loss is bounded to the torn line: every row this pass says it enqueued is readable on
    the queue afterwards, and so is the family row that was already there.
    """
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


# ---------------------------------------------------------------------------------------
# O7 — what keeps an episode's findings off the defender queue (#1234: the world's own draws)
# ---------------------------------------------------------------------------------------


def test_921_self_contradicting_episode_is_discard_and_the_record_is_the_artifact(tmp_path):
    """#1234 rewrite (A17, I2/P-c): the family word `discard` is retired, and the family call
    can never close any world's defender lane. What survives of the pre-#1224 arm: pre-flight's
    recorded drift reaches the model as host text. What the family call files instead is a
    family-scope world finding (`incoherent` here), which goes to the questioner — and the
    worlds' own measured, unanimous draws still queue their defender rows, with the per-world
    grading on the record.
    """
    from defender._episode_handle import Episode
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
    """#1234 rewrite (A16, F-14): the episode word `corpus-contradiction` is retired. A defect in
    the experiment rather than in the analyst is now said by the world's own draws — here a
    deployment gap flagged `kept_facts_from_investigator` in every draw: the world is not
    measured, the reason names the gap, the gap goes to the user record, and no defender row is
    authored from the world. Positive control: the same episode with an unflagged reply is
    graded normally and enqueues.
    """
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
    """#1234 rewrite (A7): the majority rule is replaced by UNANIMITY over a world's completed
    draws. One draw of three filing an `incoherent` world finding makes the draws disagree: the
    world is withheld (`draws_disagree`), neither measured nor not-measured, and none of its
    investigator findings reaches the defender queue (lane `draws_disagree`). Positive control:
    all three draws filing it make the world not measured (lane `not_measured`).
    """
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


# ---------------------------------------------------------------------------------------
# N6 and J12 — what this appender does NOT touch
# ---------------------------------------------------------------------------------------


def test_the_row_rule_screens_key_presence_not_the_value():
    """`finding_id`/`run_id`/`direction` are screened for KEY PRESENCE: an explicit `None`
    passes that screen (and is refused, if at all, by a later rule), a missing key does not."""
    JudgeRefused = J.sym("learning.judge", "JudgeRefused")
    row = _family_row()
    del row["run_id"]
    with pytest.raises(JudgeRefused, match="missing 'run_id'"):
        _enqueue()._validate_row(row)
    assert _enqueue()._validate_row(_family_row(run_id=None)) is None
