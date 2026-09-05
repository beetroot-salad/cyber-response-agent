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


@pytest.fixture(autouse=True)
def _tmp_roots(tmp_path, monkeypatch):
    monkeypatch.setenv(J.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(J.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    # The learning STATE root too, so the shared findings queue this pass appends to is
    # this test's own and not the checkout's real `learning/_pending/`. Isolation belongs
    # here rather than in the appender: a production path that picks a different queue when
    # an env var is unset is a pass whose rows can land where no drain reads.
    monkeypatch.setenv(J.STATE_DIR_ENV, str(tmp_path / "learning-state"))


def _enqueue():
    return J.mod("learning.judge.enqueue")


def _family_row(fid: str = "ep-1/b/0/0", **over) -> dict:
    """One `FindingRow` in the `direction: family` shape M5 appends."""
    row = dict(D.finding_row(fid, run_id="ep-1", direction="family"),
               type="decision-discipline", judge_outcome="survived",
               subject_anchor="l-001", subject_topic="holding-system coverage",
               source_run_dir="episodes/ep-1/worlds/b")
    row.update(over)
    return row


def _graded(tmp_path, **kw):
    """An accepted episode, graded end to end, as `(episode_dir, family record)`."""
    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.staged_row("b")], "c": []},
                            dispositions={"a": "benign", "b": "malicious", "c": "malicious"},
                            **kw)
    (ep / "worlds" / "b" / "report.md").write_text(J.report_text("benign"), encoding="utf-8")
    J.mod("learning.judge").grade_episode(
        ep, judge=J.FakeJudge(default=J.as_reply_text(J.reply_doc())),
        runs_base=tmp_path / "defender-runs", draws=1)
    return ep, J.judge_record(ep)


# ---------------------------------------------------------------------------------------
# O2 / D6 — the family partition inside the channel's one gate
# ---------------------------------------------------------------------------------------


def test_921_family_row_is_not_held_as_no_ground_truth(tmp_path):
    """A `direction: family` row with NO `source_refs.yaml` behind it is ADMITTED by
    `_gate_family` on the ground truth the family record carries (`disposition_declared`), where
    `_gate_findings` would hold it `no_ground_truth` forever.

    The HELD-FOREVER state is the observable driven here, not a mocked gate: the row is seeded
    into the real findings channel and the real drain tick is run, so the assertion is about
    where the row ends up rather than about which function was called.
    """
    paths = D.make_paths(tmp_path)
    channel = D.channel_of(paths, "findings")
    D.seed(channel, [_family_row()])
    cfg = D.cfg_for(paths, "findings", invoke_agent=D.committing("family-lesson"))

    assert J.mod("learning.author.drain").run_batch(cfg=cfg) == 0
    assert D.pending(channel) == [], (
        "the family row is still queued; without a gate of its own it is held forever as "
        "no_ground_truth")
    assert [r["finding_id"] for r in D.consumed(channel)] == ["ep-1/b/0/0"]


def test_921_mixed_batch_routes_family_rows_and_leaves_the_rest_to_gate_findings(tmp_path):
    """One tick's batch carrying family rows AND adversarial/benign rows routes each population
    by its OWN rule and neither disturbs the other: the family rows take the family partition,
    the rest take `_gate_findings` unchanged.

    A mixed batch is the designed shape, not an edge case — the channel gate is called once per
    tick over every keyed row of the file — and it is the shape the whole tick fails on if the
    partition is written as a second gate downstream of the first.
    """
    paths = D.make_paths(tmp_path)
    channel = D.channel_of(paths, "findings")
    D.write_source_refs(paths, "run-adv", disposition="benign")
    D.seed(channel, [
        D.finding_row("run-adv/0", run_id="run-adv", direction="adversarial"),
        _family_row("ep-1/b/0/0"),
        D.finding_row("run-held/0", run_id="run-held", direction="adversarial"),
    ])
    agent = D.recording(D.committing("mixed"))
    cfg = D.cfg_for(paths, "findings", invoke_agent=agent)

    assert J.mod("learning.author.drain").run_batch(cfg=cfg) == 0
    authored = {r["finding_id"] for r in agent.calls[0]["rows"]}
    assert authored == {"run-adv/0", "ep-1/b/0/0"}, (
        f"the two populations did not route independently: {sorted(authored)}")
    still_held = {r["finding_id"] for r in D.pending(channel)}
    assert still_held == {"run-held/0"}, (
        "the adversarial row with no ground truth stopped being held, or the family row was "
        "held with it")


def test_921_gate_family_authors_a_survived_row(tmp_path):
    """A family row whose `judge_outcome` is `survived` is admitted for authoring."""
    paths = D.make_paths(tmp_path)
    channel = D.channel_of(paths, "findings")
    D.seed(channel, [_family_row(judge_outcome="survived")])
    agent = D.recording(D.committing("survived"))

    assert J.mod("learning.author.drain").run_batch(
        cfg=D.cfg_for(paths, "findings", invoke_agent=agent)) == 0
    assert agent.calls, "the `survived` row authored nothing; it was held, not admitted"
    assert [r["finding_id"] for r in agent.calls[0]["rows"]] == ["ep-1/b/0/0"]


def test_921_gate_family_skips_caught_and_undecidable(tmp_path):
    """`caught` and `undecidable` rows are SKIPPED, not held.

    A skip is terminal and a hold is forever, and the two are different rows in the drain's own
    report — a row held on a word that will never change is a queue entry no operator can ever
    clear. Positive control in the same tick: a `survived` row beside them IS authored, so the
    skip cannot pass on a gate that admits nothing.
    """
    paths = D.make_paths(tmp_path)
    channel = D.channel_of(paths, "findings")
    D.seed(channel, [
        _family_row("ep-1/b/0/0", judge_outcome="caught"),
        _family_row("ep-1/c/0/0", judge_outcome="undecidable"),
        _family_row("ep-1/b/0/1", judge_outcome="survived"),
    ])
    agent = D.recording(D.committing("skip-vs-author"))

    assert J.mod("learning.author.drain").run_batch(
        cfg=D.cfg_for(paths, "findings", invoke_agent=agent)) == 0
    assert agent.calls, "the positive control failed: the `survived` row authored nothing"
    assert [r["finding_id"] for r in agent.calls[0]["rows"]] == ["ep-1/b/0/1"]
    assert D.pending(channel) == [], "a skipped row was HELD instead; a hold is forever"
    assert {r["finding_id"] for r in D.consumed(channel)} == {
        "ep-1/b/0/0", "ep-1/c/0/0", "ep-1/b/0/1"}


def test_921_gate_family_is_idempotent_over_a_replayed_batch(tmp_path):
    """A row whose `finding_id` already appears in an authored lesson's provenance is consumed
    idempotently and authors NO second lesson.

    The guard keys on `finding_id` EXACTLY — not `run_id`, not row content (P5, executed against
    both idempotency guards). Positive control: a row with a NEW id in the same replayed batch
    still authors, so idempotency cannot pass on a gate that has stopped authoring at all.
    """
    paths = D.make_paths(tmp_path)
    channel = D.channel_of(paths, "findings")
    drain = J.mod("learning.author.drain")

    D.seed(channel, [_family_row("ep-1/b/0/0")])
    first = D.recording(D.committing("once"))
    assert drain.run_batch(cfg=D.cfg_for(paths, "findings", invoke_agent=first)) == 0

    D.seed(channel, [_family_row("ep-1/b/0/0"), _family_row("ep-1/b/0/1")])
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
    enqueue = _enqueue()
    ep, record = _graded(tmp_path)

    first = J.enqueued_rows(record)
    ids = [row["finding_id"] for row in first]
    assert len(ids) == len(set(ids)), f"colliding finding ids inside one pass: {ids}"

    retried = enqueue.enqueue(ep, J.mod("learning.judge.family").grade_family(ep))
    again = [row["finding_id"] for row in J.enqueued_rows(record)][len(ids):]
    assert retried == len(ids)
    assert again == ids, (
        "a retried enqueue minted new ids; the guard keys on the id alone, so a fresh id per "
        "retry defeats it entirely")

    two = J.as_reply_text(J.reply_doc(findings=[
        J.finding_doc(topic="first"), J.finding_doc(topic="second", anchor="l-002")]))
    ep2 = J.accepted_episode(tmp_path / "two", ledgers={"b": [J.staged_row("b")], "c": []},
                             dispositions={"a": "benign", "b": "malicious", "c": "malicious"})
    (ep2 / "worlds" / "b" / "report.md").write_text(J.report_text("benign"), encoding="utf-8")
    # Its OWN queue: the appender writes to the one configured findings queue, and this second
    # fixture episode reuses the first one's episode id by construction, so sharing a sink here
    # would count the first episode's rows as this one's rather than test the id minting.
    J.mod("learning.judge").grade_episode(
        ep2, judge=J.FakeJudge(default=two), runs_base=tmp_path / "two" / "defender-runs",
        draws=2, queue_dir=tmp_path / "two" / "queue")
    fresh = [row["finding_id"] for row in J.enqueued_rows(J.judge_record(ep2))]
    assert len(fresh) == len(set(fresh)) == 8, (
        f"two worlds x two draws x two findings did not mint eight distinct ids: {fresh}")


def test_921_enqueue_refuses_discard_and_corpus_contradiction(tmp_path):
    """An episode whose `episode_outcome` is `discard` or `corpus-contradiction` appends NOTHING
    to `findings.jsonl` — the refusal is M5's, AT THE APPENDER, not the gate's. The family
    record is the whole artifact.

    At the appender because a `discard` row that reaches the queue is already a row an operator
    has to clear: D6 routes on `judge_outcome`, and neither of these two words is a defender
    failure to author from. Both words are driven, because they are two members of the
    vocabulary and a refusal written against one is silent about the other.
    """
    for word in ("discard", "corpus-contradiction"):
        ep = J.accepted_episode(tmp_path / word, ledgers={"b": [J.staged_row("b")], "c": []})
        # `accepted_episode` drives `report.md`'s disposition and the manifest's
        # `disposition_declared` off the same value by default, so a doctored world (the
        # `staged_row` on H) buckets `None` on agreement — write the mismatch this assertion
        # needs explicitly, the standard idiom other bucket tests already use.
        (ep / "worlds" / "b" / "report.md").write_text(J.report_text("benign"), encoding="utf-8")
        J.mod("learning.judge").grade_episode(
            ep, judge=J.FakeJudge(default=J.as_reply_text(J.reply_doc(episode_outcome=word))),
            runs_base=tmp_path / word / "defender-runs", draws=1)
        record = J.judge_record(ep)
        assert record["episode_outcome"] == word
        assert record["enqueued_rows"] == 0
        assert J.enqueued_rows(record) == [], f"a {word} episode appended rows"
        assert J.world_rows(record)["b"]["bucket"], (
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
    J.mod("learning.judge").grade_episode(
        ep, judge=J.FakeJudge(default=two_findings), runs_base=tmp_path / "defender-runs",
        draws=2)

    record = J.judge_record(ep)
    rows = J.enqueued_rows(record)
    assert record["episode_outcome"] == "gradable"
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
            enqueue.append_rows(ep, [broken])
        assert missing in str(raised.value)
    assert len(J.enqueued_rows(record)) == before, "a refused row was appended anyway"

    # The blast radius the refusal exists to prevent, on the real channel.
    paths = D.make_paths(tmp_path / "blast")
    channel = D.channel_of(paths, "findings")
    D.write_source_refs(paths, "run-adv", disposition="benign")
    unkeyable = _family_row("ep-1/b/0/9")
    unkeyable.pop("run_id")
    D.seed(channel, [D.finding_row("run-adv/0", run_id="run-adv"), unkeyable])
    with pytest.raises(KeyError):
        J.mod("learning.author.drain").run_batch(
            cfg=D.cfg_for(paths, "findings", invoke_agent=D.committing("blast")))
    stuck = D.stuck_records(channel)
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
    real = {f.fingerprint for f in gate._scan(defender_dir)
            if f.fingerprint.startswith("learning/judge/")}
    assert not real, f"the judge's own appender trips the write lint: {sorted(real)}"


# ---------------------------------------------------------------------------------------
# O6 / M5 — the twelve-key row
# ---------------------------------------------------------------------------------------


def test_921_finding_row_carries_the_twelve_keys_persist_writes(tmp_path):
    """One row per finding carrying the TWELVE keys `persist.py:315-330` writes:
    `schema_version, finding_id, run_id, alert_rule_key, direction="family", type=<bucket>,
    subject_anchor, subject_topic, finding, judge_outcome=<verdict_word>, citations=<evidence>,
    source_run_dir=<archived world dir>`.

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
        assert set(row) == set(J.ROW_KEYS), (
            f"row keys differ from the queue's shape: {sorted(set(row) ^ set(J.ROW_KEYS))}")
        assert row["direction"] == "family"
        assert row["judge_outcome"] == record["verdict_word"]
        assert row["type"] in J.mod("learning.core.config").ALL_FINDING_TYPES | {
            "decision-discipline"}
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

    There is no production consumer of `QUEUEABLE_FINDING_TYPES` at base — the only membership
    test on a finding `type` anywhere is over `ALL_FINDING_TYPES` inside
    `core/validate.py::_validate_finding`, which validates the OLD pipeline judge's YAML
    document and never sees a queue row — so the enforcement O6 names does not exist yet and is
    M5's to build.
    """
    config = J.mod("learning.core.config")
    enqueue = _enqueue()
    ep, record = _graded(tmp_path)

    assert "decision-discipline" in config.QUEUEABLE_FINDING_TYPES
    before = len(J.enqueued_rows(record))
    with pytest.raises(J.refusals()) as raised:
        enqueue.append_rows(ep, [_family_row(type="root-cause-vibes")])
    assert "root-cause-vibes" in str(raised.value)
    assert len(J.enqueued_rows(record)) == before

    # Positive control: the same row with a queueable type lands.
    assert enqueue.append_rows(ep, [_family_row("ep-1/b/0/7", type="decision-discipline")]) == 1


def test_921_row_carries_subject_anchor_and_subject_topic_from_anchor_and_topic(tmp_path):
    """`subject_anchor` and `subject_topic` are filled from the finding's `anchor` (the lead id
    or invlang row id the defect hangs on) and `topic` (one noun phrase); a row without them
    fails the queue's OWN validator.

    Driven through that validator rather than through a re-implementation of it: `validate.py`
    owns what a well-formed finding is, and a second opinion here would go stale the day it
    moves.
    """
    validate = J.mod("learning.core.validate")
    reply = J.as_reply_text(J.reply_doc(findings=[
        J.finding_doc(anchor="h-001.ac1", topic="cadence break at the derivation hand-off")]))
    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.staged_row("b")], "c": []},
                            dispositions={"a": "benign", "b": "malicious", "c": "malicious"})
    (ep / "worlds" / "b" / "report.md").write_text(J.report_text("benign"), encoding="utf-8")
    J.mod("learning.judge").grade_episode(
        ep, judge=J.FakeJudge(default=reply), runs_base=tmp_path / "defender-runs", draws=1)

    row = J.enqueued_rows(J.judge_record(ep))[0]
    assert row["subject_anchor"] == "h-001.ac1"
    assert row["subject_topic"] == "cadence break at the derivation hand-off"
    validate._validate_finding(0, row, set(J.mod("learning.core.config").ALL_FINDING_TYPES) | {
        row["type"]})

    naked = dict(row)
    naked.pop("subject_anchor")
    with pytest.raises(J.refusals()):
        validate._validate_finding(0, naked, {row["type"]})


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
                _family_row(f"ep-1/{tag}/{n}", finding=f"{tag}-{n}-{big}") for n in range(20)])
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
    the queue afterwards, and so is the adversarial row that was already there.
    """
    from defender._io import read_jsonl_rows_report

    paths = D.make_paths(tmp_path)
    channel = D.channel_of(paths, "findings")
    D.write_source_refs(paths, "run-adv", disposition="benign")
    D.seed(channel, [D.finding_row("run-adv/0", run_id="run-adv", direction="adversarial")])
    with channel.file.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(_family_row("ep-1/b/9/9"))[:120])   # NO newline: the tail is TORN

    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.staged_row("b")], "c": []},
                            dispositions={"a": "benign", "b": "malicious", "c": "malicious"})
    (ep / "worlds" / "b" / "report.md").write_text(J.report_text("benign"), encoding="utf-8")
    J.mod("learning.judge").grade_episode(
        ep, judge=J.FakeJudge(default=J.as_reply_text(J.reply_doc())),
        runs_base=tmp_path / "defender-runs", draws=1, queue_dir=channel.file.parent)

    record = J.judge_record(ep)
    assert Path(record["enqueued_to"]) == channel.file, (
        "the pass wrote somewhere other than the queue it was pointed at, so nothing below is "
        "about the torn tail")
    assert record["queue_malformed_rows"] == 1, (
        "the torn trailing line was dropped without a count; a silent skip and a counted skip "
        "are the same drain and different evidence, and the count is the only thing that says "
        "a writer left a row half-written")

    rows, unreadable = read_jsonl_rows_report(channel.file)
    assert unreadable == 1, (
        f"{unreadable} unreadable line(s) on the queue: the torn tail cost more than itself — "
        "an appended row was concatenated onto the fragment and lost with it")
    ids = [r["finding_id"] for r in rows]
    assert "run-adv/0" in ids, (
        "the adversarial row that was already queued went with the torn tail")
    family_ids = [r["finding_id"] for r in rows if r.get("direction") == "family"]
    assert len(family_ids) == record["enqueued_rows"], (
        f"the record claims {record['enqueued_rows']} enqueued rows and {len(family_ids)} are "
        "readable; a row of this pass's own was swallowed by the fragment")

    # The stall F-11 exists to prevent, on the real channel: the tick runs to completion and
    # routes both populations rather than stuck-recording the whole batch behind one torn line.
    agent = D.recording(D.committing("torn-tail"))
    assert J.mod("learning.author.drain").run_batch(
        cfg=D.cfg_for(paths, "findings", invoke_agent=agent)) == 0
    assert D.stuck_records(channel) == [], (
        "a torn trailing row stuck-recorded the batch; P6's blast radius is every direction "
        "riding in that tick, which is the whole reason the reader must skip it")
    authored = {r["finding_id"] for call in agent.calls for r in call["rows"]}
    assert "run-adv/0" in authored, (
        "the direction that already works stopped draining because of a torn line written by "
        "the direction this issue adds")


# ---------------------------------------------------------------------------------------
# O7 — discard and corpus-contradiction
# ---------------------------------------------------------------------------------------


def test_921_self_contradicting_episode_is_discard_and_the_record_is_the_artifact(tmp_path):
    """A self-contradicting episode yields `discard`, no defender finding is authored, and the
    family record is the artifact.

    A finding row authored against a `discard` episode is O7's stated failing mode. Driven
    through the mechanical arm — the discriminator envelope's key among the review's
    control-drift keys — so the word comes from the archive rather than from a draw's say-so.
    """
    import yaml

    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.staged_row("b")], "c": []})
    # See the sibling test above: the doctored world's `verdict` must differ from its
    # `declared` disposition for its bucket to be non-`None`.
    (ep / "worlds" / "b" / "report.md").write_text(J.report_text("benign"), encoding="utf-8")
    # THE DRIFT IS WRITTEN WHERE `review.py` WRITES IT, and keyed the way it keys it. Both
    # halves were wrong here and the production reader agreed with the fixture rather than with
    # the writer, so the mechanical arm this test claims to drive could not fire on a real
    # episode at all: `review._record` files each world's result under `worlds[<label>]` and
    # the drift list is `consistency.control_mismatch_keys` on the CONTROL arm — never
    # `episode.control_drift_keys`, a key nothing in this repo has ever emitted. And the key
    # itself is minted by `ledger.request_key`, the one canonical encoding (it sorts the params;
    # a hand-written `json.dumps` matches a recorded key only by luck of dict order).
    review = yaml.safe_load((ep / "review.yaml").read_text(encoding="utf-8"))
    review["worlds"] = {"a": {"consistency": {"control_mismatch_keys": [
        J.request_key("elastic", "esql", {"query": f"FROM {J.EVENTS_PATTERN} | LIMIT 5"})]}}}
    (ep / "review.yaml").write_text(yaml.safe_dump(review), encoding="utf-8")

    J.mod("learning.judge").grade_episode(
        ep, judge=J.FakeJudge(default=J.as_reply_text(J.reply_doc())),
        runs_base=tmp_path / "defender-runs", draws=1)

    record = J.judge_record(ep)
    assert record["episode_outcome"] == "discard"
    assert J.enqueued_rows(record) == []
    assert J.world_rows(record)["b"]["bucket"], "the family record lost its per-world grading"


def test_921_world_contradicted_by_the_corpus_is_corpus_contradiction(tmp_path):
    """A defender that held an environment fact the served world CONTRADICTS yields
    `corpus-contradiction`, not a defender failure — a defect in the experiment, not in the
    analyst.

    N5 records that the defender has no channel of its own to RAISE one, so the word can only
    arrive through the judge's reply; the majority requirement is what keeps one draw from
    minting it. Positive control: the same episode with a `gradable` majority is graded normally
    and enqueues.
    """
    contradiction = J.as_reply_text(J.reply_doc(
        episode_outcome="corpus-contradiction",
        findings=[J.finding_doc(evidence=["report.md", "investigation.md#l-001"])]))
    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.staged_row("b")], "c": []})
    J.mod("learning.judge").grade_episode(
        ep, judge=J.FakeJudge(default=contradiction), runs_base=tmp_path / "defender-runs",
        draws=2)

    record = J.judge_record(ep)
    assert record["episode_outcome"] == "corpus-contradiction"
    assert record["verdict_word"] == "corpus-contradiction", (
        "`corpus-contradiction` is the family's verdict word when it applies, not a note "
        "beside one")
    assert J.enqueued_rows(record) == [], "a corpus contradiction was authored as a lesson"

    ok = J.accepted_episode(tmp_path / "ok", ledgers={"b": [J.staged_row("b")], "c": []},
                            dispositions={"a": "benign", "b": "malicious", "c": "malicious"})
    (ok / "worlds" / "b" / "report.md").write_text(J.report_text("benign"), encoding="utf-8")
    J.mod("learning.judge").grade_episode(
        ok, judge=J.FakeJudge(default=J.as_reply_text(J.reply_doc())),
        runs_base=tmp_path / "ok" / "defender-runs", draws=2)
    assert J.enqueued_rows(J.judge_record(ok)), "the positive control enqueued nothing"


def test_921_discard_needs_the_control_drift_key_or_a_majority_of_draws(tmp_path):
    """`discard` is MECHANICAL-FIRST: the discriminator envelope's key among the review's
    control-drift keys, OR a majority of a world's draws answering `discard` citing the same
    ledger or review pointer.

    A MINORITY answering `discard` does not meet the bar and the episode stays `gradable`; one
    draw's say-so never suppresses an episode. The majority's denominator is COMPLETED draws
    (J6), and the review pointer is recorded beside the key test so a human can see whether the
    disagreement was injected.
    """
    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.staged_row("b")], "c": []},
                            dispositions={"a": "benign", "b": "malicious", "c": "malicious"})
    (ep / "worlds" / "b" / "report.md").write_text(J.report_text("benign"), encoding="utf-8")
    minority = J.FakeJudge(
        replies=[J.as_reply_text(J.reply_doc(episode_outcome="discard")),
                 J.as_reply_text(J.reply_doc()), J.as_reply_text(J.reply_doc())],
        default=J.as_reply_text(J.reply_doc()))
    J.mod("learning.judge").grade_episode(
        ep, judge=minority, runs_base=tmp_path / "defender-runs", draws=3)

    record = J.judge_record(ep)
    assert record["episode_outcome"] == "gradable", (
        "one draw of three suppressed the whole episode's findings")
    assert J.enqueued_rows(record), "a gradable episode enqueued nothing"
    assert record["discard_evidence"]["review_pointer"], (
        "the review pointer is not recorded beside the key test, so a human cannot see whether "
        "the disagreement was injected")


# ---------------------------------------------------------------------------------------
# N6 and J12 — what this appender does NOT touch
# ---------------------------------------------------------------------------------------


def test_921_new_appender_is_used_and_outcome_enum_and_append_findings_are_unchanged(tmp_path):
    """The judge writes through its OWN appender: `OUTCOME_ENUM` — the vocabulary of
    `learning/pipeline/judge/`, which #922 deletes — gains no member, and
    `persist.append_findings`'s `_outcome_keyword` membership check is unchanged.

    Positive control: a family row still lands in the SAME `findings.jsonl` the old appender
    writes to, so "untouched" cannot pass on a judge that writes somewhere else entirely.
    """
    config = J.mod("learning.core.config")
    validate = J.mod("learning.core.validate")

    assert config.OUTCOME_ENUM == {  # noqa: SIM300 — the vocabulary is the SUBJECT, not a bound
        "caught", "survived", "undecidable", "incoherent", "skip-passthrough"}, (
        "the old pipeline judge's vocabulary gained a member; #922 deletes it and this design "
        "writes through its own appender instead")
    for word in ("discard", "corpus-contradiction"):
        with pytest.raises(J.refusals()):
            validate._outcome_keyword(word)

    ep, record = _graded(tmp_path)
    paths = J.mod("learning.core.config").DEFAULT_PATHS
    assert J.enqueued_rows(record), "the judge enqueued nothing at all"
    assert str(record["enqueued_to"]).endswith("findings.jsonl"), (
        f"the judge wrote to {record['enqueued_to']}, not the shared findings queue")
    assert paths.pending_file.name == "findings.jsonl"


def test_921_a_family_row_is_exempt_from_the_forward_check(tmp_path):
    """J12, settled with the human: a `direction: family` row is EXEMPT from the lessons
    forward check, whose ground truth for it is `disposition_declared` on the family record
    rather than a `source_refs.yaml` it does not have — and the model-facing direction literal
    is NOT widened, because the check is not kept for this direction.

    Three consumers break on a family row as originally specified, and all three are downstream
    of the gate the design stops at: `verify_forward._run_findings` resolves the row's source
    through `runs_dir/<source_id>` and raises `SystemExit`; `forward.expected_disposition` reads
    the `source_refs.yaml` D6 says a family row does not have; `verify_forward/tool.py` types
    the direction as `Literal["adversarial", "benign"]`. A `survived` family row is AUTHORED
    into a lesson — that is D6's whole point — and the authoring path is the one that breaks.

    Positive control: an adversarial row in the same corpus still runs the forward check, so the
    exemption is a route rather than the check's removal.
    """
    checks = J.mod("learning.author.verify_forward.checks")
    paths = D.make_paths(tmp_path)
    D.write_source_refs(paths, "run-adv", disposition="benign")

    assert checks.skips_forward_check(_family_row()) is True
    assert checks.skips_forward_check(
        D.finding_row("run-adv/0", run_id="run-adv")) is False, (
        "the exemption swallowed the adversarial direction's check as well")

    tool_source = (J.mod("run_common").DEFENDER_DIR / "learning" / "author" /
                   "verify_forward" / "tool.py").read_text(encoding="utf-8")
    assert '"family"' not in tool_source, (
        "the model-facing direction literal was widened; J12 keeps the family direction out of "
        "the check rather than teaching the check about it")

    # AND THE EXEMPTION IS A ROUTE, not a runtime type check inside
    # `forward.expected_disposition`. That function is typed `(str, str) -> str` and its one
    # caller feeds it from a reader typed `-> tuple[str, str]`, so a guard inside it would
    # defend against a call no code makes while putting the property in a second place that can
    # disagree with `skips_forward_check` above.
    #
    # DRIVEN THROUGH PRODUCTION'S OWN DERIVATION, `lessons.run.forward_checkable_ids` — the
    # function `invoke_agent` builds `ForwardCheckConfig.queued_ids` from. Re-deriving that
    # comprehension inside the test instead would pin nothing: removing the filter from the
    # production expression would leave the test green, because the test would still be
    # filtering its own copy.
    lessons_run = J.mod("learning.author.lessons.run")
    queued = lessons_run.forward_checkable_ids([
        _family_row(),
        D.finding_row("run-adv/0", run_id="run-adv", direction="adversarial"),
    ])
    assert queued == {"run-adv"}, (
        f"the family row entered the set the model may forward_check: {sorted(queued)}")
