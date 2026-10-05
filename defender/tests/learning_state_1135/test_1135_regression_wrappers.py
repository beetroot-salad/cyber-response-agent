"""#1135 — O3's two re-homed regression pointers (deviation D-1). Each wrapper re-drives the
scenario of an existing test outside this directory over a BUILT state root (R15: the root must
exist, so the fixture creates it) and reads the outcome through the handle as well as by today's
record names (R14). The wrapped originals are not imported or called, and stay unchanged:

  * `e2e/test_922_spine.py::test_922_graded_episode_reaches_the_corpus_through_the_family_partition`
  * `test_drain719_locks.py::test_the_drains_append_lock_wait_ends_at_the_configured_repo_lock_deadline`

The spine's seams (`TriggerRecorder`, `drive_author_drain` over its `RepoBranch`) are imported from
its module, as `test_1007_corpus.py` does, so a fixture edit there reaches this wrapper too. Shared
machinery and the names this suite coins are in `_spec1135.py`.
"""
from __future__ import annotations

import logging
from pathlib import Path

import pytest

from defender.learning import judge as judge_mod
from defender.tests import _drain719 as D
from defender.tests import _judge_921 as J
from defender.tests.e2e.test_922_spine import TriggerRecorder, drive_author_drain
from defender.tests.learning_state_1135 import _spec1135 as S

ENV = "DEFENDER_LEARNING_STATE_DIR"


def _finding_ids(rows: list[dict]) -> list[str]:
    return [r["finding_id"] for r in rows]


@pytest.mark.e2e
def test_1135_the_e2e_spine_replay_reaches_the_corpus_unchanged(tmp_path: Path, monkeypatch):
    """The one end-to-end replay of the queue path stays green with only import and fixture edits:
    judge enqueue -> _pending/findings.jsonl -> author_drain -> corpus commit -> idempotent rotate
    (the wrapped test's docstring states each hop). Driven here over a built state root, the grade
    handed the handle (RF5) in place of queue_dir=."""
    paths = S.built_paths(tmp_path, repo_root=D.make_repo(tmp_path))
    runs_base = tmp_path / "defender-runs"
    monkeypatch.setenv(J.RUNS_BASE_ENV, str(runs_base))
    monkeypatch.setenv(J.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    monkeypatch.setenv(ENV, str(paths.state_root))
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "1")
    channel = paths.findings

    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.staged_row("b")], "c": []},
                            dispositions={"a": "benign", "b": "malicious", "c": "malicious"})
    (ep / "worlds" / "b" / "report.md").write_text(J.report_text("benign"), encoding="utf-8")
    state = S.LearningState.open(paths)
    graded = S.caught(lambda: judge_mod.grade_episode(
        ep, judge=J.FakeJudge(default=J.as_reply_text(J.reply_doc())), runs_base=runs_base,
        draws=1, state=state))
    assert graded is None, f"grade_episode did not grade on the handle it was handed (RF5): {graded!r}"
    record = J.judge_record(ep)

    # hop 1: the judge's record says how many rows it enqueued, and the queue carries them
    assert record.get("episode_outcome") == "gradable", f"the episode graded {record.get('episode_outcome')!r}"
    queued = _finding_ids(D.pending(channel))
    assert record.get("enqueued_rows") == len(queued) == 2, \
        f"the graded episode did not put its rows on the shared queue: {queued}"
    assert {r["direction"] for r in D.pending(channel)} == {"family"}, \
        "the spine's producer is the family judge; a non-family row means the partition is not driven"
    assert _finding_ids(S.rows_of(state.rows(S.coined("FINDINGS")))) == queued, \
        "the handle does not read the rows the grade enqueued"

    # hop 2: the batch the curator's model call receives is exactly those rows
    head_before = D.git(paths.repo_root, "rev-parse", "HEAD").stdout.strip()
    agent = D.recording(D.committing("family-lesson"))
    rc, _rec = drive_author_drain(paths, TriggerRecorder(agent))
    assert rc == 0, f"author_drain did not complete its batch (rc={rc})"
    assert len(agent.calls) == 1, f"the findings curator ran {len(agent.calls)} times, not once"
    authored = _finding_ids(agent.calls[0]["rows"])
    assert authored == queued, \
        f"the curator was handed {authored}, not the graded episode's rows {queued}"

    # hop 3: git log gains one commit, the corpus one document naming both finding ids
    head_after = D.git(paths.repo_root, "rev-parse", "HEAD").stdout.strip()
    assert head_after != head_before, "the corpus author opened no commit"
    lessons = list(paths.lessons_dir.glob("*.md"))
    assert len(lessons) == 1, f"the corpus gained {len(lessons)} documents, not one"
    body = lessons[0].read_text(encoding="utf-8")
    assert all(fid in body for fid in queued), f"the committed lesson does not attribute {queued}"
    assert set(_finding_ids(D.pending(channel))) == set(queued), \
        "the committed rows left the queue before the batch's PR (hold_committed=True keeps them)"

    # hop 4: a second tick reads the corpus back and rotates the rows off as consumed_idempotent
    second = D.recording(D.committing("must-not-run-twice"))
    assert drive_author_drain(paths, TriggerRecorder(second))[0] == 0, "the second tick failed"
    assert second.calls == [], "the second tick authored the same findings again"
    consumed = {r["finding_id"]: r for r in D.consumed(channel)}
    assert set(consumed) == set(queued), \
        f"the rows did not rotate off the queue as consumed: {sorted(consumed)}"
    assert all(r.get("consumed_category") == "consumed_idempotent" for r in consumed.values()), \
        f"the rotation's categories are {[r.get('consumed_category') for r in consumed.values()]}"
    assert D.pending(channel) == [], "the authored rows are still queued"
    assert D.git(paths.repo_root, "rev-parse", "HEAD").stdout.strip() == head_after, \
        "the second tick opened a second commit for findings already in the corpus"


def test_1135_the_drains_append_lock_wait_ends_at_the_configured_deadline(tmp_path: Path, caplog):
    """RF7's third expiry behaviour, kept: _tick's read window waits up to the configured deadline,
    then skips the tick (0, "skipping"), never raising TimeoutError. The composite verb that
    replaces acquire_flock_within keeps it (X4, executed at the base). The same contention is
    driven at two configured deadlines over a built state root, and each give-up tracks its own."""
    paths = S.built_paths(tmp_path, repo_root=D.make_repo(tmp_path))
    channel = D.channel_of(paths, "findings")
    rows = [D.row_for("findings", "a/0")]
    D.write_source_refs(paths, "a")
    # The append lock by today's record name (R14); the handle exposes no append-lock role.
    append_lock = channel.file.parent / D.APPEND_LOCK_NAMES_TODAY["findings"]
    caplog.set_level(logging.INFO)
    observed: dict[int, float] = {}

    for deadline in (1, 4):
        D.seed(channel, rows)
        agent = D.recording(D.committing("never"))
        cfg = D.cfg_for(paths, "findings", invoke_agent=agent, repo_lock_wait_seconds=deadline)
        caplog.clear()
        answer: dict[str, object] = {}

        def tick(cfg=cfg, answer=answer) -> None:
            answer["rc"], answer["seconds"] = D.elapsed(lambda: D.drain.run_batch(cfg=cfg))

        with S.held_flock(append_lock):
            escaped = S.caught(tick)
        assert escaped is None, f"the read window's expiry raised {escaped!r} at the {deadline}s deadline"
        assert answer["rc"] == 0, f"the skipped tick answered rc={answer['rc']}, not 0"
        assert any("skipping" in r.getMessage() for r in caplog.records), \
            f"the {deadline}s expiry did not log the skipped tick"
        assert agent.calls == [], "the curator ran although the read window never opened"
        assert D.pending(channel) == rows, "the skipped tick changed the queue"
        observed[deadline] = answer["seconds"]  # type: ignore[assignment]

    assert 0.8 <= observed[1] < 3.0, f"the 1s deadline was not what ended the wait: {observed}"
    assert 3.2 <= observed[4] < 8.0, f"the 4s deadline was not what ended the wait: {observed}"
    held = S.rows_of(S.LearningState.open(paths).rows(S.coined("FINDINGS")))
    assert held == rows, f"the handle reads {held}, not the queue the skipped ticks left intact"
