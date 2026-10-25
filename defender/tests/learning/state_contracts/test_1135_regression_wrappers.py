from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path

from defender.tests.support.learning.branch import _triplet_947 as T

import logging
from pathlib import Path

import pytest

from defender.learning.core.state import FINDINGS
from defender.tests.support.learning.curation import _drain719 as D
from defender.tests.support.learning.judge import _judge_921 as J
from defender.tests.learning.state_contracts import _spec1135 as S
from defender.tests.tenancy.tenant_1108_delivery._support import merge_on_remote
from defender.tests.tenancy.tenant_1108_p4._drain_support import (
    LESSONS_PREFIX, BoxSpy, CuratorTrigger, author_drain, drain_paths, product_repo,
    remote_branches, touched)
from defender.tests.tenancy.tenant_1108_p4._support import bind_forge, git, published_tenant

ENV = "DEFENDER_LEARNING_STATE_DIR"


def _finding_ids(rows: list[dict]) -> list[str]:
    return [r["finding_id"] for r in rows]


@pytest.mark.e2e
def test_1135_the_e2e_spine_replay_reaches_the_corpus_unchanged(tmp_path: Path, data_root: Path,
                                                               monkeypatch):
    """The spine over the tenant path (#1108 P4 flow 4): the graded rows reach the curator on
    the handle the drain opens over the tenant's learning root, the lesson lands as one commit
    on a `lessons/` branch of the tenant repo, and after its merge a second tick retires them."""
    with published_tenant(tmp_path / "forge", root=data_root) as t:
        bind_forge(t)
        paths = drain_paths(t, product_repo(tmp_path))
        location_path(paths.state_root).mkdir(parents=True, exist_ok=True)
        _spine(t, tmp_path, paths, monkeypatch)


def _spine(t, tmp_path: Path, paths, monkeypatch) -> None:
    runs_base = tmp_path / "defender-runs"
    monkeypatch.setenv(J.RUNS_BASE_ENV, str(runs_base))
    monkeypatch.setenv(J.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    monkeypatch.setenv(ENV, str(location_path(paths.state_root)))
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "1")
    channel = FINDINGS

    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.oracle_row("b")], "c": []},
                            dispositions={"a": "benign", "b": "malicious", "c": "malicious"})
    (ep / "worlds" / T.world_id(ep, "b") / "report.md").write_text(J.report_text("benign"), encoding="utf-8")
    state = S.LearningState.open(paths)
    graded = S.caught(lambda: J.grade_at(
        ep, judge=J.FakeJudge(  # the family-scope call files family findings only (#1234 A17)
            default=J.as_reply_text(J.reply_doc()),
            family_default=J.as_reply_text(J.family_reply())),
        draws=1, state=state))
    assert graded is None, f"grade_episode did not grade on the handle it was handed (RF5): {graded!r}"
    record = J.judge_record(ep)

    # hop 1: the judge's record says how many rows it enqueued, and the queue carries them
    # (#1234: the episode word is retired, A17 — every graded world is measured and committed)
    assert all(row.get("measured") and row.get("state") == "queued"
               for row in record.get("worlds", [])), f"the episode graded {record.get('worlds')!r}"
    queued = _finding_ids(D.pending(paths, channel))
    assert record.get("enqueued_rows") == len(queued) == 2, \
        f"the graded episode did not put its rows on the shared queue: {queued}"
    assert {r["direction"] for r in D.pending(paths, channel)} == {"family"}, \
        "the spine's producer is the family judge; a non-family row means the partition is not driven"
    assert _finding_ids(S.rows_of(state.rows(S.coined("FINDINGS")))) == queued, \
        "the handle does not read the rows the grade enqueued"

    # hop 2: the batch the curator's model call receives is exactly those rows
    main = t.origin_main()
    product_head = D.git(paths.repo_root, "rev-parse", "HEAD").stdout.strip()
    agent = D.recording(D.committing("family-lesson"))
    rc = author_drain(t, paths, trigger=CuratorTrigger(author=agent), box=BoxSpy())
    assert rc == 0, f"author_drain did not complete its batch (rc={rc})"
    assert len(agent.calls) == 1, f"the findings curator ran {len(agent.calls)} times, not once"
    authored = _finding_ids(agent.calls[0]["rows"])
    assert authored == queued, \
        f"the curator was handed {authored}, not the graded episode's rows {queued}"

    # hop 3: the tenant repo gains one lessons/ branch whose commits add one document naming
    # both finding ids; the product checkout is untouched
    (branch, tip), = remote_branches(t.remote, LESSONS_PREFIX).items()
    landed = touched(t.remote, main, tip)
    assert len(landed) == 1, f"the batch landed {landed}, not one lesson"
    assert landed[0].startswith("agent/lessons/family-lesson-"), landed
    body = git(t.remote, "show", f"{tip}:{landed[0]}")
    assert all(fid in body for fid in queued), f"the committed lesson does not attribute {queued}"
    assert D.git(paths.repo_root, "rev-parse", "HEAD").stdout.strip() == product_head, \
        "the drain committed to the product checkout"
    assert set(_finding_ids(D.pending(paths, channel))) == set(queued), \
        "the committed rows left the queue before the batch's PR (hold_committed=True keeps them)"

    # hop 4: once merged, a second tick reads the corpus back and rotates the rows off as
    # consumed_idempotent
    merge_on_remote(t.p3, t.scratch, branch)
    branches = remote_branches(t.remote, LESSONS_PREFIX)
    second = D.recording(D.committing("must-not-run-twice"))
    assert author_drain(t, paths, trigger=CuratorTrigger(author=second), box=BoxSpy()) == 0, \
        "the second tick failed"
    assert second.calls == [], "the second tick authored the same findings again"
    consumed = {r["finding_id"]: r for r in D.consumed(paths, channel)}
    assert set(consumed) == set(queued), \
        f"the rows did not rotate off the queue as consumed: {sorted(consumed)}"
    assert all(r.get("consumed_category") == "consumed_idempotent" for r in consumed.values()), \
        f"the rotation's categories are {[r.get('consumed_category') for r in consumed.values()]}"
    assert D.pending(paths, channel) == [], "the authored rows are still queued"
    assert remote_branches(t.remote, LESSONS_PREFIX) == branches, \
        "the second tick opened a second batch for findings already in the corpus"


def test_1135_the_drains_append_lock_wait_ends_at_the_configured_deadline(tmp_path: Path, caplog):
    paths = S.built_paths(tmp_path, repo_root=D.make_repo(tmp_path))
    channel = D.channel_of("findings")
    rows = [D.row_for("findings", "a/0")]
    # The append lock by today's record name (R14); the handle exposes no append-lock role.
    append_lock = (location_path(paths.state_root) / channel.queue).parent / D.APPEND_LOCK_NAMES_TODAY["findings"]
    caplog.set_level(logging.INFO)
    observed: dict[int, float] = {}

    for deadline in (1, 4):
        D.seed(paths, channel, rows)
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
        assert D.pending(paths, channel) == rows, "the skipped tick changed the queue"
        observed[deadline] = answer["seconds"]  # type: ignore[assignment]

    assert 0.8 <= observed[1] < 3.0, f"the 1s deadline was not what ended the wait: {observed}"
    assert 3.2 <= observed[4] < 8.0, f"the 4s deadline was not what ended the wait: {observed}"
    held = S.rows_of(S.LearningState.open(paths).rows(S.coined("FINDINGS")))
    assert held == rows, f"the handle reads {held}, not the queue the skipped ticks left intact"
