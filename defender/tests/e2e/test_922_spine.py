"""#922 — the surviving training spine, and the drain that must stop deriving itself from a
table the cutover deletes."""
from __future__ import annotations

import dataclasses
import json
from pathlib import Path

import pytest

from defender.learning.author.lessons import run as lessons_run
from defender.learning.core import drains
from defender.tests import _drain719 as D
from defender.tests import _judge_921 as J
from defender.tests._curator1134 import author_trees
from defender.tests.e2e import _box665 as B
from defender.tests import _state1135
from defender.learning.core.state import FINDINGS

pytestmark = pytest.mark.e2e


#: The retired observation queues, by the FILE NAMES they occupy under `_pending/`, never by
#: the `LoopPaths` channel attributes or the `BY_NAME` triggers that resolve them today. Both
#: of those are inside the deletion set (D5/D6), and a test that named them could not survive
#: the change it exists to pin. A path is data; a symbol is a dependency.
RETIRED_OBSERVATION_QUEUES = (
    "actor_observations.jsonl",
    "actor_environment_observations.jsonl",
    "environment_observations.jsonl",
)

#: The retired sibling corpora, by directory name for the same reason.
RETIRED_CORPORA = ("lessons-actor", "lessons-environment")


@pytest.fixture(autouse=True)
def _isolated_roots(tmp_path, monkeypatch):
    """Every shared root this spine touches, pointed inside `tmp_path`."""
    monkeypatch.setenv(J.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(J.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    _state1135.set_state_dir(monkeypatch, tmp_path / "learning-state")
    # Stated rather than inherited: the drive below queues two family rows, and the shipped
    # default of 5 would make every assertion below vacuous on a drain that never woke.
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "1")


class RepoBranch(B.RecordingBranch):
    """`AuthorBranch`'s seam over a REAL git repo rather than a bare temp leaf."""

    def __init__(self, repo: Path, **kw) -> None:
        super().__init__(repo.parent, **kw)
        self._repo = repo

    def start_batch(self, batch_id: str) -> Path:
        self.events.append(f"start_batch:{batch_id}")
        return self._repo


class TriggerRecorder:
    """The `trigger_author=` seam: records the inbound payload of every curator trigger, and
    runs the REAL findings curator for the findings one."""

    def __init__(self, agent) -> None:
        self.calls: list[dict] = []
        self._agent = agent

    def __call__(self, paths, state, channel, threshold_env, module_name, pending_label,
                 *, box=None) -> None:
        self.calls.append({
            "pending_file": state.describe(channel), "threshold_env": threshold_env,
            "module_name": module_name, "pending_label": pending_label, "box": box,
        })
        if module_name != "author":
            return
        cfg = dataclasses.replace(
            lessons_run.build_author_config(
                paths, state=state, trees=author_trees(paths), box=box),
            invoke_agent=self._agent,
        )
        lessons_run.run_batch(paths=paths, state=state, cfg=cfg, hold_committed=True, box=box)

    @property
    def modules(self) -> list[str]:
        return [c["module_name"] for c in self.calls]


def graded_episode(tmp_path: Path, paths, *, reply=None):
    """One accepted episode graded by the REAL family judge, its rows on the REAL queue."""
    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.oracle_row("b")], "c": []},
                            dispositions={"a": "benign", "b": "malicious", "c": "malicious"})
    (ep / "worlds" / "b" / "report.md").write_text(J.report_text("benign"), encoding="utf-8")
    from defender.learning.core.state import LearningState

    with LearningState.open(paths) as state:
        J.grade_at(
            ep, judge=J.FakeJudge(
                default=reply or J.as_reply_text(J.reply_doc()),
                family_default=J.as_reply_text(J.family_reply())),
            draws=1, state=state)
    return ep, J.judge_record(ep)


def drive_author_drain(paths, trigger, *, rec=None):
    """The REAL `author_drain` entry point over its five injection seams."""
    rec = rec or B.BoxLifecycleRecorder()
    rc = drains.author_drain(
        paths, trigger_author=trigger, branch=RepoBranch(paths.repo_root, events=rec.events),
        start_box=rec.start_box, stop_box=rec.stop_box, scrub=rec.scrub)
    return rc, rec


def writable_sources(request) -> set[Path]:
    return {Path(m.source) for m in request.mounts if m.writable}


def readonly_sources(request) -> set[Path]:
    return {Path(m.source) for m in request.mounts if not m.writable}


def stuff_retired_queues(paths, *, rows: int = 25) -> None:
    """Put every retired observation queue far over any threshold the drain could read."""
    (paths.state_root / FINDINGS.queue).parent.mkdir(parents=True, exist_ok=True)
    for name in RETIRED_OBSERVATION_QUEUES:
        ((paths.state_root / FINDINGS.queue).parent / name).write_text(
            "".join(json.dumps(D.obs_row(f"{name}-{i}")) + "\n" for i in range(rows)),
            encoding="utf-8")


# ---------------------------------------------------------------------------------------
# O4 — the surviving spine, end to end
# ---------------------------------------------------------------------------------------


def test_922_graded_episode_reaches_the_corpus_through_the_family_partition(tmp_path):
    """GUARD (green now, must stay green)."""
    paths = D.make_paths(tmp_path, state_dir=tmp_path / "learning-state")
    _ep, record = graded_episode(tmp_path, paths)
    channel = FINDINGS

    assert all(row["measured"] for row in record["worlds"]), "a graded world was not measured"
    queued = [r["finding_id"] for r in D.pending(paths, channel)]
    assert record["enqueued_rows"] == len(queued) == 2, (
        f"the graded episode did not put its rows on the shared queue: {queued}")
    assert {r["direction"] for r in D.pending(paths, channel)} == {"family"}, (
        "the spine's producer is the family judge; a non-family row here means the drive is "
        "not exercising the partition this demand is about")

    head_before = D.git(paths.repo_root, "rev-parse", "HEAD").stdout.strip()
    agent = D.recording(D.committing("family-lesson"))
    rc, _rec = drive_author_drain(paths, TriggerRecorder(agent))

    assert rc == 0, "author_drain did not complete its batch"
    assert len(agent.calls) == 1, (
        f"the findings curator ran {len(agent.calls)} times, not once")
    authored = [r["finding_id"] for r in agent.calls[0]["rows"]]
    assert authored == queued, (
        f"the curator was handed {authored}, not the graded episode's rows {queued} — the "
        "family partition did not admit them for authoring")

    head_after = D.git(paths.repo_root, "rev-parse", "HEAD").stdout.strip()
    assert head_after != head_before, "the corpus author opened no commit"
    lessons = list(paths.lessons_dir.glob("*.md"))
    assert len(lessons) == 1, f"the corpus gained {len(lessons)} documents, not one"
    body = lessons[0].read_text(encoding="utf-8")
    for fid in queued:
        assert fid in body, f"the committed lesson does not attribute {fid}"
    assert {r["finding_id"] for r in D.pending(paths, channel)} == set(queued), (
        "the committed rows left the queue before the batch's PR — `hold_committed=True` is "
        "what keeps them there for the next tick to retire")

    second = D.recording(D.committing("must-not-run-twice"))
    assert drive_author_drain(paths, TriggerRecorder(second))[0] == 0
    assert second.calls == [], (
        "the second tick authored the same findings again — the corpus attribution the first "
        "tick wrote is not being read back")
    consumed = {r["finding_id"]: r for r in D.consumed(paths, channel)}
    assert set(consumed) == set(queued), (
        f"the rows did not rotate off the queue as consumed: {sorted(consumed)}")
    assert all(r["consumed_category"] == "consumed_idempotent" for r in consumed.values())
    assert D.pending(paths, channel) == [], "the authored rows are still queued"
    assert D.git(paths.repo_root, "rev-parse", "HEAD").stdout.strip() == head_after, (
        "the second tick opened a second commit for findings already in the corpus")


def test_922_a_caught_family_is_consumed_without_authoring(tmp_path):
    """GUARD (green now, must stay green)."""
    paths = D.make_paths(tmp_path, state_dir=tmp_path / "learning-state")
    channel = FINDINGS
    D.seed(paths, channel, [
        dict(D.finding_row("ep-caught/b/0/0", run_id="ep-caught", direction="family"),
             type="decision-discipline", judge_outcome="caught", subject_anchor="l-001",
             subject_topic="holding-system coverage",
             source_run_dir="episodes/ep-caught/worlds/b"),
    ])

    head_before = D.git(paths.repo_root, "rev-parse", "HEAD").stdout.strip()
    agent = D.recording(D.committing("must-not-run"))
    rc, _rec = drive_author_drain(paths, TriggerRecorder(agent))

    assert rc == 0
    assert agent.calls == [], (
        "a retired-word family row reached the curator — the partition authored a row the "
        "retired design would have read")
    assert D.git(paths.repo_root, "rev-parse", "HEAD").stdout.strip() == head_before, (
        "a retired-word family row produced a corpus commit")
    assert D.consumed(paths, channel) == [], "the retired-word row was consumed, not held"
    assert [r["finding_id"] for r in D.pending(paths, channel)] == ["ep-caught/b/0/0"], (
        "the retired-word row left the queue instead of being held")


# ---------------------------------------------------------------------------------------
# D5 — the drain names its channel and its mount
# ---------------------------------------------------------------------------------------


def test_922_author_drain_triggers_exactly_the_findings_curator(tmp_path):
    """RED-FIRST (fails at HEAD)."""
    paths = D.make_paths(tmp_path, state_dir=tmp_path / "learning-state")
    graded_episode(tmp_path, paths)
    stuff_retired_queues(paths)

    trigger = TriggerRecorder(D.recording(D.committing("family-lesson")))
    rc, _rec = drive_author_drain(paths, trigger)

    assert rc == 0
    # EDITED BY #1007, ON A RECORDED HUMAN DECISION (15-resolutions R1), NOT AS TEST CHURN.
    # #922's stated property is "a second channel returning is an edit here, in a diff"; the
    # questioner channel arrives WITH its edit, which honours that property rather than
    # exempting itself from it. STILL EXACT — a multiset equality, not an `in` check, because
    # exactness is what makes this its own positive control. The list's ORDER is not part of
    # the contract (nothing downstream depends on which curator the tick triggers first), so
    # the set is compared sorted; loosening it any further would give up the property.
    assert sorted(trigger.modules) == ["author", "questioner_curator"], (
        f"author_drain triggered {trigger.modules} — it is still discovering its curators by "
        "iterating the direction table, so the retired observation channels are still drained")
    # Selected BY MODULE rather than by position, for the same reason the set above is sorted:
    # the tick now triggers two curators and their order is not a contract.
    call = next(c for c in trigger.calls if c["module_name"] == "author")
    assert call["pending_file"] == str(paths.state_root / FINDINGS.queue), (
        f"the findings trigger names {call['pending_file']}, not the findings queue")
    assert call["threshold_env"] == "LEARNING_AUTHOR_THRESHOLD"
    assert call["pending_label"] == "pending"


def test_922_the_drain_box_gets_exactly_the_lessons_corpus_writable(tmp_path):
    """RED-FIRST (fails at HEAD)."""
    paths = D.make_paths(tmp_path, state_dir=tmp_path / "learning-state")
    graded_episode(tmp_path, paths)
    stuff_retired_queues(paths)

    rec = B.BoxLifecycleRecorder()
    trigger = TriggerRecorder(D.recording(D.committing("family-lesson")))
    rc, rec = drive_author_drain(paths, trigger, rec=rec)

    assert rc == 0
    request = rec.only_request()
    # EDITED BY #1007 (15-resolutions R1), and STILL AN EXACT SET. The set gains exactly one
    # member — the questioner corpus the second curator authors into — because both curators
    # share one batch and one box. It is not loosened into two `in` checks: an exact set is its
    # own positive control, and a bare membership test passes on a request that mounts the
    # whole checkout writable.
    assert writable_sources(request) == {paths.lessons_dir, paths.lessons_questioner_dir}, (
        f"the drain box's writable mounts are {sorted(map(str, writable_sources(request)))} — "
        "the mount set is still derived from the direction table, so a retired corpus is "
        "still handed to the batch as a writable bind")
    # The positive control for the negative above: the box IS composed, and it still carries
    # the read-only worktree leaf both drain roles anchor on. Without this the exact-set
    # assertion could be satisfied by a request that mounts nothing at all.
    assert readonly_sources(request) == {paths.repo_root}, (
        f"the drain box lost its read-only worktree mount: {request.mounts}")
    for retired in RETIRED_CORPORA:
        assert B.mount_for(request, retired) is None, (
            f"{retired} is still bound into the drain box")


def test_922_a_full_findings_queue_alone_wakes_the_drain(tmp_path):
    """GUARD (green now, must stay green)."""
    paths = D.make_paths(tmp_path, state_dir=tmp_path / "learning-state")
    graded_episode(tmp_path, paths)
    for name in RETIRED_OBSERVATION_QUEUES:
        assert not ((paths.state_root / FINDINGS.queue).parent / name).exists(), (
            "this control is about a findings-only queue; an observation queue exists")

    trigger = TriggerRecorder(D.recording(D.committing("family-lesson")))
    rec = B.BoxLifecycleRecorder()
    rc, rec = drive_author_drain(paths, trigger, rec=rec)

    assert rc == 0
    assert "author" in trigger.modules, (
        "the findings queue alone did not wake the drain — the surviving channel's own "
        "threshold no longer answers the wake gate")
    # EDITED BY #1007 (15-resolutions R1). This test is declared "GUARD (green now, must stay
    # green)" and this line is the one part of it the change touches: `_drain_box_request`
    # never learns WHICH queue crossed threshold, so a findings-only drive composes the same
    # two-corpus box any other drive does. The guard's own subject — that a full findings queue
    # alone still wakes the drain — is unchanged and still asserted above. Kept exact.
    assert writable_sources(rec.only_request()) == {paths.lessons_dir,
                                                    paths.lessons_questioner_dir}
