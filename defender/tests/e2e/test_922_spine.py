"""#922 — the surviving training spine, and the drain that must stop deriving itself from a
table the cutover deletes.

Two obligations live here, and the design doc (§D8) says why they cannot share a posture:

* **O4 — training still flows.** The cut deletes the four model-role stages and both engines.
  "The suite is green" cannot witness that, because the change that deletes the code deletes
  the tests that would object. The real oracle is the SURVIVING spine driven end to end —
  graded episode -> `_pending/findings.jsonl` -> `author_drain` -> the `direction: family`
  partition of `_gate_findings` -> a corpus commit. Green at HEAD, green after a correct
  deletion, RED after a careless one, so these are GUARDs.

* **D5 — `author_drain` names its one channel and its one box mount.** Today all three of
  `_curator_queue_checks`, `_drain_curators` and `_drain_triggered_corpora` iterate
  `directions.BY_NAME`, so the drain's channel set and its sandbox's writable mount set are
  DERIVED from the table the cutover empties. C7 (executed) records that emptying it narrows
  the drain from four channels to one and shrinks its mounts with no error and no red test.
  The demand is therefore stated positively — exactly one channel, exactly one writable mount —
  and it is RED-FIRST: at HEAD the drain triggers four curators and mounts three corpora.

WHY NOT `monkeypatch.setattr(directions, "BY_NAME", {})`: CI ratchets new setattr sites
(`scripts/lint/lint_monkeypatch.py`), and — more to the point — a drive with an emptied table
would be GREEN at HEAD, because the findings channel and the base lessons corpus are literals
outside all three loops (C7). The discriminating drive is the opposite one: leave the table
alone, put the retired observation queues over their thresholds, and demand that the drain
reach for NEITHER. Only a drain that no longer consults the table can pass that.

Every fake enters through a real injection seam that already exists on the target —
`author_drain`'s `trigger_author=` / `branch=` / `start_box=` / `stop_box=` / `scrub=`, and
`lessons/run.py::run_batch`'s `cfg=` (whose `invoke_agent` is the model call). Nothing is
monkeypatched, and the only thing faked below the drain's own boundary is the model.
"""
from __future__ import annotations

import dataclasses
import json
import ast
from pathlib import Path

import pytest

from defender.learning.author.lessons import run as lessons_run
from defender.learning.core import drains
from defender.tests import _drain719 as D
from defender.tests import _judge_921 as J
from defender.tests.e2e import _box665 as B

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
    """Every shared root this spine touches, pointed inside `tmp_path`.

    The findings queue is a SHARED sink resolved through `config.loop_paths()`; without the
    state-dir override a drive would append the checkout's own `learning/_pending/`.
    """
    monkeypatch.setenv(J.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(J.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    monkeypatch.setenv(J.STATE_DIR_ENV, str(tmp_path / "learning-state"))
    # Stated rather than inherited: the drive below queues two family rows, and the shipped
    # default of 5 would make every assertion below vacuous on a drain that never woke.
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "1")


class RepoBranch(B.RecordingBranch):
    """`AuthorBranch`'s seam over a REAL git repo rather than a bare temp leaf.

    `_run_worktree_batch` hands `start_batch`'s return to `paths.with_repo_root`, and the
    corpus commit at the end of the spine is a real `git add` + `git commit` over that tree
    (`author/shared.py::commit_corpus`). A fake that returned a git-less directory would make
    the spine's LAST STOP unreachable, which is the one stop D8 calls the oracle.
    """

    def __init__(self, repo: Path, **kw) -> None:
        super().__init__(repo.parent, **kw)
        self._repo = repo

    def start_batch(self, batch_id: str) -> Path:
        self.events.append(f"start_batch:{batch_id}")
        return self._repo


class TriggerRecorder:
    """The `trigger_author=` seam: records the inbound payload of every curator trigger, and
    runs the REAL findings curator for the findings one.

    It records rather than answers. What a demand asserts on is `self.calls` — the channel,
    threshold knob, module and label the drain decided to trigger — never a canned return.
    Only the model is faked below it (`cfg.invoke_agent`), so the gate, the partition, the
    rotation and the commit are all production code.
    """

    def __init__(self, agent) -> None:
        self.calls: list[dict] = []
        self._agent = agent

    def __call__(self, paths, pending_file, threshold_env, module_name, pending_label,
                 *, box=None) -> None:
        self.calls.append({
            "pending_file": pending_file, "threshold_env": threshold_env,
            "module_name": module_name, "pending_label": pending_label, "box": box,
        })
        if module_name != "author":
            return
        cfg = dataclasses.replace(
            lessons_run.build_author_config(paths, box=box), invoke_agent=self._agent)
        lessons_run.run_batch(paths=paths, cfg=cfg, hold_committed=True, box=box)

    @property
    def modules(self) -> list[str]:
        return [c["module_name"] for c in self.calls]


def graded_episode(tmp_path: Path, paths, *, reply=None):
    """One accepted episode graded by the REAL family judge, its rows on the REAL queue.

    Returns `(episode_dir, family record)`. The model is the only fake — `FakeJudge` records
    the prompts it was handed and answers with the reply document the scenario names.
    """
    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.staged_row("b")], "c": []},
                            dispositions={"a": "benign", "b": "malicious", "c": "malicious"})
    (ep / "worlds" / "b" / "report.md").write_text(J.report_text("benign"), encoding="utf-8")
    J.mod("learning.judge").grade_episode(
        ep, judge=J.FakeJudge(default=reply or J.as_reply_text(J.reply_doc())),
        runs_base=tmp_path / "defender-runs", draws=1, queue_dir=paths.pending_dir)
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
    """Put every retired observation queue far over any threshold the drain could read.

    Written by FILE NAME (see `RETIRED_OBSERVATION_QUEUES`). At HEAD these are the three
    channels `BY_NAME` resolves, and the drain wakes a curator and mounts a corpus for each;
    after the cut they are three files nothing reads. That difference is the whole demand.
    """
    paths.pending_dir.mkdir(parents=True, exist_ok=True)
    for name in RETIRED_OBSERVATION_QUEUES:
        (paths.pending_dir / name).write_text(
            "".join(json.dumps(D.obs_row(f"{name}-{i}")) + "\n" for i in range(rows)),
            encoding="utf-8")


# ---------------------------------------------------------------------------------------
# O4 — the surviving spine, end to end
# ---------------------------------------------------------------------------------------


def test_922_graded_episode_reaches_the_corpus_through_the_family_partition(tmp_path):
    """GUARD (green now, must stay green).

    O4 / D8's real oracle, driven end to end over production entry points: a graded episode's
    findings land on `_pending/findings.jsonl`, `author_drain` picks that batch up, the
    `direction: family` partition of `_gate_findings` admits the `survived` rows for authoring,
    and the corpus author's commit lands a lesson in `defender/lessons` as a NEW git commit.

    Each hop is asserted at its own address rather than through the last one, because a spine
    test that only looked at the end could pass on a drain that authored a row some other
    producer left on the queue:

      1. the judge's own record says how many rows it enqueued, and the queue carries them;
      2. the batch the curator's model call RECEIVES is exactly those rows (the captured
         inbound payload, not the fake's answer);
      3. `git log` gains one commit and the corpus gains the document naming both finding ids;
      4. a SECOND tick reads that corpus back, recognises the rows as already authored, and
         rotates them off the queue as `consumed_idempotent` without a second model call.

    Step 4 is part of the spine rather than a bonus: `_maybe_trigger_author` passes
    `hold_committed=True`, so one tick COMMITS but holds the rows on the queue, and it is the
    next tick's `existing_finding_ids` read of the corpus that retires them. A spine that
    stopped at the commit would not notice a cut that broke the attribution round-trip.

    A careless deletion breaks this at (2) — the doc's first draft listed `_gate_findings` for
    deletion, in the wrong file (C10), which would leave the family rows held forever with the
    suite still green.
    """
    paths = D.make_paths(tmp_path, state_dir=tmp_path / "learning-state")
    _ep, record = graded_episode(tmp_path, paths)
    channel = paths.findings

    assert record["episode_outcome"] == "gradable"
    queued = [r["finding_id"] for r in D.pending(channel)]
    assert record["enqueued_rows"] == len(queued) == 2, (
        f"the graded episode did not put its rows on the shared queue: {queued}")
    assert {r["direction"] for r in D.pending(channel)} == {"family"}, (
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
    assert {r["finding_id"] for r in D.pending(channel)} == set(queued), (
        "the committed rows left the queue before the batch's PR — `hold_committed=True` is "
        "what keeps them there for the next tick to retire")

    second = D.recording(D.committing("must-not-run-twice"))
    assert drive_author_drain(paths, TriggerRecorder(second))[0] == 0
    assert second.calls == [], (
        "the second tick authored the same findings again — the corpus attribution the first "
        "tick wrote is not being read back")
    consumed = {r["finding_id"]: r for r in D.consumed(channel)}
    assert set(consumed) == set(queued), (
        f"the rows did not rotate off the queue as consumed: {sorted(consumed)}")
    assert all(r["consumed_category"] == "consumed_idempotent" for r in consumed.values())
    assert D.pending(channel) == [], "the authored rows are still queued"
    assert D.git(paths.repo_root, "rev-parse", "HEAD").stdout.strip() == head_after, (
        "the second tick opened a second commit for findings already in the corpus")


def test_922_a_caught_family_is_consumed_without_authoring(tmp_path):
    """GUARD (green now, must stay green).

    The complementary condition on the SAME address, so the spine test above cannot pass
    vacuously on a partition that admits everything. `_gate_family` is a POSITIVE rule: only
    `survived` is authored; `caught` is consumed terminally, without a corpus commit.

    Driven through the same real entry point, so what is asserted is the drain's behaviour and
    not the gate function read in isolation.
    """
    paths = D.make_paths(tmp_path, state_dir=tmp_path / "learning-state")
    channel = paths.findings
    # The judge's own appender writes the family's verdict word onto every row; a `caught`
    # family is enqueued exactly like a `survived` one and separated only by this partition.
    D.seed(channel, [
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
        "a `caught` family reached the curator — the partition authored a row whose whole "
        "point is that there is nothing to author")
    assert D.git(paths.repo_root, "rev-parse", "HEAD").stdout.strip() == head_before, (
        "a `caught` family produced a corpus commit")
    consumed = D.consumed(channel)
    assert [r["finding_id"] for r in consumed] == ["ep-caught/b/0/0"], (
        f"the caught row was not consumed terminally: {consumed}")
    assert consumed[0]["consumed_category"] == "consumed_family_skip"
    assert D.pending(channel) == [], "the caught row was left queued forever"


# ---------------------------------------------------------------------------------------
# D5 — the drain names its channel and its mount
# ---------------------------------------------------------------------------------------


def test_922_author_drain_triggers_exactly_the_findings_curator(tmp_path):
    """RED-FIRST (fails at HEAD).

    D5, first loop pair (`_curator_queue_checks` / `_drain_curators`). After the cut the
    findings channel is the drain's ONE channel, so one tick triggers exactly one curator and
    the payload it is handed names the findings queue.

    The retired observation queues are seeded far over any threshold, which is what makes this
    discriminating in BOTH directions: a drain still iterating `BY_NAME` wakes three more
    curators here (RED at HEAD), and a drain that named its channel explicitly wakes exactly
    one however full those files are.

    Asserted on the CAPTURED INBOUND PAYLOAD — pending file, threshold knob, module and label
    — rather than on a count alone, so a drain that triggered once for the wrong channel fails
    too.

    AT HEAD: `trigger_author` is called four times, with modules
    `['author', 'author_actor', 'author_actor_env', 'author_actor_benign']`.
    """
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
    assert call["pending_file"] == paths.findings.file, (
        f"the findings trigger names {call['pending_file']}, not the findings queue")
    assert call["threshold_env"] == "LEARNING_AUTHOR_THRESHOLD"
    assert call["pending_label"] == "pending"


def test_922_the_drain_box_gets_exactly_the_lessons_corpus_writable(tmp_path):
    """RED-FIRST (fails at HEAD).

    D5, third loop (`_drain_triggered_corpora` feeding `_drain_box_request`). The drain box's
    geography after the cut: read-only over the worktree leaf, writable over the base lessons
    corpus and NOTHING else.

    The retired observation queues are over threshold, so at HEAD `_drain_triggered_corpora`
    adds `lessons-actor` and `lessons-environment` to the mount set. The assertion is an exact
    set rather than a pair of `not in` checks: an exact set is its own positive control, and a
    bare `assert lessons-actor not in mounts` would pass on a request with no mounts at all.

    AT HEAD: three writable mounts (`lessons`, `lessons-actor`, `lessons-environment`).
    """
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
    """GUARD (green now, must stay green).

    The wake gate (`_has_curator_work`) answers for the findings channel on its own, so the
    drain still runs when the retired queues are empty. This is the positive control for the
    two demands above: they assert that the retired channels are NOT reached, and they would
    both pass on a drain that had stopped running altogether.
    """
    paths = D.make_paths(tmp_path, state_dir=tmp_path / "learning-state")
    graded_episode(tmp_path, paths)
    for name in RETIRED_OBSERVATION_QUEUES:
        assert not (paths.pending_dir / name).exists(), (
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


def test_922_the_retired_queues_alone_no_longer_wake_the_drain(tmp_path):
    """RED-FIRST (fails at HEAD).

    D5's remaining loop, `_curator_queue_checks`, at the place its narrowing is INVISIBLE. The
    wake gate (`_has_curator_work`) answers over every queue that loop yields, so today three
    retired observation queues can wake a drain, mint a batch worktree, create a box and open a
    PR for channels that will have no producer after the cut.

    After the cut those files are stale data nothing reads: the tick is a clean skip — no
    trigger, no box, no worktree — and the drain waits for the findings queue.

    "No box was created" is the load-bearing half and it is paired with its control: the
    findings-only drive above proves the same recorder DOES capture a request when the drain
    genuinely runs, so the emptiness asserted here is a fact about the wake gate rather than
    about a recorder that never sees anything.

    AT HEAD: the retired queues wake the drain, four curators are triggered and one box is
    created.
    """
    paths = D.make_paths(tmp_path, state_dir=tmp_path / "learning-state")
    stuff_retired_queues(paths)
    assert not paths.findings.file.exists(), (
        "this drive is about the retired queues ALONE; the findings queue must be absent")

    trigger = TriggerRecorder(D.recording(D.committing("must-not-run")))
    rec = B.BoxLifecycleRecorder()
    rc, rec = drive_author_drain(paths, trigger, rec=rec)

    assert rc == 0
    assert trigger.modules == [], (
        f"the retired observation queues woke {trigger.modules} — the drain's wake gate is "
        "still derived from the direction table, so three channels with no producer can still "
        "mint a batch")
    assert rec.requests == [], (
        f"the drain created a box for the retired queues: {rec.requests}")
    assert rec.events == [], (
        f"the drain minted batch resources for the retired queues: {rec.events}")


def test_922_the_drain_decides_its_channel_without_consulting_a_direction_table():
    """GUARD (green after the cut, must stay green) — the STRUCTURAL arm the three behavioural
    demands above cannot supply.

    Those three drive `author_drain` and assert what it reaches for: one curator, one writable
    mount, no wake on the retired queues. All three are equally satisfied by a drain that still
    DERIVES its answer from a table which happens to be empty — swap `BY_NAME` for a new empty
    mapping and every one of them passes while the direction table, both observation curators
    and their corpora stay fully alive. That was found by attacking this file, not imagined.

    The difference is invisible from outside and decisive from inside: a derived answer comes
    back the moment something repopulates the table, and it takes with it the three channels
    whose producer the cutover deleted. So the property is asserted where it actually lives —
    the drain module reaches no direction table at all.

    Written against the IMPORT rather than against a symbol name so that reintroducing the
    coupling under a different spelling fails here too; `learning.core.directions` is gone, but
    a successor table imported into this module is the same defect wearing a new name.
    """
    drains_py = Path(drains.__file__).resolve()
    tree = ast.parse(drains_py.read_text(encoding="utf-8"))
    imported: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            imported.append(node.module)
        elif isinstance(node, ast.Import):
            imported.extend(alias.name for alias in node.names)

    offenders = [m for m in imported if "direction" in m.lower()]
    assert not offenders, (
        f"the drain imports {offenders} — its channel, curator and box-mount decisions must be "
        "spelled literally, not derived from a table whose emptiness is what makes the "
        "behavioural demands pass")

    # POSITIVE CONTROL on the same address: the scan really does see this module's imports, so
    # the empty `offenders` above is a fact about the module and not about a broken walk.
    assert any(m.startswith("defender.") for m in imported), (
        "positive control: the import scan found no `defender.` import in the drain module at "
        "all, so its silence about direction tables means nothing")
