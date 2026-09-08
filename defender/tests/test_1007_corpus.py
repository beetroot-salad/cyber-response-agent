"""#1007 — D3/M7: the second authored corpus, its curator, and the one drain tick they share.

`defender/lessons-questioner/` is authored by a second `CorpusAuthorConfig` from the second
queue channel. R1 (human, at the early-exit seam) re-derived the attachment points against the
four literals #922 left in place of the deleted direction table: `_CURATOR_MODULES`,
`_curator_queue_checks`, `_drain_curators`, and `_drain_box_request`'s `label` branch.

A2 (§7) settled the tick's shape: ONE unit — one drain lock, one batch, one branch, one PR
lease covering both corpora — with per-curator consumption and per-curator corpus scoping, and
a curator's fault leaving the other's landed work intact.

THE THREE EXACT-SET ASSERTIONS #922 WROTE RED-FIRST ARE EDITED, NOT LOOSENED. `test_922_spine`
holds `trigger.modules` and `writable_sources(request)` as exact sets, with the comment "an
exact set is its own positive control". This change gives each set a second member and edits
those assertions IN THE SAME DIFF — which is #922's own stated property ("a second channel
returning is an edit here, in a diff"), not an exemption from it. The tests below are the new
channel's side of that same exactness.

Every fake enters through a real injection seam that already exists on the target:
`author_drain`'s `trigger_author=` / `branch=` / `start_box=` / `stop_box=` / `scrub=`, and
`run_batch`'s `cfg=`. Nothing is monkeypatched.

LOCATED IN `tests/` RATHER THAN `tests/e2e/` on purpose, and it is not a filing preference:
`check_binds` scans the ONE directory the graph's `tests:` field names, non-recursively, so a
demand whose test sat one directory down would report as a dangling pointer and its prose would
be unscannable — the graph and its suite would disagree while both looked complete. The
`e2e` marker travels with the module, so CI still runs it in the lane it belongs to.

RED AGAINST HEAD is the expected state.
"""
from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest

from defender.learning.core import drains
from defender.tests import _by_path as P
from defender.tests import _drain719 as D
from defender.tests import _world_1007 as W
from defender.tests.e2e import _box665 as B
from defender.tests.e2e.test_922_spine import (
    RepoBranch,
    readonly_sources,
    writable_sources,
)

pytestmark = pytest.mark.e2e


@pytest.fixture(autouse=True)
def _thresholds(monkeypatch):
    """Both channels' thresholds at 1, stated rather than inherited: the shipped default of 5
    would make every assertion below vacuous on a drain that never woke."""
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "1")
    monkeypatch.setenv("LEARNING_QUESTIONER_THRESHOLD", "1")


class TwoLaneRecorder:
    """The `trigger_author=` seam, recording BOTH curators' inbound payloads.

    Records rather than answers: what the demands assert on is `self.calls` — the channel,
    threshold knob, module and label the drain decided to trigger for each lane. The real
    curator module runs for whichever modules `run` names, so the gate, the rotation and the
    commit stay production code.
    """

    def __init__(self, agent, *, run: tuple[str, ...] = (), fail_on: tuple[str, ...] = (),
                 fault_class: type[BaseException] = RuntimeError):
        self.calls: list[dict] = []
        self._agent = agent
        self._run = run
        self._fail_on = fail_on
        #: THE FAULT CLASS IS DATA, and the two this suite drives are P-A's own executed
        #: measurement of this tick's envelope (pa-2), never an author's imagined taxonomy:
        #: `_run_curator_module` catches `(SubprocessError, OSError)`, so a `RuntimeError`
        #: ESCAPES it and a `TimeoutError` — an `OSError` subclass — is SWALLOWED, leaving
        #: `rc=None`, one `(continuing)` log line and no other trace anywhere.
        self._fault_class = fault_class

    def __call__(self, paths, pending_file, threshold_env, module_name, pending_label,
                 *, box=None) -> None:
        self.calls.append({
            "pending_file": pending_file, "threshold_env": threshold_env,
            "module_name": module_name, "pending_label": pending_label, "box": box,
        })
        if module_name in self._fail_on:
            raise self._fault_class(f"{module_name} faulted mid-batch")
        if module_name not in self._run:
            return
        from defender.learning.author.lessons import run as lessons_run

        cfg = dataclasses.replace(
            lessons_run.build_author_config(paths, box=box), invoke_agent=self._agent)
        lessons_run.run_batch(paths=paths, cfg=cfg, hold_committed=True, box=box)

    @property
    def modules(self) -> list[str]:
        return [c["module_name"] for c in self.calls]


def world_queue_row(fid: str = "ep-1/b/0/0", **extra) -> dict:
    row = dict(D.finding_row(fid, run_id="ep-1", direction=W.SUBJECT_WORLD),
               subject=W.SUBJECT_WORLD, type="story-overlay-gap", world="b",
               pattern=W.EVENTS_PATTERN, holding_system="elastic", provenance="model",
               subject_anchor="overlay", subject_topic="corpus shape",
               judge_outcome="gradable", source_run_dir="episodes/ep-1")
    row.update(extra)
    return row


def defender_queue_row(fid: str = "ep-1/b/0/1", **extra) -> dict:
    row = dict(D.finding_row(fid, run_id="ep-1", direction="family"),
               subject=W.SUBJECT_DEFENDER, type="lead-set", judge_outcome="survived",
               subject_anchor="l-001", subject_topic="coverage",
               source_run_dir="episodes/ep-1/worlds/b")
    row.update(extra)
    return row


def drive(paths, trigger, *, rec=None):
    rec = rec or B.BoxLifecycleRecorder()
    rc = drains.author_drain(
        paths, trigger_author=trigger, branch=RepoBranch(paths.repo_root, events=rec.events),
        start_box=rec.start_box, stop_box=rec.stop_box, scrub=rec.scrub)
    return rc, rec


# ---------------------------------------------------------------------------------------
# The corpus and its curator
# ---------------------------------------------------------------------------------------


def test_lessons_questioner_dir_and_rel_resolve(tmp_path):
    """The corpus root exists as a PATH PAIR on `_paths`, beside `lessons_dir`.

    Observably true: `lessons_questioner_dir` is `<defender_dir>/lessons-questioner` and
    `lessons_questioner_dir_rel` is its repo-relative spelling, and both come off the same
    class that owns every other corpus directory name. Two spellings are needed because git
    pathspecs and porcelain paths use the relative one and the absolute join is off a tree; a
    site that composed either by hand joins no census and moves with no rename.

    What failure looks like: the directory is spelled inline at the curator, the box request
    and the lint exclusion list. Three copies of one name then drift independently.
    """
    paths = D.make_paths(tmp_path, state_dir=tmp_path / "learning-state")

    assert paths.lessons_questioner_dir == paths.defender_dir / W.QUESTIONER_CORPUS_DIRNAME
    assert paths.lessons_questioner_dir_rel == W.QUESTIONER_CORPUS_REL
    assert paths.lessons_questioner_dir != paths.lessons_dir


def test_the_questioner_curator_gate_is_idempotency_only(tmp_path):
    """The questioner curator's gate is IDEMPOTENCY ONLY — no ground-truth check, no family
    partition.

    Observably true: a world row whose episode has no `source_refs.yaml` and no disposition is
    admitted for authoring, while a row whose finding id the corpus already attributes is
    consumed as `consumed_idempotent`. The defender gate's ground-truth requirement is about a
    DEFENDER verdict, which a world finding does not have and never will.

    What failure looks like: the findings gate is reused. Every world finding is then held as
    `no_ground_truth` forever, the queue grows, and the corpus stays empty with nothing raising.
    """
    paths = D.make_paths(tmp_path, state_dir=tmp_path / "learning-state")
    curator = W.mod("learning.author.questioner.run")
    cfg = curator.build_questioner_config(paths)

    to_author, held, consumed = cfg.gate([world_queue_row()], cfg)

    assert [r["finding_id"] for r in to_author] == ["ep-1/b/0/0"], (
        f"a world row with no defender ground truth was held: {held}")
    assert consumed == []


def test_the_questioner_curator_registers_no_forward_check(tmp_path):
    """The questioner curator registers NO forward check.

    Observably true: the forward-check registry still holds exactly the one findings check it
    holds today, and the questioner config declares no check of its own. A forward check
    re-runs the JUDGE against a candidate lesson to see whether the finding still fires; there
    is no defender behaviour for a world lesson to change, so the check would compare a lesson
    against a verdict it has no bearing on.

    What failure looks like: a second check is registered for symmetry. Every questioner lesson
    then pays a model call to be measured against a question it does not answer, and the
    results gate a corpus on noise.
    """
    import inspect

    checks = W.mod("learning.author.verify_forward.checks")
    curator = W.mod("learning.author.questioner.run")

    registered = [name for name, value in vars(checks).items()
                  if isinstance(value, checks.ForwardCheck)]
    assert registered == ["FINDINGS_CHECK"], (
        f"the forward-check registry holds {registered}; the questioner corpus added one")
    # The check is wired at the curator's own `invoke_agent`, not declared as a config field,
    # so that frame is where the absence is observable.
    source = inspect.getsource(curator.invoke_agent)
    for wired in ("FINDINGS_CHECK", "ForwardCheckConfig"):
        assert wired not in source, (
            f"the questioner curator wires {wired} — a world lesson has no defender verdict "
            "for a forward check to re-run against")


def test_the_defender_curator_still_registers_findings_check(tmp_path):
    """The DEFENDER curator keeps its forward check — the survival half of the pair above.

    Observably true: the findings check is still registered and still reachable from the
    defender author config. Without this control, "exactly one check is registered" would also
    hold on a change that deleted the incumbent one.

    What failure looks like: the check registry is refactored to be per-corpus while adding the
    second corpus, and the one check that exists is dropped in the move.
    """
    import inspect

    checks = W.mod("learning.author.verify_forward.checks")
    lessons_run = W.mod("learning.author.lessons.run")

    assert getattr(checks, "FINDINGS_CHECK", None) is not None, (
        "the incumbent findings forward check is gone")
    assert "FINDINGS_CHECK" in inspect.getsource(lessons_run.invoke_agent), (
        "the defender curator stopped wiring its forward check — the regression gate every "
        "lesson edit passes through")


def test_curator_modules_names_the_questioner_curator_module(tmp_path):
    """`_CURATOR_MODULES` gains a key for the questioner curator, and it IMPORTS.

    Observably true: the fixed dict names `questioner_curator` and the dotted path it maps to
    imports successfully. The dict is a literal the drain reads to import a curator by name; a
    key naming a module that does not exist fails at the moment the drain triggers, inside a
    handler that catches only `SubprocessError` and `OSError`.

    What failure looks like: the module is added to the trigger list and not to this dict.
    `_run_curator_module` then raises `KeyError` from inside a tick, past the one handler that
    was supposed to keep a curator's fault contained.
    """
    import importlib

    assert W.QUESTIONER_CURATOR_MODULE in drains._CURATOR_MODULES, (
        f"_CURATOR_MODULES is {sorted(drains._CURATOR_MODULES)}")
    dotted = drains._CURATOR_MODULES[W.QUESTIONER_CURATOR_MODULE]
    assert importlib.import_module(dotted) is not None


def test_the_questioner_queue_alone_wakes_the_drain(tmp_path):
    """The questioner queue over threshold wakes the drain ON ITS OWN.

    Observably true: with the defender findings queue EMPTY and the questioner queue over
    threshold, one tick runs — a box is created and the questioner curator is triggered. The
    wake gate reads `_curator_queue_checks`, which is NAMED not derived; a second channel that
    is triggered but not listed there is a channel the drain never wakes for.

    What failure looks like: `_drain_curators` gains its second trigger and
    `_curator_queue_checks` does not. Questioner findings then accumulate until some unrelated
    defender finding happens to wake the drain, and the corpus updates at random.
    """
    paths = D.make_paths(tmp_path, state_dir=tmp_path / "learning-state")
    D.seed(W.questioner_channel(paths), [world_queue_row()])
    assert D.pending(paths.findings) == []

    trigger = TwoLaneRecorder(D.recording(D.committing("questioner-lesson")))
    rc, rec = drive(paths, trigger)

    assert rc == 0
    assert W.QUESTIONER_CURATOR_MODULE in trigger.modules, (
        f"the questioner queue alone did not wake the drain: {trigger.modules}")
    assert rec.only_request() is not None, "no box was created for the questioner-only tick"


def test_the_author_drain_triggers_exactly_its_two_named_curators(tmp_path):
    """One tick triggers EXACTLY the two named curators — no more, and no fewer.

    Observably true: with both queues over threshold, `trigger.modules` is exactly
    `{author, questioner_curator}` as a multiset. This is the same exact-set assertion #922
    wrote red-first at `test_922_spine.py:327`, gaining its second member here: an exact set is
    its own positive control, where a bare `in` check would pass on a drain that triggered
    twenty.

    What failure looks like: the trigger list is derived from something again — a registry
    walk, a directory scan — and a third curator appears with no diff to point at.
    """
    paths = D.make_paths(tmp_path, state_dir=tmp_path / "learning-state")
    D.seed(paths.findings, [defender_queue_row()])
    D.seed(W.questioner_channel(paths), [world_queue_row()])

    trigger = TwoLaneRecorder(D.recording(D.committing("lesson")))
    rc, _rec = drive(paths, trigger)

    assert rc == 0
    assert sorted(trigger.modules) == sorted(
        [W.DEFENDER_CURATOR_MODULE, W.QUESTIONER_CURATOR_MODULE]), (
        f"one tick triggered {trigger.modules} — the drain's curator set is not the two "
        "literals it names")
    by_module = {c["module_name"]: c for c in trigger.calls}
    assert by_module[W.DEFENDER_CURATOR_MODULE]["pending_file"] == paths.findings.file
    assert by_module[W.QUESTIONER_CURATOR_MODULE]["pending_file"] == (
        W.questioner_channel(paths).file)


def test_a_full_findings_queue_alone_still_wakes_the_drain(tmp_path):
    """SURVIVAL: the incumbent findings-only drive still wakes the drain and still runs.

    Observably true: with the questioner queue empty and the findings queue over threshold, the
    drain wakes, triggers `author`, and composes its box. This is #922's own guard
    (`test_922_spine.py:397`, "green now, must stay green") re-asserted from the other side of
    the change — and the box's writable set is now the EDITED exact set, two corpora, because
    `_drain_box_request` never learns which queue crossed threshold.

    What failure looks like: the wake gate is rewritten to require both channels, and the
    defender lane — the one already in use — stops running whenever the questioner queue is
    empty, which is most of the time.
    """
    paths = D.make_paths(tmp_path, state_dir=tmp_path / "learning-state")
    D.seed(paths.findings, [defender_queue_row()])
    assert D.pending(W.questioner_channel(paths)) == []

    trigger = TwoLaneRecorder(D.recording(D.committing("family-lesson")),
                              run=(W.DEFENDER_CURATOR_MODULE,))
    rc, rec = drive(paths, trigger)

    assert rc == 0
    assert W.DEFENDER_CURATOR_MODULE in trigger.modules, (
        "the findings queue alone no longer wakes the drain")
    assert writable_sources(rec.only_request()) == {
        paths.lessons_dir, paths.lessons_questioner_dir}


def test_the_drain_still_decides_its_channels_without_a_direction_table(tmp_path):
    """SURVIVAL: the drain still names its channels rather than deriving them.

    Observably true: `_curator_queue_checks` returns exactly two `(file, knob)` pairs, one per
    channel, and `_CURATOR_MODULES` has one key per curator the drain triggers — all read as
    literals off the module, with no registry walk between them. #922's stated property is that
    a second channel returning is an EDIT HERE, IN A DIFF; this asserts the second channel
    arrived that way.

    What failure looks like: a helper is introduced that discovers channels from `LoopPaths`
    attributes or from a directory listing. The narrowing #922 paid for is silently undone, and
    the next deletion shrinks the drain with no error and no failing test.
    """
    paths = D.make_paths(tmp_path, state_dir=tmp_path / "learning-state")

    checks = drains._curator_queue_checks(paths)

    assert sorted(f.name for f, _knob in checks) == sorted(
        [paths.findings.file.name, W.QUESTIONER_QUEUE_FILENAME]), (
        f"the wake gate answers for {[f.name for f, _k in checks]}")
    assert len({knob for _f, knob in checks}) == 2, (
        "the two channels share one threshold knob, so neither can be tuned alone")
    assert W.QUESTIONER_CURATOR_MODULE in drains._CURATOR_MODULES


def test_the_lead_author_label_never_mounts_the_questioner_corpus(tmp_path):
    """The `lead_author_drain` label mounts the skills tree and NEITHER lessons corpus.

    Observably true: a box request built for the lead-author label has exactly
    `{skills_dir}` writable — no lessons corpus, and specifically not the new one. The two
    drain roles share one request builder and one worktree leaf, so the label is the only thing
    that separates them.

    KNOWN LIMIT, on the record: this is strictly weaker than S5's sentence. Because
    `_drain_box_request` never learns which QUEUE crossed threshold, a findings-only drive
    still mounts the questioner corpus rw in a batch that authors no questioner lesson. What is
    assertable at the label grain is asserted here.

    What failure looks like: the new corpus is added to the shared mount tuple above the label
    branch, and the lead author's box can write to a corpus its curator has no business in.
    """
    paths = D.make_paths(tmp_path, state_dir=tmp_path / "learning-state")

    request = drains._drain_box_request(
        paths.repo_root, "batch-1", "lead_author_drain", paths)

    assert writable_sources(request) == {paths.with_repo_root(paths.repo_root).skills_dir}, (
        f"the lead-author box's writable mounts are "
        f"{sorted(map(str, writable_sources(request)))}")
    assert paths.lessons_questioner_dir not in writable_sources(request)


def test_the_author_drain_box_mounts_exactly_the_two_lessons_corpora_writable(tmp_path):
    """The author drain's box mounts EXACTLY the two lessons corpora writable.

    Observably true: the request built for the `author_drain` label has writable sources
    `{lessons_dir, lessons_questioner_dir}` and read-only `{repo_root}`. This is the second of
    #922's exact-set tripwires (`test_922_spine.py:361`), gaining its second member here — kept
    EXACT rather than loosened to two `in` checks, because exactness is the property: a bare
    membership test passes on a request that mounts the whole checkout writable.

    What failure looks like: a static union of every corpus directory. The drain box then gets
    write access to trees its batch never touches, which is what #922's narrowing removed.
    """
    paths = D.make_paths(tmp_path, state_dir=tmp_path / "learning-state")
    wt = paths.with_repo_root(paths.repo_root)

    request = drains._drain_box_request(paths.repo_root, "batch-1", "author_drain", paths)

    assert writable_sources(request) == {wt.lessons_dir, wt.lessons_questioner_dir}, (
        f"the author drain box's writable mounts are "
        f"{sorted(map(str, writable_sources(request)))}")
    assert readonly_sources(request) == {paths.repo_root}, (
        "the drain box lost its read-only worktree mount — without it the exact set above "
        "could be satisfied by a request that mounts nothing at all")


def test_an_unrecognized_drain_label_mounts_no_lesson_corpus_writable(tmp_path):
    """An UNRECOGNIZED drain label mounts no lesson corpus writable.

    Observably true: a third label — one no branch names — produces a request with no writable
    lessons corpus at all. Today `_drain_box_request` is a two-way `if/else`, so a naive third
    label falls into the `else` and gets the DEFENDER corpus rw: a silent misroute of the same
    failure class as a silent widen.

    What failure looks like: a future drain role is added, spells its label slightly
    differently, and its box quietly gains write access to the lessons corpus — with the mount
    set reading as correct in every existing test.
    """
    paths = D.make_paths(tmp_path, state_dir=tmp_path / "learning-state")
    wt = paths.with_repo_root(paths.repo_root)

    request = drains._drain_box_request(paths.repo_root, "batch-1", "a_third_drain", paths)

    assert not ({wt.lessons_dir, wt.lessons_questioner_dir} & writable_sources(request)), (
        f"an unrecognized label got {sorted(map(str, writable_sources(request)))} writable — "
        "the two-way if/else fell through to the defender corpus")


# ---------------------------------------------------------------------------------------
# A2 — the two-curator tick is ONE unit
# ---------------------------------------------------------------------------------------


def test_one_author_drain_tick_opens_one_branch_and_one_pr_for_both_corpora(tmp_path):
    """One tick, one worktree, one box, one branch and one PR lease — covering both corpora.

    Observably true: a tick with both queues over threshold starts exactly one batch, creates
    exactly one box, and finishes exactly one batch, while triggering two curators. The tick is
    ONE UNIT (A2), and the shared drain lock is what keeps two curators from holding one
    worktree at once.

    What failure looks like: the second curator gets its own branch and PR. Every drain tick
    then opens two pull requests against one repository, and the two batches race each other's
    commits on the same worktree.
    """
    paths = D.make_paths(tmp_path, state_dir=tmp_path / "learning-state")
    D.seed(paths.findings, [defender_queue_row()])
    D.seed(W.questioner_channel(paths), [world_queue_row()])

    trigger = TwoLaneRecorder(D.recording(D.committing("lesson")))
    rc, rec = drive(paths, trigger)

    assert rc == 0
    starts = [e for e in rec.events if str(e).startswith("start_batch")]
    finishes = [e for e in rec.events if str(e).startswith("finish_batch")]
    assert len(starts) == 1, f"one tick started {len(starts)} batches: {rec.events}"
    assert len(finishes) <= 1, f"one tick finished {len(finishes)} batches: {rec.events}"
    assert len(rec.requests) == 1, f"one tick created {len(rec.requests)} boxes"
    assert len(trigger.modules) == 2


def test_each_curator_consumes_its_own_channel_and_is_scoped_to_its_own_corpus(tmp_path):
    """Per-curator consumption and per-curator corpus scoping.

    Observably true: after a tick in which the questioner curator authors, the questioner
    channel's rows are consumed and the findings channel's are not; and the questioner
    curator's commit pathspec names its own corpus dir alone. One shared batch does not mean
    one shared bookkeeping: a curator that consumed the other's rows would retire findings
    nothing authored.

    What failure looks like: the batch consumes both queues on success. A defender finding is
    then marked authored by a tick that only ran the questioner curator, and its lesson is
    never written.
    """
    paths = D.make_paths(tmp_path, state_dir=tmp_path / "learning-state")
    curator = W.mod("learning.author.questioner.run")
    D.seed(paths.findings, [defender_queue_row()])
    D.seed(W.questioner_channel(paths), [world_queue_row()])

    trigger = TwoLaneRecorder(D.recording(D.committing("questioner-lesson")),
                              run=(W.QUESTIONER_CURATOR_MODULE,))
    drive(paths, trigger)

    assert D.pending(paths.findings), (
        "the defender queue was consumed by a tick in which only the questioner curator ran")
    cfg = curator.build_questioner_config(paths)
    assert Path(cfg.corpus_dir) == paths.lessons_questioner_dir, (
        f"the questioner curator's corpus dir is {cfg.corpus_dir}")


@pytest.mark.parametrize("fault_class", [RuntimeError, TimeoutError],
                         ids=["escapes-the-catch", "swallowed-as-an-oserror"])
def test_a_faulting_curator_leaves_the_others_commit_and_consumed_markers_intact(
        tmp_path, fault_class):
    """One curator's fault leaves the other's landed commit AND CONSUMED MARKERS intact, and
    IS RECORDED — A2's three clauses, one assertion each.

    Observably true over TWO ticks — the defender curator authoring and committing, the
    questioner curator raising in each — because `hold_committed=True` is what this drain runs
    and a tick's committed rows stay queued for the NEXT tick to retire, so consumption is not
    observable at all on one tick:
      1. the defender's commit is still on `HEAD` and its lesson is still in the corpus — the
         tick does not roll back;
      2. the DEFENDER channel's rows are CONSUMED (they left `pending` and are named in that
         channel's own `consumed` file) while the QUESTIONER channel's are NOT — consumption is
         per-curator by A2's own decision, so a fault in one lane may neither retire the other
         lane's rows nor un-retire its own;
      3. the fault IS RECORDED, durably, on the faulting channel's own stuck report — and NOT on
         the surviving one's, which would blame the lane that worked.

    BOTH FAULT CLASSES, because the envelope is asymmetric and P-A measured it by execution
    (pa-2): `_run_curator_module` catches `(SubprocessError, OSError)` only, so a `RuntimeError`
    ESCAPES the catch and a `TimeoutError` is SWALLOWED by it — leaving `rc=None`, one
    `(continuing)` log line, and nothing an operator can read afterwards. The swallowed arm is
    the one where "is RECORDED" is false today, so a test that drove only the escaping class
    would pin the clause on the half that was never in doubt.

    A DURABLE RECORD, not a log line: `_log` writes to a stream nobody keeps, and A2 is an
    auto-resolved fork recorded for override — the human is meant to be able to see what it
    bought. The channel's own stuck report is the surface this suite fixes, because it is the
    shipped spelling for "this lane's tick could not be authored and here is the fault class and
    the rows it stranded" (`author/drain.py::_record_stuck` / `stuck_report_file`). If the human
    prefers another surface, that is a one-line change here and in the graph's seam list.

    What failure looks like: the tick's failure path discards the worktree changes wholesale —
    the defender's lesson is reverted for a fault in a lane it shares nothing with while its rows
    are already consumed, so it is never authored again. Or the fault is swallowed: a questioner
    curator that times out leaves a tick that half ran, with rows possibly consumed, and nothing
    an operator can read.
    """
    paths = D.make_paths(tmp_path, state_dir=tmp_path / "learning-state")
    D.seed(paths.findings, [defender_queue_row()])
    D.seed(W.questioner_channel(paths), [world_queue_row()])
    head_before = D.git(paths.repo_root, "rev-parse", "HEAD").stdout.strip()

    def faulting_tick(stem):
        trigger = TwoLaneRecorder(D.recording(D.committing(stem)),
                                  run=(W.DEFENDER_CURATOR_MODULE,),
                                  fail_on=(W.QUESTIONER_CURATOR_MODULE,),
                                  fault_class=fault_class)
        drive(paths, trigger)
        return trigger

    # TWO TICKS, because `hold_committed=True` is what this drain runs: the rows a tick commits
    # STAY queued for the next tick to retire (`test_922_a_full_findings_queue_alone_wakes_the
    # _drain` pins that), so consumption is only observable on the second — and a one-tick test
    # asserting "consumed" would fail against a correct implementation while a one-tick test
    # asserting "still queued" would pass against one that never consumes at all.
    first = faulting_tick("family-lesson")
    faulting_tick("must-not-author-twice")

    assert W.QUESTIONER_CURATOR_MODULE in first.modules, (
        f"the questioner curator was never triggered, so no fault was induced and every "
        f"assertion below holds vacuously: {first.modules}")
    head_after = D.git(paths.repo_root, "rev-parse", "HEAD").stdout.strip()
    assert head_after != head_before, (
        "the defender curator's landed commit was rolled back by the other lane's fault")
    assert list(paths.lessons_dir.glob("*.md")), (
        "the defender corpus lost its authored document to the other curator's fault")

    landed = D.pending_by_id(paths.findings)
    consumed = {r.get(paths.findings.id_key) for r in D.consumed(paths.findings)}
    assert "ep-1/b/0/1" not in landed, (
        f"the defender curator authored, committed and rotated, and its row is still queued: "
        f"{landed} — the next tick authors the same lesson again")
    assert "ep-1/b/0/1" in consumed, (
        f"the defender curator's consumed markers do not name its landed row: {consumed} — its "
        "commit is on HEAD and nothing records that the row behind it was retired")

    stranded = D.pending_by_id(W.questioner_channel(paths))
    assert "ep-1/b/0/0" in stranded, (
        f"the FAULTING curator's row was consumed anyway: {stranded} — a fault after "
        "consumption and before authoring retires a finding no lesson was ever written from, "
        "which is the failure per-curator consumption exists to prevent")
    assert not D.consumed(W.questioner_channel(paths)), (
        "the faulting lane wrote consumed markers for rows it never authored")

    stuck = D.stuck_records(W.questioner_channel(paths))
    assert stuck, (
        f"a {fault_class.__name__} took the questioner curator out of a tick that then committed "
        "and pushed, and left no durable record of it — A2's third clause is 'and IS RECORDED'; "
        "a log line in a stream nobody keeps is not a record an operator can read afterwards")
    assert any(r.get("fault_class") == fault_class.__name__ for r in stuck), (
        f"the stuck record names {[r.get('fault_class') for r in stuck]} rather than "
        f"{fault_class.__name__!r} — a record that cannot say WHICH fault stopped the lane "
        "cannot tell an outage from a bug")
    assert not D.stuck_records(paths.findings), (
        "the SURVIVING lane carries a stuck record — the fault was recorded against the curator "
        "that landed its work")


# ---------------------------------------------------------------------------------------
# The census: who must see the new root, and who must not
# ---------------------------------------------------------------------------------------


def test_every_corpus_enumerator_that_must_see_the_new_root_names_it(tmp_path):
    """The four enumerators that MUST see the new corpus name it IN THE STRUCTURE THAT ACTS.

    Observably true: `serialize.GROUPS` carries a group whose `dir` IS the new corpus root, and
    each of the three ratcheted lints' own exclusion tuples — `lint_shippable_surface`'s and
    `lint_ci_hygiene`'s `EXCLUDED_PREFIXES`, `lint_stale_refs`' `EXCLUDED_GREP_DIRS` — holds
    `defender/lessons-questioner` as a MEMBER. "Which lesson corpora exist" is not one symbol —
    that is the finding: eight independent spellings, four of which need a deliberate add or the
    corpus is invisible to the frontend and trips a ratcheted lint the moment a lesson lands.

    THE VALUES, NOT THE FILE TEXT, and that is the repair. This test read each file with `in`,
    so a mention in a comment — or in the wrong list in the right file — satisfied it, and
    cosmetic-only wiring passed. The lints are reached the way CI reaches them
    (`_by_path.load_lint_gate`: they are standalone programs, not an importable package), and
    the entries are compared with any trailing `/` stripped because the three tuples disagree
    about it (`"defender/lessons/"` vs `"defender/lessons"`) and that is a spelling, not a wire.

    What failure looks like: the corpus ships and CI goes red in `code-smells` on a lint whose
    connection to this change is two directories away — or the corpus is simply never rendered
    and nobody notices for months.
    """
    serialize = W.mod("learning.frontend.serialize")
    dirs = {str(spec.get("dir")) for spec in serialize.GROUPS.values()}
    assert W.QUESTIONER_CORPUS_DIRNAME in dirs, (
        f"no `serialize.GROUPS` entry renders {W.QUESTIONER_CORPUS_DIRNAME!r}; the groups render "
        f"{sorted(dirs)} — the corpus is authored and never shown")

    rel = W.QUESTIONER_CORPUS_REL.rstrip("/")
    gates = {"lint_shippable_surface": "EXCLUDED_PREFIXES",
             "lint_ci_hygiene": "EXCLUDED_PREFIXES",
             "lint_stale_refs": "EXCLUDED_GREP_DIRS"}
    missing = {}
    for stem, attr in gates.items():
        entries = {str(e).rstrip("/") for e in getattr(P.load_lint_gate(stem), attr)}
        if rel not in entries:
            missing[f"{stem}.{attr}"] = sorted(e for e in entries if "lessons" in e)

    assert missing == {}, (
        f"these gates do not EXCLUDE {rel!r} (their lesson-corpus entries are shown): {missing} "
        "— a mention anywhere else in the file is not the list the gate reads")


def test_the_new_corpus_root_is_admitted_by_no_runtime_read_or_write_scope(tmp_path):
    """The new corpus root widens NO runtime read or write scope.

    Observably true: the defender agent's own corpus tuple (`driver/_build.py::_CORPUS_DIRS`)
    and its permission policy's subdirectory tuple (`policies/_common.py::_CORPUS_SUBDIRS`)
    both still hold exactly `('lessons', 'skills', 'examples')`, and neither names the new
    root. These two are independently hardcoded copies of one list and must be edited in
    lockstep or main's confine tuple and its own `cat` grant disagree about what it may read —
    which is precisely why NEITHER may be edited here.

    What failure looks like: the root is added "so it is readable". The defender agent then has
    read access to a corpus of advice about how adversarial worlds are authored against it.
    """
    build = W.mod("runtime.driver._build")
    policy_common = W.mod("runtime.permission.policies._common")

    assert tuple(build._CORPUS_DIRS) == ("lessons", "skills", "examples"), (
        f"_CORPUS_DIRS is {build._CORPUS_DIRS}")
    assert tuple(policy_common._CORPUS_SUBDIRS) == ("lessons", "skills", "examples"), (
        f"_CORPUS_SUBDIRS is {policy_common._CORPUS_SUBDIRS}")
    assert W.QUESTIONER_CORPUS_DIRNAME not in build._CORPUS_DIRS
    assert W.QUESTIONER_CORPUS_DIRNAME not in policy_common._CORPUS_SUBDIRS


def test_nothing_lands_outside_the_declared_write_set(tmp_path, monkeypatch):
    """M1 to M5 write EXACTLY the five artifacts this change declares, and nothing else.

    Observably true: driving a whole episode — review, serve, grade, enqueue — over a tree
    snapshotted before and after leaves changes only at `review.yaml`, `samples.yaml`, the
    served ledgers, `judge.yaml` and the two queue files. Every new artifact of this change is
    accounted for by a demand; a sixth would be an unbudgeted sink in a tree nothing prunes.

    What failure looks like: a scratch file, a memo cache or a per-world debug dump lands in
    the episode dir. Nothing removes an episode dir, so an unbudgeted artifact per world per
    episode grows forever, and no test anywhere would object.
    """
    judge_mod = W.mod("learning.judge")
    paths = D.make_paths(tmp_path, state_dir=tmp_path / "learning-state")
    _base, _src, root = W.configured_layout(tmp_path, monkeypatch)
    doc = W.family_doc(worlds=[W.base_world(), W.world_doc(
        "b", ov=W.overlay(elastic=W.elastic_overlay(inject=[{"_id": "i1"}])))])
    ep = W.episode(tmp_path, doc=doc, root=root)
    W.archived_world(ep, "b")
    W.write_served(ep, "b", [W.served_row(world="b")])
    W.write_review(ep, worlds={"b": W.reviewed_world(label="b")})
    W.write_samples(ep)
    before = {p.relative_to(ep) for p in ep.rglob("*") if p.is_file()}

    judge_mod.grade_episode(ep, judge=W.FakeJudge(W.reply_document()),
                            queue_dir=paths.pending_dir)

    after = {p.relative_to(ep) for p in ep.rglob("*") if p.is_file()}
    allowed = {Path(W.JUDGE_NAME), Path(W.REVIEW_NAME), Path(W.SAMPLES_NAME)}
    new = {p for p in after - before
           if p not in allowed and p.parts[0] not in ("served", "worlds", "draws", "wire_logs")}
    assert new == set(), (
        f"the pass wrote artifacts outside the declared set: {sorted(map(str, new))}")
    queue_files = {p.name for p in paths.pending_dir.glob("*") if p.is_file()}
    assert queue_files <= {paths.findings.file.name, W.QUESTIONER_QUEUE_FILENAME,
                           paths.findings.append_lock.name,
                           W.questioner_channel(paths).append_lock.name,
                           paths.findings.consumed.name,
                           W.questioner_channel(paths).consumed.name, ".lock"}, (
        f"the queue directory gained {sorted(queue_files)}")
