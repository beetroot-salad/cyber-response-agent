"""#1135 — the three exemptions from the refusal's halt (R16: E1 the run-end enqueue, E2 the queue
page, E3 the judge), the page's planted failed folder (I10), the display readers of the describe
strings (F7 = JF8 reading A), and the pitfalls stage's own root (X6).

Every plant is a real entry made on disk in the test. Every oracle reads the tree by today's record
names (R14) through `lstat`/`readlink`, never through the verb under test. The queue page is built
through `serialize_queues.stamped_view(paths)`, what `frontend/build.main` calls; `build.main`
itself writes `lessons.json`/`queues.json` into the checkout, so no test here calls it. Shared
machinery and the names this suite coins are in `_spec1135.py`.
"""
from __future__ import annotations

import copy
import functools
import json
import logging
import os
from pathlib import Path

import pytest

from defender import run as run_py
from defender import run_common
from defender.run_repository import case_ref
from defender.learning import judge as judge_mod
from defender.learning.branch import cli as branch_cli
from defender.learning.core import config
from defender.learning.core.config import FatalConfigError, LoopPaths
from defender.learning.frontend import build as frontend_build
from defender.learning.frontend import serialize_queues
from defender.learning.leads import _lead_spine, pitfalls_curator
from defender.runtime import scrub as scrub_mod
from defender.scripts.visualize import visualize_episode
from defender.tests import _judge_921 as J
from defender.tests._lead_author_1134 import lead_trees
from defender.tests._repo import seed_skills_repo
from defender.tests._spec791 import (
    SpecTail,
    drive_tail,
    make_run_dir,
    plant_alert,
    satisfy_entrypoint_keys,
)
from defender.tests.learning_state_1135 import _spec1135 as S
from defender.learning.core.state import FINDINGS, LEAD_QUEUE_LOCK, PITFALLS, QUESTIONER_FINDINGS

ENV = "DEFENDER_LEARNING_STATE_DIR"

#: A marker no page or log can contain unless it read the planted link's target.
LEAKED = "outside-leak-1135"


# ---------------------------------------------------------------------------------------------
# helpers (this file only)
# ---------------------------------------------------------------------------------------------


def _judge_roots(tmp_path: Path, monkeypatch, root: Path) -> Path:
    """The judge's three roots inside `tmp_path`, the state root spelled through the env var (as
    the launcher's `_grade` resolves it). Returns the runs base."""
    runs_base = tmp_path / "defender-runs"
    monkeypatch.setenv(J.RUNS_BASE_ENV, str(runs_base))
    monkeypatch.setenv(J.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    monkeypatch.setenv(ENV, str(root))
    return runs_base


def _gradable_episode(tmp_path: Path) -> Path:
    """One accepted episode whose grade enqueues finding rows (the e2e spine's episode)."""
    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.staged_row("b")], "c": []},
                            dispositions={"a": "benign", "b": "malicious", "c": "malicious"})
    (ep / "worlds" / "b" / "report.md").write_text(J.report_text("benign"), encoding="utf-8")
    return ep


def _model() -> J.FakeJudge:
    """The judge's model seam: records its prompts, answers the scripted reply."""
    return J.FakeJudge(default=J.as_reply_text(J.reply_doc()))


def _exception_chain(exc: BaseException | None) -> list[BaseException]:
    seen: list[BaseException] = []
    while exc is not None and exc not in seen:
        seen.append(exc)
        exc = exc.__cause__ or exc.__context__
    return seen


def _record_text(record: logging.LogRecord) -> str:
    """A log record's message and every exception it carries, as one searchable text."""
    exc = record.exc_info[1] if record.exc_info else None
    return " ".join([record.getMessage(), *(repr(e) for e in _exception_chain(exc))])


def _page(paths: LoopPaths) -> dict:
    """The queue page's contract over `paths`, without its clock."""
    view = serialize_queues.stamped_view(paths)
    view.pop("generated_at", None)
    return view


def _channel(view: dict, name: str) -> dict:
    return next(c for c in view["channels"] if c["name"] == name)


# ---------------------------------------------------------------------------------------------
# E1 — the run-end enqueue logs and continues (#33)
# ---------------------------------------------------------------------------------------------


@pytest.mark.parametrize("at", ["queue-folder", "record"])
def test_e1_a_refused_curation_request_costs_the_investigation_nothing(tmp_path: Path, monkeypatch,
                                                                      caplog, at):
    """With a symlink planted at author-queue/ (or at the case's record name):
    run_common.enqueue_curation catches the StateRefused by name, logs "could not enqueue" naming
    the refused entry, and returns False; nothing is written through the link; the investigation's
    exit status and its render step are unchanged. run_common.enqueue_curation keeps its existing
    OSError arm beside the new one (X15's test drives it) and has a third arm for the missing
    root's FatalConfigError (3.1 C, F40; #13 drives it). A failure of any other class escapes as
    today (JF4 A)."""
    paths = S.built_paths(tmp_path)
    monkeypatch.setenv(ENV, str(paths.state_root))
    satisfy_entrypoint_keys(monkeypatch, tmp_path)
    run_dir = make_run_dir(tmp_path / "runs-1135", name="case-1135", disposition="benign")
    scrub_mod.scrub(run_dir)
    case_id = case_ref((run_dir / "alert.json").read_bytes())

    if at == "queue-folder":
        target = tmp_path / "outside" / "queue"
        target.mkdir(parents=True)
        planted = S.plant(paths.state_root / "author-queue", "symlink", target=target)
        named = (paths.state_root / "author-queue").name
    else:
        target = S.outside(tmp_path, "record.json", json.dumps({"case_id": LEAKED}) + "\n")
        planted = S.plant(paths.state_root / "author-queue" / f"{case_id}.json", "symlink", target=target)
        named = f"{case_id}.json"
    link_text = os.readlink(planted)
    outside_before = S.tree_snapshot(tmp_path / "outside")

    caplog.set_level(logging.INFO)
    answered: list[bool] = []
    escaped = S.caught(lambda: answered.append(
        run_common.enqueue_curation(run_dir, run_dir / "alert.json")))
    assert escaped is None, f"the refused curation request raised {escaped!r} into the investigation"
    assert answered == [False], f"a refused curation request answered {answered!r}, not False"
    logged = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
    assert any("enqueu" in m.lower() and named in m for m in logged), \
        f"no 'could not enqueue' line names the refused entry {named}: {logged}"
    assert S.tree_snapshot(tmp_path / "outside") == outside_before, \
        "the request was written through the planted link"
    assert S.entry_kind(planted) == "link", "the planted link was replaced or removed"
    assert os.readlink(planted) == link_text, "the planted link was re-pointed"

    # `plant_alert`'s default bytes are `make_run_dir`'s, so the investigation's own case_ref is
    # `case_id` and its own enqueue meets the same plant. Deliberate: keep the bytes equal.
    tail = SpecTail(paths)
    rc = drive_tail(run_py.main, plant_alert(tmp_path / "investigation"), tail)
    assert rc == 0, f"a refused curation request changed the investigation's exit status to {rc}"
    assert "visualize" in tail.names, \
        f"the refused curation request took the render step with it (ran {tail.names})"
    assert S.tree_snapshot(tmp_path / "outside") == outside_before, \
        "the investigation's own enqueue wrote through the planted link"

    # Positive control: the same request with the plant gone is enqueued at today's name.
    os.unlink(planted)
    answered.clear()
    assert S.caught(lambda: answered.append(
        run_common.enqueue_curation(run_dir, run_dir / "alert.json"))) is None, \
        "the unplanted enqueue raised"
    assert answered == [True], f"the unplanted enqueue answered {answered!r}"
    assert S.entry_kind(paths.state_root / "author-queue" / f"{case_id}.json") == "file", \
        "the unplanted request is not at author-queue/<case_id>.json (R14)"
    assert S.LearningState.open(paths).has_requests(), \
        "the handle does not see the request the run-end enqueue wrote"


# ---------------------------------------------------------------------------------------------
# E2 — the queue page counts a refused sidecar unreadable (#34)
# ---------------------------------------------------------------------------------------------


def test_e2_the_queue_page_counts_a_refused_sidecar_unreadable(tmp_path: Path):
    """With a symlink planted at a channel's deadletter (graveyard) file, the queue page still
    builds: that channel's unreadable count includes the refused sidecar; none of the link
    target's rows appear on the page; no other field of the page contract changes (R16: no names,
    no contract change); building the page writes nothing (JF17).

    The tree also holds one torn live delivery record in the pending_delivery_dir (JF17, D20):
    the page reads it (it counts it unreadable, as today) and never quarantines it, because
    quarantining an unreadable delivery record is the drain's verb, never the page's. Each page
    build, before and after the plant, leaves the tree byte for byte as it found it."""
    paths = S.built_paths(tmp_path)
    S.write_jsonl(paths.state_root / FINDINGS.queue, [{"finding_id": "ep-1/b/0/0", "run_id": "ep-1"}])
    graveyard = paths.state_root / QUESTIONER_FINDINGS.deadletter
    S.write_jsonl(graveyard, [{"finding_id": "ep-2/c/0/0", "row": {"finding_id": "ep-2/c/0/0"},
                               "deadletter_reason": "retired", "attempts": 3}])
    torn = paths.state_root / "_pending_delivery" / "lessons-1135torn.json"
    torn.parent.mkdir(parents=True)
    torn.write_text('{"branch": "lessons/1135torn", "pr_ur', encoding="utf-8")
    seeded = S.tree_snapshot(tmp_path)
    before = _page(paths)
    assert S.tree_snapshot(tmp_path) == seeded, (
        "building the page wrote to disk: the torn delivery record was quarantined or rewritten "
        "(JF17: that is the drain's verb, never the page's)")
    assert before["quarantine"]["deliveries"]["unreadable"] >= 1, \
        f"the page did not read the torn delivery record: {before['quarantine']['deliveries']}"

    target = S.outside(tmp_path, "graveyard.jsonl", json.dumps(
        {"finding_id": LEAKED, "row": {"finding_id": LEAKED}, "deadletter_reason": LEAKED}) + "\n")
    planted = S.plant(paths.state_root / FINDINGS.deadletter, "symlink",
                      target=target)
    on_disk = S.tree_snapshot(tmp_path)

    page: dict = {}
    built = S.caught(lambda: page.update(_page(paths)))
    assert built is None, f"the queue page did not build over a refused sidecar: {built!r}"
    assert LEAKED not in json.dumps(page), "the page shows rows read through the planted link"
    assert _channel(page, "findings")["unreadable"] == _channel(before, "findings")["unreadable"] + 1, \
        "the findings channel's unreadable count does not include the refused graveyard"
    expected = copy.deepcopy(before)
    _channel(expected, "findings")["unreadable"] += 1
    assert page == expected, "a field of the page contract other than the unreadable count changed"
    assert S.tree_snapshot(tmp_path) == on_disk, "building the page wrote to disk (JF17)"
    assert os.readlink(planted) == str(target), "the planted link was changed"

    state = S.LearningState.open(paths)
    answer: list = []
    read = S.caught(lambda: answer.append(state.deadletter_rows(S.coined("FINDINGS"))))
    assert read is None, f"the display read raised the refusal instead of answering it ({read!r})"
    assert LEAKED not in repr(answer), "the display read answered the link target's rows"
    kept = [r.get("finding_id") for r in S.rows_of(state.deadletter_rows(S.coined("QUESTIONER_FINDINGS")))]
    assert kept == ["ep-2/c/0/0"], f"the plain graveyard beside the refused one reads {kept}"


# ---------------------------------------------------------------------------------------------
# E3 — the judge logs and continues (#35)
# ---------------------------------------------------------------------------------------------


@pytest.mark.parametrize("fault", ["linked-queue", "missing-root"])
def test_e3_a_refused_findings_queue_leaves_the_launch_unaffected(tmp_path: Path, monkeypatch,
                                                                  caplog, fault):
    """With a symlink planted at the findings channel's queue file and a grade that enqueues at
    least one row: grade_episode raises StateRefused out of the enqueue; the launcher's _grade logs
    a warning naming the refused entry; the launch continues with its own outcome unchanged (R13);
    nothing is appended through the link. A missing root takes the same route (3.1 C):
    LearningState.open raises FatalConfigError naming the root and DEFENDER_LEARNING_STATE_DIR,
    _grade's catch logs it as a warning, and the launch continues. Whether judge.yaml is written
    is not asserted (JF5 A).

    "Its own outcome unchanged" is observed on the episode's archive: every record the episode
    held before the grade (its manifest, review, world archives and ledgers) is byte for byte
    the same after the failed grade, which may only add its own files (today's grade only adds,
    probed at base). Positive control: with the fault removed, a fresh episode's grade logs no
    warning and appends its rows to the findings queue at today's name."""
    if fault == "linked-queue":
        paths = S.built_paths(tmp_path)
        root = paths.state_root
        target = S.outside(tmp_path, "findings.jsonl", json.dumps({"finding_id": LEAKED}) + "\n")
        planted = S.plant(paths.state_root / FINDINGS.queue, "symlink", target=target)
    else:
        root = tmp_path / "absent" / "learning-state"
    runs_base = _judge_roots(tmp_path, monkeypatch, root)
    ep = _gradable_episode(tmp_path)
    archived = S.tree_snapshot(ep)

    caplog.set_level(logging.INFO)
    escaped = S.caught(lambda: branch_cli._grade(ep, episode_id="ep-1135", judge=_model(),
                                                 runs_base=runs_base))
    assert escaped is None, f"_grade raised {escaped!r} into the launch"
    after = S.tree_snapshot(ep)
    rewritten = sorted(k for k, v in archived.items() if after.get(k) != v)
    assert not rewritten, f"the failed grade changed the episode's own records: {rewritten}"
    warned = [r for r in caplog.records if r.levelno == logging.WARNING and r.exc_info]

    if fault == "linked-queue":
        refused = [r for r in warned if S.is_refusal(r.exc_info[1])]
        assert refused, ("_grade logged no warning carrying the StateRefused out of the enqueue: "
                         f"{[_record_text(r) for r in warned]}")
        assert any("findings.jsonl" in _record_text(r) for r in refused), \
            f"the warning does not name the refused entry: {[_record_text(r) for r in refused]}"
        assert target.read_text(encoding="utf-8") == json.dumps({"finding_id": LEAKED}) + "\n", \
            "the grade appended through the planted link"
        assert S.entry_kind(planted) == "link", "the planted link was replaced or removed"
        assert os.readlink(planted) == str(target), "the planted link was re-pointed"
        reread = S.caught(lambda: S.LearningState.open(paths).rows(S.coined("FINDINGS")))
        assert S.is_refusal(reread), f"the handle's read of the linked queue answered {reread!r}"
    else:
        named = [r for r in warned if any(isinstance(e, FatalConfigError)
                                          for e in _exception_chain(r.exc_info[1]))]
        assert named, ("_grade logged no warning carrying the missing root's FatalConfigError: "
                       f"{[_record_text(r) for r in warned]}")
        assert any(str(root.resolve()) in _record_text(r) and ENV in _record_text(r)
                   for r in named), \
            f"the warning does not name the root and {ENV}: {[_record_text(r) for r in named]}"
        assert S.entry_kind(root.parent) == "absent", "the grade created the missing root"
        opened = S.caught(lambda: S.LearningState.open(config.loop_paths()))
        assert isinstance(opened, FatalConfigError), \
            f"LearningState.open over the missing root answered {opened!r}"

    # Positive control: the fault removed (the link unplanted, or the root created by the
    # operator), a fresh episode's grade runs through and enqueues at today's name (R14).
    if fault == "linked-queue":
        os.unlink(planted)
    else:
        root.mkdir(parents=True)
    control = _gradable_episode(tmp_path / "control")
    caplog.clear()
    escaped = S.caught(lambda: branch_cli._grade(control, episode_id="ep-1135-control",
                                                 judge=_model(), runs_base=runs_base))
    assert escaped is None, f"the control's _grade raised {escaped!r}"
    failed = [_record_text(r) for r in caplog.records if r.levelno >= logging.WARNING]
    assert not failed, f"the control's grade logged a failure with no fault planted: {failed}"
    queued = S.jsonl_rows(root / "_pending" / "findings.jsonl")
    assert queued, "the control's grade appended no rows at today's queue name"
    assert len(queued) == J.judge_record(control).get("enqueued_rows"), (
        f"the control's grade appended {len(queued)} rows, not the episode's enqueued count")


# ---------------------------------------------------------------------------------------------
# I10 — the page's failed folder is a planted entry (s_i10)
# ---------------------------------------------------------------------------------------------


def test_1135_the_failed_folder_is_a_planted_entry_when_the_page_lists_failed_requests(
        tmp_path: Path):
    """The planted failed folder is counted unreadable on the page and the page still builds
    (E2); the other channels and the other failed records show normally, and building the page
    changes nothing on disk."""
    paths = S.built_paths(tmp_path)
    S.write_jsonl(paths.state_root / FINDINGS.queue, [{"finding_id": "ep-1/b/0/0", "run_id": "ep-1"}])
    delivered = paths.state_root / "_pending_delivery" / "failed" / "delivery-1135.json"
    delivered.parent.mkdir(parents=True)
    delivered.write_text(json.dumps({"failed": "push refused", "run_dir": "/runs/r"}) + "\n",
                         encoding="utf-8")
    before = _page(paths)

    elsewhere = tmp_path / "outside" / "failed"
    elsewhere.mkdir(parents=True)
    (elsewhere / f"{LEAKED}.json").write_text(
        json.dumps({"case_id": LEAKED, "failed": LEAKED}) + "\n", encoding="utf-8")
    planted = S.plant(paths.state_root / "author-queue" / "failed", "symlink", target=elsewhere)
    on_disk = S.tree_snapshot(tmp_path)

    page: dict = {}
    built = S.caught(lambda: page.update(_page(paths)))
    assert built is None, f"the queue page did not build over a planted failed folder: {built!r}"
    assert LEAKED not in json.dumps(page), "the page lists a failed record read through the link"
    markers = page["quarantine"]["markers"]
    assert markers["unreadable"] == before["quarantine"]["markers"]["unreadable"] + 1, \
        f"the planted failed folder is not counted unreadable: {markers}"
    assert [r["identity"] for r in markers["rows"]] == ["delivery-1135"], \
        f"the other failed records do not show normally: {markers['rows']}"
    assert _channel(page, "findings")["depth"] == {"queued": 1}, \
        "the findings channel does not show normally beside the planted folder"
    expected = copy.deepcopy(before)
    expected["quarantine"]["markers"]["unreadable"] += 1
    assert page == expected, "a field of the page other than the markers' unreadable count changed"
    assert S.tree_snapshot(tmp_path) == on_disk, "building the page changed something on disk"
    assert S.entry_kind(planted) == "link", "the planted failed folder was replaced or removed"

    state = S.LearningState.open(paths)
    answer: list = []
    read = S.caught(lambda: answer.append(state.failed_requests()))
    assert read is None, f"failed_requests raised the refusal instead of answering it ({read!r})"
    assert LEAKED not in repr(answer), "failed_requests answered a record read through the link"


# ---------------------------------------------------------------------------------------------
# #43 — every display reader of a describe string stays coherent (F7 = JF8 reading A)
# ---------------------------------------------------------------------------------------------


def test_describe_strings_keep_every_display_reader_coherent(tmp_path: Path, monkeypatch):
    """Every reader of a describe string agrees with the record it names: the judge yaml's
    enqueued_to/world_enqueued_to come from describe, and reading the queue back through
    enqueued_to (_judge_921.enqueued_rows, test_921_enqueue_gate.py:531) finds the rows the grade
    appended; the queue page's state_root field (rendered by frontend/build.py) and
    visualize_episode's "enqueued to" line render the same string."""
    paths = S.built_paths(tmp_path)
    runs_base = _judge_roots(tmp_path, monkeypatch, paths.state_root)
    ep = _gradable_episode(tmp_path)
    state = S.LearningState.open(paths)

    graded = S.caught(lambda: judge_mod.grade_episode(ep, judge=_model(), runs_base=runs_base,
                                                      draws=1, state=state))
    assert graded is None, f"grade_episode did not grade on the handle it was handed (RF5): {graded!r}"
    record = J.judge_record(ep)
    findings = state.describe(S.coined("FINDINGS"))
    questioner = state.describe(S.coined("QUESTIONER_FINDINGS"))
    assert isinstance(findings, str), f"describe(FINDINGS) is not a string: {findings!r}"
    assert findings == os.path.realpath(paths.state_root / FINDINGS.queue), \
        f"describe(FINDINGS) is not the queue's absolute path string: {findings!r}"
    assert isinstance(questioner, str), f"describe(QUESTIONER_FINDINGS) is not a string: {questioner!r}"
    assert questioner == os.path.realpath(paths.state_root / QUESTIONER_FINDINGS.queue), \
        f"describe(QUESTIONER_FINDINGS) is not the queue's absolute path string: {questioner!r}"

    assert record.get("enqueued_to") == findings, \
        f"judge.yaml's enqueued_to {record.get('enqueued_to')!r} is not describe's {findings!r}"
    assert record.get("world_enqueued_to") == questioner, \
        f"judge.yaml's world_enqueued_to {record.get('world_enqueued_to')!r} is not {questioner!r}"
    read_back = J.enqueued_rows(record)
    assert record.get("enqueued_rows", 0) >= 1, f"the grade enqueued {record.get('enqueued_rows')!r} rows"
    assert len(read_back) == record["enqueued_rows"], \
        f"reading enqueued_to back finds {len(read_back)} rows, the grade says {record['enqueued_rows']}"
    assert read_back == S.jsonl_rows(paths.state_root / FINDINGS.queue), \
        "enqueued_to does not name the queue the grade appended to"

    shown = visualize_episode.build_page(ep)
    assert f"enqueued to {findings}" in shown, \
        "visualize_episode's defender 'enqueued to' line does not render describe(FINDINGS)"
    assert f"enqueued to {questioner}" in shown, \
        "visualize_episode's questioner 'enqueued to' line does not render describe(QUESTIONER_FINDINGS)"

    view = _page(paths)
    assert findings == os.path.join(view["state_root"], "_pending", "findings.jsonl"), \
        f"the page's state_root {view['state_root']!r} is not the root describe names"
    assert view["state_root"] in frontend_build.render_queues(view), \
        "frontend/build.py does not render the page's state_root"


# ---------------------------------------------------------------------------------------------
# #12 — the pitfalls stage writes under its own root (X6)
# ---------------------------------------------------------------------------------------------


def test_pitfalls_curator_on_a_non_default_root_writes_nothing_under_the_default_root(
        tmp_path: Path, monkeypatch):
    """run_pitfalls driven on a handle over a non-default root writes nothing under the default
    root: the pitfalls stage's learning_run_dir is the held root's _pending_leads (from
    stage_dir), and no folder, trace or budget.json appears under
    the default root's `_pending_leads/`.

    Only the model is out of reach (JF12): the real spawn (`_spawn_author_agent`, F32) runs its
    own folder preparation, and the stage stops at the model's key sourcing, because the
    configured model is one no provider serves."""
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "1")
    monkeypatch.setenv("LEAD_AUTHOR_MODEL", "no-such-model-1135")
    paths = S.built_paths(tmp_path, repo_root=seed_skills_repo(tmp_path / "repo"))
    S.write_jsonl(paths.state_root / PITFALLS.queue, [{
        "schema_version": 1, "pitfall_id": "r:l-000:0", "source_run": "r", "system": "elastic",
        "query_id": "elastic.esql", "goal": "g", "executed_query": "bad pipe",
        "stderr_digest": "exit=1; mismatched input", "error_class": "agent-fixable",
    }])
    default = (config.DEFAULT_PATHS.state_root / LEAD_QUEUE_LOCK.file).parent
    default_kind = S.entry_kind(default)
    default_before = S.tree_snapshot(default)

    spawned: list[dict] = []

    def spawn(**kw):
        spawned.append(kw)
        return _lead_spine._spawn_author_agent(**kw)

    try:
        escaped = S.caught(lambda: pitfalls_curator.run_pitfalls(
            paths=paths, trees=lead_trees(paths),
            invoke=functools.partial(pitfalls_curator._invoke_pitfalls_agent, spawn=spawn)))
        default_after = (S.entry_kind(default), S.tree_snapshot(default))
    finally:
        if default_kind == "absent" and S.entry_kind(default) == "dir" and not any(default.iterdir()):
            default.rmdir()  # what today's import-frozen spawn made in the checkout

    assert len(spawned) == 1, f"the pitfalls stage was spawned {len(spawned)} times (escaped {escaped!r})"
    stage_dir = Path(spawned[0]["learning_run_dir"])
    assert stage_dir.resolve() == (paths.state_root / LEAD_QUEUE_LOCK.file).parent.resolve(), \
        f"the pitfalls stage's learning_run_dir is {stage_dir}, not the held root's _pending_leads"
    assert isinstance(escaped, FatalConfigError), \
        f"the stage did not stop at the model, the one thing out of reach: {escaped!r}"
    assert "no-such-model-1135" in str(escaped), f"the stage stopped on another config fault: {escaped}"
    assert default_after == (default_kind, default_before), \
        f"a folder, trace or budget.json appeared under {default}: {default_after}"
    held = S.LearningState.open(paths).stage_dir(config.LEAD_AUTHOR_DRAIN_LABEL)
    assert isinstance(held, Path), f"stage_dir(LEAD_AUTHOR_DRAIN_LABEL) answered {held!r}, not a Path"
    assert held.resolve() == stage_dir.resolve(), \
        f"stage_dir(LEAD_AUTHOR_DRAIN_LABEL) is {held}, not the folder the stage was handed"
