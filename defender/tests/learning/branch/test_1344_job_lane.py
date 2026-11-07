"""#1344: what a family step does for a learning job: the fork pick, siblings in turn, the cost reader, the judge's
job-lane sink, publishing, and nothing outliving its worker. No database. The end record is
`test_1344_job_end.py`; the post-step is `test_1344_post_step.py`; the worker's side is `tests/jobs/`.

Names the design leaves open are fixed in `.contract-first/interface.md`; this file uses them as written.
"""
from __future__ import annotations

import json
import os
import random
import signal
import subprocess
import sys
import textwrap
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from defender.learning.core.state import FINDINGS, QUESTIONER_FINDINGS
from defender.records._episode_handle import Episode
from defender.records.formats import BASE_ROLE, load_family
from defender.tests.learning.branch.test_947_triplet_launcher import _BASE, _calls, _launch
from defender.tests.learning.oracle.live_contracts import _spec1224 as S
from defender.tests.support.learning.branch import _triplet_947 as T
from defender.tests.support.learning.core import _state1135
from defender.tests.support.learning.core._state1135 import env_state
from defender.tests.support.learning.judge import _judge_921 as J
from defender.tests.support.shared._fixture_uuid import fixture_uuid

JOB = fixture_uuid("1344-job")


@pytest.fixture(autouse=True)
def _roots(tmp_path, monkeypatch):
    monkeypatch.setenv(T.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))


# --- the job entry in-process: shared by this slice's three files -----------------------------------------


class Watch(T.FakeAgent):
    """The questioner double, which also reads the job's progress record each time it is paid for."""

    def __init__(self, *replies: Any, fail: BaseException | None = None) -> None:
        super().__init__(*replies)
        self.fail = fail
        self.record: Path | None = None
        self.progress_seen: list[dict | None] = []

    def __call__(self, prompt: str, **kw: Any) -> Any:
        self.progress_seen.append(_read_json(self.record))
        if self.fail is not None:
            raise self.fail
        return super().__call__(prompt, **kw)


def _read_json(path: Path | None) -> dict | None:
    if path is None or not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


@dataclass
class Ran:
    end: dict | None
    progress: dict | None
    questioner: Watch
    spawn: Any
    judge: Any
    ep: Path
    src: Path
    tenant: str
    exit: object


def _unexpected_sigterm(_signum, _frame):
    raise AssertionError("SIGTERM reached the test process: the entry installed no handler of its own")


def run_entry(  # noqa: PLR0913 — one keyword per seam a scenario may replace
        tmp_path, *, candidates=None, spawn=None, judge=None, questioner=None, live_tree=None,
        oracle=None, fix_source=None, job=JOB, late_signal_ok=False) -> Ran:
    """The job entry in-process over `_spec1224`'s fixture tenant; every paid seam a recording double."""
    est = S.estate(tmp_path)
    _base, src = S.source_run(tmp_path, est, calls=_calls())
    if fix_source is not None:
        fix_source(src)
    tenant = src.parent.parent.name
    authored = S.questioner_for()
    asking = questioner if questioner is not None else Watch(*authored.replies)
    runs = Path(os.environ["DEFENDER_DATA_ROOT"]) / tenant / "runs"
    asking.record = runs / f"{job}.learning-progress.json"
    spawn = spawn if spawn is not None else J.FakeSibling()
    judge = judge if judge is not None else J.FakeJudge(
        default=J.as_reply_text(J.reply_doc(bucket="none", systems=[])))
    seams = dict(
        questioner=asking, preflight=S.no_preflight, live_tree=live_tree or T.source_capture(),
        roster=est.roster(), judge=judge,
        oracle=(oracle or S.oracle(then=S.submit(_BASE, S.EMPTY_CLAIM))).model,
        verifier=S.passing_verifier().model, directory=T.launcher_directory(tenant), spawn=spawn,
        candidates=candidates if candidates is not None else (lambda *_a: [T.BRANCH_MESSAGE_ID]))
    argv = ["--job", job, "--tenant", tenant, "--source", src.name, "--parent-pid", str(os.getppid())]
    from defender.learning.branch import job_entry

    previous = signal.signal(signal.SIGTERM, signal.SIG_IGN if late_signal_ok else _unexpected_sigterm)
    outcome: object = None
    try:
        try:
            outcome = job_entry.main(argv, **seams)
        except SystemExit as stop:
            outcome = stop.code
    finally:
        signal.signal(signal.SIGTERM, previous)
    return Ran(end=_read_json(runs / f"{job}.learning-end.json"),
               progress=_read_json(runs / f"{job}.learning-progress.json"), questioner=asking, spawn=spawn,
               judge=judge, ep=Path(os.environ["DEFENDER_DATA_ROOT"]) / tenant / "episodes" / job, src=src,
               tenant=tenant, exit=outcome)


# --- O3: the fork pick --------------------------------------------------------------------------------


def _driven_source(tmp_path, turns):
    """A real scripted source run recording real fork snapshots, as the #1255 suite drives one."""
    from defender.tests.e2e._lead_zero_808 import VerbRecorder, answer_hits, elastic_backend, hit
    from defender.tests.e2e._replay_harness import Turn
    from defender.tests.support.runtime.state import _1255_snapshot as R

    query = Turn(tool_calls=[("query", {"system": "elastic", "verb": "query",
                                        "params": {"native_query": "user.name:dev.dana"}})])
    docs = [hit(ts="2026-05-25T15:20:00.000Z")]
    return R, R.drive_source(
        tmp_path, turns(R, R.chunks(3)),
        leads={lead: (query, Turn(text=f"summary of {lead}")) for lead in ("l-001", "l-002")},
        verbs=elastic_backend(VerbRecorder(), answer_hits(docs)))


def _run_of(source):
    from defender.tests.support.shared.contracts._spec1077 import fixture_run

    return fixture_run(source.run_dir)


@pytest.mark.e2e
def test_o3_the_candidates_are_mains_gather_calls_and_no_other_response(tmp_path):
    """Candidates: MAIN's gather responses, not its other tool calls, not the automatic lead. (O3, D-B)"""
    pytest.importorskip("pydantic_ai")
    R, source = _driven_source(tmp_path, lambda R, c: (
        R.append(c[0]), R.dispatch("l-001"), R.echo("x"), R.dispatch("l-002"), R.done()))
    _append, first, _echo, second = R.tool_calling_responses(source.store)
    named = {r: [c.tool_name for c in R.calls_of(R.message_at(source.store, r))] for r in (first, second)}
    assert named == {first: ["gather"], second: ["gather"]}, "premise: the script's two dispatches"
    assert R.CORRELATION_LEAD in source.gather.asked, "premise: the harness ran its automatic lead too"
    from defender.learning.branch.fork_pick import fork_candidates

    assert fork_candidates(source.store, _run_of(source)) == [first, second]


@pytest.mark.e2e
def test_o3_a_source_with_tool_calls_but_no_gather_has_no_candidate(tmp_path):
    """An `append_block` was a legal operator fork point; for a job it is none. (O3)"""
    pytest.importorskip("pydantic_ai")
    R, source = _driven_source(tmp_path, lambda R, c: (R.append(c[0]), R.echo("x"), R.done()))
    assert R.tool_calling_responses(source.store), "premise: MAIN called tools"
    from defender.learning.branch.fork_pick import fork_candidates

    assert fork_candidates(source.store, _run_of(source)) == []


@pytest.mark.e2e
def test_o3_a_gather_that_fails_admission_is_dropped_and_the_rest_stay(tmp_path):
    """A gather with nothing open in the frontier is no candidate; the later admitted one still is. (O3)"""
    pytest.importorskip("pydantic_ai")
    R, source = _driven_source(tmp_path, lambda R, c: (
        R.dispatch("l-001"), R.append(c[0]), R.dispatch("l-002"), R.done()))
    early, _append, late = R.tool_calling_responses(source.store)
    assert [c.tool_name for c in R.calls_of(R.message_at(source.store, early))] == ["gather"]
    from defender.learning.branch.fork_pick import fork_candidates

    assert fork_candidates(source.store, _run_of(source)) == [late]


@pytest.mark.e2e
def test_o3_when_every_gather_fails_admission_there_is_no_candidate(tmp_path):
    """Dropping is per candidate: a source whose only gather is inadmissible yields none, not an error. (O3)"""
    pytest.importorskip("pydantic_ai")
    R, source = _driven_source(tmp_path, lambda R, c: (R.dispatch("l-001"), R.done()))
    assert R.tool_calling_responses(source.store), "premise: a gather was called"
    from defender.learning.branch.fork_pick import fork_candidates

    assert fork_candidates(source.store, _run_of(source)) == []


def test_o3_the_pick_is_uniform_over_the_candidates():
    """Each of three candidates is picked about a third of the time, whatever its position. (O3, D-B)"""
    from defender.learning.branch.fork_pick import pick_fork

    candidates = [11, 23, 37]
    draws = [pick_fork(candidates, rng=random.Random(seed)) for seed in range(900)]
    counts = {c: draws.count(c) for c in candidates}
    assert set(counts) == set(candidates)
    assert all(240 <= n <= 360 for n in counts.values()), counts


def test_o3_the_pick_is_written_to_the_progress_record_before_any_spend(tmp_path):
    """When the questioner is first paid for, the progress record already names the fork. (O3)"""
    ran = run_entry(tmp_path)
    assert ran.questioner.progress_seen, "premise: the questioner was reached"
    first = ran.questioner.progress_seen[0]
    assert first is not None, "nothing was recorded before the first spend"
    assert first["fork_message_id"] == T.BRANCH_MESSAGE_ID
    assert ran.progress["fork_message_id"] == T.BRANCH_MESSAGE_ID


# --- O4: one job, one slot ---------------------------------------------------------------------------


def _control_of(ep: Path) -> str:
    with Episode.open(ep) as episode:
        family = load_family(episode.view(), expected_episode_id=ep.name)
    return next(w.label for w in family.worlds if w.role == BASE_ROLE)


def _five_worlds() -> dict:
    return S.family_v2(worlds=[
        S.control_world("a"), S.world_v2("b", facts=[S.fact("f1")]),
        S.world_v2("c", role="C", facts=[S.fact("f2", "bob reset carol's password from 10.0.0.9",
                                                ("bob", "carol", "10.0.0.9"))]),
        S.world_v2("d", role="D", facts=[S.fact("f3", "dana read the payroll share", ("dana",))]),
        S.world_v2("e", role="E", facts=[S.fact("f4", "erin ran a new scheduled task", ("erin",))])])


def test_o4_a_jobs_siblings_run_in_turn_control_first_each_with_the_whole_rate(tmp_path, monkeypatch):
    """No overlap, the control first, the episode's whole rate per sibling, the episode named by the job. (O4)"""
    from defender.learning.core.config import KNOB_RATE

    monkeypatch.setenv(KNOB_RATE, "6.0")
    slow = T.FakeSpawn(fault=T.Fault(delay=0.1))
    rc, spawn, ep, message = _launch(tmp_path, spawn=slow, argv_extra=("--job-id", JOB))

    assert rc == 0, message or "exit 2: the launcher's usage refused the flag"
    assert ep.name == JOB
    assert sorted(spawn.worlds) == list(T.WORLDS), message
    assert not spawn.overlap, "siblings overlapped"
    assert spawn.worlds[0] == _control_of(ep)
    assert [float(la["env"][KNOB_RATE]) for la in spawn.launches] == [6.0] * len(T.WORLDS)


def test_o4_the_operator_lane_still_starts_its_worlds_together_with_the_rate_split(tmp_path, monkeypatch):
    """Without `--job-id`: overlapping worlds, a third of the rate each, an episode id of its own. (D9)"""
    from defender.learning.core.config import KNOB_RATE

    monkeypatch.setenv(KNOB_RATE, "6.0")
    rc, spawn, ep, message = _launch(tmp_path, spawn=T.FakeSpawn(fault=T.Fault(delay=0.25)))

    assert rc == 0, message
    assert spawn.overlap, "the operator lane's worlds ran one after another"
    assert [float(la["env"][KNOB_RATE]) for la in spawn.launches] == [2.0] * len(T.WORLDS)
    assert ep.name != JOB


def test_o4_a_failed_control_ends_a_jobs_family_before_any_other_world_starts(tmp_path):
    """The control fails: it is the only sibling that started. (O4)"""
    rc, spawn, ep, message = _launch(tmp_path, spawn=T.FakeSpawn(exits={"a": 1}), argv_extra=("--job-id", JOB))
    assert spawn.worlds == ["a"], (rc, message, spawn.worlds)
    assert S.read_world_record(ep, "a")["reason"] == S.REASON_DID_NOT_FINISH


def test_o4_two_failed_siblings_stop_a_jobs_family_and_record_the_worlds_that_never_started(tmp_path):
    """b and c fail: d and e are never started and each has a world record. (O4, UNUSABLE_AT)"""
    rc, spawn, ep, message = _launch(
        tmp_path, spawn=T.FakeSpawn(exits={"b": 1, "c": 1}), argv_extra=("--job-id", JOB),
        questioner=S.questioner_for(_five_worlds()))
    assert spawn.worlds == ["a", "b", "c"], (rc, message, spawn.worlds)
    for label in ("d", "e"):
        record = S.read_world_record(ep, label)
        assert record is not None, f"world {label} never started and left no record"
        assert record["reason"] == S.REASON_DID_NOT_FINISH


def test_o4_one_failed_sibling_does_not_stop_a_jobs_family(tmp_path):
    """Control for the stop: with a single failure every world still starts, in order. (O4)"""
    rc, spawn, ep, message = _launch(
        tmp_path, spawn=T.FakeSpawn(exits={"b": 1}), argv_extra=("--job-id", JOB),
        questioner=S.questioner_for(_five_worlds()))
    assert spawn.worlds == ["a", "b", "c", "d", "e"], (rc, message, spawn.worlds)
    assert S.read_world_record(ep, "b")["reason"] == S.REASON_DID_NOT_FINISH
    assert S.read_world_record(ep, "d") is None


# --- O13: what the siblings cost ---------------------------------------------------------------------

SONNET = "claude-sonnet-4-6"
CASE = "c1" * 16


def _spent(usage: dict) -> list:
    from defender.tests.support.jobs._jobs1342 import _response

    return _response(SONNET, usage)


def _cost_of(store, sibling_session: str) -> float:
    """The one call into the reader. `store` is an open store on the database the siblings share."""
    from defender.records.job_lane import sibling_cost

    return sibling_cost(store, sibling_session)


def test_o13_a_siblings_cost_is_its_own_main_session_and_descendants_in_the_shared_database(tmp_path):
    """Two siblings fork one source: each is priced alone, the prefix, the source's gathers and the other roles not at all. (O13)"""
    from defender.records.session_store._write import open_store
    from defender.tests.support.jobs._jobs1342 import _paths

    runs = tmp_path / "runs"
    runs.mkdir()
    one_in, one_out = {"input_tokens": 1_000_000}, {"output_tokens": 1_000_000}
    with open_store(case_id=CASE, sessions=_paths(runs)) as store:
        source = store.new_session("main")
        ids = store.append(source, _spent(one_in) + _spent(one_in), agent_id="main")
        fork_at = ids[-1]
        store.append(store.fork(source, fork_at), _spent(one_in), agent_id="gather")  # the source's own gather
        first, second = store.fork(source, fork_at), store.fork(source, fork_at)
        first_ids = store.append(first, _spent(one_out), agent_id="main")      # 15.0
        store.append(store.fork(first, first_ids[-1]), _spent(one_in), agent_id="gather")  # its descendant, 3.0
        store.append(second, _spent(one_in), agent_id="main")                  # 3.0
        for role in ("questioner", "oracle", "judge"):
            store.append(store.new_session(role), _spent(one_out), agent_id=role)  # 15.0 each, outside
        assert _cost_of(store, first) == pytest.approx(18.0)
        assert _cost_of(store, second) == pytest.approx(3.0)


# --- judge modes, publishing, dedup -------------------------------------------------------------------


def _graded_episode(tmp_path, monkeypatch, *, job_lane: bool, episode_id: str = S.EPISODE_ID):
    _state1135.set_state_dir(monkeypatch, tmp_path / f"learning-state-{job_lane}")
    ep = S.judged_episode(tmp_path, doc=S.family_v2(episode_id=episode_id), outcome=None, episode_id=episode_id)
    S.outcome_record(ep, "accepted", family_stamp=False)
    J.comparable_family_stamp(ep)
    finding = J.finding_doc(bucket="lead-quality", subject="defender", topic="the lead was never revisited")
    world = J.reply_doc(findings=[finding])
    world.update(bucket="lead-quality", systems=["idp"])
    judge = J.scripted_judge(default=S.as_reply_text(world), family_default=S.as_reply_text(J.family_reply()))
    before = {p for p in ep.rglob("*") if p.is_file()}
    J.grade(ep, judge=judge, state=env_state(), job_lane=job_lane)
    return ep, {p for p in ep.rglob("*") if p.is_file()} - before


def sink_files(new) -> list[Path]:
    """The files among `new` that hold finding rows (a `finding_id` and a topic on every line)."""
    found = []
    for path in sorted(new):
        lines = [x for x in path.read_text(encoding="utf-8", errors="replace").splitlines() if x.strip()]
        try:
            rows = [json.loads(x) for x in lines]
        except ValueError:
            continue
        if rows and all(isinstance(r, dict) and "finding_id" in r and "topic" in r for r in rows):
            found.append(path)
    return found


def _queue() -> list[dict]:
    state = env_state()
    return state.rows(FINDINGS) + state.rows(QUESTIONER_FINDINGS)


def test_judge_modes_the_job_lane_writes_the_episode_and_the_operator_lane_the_queue(tmp_path, monkeypatch):
    """Same reply, two lanes: the operator's findings reach the queue now; the job's wait in the episode. (Judge modes)"""
    _graded_episode(tmp_path, monkeypatch, job_lane=False)
    assert _queue(), "control: the operator lane appended nothing"

    _ep, new = _graded_episode(tmp_path, monkeypatch, job_lane=True, episode_id=JOB)
    assert _queue() == [], "a job's judge reached the queue"
    sunk = sink_files(new)
    assert sunk, f"the job's findings are in no file the judge added to the episode: {sorted(new)}"
    assert any(json.loads(line)["topic"] == "the lead was never revisited"
               for p in sunk for line in p.read_text(encoding="utf-8").splitlines() if line.strip())


def test_d5_a_jobs_findings_publish_once_even_after_an_author_consumed_them(tmp_path, monkeypatch):
    """Publishing fills the queue; a second publish adds nothing, nor does one after rotation. (D5, O14, L-C19)"""
    ep, _new = _graded_episode(tmp_path, monkeypatch, job_lane=True)
    from defender.learning.judge.enqueue import publish_episode_findings

    state = env_state()
    publish_episode_findings(ep, state=state)
    rows = state.rows(FINDINGS)
    assert rows, "the episode's findings never reached the queue"
    publish_episode_findings(ep, state=state)
    assert state.rows(FINDINGS) == rows, "a crash's republish doubled the queue"

    state.rotate(FINDINGS, [], rows, None)
    publish_episode_findings(ep, state=state)
    assert state.rows(FINDINGS) == [], "a consumed finding came back"


def test_d5_dedup_reads_the_consumed_ledger_on_both_lanes_channels(tmp_path, monkeypatch):
    """Append, consume, append the same id: nothing comes back; a new id does. Both findings channels. (L-C19)"""
    _state1135.set_state_dir(monkeypatch, tmp_path / "state")
    state = env_state()
    for channel in (FINDINGS, QUESTIONER_FINDINGS):
        row, fresh = {"finding_id": f"{channel.name}-1", "topic": "t"}, {"finding_id": f"{channel.name}-2", "topic": "t"}
        assert state.append(channel, [row], dedup_key="finding_id") == (1, 0)
        state.rotate(channel, [], [row], None)
        assert state.append(channel, [row], dedup_key="finding_id") == (0, 0)
        assert state.rows(channel) == []
        assert state.append(channel, [fresh], dedup_key="finding_id") == (1, 0), "control: the channel still appends"


# --- O9: nothing outlives its worker ------------------------------------------------------------------

_SIBLING = textwrap.dedent("""
    import os, sys, time
    open(sys.argv[1], "w").write(str(os.getpid()))
    time.sleep(600)
""")
_ENTRY = textwrap.dedent("""
    import os, sys
    from defender.learning.branch.cli import _default_spawn
    from defender.run import _interrupt_on_sigterm, _tie_to_parent

    _tie_to_parent()
    _interrupt_on_sigterm()
    _default_spawn([sys.executable, "-c", sys.argv[2], sys.argv[1]], env=dict(os.environ))
""")
_WORKER = textwrap.dedent("""
    import subprocess, sys, time
    subprocess.Popen([sys.executable, "-c", sys.argv[1], sys.argv[2], sys.argv[3]])
    time.sleep(600)
""")


def _running(pid: int) -> bool:
    try:
        state = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8").rsplit(")", 1)[1].split()[0]
    except OSError:
        return False
    return state != "Z"


def _await_pid(pid_file: Path) -> int:
    for _ in range(3000):
        if pid_file.exists() and pid_file.read_text(encoding="utf-8"):
            return int(pid_file.read_text(encoding="utf-8"))
        time.sleep(0.01)
    raise AssertionError(f"premise: no sibling wrote {pid_file}")


def _gone(pid: int) -> bool:
    for _ in range(1500):
        if not _running(pid):
            return True
        time.sleep(0.01)
    return False


def test_o9_a_sibling_dies_with_its_killed_worker(tmp_path):
    """SIGKILL the worker: the entry's real tie fires and the launcher's real spawn takes the sibling with it. (O9, L-C21)"""
    pid_file = tmp_path / "sibling.pid"
    worker = subprocess.Popen([sys.executable, "-c", _WORKER, _ENTRY, str(pid_file), _SIBLING])
    sibling = None
    try:
        sibling = _await_pid(pid_file)
        assert _running(sibling), "control: the sibling is up"
        worker.kill()
        worker.wait()
        assert _gone(sibling), "the sibling outlived its worker"
    finally:
        worker.kill()
        worker.wait()
        if sibling is not None and _running(sibling):
            os.kill(sibling, signal.SIGKILL)


_UNWINDING = textwrap.dedent("""
    import os, sys
    from defender.learning.branch.cli import _default_spawn
    from defender.run import _interrupt_on_sigterm

    _interrupt_on_sigterm()
    try:
        _default_spawn([sys.executable, "-c", sys.argv[2], sys.argv[1]], env=dict(os.environ))
    except KeyboardInterrupt:
        sys.exit(0)
""")


def test_o9_the_launcher_terminates_its_child_when_it_unwinds_on_sigterm(tmp_path):
    """SIGTERM the launcher's process: it unwinds and the sibling it was waiting on is gone. (O9)"""
    pid_file = tmp_path / "sibling.pid"
    launcher = subprocess.Popen([sys.executable, "-c", _UNWINDING, str(pid_file), _SIBLING])
    sibling = None
    try:
        sibling = _await_pid(pid_file)
        assert _running(sibling), "control: the sibling is up"
        launcher.send_signal(signal.SIGTERM)
        launcher.wait(timeout=60)
        assert _gone(sibling), "the launcher unwound and left its sibling running"
    finally:
        launcher.kill()
        launcher.wait()
        if sibling is not None and _running(sibling):
            os.kill(sibling, signal.SIGKILL)
