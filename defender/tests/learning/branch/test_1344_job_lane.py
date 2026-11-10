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
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from defender.learning.core.state import FINDINGS, QUESTIONER_FINDINGS
from defender.records._episode_handle import Episode
from defender.records.formats import BASE_ROLE, load_family
from defender.tests.learning.branch.test_triplet_launcher import _BASE, _calls, _launch
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
class Candidates:
    """What the `candidates=` seam returns, shaped as `fork_candidates` does: `.ids` (and no dropped candidate)."""

    ids: list[int]


def choose(*ids: int):
    """A `candidates=` seam answering `ids` whatever it is asked."""
    return lambda *_a, **_k: Candidates(list(ids))


@dataclass
class WatchJudge(J.FakeJudge):
    """The judge double, which also reads the job's progress record each time it is called."""

    record: Path | None = None
    progress_seen: list = field(default_factory=list)

    def __call__(self, *a: Any, **kw: Any) -> str:
        self.progress_seen.append(_read_json(self.record))
        return super().__call__(*a, **kw)


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
        oracle=None, fix_source=None, job=JOB, grade=None, preflight=None, after_source=None,
        estate=None, calls=None, **extra) -> Ran:
    """The job entry in-process over `_spec1224`'s fixture tenant (or `estate`, made at `tmp_path`), the source run
    holding `calls` (default: `_calls()`); every paid seam a recording double. `extra` seams (the launcher's
    `proxy_url`, `issuer_transport`, `directory`, ...) are handed as given, over the defaults."""
    est = estate(tmp_path) if estate is not None else S.estate(tmp_path)
    _base, src = S.source_run(tmp_path, est, calls=_calls() if calls is None else calls, after_source=after_source)
    if fix_source is not None:
        fix_source(src)
    tenant = src.parent.parent.name
    authored = S.questioner_for()
    asking = questioner if questioner is not None else Watch(*authored.replies)
    runs = Path(os.environ["DEFENDER_DATA_ROOT"]) / tenant / "runs"
    asking.record = runs / f"{job}.learning-progress.json"
    siblings = spawn if spawn is not None else J.FakeSibling()
    grading = judge if judge is not None else WatchJudge(
        default=J.as_reply_text(J.reply_doc(bucket="none", systems=[])))
    if isinstance(grading, WatchJudge):
        grading.record = asking.record
    seams = dict(
        questioner=asking, preflight=preflight or S.no_preflight, live_tree=live_tree or T.source_capture(),
        roster=est.roster(), judge=grading,
        oracle=(oracle or S.oracle(then=S.submit(_BASE, S.EMPTY_CLAIM))).model,
        verifier=S.passing_verifier().model, directory=T.launcher_directory(tenant), spawn=siblings,
        candidates=candidates if candidates is not None else choose(T.BRANCH_MESSAGE_ID))
    if grade is not None:
        seams["grade"] = grade
    seams.update(extra)
    argv = ["--job", job, "--tenant", tenant, "--source", src.name, "--parent-pid", str(os.getppid())]
    from defender.learning.branch import job_entry

    previous = signal.signal(signal.SIGTERM, _unexpected_sigterm)
    outcome: object = None
    try:
        try:
            outcome = job_entry.main(argv, **seams)
        except SystemExit as stop:
            outcome = stop.code
    finally:
        signal.signal(signal.SIGTERM, previous)
    return Ran(end=_read_json(runs / f"{job}.learning-end.json"),
               progress=_read_json(runs / f"{job}.learning-progress.json"), questioner=asking, spawn=siblings,
               judge=grading, ep=Path(os.environ["DEFENDER_DATA_ROOT"]) / tenant / "episodes" / job, src=src,
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

    assert fork_candidates(source.store, _run_of(source)).ids == [first, second]


class _CountingStore:
    """A session store that counts the fork snapshots asked of it, by request."""

    def __init__(self, store) -> None:
        self._store, self.asked = store, []

    def __getattr__(self, name):
        return getattr(self._store, name)

    def fork_snapshot(self, session_id, request):
        self.asked.append(request)
        return self._store.fork_snapshot(session_id, request)


@pytest.mark.e2e
def test_o3_each_candidates_fork_snapshot_is_loaded_once(tmp_path):
    """The pick reads a candidate's moment from its fork snapshot and then admits it on that snapshot: one load per
    candidate, not one for the moment and another for the admission. (O3, #1446 review)"""
    pytest.importorskip("pydantic_ai")
    R, source = _driven_source(tmp_path, lambda R, c: (
        R.append(c[0]), R.dispatch("l-001"), R.dispatch("l-002"), R.done()))
    from defender.learning.branch.fork_pick import fork_candidates

    counting = _CountingStore(source.store)
    assert len(fork_candidates(counting, _run_of(source)).ids) == 2, "premise: both dispatches are candidates"
    assert sorted(counting.asked) == sorted(set(counting.asked)), counting.asked
    assert len(counting.asked) == 2, counting.asked


@pytest.mark.e2e
def test_o3_a_gather_before_any_captured_query_is_no_candidate(tmp_path):
    """A sibling refuses a point with no query captured by then, so the pick must too: with the automatic lead muted,
    the first dispatch precedes every capture and only the second, after l-001's query, is a candidate. (O3)"""
    pytest.importorskip("pydantic_ai")
    from defender.investigation import branch
    from defender.tests.e2e._lead_zero_808 import VerbRecorder, answer_hits, elastic_backend, hit
    from defender.tests.e2e._replay_harness import Turn
    from defender.tests.support.runtime.state import _1255_snapshot as R

    query = Turn(tool_calls=[("query", {"system": "elastic", "verb": "query",
                                        "params": {"native_query": "user.name:dev.dana"}})])
    c = R.chunks(3)
    source = R.drive_source(
        tmp_path, (R.append(c[0]), R.dispatch("l-001"), R.dispatch("l-002"), R.done()),
        leads={R.CORRELATION_LEAD: [Turn(text="nothing to correlate")],
               **{lead: (query, Turn(text=f"summary of {lead}")) for lead in ("l-001", "l-002")}},
        verbs=elastic_backend(VerbRecorder(), answer_hits([hit(ts="2026-05-25T15:20:00.000Z")])))
    _append, first, second = R.tool_calling_responses(source.store)
    run = _run_of(source)
    as_of = branch.branch_point_time(source.store, run.run_dir, first, source_run=run)
    with pytest.raises(branch.BranchError) as refused:
        branch.validate(source.store, branch.BranchSpec(source_run_dir=run.run_dir, branch_message_id=first,
                                                        as_of=as_of), source_run=run)
    assert refused.value.kind == branch.REFUSED_NO_CAPTURE, "premise: a sibling refuses the first dispatch"
    from defender.learning.branch.fork_pick import fork_candidates

    found = fork_candidates(source.store, run)
    assert found.ids == [second]
    assert found.refusal_kinds == (branch.REFUSED_NO_CAPTURE,)


@pytest.mark.e2e
def test_o3_a_source_with_tool_calls_but_no_gather_has_no_candidate(tmp_path):
    """An `append_block` was a legal operator fork point; for a job it is none. (O3)"""
    pytest.importorskip("pydantic_ai")
    R, source = _driven_source(tmp_path, lambda R, c: (R.append(c[0]), R.echo("x"), R.done()))
    assert R.tool_calling_responses(source.store), "premise: MAIN called tools"
    from defender.learning.branch.fork_pick import fork_candidates

    assert fork_candidates(source.store, _run_of(source)).ids == []


@pytest.mark.e2e
def test_o3_a_gather_that_fails_admission_is_dropped_and_the_rest_stay(tmp_path):
    """A gather with nothing open in the frontier is no candidate; the later admitted one still is. (O3)"""
    pytest.importorskip("pydantic_ai")
    R, source = _driven_source(tmp_path, lambda R, c: (
        R.dispatch("l-001"), R.append(c[0]), R.dispatch("l-002"), R.done()))
    early, _append, late = R.tool_calling_responses(source.store)
    assert [c.tool_name for c in R.calls_of(R.message_at(source.store, early))] == ["gather"]
    from defender.learning.branch.fork_pick import fork_candidates

    found = fork_candidates(source.store, _run_of(source))
    assert found.ids == [late]
    names_the_refusal_not_its_text(tmp_path, source, found, [early], source.store)


@pytest.mark.e2e
def test_o3_when_every_gather_fails_admission_there_is_no_candidate(tmp_path):
    """Dropping is per candidate: a source whose only gather is inadmissible yields none, not an error. (O3)"""
    pytest.importorskip("pydantic_ai")
    R, source = _driven_source(tmp_path, lambda R, c: (R.dispatch("l-001"), R.done()))
    assert R.tool_calling_responses(source.store), "premise: a gather was called"
    from defender.learning.branch.fork_pick import fork_candidates

    found = fork_candidates(source.store, _run_of(source))
    assert found.ids == []
    names_the_refusal_not_its_text(tmp_path, source, found, gathers_of(R, source), source.store)


def gathers_of(R, source) -> list[int]:
    """MAIN's responses that called `gather`, in path order."""
    return [r for r in R.tool_calling_responses(source.store)
            if [c.tool_name for c in R.calls_of(R.message_at(source.store, r))] == ["gather"]]


def admission_refusals(source, rows: list[int], store) -> list[str]:
    """The text of the branch admission's refusal of each of `rows`, as a sibling's admission gives it (the one the pick
    applies): what a learning job's message must never carry (it holds host paths and run text). Asserts each row is
    refused."""
    from defender.investigation import branch

    run, texts = _run_of(source), []
    for row_id in rows:
        try:
            as_of = branch.branch_point_time(store, run.run_dir, row_id, source_run=run)
            branch.validate(store, branch.BranchSpec(source_run_dir=run.run_dir, branch_message_id=row_id, as_of=as_of),
                            source_run=run)
        except branch.BranchError as refused:
            texts.append(str(refused))
        else:
            raise AssertionError(f"premise: message {row_id} is admitted")
    return texts


def no_fork_point_message(tmp_path, found) -> str:
    """The `no_fork_point` message the job entry writes when `fork_candidates` answered `found` with no candidate left:
    `found` with its `ids` emptied goes through the entry's `candidates=` seam, whatever else it carries."""
    import dataclasses

    n = len(list(tmp_path.glob("entry-*")))
    ran = run_entry(tmp_path / f"entry-{n}", job=fixture_uuid(f"1344-no-fork-point-{tmp_path}-{n}"),
                    candidates=lambda *_a, **_k: dataclasses.replace(found, ids=[]))
    assert ran.end is not None, f"no end record (the entry exited {ran.exit!r})"
    assert (ran.end["status"], ran.end["reason"]) == ("skipped", "no_fork_point"), ran.end
    assert ran.end["message"], "a skip with no message for a person to read"
    return ran.end["message"]


def names_the_refusal_not_its_text(tmp_path, source, found, refused: list[int], store) -> str:
    """The dropped candidates' refusals reach a `no_fork_point` message as a kind in our own words: the message differs
    from the one with nothing dropped, and carries neither a refusal's text nor the source's run folder. (O3, O12)"""
    from defender.learning.branch.fork_pick import ForkCandidates

    texts = admission_refusals(source, refused, store)
    message = no_fork_point_message(tmp_path, found)
    assert message != no_fork_point_message(tmp_path, ForkCandidates()), "the dropped candidates' refusal is not named"
    for text in texts:
        assert text not in message, "a refusal's own text reached the job's message"
    assert str(source.run_dir) not in message, "the source's run folder reached the job's message"
    assert str(tmp_path) not in message, "a host path reached the job's message"
    return message


def drop_snapshot(source, request: int) -> None:
    """Delete the fork snapshot MAIN recorded at its `request`-th response: the admission's refusal names the run folder."""
    import sqlite3

    connection = sqlite3.connect(str(source.store.path))
    try:
        changed = connection.execute("DELETE FROM fork_snapshot WHERE request = ?", (request,)).rowcount
        connection.commit()
    finally:
        connection.close()
    assert changed, f"premise: no snapshot was recorded at request {request}"


def _break_snapshot(source, request: int) -> None:
    """Replace the fork snapshot MAIN recorded at its `request`-th response with a body of a version current code refuses."""
    import sqlite3

    connection = sqlite3.connect(str(source.store.path))
    try:
        changed = connection.execute("UPDATE fork_snapshot SET body = ? WHERE request = ?",
                                     (json.dumps({"version": 1}), request)).rowcount
        connection.commit()
    finally:
        connection.close()
    assert changed, f"premise: no snapshot was recorded at request {request}"


@pytest.mark.e2e
def test_o3_a_fork_snapshot_current_code_cannot_read_drops_that_candidate_and_names_why(tmp_path):
    """Two admitted gathers, the first one's snapshot unreadable: only the other stays, and the refusal is named. (O3)"""
    pytest.importorskip("pydantic_ai")
    R, source = _driven_source(tmp_path, lambda R, c: (
        R.append(c[0]), R.dispatch("l-001"), R.append(c[1]), R.dispatch("l-002"), R.done()))
    gathers = [r for r in R.tool_calling_responses(source.store)
               if [c.tool_name for c in R.calls_of(R.message_at(source.store, r))] == ["gather"]]
    assert len(gathers) == 2, "premise: two gathers"
    from defender.learning.branch.fork_pick import fork_candidates

    assert fork_candidates(source.store, _run_of(source)).ids == gathers, "control: both admitted before the plant"
    _break_snapshot(source, R.responses(source.store).index(gathers[0]) + 1)
    from defender.tests.support.storage._store_owner import reread

    found = fork_candidates(reread(source.store), _run_of(source))
    assert found.ids == [gathers[1]]
    names_the_refusal_not_its_text(tmp_path, source, found, [gathers[0]], reread(source.store))


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
    assert first["fork_message_id"] == str(T.BRANCH_MESSAGE_ID), "the record holds the fork id as a string"
    assert ran.progress["fork_message_id"] == str(T.BRANCH_MESSAGE_ID)


def test_o3_the_entry_picks_among_its_candidates_and_does_not_always_pick_the_same(tmp_path):
    """Four candidates, twelve jobs: every recorded pick is one of them, and the picks are not all one. (O3, D-B)"""
    ids = [53, 55, 57, 59]
    picks = []
    for n in range(12):
        stopped_at_the_first_spend = Watch(fail=RuntimeError("stop at the first spend"))
        ran = run_entry(tmp_path / f"job-{n}", candidates=choose(*ids), questioner=stopped_at_the_first_spend,
                        job=fixture_uuid(f"1344-pick-{n}"))
        recorded = ran.questioner.progress_seen[0]
        assert recorded is not None, "nothing was recorded before the first spend"
        picks.append(recorded["fork_message_id"])
    assert set(picks) <= {str(i) for i in ids}, picks
    assert len(set(picks)) > 1, f"twelve jobs, one pick every time: {picks}"


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
    # Started and exited 0: verification gives each finished world a record of its own (this spawn leaves no run
    # folder, so `not archived`), and it is never the never-started record the stop above leaves.
    for label in ("c", "d", "e"):
        record = S.read_world_record(ep, label)
        assert record is not None, f"world {label} finished and was left with no record"
        assert record["reason"] != S.REASON_DID_NOT_FINISH, (label, record)


# --- O13: what the siblings cost ---------------------------------------------------------------------

SONNET = "claude-sonnet-4-6"
CASE = "c1" * 16


def _spent(usage: dict) -> list:
    from defender.tests.support.jobs._jobs1342 import _response

    return _response(SONNET, usage)


def _cost_of(store, sibling_run_id: str) -> float:
    """The one call into the reader. `store` is an open store on the database the siblings share (r7.5 L1)."""
    from defender.records.job_lane import sibling_cost

    return sibling_cost(store, sibling_run_id)


def _row(store, run_id: str, usage: dict, *, agent_id: str = "main", outcome: str = "response",
         requested: str = SONNET, reported: str | None = SONNET) -> None:
    """One ledger row through the real writer, as a run's agent leaves it."""
    from defender.records import session_store as ss

    ss.record_spend(store, run_id, agent_id=agent_id, requested_model=requested, outcome=outcome,
                    reported_model=reported, usage=usage)


def test_o13_a_siblings_cost_is_its_own_ledger_total_in_the_shared_database(tmp_path):
    """CONFLICT-UPDATED (was #1344 O13: session lineage; r7.5 L1): a sibling's cost is the ledger total under its own
    run id. Two siblings and the source run share one database; each is priced alone, gather and review rows count, a
    refused row is $0, a row is priced at the requested model, and the source run's rows are never counted. (O13)"""
    from defender.records.session_store._write import open_store
    from defender.tests.support.jobs._jobs1342 import _paths

    runs = tmp_path / "runs"
    runs.mkdir()
    one_in, one_out = {"input_tokens": 1_000_000}, {"output_tokens": 1_000_000}
    source, first, second, third = (fixture_uuid(f"o13-{n}") for n in ("source", "first", "second", "third"))
    opus = "claude-opus-4-1"
    with open_store(case_id=CASE, sessions=_paths(runs)) as store:
        _row(store, source, one_out, agent_id="main")                       # the source run's own: never counted
        _row(store, source, one_in, agent_id="gather:l-001")
        _row(store, first, one_out, agent_id="main")                        # 15.0
        _row(store, first, one_in, agent_id="gather:l-001")                       # 3.0
        _row(store, first, one_in, agent_id="review:quality")                       # 3.0: a review call counts
        _row(store, first, one_in, agent_id="main", outcome="refused", requested=SONNET, reported=None)  # $0
        _row(store, second, one_in, agent_id="main")                        # 3.0
        _row(store, third, one_in, agent_id="main", requested=SONNET, reported=opus)  # priced at the requested model: 3.0
        assert _cost_of(store, first) == pytest.approx(21.0)
        assert _cost_of(store, second) == pytest.approx(3.0)
        assert _cost_of(store, third) == pytest.approx(3.0)
        assert _cost_of(store, source) == pytest.approx(18.0)               # control: the reader does read a run's rows


class SpendingSibling(J.FakeSibling):
    """A sibling that RAN and was billed: it forks the source's session in the shared database, as a real resume
    does, points its run at it (`attach_case_pointer`) and leaves its spend as ledger rows under its arm's run id."""

    def __init__(self, spend: dict[str, dict], **kw: Any) -> None:
        super().__init__(**kw)
        self.spend = spend
        self.src: Path | None = None

    def attach(self, src: Path) -> None:
        self.src = src

    def __call__(self, argv, **kw):
        code = super().__call__(argv, **kw)
        usage = self.spend.get(_label_of(argv))
        if usage is not None:
            self._bill(_label_of(argv), usage)
        return code

    def _bill(self, label: str, usage: dict) -> None:
        from defender.records import SessionPaths
        from defender.records import session_store as ss
        from defender.tests.support.shared._locations_1210 import fixture_runs_base
        from defender.tests.support.shared.contracts._spec1077 import fixture_run

        assert self.src is not None, "attach(src) first"
        assert self.episode_dir is not None, "the sibling has not run"
        arm = json.loads((self.episode_dir / T.ROSTER_NAME).read_text(encoding="utf-8"))[
            T.world_id(self.episode_dir, label)]
        case_id = T.source_case_id(self.src)
        with ss.open_store(case_id=case_id, sessions=SessionPaths(fixture_runs_base(self.src.parent))) as store:
            fork = store.fork(ss.main_session_id(store), T.BRANCH_MESSAGE_ID)
            # The conversation carries a decoy (r7.5 L1): the cost is the ledger rows below, never this response.
            store.append(fork, _spent({"output_tokens": 99_000_000}), agent_id="main")
            _row(store, arm, usage)
            ss.write_case_pointer(fixture_run(self.episode_dir / "runs" / arm), case_id=case_id,
                                  store_path=store.path, session_id=fork)


def _label_of(argv: list[str]) -> str | None:
    return argv[argv.index("--world") + 1] if "--world" in argv else None


def test_o13_the_entry_carries_the_siblings_cost_and_its_stage_to_the_progress_and_end_records(tmp_path):
    """Three siblings billed 15, 3 and 6 dollars in the ledger: both records say 24, and the stage moves on. (O13, Records)"""
    spawn = SpendingSibling({"a": {"output_tokens": 1_000_000}, "b": {"input_tokens": 1_000_000},
                             "c": {"input_tokens": 2_000_000}})
    ran = run_entry(tmp_path, spawn=spawn, fix_source=spawn.attach)

    assert ran.end is not None, "no end record"
    assert ran.end["status"] == "completed", ran.end
    assert ran.end["sibling_cost_usd"] == pytest.approx(24.0)
    assert ran.progress["sibling_cost_usd"] == pytest.approx(24.0)
    at_spend, at_judge = ran.questioner.progress_seen[0], ran.judge.progress_seen[-1]
    assert at_judge["sibling_cost_usd"] == pytest.approx(24.0), "the progress record lagged the family's last sibling"
    assert at_spend["sibling_cost_usd"] < at_judge["sibling_cost_usd"]
    stages = [at_spend["stage"], at_judge["stage"], ran.end["stage"]]
    assert all(isinstance(x, str) and x for x in stages), stages
    assert stages[0] != stages[1], f"the stage did not move between the questioner and the judge: {stages}"


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
    """The files among `new` that hold finding rows (a `finding_id` and a `subject_topic` on every line)."""
    found = []
    for path in sorted(new):
        lines = [x for x in path.read_text(encoding="utf-8", errors="replace").splitlines() if x.strip()]
        try:
            rows = [json.loads(x) for x in lines]
        except ValueError:
            continue
        if rows and all(isinstance(r, dict) and "finding_id" in r and "subject_topic" in r for r in rows):
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
    assert any(json.loads(line)["subject_topic"] == "the lead was never revisited"
               for p in sunk for line in p.read_text(encoding="utf-8").splitlines() if line.strip())


def test_d5_a_jobs_findings_publish_once_even_after_an_author_consumed_them(tmp_path, monkeypatch):
    """Publishing fills the queue; a second publish adds nothing, nor does one after rotation. (D5, O14, L-C19)"""
    ep, _new = _graded_episode(tmp_path, monkeypatch, job_lane=True)
    from defender.learning.judge.enqueue import publish_episode_findings

    def publish() -> None:
        # The episode reached as the post-step reaches it: by id, through its tenant's runs repository.
        with J.episode_runs_for(ep).episode_files(ep.name) as episode:
            publish_episode_findings(episode, state=state)

    state = env_state()
    publish()
    rows = state.rows(FINDINGS)
    assert rows, "the episode's findings never reached the queue"
    publish()
    assert state.rows(FINDINGS) == rows, "a crash's republish doubled the queue"

    state.rotate(FINDINGS, [], rows, None)
    publish()
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
    from defender._parent_tie import tie_to_parent
    from defender.run import _interrupt_on_sigterm

    tie_to_parent()
    _interrupt_on_sigterm()
    _default_spawn([sys.executable, "-c", sys.argv[2], sys.argv[1]], env=dict(os.environ))
""")
_WORKER = textwrap.dedent("""
    import subprocess, sys, time
    subprocess.Popen([sys.executable, "-c", sys.argv[1], *sys.argv[2:]])
    time.sleep(600)
""")


def child_env() -> dict[str, str]:
    """The environment of a Python child that imports `defender`: pyproject's `pythonpath` reaches only pytest's own
    `sys.path`, and CI sets none, so the checkout root is named."""
    return dict(os.environ, PYTHONPATH=str(T.DEFENDER.parent))


class RealChild:
    """The launcher's spawn seam over its REAL `_default_spawn`, running the test-owned sleeping child for a sibling."""

    def __init__(self, pid_file: str) -> None:
        self.pid_file = pid_file

    def __call__(self, argv, *, env=None, **kw) -> int:
        from defender.learning.branch.cli import _default_spawn

        return _default_spawn([sys.executable, "-c", _SIBLING, self.pid_file], env=env, **kw)


_JOB_ENTRY = textwrap.dedent("""
    import sys
    from pathlib import Path
    from defender.tests.learning.branch.test_1344_job_lane import RealChild, run_entry
    from defender.tests.support.learning.branch import _triplet_947

    _triplet_947.PLANT_RECORDS = True  # as tests/conftest.py's autouse fixture does in-process
    run_entry(Path(sys.argv[1]), spawn=RealChild(sys.argv[2]))
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
    worker = subprocess.Popen([sys.executable, "-c", _WORKER, _ENTRY, str(pid_file), _SIBLING], env=child_env())
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


def test_o9_the_real_job_entry_takes_its_launchers_sibling_with_it_when_its_worker_is_killed(tmp_path):
    """SIGKILL the worker above the REAL job entry: the entry's tie fires, its launcher unwinds, the sibling is gone. (O9, L-C21)"""
    pid_file = tmp_path / "sibling.pid"
    worker = subprocess.Popen([sys.executable, "-c", _WORKER, _JOB_ENTRY, str(tmp_path / "entry"), str(pid_file)],
                              env=child_env())
    sibling = None
    try:
        sibling = _await_pid(pid_file)
        assert _running(sibling), "control: the sibling is up"
        worker.kill()
        worker.wait()
        assert _gone(sibling), "the sibling outlived the worker above the real job entry"
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
    launcher = subprocess.Popen([sys.executable, "-c", _UNWINDING, str(pid_file), _SIBLING], env=child_env())
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



def test_the_job_entrys_role_check_covers_the_roles_its_siblings_run(monkeypatch):
    """The worker's job command hands in the operator launch's role check: a sibling model no provider serves refuses
    the job before the questioner is paid, not inside the control's run (control: every key set, the shipped models
    pass). (O12, r5 table)"""
    from defender import providers
    from defender.cli.learning import job

    for var in providers.api_key_vars():
        monkeypatch.setenv(var, "k-test")
    assert job._preflight(branching=True) == 0, "control: the shipped models pass with every key set"
    assert job._preflight("no-such-model", branching=True) == 2
