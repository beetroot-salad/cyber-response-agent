"""#1344: the end record a learning job's entry leaves at every exit, for each row of the outcome table the entry
decides (the worker's rows are `tests/jobs/test_1344_learning_jobs.py`), the failure message, and SIGTERM. No database."""
from __future__ import annotations

import json
import os
import re
import shutil
import signal
import sqlite3
import subprocess
import sys
import textwrap
import threading
import time
from dataclasses import dataclass
from pathlib import Path

import pytest

from defender.tests.learning.branch.test_1344_job_lane import (
    JOB,
    Watch,
    WatchJudge,
    _driven_source,
    _run_of,
    child_env,
    choose,
    drop_snapshot,
    gathers_of,
    names_the_refusal_not_its_text,
    run_entry,
)
from defender.tests.learning.branch.test_triplet_launcher import _BASE, _calls
from defender.tests.learning.oracle.live_contracts import _spec1224 as S
from defender.tests.support.learning.branch import _triplet_947 as T
from defender.tests.support.learning.judge import _judge_921 as J
from defender.tests.support.shared._fixture_uuid import fixture_uuid

_FIELDS = {"status", "reason", "message", "fork_message_id", "stage", "findings_count", "sibling_cost_usd"}
_GOOD_REPLY = J.as_reply_text(J.reply_doc(bucket="none", systems=[]))


class Boom(Exception):
    """An exception class no production code lists."""


def _world(argv: list[str]) -> str | None:
    return argv[argv.index("--world") + 1] if "--world" in argv else None


class PerWorld:
    """A spawn that routes each world to its own sibling double, in the order they are called."""

    def __init__(self, default, **by_world) -> None:
        self.default, self.by_world = default, by_world

    def __call__(self, argv, **kw):
        return self.by_world.get(_world(argv), self.default)(argv, **kw)

    @property
    def launches(self) -> list:
        return [la for d in (self.default, *self.by_world.values()) for la in d.launches]


class UnscrubbedControl(J.FakeSibling):
    """A control that exits 0 but whose tree no scrub verdict covers, so it is not archived."""

    def __call__(self, argv, **kw):
        code = super().__call__(argv, **kw)
        if _world(argv) == "a":
            arm = T.roster_arm_id(self.episode_dir, T.world_id(self.episode_dir, "a"))
            (self.episode_dir / "runs" / f"{arm}.scrub-verdict.json").write_text(json.dumps({"ran": False}),
                                                                              encoding="utf-8")
        return code


class RosterLostAfterTheLast(J.FakeSibling):
    """The arm roster disappears once the last sibling has run, so no finished arm can be named."""

    def __call__(self, argv, **kw):
        code = super().__call__(argv, **kw)
        if _world(argv) == "c":
            (self.episode_dir / T.ROSTER_NAME).unlink()
        return code


def _session_db(src: Path) -> Path:
    from defender.records import SessionPaths
    from defender.tests.support.shared._locations_1210 import fixture_runs_base

    return SessionPaths(fixture_runs_base(src.parent)).session_db(T.source_case_id(src))


def _wrong_session_store_version(src: Path) -> None:
    connection = sqlite3.connect(str(_session_db(src)))
    connection.execute("PRAGMA user_version = 99")
    connection.commit()
    connection.close()


def _ended(ran, status: str, reason: str | None) -> dict:
    end = ran.end
    assert end is not None, f"no end record (the entry exited {ran.exit!r})"
    assert set(end) == _FIELDS, set(end) ^ _FIELDS
    assert (end["status"], end["reason"]) == (status, reason), end
    return end


def _failed_with(ran, status: str, reason: str) -> str:
    message = _ended(ran, status, reason)["message"]
    assert message, "a refusal or failure with no message for a person to read"
    return message


# --- completed: the judge's pass finished -------------------------------------------------------------


def test_a_family_the_judge_graded_ends_completed(tmp_path):
    """The positive control for the verdict rows below: a comparable family, a judge that ran. (End record)"""
    ran = run_entry(tmp_path)
    end = _ended(ran, "completed", None)
    assert ran.judge.calls, "premise: the judge was asked"
    assert end["fork_message_id"] == str(T.BRANCH_MESSAGE_ID), "the record holds the fork id as a string"
    assert ran.ep.name == JOB
    assert ran.ep.is_dir()


@pytest.mark.parametrize("verdict", ["not comparable", "unusable", "control unusable"])
def test_a_judge_verdict_that_grades_nothing_is_still_completed_with_the_word_in_the_message(tmp_path, verdict):
    """Zero findings, status `completed`, and the verdict word a person can read. (End record, r5 table)"""
    spawn = {
        "not comparable": lambda: PerWorld(J.FakeSibling(commit="deadbee"), b=J.FakeSibling(commit="cafe2")),
        "unusable": lambda: J.FakeSibling(exits={"b": 1, "c": 1}),
        "control unusable": UnscrubbedControl,
    }[verdict]()
    ran = run_entry(tmp_path, spawn=spawn)
    end = _ended(ran, "completed", None)
    assert end["findings_count"] == 0
    assert verdict in (end["message"] or "")
    assert ran.judge.calls == 0, "a verdict that grades nothing still bought a judge call"


# --- skipped ------------------------------------------------------------------------------------------


def test_no_candidate_ends_skipped_before_any_spend(tmp_path):
    """`no_fork_point`, with a message, for nothing: no questioner, no sibling. (O3, L3)"""
    ran = run_entry(tmp_path, candidates=choose())
    assert _failed_with(ran, "skipped", "no_fork_point")
    assert ran.questioner.calls == 0
    assert ran.spawn.launches == []


@pytest.mark.e2e
def test_no_fork_point_names_each_kind_of_refusal_the_candidates_carry_and_never_their_text(tmp_path):
    """Every candidate refused, by real admission refusals (one of them naming the source's run folder): the message
    names each kind of refusal met, the first as well as the last, in our own words, and carries neither a refusal's
    text nor a host path. (O3, O12, #1344 attack round F2)"""
    pytest.importorskip("pydantic_ai")
    from defender.learning.branch.fork_pick import fork_candidates
    from defender.tests.support.storage._store_owner import reread

    def refused_source(name: str, turns, *, drop: tuple[int, ...] = ()) -> str:
        R, source = _driven_source(tmp_path / name, turns)
        gathers = gathers_of(R, source)
        for index in drop:
            drop_snapshot(source, R.responses(source.store).index(gathers[index]) + 1)
        store = reread(source.store)
        found = fork_candidates(store, _run_of(source))
        assert found.ids == [], f"premise: every gather of source {name} is refused"
        return names_the_refusal_not_its_text(tmp_path / name, source, found, gathers, store)

    nothing_open = refused_source("first", lambda R, c: (R.dispatch("l-001"), R.done()))
    no_snapshot = refused_source("last", lambda R, c: (R.append(c[0]), R.dispatch("l-001"), R.done()), drop=(0,))
    both = refused_source("both", lambda R, c: (
        R.dispatch("l-001"), R.append(c[0]), R.dispatch("l-002"), R.done()), drop=(1,))

    def words(message: str) -> set[str]:
        return set(re.findall(r"[a-z]+", message.lower()))

    first_kind, last_kind = words(nothing_open) - words(no_snapshot), words(no_snapshot) - words(nothing_open)
    assert first_kind, "the first kind of refusal reads the same as the last"
    assert last_kind, "the last kind of refusal reads the same as the first"
    assert first_kind <= words(both), f"the first kind met is not named: {both!r}"
    assert last_kind <= words(both), f"the last kind met is not named: {both!r}"


def test_a_session_store_of_another_version_ends_skipped_history_unreadable_naming_the_type(tmp_path):
    """The real refusal of a store this code cannot read: skipped for good, the type named, cheaply. (r5 table, L5)"""
    broken = run_entry(tmp_path, fix_source=_wrong_session_store_version)
    message = _failed_with(broken, "skipped", "history_unreadable")
    assert "UnknownSchemaVersion" in message
    assert "99" not in message, "the store's own text reached the message"
    assert (broken.questioner.calls, broken.spawn.launches) == (0, [])


def test_a_source_history_with_no_single_main_session_ends_skipped_history_unreadable(tmp_path):
    """The fork pick's one read of MAIN's session refuses the store (zero or several root sessions, the shared
    read's `BranchError`): the history is not one current code can fork, so the job is skipped, never an
    `entry_error`. (r5 table, L5)"""
    from defender.investigation import branch

    def no_single_root(*_a, **_k):
        raise branch.BranchError("the source store holds no single root 'main' session: found 2")

    ran = run_entry(tmp_path, candidates=no_single_root)
    message = _failed_with(ran, "skipped", "history_unreadable")
    assert "found 2" not in message, "the refusal's own text reached the message"
    assert (ran.questioner.calls, ran.spawn.launches) == (0, [])


@pytest.mark.parametrize("where", ["questioner", "candidates"])
def test_an_untyped_fault_before_the_first_sibling_is_not_history_unreadable(tmp_path, where):
    """The steps before the first sibling failing with a fault no one typed (the questioner's, or one raised while the
    fork points are read from the source's history) end `failed: entry_error` naming its type, never `skipped`.
    (r5 table)"""
    def unreadable(*_a, **_k):
        raise Boom("the history reader broke in a way nobody typed")

    if where == "questioner":
        ran = run_entry(tmp_path, questioner=Watch(fail=RuntimeError("the questioner's connection reset")))
        _failed_with(ran, "failed", "entry_error")
        return
    ran = run_entry(tmp_path, candidates=unreadable)
    assert "Boom" in _failed_with(ran, "failed", "entry_error")
    assert (ran.questioner.calls, ran.spawn.launches) == (0, [])


def test_a_source_stamp_current_code_cannot_read_ends_skipped_history_unreadable_without_its_text(tmp_path):
    """The source's provenance stamp is unreadable: skipped for good, nothing spent, the stamp's own text absent. (r5 table, L5)"""
    def unreadable(src: Path) -> None:
        (src / "provenance.json").write_text('{"commit": ["SECRET-STAMP-TEXT"]}', encoding="utf-8")

    ran = run_entry(tmp_path, fix_source=unreadable)
    message = _failed_with(ran, "skipped", "history_unreadable")
    assert "SECRET-STAMP-TEXT" not in message
    assert str(tmp_path) not in message, "the launcher's text reached the message"
    assert (ran.questioner.calls, ran.spawn.launches) == (0, [])


def test_too_many_unservable_worlds_end_skipped_family_unusable_with_nothing_started(tmp_path, monkeypatch):
    """Preflight finds every fact world unservable: `unusable`, so no sibling and no retry. (r5 table, UNUSABLE_AT)"""
    monkeypatch.setenv(S.KNOB_RETRY_CAP, "1")
    ran = run_entry(tmp_path, oracle=S.oracle(then=S.text_only("no served answer fits this world")))
    assert _failed_with(ran, "skipped", "family_unusable")
    assert ran.spawn.launches == []


#: Every refusal pre-flight records before the first sibling, by cause, and the row it ends: a refusal caused by the
#: family or its source skips the job for good; the environment's (the read token for the credential proxy cannot be
#: signed) fails it. A new refusal in pre-flight fails the census below until it is given a row here.
_PREFLIGHT_REFUSALS = {
    "no fact world": ("skipped", "family_unusable"),
    "no original call": ("skipped", "family_unusable"),
    "no replayable call": ("skipped", "family_unusable"),
    "read token cannot be signed": ("failed", "launch_refused"),
    "too many unservable worlds": ("skipped", "family_unusable"),
}
#: The question-writer's family refused before pre-flight: the family's own refusal too.
_QUESTIONER_UNUSABLE = "questioner family unusable"


def _preflight_refusal_sites() -> int:
    """How many refusals `preflight_replay` records: its `record(REFUSED | UNUSABLE, ...)` calls."""
    import ast
    import inspect

    from defender.learning.branch import preflight

    tree = ast.parse(textwrap.dedent(inspect.getsource(preflight.preflight_replay)))
    return sum(1 for node in ast.walk(tree)
               if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "record"
               and node.args and isinstance(node.args[0], ast.Name) and node.args[0].id in {"REFUSED", "UNUSABLE"})


@dataclass
class _ProxiedEstate(S.Estate):
    """The fixture estate plus `elastic` on the credential proxy, its declaration planted as every tenant's is."""

    systems: tuple[str, ...] = (*S.SYSTEMS, "elastic")

    def place(self, data_root=None, tenant_id=S.FIXTURE_TENANT, configs=None):
        from defender.tests.support.tenancy._tenants1106 import config_texts

        return super().place(data_root, tenant_id, configs={**(configs or {}), "elastic": config_texts(tenant_id)["elastic"]})


def _refused_before_the_first_sibling(tmp_path, monkeypatch, cause: str):
    from defender.tests.learning.oracle.live_contracts.test_preflight_and_outcome import _family

    if cause == _QUESTIONER_UNUSABLE:
        return run_entry(tmp_path, questioner=Watch("worlds: [unclosed, {facts: "))
    if cause == "no fact world":
        return run_entry(tmp_path, questioner=Watch(*S.questioner_for(_family(facts_b=[], facts_c=[])).replies))
    if cause == "no original call":
        return run_entry(tmp_path, calls=[])
    if cause == "no replayable call":
        return run_entry(tmp_path, estate=lambda root: S.estate(root, withheld=(("idp", "query"),)),
                         calls=[S.Call("idp", "query", S.query_params("user:alice"), _BASE)])
    if cause == "read token cannot be signed":
        from defender.kit.access import PROXY_URL_ENV

        monkeypatch.delenv(PROXY_URL_ENV, raising=False)
        return run_entry(tmp_path, estate=_ProxiedEstate,
                         calls=[*_calls(), S.Call("elastic", "query", S.query_params("user.name:alice"), _BASE)])
    assert cause == "too many unservable worlds", cause
    monkeypatch.setenv(S.KNOB_RETRY_CAP, "1")
    return run_entry(tmp_path, oracle=S.oracle(then=S.text_only("no served answer fits this world")))


@pytest.mark.parametrize("cause", [*_PREFLIGHT_REFUSALS, _QUESTIONER_UNUSABLE])
def test_a_refusal_before_the_first_sibling_skips_the_job_when_the_family_caused_it_and_fails_it_when_the_environment_did(
        tmp_path, monkeypatch, cause):
    """Each refusal pre-flight records, and the question-writer's unusable family: the family's or its source's own end
    `skipped: family_unusable`; the read token for the credential proxy that cannot be signed is the environment's and
    ends `failed: launch_refused`. Nothing is started either way. (r5 table, L3, #1344 attack round F3)"""
    assert _preflight_refusal_sites() == len(_PREFLIGHT_REFUSALS), \
        "pre-flight records a refusal no row of `_PREFLIGHT_REFUSALS` decides"
    status, reason = _PREFLIGHT_REFUSALS.get(cause, ("skipped", "family_unusable"))
    ran = _refused_before_the_first_sibling(tmp_path, monkeypatch, cause)
    _failed_with(ran, status, reason)
    assert ran.spawn.launches == []


# --- failed -------------------------------------------------------------------------------------------


def test_a_failed_control_ends_failed_control_failed_and_no_other_sibling_starts(tmp_path):
    """The control exits 1: the family ends there. (O4, r5 table)"""
    spawn = J.FakeSibling(exits={"a": 1})
    ran = run_entry(tmp_path, spawn=spawn)
    assert _failed_with(ran, "failed", "control_failed")
    assert spawn.worlds == ["a"]
    assert ran.judge.calls == 0


def test_knowledge_the_tenant_cannot_pin_ends_failed_launch_refused(tmp_path):
    """A source that ran at a knowledge commit the tenant's clone does not hold: refused before any spend. (r5 table)"""
    def unpinnable(src: Path) -> None:
        T.source_stamp(src, tenant_id=S.FIXTURE_TENANT, knowledge={"commit": T.OTHER_KNOWLEDGE_SHA})

    ran = run_entry(tmp_path, fix_source=unpinnable)
    assert _failed_with(ran, "failed", "launch_refused")
    assert (ran.questioner.calls, ran.spawn.launches) == (0, [])


@pytest.mark.parametrize("knowledge", [T.NO_KNOWLEDGE_KEY, "unversioned"], ids=["not recorded", "unversioned"])
def test_knowledge_no_commit_proves_ends_failed_launch_refused(tmp_path, knowledge):
    """A source whose stamp records no knowledge commit, or says unversioned: refused before any spend. (r5 table)"""
    ran = run_entry(tmp_path, fix_source=lambda src: T.source_stamp(src, tenant_id=S.FIXTURE_TENANT,
                                                                    knowledge=knowledge))
    assert _failed_with(ran, "failed", "launch_refused")
    assert (ran.questioner.calls, ran.spawn.launches) == (0, [])


@pytest.mark.parametrize("live", [{"dirty": True}, {"commit": None, "dirty": None, "unavailable": T.GIT_UNAVAILABLE}],
                         ids=["dirty", "no commit"])
def test_a_live_tree_that_fails_its_own_stamp_check_ends_failed_launch_refused(tmp_path, live):
    """The code the family would run is not certified: refused before any spend, not skipped as old history. (r5 table)"""
    ran = run_entry(tmp_path, live_tree=T.source_capture(**live))
    assert _failed_with(ran, "failed", "launch_refused")
    assert (ran.questioner.calls, ran.spawn.launches) == (0, [])
    _ended(run_entry(tmp_path / "control", job=fixture_uuid("1344-job-control")), "completed", None)


def test_a_verification_that_refuses_ends_failed_verify_refused_but_a_withheld_stamp_does_not(tmp_path):
    """The arm roster gone is a refusal; siblings at different commits are only `not comparable`. (r5 table)"""
    lost = run_entry(tmp_path / "lost", spawn=RosterLostAfterTheLast())
    _failed_with(lost, "failed", "verify_refused")

    other_job = fixture_uuid("1344-job-split")
    split = run_entry(tmp_path / "split", job=other_job,
                      spawn=PerWorld(J.FakeSibling(commit="deadbee"), b=J.FakeSibling(commit="cafe2")))
    _ended(split, "completed", None)


def _session_pointer(src: Path) -> Path:
    """The run -> case link beside the source's run folder (#1235)."""
    pointer = src.parent / f"{src.name}.session-pointer.json"
    assert pointer.is_file(), f"premise: the source carries its session pointer at {pointer}"
    return pointer


@pytest.mark.parametrize("gone", ["run folder", "session store", "session pointer"])
def test_a_source_that_is_gone_ends_failed_source_unavailable(tmp_path, gone):
    """Its folder removed, its session database removed, or its session pointer removed (and no pre-#1235 link
    inside the folder): failed, without the launcher's own paths. (r5 table, O12)"""
    def lose(src: Path) -> None:
        if gone == "run folder":
            shutil.rmtree(src)
        elif gone == "session store":
            _session_db(src).unlink()
        else:
            _session_pointer(src).unlink()

    ran = run_entry(tmp_path, fix_source=lose)
    message = _failed_with(ran, "failed", "source_unavailable")
    assert str(tmp_path) not in message, "the launcher's text reached the message"
    assert ran.spawn.launches == []


def test_a_source_recorded_before_1235_ends_skipped_history_unreadable_naming_the_type(tmp_path):
    """No session pointer beside the folder, but the pre-#1235 link inside it: current code will never read that
    history, so it is skipped for good, the refusal's type named and nothing spent; not `source_unavailable`.
    (r5 table, L5)"""
    def legacy(src: Path) -> None:
        pointer = _session_pointer(src)
        (src / "session_store_pointer.json").write_text(pointer.read_text(encoding="utf-8"), encoding="utf-8")
        pointer.unlink()

    ran = run_entry(tmp_path, fix_source=legacy)
    message = _failed_with(ran, "skipped", "history_unreadable")
    assert "LegacyRunLink" in message
    assert str(tmp_path) not in message, "the launcher's text reached the message"
    assert (ran.questioner.calls, ran.spawn.launches) == (0, [])


def test_a_judge_that_crashes_ends_failed_judge_failed_where_the_operator_lane_swallows_it(tmp_path):
    """The family ran and the judge died on its first call: the job fails, with no secret of the run's in the message. (r5 table, O12)"""
    judge = J.FakeJudge(default=_GOOD_REPLY, fault=T.Fault(raise_after=0))
    ran = run_entry(tmp_path, judge=judge)
    _failed_with(ran, "failed", "judge_failed")
    assert judge.calls, "premise: the judge was reached"


def test_one_judge_call_that_raises_among_completed_ones_costs_only_its_draw(tmp_path):
    """The judge's first call completes and every later one raises: the pass graded something, so the job completes,
    as the operator lane grades the rest. (r5 table, "Judge modes")"""
    judge = J.FakeJudge(default=_GOOD_REPLY, fault=T.Fault(raise_after=1))
    ran = run_entry(tmp_path, judge=judge)
    _ended(ran, "completed", None)
    assert judge.calls > 1, "premise: a call after the first was made, and raised"


def test_a_family_judge_call_that_raises_before_its_draws_costs_only_itself(tmp_path, monkeypatch):
    """The family-level call fails building its prompt while every world was graded: the worlds' findings stand,
    so the job completes, as the operator lane records the family's failure and keeps them. (r5 table, "Judge
    modes")"""
    from defender.learning.judge import run as judge_run

    def broken(*_a, **_k):
        raise RuntimeError("the family prompt could not be built")

    monkeypatch.setattr(judge_run, "_build_family_prompt", broken)  # lint-monkeypatch: ok — no seam builds the family prompt
    ran = run_entry(tmp_path)
    _ended(ran, "completed", None)


# --- entry_error and the message ----------------------------------------------------------------------


@pytest.mark.parametrize("raiser", ["questioner", "judge"])
def test_a_fault_no_one_listed_ends_failed_entry_error_and_the_runs_text_never_reaches_the_message(tmp_path, raiser):
    """A test-defined class through a seam: `entry_error` names the type, never the exception's own text. (r5 table, O12)"""
    secret = "SECRET-RUN-TEXT-alice-db-1"
    if raiser == "questioner":
        ran = run_entry(tmp_path, questioner=Watch(fail=Boom(secret)))
        expected = "entry_error"
    else:
        class Raising(J.FakeJudge):
            def __call__(self, *_a, **_k):
                raise Boom(secret)

        ran = run_entry(tmp_path, judge=Raising(default=_GOOD_REPLY))
        expected = "judge_failed"
    message = _failed_with(ran, "failed", expected)
    assert secret not in message
    if raiser == "questioner":
        assert "Boom" in message


def test_a_progress_record_that_cannot_be_written_ends_failed_entry_error_before_the_questioner(tmp_path):
    """The fork pick must be durable before any spend: a non-file where the progress record goes makes that write fail,
    and the job ends `failed: entry_error` with no questioner call and no sibling. (O3)"""
    def blocked(src: Path) -> None:
        runs = Path(os.environ["DEFENDER_DATA_ROOT"]) / src.parent.parent.name / "runs"
        (runs / f"{JOB}.learning-progress.json").mkdir()

    ran = run_entry(tmp_path, fix_source=blocked)
    _failed_with(ran, "failed", "entry_error")
    assert (ran.questioner.calls, ran.spawn.launches) == (0, [])


# --- stopped ------------------------------------------------------------------------------------------
#
# Every stop below is a real SIGTERM to this process, sent from inside a seam the entry is running, so it lands while the
# entry holds its own handler and never after the entry has returned.


def _term() -> None:
    os.kill(os.getpid(), signal.SIGTERM)


class TermAtB(J.FakeSibling):
    """A real SIGTERM, to this process, as sibling b is about to start."""

    def __call__(self, argv, **kw):
        if _world(argv) == "b":
            _term()
        return super().__call__(argv, **kw)


class TermInControl(J.FakeSibling):
    """The stop arrives while the control runs; the control then reports `exit` (0: it finished; 143: the stop killed it)."""

    def __init__(self, exit_code: int = 0) -> None:
        super().__init__()
        self.exit_code = exit_code

    def __call__(self, argv, **kw):
        if _world(argv) == "a":
            _term()
            if self.exit_code:
                self.launches.append({"argv": list(argv), "env": dict(kw.get("env") or {})})
                return self.exit_code
        return super().__call__(argv, **kw)


class TermAtFirstAnswer(S.ScriptedModel):
    """The oracle, with a SIGTERM as it is first asked (the preflight replay is running)."""

    def __call__(self, messages, info):
        if not self.seen:
            _term()
        return super().__call__(messages, info)


class TermInJudge(WatchJudge):
    """The judge, with a SIGTERM as it is first called; then it answers, or dies of the stop (`dies`)."""

    dies = False
    signalled = False

    def __call__(self, *a, **kw):
        if not self.signalled:
            self.signalled = True
            _term()
            if self.dies:
                raise Boom("the judge was cut off")
        return super().__call__(*a, **kw)


class TermOnce(Watch):
    """The questioner, with a SIGTERM as it is first paid for."""

    def __call__(self, prompt, **kw):
        if not self.prompts:
            _term()
        return super().__call__(prompt, **kw)


def _stop_during_candidates(*_a, **_k):
    _term()
    return choose(T.BRANCH_MESSAGE_ID)()


def _stop_during_preflight(*_a, **_k):
    _term()
    return 0


def _oracle_stopped() -> S.ScriptedModel:
    return TermAtFirstAnswer(then=S.submit(_BASE, S.EMPTY_CLAIM), name="oracle")


STOP_SEAMS = {
    "candidates": lambda: dict(candidates=_stop_during_candidates),
    "role preflight": lambda: dict(preflight=_stop_during_preflight),
    "questioner": lambda: dict(questioner=TermOnce(*S.questioner_for().replies)),
    "replay preflight": lambda: dict(oracle=_oracle_stopped()),
    "control": lambda: dict(spawn=TermInControl()),
    "control killed by the stop": lambda: dict(spawn=TermInControl(143)),
    "sibling b": lambda: dict(spawn=TermAtB()),
    "judge": lambda: dict(judge=TermInJudge(default=_GOOD_REPLY)),
    "judge killed by the stop": lambda: dict(judge=_judge_dying()),
}


def _judge_dying() -> TermInJudge:
    judge = TermInJudge(default=_GOOD_REPLY)
    judge.dies = True
    return judge


@pytest.mark.parametrize("seam", list(STOP_SEAMS))
def test_a_sigterm_before_the_judge_returns_records_stopped_so_a_stop_never_skips_or_fails(tmp_path, seam):
    """The entry's own handler turns the real signal into `stopped`, wherever it lands; never failed or skipped. (End record, O7)"""
    ran = run_entry(tmp_path, **STOP_SEAMS[seam]())
    _ended(ran, "stopped", None)
    if seam in ("control", "control killed by the stop"):
        assert ran.spawn.worlds == ["a"], "a sibling started after the stop"
    if seam == "sibling b":
        # The stop lands inside b's own launch, so b was already started; c never is.
        assert ran.spawn.worlds == ["a", "b"], "a sibling started after the stop"
    if seam in ("candidates", "role preflight", "questioner", "replay preflight"):
        assert ran.spawn.launches == [], "a sibling started after the stop"
    if seam != "judge" and seam != "judge killed by the stop":
        assert ran.judge.calls == 0, "the judge was bought after the stop"


def test_a_sigterm_while_no_fork_point_is_being_decided_ends_skipped_or_stopped_never_failed(tmp_path):
    """A stop racing the pick cannot fail the job: an ending already decided stays `skipped`, one not yet decided is a stop. (End record, r5)"""
    def stop_then_nothing(*_a, **_k):
        _term()
        return choose()()

    ran = run_entry(tmp_path, candidates=stop_then_nothing)
    assert ran.end is not None
    assert (ran.end["status"], ran.end["reason"]) in {("skipped", "no_fork_point"), ("stopped", None)}, ran.end


_LATE_STOP = textwrap.dedent("""
    import json, os, signal, sys, threading
    from pathlib import Path
    from defender.learning.judge import grade_episode
    from defender.tests.learning.branch.test_1344_job_lane import run_entry
    from defender.tests.support.learning.branch import _triplet_947

    _triplet_947.PLANT_RECORDS = True  # as tests/conftest.py's autouse fixture does in-process

    # The stop lands deterministically: at the first file the entry opens or folder it lists once the judge seam
    # has returned (the findings count reads the episode), never on a timer.
    _armed = []

    def _stop_at_the_next_read(event, _args):
        if _armed and event in ("open", "os.scandir", "os.listdir"):
            _armed.clear()
            signal.raise_signal(signal.SIGTERM)

    def graded_then_a_late_stop(runs, episode_id, **kw):
        graded = grade_episode(runs, episode_id, **kw)
        sys.addaudithook(_stop_at_the_next_read)
        _armed.append(True)
        return graded

    # A signal landing once the entry has returned must be harmless to this wrapper: ignored (so `run_entry` restores
    # SIG_IGN, not SIG_DFL), and whatever it raises in the gap before that is swallowed. The record is read from disk.
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    try:
        run_entry(Path(sys.argv[1]), grade=graded_then_a_late_stop)
    except BaseException as late:
        print(repr(late), file=sys.stderr)
    threading.Event().wait(0.5)
    records = sorted(Path(os.environ["DEFENDER_DATA_ROOT"]).glob("*/runs/*.learning-end.json"))
    ended = json.loads(records[0].read_text(encoding="utf-8")) if len(records) == 1 else None
    Path(sys.argv[2]).write_text(json.dumps(ended), encoding="utf-8")
""")


def test_a_sigterm_after_the_judge_returned_is_still_completed(tmp_path):
    """A real SIGTERM landing just after the judge seam returned (at the entry's first read after it, inside the
    findings count), in a child over the real entry, is not a stop. (End record, r5)"""
    out = tmp_path / "end.json"
    done = subprocess.run([sys.executable, "-c", _LATE_STOP, str(tmp_path / "entry"), str(out)],
                          capture_output=True, text=True, timeout=300, check=False,
                          env=child_env())
    # Read here, not from the wrapper: an entry may legally leave SIGTERM at its default, and the late signal
    # then ends the wrapper before it reports.
    records = sorted(Path(child_env()["DEFENDER_DATA_ROOT"]).glob("*/runs/*.learning-end.json"))
    assert len(records) == 1, f"premise: the entry left one end record, not {records}: {done.stderr[-2000:]}"
    ended = json.loads(records[0].read_text(encoding="utf-8"))
    assert (ended["status"], ended["reason"]) == ("completed", None), ended


HOLD_SECONDS = 120


def test_a_tenant_host_lock_still_busy_after_the_entrys_wait_is_a_hand_back(tmp_path):
    """Prepare or teardown holds the tenant exclusively: the entry hands the job back (`stopped`), not fails it. (End record, O6)"""
    from defender.tenancy import host_lock

    held: list = []
    gate = threading.Lock()
    began: list[float] = []

    def release() -> None:
        with gate:
            while held:
                fd = held.pop()
                if fd is not None:
                    host_lock.release_lock(fd)

    def hold(src: Path) -> None:
        held.append(host_lock.acquire(Path(os.environ["DEFENDER_DATA_ROOT"]), src.parent.parent.name,
                                      exclusive=True, timeout=0))
        began.append(time.monotonic())

    # The lock is let go after HOLD_SECONDS whatever the entry does, so an entry that waits for ever
    # finishes (and fails the assertions below) instead of hanging the run.
    timer = threading.Timer(HOLD_SECONDS, release)
    timer.daemon = True
    timer.start()
    try:
        ran = run_entry(tmp_path, fix_source=hold)
    finally:
        timer.cancel()
        waited = time.monotonic() - began[0] if began else 0.0
        had_it = bool(held) and held[0] is not None
        release()
    assert began, "premise: the test took the lock"
    assert had_it, "premise: the lock was free to take"
    assert waited < HOLD_SECONDS - 5, f"the entry waited out the whole {HOLD_SECONDS} s the lock was held"
    _ended(ran, "stopped", None)
    assert ran.spawn.launches == []
