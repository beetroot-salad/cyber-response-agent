"""#1344: the end record a learning job's entry leaves at every exit, for each row of the outcome table the entry
decides (the worker's rows are `tests/jobs/test_1344_learning_jobs.py`), the failure message, and SIGTERM. No database."""
from __future__ import annotations

import json
import os
import shutil
import signal
import sqlite3
import threading
import time
from pathlib import Path

import pytest

from defender.tests.learning.branch.test_1344_job_lane import JOB, Watch, run_entry
from defender.tests.learning.oracle.live_contracts import _spec1224 as S
from defender.tests.support.learning.branch import _triplet_947 as T
from defender.tests.support.learning.judge import _judge_921 as J

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
    assert end["fork_message_id"] == T.BRANCH_MESSAGE_ID
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
    assert ran.judge.calls == [], "a verdict that grades nothing still bought a judge call"


# --- skipped ------------------------------------------------------------------------------------------


def test_no_candidate_ends_skipped_before_any_spend(tmp_path):
    """`no_fork_point`, with a message, for nothing: no questioner, no sibling. (O3, L3)"""
    ran = run_entry(tmp_path, candidates=lambda *_a: [])
    assert _failed_with(ran, "skipped", "no_fork_point")
    assert ran.questioner.calls == 0
    assert ran.spawn.launches == []


def test_a_session_store_of_another_version_ends_skipped_history_unreadable_naming_the_type(tmp_path):
    """The real refusal of a store this code cannot read: skipped for good, the type named, cheaply. (r5 table, L5)"""
    broken = run_entry(tmp_path, fix_source=_wrong_session_store_version)
    message = _failed_with(broken, "skipped", "history_unreadable")
    assert "UnknownSchemaVersion" in message
    assert "99" not in message, "the store's own text reached the message"
    assert (broken.questioner.calls, broken.spawn.launches) == (0, [])


def test_an_untyped_fault_before_the_first_sibling_is_not_history_unreadable(tmp_path):
    """The same step failing with a fault no one typed ends `failed: entry_error`, never `skipped`. (r5 table)"""
    ran = run_entry(tmp_path, questioner=Watch(fail=RuntimeError("the questioner's connection reset")))
    _failed_with(ran, "failed", "entry_error")


def test_too_many_unservable_worlds_end_skipped_family_unusable_with_nothing_started(tmp_path, monkeypatch):
    """Preflight finds every fact world unservable: `unusable`, so no sibling and no retry. (r5 table, UNUSABLE_AT)"""
    monkeypatch.setenv(S.KNOB_RETRY_CAP, "1")
    ran = run_entry(tmp_path, oracle=S.oracle(then=S.text_only("no served answer fits this world")))
    assert _failed_with(ran, "skipped", "family_unusable")
    assert ran.spawn.launches == []


# --- failed -------------------------------------------------------------------------------------------


def test_a_failed_control_ends_failed_control_failed_and_no_other_sibling_starts(tmp_path):
    """The control exits 1: the family ends there. (O4, r5 table)"""
    spawn = J.FakeSibling(exits={"a": 1})
    ran = run_entry(tmp_path, spawn=spawn)
    assert _failed_with(ran, "failed", "control_failed")
    assert spawn.worlds == ["a"]
    assert ran.judge.calls == []


def test_knowledge_the_tenant_cannot_pin_ends_failed_launch_refused(tmp_path):
    """A source that ran at a knowledge commit the tenant's clone does not hold: refused before any spend. (r5 table)"""
    def unpinnable(src: Path) -> None:
        T.source_stamp(src, tenant_id=S.FIXTURE_TENANT, knowledge={"commit": T.OTHER_KNOWLEDGE_SHA})

    ran = run_entry(tmp_path, fix_source=unpinnable)
    assert _failed_with(ran, "failed", "launch_refused")
    assert (ran.questioner.calls, ran.spawn.launches) == (0, [])


def test_a_verification_that_refuses_ends_failed_verify_refused_but_a_withheld_stamp_does_not(tmp_path):
    """The arm roster gone is a refusal; siblings at different commits are only `not comparable`. (r5 table)"""
    lost = run_entry(tmp_path / "lost", spawn=RosterLostAfterTheLast())
    _failed_with(lost, "failed", "verify_refused")

    split = run_entry(tmp_path / "split", spawn=PerWorld(J.FakeSibling(commit="deadbee"),
                                                         b=J.FakeSibling(commit="cafe2")))
    _ended(split, "completed", None)


@pytest.mark.parametrize("gone", ["run folder", "session store"])
def test_a_source_that_is_gone_ends_failed_source_unavailable(tmp_path, gone):
    """Its folder removed, or its session database removed: failed, without the launcher's own paths. (r5 table, O12)"""
    def lose(src: Path) -> None:
        if gone == "run folder":
            shutil.rmtree(src)
        else:
            _session_db(src).unlink()

    ran = run_entry(tmp_path, fix_source=lose)
    message = _failed_with(ran, "failed", "source_unavailable")
    assert str(tmp_path) not in message, "the launcher's text reached the message"
    assert ran.spawn.launches == []


def test_a_judge_that_crashes_ends_failed_judge_failed_where_the_operator_lane_swallows_it(tmp_path):
    """The family ran and the judge died on its first call: the job fails, with no secret of the run's in the message. (r5 table, O12)"""
    judge = J.FakeJudge(default=_GOOD_REPLY, fault=T.Fault(raise_after=0))
    ran = run_entry(tmp_path, judge=judge)
    _failed_with(ran, "failed", "judge_failed")
    assert judge.calls, "premise: the judge was reached"


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


# --- stopped ------------------------------------------------------------------------------------------


class TermAtB(J.FakeSibling):
    """A real SIGTERM, to this process, as sibling b is about to start."""

    def __call__(self, argv, **kw):
        if _world(argv) == "b":
            os.kill(os.getpid(), signal.SIGTERM)
        return super().__call__(argv, **kw)


def test_a_sigterm_before_the_judge_returns_records_stopped_so_a_stop_never_skips_or_fails(tmp_path):
    """The entry's own handler turns the real signal into the unwind; the record says `stopped`, and b never ran. (End record, O7)"""
    spawn = TermAtB()
    ran = run_entry(tmp_path, spawn=spawn)
    _ended(ran, "stopped", None)
    assert spawn.worlds == ["a"]
    assert ran.judge.calls == []


def test_a_sigterm_after_the_judge_returned_and_before_exit_is_still_completed(tmp_path):
    """The ending is decided at the judge's return: a signal landing once the judge has written is not a stop. (End record, r11 rule)"""
    landed = threading.Event()
    seen: list[float] = []

    def signal_once_graded(ep_of_job: Path) -> None:
        judged = ep_of_job / "judge.yaml"
        for _ in range(6000):
            if judged.is_file():
                break
            time.sleep(0.005)
        else:
            return
        time.sleep(0.25)  # far longer than the pass's remaining work, far shorter than a deploy
        seen.append(time.monotonic())
        os.kill(os.getpid(), signal.SIGTERM)
        landed.set()

    holder: list[threading.Thread] = []

    def start_watching(src: Path) -> None:
        tenant = src.parent.parent.name
        thread = threading.Thread(
            target=signal_once_graded, args=(Path(os.environ["DEFENDER_DATA_ROOT"]) / tenant / "episodes" / JOB,),
            daemon=True)
        thread.start()
        holder.append(thread)

    ran = run_entry(tmp_path, fix_source=start_watching, late_signal_ok=True)  # a signal after the entry is ignored
    holder[0].join(timeout=30)
    assert landed.is_set(), "premise: the signal was sent"
    _ended(ran, "completed", None)


def test_a_tenant_host_lock_still_busy_after_the_entrys_wait_is_a_hand_back(tmp_path):
    """Prepare or teardown holds the tenant exclusively: the entry hands the job back (`stopped`), not fails it. (End record, O6)"""
    from defender.tenancy import host_lock

    held: list = []

    def hold(src: Path) -> None:
        held.append(host_lock.acquire(Path(os.environ["DEFENDER_DATA_ROOT"]), src.parent.parent.name,
                                      exclusive=True, timeout=0))

    try:
        ran = run_entry(tmp_path, fix_source=hold)
    finally:
        for fd in held:
            if fd is not None:
                host_lock.release_lock(fd)
    assert held, "premise: the test took the lock"
    assert held[0] is not None, "premise: the lock was free to take"
    _ended(ran, "stopped", None)
    assert ran.spawn.launches == []
