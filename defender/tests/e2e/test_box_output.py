"""#1205, #1421: an unusable box or a fence trip ends the run by name, through MAIN and
correlation-lead boundaries; a command printing too much does not."""
from __future__ import annotations

import asyncio
import json
import logging
import shutil
import subprocess
import sys
import uuid
from datetime import UTC, datetime
from collections.abc import Callable
from pathlib import Path

import pytest

from defender import box, run_common
from defender._exception_groups import carried
from defender.hooks.budget_enforcer import BudgetKill
from defender.systems.circuit_breaker import RunAborted
from defender.systems.verbs import ServingAbort
from defender.execution import bash_exec
from defender.investigation import ticket_writer
from defender.providers import ProviderDown
from defender.records import RunPaths
from defender.records import run_end
from defender.records.run_end import CALL_RECORDS, CallRecordWriteFailed, parse_record
from defender.tests.e2e._box665 import RecordingDocker
from defender.tests.support.tenancy._host1214 import counting_calls
from defender.tests.support.sandbox._docker import daemon_reachable, docker_runtimes, dood_anchor, is_dood
from defender.tests.support.sandbox._spec1092 import make_run_dir
from defender.tests.tenancy.alert_front_door_1222 import _spec1222 as S
from defender.tests.runtime.providers import _spec1243 as P
from defender.tests.support.tenancy._host1214 import TEST_TENANT
from defender.tests.support.shared.contracts._data_root_1078 import current_data_root

pytestmark = pytest.mark.e2e


def _lost() -> box.BoxLost:
    # GAP G12: `BoxLost`'s constructor is unfixed; it is built as `BoxFault` is, from one message.
    return box.BoxLost("the box is unusable")


#: The two endings: how each is raised, the exit it gives, the word it leaves on the record.
ENDINGS = {"box-lost": (_lost, 5), "box-output-limit": (box.BoxOutputLimitExceeded, 6)}


def _fault(shape, ending):
    overflow = ENDINGS[ending][0]()
    if shape == "bare":
        return overflow
    if shape == "nested":
        return ExceptionGroup("outer", [ExceptionGroup("inner", [overflow])])
    if shape == "call-record":
        return ExceptionGroup("mixed", [CallRecordWriteFailed(sorted(CALL_RECORDS)[0], "test"), overflow])
    return ExceptionGroup("mixed", [ProviderDown(model="test", status=503, attempts=4), overflow])


def _run_end(result: S.Drive):
    """The run-end record as its strict reader sees it; a value outside the vocabulary reads as none."""
    return parse_record(json.loads(RunPaths(result.folder).run_end_sidecar().read_text(encoding="utf-8")))


def _named(result: S.Drive) -> str | None:
    """The class a run's record names, or None when it left no record."""
    path = RunPaths(result.folder).run_end_sidecar()
    return _run_end(result).truncated_by if path.is_file() else None


def test_the_run_end_vocabulary_knows_both_endings_and_forces_no_close_for_them():
    """Without both in the vocabulary `comments_on` normalizes the value away and the sidecar reads as no record. (O8, O9)"""
    for word in ENDINGS:
        assert word in run_end.TRUNCATED_BY_VALUES
        assert run_end.normalized_truncated_by(word) == word
        assert word not in run_end.FORCED_CLOSE_EXITS


@pytest.mark.parametrize("shape", ["bare", "nested", "mixed", "call-record"])
@pytest.mark.parametrize("where", ["main", "correlation"])
@pytest.mark.parametrize("ending", list(ENDINGS))
def test_o8_o9_a_box_ending_ends_the_run_by_name_instead_of_a_retry_or_fallback(tmp_path, shape, where, ending):
    """Named on the run-end record and its exit (5, 6), over provider-down and call-record faults. (O8, O9)"""
    fault = _fault(shape, ending)
    injected = S.LeadFault(raise_on=1, exc=lambda: fault)
    main = S.MainScript([S.text(S.DONE)], fault=injected if where == "main" else S.CLEAN)
    result = S.run_alert(tmp_path, main=main,
                         lead_faults={S.L3: injected} if where == "correlation" else None)
    assert result.raised is None, result.raised
    assert result.rc == ENDINGS[ending][1]
    assert _run_end(result).truncated_by == ending
    assert main.requests == (1 if where == "main" else 0)
    assert result.report is None


def test_o9_the_fences_wording_is_its_exceptions_text_logged_once_at_the_ending(tmp_path, caplog):
    """A process bypassing the helper: the text says so, the log carries it once, the records only the class. (O9)"""
    fault = box.BoxOutputLimitExceeded()
    assert "helper" in str(fault).lower(), "the fence's text does not word a bypass of the helper"
    caplog.set_level(logging.INFO)
    main = S.MainScript([S.text(S.DONE)], fault=S.LeadFault(raise_on=1, exc=lambda: fault))
    result = S.run_alert(tmp_path, main=main)
    assert result.rc == 6
    logged = [r for r in caplog.records if str(fault) in r.getMessage()]
    assert len(logged) == 1, [r.getMessage() for r in caplog.records]
    assert str(fault) not in RunPaths(result.folder).run_end_sidecar().read_text(encoding="utf-8")


@pytest.mark.parametrize("ending", list(ENDINGS))
def test_o8_o9_the_lead_that_met_the_ending_is_stamped_and_so_is_main(tmp_path, ending):
    """The lead's session reads the class, beside the provider-down and call-record stamps. (O8, O9)"""
    stores: list = []
    lead = "l-001"
    fault = S.LeadFault(raise_on=1, exc=ENDINGS[ending][0])
    result = S.run_alert(tmp_path, main=[S.gather(lead, "cmdb"), S.text(S.DONE)],
                         leads={S.L3: [S.text("corr")], lead: [S.text("x")]}, lead_faults={lead: fault},
                         store_factory=S.store_factory(tmp_path, sink=stores), stores=stores)
    assert result.rc == ENDINGS[ending][1]
    ended = P.sessions(stores[-1].path)
    assert ended.get(P.gather_agent(lead)) == ending, ended
    assert ended.get("main") == ending, ended


@pytest.mark.parametrize("ending", list(ENDINGS))
def test_o8_o9_the_correlation_lead_that_met_the_ending_is_stamped(tmp_path, ending):
    """Same at the correlation site, which stops before MAIN. (O8, O9)"""
    stores: list = []
    result = S.run_alert(tmp_path, main=S.MainScript([S.text(S.DONE)]), leads={S.L3: [S.text("corr")]},
                         lead_faults={S.L3: S.LeadFault(raise_on=1, exc=ENDINGS[ending][0])},
                         store_factory=S.store_factory(tmp_path, sink=stores), stores=stores)
    assert result.rc == ENDINGS[ending][1]
    assert result.main.requests == 0
    assert P.sessions(stores[-1].path).get(P.gather_agent(S.L3)) == ending


KILLS = {"budget": lambda: BudgetKill("run budget spent"), "aborted": lambda: RunAborted(5, ["cmdb"])}


def _group_run(tmp_path: Path, group: BaseException, where: str, **kw):
    """`group` raised by MAIN's lead, by the correlation lead (which stops before MAIN), or by a gather lead (`gather`; pass `stores=[]`)."""
    injected = S.LeadFault(raise_on=1, exc=lambda: group)
    if where == "gather":
        lead = "l-001"
        return S.run_alert(tmp_path, main=[S.gather(lead, "cmdb"), S.text(S.DONE)],
                           leads={S.L3: [S.text("corr")], lead: [S.text("x")]}, lead_faults={lead: injected},
                           store_factory=S.store_factory(tmp_path, sink=kw["stores"]), **kw)
    main = S.MainScript([S.text(S.DONE)], fault=injected if where == "main" else S.CLEAN)
    return S.run_alert(tmp_path, main=main, lead_faults={S.L3: injected} if where == "correlation" else None, **kw)


WHERE = pytest.mark.parametrize("where", ["main", "correlation"])


@WHERE
@pytest.mark.parametrize("ending", list(ENDINGS))
@pytest.mark.parametrize("kill", list(KILLS))
def test_o8_o9_a_group_with_a_budget_or_abort_propagates_first_and_is_not_named_for_the_box(tmp_path, kill, ending, where):
    """The kill's own ending wins; the record names it or nothing, never the box. (O8, O9, group precedence)"""
    group = ExceptionGroup("g", [KILLS[kill](), ENDINGS[ending][0]()])
    result = _group_run(tmp_path, group, where)
    assert result.rc not in (5, 6), result.rc
    assert _named(result) in (None, kill), _named(result)
    assert result.raised is not None or _named(result) == kill, "the group vanished without an ending"


PROPAGATES_FIRST = {
    "interrupt": KeyboardInterrupt, "cancelled": asyncio.CancelledError, "budget": lambda: BudgetKill("run budget spent"),
    "aborted": lambda: RunAborted(5, ["cmdb"]), "serving-abort": lambda: ServingAbort("the oracle gave up on the world"),
}


@pytest.mark.parametrize("where", ["main", "correlation", "gather"])
@pytest.mark.parametrize("ending", list(ENDINGS))
@pytest.mark.parametrize("first", list(PROPAGATES_FIRST))
def test_o8_o9_a_group_holding_anything_that_propagates_first_is_named_for_no_box_ending_at_any_site(tmp_path, first, ending, where):
    """At the driver's two sites and the gather stamp, the group goes up as itself and no box ending is returned, named or stamped. (O8, O9, group precedence)"""
    stores: list = []
    group = BaseExceptionGroup("g", [PROPAGATES_FIRST[first](), ENDINGS[ending][0]()])
    if first in ("interrupt", "cancelled"):
        with pytest.raises(BaseExceptionGroup) as caught:
            _group_run(tmp_path, group, where, stores=stores, catch=False)
        assert carried(caught.value, type(group.exceptions[0])) is not None
    else:
        result = _group_run(tmp_path, group, where, stores=stores)
        assert result.rc not in (5, 6), result.rc
        assert _named(result) not in ENDINGS, _named(result)
    if where == "gather":
        assert P.sessions(stores[-1].path).get(P.gather_agent("l-001")) not in ENDINGS


@WHERE
@pytest.mark.parametrize("order", ["lost-first", "fence-first"])
def test_o8_o9_a_group_holding_both_box_endings_names_the_fence(tmp_path, order, where):
    """Both in one group: the fence is named and exits 6, whichever was raised first. (O9, Run ending)"""
    leaves = [_lost(), box.BoxOutputLimitExceeded()]
    result = _group_run(tmp_path, ExceptionGroup("g", leaves if order == "lost-first" else leaves[::-1]), where)
    assert result.raised is None, result.raised
    assert result.rc == 6
    assert _run_end(result).truncated_by == "box-output-limit"


@WHERE
@pytest.mark.parametrize("ending", list(ENDINGS))
def test_o8_o9_a_group_with_an_interrupt_propagates_first(tmp_path, ending, where):
    """An interrupt beside a box ending is never turned into the ending. (O8, O9)"""
    group = BaseExceptionGroup("g", [KeyboardInterrupt(), ENDINGS[ending][0]()])
    with pytest.raises(BaseExceptionGroup) as caught:
        _group_run(tmp_path, group, where, catch=False)
    assert carried(caught.value, KeyboardInterrupt) is not None


@pytest.mark.parametrize("ending", [None, *ENDINGS])
def test_o8_o9_a_serving_abort_in_a_group_still_exits_3_for_an_unservable_world(tmp_path, monkeypatch, ending):
    """The unservable sibling world's exit 3 wins over a box ending in the same group; bare is the control. (O8, O9)"""

    leaves = [ServingAbort("the oracle gave up on the world")] + ([ENDINGS[ending][0]()] if ending else [])
    raised = leaves[0] if len(leaves) == 1 else ExceptionGroup("g", leaves)
    ep = P.sibling_episode(tmp_path, monkeypatch)
    main = S.MainScript([S.text(S.DONE)], fault=S.LeadFault(raise_on=1, exc=lambda: raised))
    result = P.run_sibling(tmp_path / "sibling", ep, main)
    assert result.raised is None, result.raised
    assert result.rc == 3, result.rc


@pytest.mark.parametrize("ending", list(ENDINGS))
def test_o8_o9_a_sibling_world_exiting_5_or_6_did_not_finish(tmp_path, monkeypatch, ending):
    """The exit (a fixture's here) is new, not 0, 2, 3, 4, and the branched world is recorded as unfinished. (O8, O9)"""
    from defender.learning.branch import cli
    from defender.learning.branch.outcome import DID_NOT_FINISH
    from defender.records._episode_handle import Episode
    from defender.tests.support.learning.branch import _triplet_947 as T

    code = ENDINGS[ending][1]
    assert code not in P.TAKEN_EXITS | {P.PROVIDER_DOWN_EXIT}
    _base, src, _root = T.configured_layout(tmp_path, monkeypatch)
    spawn = T.FakeSpawn(exits={"b": code})
    ep = T.episode(tmp_path, doc=T.family_doc(source_run_dir=str(src.resolve())))
    with Episode.open(ep) as episode:
        T.episode_view(episode)
        exits = cli.start_family(
            episode, [T.world_id(ep, label) for label in ("a", "b")], spawn=spawn, tenant_id=T.SOURCE_TENANT)
    assert exits.get(T.world_id(ep, "b")) == code
    records = {p.stem: p.read_text(encoding="utf-8") for p in ep.rglob("world_records/*.yaml")}
    assert DID_NOT_FINISH in records[T.world_id(ep, "b")]
    assert T.world_id(ep, "a") not in records


@pytest.mark.parametrize("ending", list(ENDINGS))
def test_o8_o9_a_sibling_world_that_meets_the_ending_exits_5_or_6_by_its_own_door(tmp_path, monkeypatch, ending):
    """The sibling's real run ends by class, so the exit the family records is the run's, not a fixture's. (O8, O9)"""
    ep = P.sibling_episode(tmp_path, monkeypatch)
    main = S.MainScript([S.text(S.DONE)], fault=S.LeadFault(raise_on=1, exc=ENDINGS[ending][0]))
    d = P.run_sibling(tmp_path / "sibling", ep, main)
    assert d.run_dir is not None, (d.rc, d.refusal, d.raised)
    assert d.raised is None, d.raised
    assert (d.summary or {}).get("truncated_by") == ending, d.summary
    assert d.rc == ENDINGS[ending][1]


NAME = "defender-1421-box"
COMMAND = "echo hello"


def _exchange_runs(*argv: str) -> Callable[..., subprocess.Popen[bytes]]:
    """`docker exec` as a real process that ends the way the fault does; the fence reads its real streams."""
    return lambda _argv, **kw: subprocess.Popen(list(argv), **kw)


def _exchange_fails(error: Exception) -> Callable[..., subprocess.Popen[bytes]]:
    """A docker client that cannot be run at all: the transport itself raises."""
    def popen(_argv, **_kw):
        raise error

    return popen


class _MuteDaemon(RecordingDocker):
    """A daemon that does not answer a status question (rc 1), recording what it is asked."""

    def __call__(self, argv, **_kw) -> subprocess.CompletedProcess:
        self.calls.append(list(argv))
        return subprocess.CompletedProcess(list(argv), 1, stdout="", stderr="Cannot connect to the Docker daemon")


def _executor(status: str | None, popen: Callable[..., subprocess.Popen[bytes]], *, attached: bool = True):
    """A sandboxed executor whose exchange is the fault and whose daemon answers `status` ("mute": not at
    all). A run box has its attached start, so it is auto-removed: gone counts as stopped (#1343 B10)."""
    daemon = _MuteDaemon() if status == "mute" else _DaemonThatRaises() if status == "raises" else RecordingDocker(status=status)
    starter = None
    if attached:
        starter = subprocess.Popen(["true"])
        starter.wait()
    return box.BoxExecutor(name=NAME, docker=daemon, starter=starter,
                           transport=box._DockerTransport(NAME, box.BoxSpec(), popen=popen)), daemon


def _boxed(status: str | None, popen: Callable[..., subprocess.Popen[bytes]]) -> dict:
    """The real lifecycle over that executor."""
    executor, _daemon = _executor(status, popen)

    def scrub(_tree: Path, *, write_verdict) -> None:
        write_verdict({"ran": True, "reason": "walk completed"})

    return {"start_box": lambda *_a, **_k: executor, "stop_box": lambda *_a, **_k: None, "scrub": scrub}


def _asks(executor: box.BoxExecutor, command: str = COMMAND, timeout: float = 5):
    return executor.run_parsed(bash_exec.parse(command), command=command, cwd=Path("/runs/current"), timeout=timeout)


class _DaemonThatRaises(RecordingDocker):
    """A docker client that cannot be run when asked anything (a real `TimeoutExpired`, as `_call` maps)."""

    def __call__(self, argv, **_kw):
        self.calls.append(list(argv))
        raise subprocess.TimeoutExpired(list(argv), 1)


EXEC_KILLED = ("sh", "-c", "exit 137")  # C4, C5: exec rc 137 and no bytes, whether the box or the helper died
EXEC_KILLED_WITH_BYTES = ("sh", "-c", "printf 'partial output'; exit 137")  # C4: bytes arrived before the kill
# Half of a real frame, with the frame built here: the child needs no import of `defender`, which a
# subprocess started from CI's working directory cannot do.
_HALF_FRAME = box.encode_response(box.BoxResult(rc=0, out=b"x" * 99, err=b""))
EXEC_KILLED_MID_FRAME = (sys.executable, "-c", "import os, sys\n"
                         f"os.write(1, {_HALF_FRAME[:len(_HALF_FRAME) // 2]!r}); sys.exit(137)")
EXEC_SAYS_NO_SUCH_BOX = ("sh", "-c", "echo 'No such container' >&2; exit 1")  # C5, the next exec
NOT_A_FRAME = ("sh", "-c", "printf 'wrong magic, a bypassing writer'")  # C13
EXEC_REFUSED_REQUEST = ("sh", "-c", "exit 2")  # the helper could not decode the request: rule 4
EXEC_HELPER_DEADLINE = ("sh", "-c", "exit 3")  # the helper's own deadline: rule 3
OVER_THE_FENCE = ("head", "-c", str(box.BOX_OUTPUT_LIMIT + 1), "/dev/zero")


@pytest.mark.parametrize(("status", "exchange", "code", "named"), [
    ("exited", _exchange_runs(*EXEC_KILLED), 5, "box-lost"),  # rule 1, box dead
    (None, _exchange_runs(*EXEC_SAYS_NO_SUCH_BOX), 5, "box-lost"),  # rule 1, box gone
    ("mute", _exchange_runs(*EXEC_KILLED), 5, "box-lost"),  # rule 1, no answer
    ("exited", _exchange_fails(OSError("docker client")), 5, "box-lost"),  # rule 1, transport exception
    ("running", _exchange_runs(*NOT_A_FRAME), 5, "box-lost"),  # rule 4
    ("running", _exchange_runs(*EXEC_REFUSED_REQUEST), 5, "box-lost"),  # rule 4: rc 2 is not rule 3
    ("running", _exchange_fails(OSError("docker client")), 5, "box-lost"),  # rule 4, transport exception
    ("exited", _exchange_runs(*OVER_THE_FENCE), 6, "box-output-limit"),
    ("running", _exchange_runs(*OVER_THE_FENCE), 6, "box-output-limit"),  # the stop cannot be proven: still the fence
], ids=["box-exited", "box-gone", "daemon-mute", "exited-transport-exception", "running-no-frame",
        "running-exec-rc-2", "running-transport-exception", "fence", "fence-unprovable-stop"])
def test_o8_o9_the_first_command_that_finds_the_box_unusable_ends_the_run(tmp_path, status, exchange, code, named):
    """From the bash tool: no retry prompt, no forced close, the class on the record and in the exit code. (O8, O9)"""
    main = S.MainScript([S.call("bash", command=COMMAND), S.text(S.DONE)])
    result = S.run_alert(tmp_path, main=main, box_lifecycle=_boxed(status, exchange))
    assert result.raised is None, result.raised
    assert result.rc == code
    assert _run_end(result).truncated_by == named
    assert _run_end(result).closed_before_cut is False
    assert main.requests == 1, "the model was asked again after the box was found unusable"
    assert result.report is None


@pytest.mark.parametrize(("answer", "stop", "code", "named", "requests"), [
    ("LOST", "STOPPED", 5, "box-lost", 1),
    ("LOST", "STOP_FAULT", 5, "box-lost", 1),  # the teardown fault does not replace the ending
    ("OUTPUT_LIMIT", "STOPPED", 6, "box-output-limit", 1),
    ("OUTPUT_LIMIT", "STOP_FAULT", 6, "box-output-limit", 1),
    ("KILLED", "STOPPED", 0, None, 2),  # controls: a result and a timeout leave the run going
    ("TIMEOUT", "STOPPED", 0, None, 2),
], ids=["lost", "lost-stop-fault", "fence", "fence-stop-fault", "control-kill-line", "control-timeout"])
def test_a4_a_box_over_the_relay_ends_the_run_by_name_exactly_as_the_docker_exchange_does(
        tmp_path, answer, stop, code, named, requests):
    """The helper's answer decides the ending; the job's stop goes through `box.stop`. (A4, O8, O9; same table as the docker rows above)"""
    from defender.tests.support.jobs import _box_relay as R

    helper = R.ScriptedHelper(getattr(R, answer), stop=getattr(R, stop))

    def scrub(_tree: Path, *, write_verdict) -> None:
        write_verdict({"ran": True, "reason": "walk completed"})

    lifecycle = {"start_box": lambda *_a, **_k: R.relay_executor(helper), "stop_box": box.stop_box, "scrub": scrub}
    main = S.MainScript([S.call("bash", command=COMMAND), S.text(S.DONE)])
    result = S.run_alert(tmp_path, main=main, box_lifecycle=lifecycle)
    assert result.raised is None, result.raised
    assert result.rc == code
    assert _run_end(result).truncated_by == named
    assert main.requests == requests
    assert helper.asked("box.stop"), "the run was torn down without asking the helper to stop the box"


@pytest.mark.parametrize("exchange", [EXEC_KILLED, EXEC_KILLED_WITH_BYTES, EXEC_KILLED_MID_FRAME],
                         ids=["no-bytes", "partial-bytes", "half-a-frame"])
def test_o6_exec_137_with_the_box_running_is_a_result_and_the_run_continues(tmp_path, exchange):
    """Rule 2, whatever bytes arrived: the helper was killed, the box lives; the model gets the reason line and goes on. (O6)"""
    main = S.MainScript([S.call("bash", command=COMMAND), S.text(S.DONE)])
    result = S.run_alert(tmp_path, main=main, box_lifecycle=_boxed("running", _exchange_runs(*exchange)))
    assert result.raised is None, result.raised
    assert result.rc == 0
    assert _run_end(result).truncated_by is None
    assert main.requests == 2
    said = "\n".join(main.seen[1].tool_returns)
    assert "memory" in said.lower(), said
    assert "exit=-9" in said, said
    assert "partial output" not in said, "bytes of a killed exchange reached the model"
    assert "x" * 20 not in said, "bytes of a killed exchange reached the model"
    assert "could not run this command" not in said, f"reached the model as a retry: {said}"


def test_o6_rule_3_the_helpers_own_deadline_keeps_the_existing_timeout_message_and_the_run_goes_on(tmp_path):
    """With the box running, exec rc 3 is the model's timeout, not a lost box; the host-timeout arm is the executor's, below. (O6)"""
    main = S.MainScript([S.call("bash", command=COMMAND), S.text(S.DONE)])
    result = S.run_alert(tmp_path, main=main, box_lifecycle=_boxed("running", _exchange_runs(*EXEC_HELPER_DEADLINE)))
    assert result.raised is None, result.raised
    assert result.rc == 0
    assert _run_end(result).truncated_by is None
    assert main.requests == 2
    said = "\n".join(main.seen[1].tool_returns)
    assert "timed out" in said, said


def test_o6_the_killed_helpers_result_is_a_fixed_one_line_reason_whatever_arrived(tmp_path):
    """Executor: rc -9, empty stdout, one fixed line of at most 160 characters naming memory, byte-identical across triggers. (O6, P1)"""
    results = []
    for exchange in (EXEC_KILLED, EXEC_KILLED_WITH_BYTES, EXEC_KILLED_MID_FRAME):
        executor, _daemon = _executor("running", _exchange_runs(*exchange))
        results.append(_asks(executor))
    first = results[0]
    assert first.rc == -9
    assert first.out == b""
    line = first.err.decode("utf-8")
    assert len(line.strip().splitlines()) == 1, line
    assert len(line.strip()) <= 160, line
    assert "memory" in line.lower()
    assert all(r == first for r in results), results


def test_o6_rule_2_leaves_the_box_usable_and_stops_nothing(tmp_path):
    """A result, not a loss: nothing is stopped and the next command is executed. (O6)"""
    executor, daemon = _executor("running", _exchange_runs(*EXEC_KILLED))
    _asks(executor)
    _asks(executor)
    assert [c for c in daemon.calls if c[1] in {"stop", "kill", "rm"}] == []
    assert len([c for c in daemon.calls if c[1] == "inspect"]) >= 1, "no status was asked, so rule 2 was guessed"


@pytest.mark.parametrize("status", ["exited", "mute", "raises"], ids=["exited", "no-answer", "status-call-raises"])
@pytest.mark.parametrize("exchange", [EXEC_HELPER_DEADLINE, EXEC_KILLED, ("sleep", "30")],
                         ids=["helper-deadline-rc-3", "exec-137", "host-timeout"])
def test_o8_rule_1_any_exchange_without_a_frame_on_a_box_not_running_is_a_lost_box(status, exchange):
    """Not running, no answer, or a fault asking: `BoxLost`, even for the exchanges rule 3 would excuse on a running box. (O8, O6)"""
    executor, daemon = _executor(status, _exchange_runs(*exchange))
    with pytest.raises(box.BoxLost):
        _asks(executor, timeout=0.5)
    assert any(c[1] == "inspect" for c in daemon.calls), "the box was judged lost without asking its status"


@pytest.mark.parametrize("rc", [137, -9, 75, 2, 3])
def test_o6_a_clean_frame_is_returned_untouched_and_no_status_is_asked(rc):
    """A command's own 137 or 75 inside a good frame is the command's, not a rule's. Control for the rules. (O6)"""
    wire = box.encode_response(box.BoxResult(rc=rc, out=b"o\n", err=b"e\n"))
    executor, daemon = _executor("running", _exchange_runs(sys.executable, "-c", f"import os; os.write(1, {wire!r})"))
    assert _asks(executor) == box.BoxResult(rc=rc, out=b"o\n", err=b"e\n")
    assert daemon.calls == []


def test_o6_a_host_timeout_with_the_box_running_stays_a_timeout_and_the_box_is_usable():
    """Rule 3 at the executor: `TimeoutExpired`, no loss, no stop. (O6)"""
    executor, daemon = _executor("running", _exchange_runs("sleep", "30"))
    with pytest.raises(subprocess.TimeoutExpired):
        executor.run_parsed(bash_exec.parse(COMMAND), command=COMMAND, cwd=Path("/"), timeout=0.5)
    assert [c for c in daemon.calls if c[1] == "stop"] == []
    with pytest.raises(subprocess.TimeoutExpired):  # not sticky: the next command is executed again
        executor.run_parsed(bash_exec.parse(COMMAND), command=COMMAND, cwd=Path("/"), timeout=0.5)


@pytest.mark.parametrize("status", ["exited", "running"], ids=["stop-proven", "stop-unprovable"])
def test_o8_box_lost_stops_the_box_goes_sticky_and_keeps_its_identity_when_the_stop_faults(status):
    """The refusal stays for every later command, with no new exchange; an unprovable stop adds a note. (O8)"""
    attempts: list[int] = []

    def popen(argv, **kw):
        attempts.append(1)
        return subprocess.Popen(list(NOT_A_FRAME), **kw)

    executor, daemon = _executor(status, popen)
    with pytest.raises(box.BoxLost) as first:
        _asks(executor)
    assert ["docker", "stop", "-t", "0", NAME] in daemon.calls
    assert bool(getattr(first.value, "__notes__", [])) is (status == "running"), first.value.__notes__
    with pytest.raises(box.BoxLost):
        _asks(executor)
    assert len(attempts) == 1, "a refused box was asked to run another command"


def test_o8_a_box_with_no_container_attached_is_outside_the_rule():
    """The unattached default executor keeps its plain `BoxFault` (a retry), not a loss. (O8)"""
    with pytest.raises(box.BoxFault) as caught:
        _asks(box.BoxExecutor())
    assert not isinstance(caught.value, box.BoxLost)


def test_o8_an_unsandboxed_transport_is_outside_the_rule_and_asks_no_daemon():
    """A fallback transport with no frame stays a `BoxFault`; the daemon is never asked. (O8)"""
    from defender.tests.e2e._box665 import ScriptedTransport

    daemon = RecordingDocker(status="exited")
    executor = box.BoxExecutor(name=NAME, docker=daemon, transport=ScriptedTransport(box.RawExec(137, b"", b"")))
    assert not executor.sandboxed
    with pytest.raises(box.BoxFault) as caught:
        _asks(executor)
    assert not isinstance(caught.value, box.BoxLost)
    assert daemon.calls == []


def test_o8_a_clock_write_fault_is_outside_the_rule(tmp_path):
    """A box whose clock file cannot be written fails with its own `BoxFault`, before any exchange. (O8)"""
    executor, daemon = _executor("exited", _exchange_runs(*EXEC_KILLED))
    executor.clock_file = tmp_path / "no-such-dir" / "clock"
    executor.follow_clock(lambda: datetime.now(UTC))
    with pytest.raises(box.BoxFault) as caught:
        _asks(executor)
    assert not isinstance(caught.value, box.BoxLost)
    assert daemon.calls == []


def _reducer_run(root: Path, executor: box.BoxExecutor | None, sql: str = "'SELECT 1'", payload_size: int | None = None):
    """A real run whose gather lead reduces its payload through `defender-sql <sql>` on `executor` (None: the
    unboxed one), the payload made a sparse `payload_size` bytes when given; returns its queries rows."""
    from defender.records import RunPaths as Paths
    from defender.tests.e2e._replay_harness import GOLDEN_AB3, ReplayFn, Turn, VerbRecorder, drive, materialize
    from defender.tests.e2e.test_query_tool import DONE, elastic_ok, q
    from defender.tests.support.runtime.state._1255_view import model_path
    from defender._io import read_jsonl_rows

    run_dir = materialize(root, GOLDEN_AB3)
    payload = run_dir / "gather_raw" / "l-001" / "0.json"
    if payload_size is not None:
        payload.parent.mkdir(parents=True, exist_ok=True)
        with payload.open("wb") as big:
            big.truncate(payload_size)
    reduce = Turn(tool_calls=[("bash", {"command": f"cat {model_path(payload, run_dir=run_dir)} | defender-sql {sql}"})])
    main = ReplayFn([Turn(tool_calls=[("gather", {"lead_id": "l-001", "system": "elastic", "goal": "reduce",
                                                   "what_to_summarize": ["events"]})]), Turn(text="Investigation complete.")])
    # A planted payload stands in for the query's: the query would overwrite it.
    gather = ReplayFn([*([] if payload_size is not None else [q("elastic", "query", {"native_query": "FROM logs"})]), reduce, DONE])
    drive(run_dir, run_id="d1421-rows", main=main, gather=gather, verbs=elastic_ok(VerbRecorder()), box=executor)
    return [r for r in read_jsonl_rows(Paths(run_dir).executed_queries) if r.get("lead_id") == "l-001"], gather


def test_o6_a_killed_reducer_stage_is_recorded_as_a_row_with_the_same_digest_whatever_arrived(tmp_path):
    """Rule 2 is a result, so the queries table gets its shim row; the digest (the pitfall's merge key) is fixed. (O6, P1, O7)"""
    digests = []
    for n, exchange in enumerate((EXEC_KILLED, EXEC_KILLED_WITH_BYTES)):
        root = tmp_path / str(n)
        root.mkdir()
        executor, _daemon = _executor("running", _exchange_runs(*exchange))
        rows, gather = _reducer_run(root, executor)
        shim = [r for r in rows if r["verb"] == "bash"]
        assert len(shim) == 1, f"the killed exchange left no row: {rows}"
        assert shim[0]["error_class"] == "agent-fixable"
        assert shim[0]["payload_digest"].startswith("exit=-9; ")
        assert "memory" in shim[0]["payload_digest"].lower()
        assert "memory" in gather.seen[-1].lower()
        digests.append(shim[0]["payload_digest"])
    assert digests[0] == digests[1]


def _merge_key_of(row: dict) -> tuple[str, str]:
    """The pitfall key of a shim row as the curator's queue carries it: the row's digest is the queue's `stderr_digest`."""
    from defender.learning.core.persist import pitfall_key

    return pitfall_key({"query_id": row["query_id"], "system": "", "pitfall_id": f"r:{row['lead_id']}:{row['seq']}",
                        "stderr_digest": row["payload_digest"]})


def _two_triggers_one_key(tmp_path: Path, runs: list[dict], start: str) -> None:
    keys = []
    for n, kw in enumerate(runs):
        root = tmp_path / str(n)
        root.mkdir()
        rows, _gather = _reducer_run(root, **kw)
        shim = [r for r in rows if r["verb"] == "bash"]
        assert len(shim) == 1, f"trigger {n} left no shim row: {rows}"
        assert shim[0]["payload_digest"].startswith(start), shim[0]["payload_digest"]
        keys.append(_merge_key_of(shim[0]))
    assert keys[0] == keys[1] == keys[-1], keys
    assert not keys[0][1].startswith("\x00"), "a digest read as content-less never merges"


def test_p1_the_kill_line_gives_one_pitfall_key_whatever_arrived_before_it(tmp_path):
    """Three triggers of one kill (nothing, partial bytes, half a frame) merge into one pitfall. (P1, O6)"""
    runs = [{"executor": _executor("running", _exchange_runs(*x))[0]}
            for x in (EXEC_KILLED, EXEC_KILLED_WITH_BYTES, EXEC_KILLED_MID_FRAME)]
    _two_triggers_one_key(tmp_path, runs, "exit=-9; ")


def test_p1_the_size_refusal_gives_one_pitfall_key_on_both_load_paths_and_at_any_size(tmp_path):
    """The payload-maximum refusal through the real bash tool: undeclared, declared and larger merge. (P1, O1)"""
    over = 64 << 20
    declared = "--rows values --names columns 'SELECT 1'"
    runs = [{"executor": None, "payload_size": over + 1}, {"executor": None, "sql": declared, "payload_size": over + 1},
            {"executor": None, "payload_size": over + (1 << 20)}]
    _two_triggers_one_key(tmp_path, runs, "exit=2; ")


def test_o5_a_command_printing_too_much_keeps_the_run_alive(tmp_path):
    """Exit 75 reaches the model with no partial output; the run goes on to end cleanly. (O5, decision 2)"""
    def plant_big_file(run_dir: Path) -> None:
        with (run_dir / "big.bin").open("wb") as big:  # sparse: reads as zeros, costs no disk
            big.truncate(box.BOX_OUTPUT_LIMIT + 1)

    main = S.MainScript([S.call("bash", command="cat big.bin"), S.text(S.DONE)])
    result = S.run_alert(tmp_path, main=main, before=plant_big_file)  # the unsandboxed transport: bounded too
    assert result.raised is None, result.raised
    assert result.rc == 0
    assert _run_end(result).truncated_by is None
    assert main.requests == 2
    said = "\n".join(main.seen[1].tool_returns)
    assert "exit=75" in said, said[:400]
    assert "\0" not in said, "partial output reached the model"


def _torn_down(exchange: tuple[str, ...], *, teardown_faults: bool, seen: list[str]) -> dict:
    seams = _boxed("exited", _exchange_runs(*exchange))

    def stop(*_a, **_k) -> None:
        seen.append("stop")
        if teardown_faults:
            raise box.BoxFault("could not tear down the box")

    return {**seams, "stop_box": stop}


@pytest.mark.parametrize(("exchange", "code", "named"), [
    (EXEC_KILLED, 5, "box-lost"), (OVER_THE_FENCE, 6, "box-output-limit")], ids=["box-lost", "fence"])
@pytest.mark.parametrize(("teardown_faults", "pages", "checks"), [(True, 0, 0), (False, 1, 1)],
                         ids=["teardown-fault", "control-clean-teardown"])
def test_o8_a_teardown_fault_cannot_replace_the_ending_and_skips_the_post_steps(
        tmp_path, teardown_faults, pages, checks, exchange, code, named):
    """A box that may be alive: its exit still returned, nothing read or published from its tree; a proven stop runs them. (O8, O9)"""
    stops: list[str] = []
    rendered: list[object] = []
    with counting_calls(cross_check=run_common.cross_check_tables) as calls:
        result = S.run_alert(
            tmp_path, main=S.MainScript([S.call("bash", command=COMMAND), S.text(S.DONE)]),
            visualize=lambda *a, **_k: rendered.append(a),
            box_lifecycle=_torn_down(exchange, teardown_faults=teardown_faults, seen=stops))
    assert stops, "the lifecycle never tore the box down, so the fault proves nothing"
    assert result.raised is None, result.raised
    assert result.rc == code
    assert _run_end(result).truncated_by == named
    assert len(rendered) == pages
    assert calls.counts["cross_check"] == checks


def test_control_a_clean_run_through_the_real_lifecycle_reads_its_tree_and_exits_0(tmp_path):
    """The seams above reach the post-steps they count when no box ending is involved. (O8)"""
    wire = box.encode_response(box.BoxResult(rc=0, out=b"hello\n", err=b""))
    rendered: list[object] = []
    main = S.MainScript([S.call("bash", command=COMMAND), S.text(S.DONE)])
    with counting_calls(cross_check=run_common.cross_check_tables) as calls:
        result = S.run_alert(tmp_path, main=main, visualize=lambda *a, **_k: rendered.append(a),
                             box_lifecycle=_boxed("running",
                                                  _exchange_runs("python3", "-c", f"import os; os.write(1, {wire!r})")))
    assert result.raised is None, result.raised
    assert result.rc == 0
    assert "hello" in "\n".join(main.seen[1].tool_returns)
    assert len(rendered) == 1
    assert calls.counts["cross_check"] == 1


@pytest.mark.parametrize(("exchange", "code", "named"), [
    (EXEC_KILLED, 5, "box-lost"), (OVER_THE_FENCE, 6, "box-output-limit")], ids=["box-lost", "fence"])
def test_o8_o9_a_run_the_model_had_closed_keeps_its_report_and_its_case_comment_and_still_exits_by_class(
        tmp_path, exchange, code, named):
    """Closed, then the ending: `closed_before_cut` stands, the case is commented on, the exit is 5 or 6. (O8, O9, decision 3)"""
    main = S.MainScript([*S.closing_main_turns()[:2], S.call("bash", command=COMMAND), S.text(S.DONE)])
    result = S.run_alert(tmp_path, main=main, box_lifecycle=_boxed("exited", _exchange_runs(*exchange)))
    assert result.raised is None, result.raised
    end = _run_end(result)
    assert end.truncated_by == named
    assert end.closed_before_cut is True
    assert result.report is not None
    assert ticket_writer.comments_on(end.truncated_by, end.closed_before_cut) is True
    assert result.rc == code


@pytest.mark.parametrize(("exchange", "code", "named"), [
    (EXEC_KILLED, 5, "box-lost"), (OVER_THE_FENCE, 6, "box-output-limit")], ids=["box-lost", "fence"])
@pytest.mark.parametrize("closed", [True, False], ids=["model-closed", "not-closed"])
def test_o8_o9_the_case_is_commented_on_only_when_the_model_had_closed_before_the_ending(
        tmp_path, exchange, code, named, closed):
    """Through the ticketed run: one comment for a model-closed run, none for an unclosed one. (O8, O9, decision 3)"""
    store = S.TicketStore(tmp_path)
    main = S.MainScript([*(S.closing_main_turns()[:2] if closed else []),
                         S.call("bash", command=COMMAND), S.text(S.DONE)])
    result = S.run_alert(tmp_path, main=main, alert=S.ticketed_alert(),
                         tenant=S.ticket_the_tenant(S.plant_tenant()), tickets=S.ticket_writer(store),
                         update_ticket=True, box_lifecycle=_boxed("exited", _exchange_runs(*exchange)))
    assert result.raised is None, result.raised
    assert result.rc == code
    assert _run_end(result).truncated_by == named
    assert (result.report is not None) is closed
    assert len(store.comment_payloads) == (1 if closed else 0), store.calls


def test_control_a_closed_run_with_no_ending_comments_on_the_case_through_the_same_harness(tmp_path):
    """The ticketed, learn-enabled harness does see a comment and a curation enqueue when due. (O8)"""
    store = S.TicketStore(tmp_path)
    result = S.run_alert(tmp_path, main=S.MainScript(S.closing_main_turns()), alert=S.ticketed_alert(),
                         tenant=S.ticket_the_tenant(S.plant_tenant()), tickets=S.ticket_writer(store),
                         update_ticket=True, no_learn=False)
    assert result.rc == 0
    assert len(store.comment_payloads) == 1, store.calls
    assert len(result.enqueued) == 1, result.enqueued


@pytest.mark.parametrize(("exchange", "code", "named"), [
    (EXEC_KILLED, 5, "box-lost"), (OVER_THE_FENCE, 6, "box-output-limit")], ids=["box-lost", "fence"])
def test_o8_o9_a_model_closed_run_whose_stop_faulted_is_not_commented_or_curated(tmp_path, exchange, code, named):
    """The box may be alive, so the closed run's case gets no comment and its tree no curation; the ending's exit stands. (O8, O9)"""
    store = S.TicketStore(tmp_path)
    stops: list[str] = []
    main = S.MainScript([*S.closing_main_turns()[:2], S.call("bash", command=COMMAND), S.text(S.DONE)])
    result = S.run_alert(tmp_path, main=main, alert=S.ticketed_alert(), tenant=S.ticket_the_tenant(S.plant_tenant()),
                         tickets=S.ticket_writer(store), update_ticket=True, no_learn=False,
                         box_lifecycle=_torn_down(exchange, teardown_faults=True, seen=stops))
    assert stops, "the lifecycle never tore the box down, so the fault proves nothing"
    assert result.raised is None, result.raised
    assert result.rc == code
    assert _run_end(result).truncated_by == named
    assert store.comment_payloads == [], store.calls
    assert result.enqueued == [], result.enqueued


@pytest.mark.parametrize("exchange", [EXEC_KILLED, OVER_THE_FENCE], ids=["box-lost", "fence"])
def test_o8_o9_the_run_log_names_the_command_that_met_the_ending(tmp_path, caplog, exchange):
    """The records and the job text carry only the class; the log is where an operator finds the command. (O8, O9)"""
    command = "echo marker-1421-unique"
    caplog.set_level(logging.INFO)
    main = S.MainScript([S.call("bash", command=command), S.text(S.DONE)])
    result = S.run_alert(tmp_path, main=main, box_lifecycle=_boxed("exited", _exchange_runs(*exchange)))
    assert result.rc in (5, 6)
    assert any(command in r.getMessage() for r in caplog.records), [r.getMessage() for r in caplog.records]
    assert command not in RunPaths(result.folder).run_end_sidecar().read_text(encoding="utf-8")


@pytest.mark.parametrize("named", ["box-lost", "box-output-limit"])
def test_o8_o9_a_box_ending_leaves_the_case_uncommented_unless_the_model_had_closed(named):
    """`comments_on` normalizes first, so the class must be in the vocabulary or this reads as True. (O8, O9)"""
    assert ticket_writer.comments_on(named, False) is False
    assert ticket_writer.comments_on(named, True) is True


@pytest.mark.parametrize("runtime", ["runsc", "runc"])
def test_live_box_output_past_the_budget_is_a_result_and_past_the_helper_is_a_fence_trip(tmp_path, runtime):
    """A cooperating command gets exit 75 and the box lives; a process writing to the helper's own
    stdout trips the fence, which stops the box for good. (O5, O9, P4)"""
    if not daemon_reachable():
        pytest.skip("no reachable Docker daemon")
    if runtime not in docker_runtimes():
        pytest.skip(f"runtime {runtime} is not registered")
    anchor = dood_anchor() if is_dood() else tmp_path
    if anchor is None:
        pytest.skip("Docker daemon cannot bind the checkout")
    root = anchor / f"output-1205-{uuid.uuid4().hex}"
    root.mkdir(parents=True)
    executor = None
    try:
        run_dir = make_run_dir(root, name="run-1205")
        executor = box.start_box(run_dir, Path(__file__).resolve().parents[2],
                                 spec=box.BoxSpec(runtime=runtime), tenant_id=TEST_TENANT, data_root=current_data_root())
        assert executor.sandboxed
        cwd = Path("/runs/current")
        control = executor.run_parsed(bash_exec.parse("echo answer"), command="echo answer", cwd=cwd, timeout=30)
        assert control.out == b"answer\n"
        # Finite output keeps a regression safe: ~64 MiB, never an unbounded producer.
        command = f"head -c {box.BOX_OUTPUT_LIMIT + 1} /dev/zero"
        stopped = executor.run_parsed(bash_exec.parse(command), command=command, cwd=cwd, timeout=60)
        assert stopped.rc == 75
        assert stopped.out == b""
        again = executor.run_parsed(bash_exec.parse("echo answer"), command="echo answer", cwd=cwd, timeout=30)
        assert again.out == b"answer\n", "the box did not survive the helper stopping a command"

        if runtime != "runc":
            # On runsc (CI, #1421) a write through `/proc/$PPID/fd/1` reaches the exec stream as bytes
            # that are no frame and never trips the fence; no way to trip it there is known, so the
            # fence half is verified on runc only (owner decision).
            return
        # Written past the helper, as C13's child did: `$PPID`'s stdout is the exec stream.
        bypass = ("python3 -c "
                  f"\"import os; f = os.open(f'/proc/{{os.getppid()}}/fd/1', os.O_WRONLY); "
                  f"[os.write(f, bytes(1 << 20)) for _ in range({(box.BOX_OUTPUT_LIMIT >> 20) + 1})]\"")
        with pytest.raises(box.BoxOutputLimitExceeded):
            executor.run_parsed(bash_exec.parse(bypass), command="bypass", cwd=cwd, timeout=60)
        status = box.run_docker(["docker", "inspect", "-f", "{{.State.Status}}", executor.name])
        # The run box is auto-removed once stopped (#1343 B10): stopped is `exited`/`dead`, being removed, or already
        # gone (the product's own stopped test, `BoxRuns._stopped`, takes `removing` for an auto-removed box).
        assert status.stdout.strip() in {"exited", "dead", "removing"} or (
            status.returncode != 0 and "no such object" in status.stderr.lower())
        with pytest.raises(box.BoxOutputLimitExceeded):
            executor.run_parsed([], command="again", cwd=cwd, timeout=5)
    finally:
        if executor is not None:
            box.stop_box(executor)
        shutil.rmtree(root)
