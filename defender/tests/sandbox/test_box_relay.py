"""#1170 A4: the job-side box over the relay. A box reached over the job socket is sandboxed by construction, every command goes over
the relay, and each of the helper's answers becomes today's typed ending (#1421); the stop goes through `box.stop`. Fakes enter at
the job's socket client (`ScriptedHelper`); the helper's own classification is `jobs/test_box_relay_helper.py`."""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from defender import box
from defender.execution import bash_exec
from defender.execution.box_codec import KILLED_LINE
from defender.records.run_end import TRUNCATED_BY_BOX_LOST, TRUNCATED_BY_BOX_OUTPUT_LIMIT
from defender.tests.e2e._box665 import ScriptedTransport, framed
from defender.tests.support.jobs._box_relay import (
    HANDLE,
    KILLED,
    LOST,
    OUTPUT_LIMIT,
    STOP_FAULT,
    TIMEOUT,
    ScriptedHelper,
    ok,
    relay_executor,
)

COMMAND = "echo hello"


def _ask(executor: box.BoxExecutor, command: str = COMMAND, *, timeout: float = 5, cwd: str = "/runs/current"):
    return executor.run_parsed(bash_exec.parse(command), command=command, cwd=Path(cwd), timeout=timeout)


def test_a4_a_box_reached_over_the_relay_counts_as_sandboxed_and_an_unconfined_transport_does_not():
    """Sandboxed is derived from the transport: the relay is confining by construction; a host or scripted one is not. (A4)"""
    assert relay_executor(ScriptedHelper()).sandboxed is True
    assert box.BoxExecutor(name="x", transport=ScriptedTransport(framed(0, b"", b""))).sandboxed is False


def test_a4_a_relay_box_is_never_taken_for_host_execution_when_its_run_is_reaped():
    """`stop_and_scrub` marks a tree `unsandboxed` only for a box that is not; over the relay it must not. Control: the scripted one. (A4)"""
    def reaped(executor, stop) -> list[dict]:
        verdicts: list[dict] = []
        box.stop_and_scrub(executor, Path("/nonexistent-tree"), stop_box=stop, scrub_tree=lambda _t: None, in_flight=False,
                           read_verdict=lambda: None, write_verdict=verdicts.append)
        return verdicts

    assert reaped(box.BoxExecutor(name="x", transport=ScriptedTransport(framed(0, b"", b""))), lambda _b: None) != [], \
        "control: an unconfined transport was not marked unsandboxed"
    assert reaped(relay_executor(ScriptedHelper()), box.stop_box) == []


def test_a4_every_command_goes_over_the_relay_as_its_frame_with_its_handle_cwd_and_timeout():
    """The frame the executor encodes, the handle, the cwd and the timeout reach `box.exec` unchanged, and the answer's frame is the result. (A4)"""
    helper = ScriptedHelper(ok(0, b"from-the-box\n", b"e"))
    result = _ask(relay_executor(helper), timeout=7.25, cwd="/runs/current/sub")
    assert result == box.BoxResult(rc=0, out=b"from-the-box\n", err=b"e")
    (sent,) = helper.asked("box.exec")
    assert sent["handle"] == HANDLE
    assert sent["frame"] == box.encode_request(bash_exec.parse(COMMAND))
    assert str(sent["cwd"]) == "/runs/current/sub"
    assert sent["timeout"] == 7.25
    assert [n for n, _f in helper.calls] == ["box.exec"], "the job asked the helper for something other than the command"


@pytest.mark.parametrize("rc", [137, -9, 75, 2, 3, 127])
def test_a4_a_command_s_own_exit_inside_the_frame_is_its_result_whatever_the_code(rc):
    """Control for the kill line: only the helper's own `ok` kill line is the killed result, a frame's code is the command's. (A4)"""
    helper = ScriptedHelper(ok(rc, b"o\n", b"e\n"))
    assert _ask(relay_executor(helper)) == box.BoxResult(rc=rc, out=b"o\n", err=b"e\n")
    assert helper.asked("box.stop") == []


@pytest.mark.parametrize("value", [0.5, 7.25, 120, 901, 3600, 86400.5])
def test_a4_the_relay_forwards_the_executors_own_timeout_without_a_ceiling_of_its_own(value):
    """No new cap: the helper bounds a command by the timeout the executor was given, so the job sends it as given. (A4, O10)"""
    helper = ScriptedHelper(ok())
    _ask(relay_executor(helper), timeout=value)
    assert helper.asked("box.exec")[0]["timeout"] == value


def test_a4_the_helper_s_kill_line_is_a_result_the_run_goes_on_from_and_the_box_is_not_stopped():
    """`ok` carrying the kill line: rc -9, no bytes, the fixed line; nothing stopped, the next command is asked. (A4, #1421 rule 2)"""
    helper = ScriptedHelper(KILLED, ok(0, b"next\n"))
    executor = relay_executor(helper)
    assert _ask(executor) == box.BoxResult(rc=-9, out=b"", err=KILLED_LINE)
    assert _ask(executor).out == b"next\n"
    assert helper.asked("box.stop") == []


def test_a4_a_timeout_answer_is_the_timeout_and_the_box_stays_usable():
    """`timeout`: `TimeoutExpired`, no stop, not sticky: the next command is asked. (A4, #1421 rule 3)"""
    helper = ScriptedHelper(TIMEOUT, TIMEOUT)
    executor = relay_executor(helper)
    for _ in range(2):
        with pytest.raises(subprocess.TimeoutExpired):
            _ask(executor)
    assert len(helper.asked("box.exec")) == 2
    assert helper.asked("box.stop") == []


@pytest.mark.parametrize(("answer", "ending", "word"), [
    (OUTPUT_LIMIT, box.BoxOutputLimitExceeded, TRUNCATED_BY_BOX_OUTPUT_LIMIT),
    (LOST, box.BoxLost, TRUNCATED_BY_BOX_LOST),
], ids=["output-limit", "lost"])
def test_a4_an_ending_answer_raises_its_typed_ending_stops_the_box_through_the_relay_and_refuses_every_later_command(answer, ending, word):
    """The ending's class, one `box.stop` for the handle, and no further `box.exec`. (A4, #1421 O8)"""
    helper = ScriptedHelper(answer, ok(0, b"must not run\n"))
    executor = relay_executor(helper)
    with pytest.raises(ending) as first:
        _ask(executor)
    assert first.value.exit_class == word
    assert helper.asked("box.stop") == [{"handle": HANDLE}]
    for _ in range(2):
        with pytest.raises(ending):
            _ask(executor)
    assert len(helper.asked("box.exec")) == 1, "a refused box was asked to run another command"
    assert len(helper.asked("box.stop")) == 1


def test_a4_readmit_lifts_a_lost_box_s_refusal_but_not_the_output_limit_s():
    """A lane window that proves its box started lifts a loss, never the fence. Controls: the same sequence without `readmit`. (A4)"""
    lost = ScriptedHelper(LOST, ok(0, b"again\n"))
    executor = relay_executor(lost)
    with pytest.raises(box.BoxLost):
        _ask(executor)
    with pytest.raises(box.BoxLost):
        _ask(executor)
    assert len(lost.asked("box.exec")) == 1, "control: the loss did not refuse without a readmit"
    executor.readmit()
    assert _ask(executor).out == b"again\n"

    fence = ScriptedHelper(OUTPUT_LIMIT, ok())
    fenced = relay_executor(fence)
    with pytest.raises(box.BoxOutputLimitExceeded):
        _ask(fenced)
    fenced.readmit()
    with pytest.raises(box.BoxOutputLimitExceeded):
        _ask(fenced)
    assert len(fence.asked("box.exec")) == 1


class _HelperGone(Exception):
    """A test-defined failure of the socket client."""


@pytest.mark.parametrize("failure", [
    ConnectionResetError("reset"), BrokenPipeError("pipe"), FileNotFoundError("socket"), ConnectionRefusedError("refused"),
    TimeoutError("no answer"), _HelperGone("gone"),
], ids=lambda f: type(f).__name__)
def test_a4_a_helper_that_cannot_be_reached_is_a_lost_box_and_the_unreachable_stop_keeps_the_ending(failure):
    """The box ends with its helper, so no answer is a loss; the stop that also gets no answer adds a note, not another type. (A4)"""
    helper = ScriptedHelper(failure, stop=failure)
    executor = relay_executor(helper)
    with pytest.raises(box.BoxLost) as caught:
        _ask(executor)
    assert getattr(caught.value, "__notes__", []), "the stop could not be proven and the ending says nothing of it"
    with pytest.raises(box.BoxLost):
        _ask(executor)
    assert len(helper.asked("box.exec")) == 1


@pytest.mark.parametrize("answer", [
    {}, {"result": None}, {"result": 0}, {"result": "ok-ish"}, {"result": "OK"}, {"result": "lost?"}, {"status": "ok"}, "ok", None, [],
], ids=repr)
def test_a4_an_answer_outside_the_helpers_vocabulary_is_a_lost_box_not_a_result(answer):
    """The relay fails closed: nothing but `ok`, `output-limit`, `timeout` or `lost` is taken for a command's outcome. (A4)"""
    with pytest.raises(box.BoxLost):
        _ask(relay_executor(ScriptedHelper(answer)))


@pytest.mark.parametrize("answer", [
    {"result": "ok", "frame": b""},
    {"result": "ok", "frame": b"not a response frame"},
    {"result": "ok", "frame": ok(0, b"hello\n")["frame"][:-3]},
    {"result": "ok", "frame": ok(0, b"hello\n")["frame"] + b"trailing"},
    {"result": "ok", "frame": None},
    {"result": "ok", "frame": "text, not bytes"},
    {"result": "ok"},
], ids=["empty", "garbage", "truncated", "trailing-bytes", "frame-none", "frame-text", "frame-missing"])
def test_a4_an_ok_answer_whose_frame_does_not_decode_is_a_lost_box_like_any_other_loss(answer):
    """The relay fails closed on the frame too, not only on the answer's word: `ok` with bytes that are not a response frame is
    not a command's result. It ends the box as lost (the class `box-lost`), stops it through the relay once, and every later
    command is refused with no further `box.exec`. Control: a valid `ok` frame is the result, from the same executor. (A4, B-G2, P2)"""
    control = relay_executor(ScriptedHelper(ok(0, b"fine\n")))
    assert _ask(control).out == b"fine\n", "control: a well-formed ok frame is the command's result"

    helper = ScriptedHelper(answer, ok(0, b"must not run\n"))
    executor = relay_executor(helper)
    with pytest.raises(box.BoxLost) as first:
        _ask(executor)
    assert first.value.exit_class == TRUNCATED_BY_BOX_LOST
    assert helper.asked("box.stop") == [{"handle": HANDLE}]
    for _ in range(2):
        with pytest.raises(box.BoxLost):
            _ask(executor)
    assert len(helper.asked("box.exec")) == 1, "a box whose answer could not be read was asked to run another command"
    assert len(helper.asked("box.stop")) == 1


def test_a4_a_stop_the_helper_proves_returns_and_one_it_cannot_is_a_teardown_fault():
    """`box.stop` over the relay: `stopped` returns, `fault` is a `BoxFault` carrying the helper's reason. (A4)"""
    helper = ScriptedHelper()
    box.stop_box(relay_executor(helper))
    assert helper.asked("box.stop") == [{"handle": HANDLE}]

    broken = ScriptedHelper(stop=STOP_FAULT)
    with pytest.raises(box.BoxFault, match="could not stop the box"):
        box.stop_box(relay_executor(broken))
    assert len(broken.asked("box.stop")) == 1


@pytest.mark.parametrize("answer", [OUTPUT_LIMIT, LOST], ids=["output-limit", "lost"])
def test_a4_a_teardown_fault_cannot_replace_a_box_ending_and_a_proven_stop_adds_no_note(answer):
    """The ending keeps its identity when the stop faults, with a note; controls: a proven stop leaves no note. (A4, #1421 O8)"""
    kinds = {"output-limit": box.BoxOutputLimitExceeded, "lost": box.BoxLost}
    ending = kinds[answer["result"]]
    for stop, noted in ((STOP_FAULT, True), ({"result": "stopped"}, False)):
        with pytest.raises(ending) as caught:
            _ask(relay_executor(ScriptedHelper(answer, stop=stop)))
        assert bool(getattr(caught.value, "__notes__", [])) is noted


@pytest.mark.parametrize("stop", [{"result": "stopped"}, STOP_FAULT], ids=["stopped", "teardown-fault"])
def test_a4_the_scrub_gate_over_a_relay_box_walks_the_tree_only_when_the_helper_proved_it_stopped(stop):
    """`stop_and_scrub` with the real `stop_box`: a fault under an in-flight ending skips the walk and reports the box not down;
    a proof lets the walk run. This is what `TEARDOWN_FAULTED` reads. (A4)"""
    walked: list[Path] = []
    down = box.stop_and_scrub(relay_executor(ScriptedHelper(stop=stop)), Path("/nonexistent-tree"), stop_box=box.stop_box,
                              scrub_tree=walked.append, in_flight=True, read_verdict=lambda: None, write_verdict=lambda _v: None)
    assert down is (stop["result"] == "stopped")
    assert bool(walked) is down
