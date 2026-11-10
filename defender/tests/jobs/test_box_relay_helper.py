"""#1170 A4, O10, B10: the helper owns the daemon-facing part of #1421. It answers `box.exec` with `ok`, `output-limit`, `timeout` or
`lost`, `box.stop` with proof or a teardown fault, holds the run box's attached starter, and bounds a runaway box at itself. Driven
through the real `job_host.main` over a published tenant, as `test_job_helper.py` does; the daemon is `RelayDocker`. Wire and names
are picks, see `support/jobs/_box_relay.py`."""
from __future__ import annotations

import gc
import json
import os
import subprocess
import sys
import time
import uuid

import pytest
from defender import box
from defender.execution.box_codec import BOX_OUTPUT_LIMIT, KILLED_LINE
from defender.records.run_end import TRUNCATED_BY_BOX_LOST
from defender.tests.support.jobs import _box_relay as R
from defender.tests.support.jobs import _job_helper as J
from defender.tests.support.jobs._job_helper import (  # noqa: F401 — process_state is autouse, scene a fixture
    drive_helper,
    make_signer,
    until,
)
from defender.tests.support.sandbox._box1343 import input_open

# The shared fixtures (`_job_helper`'s docs): `process_state` is autouse, `scene` the default helper scene.
process_state = J.process_state
scene = J.scene

pytestmark = [pytest.mark.postgres, pytest.mark.skipif(
    not sys.platform.startswith("linux"), reason="reads /proc and uses prctl(PR_SET_PDEATHSIG), Linux only")]

LOST = {"result": "lost", "class": TRUNCATED_BY_BOX_LOST}


def _run(scene, docker: R.RelayDocker, asks):
    """One investigation helper whose job starts a shell box, then runs `asks(client, handle, got)`; returns `got`."""
    inv = str(uuid.uuid4())
    scene.plant(inv)
    got: dict = {"inv": inv}

    def job(c) -> int:
        got["handle"] = c.request("box.start", kind="shell", id=inv)["handle"]
        asks(c, got["handle"], got)
        return 0

    docker.job = job
    ran = drive_helper(scene, scene.argv("investigation", inv), docker=docker, signer=make_signer())
    assert ran.raised is None, ran.raised
    assert docker.job_error is None, docker.job_error
    got["ran"] = ran
    return got


def _exec_once(scene, *, state="running", exec_with=None, timeout=5.0, frame=R.FRAME, cwd="/runs/current"):
    docker = R.RelayDocker()
    docker.exec_with = exec_with

    def asks(c, h, got):
        docker.put(state)
        got["before"] = docker.status_asks()
        started = time.monotonic()
        got["answer"] = c.request("box.exec", handle=h, frame=frame, cwd=cwd, timeout=timeout)
        got["took"] = time.monotonic() - started
        got["after"] = docker.status_asks()

    got = _run(scene, docker, asks)
    got["docker"] = docker
    return got


def _killed_line(answer: dict) -> box.BoxResult:
    return box.decode_response(answer["frame"])


# --- A4: where a box exchange is classified ----------------------------------------------------------------------------

@pytest.mark.parametrize(("state", "exchange"), [
    ("exited", R.EXEC_KILLED),  # rule 1, box dead
    ("gone", R.EXEC_SAYS_NO_SUCH_BOX),  # rule 1, box gone
    ("mute", R.EXEC_KILLED),  # rule 1, the daemon says nothing
    ("raises", R.EXEC_KILLED),  # rule 1, asking faults
    ("exited", OSError("docker client")),  # rule 1, the client cannot run
    ("exited", R.EXEC_HELPER_DEADLINE),  # rule 1 outranks rule 3 on a box not running
    ("running", R.NOT_A_FRAME),  # rule 4
    ("running", R.EXEC_REFUSED_REQUEST),  # rule 4: rc 2 is not rule 3
    ("running", OSError("docker client")),  # rule 4, transport exception
], ids=["box-exited", "box-gone", "daemon-mute", "status-raises", "exited-transport-exception", "exited-helper-deadline",
        "running-no-frame", "running-exec-rc-2", "running-transport-exception"])
def test_a4_an_exchange_with_no_frame_on_a_box_the_helper_cannot_vouch_for_is_answered_lost_with_its_class(scene, state, exchange):
    """The helper asked the daemon once and answers `lost` with the box-lost class, carrying no bytes of the exchange. (A4, #1421 rules 1, 4)"""
    got = _exec_once(scene, state=state, exec_with=exchange)
    assert got["answer"] == LOST, got["answer"]
    assert got["after"] > got["before"], "the box was judged lost without asking its status"


@pytest.mark.parametrize(("exchange", "timeout"), [
    (R.SLEEPS, 0.5),  # the helper's own deadline on the host: no exec status at all
    (R.EXEC_HELPER_DEADLINE, 5.0),  # exec 3
    (R.EXEC_KILLED, 5.0),  # exec 137
    (R.NOT_A_FRAME, 5.0),  # bytes that are no frame
], ids=["host-timeout", "exec-3", "exec-137", "no-frame"])
def test_a4_every_frameless_end_on_a_box_that_has_exited_is_lost_with_its_class_never_a_timeout_or_a_kill(
        scene, exchange, timeout):
    """On a box the daemon shows exited, each way an exchange can end without a frame (the helper's own deadline passing,
    exec 3, exec 137, bytes that are no frame) is `lost` with the box-lost class, judged after asking the box's status:
    rule 1 outranks the timeout and the kill. Control: on a running box the same host deadline is `timeout`
    (`test_a4_a_command_outliving_the_timeout...`). (A4, #1421 rule 1)"""
    got = _exec_once(scene, state="exited", exec_with=exchange, timeout=timeout)
    assert got["answer"] == LOST, got["answer"]
    assert got["after"] > got["before"], "the box was judged without asking its status"


@pytest.mark.parametrize("exchange", [R.EXEC_KILLED, R.EXEC_KILLED_WITH_BYTES, R.EXEC_KILLED_MID_FRAME],
                         ids=["no-bytes", "partial-bytes", "half-a-frame"])
def test_a4_exec_137_with_the_box_running_is_an_ok_carrying_the_fixed_kill_line_whatever_arrived(scene, exchange):
    """Rule 2 (control for the lost arm, same box state): `ok`, rc -9, no output, the kill line; no bytes of the killed exchange. (A4, #1421 rule 2)"""
    got = _exec_once(scene, exec_with=exchange)
    assert got["answer"]["result"] == "ok", got["answer"]
    assert _killed_line(got["answer"]) == box.BoxResult(rc=-9, out=b"", err=KILLED_LINE)
    assert b"partial output" not in got["answer"]["frame"]
    assert got["after"] > got["before"], "the kill was judged without asking the box's status"


def test_a4_the_helpers_own_deadline_with_the_box_running_is_a_timeout_answer(scene):
    """Rule 3: exec rc 3 on a running box is `timeout`, not a loss (control for the exited-helper-deadline row). (A4, #1421 rule 3)"""
    assert _exec_once(scene, exec_with=R.EXEC_HELPER_DEADLINE)["answer"] == R.TIMEOUT


def test_a4_a_command_outliving_the_timeout_it_was_given_is_answered_timeout_at_that_timeout(scene):
    """The deadline is the timeout the job passed (the executor's own per-command timeout; no other ceiling): a command that
    sleeps is cut at 0.5 s, long before it would end, and the box is still running. (A4, O10; control: the sleeper is real)"""
    got = _exec_once(scene, exec_with=R.SLEEPS, timeout=0.5)
    assert got["answer"] == R.TIMEOUT, got["answer"]
    assert 0.4 <= got["took"] < 10, got["took"]
    assert got["docker"].status_asks() > got["before"]


def test_a4_a_timeout_that_is_no_deadline_never_leaves_the_helper_waiting_on_a_command(scene):
    """An infinite timeout is answered by a refusal or a timeout within a bound, never by waiting out the command. (A4, O10)"""
    from defender import job_host

    docker = R.RelayDocker()
    docker.exec_with = R.SLEEPS
    seen: dict = {}

    def asks(c, h, got):
        docker.put("running")
        started = time.monotonic()
        try:
            seen["answer"] = c.request("box.exec", handle=h, frame=R.FRAME, cwd="/runs/current", timeout=float("inf"))
        except job_host.Refused as refused:
            seen["answer"] = str(refused)
        seen["took"] = time.monotonic() - started

    _run(scene, docker, asks)
    assert seen["took"] < 15, f"the helper waited {seen['took']:.1f}s on a command given no deadline"
    assert not (isinstance(seen["answer"], dict) and seen["answer"].get("result") == "ok"), seen["answer"]


@pytest.mark.parametrize("rc", [137, 75, 2, 3, 0])
def test_a4_a_clean_frame_is_relayed_untouched_and_no_status_is_asked(scene, rc):
    """Control for the matrix: a command's own code inside a good frame is its result, bytes unchanged, and the daemon is not asked. (A4)"""
    frame = box.encode_response(box.BoxResult(rc=rc, out=b"o\n\xff\x00", err=b"e\n"))
    got = _exec_once(scene, exec_with=R.printing(frame))
    assert got["answer"] == {"result": "ok", "frame": frame}
    assert got["after"] == got["before"]


def test_a4_the_exchange_runs_in_the_helpers_own_box_at_the_cwd_the_job_named(scene):
    """The `docker exec` is for the container the helper created for this handle, at the job's cwd, with the job's frame on stdin. (A4, C5)"""
    docker = R.RelayDocker()
    docker.exec_with = R.printing(R.OK_FRAME)
    got = _run(scene, docker, lambda c, h, g: g.update(answer=c.request("box.exec", handle=h, frame=R.FRAME, cwd="/runs/current/sub",
                                                                         timeout=5.0)))
    assert got["answer"]["result"] == "ok"
    (create,) = docker.creates()
    name = create[create.index("--name") + 1]
    (exec_argv,) = [c for c in docker.calls if len(c) > 1 and c[1] == "exec" and "defender.execution.bash_exec" in c]
    assert exec_argv[exec_argv.index("-w") + 1] == "/runs/current/sub"
    assert name in exec_argv


@pytest.mark.parametrize("handle", ["other-container", "../../etc/passwd", "", "/var/run/docker.sock", "<job-container>"],
                         ids=["name", "path", "empty", "socket", "the-job-container"])
def test_a4_box_exec_runs_only_in_a_box_the_helper_started_for_this_job(scene, handle):
    """A handle the helper did not mint is refused and no `docker exec` is made; control: the minted one is answered. (A4, O9)"""
    from defender import job_host

    docker = R.RelayDocker()
    docker.exec_with = R.printing(R.OK_FRAME)
    seen: dict = {}

    def asks(c, h, got):
        seen["control"] = c.request("box.exec", handle=h, frame=R.FRAME, cwd="/runs/current", timeout=5.0)
        before = len([x for x in docker.calls if len(x) > 1 and x[1] == "exec" and "defender.execution.bash_exec" in x])
        foreign = c.name if handle == "<job-container>" else handle
        with pytest.raises(job_host.Refused):
            c.request("box.exec", handle=foreign, frame=R.FRAME, cwd="/runs/current", timeout=5.0)
        seen["extra"] = len([x for x in docker.calls if len(x) > 1 and x[1] == "exec" and "defender.execution.bash_exec" in x]) - before

    _run(scene, docker, asks)
    assert seen["control"]["result"] == "ok"
    assert seen["extra"] == 0, "the helper ran a command in a container it did not start for this job"


# --- A4: the stop -------------------------------------------------------------------------------------------------------

def test_a4_box_stop_answers_stopped_only_once_the_daemon_shows_the_box_stopped(scene):
    """`docker stop -t 0` then the status: `exited` is proof. (A4)"""
    docker = R.RelayDocker()
    seen: dict = {}

    def asks(c, h, got):
        docker.put("exited")
        seen["answer"] = c.request("box.stop", handle=h)

    got = _run(scene, docker, asks)
    assert seen["answer"] == R.STOPPED
    (create,) = docker.creates()
    name = create[create.index("--name") + 1]
    assert ["docker", "stop", "-t", "0", name] in docker.calls
    assert got["ran"].rc == 0


def test_a4_a_second_box_stop_for_the_same_handle_answers_the_same_proof_and_stops_nothing_again(scene):
    """The job's teardown may ask twice (its ending's stop, then the scrub gate's): the second `box.stop` for a handle the
    helper has already proven stopped answers the same proof without another `docker stop`. Control: the first asked the
    daemon once. (A4, B-G3)"""
    docker = R.RelayDocker()
    seen: dict = {}

    def stops() -> int:
        return len([c for c in docker.calls if c[1:2] == ["stop"] and "-t" in c])

    def asks(c, h, got):
        docker.put("exited")
        seen["first"] = c.request("box.stop", handle=h)
        seen["after_first"] = stops()
        seen["second"] = c.request("box.stop", handle=h)
        seen["after_second"] = stops()

    _run(scene, docker, asks)
    assert seen["first"] == R.STOPPED, "control: the first stop was proven"
    assert seen["after_first"] == 1, "control: the first stop asked the daemon once"
    assert seen["second"] == seen["first"], seen["second"]
    assert seen["after_second"] == 1, "the helper stopped a box it had already proven stopped"


@pytest.mark.parametrize("state", ["running", "mute", "raises"], ids=["still-running", "daemon-mute", "status-raises"])
def test_a4_box_stop_that_cannot_be_proven_is_a_teardown_fault_with_a_reason(scene, state):
    """No proof (the box still runs, or the daemon cannot say): `fault` with a reason, never `stopped`. Control: the row above. (A4)"""
    docker = R.RelayDocker()
    seen: dict = {}

    def asks(c, h, got):
        docker.put(state)
        seen["answer"] = c.request("box.stop", handle=h)

    _run(scene, docker, asks)
    assert seen["answer"]["result"] == "fault", seen["answer"]
    assert seen["answer"]["reason"]


# --- B10: the run box's attached starter lives in the helper ------------------------------------------------------------

def test_b10_the_run_boxs_attached_starter_is_held_by_the_helper_and_ends_when_the_helper_does(scene):
    """The starter's input stays open through the box's life, collection included; once the helper returns it is closed, so the
    box ends with the helper. (B10, A4; control: open while the job runs)"""
    docker = R.RelayDocker()
    docker.exec_with = R.printing(R.OK_FRAME)
    seen: dict = {}

    def starters():
        return [a for a in docker.asks if len(a.argv) > 1 and a.argv[1] == "start"]

    def asks(c, h, got):
        gc.collect()
        seen["held"] = [input_open(a.read_fd) for a in starters()]
        c.request("box.exec", handle=h, frame=R.FRAME, cwd="/runs/current", timeout=5.0)
        gc.collect()
        seen["held_after_exec"] = [input_open(a.read_fd) for a in starters()]

    _run(scene, docker, asks)
    assert seen["held"], "premise: the helper started no attached start"
    assert all(seen["held"]), f"the helper did not hold the run box's input: {seen['held']}"
    assert seen["held_after_exec"] == seen["held"]
    assert not any(input_open(a.read_fd) for a in starters()), "the box outlived the helper that started it"


# --- O10: one box past the limit ends only its own job --------------------------------------------------------------------

@pytest.mark.parametrize("over", [False, True], ids=["control-exactly-at-the-limit", "one-byte-past"])
def test_o10_the_limit_is_applied_at_the_helper_exactly_at_the_limit_a_result_one_byte_past_the_fence(scene, tmp_path, over):
    """A frame of exactly `BOX_OUTPUT_LIMIT` bytes is a result; one byte more is `output-limit`, and none of its bytes reach the
    job. (O10, A4)"""
    assert len(R.AT_THE_LIMIT) == BOX_OUTPUT_LIMIT
    got = _exec_once(scene, exec_with=R.OVER_THE_FENCE if over else R.printing(R.AT_THE_LIMIT, tmp_path))
    if over:
        assert got["answer"] == R.OUTPUT_LIMIT, {k: v for k, v in got["answer"].items() if k != "frame"}
    else:
        assert got["answer"] == {"result": "ok", "frame": R.AT_THE_LIMIT}


def test_o10_a_box_past_the_limit_ends_only_its_own_job_and_another_helpers_relay_goes_on(scene, tmp_path):
    """Helper A's box writes past the limit and gets `output-limit`; helper B (another job of the tenant, its own process) keeps
    answering `ok` before, during and after, and its container is never told to stop. (O10)"""
    state = tmp_path / "other"
    state.mkdir()
    other_inv = str(uuid.uuid4())
    scene.plant(other_inv)
    cfg = {"state": str(state), "inv": other_inv, "commit": scene.t.commit,
           "argv": scene.argv("investigation", other_inv, parent=os.getpid())}
    env = {**os.environ, box.CLAIM_ENV: uuid.uuid4().hex}
    proc = subprocess.Popen([sys.executable, "-c", R.OTHER_HELPER, json.dumps(cfg)], env=env, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        until(lambda: (state / "ready").exists() or proc.poll() is not None, "the other helper's first answer", 60)
        assert proc.poll() is None, proc.stderr.read().decode()
        log = state / "answers.log"
        before = len(log.read_text().split())

        docker = R.RelayDocker()
        docker.exec_with = R.OVER_THE_FENCE

        def asks(c, h, got):
            docker.put("exited")
            got["answer"] = c.request("box.exec", handle=h, frame=R.FRAME, cwd="/runs/current", timeout=5.0)
            got["stop"] = c.request("box.stop", handle=h)

        got = _run(scene, docker, asks)
        assert got["stop"] == R.STOPPED, got["stop"]
        assert got["answer"] == R.OUTPUT_LIMIT, got["answer"]

        until(lambda: len(log.read_text().split()) >= before + 3, "the other helper to keep answering after A's ending")
        (state / "stop").write_text("1")
        until(lambda: (state / "rc").exists() or proc.poll() is not None, "the other helper to end", 60)
        assert proc.wait(timeout=30) == 0, proc.stderr.read().decode()
        answers = json.loads("[" + ",".join(log.read_text().split()) + "]")
        assert answers, "premise: the other helper answered nothing"
        assert set(answers) == {"ok"}, answers
        assert (state / "stopping").read_text() == "False", "the other helper's container was told to stop"
        assert (state / "rc").read_text() == "0"
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=10)
        for stream in (proc.stdout, proc.stderr):
            if stream is not None:
                stream.close()
