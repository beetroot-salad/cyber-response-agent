"""#1205, #1421: an unusable box or a fence trip ends the run by name, through MAIN and
correlation-lead boundaries; a command printing too much does not."""
from __future__ import annotations

import json
import shutil
import subprocess
import uuid
from collections.abc import Callable
from pathlib import Path

import pytest

from defender import box, run_common
from defender.execution import bash_exec
from defender.investigation import ticket_writer
from defender.providers import ProviderDown
from defender.records import RunPaths
from defender.records.run_end import CALL_RECORDS, CallRecordWriteFailed, parse_record
from defender.tests.e2e._box665 import RecordingDocker
from defender.tests.support.tenancy._host1214 import counting_calls
from defender.tests.support.sandbox._docker import daemon_reachable, docker_runtimes, dood_anchor, is_dood
from defender.tests.support.sandbox._spec1092 import make_run_dir
from defender.tests.tenancy.alert_front_door_1222 import _spec1222 as S
from defender.tests.support.tenancy._host1214 import TEST_TENANT

pytestmark = pytest.mark.e2e


def _fault(shape):
    overflow = box.BoxOutputLimitExceeded()
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


# Reverses #1205: the run ends in one place, returning its exit code, rather than the fault escaping.
@pytest.mark.parametrize("shape", ["bare", "nested", "mixed", "call-record"])
@pytest.mark.parametrize("where", ["main", "correlation"])
def test_o9_a_fence_trip_ends_the_run_by_name_instead_of_a_retry_or_fallback(tmp_path, shape, where):
    """Named on the run-end record and exit 6, over provider-down and call-record faults. (O9)"""
    fault = _fault(shape)
    injected = S.LeadFault(raise_on=1, exc=lambda: fault)
    main = S.MainScript([S.text(S.DONE)], fault=injected if where == "main" else S.CLEAN)
    result = S.run_alert(tmp_path, main=main,
                         lead_faults={S.L3: injected} if where == "correlation" else None)
    assert result.raised is None, result.raised
    assert result.rc == 6
    assert _run_end(result).truncated_by == "box-output-limit"
    assert main.requests == (1 if where == "main" else 0)
    assert result.report is None
    # GAP G8: "worded as a process bypassing the helper" names no surface, so no wording is asserted.


NAME = "defender-1421-box"
COMMAND = "echo hello"


def _exchange_runs(*argv: str) -> Callable[..., subprocess.Popen[bytes]]:
    """`docker exec` as a real process that ends the way the fault does; the fence reads its real streams."""
    return lambda _argv, **kw: subprocess.Popen(list(argv), **kw)


def _boxed(daemon: RecordingDocker, popen: Callable[..., subprocess.Popen[bytes]]) -> dict:
    """The real lifecycle over a sandboxed executor whose exchange and daemon are the fault. A run
    box has its attached start, so it is auto-removed: gone counts as stopped (#1343 B10)."""
    attached = subprocess.Popen(["true"])
    attached.wait()
    executor = box.BoxExecutor(name=NAME, docker=daemon, starter=attached,
                               transport=box._DockerTransport(NAME, box.BoxSpec(), popen=popen))

    def scrub(_tree: Path, *, write_verdict) -> None:
        write_verdict({"ran": True, "reason": "walk completed"})

    return {"start_box": lambda *_a, **_k: executor, "stop_box": lambda *_a, **_k: None, "scrub": scrub}


EXEC_KILLED = ("sh", "-c", "exit 137")  # C4, C5: exec rc 137 and no bytes, whether the box or the helper died
EXEC_SAYS_NO_SUCH_BOX = ("sh", "-c", "echo 'No such container' >&2; exit 1")  # C5, the next exec
NOT_A_FRAME = ("sh", "-c", "printf 'wrong magic, a bypassing writer'")  # C13
OVER_THE_FENCE = ("head", "-c", str(box.BOX_OUTPUT_LIMIT + 1), "/dev/zero")


@pytest.mark.parametrize(("status", "exchange", "code", "named"), [
    ("exited", EXEC_KILLED, 5, "box-lost"),  # rule 1, box dead
    (None, EXEC_SAYS_NO_SUCH_BOX, 5, "box-lost"),  # rule 1, box gone
    ("running", NOT_A_FRAME, 5, "box-lost"),  # rule 4
    ("exited", OVER_THE_FENCE, 6, "box-output-limit"),
], ids=["box-exited", "box-gone", "running-no-frame", "fence"])
def test_o8_o9_the_first_command_that_finds_the_box_unusable_ends_the_run(tmp_path, status, exchange, code, named):
    """From the bash tool: no retry prompt, no forced close, the class on the record and in the exit code. (O8, O9)"""
    main = S.MainScript([S.call("bash", command=COMMAND), S.text(S.DONE)])
    result = S.run_alert(tmp_path, main=main,
                         box_lifecycle=_boxed(RecordingDocker(status=status), _exchange_runs(*exchange)))
    assert result.raised is None, result.raised
    assert result.rc == code
    assert _run_end(result).truncated_by == named
    assert _run_end(result).closed_before_cut is False
    assert main.requests == 1, "the model was asked again after the box was found unusable"
    assert result.report is None


def test_o6_exec_137_with_the_box_running_is_a_result_and_the_run_continues(tmp_path):
    """Rule 2: the helper was killed, the box lives; the model gets the reason line and goes on. (O6)"""
    main = S.MainScript([S.call("bash", command=COMMAND), S.text(S.DONE)])
    result = S.run_alert(tmp_path, main=main,
                         box_lifecycle=_boxed(RecordingDocker(status="running"), _exchange_runs(*EXEC_KILLED)))
    assert result.raised is None, result.raised
    assert result.rc == 0
    assert _run_end(result).truncated_by is None
    assert main.requests == 2
    said = "\n".join(main.seen[1].tool_returns)
    assert "memory" in said, said
    assert "could not run this command" not in said, f"reached the model as a retry: {said}"
    # GAP G1: the design gives this result no code when no stage died; a code is not asserted here.


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
    seams = _boxed(RecordingDocker(status="exited"), _exchange_runs(*exchange))

    def stop(*_a, **_k) -> None:
        seen.append("stop")
        if teardown_faults:
            raise box.BoxFault("could not tear down the box")

    return {**seams, "stop_box": stop}


@pytest.mark.parametrize(("teardown_faults", "pages", "checks"), [(True, 0, 0), (False, 1, 1)],
                         ids=["teardown-fault", "control-clean-teardown"])
def test_o8_a_teardown_fault_cannot_replace_the_ending_and_skips_the_post_steps(
        tmp_path, teardown_faults, pages, checks):
    """A box that may be alive: exit 5 still returned, nothing read or published from its tree. (O8)"""
    stops: list[str] = []
    rendered: list[object] = []
    with counting_calls(cross_check=run_common.cross_check_tables) as calls:
        result = S.run_alert(
            tmp_path, main=S.MainScript([S.call("bash", command=COMMAND), S.text(S.DONE)]),
            visualize=lambda *a, **_k: rendered.append(a),
            box_lifecycle=_torn_down(EXEC_KILLED, teardown_faults=teardown_faults, seen=stops))
    assert stops, "the lifecycle never tore the box down, so the fault proves nothing"
    assert result.raised is None, result.raised
    assert result.rc == 5
    assert _run_end(result).truncated_by == "box-lost"
    assert len(rendered) == pages
    assert calls.counts["cross_check"] == checks


def test_control_a_clean_run_through_the_real_lifecycle_reads_its_tree_and_exits_0(tmp_path):
    """The seams above reach the post-steps they count when no box ending is involved. (O8)"""
    wire = box.encode_response(box.BoxResult(rc=0, out=b"hello\n", err=b""))
    rendered: list[object] = []
    main = S.MainScript([S.call("bash", command=COMMAND), S.text(S.DONE)])
    with counting_calls(cross_check=run_common.cross_check_tables) as calls:
        result = S.run_alert(tmp_path, main=main, visualize=lambda *a, **_k: rendered.append(a),
                             box_lifecycle=_boxed(RecordingDocker(status="running"),
                                                  _exchange_runs("python3", "-c", f"import os; os.write(1, {wire!r})")))
    assert result.raised is None, result.raised
    assert result.rc == 0
    assert "hello" in "\n".join(main.seen[1].tool_returns)
    assert len(rendered) == 1
    assert calls.counts["cross_check"] == 1


def test_o8_a_run_the_model_had_closed_keeps_its_report_and_its_case_comment(tmp_path):
    """Closed, then the box is lost: `closed_before_cut` stands and the case is still commented on. (O8, decision 3)"""
    main = S.MainScript([*S.closing_main_turns()[:2], S.call("bash", command=COMMAND), S.text(S.DONE)])
    result = S.run_alert(tmp_path, main=main,
                         box_lifecycle=_boxed(RecordingDocker(status="exited"), _exchange_runs(*EXEC_KILLED)))
    assert result.raised is None, result.raised
    end = _run_end(result)
    assert end.truncated_by == "box-lost"
    assert end.closed_before_cut is True
    assert result.report is not None
    assert ticket_writer.comments_on(end.truncated_by, end.closed_before_cut) is True
    # GAP G2: the design does not say whether this run exits 5 or 0; `result.rc` is not asserted here.


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
                                 spec=box.BoxSpec(runtime=runtime), tenant_id=TEST_TENANT)
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

        # Written past the helper, as C13's child did: `$PPID`'s stdout is the exec stream.
        bypass = ("python3 -c "
                  f"\"import os; f = os.open(f'/proc/{{os.getppid()}}/fd/1', os.O_WRONLY); "
                  f"[os.write(f, bytes(1 << 20)) for _ in range({(box.BOX_OUTPUT_LIMIT >> 20) + 1})]\"")
        with pytest.raises(box.BoxOutputLimitExceeded):
            executor.run_parsed(bash_exec.parse(bypass), command="bypass", cwd=cwd, timeout=60)
        status = box.run_docker(["docker", "inspect", "-f", "{{.State.Status}}", executor.name])
        # The run box is auto-removed once stopped (#1343 B10): stopped is `exited`/`dead` or already gone.
        assert status.stdout.strip() in {"exited", "dead"} or (
            status.returncode != 0 and "no such object" in status.stderr.lower())
        with pytest.raises(box.BoxOutputLimitExceeded):
            executor.run_parsed([], command="again", cwd=cwd, timeout=5)
    finally:
        if executor is not None:
            box.stop_box(executor)
        shutil.rmtree(root)
