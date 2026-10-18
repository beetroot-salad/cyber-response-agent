"""#540 — the box execution seam: the length-prefixed binary wire (raw bytes, fault = frame absence), argv byte-exactness, the three-site cwd invariant, and the injected-box deps seam. Fakes enter at the transport."""
from __future__ import annotations

import pickle
import struct
from dataclasses import dataclass
from pathlib import Path

from defender.run_repository import RunPaths

import pytest

from defender.tests._1255_view import MODEL_RUN, model_path

from _replay_harness import DEFENDER, GOLDEN_AB3, materialize

pytest.importorskip("pydantic_ai")

from pydantic_ai import ModelRetry  # noqa: E402

from defender.runtime import bash_exec, box, permission  # noqa: E402
from defender.runtime import tools as runtime_tools  # noqa: E402
from defender.runtime.agent_definition import bind  # noqa: E402
from defender.runtime.driver import MAIN_DEF  # noqa: E402

pytestmark = pytest.mark.e2e

SALT = "s540"
RUN_ID = "exec-seam-540"


@dataclass(frozen=True)
class ExecCall:
    """One `docker exec` a transport was asked to perform: the encoded REQUEST FRAME,
    the cwd the caller chose, whether that cwd EXISTED at the moment of the call (C35b:
    `docker exec -w <missing>` is rc=127, so the anchor must exist before the first exec),
    and the caller's timeout."""

    frame: bytes
    cwd: Path
    cwd_existed: bool
    timeout: float


class RecordingTransport:
    """The injected box transport: records what it received, replies from a script."""

    def __init__(self, *replies, view: dict[str, Path] | None = None):
        self._replies = list(replies) or [framed(0, b"", b"")]
        self._view = dict(view) if view is not None else {}
        self.calls: list[ExecCall] = []

    def _bound(self, cwd: Path) -> Path:
        """Where `cwd` lives for the box: a model path under a mount target in `view` is the
        directory bound there (#1255 C8-extended — `/runs/current` exists in the box iff the
        run folder bound at it exists); any other cwd is itself."""
        for target, source in self._view.items():
            try:
                return Path(source) / Path(cwd).relative_to(target)
            except ValueError:
                continue
        return Path(cwd)

    def __call__(self, frame: bytes, *, cwd: Path, timeout: float) -> box.RawExec:
        self.calls.append(ExecCall(
            frame=frame, cwd=Path(cwd), cwd_existed=self._bound(Path(cwd)).is_dir(),
            timeout=timeout,
        ))
        reply = self._replies[min(len(self.calls) - 1, len(self._replies) - 1)]
        if isinstance(reply, BaseException):
            raise reply
        return reply

    def only(self) -> ExecCall:
        assert len(self.calls) == 1, f"expected exactly 1 box exec, got {len(self.calls)}"
        return self.calls[0]

    def argvs(self, i: int = 0) -> list[list[str]]:
        """Every stage argv in the i-th recorded request, read back through the REAL decoder."""
        return [list(st.argv) for pl in box.decode_request(self.calls[i].frame) for st in pl.stages]


def framed(rc: int, out: bytes, err: bytes, *, exec_rc: int | None = None) -> box.RawExec:
    """A `RawExec` whose stdout is a WELL-FORMED response frame — the in-box entrypoint
    completed and reported the program's own result. `exec_rc` defaults to `rc`, which is
    what a real `docker exec` returns when the in-box process exits with it."""
    return box.RawExec(
        rc=rc if exec_rc is None else exec_rc,
        stdout=box.encode_response(box.BoxResult(rc=rc, out=out, err=err)),
        stderr=b"",
    )


DAEMON_START_FAILURE = box.RawExec(
    rc=127,
    stdout=b"",
    stderr=(b"docker: Error response from daemon: failed to create task for container: "
            b"failed to create shim task: OCI runtime create failed: runc create failed: "
            b"unable to start container process: exec: \"/nonexistent-binary-xyz\": stat "
            b"/nonexistent-binary-xyz: no such file or directory: unknown\n"),
)

MISSING_WORKDIR_FAILURE = box.RawExec(
    rc=127, stdout=b"",
    stderr=b"OCI runtime exec failed: exec failed: unable to start container process: "
           b"chdir to cwd: no such file or directory: unknown\n",
)

NAME_COLLISION_FAILURE = box.RawExec(
    rc=125, stdout=b"",
    stderr=b"docker: Error response from daemon: Conflict. The container name "
           b"\"/defender-run-exec-seam-540\" is already in use.\n",
)


#: The stored alert, spelled relative to the run folder (it sits in the read-only input directory, #1222).
ALERT_REL = RunPaths(Path("run")).alert.relative_to("run").as_posix()


def _run_dir(tmp_path: Path) -> Path:
    return materialize(tmp_path, GOLDEN_AB3)


def _main_deps(run_dir: Path, transport) -> runtime_tools.AgentDeps:
    """MAIN deps through the REAL `bind` seam, carrying a `BoxExecutor` over `transport`."""
    return bind(
        MAIN_DEF, run_dir, defender_dir=DEFENDER,
        box=box.BoxExecutor(spec=box.BoxSpec(), transport=transport),
    )


def _bash(deps, command: str) -> str:
    """Drive the REAL `_tool_bash` — gate, parse, box, envelope. No shortcut around it."""
    return runtime_tools._tool_bash(deps, command)


def _cat_alert(run_dir: Path) -> str:
    """The alert read the model types, by its model path (#1255 P1 inbound: the model hands back
    model paths; a host path is refused)."""
    return f"cat {_alert_model_path(run_dir)}"


def _alert_model_path(run_dir: Path) -> str:
    return model_path(RunPaths(run_dir).alert, run_dir=run_dir)


def test_unframed_stdout_is_never_returned_as_program_output(tmp_path):
    """unframed_stdout_is_never_returned_as_program_output — when the box's stdout carries NO
    well-formed frame, the call raises `BoxFault`; the unframed bytes are never handed back as
    a `BoxResult`, and never reach the model inside the bash tool's program-output envelope."""
    run_dir = _run_dir(tmp_path)
    t = RecordingTransport(DAEMON_START_FAILURE)
    executor = box.BoxExecutor(spec=box.BoxSpec(), transport=t)

    with pytest.raises(box.BoxFault):
        executor.run_parsed(bash_exec.parse("cat x"), command="cat x", cwd=run_dir, timeout=5.0)

    noise = box.RawExec(rc=0, stdout=b"Error response from daemon: something\n", stderr=b"")
    executor2 = box.BoxExecutor(spec=box.BoxSpec(), transport=RecordingTransport(noise))
    with pytest.raises(box.BoxFault):
        executor2.run_parsed(bash_exec.parse("cat x"), command="cat x", cwd=run_dir, timeout=5.0)

    t3 = RecordingTransport(noise)
    deps = _main_deps(run_dir, t3)
    with pytest.raises((ModelRetry, box.BoxFault)) as caught:
        _bash(deps, _cat_alert(run_dir))
    # Control (#1255 RC-3): the gate admitted the command and the daemon-noise transport was
    # reached, so the negatives below are about unframed stdout — not a gate refusal.
    assert len(t3.calls) == 1, "the command never reached the box; the negatives are vacuous"
    shown = str(caught.value)
    assert "exit=0" not in shown, "daemon text was dressed up as a successful program result"
    assert "--- stdout ---\nError response from daemon" not in shown


def test_program_rc_127_inside_the_frame_reaches_the_model(tmp_path):
    """program_rc_127_inside_the_frame_reaches_the_model — a genuine in-pipeline `command not
    found` (rc=127 INSIDE a well-formed frame) is returned as a normal `BoxResult` and reaches
    the model as a real, actionable result."""
    run_dir = _run_dir(tmp_path)
    not_found = b"nosuchprog: command not found\n"
    t = RecordingTransport(framed(127, b"", not_found))
    deps = _main_deps(run_dir, t)

    executor = box.BoxExecutor(spec=box.BoxSpec(), transport=RecordingTransport(
        framed(127, b"", not_found)))
    result = executor.run_parsed(bash_exec.parse("cat x"), command="cat x", cwd=run_dir, timeout=5.0)
    assert isinstance(result, box.BoxResult), "a framed rc=127 was misread as infrastructure"
    assert result.rc == 127
    assert result.err == not_found

    shown = _bash(deps, _cat_alert(run_dir))
    assert "exit=127" in shown, "the program's own rc did not reach the model"
    assert "command not found" in shown


def test_program_output_bytes_cross_the_frame_untranscoded(tmp_path):
    """program_output_bytes_cross_the_frame_untranscoded — arbitrary program bytes cross the wire
    with ZERO transcoding: the `BoxResult.out`/`err` the caller receives are byte for byte the
    bytes the program wrote, including sequences that are not valid UTF-8 and a payload
    containing the frame's own MAGIC."""
    payload = b"\xff\xfe\x00\x80 \xc3(" + box.RESPONSE_MAGIC + b"\r\n\x00tail"
    errbytes = b"\x89PNG\r\n\x1a\n\xff"
    t = RecordingTransport(framed(3, payload, errbytes))
    executor = box.BoxExecutor(spec=box.BoxSpec(), transport=t)

    result = executor.run_parsed(bash_exec.parse("cat x"), command="cat x", cwd=tmp_path, timeout=5.0)

    assert result.out == payload, "program stdout bytes were transformed on the wire"
    assert result.err == errbytes
    assert b"\xef\xbf\xbd" not in result.out, "C36a's U+FFFD transcode reappeared on the wire"
    assert b"\xef\xbf\xbd" not in result.err
    assert result.rc == 3


def test_infrastructure_failure_raises_boxfault(tmp_path):
    """infrastructure_failure_raises_boxfault — an infrastructure failure RAISES `BoxFault`; it
    is never returned as a value."""
    executor = box.BoxExecutor(
        spec=box.BoxSpec(), transport=RecordingTransport(NAME_COLLISION_FAILURE))
    with pytest.raises(box.BoxFault):
        executor.run_parsed(bash_exec.parse("cat x"), command="cat x", cwd=tmp_path, timeout=5.0)

    executor = box.BoxExecutor(
        spec=box.BoxSpec(), transport=RecordingTransport(MISSING_WORKDIR_FAILURE))
    with pytest.raises(box.BoxFault) as caught:
        executor.run_parsed(bash_exec.parse("cat x"), command="cat x", cwd=tmp_path, timeout=5.0)
    assert not isinstance(caught.value, box.BoxResult)
    assert isinstance(caught.value, Exception), "BoxFault must be raisable, not a value type"

    boom = ConnectionError("Cannot connect to the Docker daemon at unix:///var/run/docker.sock")
    executor = box.BoxExecutor(spec=box.BoxSpec(), transport=RecordingTransport(boom))
    with pytest.raises(box.BoxFault):
        executor.run_parsed(bash_exec.parse("cat x"), command="cat x", cwd=tmp_path, timeout=5.0)

    ok = box.BoxExecutor(spec=box.BoxSpec(), transport=RecordingTransport(framed(0, b"ok\n", b"")))
    assert ok.run(bash_exec.parse("cat x"), command="cat x", cwd=tmp_path, timeout=5.0) == \
        box.BoxResult(rc=0, out=b"ok\n", err=b"")


def test_malformed_frame_never_becomes_a_different_command(tmp_path):
    """malformed_frame_never_becomes_a_different_command — a corrupted frame fails CLOSED in both
    directions."""
    good = box.encode_response(box.BoxResult(rc=0, out=b"abcdefgh", err=b"xy"))

    overstated = good[:8] + struct.pack("!Q", 9999) + good[16:]
    executor = box.BoxExecutor(spec=box.BoxSpec(), transport=RecordingTransport(
        box.RawExec(rc=0, stdout=overstated, stderr=b"")))
    with pytest.raises(box.BoxFault):
        executor.run_parsed(bash_exec.parse("cat x"), command="cat x", cwd=tmp_path, timeout=5.0)

    executor = box.BoxExecutor(spec=box.BoxSpec(), transport=RecordingTransport(
        box.RawExec(rc=0, stdout=good[:-3], stderr=b"")))
    with pytest.raises(box.BoxFault):
        executor.run_parsed(bash_exec.parse("cat x"), command="cat x", cwd=tmp_path, timeout=5.0)

    executor = box.BoxExecutor(spec=box.BoxSpec(), transport=RecordingTransport(
        box.RawExec(rc=0, stdout=b"XXXX" + good[4:], stderr=b"")))
    with pytest.raises(box.BoxFault):
        executor.run_parsed(bash_exec.parse("cat x"), command="cat x", cwd=tmp_path, timeout=5.0)

    pipelines = bash_exec.parse("cat /etc/hostname | grep -n root")
    request = box.encode_request(pipelines)
    original = box.decode_request(request)
    assert original, "the request frame decoded to nothing"
    assert original == pipelines, "the request frame does not round-trip at all"
    for i in range(4, min(len(request), 64)):
        mutated = request[:i] + bytes([request[i] ^ 0xFF]) + request[i + 1:]
        try:
            got = box.decode_request(mutated)
        except Exception:
            continue
        assert got == original, (
            f"a single flipped byte at offset {i} decoded into a DIFFERENT command: {got!r}")


def test_no_pickle_on_the_box_boundary(tmp_path):
    """no_pickle_on_the_box_boundary — nothing on the box boundary pickles or unpickles."""
    for module in (box, bash_exec):
        source = Path(module.__file__).read_text()
        assert "pickle" not in source, f"{module.__name__} names pickle on the box boundary"

    pipelines = bash_exec.parse("cat x")
    request = box.encode_request(pipelines)
    assert request.startswith(box.REQUEST_MAGIC)
    assert not request.startswith(b"\x80"), "the request frame begins with a pickle opcode"
    assert box.decode_request(request) == pipelines, "the frame does not carry the real parse"

    hostile = pickle.dumps({"rc": 0, "out": b"pwned", "err": b""})
    executor = box.BoxExecutor(spec=box.BoxSpec(), transport=RecordingTransport(
        box.RawExec(rc=0, stdout=hostile, stderr=b"")))
    with pytest.raises(box.BoxFault):
        executor.run_parsed(bash_exec.parse("cat x"), command="cat x", cwd=tmp_path, timeout=5.0)

    ok = box.BoxExecutor(spec=box.BoxSpec(), transport=RecordingTransport(framed(0, b"", b"")))
    assert ok.run(pipelines, command="cat x", cwd=tmp_path, timeout=5.0).rc == 0


def test_an_empty_pipeline_crosses_as_a_valid_zero_rc_frame(tmp_path):
    """an_empty_pipeline_crosses_as_a_valid_zero_rc_frame — an EMPTY pipeline list (B12:
    `parse("")` → `[]`) is a valid falsy domain member, not a fault and not a host-side
    shortcut."""
    t = RecordingTransport(framed(0, b"", b""))
    executor = box.BoxExecutor(spec=box.BoxSpec(), transport=t)

    result = executor.run_parsed([], command="", cwd=tmp_path, timeout=5.0)

    assert len(t.calls) == 1, "the empty pipeline never crossed the box boundary"
    assert box.decode_request(t.only().frame) == [], "the empty pipeline did not survive encoding"
    assert result == box.BoxResult(rc=0, out=b"", err=b"")


def test_hostile_argv_crosses_byte_exact(tmp_path):
    """hostile_argv_crosses_byte_exact — the argv the gate approved is the argv that crosses the
    wire, byte for byte."""
    run_dir = _run_dir(tmp_path)
    alert = _alert_model_path(run_dir)   # #1255 P1/C8: the model's spelling, and the box's

    cases = [
        (f"cat {alert} | grep -n 'a b'", ["grep", "-n", "a b"]),
        (f'cat {alert} | grep -n "*.txt"', ["grep", "-n", "*.txt"]),
        (f"cat {alert} | grep -n '$SECRET'", ["grep", "-n", "$SECRET"]),
    ]
    for command, expected_tail in cases:
        t = RecordingTransport(framed(0, b"", b""))
        deps = _main_deps(run_dir, t)
        _bash(deps, command)

        crossed = t.argvs()
        assert crossed[-1] == expected_tail, f"argv was rewritten on the wire for {command!r}"
        assert crossed[0] == ["cat", alert]
        # #1255 C8/C11: the decomposition the box ran, stated literally in the model view — how
        # the gate's own functions spell their inputs is the implementer's choice (C11).
        assert crossed == [["cat", alert], expected_tail], \
            "the box ran a different decomposition than the command's own"

    # The gate called directly keeps its own (host) spelling (C11).
    host_alert = RunPaths(run_dir).alert
    for denied in (f"cat {host_alert} | grep -n '`id`'", f"cat {host_alert} | grep -n '$(whoami)'"):
        assert not permission.decide_bash(
            denied, policy=deps.policy, run_dir=run_dir, defender_dir=DEFENDER).allow


def test_non_utf8_argv_rejected_rather_than_transcoded(tmp_path):
    """non_utf8_argv_rejected_rather_than_transcoded — an argv element that is not valid UTF-8 is
    REJECTED LOUDLY by the encoder, with an error naming the offending element."""
    surrogate = "\udcff"
    hostile = [bash_exec.Pipeline("first", [bash_exec.Stage(["grep", "-n", surrogate])])]

    t = RecordingTransport(framed(0, b"", b""))
    executor = box.BoxExecutor(spec=box.BoxSpec(), transport=t)

    with pytest.raises(ValueError, match="(?i)utf-?8"):
        box.encode_request(hostile)

    with pytest.raises(ValueError, match="(?i)utf-?8"):
        executor.run_parsed(hostile, command="grep -n <hostile>", cwd=tmp_path, timeout=5.0)
    assert t.calls == [], "a non-UTF-8 argv was handed to the transport instead of refused"


def test_embedded_nul_argv_rejected(tmp_path):
    """embedded_nul_argv_rejected — an argv element containing a NUL byte is rejected at the
    ENCODER, before the transport is touched, with an error naming the embedded NUL."""
    hostile = [bash_exec.Pipeline("first", [bash_exec.Stage(["grep", "-n", "a\x00b"])])]

    t = RecordingTransport(framed(0, b"", b""))
    executor = box.BoxExecutor(spec=box.BoxSpec(), transport=t)

    with pytest.raises(ValueError, match="(?i)nul"):
        box.encode_request(hostile)

    with pytest.raises(ValueError, match="(?i)nul"):
        executor.run_parsed(hostile, command="grep -n <hostile>", cwd=tmp_path, timeout=5.0)
    assert t.calls == [], "an embedded-NUL argv reached the transport"


def test_box_accepts_no_raw_command_string(tmp_path):
    """box_accepts_no_raw_command_string — the request frame carries the `Pipeline`/`Stage`
    STRUCTURE and nothing else."""
    run_dir = _run_dir(tmp_path)
    alert = _alert_model_path(run_dir)   # #1255 P1/C8: the model's spelling, and the box's
    command = f"cat   {alert}    |   grep -n   'a b'"

    t = RecordingTransport(framed(0, b"", b""))
    deps = _main_deps(run_dir, t)
    _bash(deps, command)

    frame = t.only().frame
    assert command.encode() not in frame, "the raw command string crossed into the box"
    assert b"   " not in frame, "raw command spacing survived into the frame"
    assert t.argvs() == [["cat", alert], ["grep", "-n", "a b"]]
    assert box.decode_request(frame) == bash_exec.parse(command), \
        "the box received something other than the host's single parse"


def test_relative_operand_names_the_same_file_at_all_three_sites(tmp_path):
    """relative_operand_names_the_same_file_at_all_three_sites — a RELATIVE operand names one and
    the same absolute file at ALL THREE sites the cwd is coupled at: the gate's rebase
    (`permission/bash.py:234`), `_resolve_operand`'s rebase (`tools.py:304-313`), and the
    executor's `cwd=` (now the box's ..."""
    run_dir = _run_dir(tmp_path)
    lesson = sorted((DEFENDER / "lessons").glob("*.md"))[0]
    lesson_rel = lesson.relative_to(DEFENDER.parent)

    t = RecordingTransport(framed(0, b"", b""))
    deps = _main_deps(run_dir, t)

    assert permission.decide_bash(
        f"cat {ALERT_REL}", policy=deps.policy, run_dir=run_dir, defender_dir=DEFENDER).allow, \
        "the gate did not rebase a relative operand onto the run dir"
    assert not permission.decide_bash(
        f"cat {lesson_rel}", policy=deps.policy, run_dir=run_dir, defender_dir=DEFENDER).allow, \
        "the gate is still rebasing onto the repo root — site 1 did not move"

    _bash(deps, f"cat {ALERT_REL}")
    assert t.only().cwd == Path(MODEL_RUN), "the box ran at a different cwd than the gate validated"

    assert runtime_tools._resolve_operand(deps, ALERT_REL) == RunPaths(run_dir).alert

    assert (RunPaths(run_dir).alert).exists()
    assert (t.only().cwd / ALERT_REL).as_posix() == \
        model_path(runtime_tools._resolve_operand(deps, ALERT_REL), run_dir=run_dir)


def test_cwd_is_reapplied_per_call_and_does_not_persist(tmp_path):
    """cwd_is_reapplied_per_call_and_does_not_persist — the cwd is carried caller-side and RE-
    APPLIED on every box call: two successive bash tool calls each hand the executor the
    anchor explicitly, and the second does not inherit it from the first."""
    run_dir = _run_dir(tmp_path)
    t = RecordingTransport(framed(0, b"", b""))
    deps = _main_deps(run_dir, t)

    _bash(deps, _cat_alert(run_dir))
    _bash(deps, f"{_cat_alert(run_dir)} | wc -l")

    assert len(t.calls) == 2
    assert [c.cwd for c in t.calls] == [Path(MODEL_RUN), Path(MODEL_RUN)], \
        "the cwd was not re-applied on the second call"
    assert all(c.cwd.is_absolute() for c in t.calls), \
        "a relative cwd would resolve against whatever the previous exec left behind"


def test_the_chosen_cwd_exists_before_the_first_exec(tmp_path):
    """the_chosen_cwd_exists_before_the_first_exec — the directory chosen as the box's cwd
    already EXISTS at the moment of the first exec."""
    run_dir = _run_dir(tmp_path)
    # #1255 C8-extended: the cwd is the model path `/runs/current`, which exists in the box iff
    # the run folder bound there exists — so existence is read off the bound folder.
    t = RecordingTransport(framed(0, b"", b""), view={MODEL_RUN: run_dir})
    deps = _main_deps(run_dir, t)

    _bash(deps, _cat_alert(run_dir))

    call = t.only()
    assert call.cwd_existed, f"the box's cwd {call.cwd} did not exist at the first exec"
    assert call.cwd == Path(MODEL_RUN)


def test_tool_bash_executes_through_the_injected_box_seam(tmp_path):
    """tool_bash_executes_through_the_injected_box_seam — the REAL `_tool_bash` runs its
    validated pipelines through the box carried on `AgentDeps`, and through nothing else."""
    run_dir = _run_dir(tmp_path)
    real_content = (RunPaths(run_dir).alert).read_text()
    only_the_box_says = b"<<from-the-box>>\n"
    t = RecordingTransport(framed(0, only_the_box_says, b""))
    deps = _main_deps(run_dir, t)

    shown = _bash(deps, _cat_alert(run_dir))

    assert len(t.calls) == 1, "the bash tool did not reach the injected box"
    # #1255 C8: a box mounts each tree at its model path, so the command it receives names the
    # model path the gate admitted, never the host path (which does not exist inside the box).
    assert t.argvs() == [["cat", _alert_model_path(run_dir)]]
    assert "<<from-the-box>>" in shown
    assert real_content.strip() not in shown, \
        "the host executed the command in-process; the box seam was bypassed"

    t2 = RecordingTransport(framed(0, b"", b""))
    deps2 = _main_deps(run_dir, t2)
    with pytest.raises(ModelRetry):
        _bash(deps2, "cat /etc/shadow")
    assert t2.calls == [], "a denied command was still handed to the box"


def test_infrastructure_fault_text_reaches_the_model_labelled(tmp_path):
    """infrastructure_fault_text_reaches_the_model_labelled — a mid-run box failure degrades to a
    TOOL ERROR the model sees, carrying the infrastructure detail, and labelled as
    infrastructure rather than presented inside the program-output envelope."""
    run_dir = _run_dir(tmp_path)
    t = RecordingTransport(DAEMON_START_FAILURE)
    deps = _main_deps(run_dir, t)

    with pytest.raises(ModelRetry) as caught:
        _bash(deps, _cat_alert(run_dir))

    shown = str(caught.value)
    assert "OCI runtime create failed" in shown, "the infrastructure detail never reached the model"
    assert "--- stdout ---" not in shown, "a box fault was dressed as program output"
    assert "exit=" not in shown, "a box fault was given a program exit code"
