"""#540 — the box execution seam: the wire, argv byte-exactness, the cwd anchor, the deps seam.

This module pins FOUR things and nothing else (the filesystem/network/env boundary,
the scrub, the lifecycle and the survival demands live in their sibling spec files):

  1. **The wire (demand #0).** `BoxResult` / `BoxFault` / `BoxSpec` are dataclasses at
     every Python seam, and the channel between host and box is a LENGTH-PREFIXED BINARY
     FRAMING carrying RAW BYTES — `MAGIC(4) | rc(4) | len(out)(8) | len(err)(8) | out | err`.
     Not JSON (a JSON string is unicode and cannot carry arbitrary bytes without base64,
     which is a transcoding step on the one channel whose whole promise is that it does
     not transform anything). Not pickle (it would deserialize on the trusted-parse side).
     **The fault signal is the FRAME'S ABSENCE**: an rc INSIDE a well-formed frame is the
     program's own; no frame at all is infrastructure. That is what dissolves the rc=127
     triple ambiguity, and it is version-independent — which matters, because the design's
     original heuristic (recognise daemon text on stdout) rested on ledger claim C39, which
     this run REFUTED (`docker run --rm alpine /nonexistent-binary-xyz` → rc=127 with stdout
     **0 bytes** and stderr **347 bytes with plain LF** — exactly inverted from the doc).
     No test here may assert daemon text on stdout, CRLF endings, or an empty stderr.

  2. **Argv byte-exactness (O7 / NO15).** What the gate approved is what runs, byte for
     byte, or the call fails LOUDLY. The two rejection points are DIFFERENT and are pinned
     separately: C36a (a non-UTF-8 argv element crosses `docker exec` silently rewritten to
     U+FFFD **at rc=0** — observed `ef bf bd` ×3) and C36b (an embedded NUL raises
     `ValueError: embedded null byte` from Python's **subprocess**, before docker sees it).

  3. **The three-site cwd invariant (M9 / C52).** The cwd is coupled at THREE sites: the
     gate's rebase of a relative operand (`permission/bash.py:234`), `_resolve_operand`'s
     rebase (`tools.py:304-313`), and the executor's `cwd=`. Move fewer than three and the
     validator/executor differential reopens at the same moment O12 is fixed.

  4. **The deps seam.** `_tool_bash` executes through an INJECTED box on `AgentDeps`, and
     every bash-enabled role has one (H3).

**Fakes enter through injection seams, never by monkeypatching** (`lint_monkeypatch.py` is
a blocking ratcheted gate). There are two seams in play: `AgentDeps.box` / `drive(box=…)`
takes a `BoxExecutor`, and the `BoxExecutor` itself takes a TRANSPORT — the thing that
actually spawns `docker exec` and hands back its raw rc/stdout/stderr. Faking at the
transport level rather than at `BoxExecutor.run` is deliberate: it leaves the REAL framing
codec running on both sides, so a payload demand can assert on the **captured inbound
frame** rather than on a canned answer, and a fault demand can feed the classifier the
exact bytes the ledger OBSERVED a real daemon produce.

Sandbox honesty: this environment is docker-outside-of-Docker (E2) — bind sources resolve
on the real daemon host and are invisible to this process. Nothing in this module needs a
live daemon: every assertion is on the framing, the argv, the cwd or the seam, all of which
are host-side. The demands that genuinely need a container are in the boundary spec file
and are gated there.
"""
from __future__ import annotations

import dataclasses
import pickle
import struct
from dataclasses import dataclass
from pathlib import Path

import pytest

from _replay_harness import DEFENDER, GOLDEN_AB3, ReplayFn, Turn, drive, materialize

pytest.importorskip("pydantic_ai")

from pydantic_ai import ModelRetry  # noqa: E402

from defender import agents as agents_registry  # noqa: E402
from defender.runtime import bash_exec, box, permission  # noqa: E402
from defender.runtime import tools as runtime_tools  # noqa: E402
from defender.runtime.agent_definition import RunScope, bind  # noqa: E402
from defender.runtime.agent_role import AgentRole  # noqa: E402
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
    """The injected box transport: records what it received, replies from a script.

    `replies` is consumed one per call; past the end it repeats the last one, so a replay
    with an unknown number of bash turns does not need its count predicted. A reply is
    either a `box.RawExec` (returned) or an exception INSTANCE (raised) — the latter models
    a transport that could not even reach the daemon.

    It never classifies. Whether an unframed stdout is a fault, whether an rc is the
    program's, and what the caller is told are all `BoxExecutor`'s job — a fake that
    decided any of that would be asserting against itself."""

    def __init__(self, *replies):
        self._replies = list(replies) or [framed(0, b"", b"")]
        self.calls: list[ExecCall] = []

    def __call__(self, frame: bytes, *, cwd: Path, timeout: float) -> box.RawExec:
        self.calls.append(ExecCall(
            frame=frame, cwd=Path(cwd), cwd_existed=Path(cwd).is_dir(), timeout=timeout,
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



def _run_dir(tmp_path: Path) -> Path:
    return materialize(tmp_path, GOLDEN_AB3)


def _main_deps(run_dir: Path, transport) -> runtime_tools.AgentDeps:
    """MAIN deps through the REAL `bind` seam, carrying a `BoxExecutor` over `transport`.

    `bind(..., box=…)` is the injection point (#540): production builds the executor from
    `BoxSpec`; a test hands one in. The policy, the roots and the gate are all the real
    compiled article — only the thing that would have spawned a container is faked."""
    return bind(
        MAIN_DEF, run_dir, salt=SALT, defender_dir=DEFENDER,
        box=box.BoxExecutor(spec=box.BoxSpec(), transport=transport),
    )


def _bash(deps, command: str) -> str:
    """Drive the REAL `_tool_bash` — gate, parse, box, envelope. No shortcut around it."""
    return runtime_tools._tool_bash(deps, command)


def _cat_alert(run_dir: Path) -> str:
    return f"cat {run_dir / 'alert.json'}"



def test_box_returns_boxresult_dataclass_not_a_tuple(tmp_path):
    """box_returns_boxresult_dataclass_not_a_tuple — a completed box call yields a
    `BoxResult` DATACLASS carrying `rc: int`, `out: bytes`, `err: bytes`, not a bare
    `(rc, out, err)` tuple and not a dict. Assertions on box results are therefore on
    NAMED FIELDS, and `out`/`err` stay `bytes` all the way to the caller: a tuple would
    let a field be read positionally and a str would already have transcoded the payload
    the wire exists to carry unchanged."""
    t = RecordingTransport(framed(0, b"hello\n", b"warn\n"))
    executor = box.BoxExecutor(spec=box.BoxSpec(), transport=t)

    result = executor.run_parsed(bash_exec.parse("cat x"), command="cat x", cwd=tmp_path, timeout=5.0)

    assert dataclasses.is_dataclass(result), "the box result is not a dataclass"
    assert isinstance(result, box.BoxResult)
    assert not isinstance(result, tuple), "a (rc, out, err) tuple survived at the Python seam"
    assert not isinstance(result, dict)
    assert {f.name for f in dataclasses.fields(result)} == {"rc", "out", "err"}
    assert result.rc == 0
    assert isinstance(result.out, bytes)
    assert isinstance(result.err, bytes)
    assert (result.out, result.err) == (b"hello\n", b"warn\n")


def test_unframed_stdout_is_never_returned_as_program_output(tmp_path):
    """unframed_stdout_is_never_returned_as_program_output — when the box's stdout carries
    NO well-formed frame, the call raises `BoxFault`; the unframed bytes are never handed
    back as a `BoxResult`, and never reach the model inside the bash tool's program-output
    envelope. Any unframed stdout is BY DEFINITION daemon text: the entrypoint writes a
    frame or the entrypoint never ran.

    The fault content is R-C39 as OBSERVED this run — `docker run --rm alpine:latest
    /nonexistent-binary-xyz` gave rc=127 with stdout **0 bytes** and stderr **347 bytes,
    plain LF**, exactly inverted from the doc's C39 claim. That refutation is why the signal
    here is structural (no frame) rather than a match on daemon text: the text moved streams
    under us between daemon versions, and the framing does not care which stream it chose."""
    run_dir = _run_dir(tmp_path)
    t = RecordingTransport(DAEMON_START_FAILURE)
    executor = box.BoxExecutor(spec=box.BoxSpec(), transport=t)

    with pytest.raises(box.BoxFault):
        executor.run_parsed(bash_exec.parse("cat x"), command="cat x", cwd=run_dir, timeout=5.0)

    noise = box.RawExec(rc=0, stdout=b"Error response from daemon: something\n", stderr=b"")
    executor2 = box.BoxExecutor(spec=box.BoxSpec(), transport=RecordingTransport(noise))
    with pytest.raises(box.BoxFault):
        executor2.run_parsed(bash_exec.parse("cat x"), command="cat x", cwd=run_dir, timeout=5.0)

    deps = _main_deps(run_dir, RecordingTransport(noise))
    with pytest.raises((ModelRetry, box.BoxFault)) as caught:
        _bash(deps, _cat_alert(run_dir))
    shown = str(caught.value)
    assert "exit=0" not in shown, "daemon text was dressed up as a successful program result"
    assert "--- stdout ---\nError response from daemon" not in shown


def test_program_rc_127_inside_the_frame_reaches_the_model(tmp_path):
    """program_rc_127_inside_the_frame_reaches_the_model — a genuine in-pipeline
    `command not found` (rc=127 INSIDE a well-formed frame) is returned as a normal
    `BoxResult` and reaches the model as a real, actionable result. It is NOT reclassified
    as infrastructure.

    This is the POSITIVE CONTROL for the whole fault-classification family: without it the
    classifier passes vacuously by calling every 127 infrastructure. Together with
    `test_unframed_stdout_is_never_returned_as_program_output` it is what dissolves the
    rc=127 triple ambiguity — C39's daemon error, C35b's missing `-w` target (both rc=127
    with NO frame), and the program's own 127 (rc=127 WITH a frame). Note the outer
    `docker exec` rc is 127 in all three cases, so rc alone can never separate them; only
    the frame can."""
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
    """program_output_bytes_cross_the_frame_untranscoded — arbitrary program bytes cross
    the wire with ZERO transcoding: the `BoxResult.out`/`err` the caller receives are byte
    for byte the bytes the program wrote, including sequences that are not valid UTF-8 and
    a payload containing the frame's own MAGIC.

    The excluded failure mode is C36a's, executed this run: a non-UTF-8 element crossing
    `docker exec` came back silently rewritten to U+FFFD (`ef bf bd` ×3) at rc=0. A channel
    that encodes would reproduce exactly that corruption on the results half, silently. So
    the assertion is equality on raw bytes AND the explicit absence of the replacement
    character — a decode-with-replace anywhere on the path is caught, not merely improbable."""
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
    """infrastructure_failure_raises_boxfault — an infrastructure failure RAISES `BoxFault`;
    it is never returned as a value. So callers assert the raise, and no caller can forget
    to inspect a status field: there is no status field to forget.

    Both observed failure shapes are driven. C43b (executed): a STOPPED container of the
    same name collides at **rc=125**. C35b (executed): `docker exec -w <missing>` is
    **rc=127**, while `docker run -w <missing>` silently CREATES the directory. Neither
    produces a frame, so neither can be confused with a program result. A transport that
    cannot reach the daemon at all raises, and that too must surface as `BoxFault` rather
    than as whatever primitive error the spawn happened to produce."""
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
    """malformed_frame_never_becomes_a_different_command — a corrupted frame fails CLOSED in
    both directions. A response whose declared lengths do not match its payload raises
    `BoxFault` rather than yielding a truncated or over-read `BoxResult`; a request frame
    with a mutated length header raises rather than decoding into a DIFFERENTLY-SHAPED
    pipeline. The box-side decoder is not itself a security boundary (the trust direction is
    host-sends / box-receives), but a malformed decode that silently became another command
    would be one — a length field is an offset into the argv, so a flipped byte re-slices
    which tokens are which.

    Every corrupt input here is a REAL frame from the REAL encoder, mutated — not an
    author-imagined byte string."""
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
    """no_pickle_on_the_box_boundary — nothing on the box boundary pickles or unpickles.
    The host-side module and the in-box entrypoint contain no pickle import, a real request
    frame is not a pickle stream, and a PICKLE offered where a response frame belongs is
    rejected as an absent frame rather than deserialized.

    The last clause is the one that matters: unpickling happens on the HOST — the trusted
    parse side — so a box that could choose the bytes could choose the objects the host
    constructs. TM class 2 cites 'no pickle' as evidence our own code is clean, and that
    claim has to be true of the newest boundary too."""
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
    shortcut. It crosses the wire as a real request and comes back as a well-formed frame
    decoding to `BoxResult(rc=0, out=b"", err=b"")`.

    The failure this forbids is a host-side `if not pipelines: return ...` that fabricates a
    result without ever consulting the box: it would make the falsy case the ONE input shape
    the box boundary never sees, and `run_parsed([])` → `(0, "", "")` is exactly the
    fabrication already available to copy. So the transport must record the call."""
    t = RecordingTransport(framed(0, b"", b""))
    executor = box.BoxExecutor(spec=box.BoxSpec(), transport=t)

    result = executor.run_parsed([], command="", cwd=tmp_path, timeout=5.0)

    assert len(t.calls) == 1, "the empty pipeline never crossed the box boundary"
    assert box.decode_request(t.only().frame) == [], "the empty pipeline did not survive encoding"
    assert result == box.BoxResult(rc=0, out=b"", err=b"")



def test_hostile_argv_crosses_byte_exact(tmp_path):
    """hostile_argv_crosses_byte_exact — the argv the gate approved is the argv that crosses
    the wire, byte for byte. A quoted operand containing a space stays ONE token, a glob
    stays ONE token, and a `$VAR` stays the LITERAL characters `$SECRET` — no expansion, no
    re-splitting, no requoting. Asserted against the CAPTURED INBOUND FRAME, decoded with the
    real decoder, not against a canned reply.

    R-B13 (executed) is what fixes this list: quotes, backticks and globs are each preserved
    as one token by `parse`, but `$(...)` is NOT — so there is no uniform 'all metacharacter
    classes cross as single tokens' claim to make, and that case gets its own test. Backticks
    and `$(` never reach the box at all: the host gate denies them, which is checked here so
    their absence from this list is a recorded fact rather than an oversight."""
    run_dir = _run_dir(tmp_path)
    alert = run_dir / "alert.json"

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
        assert crossed[0] == ["cat", str(alert)]
        decision = permission.decide_bash(
            command, policy=deps.policy, run_dir=run_dir, defender_dir=DEFENDER)
        assert crossed == [list(st.argv) for pl in decision.pipelines for st in pl.stages], \
            "the box ran a different decomposition than the gate approved"

    for denied in (f"cat {alert} | grep -n '`id`'", f"cat {alert} | grep -n '$(whoami)'"):
        assert not permission.decide_bash(
            denied, policy=deps.policy, run_dir=run_dir, defender_dir=DEFENDER).allow


def test_non_utf8_argv_rejected_rather_than_transcoded(tmp_path):
    """non_utf8_argv_rejected_rather_than_transcoded — an argv element that is not valid
    UTF-8 is REJECTED LOUDLY by the encoder, with an error naming the offending element. It
    is never silently repaired, and the U+FFFD replacement character never appears in a frame.

    This is C36a's fault, executed this run: a non-UTF-8 argv element handed to `docker exec`
    came back silently rewritten to U+FFFD **at rc=0** (observed `ef bf bd` ×3). The runtime
    will NOT honour byte-exact-or-fail unaided — it prefers a quiet lie — so O7's limit (a)
    has to be an explicit encoder-side refusal. The framing carrying raw bytes does not
    supersede this obligation: it removes the transcode from the RESULTS half, while the
    argv half is rejected outright."""
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
    ENCODER, before the transport is touched, with an error naming the embedded NUL.

    C36b (executed) is why this is a SEPARATE test from the UTF-8 case and not a second
    assertion inside it: the two are rejected at DIFFERENT points. A NUL raises
    `ValueError: embedded null byte` out of Python's **subprocess** layer, before docker ever
    sees the argv, whereas a non-UTF-8 element (C36a) sails through subprocess AND docker and
    is corrupted at the far end at rc=0. Inheriting the NUL rejection from subprocess would
    make the boundary's fail-closed behaviour an accident of which spawn primitive it happens
    to use — so the encoder owns it, and the proof is that the transport records nothing."""
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
    STRUCTURE and nothing else. The model's raw command text does not cross, so there is
    nothing in the box for a second parser to re-decompose.

    F5 was dissolved by demand #0 for exactly this reason: re-parsing in the box would
    reintroduce a second parse and therefore the validator/executor differential O7 exists to
    prevent. The witness is a command whose raw spelling differs from its token structure —
    doubled spaces and quoting that vanish under `parse` — so a raw string riding along would
    be visible in the frame bytes."""
    run_dir = _run_dir(tmp_path)
    alert = run_dir / "alert.json"
    command = f"cat   {alert}    |   grep -n   'a b'"

    t = RecordingTransport(framed(0, b"", b""))
    deps = _main_deps(run_dir, t)
    _bash(deps, command)

    frame = t.only().frame
    assert command.encode() not in frame, "the raw command string crossed into the box"
    assert b"   " not in frame, "raw command spacing survived into the frame"
    assert t.argvs() == [["cat", str(alert)], ["grep", "-n", "a b"]]
    assert box.decode_request(frame) == bash_exec.parse(command), \
        "the box received something other than the host's single parse"


def test_command_substitution_splits_into_four_tokens_at_the_host_parse():
    """command_substitution_splits_into_four_tokens_at_the_host_parse — `$(...)` is NOT
    preserved as one literal token by the host parse: `parse('echo $(whoami)')` yields FOUR
    tokens, `['echo', '$', '(', 'whoami', ')']`. Quotes, backticks and globs ARE each
    preserved as one token. This asymmetry is at the HOST parse, upstream of the box
    entirely, and it is pinned so no later test writes a uniform 'all four metacharacter
    classes cross as single literal tokens' assertion.

    R-B13, executed this run, refuted precisely that uniform claim. The security property is
    unchanged either way — nothing expands, because bash never re-parses — but the SHAPE the
    box receives differs between the classes, and a test that assumed otherwise would have
    pinned a false belief about the wire's contents."""
    assert bash_exec.parse("echo $(whoami)")[0].stages[0].argv == \
        ["echo", "$", "(", "whoami", ")"]

    assert bash_exec.parse("grep -n 'a b'")[0].stages[0].argv == ["grep", "-n", "a b"]
    assert bash_exec.parse("grep -n `y`")[0].stages[0].argv == ["grep", "-n", "`y`"]
    assert bash_exec.parse("grep -n *.txt")[0].stages[0].argv == ["grep", "-n", "*.txt"]



def test_relative_operand_names_the_same_file_at_all_three_sites(tmp_path):
    """relative_operand_names_the_same_file_at_all_three_sites — a RELATIVE operand names one
    and the same absolute file at ALL THREE sites the cwd is coupled at: the gate's rebase
    (`permission/bash.py:234`), `_resolve_operand`'s rebase (`tools.py:304-313`), and the
    executor's `cwd=` (now the box's working directory). All three are the run dir (F4).

    C52 is why this asserts THREE and not two: move fewer than three and the
    validator/executor differential reopens at the very moment O12 is fixed — the gate would
    resolve `x` against one root while the program opens it from another, so the file
    approved and the file read are different files. Site 1 is observed through the real
    gate's ALLOW/DENY, which is the only thing it exposes: `cat alert.json` is in the cat
    grant's scope iff the anchor is the run dir, and `cat defender/lessons/<f>.md` is in
    scope iff the anchor is the repo root — one discriminating pair, both answers required."""
    run_dir = _run_dir(tmp_path)
    lesson = sorted((DEFENDER / "lessons").glob("*.md"))[0]
    lesson_rel = lesson.relative_to(DEFENDER.parent)

    t = RecordingTransport(framed(0, b"", b""))
    deps = _main_deps(run_dir, t)

    assert permission.decide_bash(
        "cat alert.json", policy=deps.policy, run_dir=run_dir, defender_dir=DEFENDER).allow, \
        "the gate did not rebase a relative operand onto the run dir"
    assert not permission.decide_bash(
        f"cat {lesson_rel}", policy=deps.policy, run_dir=run_dir, defender_dir=DEFENDER).allow, \
        "the gate is still rebasing onto the repo root — site 1 did not move"

    _bash(deps, "cat alert.json")
    assert t.only().cwd == run_dir, "the box ran at a different cwd than the gate validated"

    assert runtime_tools._resolve_operand(deps, "alert.json") == run_dir / "alert.json"

    assert (run_dir / "alert.json").exists()
    assert (t.only().cwd / "alert.json").resolve() == \
        runtime_tools._resolve_operand(deps, "alert.json").resolve()


def test_cwd_is_reapplied_per_call_and_does_not_persist(tmp_path):
    """cwd_is_reapplied_per_call_and_does_not_persist — the cwd is carried caller-side and
    RE-APPLIED on every box call: two successive bash tool calls each hand the executor the
    anchor explicitly, and the second does not inherit it from the first.

    C35a, executed this run, is why nothing here may assert persistence: cwd does NOT persist
    across `docker exec` (exec1 at `/tmp` → exec2 at `/`), while `/tmp` itself DOES persist as
    a filesystem. A design that set the directory once and relied on it would silently run
    every subsequent command from `/` — where a relative operand resolves to a different file
    than the one the gate approved, which is the same differential C52 names."""
    run_dir = _run_dir(tmp_path)
    t = RecordingTransport(framed(0, b"", b""))
    deps = _main_deps(run_dir, t)

    _bash(deps, _cat_alert(run_dir))
    _bash(deps, f"cat {run_dir / 'alert.json'} | wc -l")

    assert len(t.calls) == 2
    assert [c.cwd for c in t.calls] == [run_dir, run_dir], \
        "the cwd was not re-applied on the second call"
    assert all(c.cwd.is_absolute() for c in t.calls), \
        "a relative cwd would resolve against whatever the previous exec left behind"


def test_the_chosen_cwd_exists_before_the_first_exec(tmp_path):
    """the_chosen_cwd_exists_before_the_first_exec — the directory chosen as the box's cwd
    already EXISTS at the moment of the first exec.

    C35b, executed this run: `docker exec -w <missing>` is **rc=127**, while
    `docker run -w <missing>` silently CREATES the directory. So the run-time behaviour of a
    missing anchor differs by which docker verb is used, and on the exec path — the one this
    design takes, for C35's amortization (57ms exec vs 201ms run) — it fails with the SAME
    rc=127 a program's own `command not found` produces. The frame absence distinguishes
    them after the fact; the anchor existing beforehand is what stops the confusion arising."""
    run_dir = _run_dir(tmp_path)
    t = RecordingTransport(framed(0, b"", b""))
    deps = _main_deps(run_dir, t)

    _bash(deps, _cat_alert(run_dir))

    call = t.only()
    assert call.cwd_existed, f"the box's cwd {call.cwd} did not exist at the first exec"
    assert call.cwd == run_dir



def test_tool_bash_executes_through_the_injected_box_seam(tmp_path):
    """tool_bash_executes_through_the_injected_box_seam — the REAL `_tool_bash` runs its
    validated pipelines through the box carried on `AgentDeps`, and through nothing else.
    The gate still runs host-side first, the box receives the gate's own parse, and the
    result the model sees is the BOX's — not the host's.

    The witness is a command that would succeed identically on the host: `cat alert.json`
    exists and is readable in this process, so a surviving in-process execution path would
    return the file's real content and the test would still 'pass' if it only checked for
    success. It checks for the box's OWN distinctive bytes instead, and for the file's real
    content being absent."""
    run_dir = _run_dir(tmp_path)
    real_content = (run_dir / "alert.json").read_text()
    only_the_box_says = b"<<from-the-box>>\n"
    t = RecordingTransport(framed(0, only_the_box_says, b""))
    deps = _main_deps(run_dir, t)

    shown = _bash(deps, _cat_alert(run_dir))

    assert len(t.calls) == 1, "the bash tool did not reach the injected box"
    assert t.argvs() == [["cat", str(run_dir / "alert.json")]]
    assert "<<from-the-box>>" in shown
    assert real_content.strip() not in shown, \
        "the host executed the command in-process; the box seam was bypassed"

    t2 = RecordingTransport(framed(0, b"", b""))
    deps2 = _main_deps(run_dir, t2)
    with pytest.raises(ModelRetry):
        _bash(deps2, "cat /etc/shadow")
    assert t2.calls == [], "a denied command was still handed to the box"


def test_every_bash_enabled_role_executes_through_a_box(tmp_path):
    """every_bash_enabled_role_executes_through_a_box — every role whose `ToolSet.bash` is
    True is bound with a real `BoxExecutor` on its deps. There is no bash-enabled role whose
    box is absent, so no production code path has to be absent-tolerant.

    H3 closed the asymmetry this way rather than by making 'bash enabled + box absent'
    unconstructible: the four `ToolSet.bash=True` learning-pipeline roles (lead_author,
    curator, actor, judge — census A4) are ported alongside the two runtime agents, and
    `verify_forward`/`oracle` have EMPTY ToolSets and are unaffected. The census is read off
    the live registry rather than restated here, so a newly bash-enabled role fails this test
    instead of quietly inheriting no box."""
    run_dir = _run_dir(tmp_path)
    scope = RunScope(read_confine=(run_dir,), scripts=(), add_dirs=(run_dir,))

    bash_roles = [d for d in agents_registry.AGENTS.values() if d.tools.bash]
    assert bash_roles, "the registry reports no bash-enabled role — the census cannot be empty"

    for defn in bash_roles:
        tree = tmp_path / "tree" / "defender" if defn.requires_explicit_tree else DEFENDER
        if defn.requires_explicit_tree:
            tree.mkdir(parents=True, exist_ok=True)
        if defn.requires_corpus:
            corpora = ("lessons", "lessons-actor", "lessons-environment")
            for name in corpora:
                (tree / name).mkdir(parents=True, exist_ok=True)
            role_scope = RunScope(
                corpus_name="lessons",
                read_confine=tuple((tree / name).resolve() for name in corpora),
            )
        else:
            role_scope = scope
        deps = bind(defn, run_dir, scope=role_scope, salt=SALT, defender_dir=tree)
        assert isinstance(deps.box, box.BoxExecutor), \
            f"{defn.role.name} has bash but no box on its deps"

    # The census's real content: the curator — bash=True but excluded under the RETIRED
    # `d.bindable` conjunct — is now enumerated by the single `d.tools.bash` predicate. A
    # reintroduced narrower gate would drop it and fail here. (The former assertion — non-bash
    # roles disjoint from the bash census — was tautological: any predicate partitions the
    # registry into disjoint sets, so it could never fail and proved nothing.)
    assert AgentRole.CORPUS_AUTHOR in {d.role for d in bash_roles}


def test_the_existing_e2e_bash_corpus_completes_through_the_box(tmp_path):
    """the_existing_e2e_bash_corpus_completes_through_the_box — the bash turns the existing
    hermetic e2e corpus already drives still complete, now routed through the box, and every
    one of them crossed the wire.

    R5's survival demand: today the e2e harness drives the REAL `_tool_bash` → `decide_bash`
    → `run_parsed` → `subprocess.Popen` with NO seam between the tool and the OS, so the box
    seam is exercised by every existing e2e test the moment it lands — leverage and risk in
    equal measure. This drives the whole real driver loop (gather dispatch included) with the
    box injected at `drive(box=…)`, so the surviving workflow is the run, not a unit call."""
    run_dir = materialize(tmp_path, GOLDEN_AB3)
    alert = run_dir / "alert.json"
    t = RecordingTransport(framed(0, b"3\n", b""))

    main = ReplayFn([
        Turn(tool_calls=[("bash", {"command": f"cat {alert}"})]),
        Turn(tool_calls=[("bash", {"command": f"cat {alert} | wc -l"})]),
        Turn(text="done"),
    ])
    drive(run_dir, run_id=RUN_ID, salt=SALT, main=main,
          box=box.BoxExecutor(spec=box.BoxSpec(), transport=t))

    assert main.calls == 3, "the run did not complete its script through the box"
    assert len(t.calls) == 2, "a bash turn did not reach the box"
    assert t.argvs(0) == [["cat", str(alert)]]
    assert t.argvs(1) == [["cat", str(alert)], ["wc", "-l"]]
    assert "3" in main.seen[-1], "the box's result never came back to the model"


def test_infrastructure_fault_text_reaches_the_model_labelled(tmp_path):
    """infrastructure_fault_text_reaches_the_model_labelled — a mid-run box failure degrades
    to a TOOL ERROR the model sees, carrying the infrastructure detail, and labelled as
    infrastructure rather than presented inside the program-output envelope. The model is
    told the tool broke; it is never told the program printed this.

    F6: a mid-run `docker exec` failure is a tool error, NEVER an in-process `bash_exec`
    fallback — a silent downgrade converts O4 from a boundary into best-effort. The fault
    content is R-C39 as observed (rc=127, stdout 0 bytes, stderr 347 bytes with plain LF).
    'Labelled' is asserted structurally, not by matching a magic word: the daemon text must
    NOT appear under the `--- stdout ---` header that means 'the program wrote this', and the
    envelope must not claim a program exit code."""
    run_dir = _run_dir(tmp_path)
    t = RecordingTransport(DAEMON_START_FAILURE)
    deps = _main_deps(run_dir, t)

    with pytest.raises(ModelRetry) as caught:
        _bash(deps, _cat_alert(run_dir))

    shown = str(caught.value)
    assert "OCI runtime create failed" in shown, "the infrastructure detail never reached the model"
    assert "--- stdout ---" not in shown, "a box fault was dressed as program output"
    assert "exit=" not in shown, "a box fault was given a program exit code"
