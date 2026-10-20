"""The host bounds actual response bytes, including diagnostics, before decoding."""
from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from defender import box
from defender.box._output import BOX_OUTPUT_LIMIT, BoxOutputLimitExceeded, capture_bounded
from defender.execution import bash_exec

_LIMIT = 65536


def _capture(script: str, *, frame: bytes = b"", limit: int = _LIMIT, timeout: float = 5):
    return capture_bounded([sys.executable, "-c", script], frame, limit=limit, timeout=timeout)


@pytest.mark.parametrize(("out", "err"), [(0, 0), (123, 456), (_LIMIT, 0), (0, _LIMIT), (30000, _LIMIT - 30000)])
def test_response_at_or_below_combined_budget_is_unchanged(out, err):
    result = _capture(f"import os; os.write(1,b'o'*{out}); os.write(2,b'e'*{err})")
    assert result.stdout == b"o" * out
    assert result.stderr == b"e" * err
    assert result.rc == 0


@pytest.mark.parametrize(("out", "err"), [(_LIMIT + 1, 0), (0, _LIMIT + 1), (30000, _LIMIT - 29999)])
def test_either_stream_or_their_sum_refuses_at_one_byte_over(out, err):
    with pytest.raises(BoxOutputLimitExceeded, match="65536-byte"):
        _capture(f"import os; os.write(1,b'o'*{out}); os.write(2,b'e'*{err})")


def test_large_request_and_simultaneous_outputs_do_not_deadlock():
    frame = b"i" * (1 << 20)
    # Fill both output pipes before accepting the request, then verify the complete stdin.
    result = _capture(
        "import os,sys; os.write(1,b'o'*100000); os.write(2,b'e'*100000); "
        "data=sys.stdin.buffer.read(); sys.exit(0 if data==b'i'*1048576 else 7)",
        frame=frame, limit=200000,
    )
    assert result.rc == 0
    assert len(result.stdout) == 100000
    assert len(result.stderr) == 100000


def test_closed_stdin_still_returns_diagnostics():
    result = _capture("import os; os.close(0); os.write(2,b'failed')", frame=b"x" * (1 << 20))
    assert result.stderr == b"failed"


@pytest.mark.parametrize("script", ["import time; time.sleep(30)", "import os,time; os.close(1); os.close(2); time.sleep(30)"])
def test_timeout_including_wait_after_eof_reaps_child(script):
    children = []

    def start(*args, **kwargs):
        proc = subprocess.Popen(*args, **kwargs)
        children.append(proc)
        return proc

    with pytest.raises(subprocess.TimeoutExpired):
        capture_bounded([sys.executable, "-c", script], b"", timeout=0.2, popen=start)
    assert children[0].poll() is not None
    assert children[0].stdout.closed
    assert children[0].stderr.closed


def test_overflow_stops_reading_and_reaps_a_writer_that_never_finishes():
    children = []

    def start(*args, **kwargs):
        proc = subprocess.Popen(*args, **kwargs)
        children.append(proc)
        return proc

    started = time.monotonic()
    with pytest.raises(BoxOutputLimitExceeded):
        capture_bounded([sys.executable, "-c", "import os\nwhile True: os.write(1,b'x'*8192)"],
                        b"", timeout=5, limit=_LIMIT, popen=start)
    assert children[0].poll() is not None
    assert time.monotonic() - started < 5


class _Daemon:
    def __init__(self, *, stopped=True):
        self.calls = []
        self.stopped = stopped

    def __call__(self, argv):
        self.calls.append(argv)
        status = "exited" if self.stopped else "running"
        return subprocess.CompletedProcess(argv, 0, stdout=status, stderr="")


@pytest.mark.parametrize("stopped", [True, False])
def test_executor_stops_through_its_daemon_and_permanently_refuses_reuse(stopped):
    children = []

    def start(_argv, **kwargs):
        script = f"import os\nfor _ in range({BOX_OUTPUT_LIMIT // 8192 + 1}): os.write(1,b'x'*8192)"
        proc = subprocess.Popen([sys.executable, "-c", script], **kwargs)
        children.append(proc)
        return proc

    daemon = _Daemon(stopped=stopped)
    executor = box.BoxExecutor(name="output-test", docker=daemon,
                              transport=box._DockerTransport("output-test", box.BoxSpec(), popen=start))
    with pytest.raises(BoxOutputLimitExceeded) as caught:
        executor.run_parsed([], command="test", cwd=Path("/"), timeout=10)
    assert daemon.calls[0] == ["docker", "stop", "-t", "0", "output-test"]
    assert daemon.calls[1][1] == "inspect"
    assert children[0].poll() is not None
    if not stopped:
        assert "could not confirm" in " ".join(caught.value.__notes__)
    with pytest.raises(BoxOutputLimitExceeded):
        executor.run_parsed([], command="again", cwd=Path("/"), timeout=10)
    assert len(children) == 1
    assert len(daemon.calls) == 2


def test_valid_framed_response_preserves_command_exit_code_and_both_streams():
    wire = box.encode_response(box.BoxResult(rc=17, out=b"answer\n", err=b"warning\n"))

    def start(_argv, **kwargs):
        return subprocess.Popen([sys.executable, "-c", f"import os; os.write(1,{wire!r})"], **kwargs)

    executor = box.BoxExecutor(transport=box._DockerTransport("test", box.BoxSpec(), popen=start))
    result = executor.run_parsed(bash_exec.parse("echo ignored"), command="test", cwd=Path("/"), timeout=5)
    assert result == box.BoxResult(rc=17, out=b"answer\n", err=b"warning\n")


def test_host_allocation_is_bounded_even_for_a_much_larger_response():
    # Limit only this isolated reader's address space; the producer streams fixed chunks.
    script = '''
import os,resource,sys
from defender.box._output import capture_bounded,BoxOutputLimitExceeded
pages=int(open('/proc/self/statm').read().split()[0])
ceiling=pages*os.sysconf('SC_PAGE_SIZE')+32*1024*1024
resource.setrlimit(resource.RLIMIT_AS,(ceiling,ceiling))
producer="import os\\nfor _ in range(16384): os.write(1,b'x'*8192)"
try:
 capture_bounded([sys.executable,'-c',producer],b'',timeout=10,limit=1024*1024)
except BoxOutputLimitExceeded:
 print('bounded')
else:
 raise AssertionError('oversized output accepted')
'''
    result = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True,
                            env={**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[3])},
                            check=False, timeout=20)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "bounded"
