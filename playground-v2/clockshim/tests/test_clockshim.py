"""#1347 r6.4.3 D15 revised: the frozen node's wall-clock shim reads its offset from a file, mapped once.

Bound here: `playground-v2/clockshim/clockshim.c` builds with `gcc -shared -fPIC -o clockshim.so clockshim.c
-ldl` (as its Dockerfile does) and, preloaded, shifts CLOCK_REALTIME readings by the offset held in the file
`V2_CLOCK_OFFSET_FILE` names: a fixed 24-byte record, a signed decimal integer number of seconds padded with
spaces and ending in a newline (r6.4.3 settlements), rewritten in place at byte 0 and never truncated.
The file is mapped on the first clock call and its mapped bytes are read on every call, so rewriting it in
place changes the next reading without a restart, and no file is opened per call. Monotonic clocks are untouched.

Compiles and runs a real process; skipped only where no C compiler is installed, and never in CI (with `CI`
set, a missing gcc fails the tests). Run:

    defender-pytest defender/.venv/bin/python -m pytest playground-v2/clockshim/tests -q
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

SOURCE = Path(__file__).resolve().parents[1] / "clockshim.c"
DAY = 86_400
WIDTH = 24          # every value is written at this width, so a rewrite in place keeps the file's size

PROBE = ("import sys, time\n"
         "for _ in sys.stdin:\n"
         "    print(time.time(), time.monotonic(), flush=True)\n")


@pytest.fixture(scope="module")
def shim(tmp_path_factory):
    if shutil.which("gcc") is None:
        if os.environ.get("CI"):
            pytest.fail("no C compiler (gcc) on the CI runner: the shim tests must run there, not skip")
        pytest.skip("no C compiler (gcc) on this machine")
    out = tmp_path_factory.mktemp("clockshim") / "clockshim.so"
    built = subprocess.run(["gcc", "-shared", "-fPIC", "-O2", "-o", str(out), str(SOURCE), "-ldl"],
                           capture_output=True, text=True)
    assert built.returncode == 0, built.stderr
    return out


def _write(path: Path, seconds: int) -> None:
    """Rewrite the offset in place (same inode, same size), as the launcher does on the shared volume."""
    text = f"{seconds:>{WIDTH - 1}}\n".encode()
    if path.exists():
        with open(path, "r+b") as fh:
            fh.seek(0)
            fh.write(text)
    else:
        path.write_bytes(text)


class Probe:
    def __init__(self, shim: Path, offset_file: Path) -> None:
        env = {"PATH": "/usr/bin:/bin", "LD_PRELOAD": str(shim), "V2_CLOCK_OFFSET_FILE": str(offset_file)}
        self.proc = subprocess.Popen([sys.executable, "-c", PROBE], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     text=True, env=env)

    def read(self) -> tuple[float, float, float]:
        """(the process's wall clock, its monotonic clock, the real wall clock at the reading)."""
        self.proc.stdin.write("\n")
        self.proc.stdin.flush()
        line = self.proc.stdout.readline()
        assert line, "the probe died"
        wall, mono = map(float, line.split())
        return wall, mono, time.time()

    def close(self) -> None:
        self.proc.stdin.close()
        self.proc.wait(timeout=10)


def test_the_offset_comes_from_the_file_and_a_rewrite_in_place_changes_the_next_reading(shim, tmp_path):
    """D15 revised: the node starts with the file holding the offset (+1 day here); a rewrite in place
    (-1 hour) moves the same process's next wall-clock reading; its monotonic clock does not jump."""
    offset_file = tmp_path / "clock-offset"
    _write(offset_file, DAY)
    probe = Probe(shim, offset_file)
    try:
        wall, mono, real = probe.read()
        assert abs(wall - (real + DAY)) < 60, (wall, real)
        _write(offset_file, -3600)
        wall2, mono2, real2 = probe.read()
        assert abs(wall2 - (real2 - 3600)) < 60, (wall2, real2)
        assert 0 <= mono2 - mono < 60, "the monotonic clock jumped with the offset"
        pid = probe.proc.pid
        assert probe.proc.poll() is None and probe.proc.pid == pid, "the process restarted"
    finally:
        probe.close()


def test_the_file_is_mapped_once_not_read_per_call(shim, tmp_path):
    """D15 revised: once mapped, the offset keeps coming from the mapping: with the file's name unlinked
    and a NEW file holding another offset put at the same path, the next reading still carries the mapped
    offset (a shim that opens the file per call would read the new one)."""
    offset_file = tmp_path / "clock-offset"
    _write(offset_file, DAY)
    probe = Probe(shim, offset_file)
    try:
        wall, _mono, real = probe.read()
        assert abs(wall - (real + DAY)) < 60
        offset_file.unlink()
        _write(offset_file, -7 * DAY)
        wall2, _mono2, real2 = probe.read()
        assert abs(wall2 - (real2 + DAY)) < 60, "the shim re-reads the file per call instead of its mapping"
    finally:
        probe.close()


def test_a_negative_offset_moves_the_clock_back(shim, tmp_path):
    """D15: a freeze moment in the past is a negative offset."""
    offset_file = tmp_path / "clock-offset"
    _write(offset_file, -30 * DAY)
    probe = Probe(shim, offset_file)
    try:
        wall, _mono, real = probe.read()
        assert abs(wall - (real - 30 * DAY)) < 60, (wall, real)
    finally:
        probe.close()
