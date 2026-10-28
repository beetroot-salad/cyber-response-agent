"""Helpers for `test_1035_one_roster_read.py`: a run-as-`nobody` probe and the surface under test."""
from __future__ import annotations

import io
import json
import os
import stat
from collections.abc import Callable, Iterator
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from dataclasses import dataclass
from pathlib import Path

from defender.tests.support.runtime.engine._declared869 import _hand_tree_to_nobody, _NOBODY, _reclaim_tree

# The surface under test, re-exported so the suite and this module name one symbol.
from defender.systems.verbs import read_roster  # noqa: F401 — re-exported to the suite

#: The child's exit codes, distinct so a red run says what happened: raising the wrong class is
#: a defect, not a setup failure.
EXIT_RAISED_EXPECTED = 0
EXIT_RETURNED = 1
EXIT_SETUP_FAILED = 2
EXIT_RAISED_OTHER = 3

_EXIT_NAMES = {
    EXIT_RAISED_EXPECTED: "raised the expected class",
    EXIT_RETURNED: "RETURNED instead of raising",
    EXIT_SETUP_FAILED: "never reached the probe (setup failed)",
    EXIT_RAISED_OTHER: "raised something OTHER than the expected class",
}


@dataclass(frozen=True)
class ChildVerdict:
    """What the `nobody` child saw: `raised` (qualified class name) and `message`, or `returned`
    (a `repr()`), plus `log`, the probe's stdout and stderr."""

    code: int
    raised: str | None
    message: str
    returned: str | None
    log: str

    def describe(self) -> str:
        what = _EXIT_NAMES.get(self.code, f"exited {self.code}")
        detail = (
            f"raised {self.raised}: {self.message}" if self.raised is not None
            else f"returned {self.returned}"
        )
        return f"the child {what} — {detail}; log: {self.log!r}"


def run_as_nobody(probe: Callable[[], object], *, expected: type[BaseException]) -> ChildVerdict:
    """Run `probe` in a forked child dropped to `nobody` (when root; a non-root uid already meets
    the mode bits) with both streams captured, and return its verdict. The pipe is drained before
    `waitpid` so a long log cannot block the child on a full pipe."""
    read_end, write_end = os.pipe()
    pid = os.fork()
    if pid == 0:  # pragma: no cover — the child never returns to pytest
        os.close(read_end)
        code = EXIT_SETUP_FAILED
        payload: dict[str, object] = {"raised": None, "message": "", "returned": None}
        buf = io.StringIO()
        try:
            if os.geteuid() == 0:
                os.setgroups([])
                os.setgid(_NOBODY)
                os.setuid(_NOBODY)
            with redirect_stdout(buf), redirect_stderr(buf):
                try:
                    value = probe()
                except expected as e:
                    code = EXIT_RAISED_EXPECTED
                    payload = {"raised": type(e).__qualname__, "message": str(e), "returned": None}
                except BaseException as e:  # noqa: BLE001 — the child reports what escaped
                    code = EXIT_RAISED_OTHER
                    payload = {"raised": type(e).__qualname__, "message": str(e), "returned": None}
                else:
                    code = EXIT_RETURNED
                    payload = {"raised": None, "message": "", "returned": repr(value)}
        except BaseException as e:  # noqa: BLE001 — setup failed; say so
            code = EXIT_SETUP_FAILED
            payload = {"raised": type(e).__qualname__, "message": str(e), "returned": None}
        finally:
            payload["log"] = buf.getvalue()
            try:
                os.write(write_end, json.dumps(payload).encode("utf-8"))
                os.close(write_end)
            finally:
                os._exit(code)
    os.close(write_end)
    chunks: list[bytes] = []
    while True:
        chunk = os.read(read_end, 65536)
        if not chunk:
            break
        chunks.append(chunk)
    os.close(read_end)
    _, status = os.waitpid(pid, 0)
    assert os.WIFEXITED(status), f"the nobody probe child did not exit: {status}"
    code = os.WEXITSTATUS(status)
    raw = b"".join(chunks)
    data = json.loads(raw.decode("utf-8")) if raw else {
        "raised": None, "message": "", "returned": None, "log": "",
    }
    return ChildVerdict(
        code=code, raised=data.get("raised"), message=str(data.get("message", "")),
        returned=data.get("returned"), log=str(data.get("log", "")),
    )


@contextmanager
def handed_to_nobody(root: Path, target: Path, mode: int) -> Iterator[None]:
    """Hand `root`'s tree to `nobody` and set `target` to `mode`, undoing both on the way out.

    Handed over, not just opened up: a probe that writes state (the drain's queue lock) or runs
    git must own the tree. `mode`: `0o400` listable but unsearchable, `0o000` unlistable,
    `0o755` the readable control."""
    # The reclaim runs even when the restoring `chmod` fails (the drain's `reset --hard` + `clean`
    # can remove `target`); otherwise later tests in this worker meet `nobody`-owned files.
    as_root = os.geteuid() == 0
    # Restore the original mode, not a fixed `0o755` that would leave an adapter file executable.
    original = stat.S_IMODE(target.stat().st_mode)
    try:
        if as_root:
            _hand_tree_to_nobody(root)
        target.chmod(mode)
        yield
    finally:
        try:
            target.chmod(original)
        except FileNotFoundError:
            pass
        finally:
            if as_root:
                _reclaim_tree(root)
