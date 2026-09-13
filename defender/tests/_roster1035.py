"""Substrate for the #1035 pins (`test_1035_one_roster_read.py`): the generalised
drop-to-`nobody` instrument, and the surface under test that does not exist yet.

WHY A SECOND INSTRUMENT. `_declared869.unreadable_dir_verdict` is the right idea and the wrong
shape for this issue: it hardcodes the probe (`declared_systems(root)`, the union), the mode
(`0o000`, the cannot-LIST arm) and the restore (`0o755`), and its child maps EVERY escape that
is not a `LeadAuthorError` to exit 2 — "setup failed". #1035's defect is a raw `PermissionError`
out of the resolver over a mode-`0o400` directory (listable, not searchable), so under that
helper the red run would read "the child never reached the resolver" — a misdiagnosis of the
very fault the pin exists to name. This one is parameterised on the probe and the expected
class, gives "raised something else" its own exit code, and ships the child's verdict — the
raised class, its message, the returned value's repr, and everything the probe logged — back
over a pipe, because `capsys` cannot see across `os._exit` and an assertion about a log line
("(continuing)" must not appear) or a message ("names the directory") needs the text.

WHY `nobody` AT ALL. The local gate runs as uid 0, for whom `chmod` is a no-op on the fault
(P2 of #869 measured it: root lists a mode-000 directory), and a `skipif(geteuid() == 0)`
leaves the pin unexecuted exactly where it is run most. So the child forks, drops to `nobody`,
and meets the real fault through the real primitive.

Underscore-prefixed so pytest does not collect it; it defines no tests.
"""
from __future__ import annotations

import io
import json
import os
from collections.abc import Callable, Iterator
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from dataclasses import dataclass
from pathlib import Path

from defender.tests._declared869 import _hand_tree_to_nobody, _NOBODY, _reclaim_tree

# THE SURFACE UNDER TEST — the roster primitive #1035 M1 lifts out of
# `ModuleVerbRegistry._read_roster`. It does not exist on this base (RED by construction).
try:  # pragma: no cover — the post-implementation branch
    from defender.runtime.verbs import read_roster  # type: ignore[attr-defined]
except ImportError as _err:  # pragma: no cover — the pre-implementation state
    _missing_target = _err

    def read_roster(adapters_dir: Path):
        """Stand in for the not-yet-written primitive.

        NOT a skip and NOT a soften: calling it raises, so each test fails loudly on its own.
        The indirection exists only so the missing target does not abort pytest's whole
        collection and take the rest of the tree's suite down with it."""
        raise ImportError(
            "defender.runtime.verbs.read_roster does not exist yet — "
            "test_1035_one_roster_read.py is the executable spec for it. "
            f"Original: {_missing_target}"
        )


#: The child's exit codes. Distinct on purpose: a red run must say WHAT happened in the child,
#: and "raised something other than the expected class" is this issue's own defect, not a
#: setup failure.
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
    """What the `nobody` child saw, shipped back over the pipe.

    `raised` is the raised exception's qualified class name (None when the probe returned);
    `message` is its `str()`; `returned` is the returned value's `repr()` (None when it
    raised); `log` is everything the probe wrote to stdout and stderr while it ran."""

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
    """Fork, drop the child to `nobody`, run `probe` there with both streams captured, and
    return its verdict.

    The exit code classifies the outcome (see the `EXIT_*` constants) and the pipe carries the
    detail. The pipe is drained BEFORE `waitpid`, so a child with a long log cannot block on a
    full pipe while the parent waits for it to exit."""
    read_end, write_end = os.pipe()
    pid = os.fork()
    if pid == 0:  # pragma: no cover — the child never returns to pytest
        os.close(read_end)
        code = EXIT_SETUP_FAILED
        payload: dict[str, object] = {"raised": None, "message": "", "returned": None}
        buf = io.StringIO()
        try:
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
    """Hand `root` (and everything under it) to `nobody`, set `target` to `mode`, and undo
    both on the way out.

    Handed over rather than merely opened up, for the same reason `_declared869` does it: a
    probe that writes state (the pitfalls drain's queue lock) or runs git needs to OWN the
    tree, and a setup failure is not a refusal. `mode` is the whole point of the parameter —
    `0o400` is the listable-but-unsearchable arm (#1035's own), `0o000` the cannot-list arm,
    `0o755` the readable positive control."""
    _hand_tree_to_nobody(root)
    target.chmod(mode)
    try:
        yield
    finally:
        target.chmod(0o755)
        _reclaim_tree(root)
