"""A child process's death tie to its parent (#1342 O7, #1344 O9): nothing a worker started outlives it.

`tie_to_parent` sets this process's parent-death signal to SIGTERM; `require_parent` exits at once
when the parent `--parent-pid` names is already gone (it died between the spawn and the tie, so no
parent-death signal will ever arrive). `tied_argv` wraps a command line so the process it starts
gets the same tie before it runs: the tie is set in the child itself, never with `preexec_fn`,
which is unsafe in a threaded parent.

The parent-death signal fires when the THREAD that started the child exits, so a caller starts and
waits for a tied child from one thread.
"""
from __future__ import annotations

import ctypes
import os
import signal
import sys

__all__ = ["require_parent", "tie_to_parent", "tied_argv"]

_PR_SET_PDEATHSIG = 1

#: Run by `python -c` in the child: tie to the parent, refuse if it is already gone, then become
#: the real command (same pid, so a signal to the child reaches the command). Imports nothing of
#: defender, so it needs no PYTHONPATH.
_TIE_SHIM = (
    "import ctypes, os, signal, sys\n"
    "libc = ctypes.CDLL(None, use_errno=True)\n"
    f"if libc.prctl({_PR_SET_PDEATHSIG}, signal.SIGTERM, 0, 0, 0) != 0:\n"
    "    sys.exit('could not set the parent-death signal: ' + os.strerror(ctypes.get_errno()))\n"
    "if os.getppid() != int(sys.argv[1]):\n"
    "    sys.exit('the parent that started this process is gone; nothing was run')\n"
    "os.execvp(sys.argv[2], sys.argv[2:])\n"
)


def tie_to_parent() -> None:
    """Die with the parent: the parent-death signal is SIGTERM, set in this process."""
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(_PR_SET_PDEATHSIG, signal.SIGTERM, 0, 0, 0) != 0:
        err = ctypes.get_errno()
        raise OSError(err, f"could not set the parent-death signal: {os.strerror(err)}")


def require_parent(parent_pid: int, *, who: str) -> None:
    """Exit at once unless this process's parent is still `parent_pid`."""
    if os.getppid() != parent_pid:
        sys.exit(f"[{who}] --parent-pid {parent_pid} is not this process's parent "
                 f"({os.getppid()}): the worker that started it is gone; nothing was run")


def tied_argv(argv: list[str]) -> list[str]:
    """`argv` run through the tie shim: the child is tied to this process before it execs
    `argv[0]` (looked up on the child's PATH when it is not a path) with `argv`."""
    return [sys.executable, "-c", _TIE_SHIM, str(os.getpid()), *argv]
