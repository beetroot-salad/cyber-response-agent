"""The one provider of short data roots for a case that starts a real job-host helper.

A helper's job socket lives at `<data root>/.job-sockets/<32-hex claim>/job.sock` (the data root plus `SOCKET_SUFFIX`
bytes) and a unix socket's path is refused at 108 bytes. pytest's own roots (`/tmp/pytest-of-<user>/pytest-N/popen-gwN/
data-rootNNN`) grow with the user name, the session number and the test's position on its xdist worker, so whether one
fits depends on where the case happens to run: it passes locally and fails in CI from about the hundredth test on a worker.
A root from `short_root()` is `/tmp/p4rXXXXXXXX/N`, whatever the machine or position.

All roots of one process (one xdist worker) live under one parent, removed when the session ends (`remove_all`, also at
interpreter exit). A passing case removes its own root at once (`release`); a failing case's stays until the session ends,
and past it only when `KEEP_ENV` is set. `adopt_scene` (the one entry that starts a helper over a root someone else chose)
accepts only roots from here (`require_short_root`)."""
from __future__ import annotations

import atexit
import itertools
import os
import shutil
import tempfile
from pathlib import Path

#: `/.job-sockets/` + the 32-hex claim + `/job.sock`.
SOCKET_SUFFIX = len("/.job-sockets/") + 32 + len("/job.sock")
#: A unix socket's `sun_path` holds 108 bytes including the terminating NUL; the helper refuses at this length.
SOCKET_LIMIT = 108
#: The longest data root a provided root may have: room for the suffix with CI's longest tmp parent to spare.
ROOT_BUDGET = 40
#: Set (to anything) to keep every root past the session, for inspection.
KEEP_ENV = "DEFENDER_KEEP_SHORT_ROOTS"

_parent: Path | None = None
_provided: set[Path] = set()
_numbers = itertools.count(1)


class NotAShortRoot(RuntimeError):
    """A helper was asked to start over a data root the short-root provider did not make."""


def short_root() -> Path:
    """A new empty directory whose job socket path fits, under this process's one parent."""
    global _parent
    if _parent is None:
        _parent = Path(tempfile.mkdtemp(prefix="p4r", dir="/tmp"))
        atexit.register(remove_all)
    root = _parent / str(next(_numbers))
    root.mkdir()
    assert len(str(root)) <= ROOT_BUDGET, f"the provider's own root is over its budget: {root}"
    _provided.add(root)
    return root


def release(root: Path) -> None:
    """Remove `root` now (a case that passed)."""
    shutil.rmtree(root, ignore_errors=True)
    _provided.discard(root)


def remove_all() -> None:
    """The session's end: the parent and every root under it, unless `KEEP_ENV` asks to keep them."""
    global _parent
    if _parent is None or os.environ.get(KEEP_ENV):
        return
    shutil.rmtree(_parent, ignore_errors=True)
    _provided.clear()
    _parent = None


def socket_path_length(root: Path | str) -> int:
    return len(str(root)) + SOCKET_SUFFIX


def require_short_root(root: Path | str) -> None:
    """Refuse at once a data root that is not from `short_root()`, however short it happens to be here."""
    path = Path(root)
    if path in _provided and len(str(path)) <= ROOT_BUDGET:
        return
    raise NotAShortRoot(
        f"the helper's job socket would be {socket_path_length(path)} bytes under data root {str(path)!r} (a unix socket "
        f"path is refused at {SOCKET_LIMIT}), and whether that fits depends on the machine and the case's position on its "
        f"worker; only a root from `tests.support.jobs._short_root.short_root()` is accepted. Remedy: build the case's "
        f"world under a data root that provider made (in `tests/tenancy/tenant_1108_p4` the `data_root` fixture already "
        f"is one), do not choose the root yourself.")
