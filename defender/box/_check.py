"""The box check (#1469 S3, D1-D3): before a box is created under the sandboxing runtime, a box is RUN to prove that
the runtime refuses a connect to a host unix socket.

Two short `docker run --rm` containers carry the box's confinement, its image and one check-owned bind (a fresh folder
under `<data root>/.box-checks/` holding a socket this process listens on): one under the box runtime, one control
under `runc` named explicitly. Each tries one stream connect and prints a marker. The verdict rests on the host
listener's own accept, never on which error the box saw:

- failed: the box runtime's run printed `connected`, or the listener accepted a connection during it;
- pass: it printed `refused` with no accept, and the control printed `connected` with an accept;
- inconclusive: anything else (a container that did not run, no marker, the timeout, a control that did not connect).

A pass is kept in memory for the process, per docker seam and registration (D2); a refusal never is. Nothing here reads
a runtime's configuration."""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import threading
import weakref
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Any, NamedTuple

from ._docker import BoxFault, DaemonRuntimes, DockerFn, Rootfs, _covered, _daemon_source, _uncovered_fault

#: Where the check folder sits in the check container, and the socket's name in it. Short, so the in-box connect path
#: can never exceed a socket name's limit whatever the data root is.
CHECK_TARGET = "/run/box-check"
SOCKET_NAME = "s"
#: Under the data root, beside `.job-sockets/` and like it outside every tenant folder and every container's binds.
CHECK_FOLDERS = ".box-checks"
#: Host wall seconds each check container is given, as `running_wait` is.
CHECK_TIMEOUT = 30
#: The one runtime that is the declared no-sandbox mode, and so is not checked. Every other name is proven, so a
#: runtime nobody meant to name (`runsc-job` among them) is refused rather than started unchecked.
_UNCHECKED = "runc"
_SOCKET_ENTRY = f"{CHECK_TARGET}/{SOCKET_NAME}"
#: The container's whole job: one stream connect, one marker.
_CONNECT = (
    "import socket\n"
    "s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n"
    "s.settimeout(5)\n"
    "try:\n"
    f"    s.connect({_SOCKET_ENTRY!r})\n"
    "    print('connected')\n"
    "except OSError as e:\n"
    "    print('refused', e.errno)\n"
)
_MARKER = re.compile(r"(connected|refused(?: (\d+))?)")


class BoxCheckFailed(BoxFault):  # noqa: N818 — named for what it reports
    """The box runtime let a box connect to a host socket. Not a `BoxStartConflict` (a collision): the unsandboxed
    opt-out never degrades a leak, so it is excluded by type (`_opt_out_or_raise`)."""


# --- the registration key and the passes held in memory (D2) ------------------------------------------------------------

#: Registrations seen to pass, by the docker seam (weakly, so a dropped seam's pass dies with it and a new seam that
#: reuses its address inherits nothing). A seam that cannot be weakly referenced is never kept.
_PASSED: weakref.WeakKeyDictionary[Any, set[tuple[str, str]]] = weakref.WeakKeyDictionary()
_PASSED_LOCK = threading.Lock()


def _registration_key(answer: DaemonRuntimes | None, runtime: str) -> tuple[str, str] | None:
    """The daemon's `ID` and a hash of `runtime`'s `docker info` Runtimes entry (canonical JSON), from the one answer
    the presence check read (`require_runtime`): a re-registration changes the entry. None when that answer cannot name
    both."""
    if answer is None or not answer.daemon_id or answer.runtimes is None:
        return None
    entry = answer.runtimes.get(runtime)
    if entry is None:
        return None
    canonical = json.dumps(entry, sort_keys=True, separators=(",", ":"))
    return answer.daemon_id, hashlib.sha256(canonical.encode()).hexdigest()


def _held(docker: DockerFn, key: tuple[str, str]) -> bool:
    try:
        with _PASSED_LOCK:
            return key in _PASSED.get(docker, ())
    except TypeError:
        return False


def _keep(docker: DockerFn, key: tuple[str, str]) -> None:
    with contextlib.suppress(TypeError), _PASSED_LOCK:
        _PASSED.setdefault(docker, set()).add(key)


#: One lock per registration key, so box starts that arrive together on one registration (a preflight's worlds, each
#: starting its first box) run one check and the rest wait for its verdict, instead of each running its own.
_KEY_LOCKS: dict[tuple[str, str], threading.Lock] = {}


def _one_at_a_time(key: tuple[str, str] | None) -> contextlib.AbstractContextManager[object]:
    if key is None:  # an unkeyed check is never kept, so a waiter would gain nothing by waiting
        return contextlib.nullcontext()
    with _PASSED_LOCK:
        return _KEY_LOCKS.setdefault(key, threading.Lock())


# --- the host listener ---------------------------------------------------------------------------------------------------

class _Count:
    accepted = 0


class _Listener:
    """A stream socket named `s` in the check folder, bound through the folder opened as a descriptor and reached as
    `/proc/self/fd/<n>/s` (never `chdir`, which is process-wide), so a long data root cannot exceed the socket-name
    limit. Open to every uid, so permissions cannot be the reason a connect fails."""

    def __init__(self, folder: Path) -> None:
        self._fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY)
        try:
            self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        except BaseException:
            os.close(self._fd)  # no socket to close, only the folder's descriptor
            raise
        try:
            self._sock.bind(f"/proc/self/fd/{self._fd}/{SOCKET_NAME}")
            os.chmod(SOCKET_NAME, 0o777, dir_fd=self._fd)  # the umask would narrow a create mode
            self._sock.listen(16)
        except BaseException:
            self.close()
            raise

    @contextlib.contextmanager
    def watching(self):  # noqa: ANN201
        """Count the connections accepted while the block runs. A connect completes in the kernel's backlog before any
        accept, so after the block the backlog is drained synchronously: a thread alone could read a leak as a pass."""
        count, stop = _Count(), threading.Event()

        def loop() -> None:
            self._sock.settimeout(0.05)
            while not stop.is_set():
                try:
                    conn, _ = self._sock.accept()
                except TimeoutError:
                    continue
                except OSError:
                    return
                conn.close()
                count.accepted += 1

        thread = threading.Thread(target=loop, name="box-check-listener", daemon=True)
        thread.start()
        try:
            yield count
        finally:
            stop.set()
            thread.join()
            self._sock.setblocking(False)
            while True:
                try:
                    conn, _ = self._sock.accept()
                except OSError:  # BlockingIOError: the backlog is empty
                    break
                conn.close()
                count.accepted += 1

    def close(self) -> None:
        with contextlib.suppress(OSError):
            self._sock.close()
        with contextlib.suppress(OSError):
            os.unlink(SOCKET_NAME, dir_fd=self._fd)
        with contextlib.suppress(OSError):
            os.close(self._fd)


# --- one check container -------------------------------------------------------------------------------------------------

class _Seen(NamedTuple):
    """What one check container did: its `marker` (`connected`, `refused`, or None), the errno a refusal printed, why it
    did not run (`failure`, None when it ran), and the connections the listener accepted during it."""

    marker: str | None
    errno: str | None
    failure: str | None
    accepted: int


def _run(docker: DockerFn, argv: list[str], name: str, listener: _Listener) -> _Seen:
    marker = errno = failure = None
    with listener.watching() as count:
        try:
            done = docker(argv, timeout=CHECK_TIMEOUT)
        except subprocess.TimeoutExpired:
            failure = f"it outlived {CHECK_TIMEOUT} s and was removed"
            with contextlib.suppress(OSError, subprocess.SubprocessError):
                docker(["docker", "rm", "-f", name])  # killing the docker client would leave the container running
        except (OSError, subprocess.SubprocessError) as e:
            failure = f"docker could not be run for it: {e}"
        else:
            if done.returncode != 0:
                failure = f"docker could not run it (exit {done.returncode}): {(done.stderr or '').strip()[:200]}"
            elif found := _MARKER.fullmatch((done.stdout or "").strip()):
                marker, errno = found.group(1).split()[0], found.group(2)
            else:
                failure = "it printed no marker"
    return _Seen(marker, errno, failure, count.accepted)


def _argv(flags: Sequence[str], runtime: str, name: str, labels: Sequence[str], source: Path, rootfs: Rootfs) -> list[str]:
    flags = list(flags)
    flags[flags.index("--runtime") + 1] = runtime
    return ["docker", "run", "--rm", *flags, "--name", name, *labels,
            "--mount", f"type=bind,source={source},target={CHECK_TARGET}",
            rootfs.image, "python3", "-c", _CONNECT]


def _dir(path: Path, what: str) -> None:
    if path.is_symlink() or not path.is_dir():
        raise BoxFault(f"the box check could not make its folder: {path} is not a folder this process made ({what})")


@contextlib.contextmanager
def _check_scope(data_root: Path) -> Iterator[tuple[Path, _Listener]]:
    """Everything the check holds on the host, owned in one place: `<data root>/.box-checks/<random>/` (a traverse-only
    parent, 0711, so the random names cannot be listed; a fresh folder open to every uid, 0777 by explicit chmod: the
    umask would narrow a create mode) and the listener in it. Once the folder exists it is removed however the scope
    ends."""
    parent = data_root / CHECK_FOLDERS
    try:
        parent.mkdir(mode=0o711, exist_ok=True)  # lint-unguarded-tree-write: ok — beside .job-sockets, in no box's or job's bind
        _dir(parent, CHECK_FOLDERS)
        os.chmod(parent, 0o711)
        folder = parent / secrets.token_hex(16)
        folder.mkdir(mode=0o700)  # lint-unguarded-tree-write: ok — exclusive, fresh, in no bind but its own check's
    except OSError as e:
        raise BoxFault(f"the box check could not make its folder under {data_root}: {e}") from e
    try:
        try:
            os.chmod(folder, 0o777)
        except OSError as e:
            raise BoxFault(f"the box check could not make its folder under {data_root}: {e}") from e
        try:
            listener = _Listener(folder)
        except OSError as e:
            raise BoxFault(f"the box check could not open its socket in {folder}: {e}") from e
        try:
            yield folder, listener
        finally:
            listener.close()
    finally:
        _clear_check_folder(folder)


# --- the verdict -----------------------------------------------------------------------------------------------------------

_LAYOUT = ("a shared folder that cannot carry sockets, a security label (SELinux) on the data root's mount, or a "
           "docker daemon that cannot see the data root")


def _leak_fault(runtime: str) -> BoxCheckFailed:
    return BoxCheckFailed(
        f"the box runtime {runtime!r} lets a box connect to a host socket: register it without host-socket access "
        "(defender/CLAUDE.md, \"Upgrade from before #1469\")")


def _inconclusive(runtime: str, why: str) -> BoxFault:
    return BoxFault(f"the box check could not tell whether the box runtime {runtime!r} refuses a connect to a host "
                    f"socket, so the box is not started: {why} (defender/CLAUDE.md, \"Upgrade from before #1469\")")


def _control_fault(runtime: str, seen: _Seen) -> BoxFault:
    if seen.failure is not None:
        what = f"its control container under runc did not run to a marker: {seen.failure}"
    elif seen.marker == "refused":
        what = f"its control container under runc could not connect either (errno {seen.errno}) or its connection was not accepted"
    else:
        what = "its control container under runc printed `connected` but the host listener saw no connection"
    return _inconclusive(runtime, f"{what}; the control proves the socket, the bind and the image work, so a refusal "
                                  f"cannot be put down to the runtime. Likely host-layout causes: {_LAYOUT}")


def _clear_check_folder(folder: Path) -> None:
    """Remove the check's folder. The folder holds only the socket, so unlink and rmdir need no new descriptor, as a
    walk would: a process out of descriptors still leaves nothing behind. Anything else in it is swept the slow way."""
    with contextlib.suppress(OSError):
        os.unlink(folder / SOCKET_NAME)
    try:
        os.rmdir(folder)
    except FileNotFoundError:
        pass
    except OSError:
        shutil.rmtree(folder, ignore_errors=True)


def require_box_check(docker: DockerFn, runtime: str, rootfs: Rootfs, *, answer: DaemonRuntimes | None,
                      flags: Sequence[str], labels: Sequence[str], data_root: Path,
                      mounts: Sequence[tuple[Path, Path]]) -> None:
    """Prove, by running a box, that `runtime` refuses a host-socket connect, once per process per registration.
    Returns on a pass (or for a runtime that is no sandbox); raises `BoxCheckFailed` when the runtime lets the connect
    through, `BoxFault` when the check could not say. `answer` is the daemon's runtimes as the presence check read them
    for this start (`require_startable`), `flags` the box's confinement (`_box_flags`), `labels` its claim and tenant
    labels, `mounts` the shared-mount table binds are translated through."""
    if runtime == _UNCHECKED:
        return
    key = _registration_key(answer, runtime)
    with _one_at_a_time(key):
        if key is not None and _held(docker, key):
            return
        _check(docker, runtime, rootfs, flags=flags, labels=labels, data_root=data_root, mounts=mounts)
        if key is not None:
            _keep(docker, key)


def _check(docker: DockerFn, runtime: str, rootfs: Rootfs, *, flags: Sequence[str], labels: Sequence[str],
           data_root: Path, mounts: Sequence[tuple[Path, Path]]) -> None:
    """One check. Its edge has one rule (D1): a leak is `BoxCheckFailed`, and anything else that stops it from saying
    `pass` is a check that could not say, a `BoxFault`, whatever raised it."""
    data_root = Path(data_root)
    if mounts and not _covered(data_root / CHECK_FOLDERS, mounts):
        raise _uncovered_fault("data root", data_root, mounts, "Set DEFENDER_DATA_ROOT to a path")
    try:
        with _check_scope(data_root) as (folder, listener):
            _run_check(docker, runtime, rootfs, flags, labels, folder, _daemon_source(folder, mounts), listener)
    except BoxFault:
        raise
    except Exception as e:  # noqa: BLE001 — the check's one edge: whatever stopped it, it could not say
        raise _inconclusive(runtime, f"the check itself failed: {type(e).__name__}: {e}") from e


def _run_check(docker: DockerFn, runtime: str, rootfs: Rootfs, flags: Sequence[str], labels: Sequence[str], folder: Path,
           source: Path, listener: _Listener) -> None:
    suffix = secrets.token_hex(6)
    box_name, control_name = f"defender-boxcheck-{suffix}-box", f"defender-boxcheck-{suffix}-control"
    box = _run(docker, _argv(flags, runtime, box_name, labels, source, rootfs), box_name, listener)
    # The listener's accept decides first: a connection reached the host whatever else the run did or printed.
    if box.accepted or box.marker == "connected":
        raise _leak_fault(runtime)
    if box.failure is not None:
        raise _inconclusive(runtime, f"its check container under {runtime} did not run to a marker: {box.failure}")
    control = _run(docker, _argv(flags, "runc", control_name, labels, source, rootfs), control_name, listener)
    if control.failure is not None or control.marker != "connected" or not control.accepted:
        raise _control_fault(runtime, control)
