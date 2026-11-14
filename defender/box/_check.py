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
from collections.abc import Sequence
from pathlib import Path
from typing import Any, NamedTuple

from ._docker import BoxFault, DockerFn, Rootfs, _covered, _daemon_source, _uncovered_fault

#: Where the check folder sits in the check container, and the socket's name in it. Short, so the in-box connect path
#: can never exceed a socket name's limit whatever the data root is.
CHECK_TARGET = "/run/box-check"
SOCKET_NAME = "s"
#: Under the data root, beside `.job-sockets/` and like it outside every tenant folder and every container's binds.
CHECK_FOLDERS = ".box-checks"
#: Host wall seconds each check container is given, as `running_wait` is.
CHECK_TIMEOUT = 30
#: The runtimes that sandbox a box, and so are proven. `runc` is the declared no-sandbox mode.
_PROVEN = frozenset({"runsc"})
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


def _info(docker: DockerFn, fmt: str) -> str | None:
    """One `docker info` field, or None when the daemon cannot answer it."""
    try:
        done = docker(["docker", "info", "--format", fmt])
    except (OSError, subprocess.SubprocessError):
        return None
    return (done.stdout or "").strip() if done.returncode == 0 else None


def _registration_key(docker: DockerFn, runtime: str) -> tuple[str, str] | None:
    """The daemon's `ID` and a hash of `runtime`'s `docker info` Runtimes entry (canonical JSON): a re-registration
    changes the entry. None when `docker info` cannot name both."""
    daemon, listed = _info(docker, "{{.ID}}"), _info(docker, "{{json .Runtimes}}")
    if not daemon or not listed:
        return None
    try:
        entry = json.loads(listed).get(runtime)
    except (ValueError, AttributeError):
        return None
    if entry is None:
        return None
    canonical = json.dumps(entry, sort_keys=True, separators=(",", ":"))
    return daemon, hashlib.sha256(canonical.encode()).hexdigest()


def _held(docker: DockerFn, key: tuple[str, str]) -> bool:
    try:
        with _PASSED_LOCK:
            return key in _PASSED.get(docker, ())
    except TypeError:
        return False


def _keep(docker: DockerFn, key: tuple[str, str]) -> None:
    with contextlib.suppress(TypeError), _PASSED_LOCK:
        _PASSED.setdefault(docker, set()).add(key)


# --- the host listener ---------------------------------------------------------------------------------------------------

class _Count:
    accepted = 0


class _Listener:
    """A stream socket named `s` in the check folder, bound through the folder opened as a descriptor and reached as
    `/proc/self/fd/<n>/s` (never `chdir`, which is process-wide), so a long data root cannot exceed the socket-name
    limit. Open to every uid, so permissions cannot be the reason a connect fails."""

    def __init__(self, folder: Path) -> None:
        self._fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY)
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
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


def _make_folder(data_root: Path) -> Path:
    """`<data root>/.box-checks/<random>/`: traverse-only parent (0711, so the random names cannot be listed), a fresh
    folder open to every uid (0777, by explicit chmod: the umask would narrow a create mode)."""
    parent = data_root / CHECK_FOLDERS
    try:
        parent.mkdir(mode=0o711, exist_ok=True)  # lint-unguarded-tree-write: ok — beside .job-sockets, in no box's or job's bind
        _dir(parent, CHECK_FOLDERS)
        os.chmod(parent, 0o711)
        folder = parent / secrets.token_hex(16)
        folder.mkdir(mode=0o700)  # lint-unguarded-tree-write: ok — exclusive, fresh, in no bind but its own check's
        os.chmod(folder, 0o777)
    except OSError as e:
        raise BoxFault(f"the box check could not make its folder under {data_root}: {e}") from e
    return folder


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


def require_box_check(docker: DockerFn, runtime: str, rootfs: Rootfs, *, flags: Sequence[str], labels: Sequence[str],
                      data_root: Path | None, mounts: Sequence[tuple[Path, Path]]) -> None:
    """Prove, by running a box, that `runtime` refuses a host-socket connect, once per process per registration.
    Returns on a pass (or for a runtime that is no sandbox); raises `BoxCheckFailed` when the runtime lets the connect
    through, `BoxFault` when the check could not say. `flags` are the box's confinement (`_box_flags`), `labels` its
    claim and tenant labels, `mounts` the shared-mount table binds are translated through."""
    if runtime not in _PROVEN:
        return
    key = _registration_key(docker, runtime)
    if key is not None and _held(docker, key):
        return
    if data_root is None:
        raise _inconclusive(runtime, "no data root was handed to this box start, so there is no folder to run the "
                                     "check in")
    data_root = Path(data_root)
    if mounts and not _covered(data_root / CHECK_FOLDERS, mounts):
        raise _uncovered_fault("data root", data_root, mounts, "Set DEFENDER_DATA_ROOT to a path")
    folder = _make_folder(data_root)
    try:
        listener = _Listener(folder)
        try:
            _run_check(docker, runtime, rootfs, flags, labels, folder, _daemon_source(folder, mounts), listener)
        finally:
            listener.close()
    except OSError as e:
        raise BoxFault(f"the box check could not open its socket in {folder}: {e}") from e
    finally:
        shutil.rmtree(folder, ignore_errors=True)
    if key is not None:
        _keep(docker, key)


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
