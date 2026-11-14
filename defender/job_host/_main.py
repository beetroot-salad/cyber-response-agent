"""The per-job host helper's flow (#1170 H7, Design 1-8, A1-A5): one job of one tenant, from the claim to its end.

In order: tied to the worker (its parent; `--parent-pid`), the kind's host half (`prepare`: the tenant's lock and
admission, ..., the first pass, the run folder), the job socket in its per-claim folder, the job container started
attached as this process's child, the socket served until the container exits, then everything the job had removed
by its claim's label, what the helper made removed, and the lock released. The helper exits 0 once it served the job to
its end, whatever the container's own status (logged); any other exit is the helper's own failure.

An ending decided before the container starts is written by the helper in the kind's vocabulary (A3): a setup
refusal; a job that cannot be started confined (no socket, an image missing, a refusing runtime, or the helper
signalled first: no container is then started, A1). From the container's start on, the container writes it.

SIGTERM (a fence, the worker's stop, teardown, the worker's death) before the container starts ends the helper with
no container; after it, the container is stopped with a grace (`docker stop --time 22`, A2) while `launch`,
`box.exec` and `box.stop` are still answered and everything else is refused (A1); teardown's own removal of the
tenant's containers ends that wait early (H8)."""
from __future__ import annotations

import argparse
import contextlib
import functools
import logging
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
import uuid
from collections.abc import Iterator
from typing import Any

from . import _common, _investigation, _learning
from ._container import (
    STOP_GRACE,
    job_container_name,
    make_socket_folder,
    container_launch,
    socket_folder,
    socket_path,
    start,
)
from ._server import Server
from ._session import KINDS, HandBack, KindSpec, Registry, Session, SetupRefused, StartFailed

_logger = logging.getLogger(__name__)

_CLAIM = re.compile(r"[0-9a-f]{32}")
#: Seconds the helper waits for a container to end once its graceful stop returned, before removing it.
_AFTER_STOP = 5.0
_POLL = 0.05


@functools.cache
def registry() -> Registry:
    """Every request and kind the helper answers: the shared requests, the investigation kind, the learning kinds."""
    built = Registry()
    _common.register_common(built)
    _investigation.register_investigation(built)
    _learning.register(built)
    return built


def _parse_argv(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="python -m defender.job_host",
                                description="Run one job of one tenant in its own container (#1170).")
    p.add_argument("--kind", required=True, choices=KINDS, help="the job's kind")
    p.add_argument("--job", help="the job's id (an investigation's, a learning job's; none for a family-less "
                                 "post-step)")
    p.add_argument("--tenant", required=True, help="the job's tenant")
    p.add_argument("--source", help="a learning job's source run")
    p.add_argument("--parent-pid", required=True, type=int,
                   help="the worker that started this process; exit at once under any other")
    ns = p.parse_args(argv)
    if ns.kind != "post-step" and not ns.job:
        p.error(f"a {ns.kind} job needs --job")
    return ns


def _tell(session: Session, what: str) -> None:
    """A refusal or a start failure, on stderr (the worker's child log): the end record names only its class."""
    sys.stderr.write(f"[job_host] {session.kind} job {session.job_id or '(family-less)'} of tenant "
                     f"{session.tenant_id}: {what}\n")
    sys.stderr.flush()


class _Signalled(BaseException):  # noqa: N818 — named for what it reports
    """SIGTERM before the container started: unwinds the host half, so no container is started (A1)."""


class _Signals:
    """SIGTERM's handler for the helper's life (main thread only): it sets `session.signalled`, and, once, while the
    host half runs (`raising`), unwinds it as `_Signalled`. From the container's start on it only sets the flag; the
    serving loop stops the container."""

    def __init__(self, session: Session) -> None:
        self._session = session
        self.raising = True
        self._previous: Any = None
        self._installed = False

    def _on_term(self, _signum: int, _frame: object) -> None:
        self._session.signalled.set()
        if self.raising:
            self.raising = False
            raise _Signalled()

    def __enter__(self) -> _Signals:
        if threading.current_thread() is threading.main_thread():
            self._previous = signal.signal(signal.SIGTERM, self._on_term)
            self._installed = True
        return self

    def __exit__(self, *_exc: object) -> None:
        self.raising = False
        if self._installed:
            signal.signal(signal.SIGTERM, self._previous if self._previous is not None else signal.SIG_DFL)


def _graceful_stop(session: Session, proc: Any) -> None:
    """`docker stop --time <grace>`: the job unwinds, scrubs and writes its end record; then, if it still has not
    ended, it is removed (O7, A2). Teardown's own removal of the tenant's containers ends the wait early (H8)."""
    try:
        session.docker(["docker", "stop", "--time", str(STOP_GRACE), session.container])
    except (OSError, subprocess.SubprocessError) as e:
        _logger.warning("could not stop the job container %s: %s", session.container, e)
    deadline = time.monotonic() + _AFTER_STOP
    while proc.poll() is None and time.monotonic() < deadline:
        time.sleep(_POLL)
    if proc.poll() is None:
        _remove_claimed(session)


def _remove_claimed(session: Session) -> None:
    from defender.box import remove_claimed_containers

    try:
        why = remove_claimed_containers(session.claim, docker=session.docker)
    except (OSError, subprocess.SubprocessError, ValueError) as e:
        why = str(e)
    if why is not None:
        _logger.warning("the job's containers (claim %s) were not all removed: %s", session.claim, why)


def _await_container(session: Session, proc: Any) -> int:
    """Wait for the container; on a signal, stop it gracefully (once). Its exit status."""
    stopping = False
    while (rc := proc.poll()) is None:
        if session.signalled.is_set() and not stopping:
            stopping = True
            _graceful_stop(session, proc)
            continue
        time.sleep(_POLL)
    with contextlib.suppress(OSError, ValueError, subprocess.SubprocessError):
        _out, err = proc.communicate(timeout=5)
        if err:
            sys.stderr.write(err.decode("utf-8", "replace") if isinstance(err, bytes) else str(err))
    return int(rc)


def _finish(session: Session, proc: Any, server: Server | None, hold: contextlib.ExitStack) -> None:
    """Step 8: the container and the job's boxes go (by the claim's label), the socket closes, what the helper made
    for the job goes, and the tenant's lock is released last."""
    try:
        if proc is not None:
            if proc.poll() is None:
                _remove_claimed(session)
                with contextlib.suppress(OSError):
                    proc.kill()
            stdin = getattr(proc, "stdin", None)
            if stdin is not None:
                with contextlib.suppress(OSError):
                    stdin.close()
        if server is not None:
            server.close()
        _common.stop_boxes(session)
        _remove_claimed(session)
        shutil.rmtree(socket_folder(session), ignore_errors=True)
        if session.prepared is not None:
            session.prepared.cleanup.close()
    finally:
        hold.close()


def _start(session: Session, spec: KindSpec, signals: _Signals, hold: contextlib.ExitStack
           ) -> tuple[Any, Server | None, tuple[str, str] | None]:
    """The host half, the socket and the container: `(proc, server, None)`, or `(None, server, (cause, why))` for an
    ending decided before the container started."""
    server: Server | None = None
    ending: tuple[str, str] | None = None
    proc = None
    try:
        try:
            session.prepared = spec.prepare(session, hold)
            path = socket_path(session)
            try:
                make_socket_folder(session)
                server = Server(session, registry(), path)
            except OSError as e:
                raise StartFailed(f"the job socket {path} could not be opened: {e}") from None
            launch = container_launch(session, path, session.prepared.command)
            signals.raising = False  # from here a signal stops the container gracefully
            if session.signalled.is_set():
                raise StartFailed("the helper was told to stop before its container started; none was started")
            proc = start(session, launch)
        except SetupRefused as refused:
            ending = ("refused", f"setup refused: {refused}")
        except StartFailed as failed:
            ending = ("start-failed", f"the job cannot be started confined: {failed}")
        except HandBack as busy:
            ending = ("busy", f"handed back: {busy}")
        except SystemExit as exited:
            ending = ("refused", f"setup refused: {exited.code}")
        except Exception as crashed:  # noqa: BLE001 — a crash before the container is the job's ending, recorded
            _logger.exception("the helper's setup crashed")
            ending = ("crashed", f"setup crashed: {type(crashed).__name__}: {crashed}")
    except _Signalled:
        ending = ("start-failed", "the helper was told to stop before its container started; none was started")
    return proc, server, ending


#: The statuses docker itself gives a container it could not start or run: the runtime is not their cause.
_DID_NOT_RUN = (125, 126, 127)


def _say_unreached(session: Session, rc: int, server: Server | None) -> None:
    """D4 (#1469): a container that ended nonzero without the server ever accepting a connection, and that the helper
    was not told to stop, most likely ran under a job runtime that does not allow host-socket connections. The job's own
    refusal ended its row; this only names the likely cause, once, for every job kind. It writes no ending."""
    if rc == 0 or rc in _DID_NOT_RUN or session.signalled.is_set() or server is None or server.accepted.is_set():
        return
    from defender.box import BoxSpec

    from ._container import job_runtime

    try:
        runtime = job_runtime(BoxSpec.from_env(os.environ).runtime)
    except ValueError:
        runtime = "(unknown)"
    why = (f"the job never reached its socket; likely cause: the job runtime {runtime} does not allow host-socket "
           "connections (register `runsc-job` per the #1469 upgrade note, defender/CLAUDE.md)")
    _logger.warning("%s", why)
    _tell(session, why)


def _run(session: Session, spec: KindSpec, signals: _Signals) -> int:
    hold = contextlib.ExitStack()
    proc, server = None, None
    try:
        proc, server, ending = _start(session, spec, signals, hold)
        signals.raising = False
        if ending is not None:
            _tell(session, ending[1])
            spec.end(session, ending[0])
            return 0
        rc = _await_container(session, proc)
        _tell(session, f"its container exited with status {rc}")
        _say_unreached(session, rc, server)
        if session.prepared is not None and session.prepared.exited is not None:
            session.prepared.exited(session, rc)
        return 0
    finally:
        signals.raising = False
        _finish(session, proc, server, hold)


def main(argv: list[str], *, docker: Any = None, signer: Any = None, publish: Any = None, forge: Any = None,
         command: list[str] | None = None, client: Any = None) -> int:
    """The helper for one job (module doc). `docker` is the docker seam (the box package's real one by default),
    `signer` the request signer (the tenant's sign login), `publish` the launch-time publish (the real child),
    `forge` the forge credential's builder (the learning kinds'), `command` a container command line in place of the
    kind's entry, `client` the forge client the drain's delivery uses (a new one by default). Returns 0 once the helper served the job to its end (its container ran and exited, whatever its status, or the
    helper wrote the ending it decided before the container), else non-zero: the worker reads any other status, with
    no end record, as the helper's own failure (`worker._helper_failure`)."""
    from defender import tenancy
    from defender._parent_tie import require_parent, tie_to_parent
    from defender._paths import process_defender_dir
    from defender.box import CLAIM_ENV, run_docker
    from defender.records.formats import TenantRefused

    ns = _parse_argv(argv)
    tie_to_parent()  # die with the worker (O7), before anything else is taken
    require_parent(ns.parent_pid, who="job_host")
    try:
        tenant_id = tenancy.requested_tenant_id(ns.tenant)
        root = tenancy.resolve_data_root()
    except TenantRefused as refused:
        sys.stderr.write(f"[job_host] this job's tenant cannot be used: {refused}\n")
        return 1
    claim = os.environ.get(CLAIM_ENV) or uuid.uuid4().hex
    if not _CLAIM.fullmatch(claim):
        sys.stderr.write(f"[job_host] {CLAIM_ENV} is not a claim token the worker mints; nothing was started\n")
        return 1
    os.environ[CLAIM_ENV] = claim  # every box the helper starts carries the claim's label
    session = Session(kind=ns.kind, job_id=ns.job, tenant_id=tenant_id, source=ns.source, root=root,
                      root_folder=tenancy.data_root_for_child(root), claim=claim,
                      docker=docker if docker is not None else run_docker,
                      defender_dir=process_defender_dir().resolve(), signer=signer, publish=publish, forge=forge,
                      client=client, command=list(command) if command is not None else None)
    session.container = job_container_name(session)
    spec = registry().kinds.get(ns.kind)
    if spec is None:
        _tell(session, f"the helper serves no {ns.kind} job yet; nothing was started")
        return 1
    with _signals(session) as signals:
        return _run(session, spec, signals)


@contextlib.contextmanager
def _signals(session: Session) -> Iterator[_Signals]:
    with _Signals(session) as signals:
        yield signals
