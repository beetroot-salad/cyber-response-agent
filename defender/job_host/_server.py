"""The job socket's server (#1170 H9): one thread accepting, one per connection, each request answered from the
registry by the job's kind, and only for a peer that is one of the job container's processes.

The peer is judged by `SO_PEERCRED`: the pid that connected must be among the container's processes as docker reports
them (its init and `docker top`, with their descendants). The answer for any other peer is a `peer` refusal and the
request is not looked at. The socket is 0600 in a 0700 folder (H9)."""
from __future__ import annotations

import contextlib
import logging
import os
import socket
import struct
import threading
from pathlib import Path
from typing import Any

from defender import tenancy
from defender.job_socket import Refused, read_message, write_message

from ._container import container_processes, owner
from ._session import Registry, Session

_logger = logging.getLogger(__name__)

_PEERCRED = struct.Struct("3i")
#: Seconds a connection may take to send its request.
_REQUEST_WAIT = 30.0


class Server:
    """Serves `session`'s socket at `path` until `close()`."""

    def __init__(self, session: Session, registry: Registry, path: Path) -> None:
        self._session, self._registry, self.path = session, registry, path
        self._listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            self._listener.bind(str(path))
            os.chmod(path, 0o600)
            uid, gid = owner(session)
            if os.geteuid() == 0 and (uid, gid) != (0, 0):
                os.chown(path, uid, gid)
            self._listener.listen(64)
        except BaseException:
            self._listener.close()
            raise
        self._listener.settimeout(0.2)
        self._closing = threading.Event()
        self._peers: dict[int, str | None] = {}
        self._peers_lock = threading.Lock()
        self._thread = threading.Thread(target=self._accept, name="job-socket", daemon=True)
        self._thread.start()

    def close(self) -> None:
        self._closing.set()
        self._thread.join(timeout=5)
        self._listener.close()
        with contextlib.suppress(OSError):
            self.path.unlink()

    def _accept(self) -> None:
        while not self._closing.is_set():
            try:
                conn, _ = self._listener.accept()
            except TimeoutError:
                continue
            except OSError:
                if self._closing.is_set():
                    return
                continue
            threading.Thread(target=self._serve, args=(conn,), name="job-socket-request", daemon=True).start()

    def _peer_ok(self, pid: int) -> bool:
        if pid <= 0:
            return False
        start = tenancy.process_start(pid)
        if start is None:
            # No such live process (gone, or a zombie): nothing to recognise it by.
            return False
        with self._peers_lock:
            if pid in self._peers and self._peers[pid] == start:
                return True
        if pid not in container_processes(self._session):
            return False
        with self._peers_lock:
            self._peers[pid] = start
        return True

    def _serve(self, conn: socket.socket) -> None:
        with conn:
            conn.settimeout(_REQUEST_WAIT)
            try:
                pid, _uid, _gid = _PEERCRED.unpack(conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                                                   _PEERCRED.size))
                if not self._peer_ok(pid):
                    _logger.warning("job socket: refused a peer (pid %s) that is not the job container's", pid)
                    write_message(conn, {"refused": {"code": "peer", "reason": "only the job container's processes "
                                                                               "are answered"}})
                    return
                request = read_message(conn)
                answer = self._answer(request)
                conn.settimeout(None)
                write_message(conn, answer)
            except (OSError, ValueError) as broken:
                _logger.info("job socket: a connection ended without an answer: %s", broken)

    def _answer(self, request: Any) -> dict[str, Any]:
        name = request.get("request") if isinstance(request, dict) else None
        fields = request.get("fields") if isinstance(request, dict) else None
        try:
            return {"ok": self._registry.answer(self._session, name, fields)}
        except Refused as refused:
            _logger.info("job socket: %s refused (%s): %s", name, refused.code, refused)
            return {"refused": {"code": refused.code, "reason": str(refused)}}
        except Exception as fault:  # noqa: BLE001 — one request's fault is its refusal, never the helper's end
            _logger.exception("job socket: %s faulted", name)
            return {"refused": {"code": "internal", "reason": f"{type(fault).__name__}: {fault}"}}
