"""#1412 repair F1: every way one proxied exchange can end, as data, and one rig that runs any of
them against the real proxy on loopback under a written, held or failing audit. The rows of the
ending tests are generated from `ENDINGS`; nothing here judges what the proxy did."""
from __future__ import annotations

import contextlib
import gzip
import socket
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A
from defender.tests.integrations.credential_proxy_1163 import _harness as H
from defender.tests.integrations.credential_proxy_1163 import _stream1412 as W
from defender.tests.integrations.credential_proxy_1163 import _tenant as T

BASE = T.BASE_PATH
CAP = 1024
OVERHEAD_SEC = 0.5
DEADLINE_SEC = 1
GAP_SEC = 0.6
Script = Callable[[socket.socket], None]


def _complete(status: int) -> Script:
    return lambda conn: conn.sendall(W.head(status, 12) + b'{"ok": true}')


def _over_declared(status: int) -> Script:
    return lambda conn: conn.sendall(W.head(status, CAP + 1) + b"a" * (CAP + 1))


def _over_undeclared(status: int) -> Script:
    head = (b"HTTP/1.1 %d X\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n" % status)
    return lambda conn: conn.sendall(head + W.chunked(b"a" * CAP, b"a") + b"0\r\n\r\n")


def _compressed(status: int) -> Script:
    packed = gzip.compress(b'{"ok": true}')
    return lambda conn: conn.sendall(W.head(status, len(packed), extra=b"Content-Encoding: gzip\r\n") + packed)


def _broke(status: int) -> Script:
    def script(conn: socket.socket) -> None:
        conn.sendall(W.head(status, 64) + b'{"id": ')
        conn.shutdown(socket.SHUT_WR)
    return script


def _deadline_after(status: int) -> Script:
    def script(conn: socket.socket) -> None:
        conn.sendall(W.head(status, 4096) + b"{")
        for _ in range(100):  # until the proxy hangs up (the send then fails)
            time.sleep(0.1)
            conn.sendall(b" ")
    return script


def _deadline_before(_status: int) -> Script:
    """The status line itself trickles in fragments, each inside the read timeout, and is not
    complete until well past the deadline: no status has arrived when the request is cut."""
    def script(conn: socket.socket) -> None:
        pieces = [b"HT", b"TP", b"/1.1 ", b"200 ", b"OK\r\n"] + [b"X-Slow: %d\r\n" % i for i in range(10)]
        for piece in pieces:
            conn.sendall(piece)
            time.sleep(GAP_SEC)
    return script


def _reader_gone(status: int) -> Script:
    return lambda conn: conn.sendall(W.head(status, W.DEFAULT_LIMIT) + b"x" * W.DEFAULT_LIMIT)


@dataclass(frozen=True)
class Ending:
    """One way an exchange ends. `script(status)` is what the upstream does (None: the upstream is
    never reached); `status_arrives`: the system's status is on the wire before the end;
    `breaks`: the system's body is withheld, broken or cut (no whole body); `how` is the
    non-upstream cause (`ungranted`, `store raises`) or None."""

    name: str
    script: Callable[[int], Script] | None
    status_arrives: bool
    breaks: bool = False
    reader_leaves: bool = False
    how: str | None = None
    cap: int | None = CAP
    timeout: int = 5


ENDINGS = (
    Ending("complete", _complete, True),
    Ending("over-limit-declared", _over_declared, True, breaks=True),
    Ending("over-limit-undeclared", _over_undeclared, True, breaks=True),
    Ending("compressed", _compressed, True, breaks=True),
    Ending("upstream-broke-mid-body", _broke, True, breaks=True),
    Ending("deadline-cut-before-the-status", _deadline_before, False, timeout=DEADLINE_SEC),
    Ending("deadline-cut-after-the-status", _deadline_after, True, breaks=True, timeout=DEADLINE_SEC),
    Ending("reader-gone", _reader_gone, True, reader_leaves=True, cap=None),
    Ending("refused-ungranted", None, False, how="ungranted"),
    Ending("unforeseen-error", None, False, how="store raises"),
)
#: The endings whose reader sees the final frame, and those among them where the status arrived.
SEEN = tuple(e for e in ENDINGS if not e.reader_leaves)
STATUSED = tuple(e for e in SEEN if e.status_arrives)
#: Of those, the ones where the system's body does not reach the run whole.
BROKEN = tuple(e for e in STATUSED if e.breaks)


class HeldAudit(H.AuditRecorder):
    """An audit port that holds each `record` until released."""

    def __init__(self) -> None:
        super().__init__()
        self.entered, self.release = threading.Event(), threading.Event()

    def record(self, entry: Any) -> None:
        self.entered.set()
        self.release.wait(10)
        super().record(entry)


class _ExplodingStore:
    def read(self, tenant_id: str, system: str) -> Any:
        raise RuntimeError("nobody foresaw this")


def audit_of(mode: str) -> Any:
    return {"written": H.AuditRecorder, "held": HeldAudit, "failing": H.FailingAudit}[mode]()


@dataclass
class Exchange:
    """What one run of an ending left: the proxy's whole reply (None when the reader left), the
    bytes that had arrived while a held record was being written, the audit, and the upstream."""

    raw: bytes | None
    before: bytes | None
    audit: Any
    up: W.Scripted | None
    url: str
    tok: str
    target: str
    rig: Any
    exchanged: list[Any]


def _then_clean(first: Script) -> Script:
    seen: list[int] = []
    lock = threading.Lock()

    def script(conn: socket.socket) -> None:
        with lock:
            seen.append(1)
            nth = len(seen)
        if nth == 1:
            first(conn)
        else:
            conn.sendall(W.head(200, 2) + b"{}")
    return script


@contextlib.contextmanager
def served(  # noqa: PLR0913 — one keyword per thing a case varies
           scratch: Path, root: Path, ending: Ending, *, status: int = 200, audit: Any = None,
           oauth: list[str] | None = None, writes: tuple[tuple[str, str], ...] = (),
           grant: str = "r", then_clean: bool = False) -> Iterator[Exchange]:
    """The proxy served over a tenant whose `identity` is the ending's upstream (with an OAuth
    scheme when `oauth` is a list, which collects the issued access tokens), nothing read yet."""
    audit = H.AuditRecorder() if audit is None else audit
    script = None if ending.script is None else ending.script(status)
    script = _then_clean(script) if then_clean and script is not None else script
    with contextlib.ExitStack() as stack:
        up = stack.enter_context(W.scripted(script or _complete(200)))
        scheme = None
        if oauth is not None:
            auth = stack.enter_context(H.upstream())
            auth.replies["/token"] = H.token_endpoint(oauth)
            scheme = H.oauth_scheme(auth.url + "/token")
        creds = T.oauth_set() if oauth is not None else "static"
        r = stack.enter_context(T.rig(scratch / "forge", root, lambda _u: H.declaration(
            up.url + BASE, scheme=scheme, writes=writes), creds=creds))
        exchanged = auth.seen if oauth is not None else []
        kw: dict[str, Any] = {"proxy_overhead_sec": OVERHEAD_SEC}
        if ending.cap is not None:
            kw["max_response_bytes"] = ending.cap
        store = _ExplodingStore() if ending.how == "store raises" else r.store
        url, _tap = stack.enter_context(A.proxy_for(r.t, store, audit=audit, **kw))
        granted = set() if ending.how == "ungranted" else {("identity", grant)}
        path = "/tickets" if writes else "/users/x"
        yield Exchange(None, None, audit, up, url, r.tok(granted), f"{up.url}{BASE}{path}", r,
                       exchanged)


def run(ex: Exchange, ending: Ending, *, hold: bool = False, method: str = "GET") -> Exchange:
    """Send the request as a reader would and read what the ending lets it read: the whole reply
    (`raw`), or for a reader that leaves, one chunk. With `hold`, also what had arrived while the
    audit record was being written."""
    request = W.doc(ex.target, method=method, timeout_sec=ending.timeout)
    arrived = bytearray()
    if ending.reader_leaves:
        with W.unread(ex.url, ex.tok, request) as response:
            next(response.iter_raw(64 * 1024))
        if hold:
            assert ex.audit.entered.wait(10), "no audit record was started"
            ex.audit.release.set()
        W.until(lambda: getattr(ex.audit, "records", None) or getattr(ex.audit, "attempts", 0), 10)
        time.sleep(0.3)  # a second record would land now
        return Exchange(None, None, ex.audit, ex.up, ex.url, ex.tok, ex.target, ex.rig,
                        ex.exchanged)

    def read() -> None:
        with W.unread(ex.url, ex.tok, request) as response:
            for chunk in response.iter_raw():
                arrived.extend(chunk)

    reader = threading.Thread(target=read)
    reader.start()
    before = None
    try:
        if hold:
            assert ex.audit.entered.wait(15), "no audit record was started"
            time.sleep(0.3)  # a final frame sent early lands now
            before = bytes(arrived)
    finally:
        if hold:
            ex.audit.release.set()
        reader.join(30)
    return Exchange(bytes(arrived), before, ex.audit, ex.up, ex.url, ex.tok, ex.target, ex.rig,
                        ex.exchanged)
