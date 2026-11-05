"""#1412 sketch: the proxy streams replies as length-prefixed frames, and nothing is an answer
until the final frame. The format's names in `defender._proxy_client` are working names, imported
at call time: `encode_body`, `encode_final`, `decode_reply` (`.chunks`, `.final`; `ValueError` when
a reply is not exactly body frames then one final frame) and `REPLY_CONTENT_TYPE`."""
from __future__ import annotations

import concurrent.futures
import contextlib
import json
import socket
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from defender._proxy_client import proxy_call
from defender.integrations import identity_adapter
from defender.kit.access import CALLER_GRACE_SEC
from defender.kit.faults import TransportFault
from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A
from defender.tests.integrations.credential_proxy_1163 import _harness as H
from defender.tests.integrations.credential_proxy_1163 import _tenant as T
from defender.tests.integrations.credential_proxy_1163._proxy_process_1412 import GAUGE_PATH
from defender.tests.integrations.credential_proxy_1163._target import PROXY_PATH
from defender.tests.integrations.credential_proxy_1163.test_proxy_faults_proxy_side import _chunked_upstream

BASE = T.BASE_PATH
PATH = f"{BASE}/users/x"
CAP = 1024
MIB = 1024 * 1024
DEFAULT_LIMIT = 8 * MIB
JSON = {"Content-Type": "application/json"}


def _fmt() -> Any:
    """The format's owner, read at call time so its missing names fail one case each."""
    import defender._proxy_client as owner

    return owner


def _final(status: int | None = 200, **over: Any) -> dict[str, Any]:
    return {"status": status, "headers": {}, "fault": None, "detail": None, "system_side": False,
            "body_whole": True} | over


def _doc(target: str, *, method: str = "GET", timeout_sec: float | None = None) -> dict[str, Any]:
    return {"system": "identity", "method": method, "url": target, "headers": {}, "body": None} | (
        {} if timeout_sec is None else {"timeout_sec": timeout_sec})


@contextlib.contextmanager
def _unread(url: str, tok: str, doc: dict[str, Any]) -> Iterator[httpx.Response]:
    """The proxy's response with its head received and its body left unread."""
    with httpx.Client(trust_env=False, timeout=60) as client, client.stream(
            "POST", url + PROXY_PATH, headers={"Authorization": f"Bearer {tok}"}, json=doc) as response:
        yield response


def _raw_post(url: str, tok: str, doc: dict[str, Any]) -> httpx.Response:
    with httpx.Client(trust_env=False, timeout=60) as client:
        return client.post(url + PROXY_PATH, headers={"Authorization": f"Bearer {tok}"}, json=doc)


def _call(url: str, tok: str, target: str, *, method: str = "GET", timeout_sec: int = 5) -> Any:
    return proxy_call(url, tok, system="identity", method=method, url=target, timeout_sec=timeout_sec)


def _until(done: Callable[[], bool], within: float) -> bool:
    limit = time.monotonic() + within
    while time.monotonic() < limit:
        if done():
            return True
        time.sleep(0.02)
    return done()


class _Scripted:
    """A loopback server that reads each request's head, then runs `script(conn)`. `hung_up` is
    set once the peer has closed its side of the connection (a send fails or a read ends)."""

    def __init__(self, script: Callable[[socket.socket], None]) -> None:
        self.hung_up = threading.Event()
        self._script = script
        self._srv = socket.socket()
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(8)
        self.url = f"http://127.0.0.1:{self._srv.getsockname()[1]}"
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        with contextlib.suppress(OSError):
            while True:
                conn, _ = self._srv.accept()
                threading.Thread(target=self._one, args=(conn,), daemon=True).start()

    def _one(self, conn: socket.socket) -> None:
        with conn:
            head = b""
            try:
                while b"\r\n\r\n" not in head:
                    head += conn.recv(65536)
                self._script(conn)
                while conn.recv(65536):  # the request's body, then the peer's close
                    pass
                self.hung_up.set()
            except OSError:
                self.hung_up.set()

    def close(self) -> None:
        self._srv.close()


@contextlib.contextmanager
def _scripted(script: Callable[[socket.socket], None]) -> Iterator[_Scripted]:
    server = _Scripted(script)
    try:
        yield server
    finally:
        server.close()


def _head(status: int, length: int) -> bytes:
    return (b"HTTP/1.1 %d OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n"
            % (status, length))


@contextlib.contextmanager
def _fake_proxy(payload: bytes, *, ended: bool) -> Iterator[str]:
    """A proxy stand-in answering with `payload` in the reply format's content type as one HTTP
    chunk, then either ending the HTTP body (`ended`) or closing with the body unfinished."""
    def script(conn: socket.socket) -> None:
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: %s\r\nTransfer-Encoding: chunked\r\n\r\n"
                     % _fmt().REPLY_CONTENT_TYPE.encode())
        conn.sendall(b"%x\r\n%s\r\n" % (len(payload), payload))
        if ended:
            conn.sendall(b"0\r\n\r\n")
        conn.shutdown(socket.SHUT_WR)

    with _scripted(script) as server:
        yield server.url


# --- main flow ---------------------------------------------------------------------------------

def test_main_a_large_reply_reaches_the_adapter_whole(tmp_path, data_root):
    """A 3 MiB JSON reply comes back through the real adapter, transport and proxy as today's
    parsed answer. O2, O8."""
    document = {"user": "dev.dana", "pad": "x" * (3 * MIB)}
    with T.rig(tmp_path / "forge", data_root) as r, A.proxy_for(r.t, r.store) as (url, _tap):
        r.up.replies[f"{BASE}/users/dev.dana"] = (200, JSON, json.dumps(document).encode())
        ctx = A.ctx_for(tmp_path, T.run_record(r.t), url, r.tok())
        assert identity_adapter.get_user(ctx, user="dev.dana") == document


# --- O1 memory independent of reply size -------------------------------------------------------

class _ProxyProcess:
    def __init__(self, process: subprocess.Popen, url: str) -> None:
        self.process, self.url = process, url

    def gauge(self, query: str = "") -> dict[str, int]:
        with httpx.Client(trust_env=False, timeout=30) as client:
            return client.get(f"{self.url}{GAUGE_PATH}{query}").json()

    def high_water(self) -> int:
        """The process's peak resident memory so far, in bytes; 0 once it is gone."""
        with contextlib.suppress(OSError), open(f"/proc/{self.process.pid}/status") as status:
            for line in status:
                if line.startswith("VmHWM:"):
                    return int(line.split()[1]) * 1024
        return 0


@contextlib.contextmanager
def _proxy_process(data_root: Path, tenant: str, *, trace: bool) -> Iterator[_ProxyProcess]:
    port = H.free_port()
    process = subprocess.Popen(
        [sys.executable, "-m", "defender.tests.integrations.credential_proxy_1163._proxy_process_1412",
         str(data_root), tenant, str(port), "trace" if trace else "plain"])
    running = _ProxyProcess(process, f"http://127.0.0.1:{port}")

    def up() -> bool:
        with contextlib.suppress(httpx.HTTPError):
            return running.gauge()["audited"] == 0
        return False

    try:
        assert _until(up, 30), "the proxy process did not start"
        yield running
    finally:
        process.kill()
        process.wait()


def test_o1_a_stalled_reader_of_an_8_mib_reply_costs_under_2_mib_of_allocations(tmp_path, data_root):
    """The proxy's Python allocation peak above its idle level stays under 2 MiB for one 8 MiB
    reply whose reader stalls, and the reader still gets all of it. O1."""
    body = b"x" * DEFAULT_LIMIT
    with T.rig(tmp_path / "forge", data_root) as r, \
            _proxy_process(data_root, r.t.tenant_id, trace=True) as proxy:
        r.up.replies[f"{BASE}/big"] = (200, JSON, body)
        _raw_post(proxy.url, r.tok(), _doc(f"{r.up.url}{PATH}"))  # lazy imports land before the measure
        idle = proxy.gauge("?reset")["traced_now"]
        with _unread(proxy.url, r.tok(), _doc(f"{r.up.url}{BASE}/big")) as response:
            stream = response.iter_raw(64 * 1024)
            raw = bytearray(next(stream))
            time.sleep(2)
            for chunk in stream:
                raw += chunk
        peak = proxy.gauge()["traced_peak"]

    assert peak - idle < 2 * MIB, f"{(peak - idle) / MIB:.1f} MiB allocated above idle"
    reply = _fmt().decode_reply(bytes(raw))
    assert (reply.final["status"], reply.final["body_whole"]) == (200, True)
    assert b"".join(reply.chunks) == body


def test_o1_forty_8_mib_replies_at_once_keep_the_process_under_256_mib(tmp_path, data_root):
    """40 overlapping 8 MiB replies leave the process's peak resident memory under the container's
    256 MiB. The process is killed as soon as it passes that, so a failure stays cheap. O1."""
    limit = 256 * MIB
    with T.rig(tmp_path / "forge", data_root) as r, \
            _proxy_process(data_root, r.t.tenant_id, trace=False) as proxy:
        r.up.replies[f"{BASE}/big"] = (200, JSON, b"x" * DEFAULT_LIMIT)
        stop, worst = threading.Event(), [0]

        def watch() -> None:
            while not stop.wait(0.02):
                worst[0] = max(worst[0], proxy.high_water())
                if worst[0] >= limit:
                    proxy.process.kill()
                    return

        def read(tok: str) -> int:
            with contextlib.suppress(httpx.HTTPError), \
                    _unread(proxy.url, tok, _doc(f"{r.up.url}{BASE}/big")) as response:
                time.sleep(1)  # every reader holds its exchange open until all 40 have begun
                return sum(len(chunk) for chunk in response.iter_raw(64 * 1024))
            return 0

        watcher = threading.Thread(target=watch, daemon=True)
        watcher.start()
        tokens = [r.tok() for _ in range(40)]
        with concurrent.futures.ThreadPoolExecutor(40) as pool:
            sizes = list(pool.map(read, tokens))
        stop.set()
        watcher.join()
        assert worst[0] < limit, f"peak {worst[0] / MIB:.0f} MiB"
        gauge = proxy.gauge()

    assert gauge["live_peak"] == 40, gauge
    assert gauge["audited"] == 40, gauge
    assert all(size > DEFAULT_LIMIT for size in sizes), sizes


# --- O2 no partial answer ----------------------------------------------------------------------

PARTIAL = b"PARTIAL-BODY-1412"


@pytest.mark.parametrize(("build", "ended"), [
    pytest.param(lambda f: f.encode_body(PARTIAL) + f.encode_body(PARTIAL)[:4], False, id="cut-inside-a-frame"),
    pytest.param(lambda f: f.encode_body(PARTIAL), True, id="ended-with-no-final-frame"),
    pytest.param(lambda f: f.encode_body(PARTIAL) + f.encode_final(_final()) + b"x", True, id="bytes-after-the-final-frame"),
    pytest.param(lambda f: f.encode_body(PARTIAL) + f.encode_final(_final()), False, id="final-frame-then-cut"),
])
def test_o2_a_broken_stream_is_the_proxys_own_fault_with_no_answer(build, ended):
    """A reply that breaks anywhere is `TransportFault`, the proxy's own, saying the reply broke,
    with no partial body even in its detail. O2, and O6 for the final-frame-then-cut row."""
    with _fake_proxy(build(_fmt()), ended=ended) as url, pytest.raises(TransportFault) as raised:
        _call(url, "tok", f"{url}/x")

    assert raised.value.proxy_own is True
    assert "unreachable" not in raised.value.detail
    assert "broke" in raised.value.detail
    assert PARTIAL.decode() not in str(raised.value)


def test_o2_the_same_frames_ended_properly_are_the_answer():
    """Positive control for the broken-stream cases, on the same stand-in. O2."""
    f = _fmt()
    with _fake_proxy(f.encode_body(PARTIAL) + f.encode_final(_final()), ended=True) as url:
        answer = _call(url, "tok", f"{url}/x")

    assert (answer.status, answer.body, answer.fault) == (200, PARTIAL.decode(), None)


def test_o2_a_write_accepted_then_dropped_keeps_its_status_and_no_body(tmp_path, data_root):
    """A 201 whose reply breaks mid-body: the status stands, the bytes already forwarded are not
    returned. O2, O8 (#1404)."""
    with H.breaks_after_status(201) as base, T.rig(
            tmp_path / "forge", data_root,
            lambda _u: H.declaration(base + BASE, writes=(("POST", "/tickets"),))) as r, \
            A.proxy_for(r.t, r.store) as (url, _tap):
        answer = _call(url, r.tok({("identity", "rw")}), f"{base}{BASE}/tickets", method="POST")

    assert (answer.status, answer.fault, answer.body) == (201, "TransportFault", "")
    assert answer.from_system is True


# --- O3 one limit ------------------------------------------------------------------------------

def test_o3_a_body_of_exactly_the_limit_is_complete(tmp_path, data_root):
    """Exactly `max_response_bytes` is whole. O3."""
    with T.rig(tmp_path / "forge", data_root, max_response_bytes=CAP) as r:
        r.up.replies[PATH] = (200, JSON, b"a" * CAP)
        reply = _fmt().decode_reply(r.post().content)

    assert b"".join(reply.chunks) == b"a" * CAP
    assert (reply.final["status"], reply.final["fault"], reply.final["body_whole"]) == (200, None, True)


def test_o3_over_the_limit_forwards_no_byte_past_it_and_says_narrow(tmp_path, data_root):
    """A chunked reply over the limit: nothing past the limit on the wire, status stands,
    `UpstreamFault`, no whole body, a detail that says to narrow the query. O3."""
    with _chunked_upstream([b"a" * 512, b"a" * 512, b"a"]) as base, T.rig(
            tmp_path / "forge", data_root, lambda _u: H.declaration(base + BASE),
            max_response_bytes=CAP) as r:
        reply = _fmt().decode_reply(r.post(url=f"{base}{PATH}").content)

    assert sum(len(chunk) for chunk in reply.chunks) <= CAP
    final = reply.final
    assert (final["status"], final["fault"], final["body_whole"]) == (200, "UpstreamFault", False)
    assert "narrow" in final["detail"]


def test_o3_a_declared_oversize_forwards_nothing_and_stops_at_its_first_byte(tmp_path, data_root):
    """A reply declaring more than the limit: the proxy hangs up on the first body byte (this
    upstream never sends another), forwards nothing, and the fault is the over-limit one. O3."""
    def script(conn: socket.socket) -> None:
        conn.sendall(_head(200, CAP * 2) + b"a")

    with _scripted(script) as up, T.rig(
            tmp_path / "forge", data_root, lambda _u: H.declaration(up.url + BASE),
            max_response_bytes=CAP) as r:
        reply = _fmt().decode_reply(r.post(url=f"{up.url}{PATH}", timeout_sec=5).content)
        hung_up = up.hung_up.wait(2)

    assert reply.chunks == []
    assert (reply.final["status"], reply.final["fault"]) == (200, "UpstreamFault"), reply.final
    assert "narrow" in reply.final["detail"]
    assert hung_up, "the proxy kept the upstream connection after the first body byte"


def test_o3_head_declaring_an_oversize_has_nothing_to_withhold(tmp_path, data_root):
    """HEAD with a `Content-Length` over the limit: status and headers, no fault. O3."""
    with T.rig(tmp_path / "forge", data_root, max_response_bytes=CAP) as r:
        r.up.replies[PATH] = (200, {"Content-Type": "text/plain", "X-Kept": "yes"}, b"a" * (CAP * 2))
        answer = r.ask("HEAD")

    assert (answer["status"], answer["fault"], answer["body"]) == (200, None, "")
    assert answer["headers"]["X-Kept"] == "yes"


# --- O4 the audit rule ---------------------------------------------------------------------------

@pytest.mark.parametrize(("ending", "outcome"), [
    pytest.param("complete", "sent 200", id="complete"),
    pytest.param("over-limit", "sent 200", id="over-limit"),
    pytest.param("refused", "ConfigFault", id="refused"),
])
def test_o4_exactly_one_record_whatever_ended_the_exchange(tmp_path, data_root, ending, outcome):
    """One audit record per request for a complete, over-limit or refused exchange. O4."""
    with T.rig(tmp_path / "forge", data_root, max_response_bytes=CAP) as r:
        r.up.replies[PATH] = (200, JSON, b"a" * (CAP + 1 if ending == "over-limit" else CAP))
        r.ask(**({"grant": set()} if ending == "refused" else {}))

    assert [record["outcome"] for record in r.audit.records] == [outcome]


def test_o4_a_departed_reader_still_leaves_exactly_one_record(tmp_path, data_root):
    """A reader that leaves mid-body: the exchange runs on and writes one record. O4."""
    audit = H.AuditRecorder()
    with T.rig(tmp_path / "forge", data_root) as r, A.proxy_for(r.t, r.store, audit=audit) as (url, _tap):
        r.up.replies[f"{BASE}/big"] = (200, JSON, b"x" * DEFAULT_LIMIT)
        with _unread(url, r.tok(), _doc(f"{r.up.url}{BASE}/big")) as response:
            next(response.iter_raw(64 * 1024))
        assert _until(lambda: audit.records, 10), "no record after the reader left"
        time.sleep(0.3)

    assert [record["outcome"] for record in audit.records] == ["sent 200"]


class _HeldAudit(H.AuditRecorder):
    """An audit port that holds each `record` until released, so a reader can look at what has
    arrived while the record is being written."""

    def __init__(self) -> None:
        super().__init__()
        self.entered, self.release = threading.Event(), threading.Event()

    def record(self, entry: Any) -> None:
        self.entered.set()
        self.release.wait(10)
        super().record(entry)


def test_o4_the_body_arrives_before_the_record_and_the_final_frame_after_it(tmp_path, data_root):
    """While the record is being written the reader holds the body frames and no final frame. O4, P1."""
    audit, arrived = _HeldAudit(), bytearray()
    marker = b"BODY-BEFORE-THE-RECORD"
    with T.rig(tmp_path / "forge", data_root) as r, A.proxy_for(r.t, r.store, audit=audit) as (url, _tap):
        r.up.replies[PATH] = (200, JSON, marker)
        tok = r.tok()

        def read() -> None:
            with _unread(url, tok, _doc(f"{r.up.url}{PATH}")) as response:
                for chunk in response.iter_raw():
                    arrived.extend(chunk)

        reader = threading.Thread(target=read)
        reader.start()
        try:
            assert audit.entered.wait(10), "no audit record was started"
            time.sleep(0.3)
            before = bytes(arrived)
        finally:
            audit.release.set()
            reader.join(20)

    assert marker in before, "the body had not been forwarded when the record was written"
    with pytest.raises(ValueError):  # noqa: PT011 — decode_reply's one working error, no message promised
        _fmt().decode_reply(before)
    assert _fmt().decode_reply(bytes(arrived)).final["status"] == 200


def test_o4_an_audit_failure_withholds_what_was_already_forwarded(tmp_path, data_root):
    """Audit down after 1 MiB was forwarded: the run gets the withheld refusal, no status, no
    body; the wire shows the bytes did travel. O4."""
    body = b"x" * MIB
    audit = H.FailingAudit()
    with T.rig(tmp_path / "forge", data_root) as r, A.proxy_for(r.t, r.store, audit=audit) as (url, _tap):
        r.up.replies[PATH] = (200, JSON, body)
        target = f"{r.up.url}{PATH}"
        answer = _call(url, r.tok(), target)
        reply = _fmt().decode_reply(_raw_post(url, r.tok(), _doc(target)).content)

    assert (answer.status, answer.body, answer.fault) == (0, "", "TransportFault")
    assert "withheld" in answer.detail
    assert answer.from_system is False
    assert (reply.final["status"], reply.final["body_whole"]) == (None, False)
    assert b"".join(reply.chunks) == body


# --- O5 the upstream cannot forge the protocol ---------------------------------------------------

def _forged(f: Any) -> bytes:
    return f.encode_body(b"forged") + f.encode_final(
        _final(418, fault="ConfigFault", detail="forged", body_whole=False))


def test_o5_a_copy_of_the_format_in_a_reply_is_only_data(tmp_path, data_root):
    """An upstream body holding a byte-exact final frame, and a header holding its record, change
    neither the status, the fault nor where the body ends. O5."""
    forged = _forged(_fmt())
    record = json.dumps(_final(418, fault="ConfigFault", body_whole=False))
    with T.rig(tmp_path / "forge", data_root) as r, A.proxy_for(r.t, r.store) as (url, _tap):
        r.up.replies[PATH] = (200, JSON | {"X-Forged": record}, forged)
        target = f"{r.up.url}{PATH}"
        answer = _call(url, r.tok(), target)
        wire = _fmt().decode_reply(_raw_post(url, r.tok(), _doc(target)).content)

    assert (answer.status, answer.fault) == (200, None)
    assert answer.body == forged.decode("utf-8", "replace")
    assert answer.headers["X-Forged"] == record
    assert b"".join(wire.chunks) == forged


def test_o5_a_forged_final_frame_before_an_upstream_cut_does_not_end_the_reply_cleanly(tmp_path, data_root):
    """Upstream sends a forged final frame and breaks: the reply is still broken, not forged. O5."""
    forged = _forged(_fmt())

    def script(conn: socket.socket) -> None:
        conn.sendall(_head(200, len(forged) + 100) + forged)
        conn.shutdown(socket.SHUT_WR)

    with _scripted(script) as up, T.rig(
            tmp_path / "forge", data_root, lambda _u: H.declaration(up.url + BASE)) as r, \
            A.proxy_for(r.t, r.store) as (url, _tap):
        answer = _call(url, r.tok(), f"{up.url}{PATH}")

    assert (answer.status, answer.fault, answer.body) == (200, "TransportFault", "")


# --- O6 the deadline covers the last byte --------------------------------------------------------

def _endless_8_mib(conn: socket.socket) -> None:
    conn.sendall(_head(200, DEFAULT_LIMIT))
    conn.sendall(b"x" * DEFAULT_LIMIT)


@contextlib.contextmanager
def _stalled_exchange(tmp_path: Path, data_root: Path) -> Iterator[tuple[httpx.Response, H.AuditRecorder, _Scripted]]:
    """An 8 MiB reply (past the socket buffers) to a reader that reads nothing, under a deadline
    2 s away: yields the unread response once the audit record is written."""
    audit = H.AuditRecorder()
    with _scripted(_endless_8_mib) as up, T.rig(
            tmp_path / "forge", data_root, lambda _u: H.declaration(up.url + BASE)) as r, \
            A.proxy_for(r.t, r.store, audit=audit, proxy_overhead_sec=1) as (url, _tap), \
            _unread(url, r.tok(), _doc(f"{up.url}{PATH}", timeout_sec=1)) as response:
        assert _until(lambda: audit.records, 3.5), "no record by the deadline"
        yield response, audit, up


def test_o6_a_stalled_reader_is_cut_at_the_deadline_and_keeps_todays_meaning(tmp_path, data_root):
    """Reader stalled past the deadline, back within the grace: upstream released, one record,
    status stands, no whole body, `TransportFault`. O6."""
    with _stalled_exchange(tmp_path, data_root) as (response, audit, up):
        assert up.hung_up.wait(1), "the upstream connection outlived the deadline"
        raw = b"".join(response.iter_raw())

    reply = _fmt().decode_reply(raw)
    assert (reply.final["status"], reply.final["fault"], reply.final["body_whole"]) == (200, "TransportFault", False)
    assert sum(len(chunk) for chunk in reply.chunks) < DEFAULT_LIMIT, "the stall cut nothing"
    assert [record["outcome"] for record in audit.records] == ["sent 200"]


def test_o6_a_reader_stalled_past_the_grace_gets_the_connection_closed_unfinished(tmp_path, data_root):
    """Reader still stalled at `CALLER_GRACE_SEC` past the cut: when it resumes the stream is
    broken, and the audit still says the call was sent. O6."""
    with _stalled_exchange(tmp_path, data_root) as (response, audit, _up):
        time.sleep(CALLER_GRACE_SEC + 1)
        with pytest.raises(httpx.TransportError):
            for _chunk in response.iter_raw():
                pass

    assert [record["outcome"] for record in audit.records] == ["sent 200"]


# --- O7 no scrubbing -----------------------------------------------------------------------------

def test_o7_an_echoed_credential_passes_unaltered_but_never_the_proxys_own_detail(tmp_path, data_root):
    """An upstream's echo of the key reaches the run in body and header; the proxy's own detail
    on a failing reply still holds no credential. O7."""
    echo = H.echo_secret(lambda seen: seen.header("Authorization"))
    bearer = f"Bearer {H.CANARY_KEY}"

    def failing(seen: H.Seen) -> H.Reply:
        _status, headers, body = echo(seen)
        return 500, headers, body

    with T.rig(tmp_path / "forge", data_root) as r:
        r.up.replies[PATH] = echo
        r.up.replies[f"{BASE}/fails"] = failing
        answer = r.ask()
        failed = r.ask(path="/fails")

    assert answer["body"] == f"before-{bearer}-after"
    assert answer["headers"]["X-Echo"] == f"hdr-{bearer}-end"
    assert failed["body"] == f"before-{bearer}-after"
    assert failed["detail"], "positive control: the failing reply has a detail"
    assert H.CANARY_KEY not in failed["detail"]


# --- O8 nothing else changes ---------------------------------------------------------------------

def test_o8_a_small_500_keeps_its_body_and_an_over_limit_500_does_not(tmp_path, data_root):
    """Same status and fault; only `body_whole` tells them apart. O8."""
    with T.rig(tmp_path / "forge", data_root, max_response_bytes=CAP) as r:
        r.up.replies[f"{BASE}/small"] = (500, JSON, b"vendor reason")
        r.up.replies[f"{BASE}/large"] = (500, JSON, b"a" * (CAP + 1))
        small, large = r.ask(path="/small"), r.ask(path="/large")

    assert (small["status"], small["fault"], small["body"], small["body_whole"]) == (
        500, "TransportFault", "vendor reason", True)
    assert (large["status"], large["fault"], large["body"], large["body_whole"]) == (
        500, "TransportFault", "", False)


def test_o8_non_utf8_bytes_travel_raw_and_become_replacement_characters_on_the_run_side(tmp_path, data_root):
    """The wire carries the upstream's bytes; `ProxyAnswer.body` has the replacement. O8."""
    body = b"caf\xe9"
    with T.rig(tmp_path / "forge", data_root) as r, A.proxy_for(r.t, r.store) as (url, _tap):
        r.up.replies[PATH] = (200, {"Content-Type": "text/plain"}, body)
        target = f"{r.up.url}{PATH}"
        answer = _call(url, r.tok(), target)
        wire = _fmt().decode_reply(_raw_post(url, r.tok(), _doc(target)).content)

    assert answer.body == "caf�"
    assert b"".join(wire.chunks) == body


# --- O9 upgrade together -------------------------------------------------------------------------

def test_o9_every_reply_carries_the_formats_content_type(tmp_path, data_root):
    """An answer and a refusal (a final frame alone) both carry the proxy's content type. O9."""
    f = _fmt()
    with T.rig(tmp_path / "forge", data_root) as r:
        answered, refused = r.post(), r.post(grant=set())

    assert answered.headers["content-type"] == f.REPLY_CONTENT_TYPE
    assert refused.headers["content-type"] == f.REPLY_CONTENT_TYPE
    assert f.decode_reply(refused.content).chunks == []


OLD_REPLY = json.dumps({"status": 200, "headers": {}, "body": "old", "fault": None, "detail": None}).encode()


def test_o9_the_run_refuses_any_other_content_type():
    """The old proxy's JSON answer, and framed bytes under another type, are `TransportFault`, the
    proxy's own; the same frames under the right type are the answer. O9."""
    f = _fmt()
    frames = f.encode_body(b"new") + f.encode_final(_final())
    with H.upstream() as fake:
        target = f"{fake.url}/x"
        for reply in ((200, JSON, OLD_REPLY), (200, JSON, frames)):
            fake.replies[PROXY_PATH] = reply
            with pytest.raises(TransportFault) as raised:
                _call(fake.url, "tok", target)
            assert raised.value.proxy_own is True
        fake.replies[PROXY_PATH] = (200, {"Content-Type": f.REPLY_CONTENT_TYPE}, frames)
        assert _call(fake.url, "tok", target).body == "new"
