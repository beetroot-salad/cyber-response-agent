"""#1412, PR review: the proxy waits on a run only so long, stops reading a system for a run that
left, and says whose stall cut a reply; a refusal the headers settle comes at the headers; and the
run judges the proxy's status, media type and final record before believing any of it."""
from __future__ import annotations

import socket
import time

import pytest

from defender.kit import transport
from defender.kit.access import CALLER_GRACE_SEC
from defender.kit.faults import TransportFault
from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A
from defender.tests.integrations.credential_proxy_1163 import _harness as H
from defender.tests.integrations.credential_proxy_1163 import _stream1412 as W
from defender.tests.integrations.credential_proxy_1163 import _tenant as T

API = T.BASE_PATH
#: Far past anything a case waits for, so only the behaviour under test can end it early.
LONG_TIMEOUT_SEC = 20


def _whole_reply_at_once(conn: socket.socket) -> None:
    conn.sendall(W.head(200, W.DEFAULT_LIMIT))
    conn.sendall(b"x" * W.DEFAULT_LIMIT)


def _reply_at_a_walk(conn: socket.socket) -> None:
    """An 8 MiB reply taking about 13 s, far longer than a case waits for the proxy to hang up."""
    conn.sendall(W.head(200, W.DEFAULT_LIMIT))
    for _piece in range(128):
        conn.sendall(b"x" * (64 * 1024))
        time.sleep(0.1)


def test_a_reader_stalled_long_before_the_deadline_frees_the_thread_and_the_system(tmp_path, data_root):
    """A run that stops reading holds a worker thread and the system's connection for
    `CALLER_GRACE_SEC`, not until the deadline. The status stands, nothing counts as a body, and
    the record says the reader was the cause."""
    audit = H.AuditRecorder()
    with W.scripted(_whole_reply_at_once) as up, T.rig(
            tmp_path / "forge", data_root, lambda _u: H.declaration(up.url + API)) as r, \
            A.proxy_for(r.t, r.store, audit=audit) as (url, _tap), \
            W.unread(url, r.tok(), W.doc(f"{up.url}{API}/users/x", timeout_sec=LONG_TIMEOUT_SEC)) as response:
        assert W.until(lambda: W.borrowed(url) == 1, 2), "no worker thread held for the exchange"
        assert W.until(lambda: audit.records, CALLER_GRACE_SEC + 3), "still waiting on the stalled reader"
        assert W.until(lambda: W.borrowed(url) == 0, 2), "the worker thread outlived the stall"
        assert up.hung_up.wait(2), "the system's connection outlived the stall"
        _forwarded, final = W.decoded(b"".join(response.iter_raw()))

    assert (final["status"], final["fault"], final["body_whole"], final["reader_fault"]) == (
        200, "TransportFault", False, True)
    assert [record["outcome"] for record in audit.records] == ["sent 200"]


def test_a_reader_that_left_stops_the_read_of_the_system_and_is_still_audited(tmp_path, data_root):
    """A run gone mid-reply: the proxy hangs up on the system at its next chunk instead of reading
    on for nobody, and the one audit record is still written."""
    audit = H.AuditRecorder()
    with W.scripted(_reply_at_a_walk) as up, T.rig(
            tmp_path / "forge", data_root, lambda _u: H.declaration(up.url + API)) as r, \
            A.proxy_for(r.t, r.store, audit=audit) as (url, _tap):
        with W.unread(url, r.tok(), W.doc(f"{up.url}{API}/users/x", timeout_sec=LONG_TIMEOUT_SEC)) as response:
            next(response.iter_raw(1024))
        assert up.hung_up.wait(4), "the proxy read on for a reader that left"
        assert W.until(lambda: audit.records, 2), "no record after the reader left"

    assert [record["outcome"] for record in audit.records] == ["sent 200"]


def test_a_deadline_cut_while_waiting_on_the_reader_is_the_readers(tmp_path, data_root):
    """Stalled past a deadline shorter than the stall limit: the reader, not the system, is why."""
    with W.scripted(_whole_reply_at_once) as up, T.rig(
            tmp_path / "forge", data_root, lambda _u: H.declaration(up.url + API)) as r, \
            A.proxy_for(r.t, r.store, proxy_overhead_sec=1) as (url, _tap), \
            W.unread(url, r.tok(), W.doc(f"{up.url}{API}/users/x", timeout_sec=1)) as response:
        assert up.hung_up.wait(5), "the system's connection outlived the deadline"
        _forwarded, final = W.decoded(b"".join(response.iter_raw()))

    assert (final["status"], final["fault"], final["reader_fault"]) == (200, "TransportFault", True)


def test_a_deadline_cut_while_waiting_on_the_system_is_still_the_systems(tmp_path, data_root):
    """Positive control for the blame: a keen reader and a system that trickles."""
    with H.breaks_after_status(200, trickle=True) as base, T.rig(
            tmp_path / "forge", data_root, lambda _u: H.declaration(base + API)) as r, \
            A.proxy_for(r.t, r.store, proxy_overhead_sec=1) as (url, _tap):
        answer = W.call(url, r.tok(), f"{base}{API}/users/x", timeout_sec=1)

    assert (answer.status, answer.fault, answer.from_system) == (200, "TransportFault", True)


def _stalled_record(*, reader_fault: bool):
    return W.final_record(fault="TransportFault", detail="a reply was cut", body_whole=False,
                          reader_fault=reader_fault)


def _ask(tmp_path, data_root, url: str, *, write: bool = False):
    with T.rig(tmp_path / "forge", data_root) as r:
        ctx = A.ctx_for(tmp_path, T.run_record(r.t), url, "a-token")
        return transport._proxy_request(ctx, f"{url}/x", system="identity", method="GET", body=None,
                                        timeout_sec=5, write=write)


@pytest.mark.parametrize("reader_fault", [True, False])
def test_a_read_cut_by_the_reader_is_not_blamed_on_the_system(tmp_path, data_root, reader_fault):
    """The fault an adapter raises: the proxy's own when the reader caused it, and only then does
    it stop reading as an HTTP answer from the system."""
    payload = W.fmt().encode_final(_stalled_record(reader_fault=reader_fault))
    with W.fake_proxy(payload, ended=True) as url, pytest.raises(TransportFault) as raised:
        _ask(tmp_path, data_root, url)

    assert raised.value.proxy_own is reader_fault
    # #1363 O4: a reply the run cut is `request`; one the system broke is the system's.
    assert getattr(raised.value, "origin", None) == ("request" if reader_fault else "system")
    assert ("HTTP 200 from identity" in raised.value.detail) is not reader_fault


def test_a_write_the_system_took_stands_though_the_reader_cut_its_reply(tmp_path, data_root):
    """The status alone judges a write (#1412 O8), whoever cut the reply."""
    payload = W.fmt().encode_final(_stalled_record(reader_fault=True))
    with W.fake_proxy(payload, ended=True) as url:
        assert _ask(tmp_path, data_root, url, write=True) == {}


def test_a_reply_declaring_over_the_cap_is_refused_at_its_headers(tmp_path, data_root):
    """A system declaring too much and then silent: `UpstreamFault` saying to narrow the query,
    not a deadline cut saying the reply broke."""
    with W.scripted(lambda conn: conn.sendall(W.head(200, 20 * W.MIB))) as up, T.rig(
            tmp_path / "forge", data_root, lambda _u: H.declaration(up.url + API)) as r, \
            A.proxy_for(r.t, r.store) as (url, _tap):
        began = time.monotonic()
        answer = W.call(url, r.tok(), f"{up.url}{API}/users/x", timeout_sec=LONG_TIMEOUT_SEC)
        took = time.monotonic() - began

    assert answer.fault == "UpstreamFault", answer
    assert "narrow" in answer.detail, answer
    assert took < 3, f"waited {took:.1f} s for a body the headers had already refused"


def _endless_html(conn: socket.socket) -> None:
    """Long enough to tell (a stand-in that truly never ended would hang a failing run for ever)."""
    conn.sendall(W.reply_head("text/html"))
    for _piece in range(120):
        conn.sendall(W.chunked(b"<p>more</p>"))
        time.sleep(0.05)
    conn.shutdown(socket.SHUT_WR)


def test_an_answer_of_another_format_is_refused_at_its_head_not_read_to_its_end():
    """A wrong service streaming for ever: the per-read wait never fires, so the head must decide."""
    with W.scripted(_endless_html) as server:
        began = time.monotonic()
        with pytest.raises(TransportFault) as raised:
            W.call(server.url, "a-token", f"{server.url}/x")
        took = time.monotonic() - began

    assert "format" in raised.value.detail
    assert raised.value.proxy_own
    assert took < 3, f"read for {took:.1f} s after a head that settled it"


def test_a_non_200_keeps_its_status_though_its_body_breaks():
    """A 502 from something in front of the proxy reads as that, whatever its body does."""
    def script(conn: socket.socket) -> None:
        conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 100\r\n\r\nshort")
        conn.shutdown(socket.SHUT_WR)

    with W.scripted(script) as server, pytest.raises(TransportFault) as raised:
        W.call(server.url, "a-token", f"{server.url}/x")

    assert "HTTP 502" in raised.value.detail
    assert raised.value.proxy_own


@pytest.mark.parametrize("over", [
    pytest.param({"status": 200, "body_whole": False}, id="no-fault-and-no-whole-body"),
    pytest.param({"status": None, "body_whole": True}, id="no-fault-and-no-status"),
])
def test_a_final_record_with_no_fault_must_be_a_whole_answer(over):
    """Otherwise it would read as a successful empty answer: data dropped, recorded as no results."""
    payload = W.fmt().encode_body(b'{"hits": 1}') + W.fmt().encode_final(W.final_record(**over))
    with W.fake_proxy(payload, ended=True) as url, pytest.raises(TransportFault) as raised:
        W.call(url, "a-token", f"{url}/x")

    assert "broke" in raised.value.detail
    assert raised.value.proxy_own
