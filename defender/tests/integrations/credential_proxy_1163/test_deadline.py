"""#1163 r7 A21: the system's own timeout travels with the request, the proxy runs the whole
request inside one deadline built from it, and the caller's wait (deadline plus a grace) is the
horizon it was told: it bounds the gap between bytes of the reply, not the whole (#1412 O6)."""
from __future__ import annotations

import contextlib
import json
import socket
import threading
import time
from collections.abc import Callable, Iterator
from pathlib import Path

import httpx
import pytest

from defender.integrations import identity_adapter
from defender.kit.access import CALLER_GRACE_SEC
from defender.kit.faults import TransportFault
from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A
from defender.tests.integrations.credential_proxy_1163 import _harness as H
from defender.tests.integrations.credential_proxy_1163 import _stream1412 as W
from defender.tests.integrations.credential_proxy_1163 import _tenant as T
from defender.tests.integrations.credential_proxy_1163._target import PROXY_PATH, proxy
from defender.tests.tenancy.tenant_1108_p4._support import published_tenant

API = T.BASE_PATH
SLOW_SEC = 3.0


def _slow(reply: H.Reply):
    def answer(_seen):
        time.sleep(SLOW_SEC)
        return reply
    return answer


def _identity_with_timeout(scratch, root, up, timeout: str):
    files = A.system_files("identity", H.declaration(up.url + API),
                           env_extra=f'IDENTITY_TIMEOUT_SEC="{timeout}"\n')
    return published_tenant(scratch, root=root, files=files)


def test_t21_the_systems_timeout_bounds_the_upstream_call(tmp_path, data_root):
    """A system with `TIMEOUT_SEC=1` and a slow upstream gets `TransportFault` after about a
    second, though the proxy's own cap is far longer. r7 A21."""
    with H.upstream() as up, _identity_with_timeout(tmp_path / "forge", data_root, up, "1") as t:
        up.replies[f"{API}/users/dev.dana"] = _slow((200, {}, b"{}"))
        store = H.FakeStore({(t.tenant_id, "identity"): T.static_set()})
        with A.proxy_for(t, store) as (url, _tap):
            ctx = A.ctx_for(tmp_path, T.run_record(t), url, T.token(t.tenant_id, T.GRANT_R))
            began = time.monotonic()
            with pytest.raises(TransportFault):
                identity_adapter.get_user(ctx, user="dev.dana")
            took = time.monotonic() - began

    assert took < SLOW_SEC - 0.5, took


def test_t21_the_proxy_caps_a_longer_timeout_at_its_own(tmp_path, data_root):
    """A request asking more time than the proxy's `upstream_timeout_sec` gets the proxy's cap.
    r7 A21."""
    with T.rig(tmp_path / "forge", data_root, upstream_timeout_sec=1.0) as r:
        r.up.replies[f"{API}/users/x"] = _slow((200, {}, b"{}"))
        began = time.monotonic()
        answer = r.ask(timeout_sec=60)
        took = time.monotonic() - began

    assert answer["fault"] == "TransportFault", answer
    assert took < SLOW_SEC - 0.5, took


@pytest.mark.parametrize("asked", [0, -1, "5", True, 10**9 + 0.5])
def test_t21_a_timeout_that_is_not_a_positive_number_is_refused_unsent(
        tmp_path, data_root, asked):
    """`timeout_sec` must be a positive number; anything else is `ConfigFault`, unsent; a huge
    one is merely capped. r7 A21."""
    with T.rig(tmp_path / "forge", data_root) as r:
        answer = r.ask(timeout_sec=asked)

    if asked == 10**9 + 0.5:
        assert answer["fault"] is None, answer
        assert len(r.up.seen) == 1
    else:
        assert answer["fault"] == "ConfigFault", answer
        assert r.up.seen == []


def test_t21_the_caller_sends_its_timeout_and_waits_out_the_proxys_deadline(
        tmp_path, data_root):
    """The adapter's transport sends the system's `TIMEOUT_SEC` to the proxy and waits longer
    than that timeout for the reply to begin: a proxy answering after it still gets through. r7 A21."""
    f = W.fmt()
    reply = f.encode_body(json.dumps({"user": "dev.dana"}).encode()) + f.encode_final(W.final_record())
    with H.upstream() as up, _identity_with_timeout(tmp_path / "forge", data_root, up, "1") as t, \
            H.upstream() as fake_proxy:
        fake_proxy.replies[PROXY_PATH] = _slow((200, {"Content-Type": f.REPLY_CONTENT_TYPE}, reply))
        ctx = A.ctx_for(tmp_path, T.run_record(t), fake_proxy.url,
                        T.token(t.tenant_id, T.GRANT_R))
        result = identity_adapter.get_user(ctx, user="dev.dana")
        sent = json.loads(fake_proxy.seen[0].body)

    assert result == {"user": "dev.dana"}
    assert sent["timeout_sec"] == 1


def test_t21_the_systems_timeout_bounds_the_token_exchange_too(tmp_path, data_root):
    """A token endpoint slower than the system's timeout gets `TransportFault` after about that timeout, not after the
    proxy's whole deadline: no single wait outlasts the system's timeout, so the caller's wait covers the proxy's. r7 A21."""
    issued: list[str] = []

    def slow_token(seen):
        time.sleep(SLOW_SEC)
        return H.token_endpoint(issued)(seen)

    with H.upstream() as auth:
        auth.replies["/token"] = slow_token
        with T.rig(tmp_path / "forge", data_root, lambda u: H.declaration(
                u + API, scheme=H.oauth_scheme(auth.url + "/token")), creds=T.oauth_set()) as r:
            began = time.monotonic()
            answer = r.ask(timeout_sec=1)
            took = time.monotonic() - began

    assert answer["fault"] == "TransportFault", answer
    assert took < SLOW_SEC - 0.5, took
    assert r.up.seen == []


# --- #1364 O1: the proxy answers every request by its deadline -------------------------------

#: The proxy's own allowance in these tests, and the answer's slack past the deadline (O1).
OVERHEAD_SEC = 0.5
SLACK_SEC = 1.0
#: A reply trickled in pieces this far apart: no single wait reaches the 1 s timeout, but the
#: whole reply takes far longer than any deadline used here.
TRICKLE_GAP_SEC = 0.6
TRICKLE_PIECES = 10


@contextlib.contextmanager
def _trickler(body: bytes = b"{}") -> Iterator[str]:
    """A loopback HTTP server that answers every request 200 with `body`, sending its status
    line, then one header line every `TRICKLE_GAP_SEC`. Yields its base URL."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    stop = threading.Event()

    def one(conn: socket.socket) -> None:
        with conn:
            try:
                conn.recv(65536)
                pieces = [b"HTTP/1.1 200 OK\r\n"] + [b"X-Slow: %d\r\n" % i for i in range(TRICKLE_PIECES)]
                pieces.append(b"Content-Type: application/json\r\nContent-Length: %d\r\n\r\n%s"
                              % (len(body), body))
                for piece in pieces:
                    if stop.wait(TRICKLE_GAP_SEC):
                        return
                    conn.sendall(piece)
            except OSError:
                return

    def serve() -> None:
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            threading.Thread(target=one, args=(conn,), daemon=True).start()

    threading.Thread(target=serve, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{srv.getsockname()[1]}"
    finally:
        stop.set()
        srv.close()


def _on_time(answer: dict, took: float, timeout: float = 1.0) -> None:
    """O1: a `TransportFault` that says the request ran out of time, by deadline + slack."""
    assert answer["fault"] == "TransportFault", answer
    assert "ran out of time" in (answer["detail"] or ""), answer
    assert took < timeout + OVERHEAD_SEC + SLACK_SEC, took


def _timed(ask: Callable[[], dict]) -> tuple[dict, float]:
    began = time.monotonic()
    answer = ask()
    return answer, time.monotonic() - began


def test_o1_an_upstream_trickling_its_reply_is_cut_at_the_deadline(tmp_path, data_root):
    """#1364 O1: an upstream whose reply arrives in pieces, none of them later than the system's
    timeout, is cut at the request's deadline, not held for the whole reply."""
    with _trickler() as slow, T.rig(tmp_path / "forge", data_root, lambda _u: H.declaration(
            slow + API), proxy_overhead_sec=OVERHEAD_SEC) as r:
        answer, took = _timed(lambda: r.ask(url=f"{slow}{API}/users/x", timeout_sec=1))

    _on_time(answer, took)


def test_o1_a_token_endpoint_trickling_its_reply_is_cut_at_the_deadline(tmp_path, data_root):
    """#1364 O1: the OAuth token exchange runs under the same deadline as the upstream call."""
    with _trickler(json.dumps({"access_token": "AT", "expires_in": 3600}).encode()) as slow, \
            T.rig(tmp_path / "forge", data_root, lambda u: H.declaration(
                u + API, scheme=H.oauth_scheme(slow + "/token")), creds=T.oauth_set(),
                proxy_overhead_sec=OVERHEAD_SEC) as r:
        answer, took = _timed(lambda: r.ask(timeout_sec=1))

    _on_time(answer, took)
    assert r.up.seen == []


_KV_REPLY = json.dumps({"data": {"data": {"kind": "static", "fields": {"api_key": H.CANARY_KEY}},
                                 "metadata": {"version": 1}}}).encode()
_VERIFY_REPLY = json.dumps({"data": {"valid": True}}).encode()


@pytest.mark.parametrize("slow_call", ["token verify", "credential read"])
def test_o1_a_slow_openbao_is_cut_at_the_deadline(tmp_path, data_root, slow_call):
    """#1364 O1: the proxy's own OpenBao calls (checking the request token, reading the
    credential set) come under the request's deadline too, so a slow OpenBao cannot hold the
    proxy past the caller's wait."""
    openbao = proxy()
    reply = _VERIFY_REPLY if slow_call == "token verify" else _KV_REPLY
    with _trickler(reply) as slow, T.rig(tmp_path / "forge", data_root) as r:
        store = (openbao.OpenBaoStore(addr=slow, token="t", mount="secret")
                 if slow_call == "credential read" else r.store)
        verifier = (openbao.TransitVerifier(addr=slow, token="t")
                    if slow_call == "token verify" else r.verifier)
        client = T.client_of(T.deps(r.data_root, store, verifier=verifier, audit=r.audit,
                                    proxy_overhead_sec=OVERHEAD_SEC))
        answer, took = _timed(lambda: T.ask(client, r.tok(), "identity", "GET",
                                            f"{r.up.url}{API}/users/x", None, None, 1))

    _on_time(answer, took)
    assert r.up.seen == []


def test_o1_a_request_waiting_on_another_requests_exchange_answers_by_its_own_deadline(
        tmp_path, data_root):
    """#1364 O1: requests for one system take turns at the token exchange. A request queued
    behind a slow exchange answers by its own deadline, not when the other exchange ends."""
    issued: list[str] = []
    exchanging = threading.Event()

    def slow_token(seen):
        exchanging.set()
        time.sleep(2.5)
        return H.token_endpoint(issued)(seen)

    with H.upstream() as auth:
        auth.replies["/token"] = slow_token
        with T.rig(tmp_path / "forge", data_root, lambda u: H.declaration(
                u + API, scheme=H.oauth_scheme(auth.url + "/token")), creds=T.oauth_set(),
                proxy_overhead_sec=OVERHEAD_SEC) as r:
            tok = r.tok()
            first: list[dict] = []
            holder = threading.Thread(target=lambda: first.append(r.ask(tok=tok, timeout_sec=5)))
            holder.start()
            assert exchanging.wait(5)
            answer, took = _timed(lambda: r.ask(tok=tok, timeout_sec=0.3))
            holder.join(10)

    _on_time(answer, took, timeout=0.3)
    assert len(first) == 1, first
    assert first[0]["fault"] is None, first
    assert issued == ["AT-1-canary-1163"], issued


def test_o1_the_caller_waits_out_the_deadline_plus_a_grace_and_no_more():
    """#1364 O1: with the deadline absolute, the caller's wait is the proxy's deadline plus a
    grace longer than the proxy's slack, the grace the final frame's send is bound by (#1412 O6)."""
    from defender.kit import access

    graces = {access.caller_wait_sec(t) - t - access.PROXY_OVERHEAD_SEC for t in (1, 10, 30)}
    assert len(graces) == 1, f"the wait past the deadline grows with the timeout: {graces}"
    grace = graces.pop()
    assert SLACK_SEC < grace <= 10, grace
    assert grace == access.CALLER_GRACE_SEC


def test_o1_openbao_gets_the_proxys_own_allowance_not_the_systems_timeout(tmp_path, data_root):
    """#1364 review: the proxy's OpenBao calls are bounded by the request's deadline, which
    carries the proxy's own allowance; the upstream system's short timeout does not cap them.
    An OpenBao answering in 1.5 s serves a request whose system timeout is 1 s."""
    def slow_kv(_seen):
        time.sleep(1.5)
        return 200, {"Content-Type": "application/json"}, _KV_REPLY

    with H.upstream() as openbao, T.rig(tmp_path / "forge", data_root) as r:
        openbao.replies[f"/v1/secret/data/{r.t.tenant_id}/identity"] = slow_kv
        store = proxy().OpenBaoStore(addr=openbao.url, token="t", mount="secret")
        client = T.client_of(T.deps(r.data_root, store, verifier=r.verifier, audit=r.audit))
        answer = T.ask(client, r.tok(), "identity", "GET", f"{r.up.url}{API}/users/x",
                       None, None, 1)

    assert answer["fault"] is None, answer
    assert len(openbao.seen) == 1
    assert r.up.paths() == [f"{API}/users/x"]


def test_o1_the_deadline_runs_from_when_the_request_arrives(tmp_path, data_root):
    """#1364 review: the proxy's deadline starts when the request reaches it, not when a worker
    thread picks it up after the body is in, so time spent before the proxy starts working
    (queued for a thread, or here a body that arrives late) counts against the proxy's deadline
    as it counts against the caller's wait. A request whose body arrives after the deadline is
    answered as out of time, unsent."""
    with T.rig(tmp_path / "forge", data_root) as r, \
            A.proxy_for(r.t, r.store, proxy_overhead_sec=OVERHEAD_SEC) as (url, _tap):
        body = json.dumps({"system": "identity", "method": "GET",
                           "url": f"{r.up.url}{API}/users/x", "headers": {}, "body": None,
                           "timeout_sec": 1}).encode()
        host, port = url.removeprefix("http://").split(":")
        with socket.create_connection((host, int(port)), timeout=10) as conn:
            conn.sendall(b"POST %s HTTP/1.0\r\nAuthorization: Bearer %s\r\n"  # 1.0: the reply is not chunked
                         b"Content-Type: application/json\r\nContent-Length: %d\r\n\r\n"
                         % (PROXY_PATH.encode(), r.tok().encode(), len(body)))
            time.sleep(1 + OVERHEAD_SEC + 0.3)
            conn.sendall(body)
            raw = b""
            while chunk := conn.recv(65536):
                raw += chunk
        answer = T.answer_of(raw.split(b"\r\n\r\n", 1)[1])

    assert answer["fault"] == "TransportFault", answer
    assert "ran out of time" in (answer["detail"] or ""), answer
    assert r.up.seen == []


@pytest.mark.parametrize("overhead", [0, -1, 20.5, 60])
def test_o1_the_proxys_allowance_cannot_exceed_what_the_caller_waits_for(tmp_path, overhead):
    """#1364 review: the caller's wait assumes the shipped allowance, so a proxy built with more
    (or with none) is refused at construction, not discovered as a caller timing out first."""
    from defender.kit import access
    from defender.kit.faults import ConfigFault

    assert access.PROXY_OVERHEAD_SEC == 20, "the cases above straddle the shipped allowance"
    with pytest.raises(ConfigFault):
        T.deps(tmp_path, H.FakeStore(), proxy_overhead_sec=overhead)
    T.deps(tmp_path, H.FakeStore(), proxy_overhead_sec=access.PROXY_OVERHEAD_SEC)


# --- #1375 O1: no network leg builds a TLS context ----------------------------------------------

def test_1375_o1_a_request_builds_no_tls_context_on_any_leg(tmp_path, data_root):
    """#1375 O1, amended by #1391 O4 (F2): a declaration without `ca` builds no TLS context on any
    request, the first included, on any of its four legs: the token check and the credential read
    at OpenBao, the token exchange and the upstream call (public contexts are built with the app)."""
    import ssl

    from defender.tests.support.tenancy._host1214 import counting_calls

    openbao = proxy()
    issued: list[str] = []
    with H.upstream() as auth, H.upstream() as bao, T.rig(
            tmp_path / "forge", data_root, lambda u: H.declaration(
                u + API, scheme=H.oauth_scheme(auth.url + "/token")), creds=T.oauth_set()) as r:
        auth.replies["/token"] = H.token_endpoint(issued)
        held = T.oauth_set()
        oauth = json.dumps({"data": {"data": {"kind": held.kind, "fields": held.fields},
                                     "metadata": {"version": held.version}}}).encode()
        bao.replies[f"/v1/secret/data/{r.t.tenant_id}/identity"] = (
            200, {"Content-Type": "application/json"}, oauth)
        bao.replies[f"/v1/transit/verify/{openbao.transit_key_for(r.t.tenant_id)}"] = (
            200, {"Content-Type": "application/json"}, _VERIFY_REPLY)
        client = T.client_of(T.deps(
            r.data_root, openbao.OpenBaoStore(addr=bao.url, token="t", mount="secret"),
            verifier=openbao.TransitVerifier(addr=bao.url, token="t"), audit=r.audit))
        # Counted on every thread the request runs on: the TestClient, not entered as a context
        # manager, starts a fresh event-loop thread per request, inside this block. Every route to a
        # context today (httpx's, httpcore's default, `tls_trust`) passes `create_default_context`.
        # `SSLContext.__new__` is every context however built (a new route past `create_default_context`
        # included), as the #1391 O4 build counts read it.
        with counting_calls(context=ssl.create_default_context, built=ssl.SSLContext.__new__) as calls:
            answer = T.ask(client, r.tok(), "identity", "GET", f"{r.up.url}{API}/users/x",
                           None, None, 5)

    assert answer["fault"] is None, answer
    assert (len(bao.seen), len(issued), r.up.paths()) == (2, 1, [f"{API}/users/x"]), \
        "control: every leg ran"
    assert (calls["context"], calls["built"]) == (0, 0), (
        f"a request built {calls['context']} default and {calls['built']} TLS contexts")


def test_1391_o4_a_second_request_under_the_same_ca_builds_no_tls_context(tmp_path, data_root):
    """Contexts are cached by `ca` content: once a request has used a declaration's `ca`, the next
    one builds no TLS context on any route. #1391 O4 (T1: the first one is not pinned)."""
    import ssl

    from defender.tests.support.shared._tls_server import chain, tls_server
    from defender.tests.support.tenancy._host1214 import counting_calls

    pki = chain()
    with tls_server(tmp_path, lambda *_: (200, b"{}"), served=pki.served()) as server:
        url = f"{server.url}{API}/users/x"
        with T.rig(tmp_path / "forge", data_root, lambda _u: H.declaration(
                server.url + API, ca=pki.root.cert)) as r:
            first = r.ask(url=url)
            # SSLContext.__new__ is every route to a context: create_default_context included.
            with counting_calls(context=ssl.SSLContext.__new__) as calls:
                second = r.ask(url=url)

    assert (first["fault"], second["fault"]) == (None, None), (first, second)
    assert len(server.seen) == 2, "control: both requests reached the server"
    assert calls["context"] == 0, f"the second request built {calls['context']} TLS contexts"


def test_1391_o4_a_ca_context_is_built_once_per_distinct_ca_and_never_on_the_event_loop(
        tmp_path, data_root):
    """A declaration's `ca` is built into a context at most once per distinct PEM, on a worker
    thread: a repeat, and a second system with the same PEM, build none; a different PEM builds one.
    #1391 O4, F2."""
    import ssl

    from defender.tests.support.shared._tls_server import chain, tls_server
    from defender.tests.support.tenancy._host1214 import counting_calls

    pki = chain()
    other_pem = pki.root.cert + pki.intermediate.cert
    crm = {("crm", "r")}
    with tls_server(tmp_path, lambda *_: (200, b"{}"), served=pki.served()) as server:
        base = server.url + API
        with T.rig(tmp_path / "forge", data_root, lambda _u: H.declaration(
                base, ca=pki.root.cert)) as r:
            r.store.sets[(r.t.tenant_id, "crm")] = T.static_set()
            r.t.merge(H.access_files("crm", H.declaration(base, ca=pki.root.cert),
                                     env=H.http_proxy_env("crm")), "a second system, same ca")
            r.t.publish()
            built = []
            for system, grant in (("identity", None), ("identity", None), ("crm", crm)):
                with counting_calls(context=ssl.SSLContext.__new__) as calls:
                    answer = r.ask(system=system, grant=grant, url=f"{base}/users/x")
                assert answer["fault"] is None, answer
                built.append(calls["context"])
                on_loop = calls.on_loop["context"]
                assert not any(on_loop), f"{system}: a context was built on the event loop"
            r.t.merge({H.ACCESS_FILE.format(system="identity"): H.declaration(
                base, ca=other_pem)}, "another ca text")
            r.t.publish()
            with counting_calls(context=ssl.SSLContext.__new__) as calls:
                answer = r.ask(url=f"{base}/users/x")
            assert answer["fault"] is None, answer
            assert not any(calls.on_loop["context"]), "a context was built on the event loop"

    assert built == [1, 0, 0], "first use builds one; a repeat and a same-PEM system build none"
    assert calls["context"] == 1, f"a different PEM built {calls['context']} contexts"


TENANT_1384 = "11111111-1111-4111-8111-111111111111"


def test_1384_the_secret_writers_async_calls_go_through_its_injected_transport():
    """#1384: an `OpenBaoSecrets` built with a test transport serves its write and its
    existence check from that transport, not by dialing `addr`. The address is one nothing
    listens on, so a call that ignores the transport fails instead of being answered."""
    import asyncio

    import httpx

    seen: list[tuple[str, str]] = []

    def answer(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, request.url.path))
        if request.method == "POST":
            return httpx.Response(200, json={"data": {"version": 1}})
        return httpx.Response(200, json={"data": {"current_version": 1, "versions": {"1": {}}}})

    secrets = proxy().OpenBaoSecrets(addr="http://127.0.0.1:1", token="t", mount="secret",
                                     transport=httpx.MockTransport(answer))

    async def both() -> bool:
        await secrets.put_credentials(TENANT_1384, "identity", "static", {"api_key": "k"})
        return await secrets.has_credentials(TENANT_1384, "identity")

    assert asyncio.run(both()) is True
    assert [method for method, _ in seen] == ["POST", "GET"], seen


@pytest.mark.parametrize("leg", ["system call", "token endpoint", "openbao token verify",
                                 "openbao credential read"])
def test_1404_a_deadline_cut_is_the_systems_only_on_the_systems_own_call(tmp_path, data_root, leg):
    """#1404 P1: the deadline cutting the target system's call marks the refusal system-side;
    cutting one of the proxy's own legs (the token exchange, its OpenBao calls) leaves it the
    proxy's. Each leg is the one the O1 tests above cut."""
    if leg == "system call":
        with _trickler() as slow, T.rig(tmp_path / "forge", data_root, lambda _u: H.declaration(
                slow + API), proxy_overhead_sec=OVERHEAD_SEC) as r:
            answer, took = _timed(lambda: r.ask(url=f"{slow}{API}/users/x", timeout_sec=1))
    elif leg == "token endpoint":
        with _trickler(json.dumps({"access_token": "AT", "expires_in": 3600}).encode()) as slow, \
                T.rig(tmp_path / "forge", data_root, lambda u: H.declaration(
                    u + API, scheme=H.oauth_scheme(slow + "/token")), creds=T.oauth_set(),
                    proxy_overhead_sec=OVERHEAD_SEC) as r:
            answer, took = _timed(lambda: r.ask(timeout_sec=1))
    else:
        openbao = proxy()
        reading = leg == "openbao credential read"
        with _trickler(_KV_REPLY if reading else _VERIFY_REPLY) as slow, \
                T.rig(tmp_path / "forge", data_root) as r:
            store = openbao.OpenBaoStore(addr=slow, token="t", mount="secret") if reading else r.store
            verifier = r.verifier if reading else openbao.TransitVerifier(addr=slow, token="t")
            client = T.client_of(T.deps(r.data_root, store, verifier=verifier, audit=r.audit,
                                        proxy_overhead_sec=OVERHEAD_SEC))
            answer, took = _timed(lambda: T.ask(client, r.tok(), "identity", "GET",
                                                f"{r.up.url}{API}/users/x", None, None, 1))
    _on_time(answer, took)
    assert "during" in answer["detail"], ("positive control: the leg itself was cut", answer)
    assert answer["system_side"] is (leg == "system call"), (leg, answer)


# --- #1412 O6: the deadline covers the last byte ----------------------------------------------

def test_o6_a_deadline_cut_after_the_system_answered_keeps_its_status_and_blames_it(
        tmp_path, data_root):
    """The system's 200 and then a body trickling past the deadline: the status stands, no body,
    `TransportFault`, the system's through its status with `system_side` unset. #1412 O6, #1404."""
    with H.breaks_after_status(200, trickle=True) as base, T.rig(
            tmp_path / "forge", data_root, lambda _u: H.declaration(base + API)) as r, \
            A.proxy_for(r.t, r.store, proxy_overhead_sec=OVERHEAD_SEC) as (url, _tap):
        answer = W.call(url, r.tok(), f"{base}{API}/users/x", timeout_sec=1)

    assert (answer.status, answer.fault, answer.body) == (200, "TransportFault", "")
    assert (answer.from_system, answer.system_side) == (True, False)


def _endless_8_mib(conn: socket.socket) -> None:
    conn.sendall(W.head(200, W.DEFAULT_LIMIT))
    conn.sendall(b"x" * W.DEFAULT_LIMIT)


@contextlib.contextmanager
def _stalled_exchange(tmp_path: Path, data_root: Path) -> Iterator[tuple[httpx.Response, H.AuditRecorder, W.Scripted]]:
    """An 8 MiB reply (past the socket buffers) to a reader that reads nothing, under a deadline
    2 s away: yields the unread response once the audit record is written. One worker thread is
    lent out while the exchange is stalled and none once the record is written, final send pending."""
    audit = H.AuditRecorder()
    with W.scripted(_endless_8_mib) as up, T.rig(
            tmp_path / "forge", data_root, lambda _u: H.declaration(up.url + API)) as r, \
            A.proxy_for(r.t, r.store, audit=audit, proxy_overhead_sec=1) as (url, _tap), \
            W.unread(url, r.tok(), W.doc(f"{up.url}{API}/users/x", timeout_sec=1)) as response:
        assert W.until(lambda: W.borrowed(url) == 1, 1.5), "no worker thread held for the exchange"
        assert W.until(lambda: audit.records, 3.5), "no record by the deadline"
        assert W.until(lambda: W.borrowed(url) == 0, 5), "the worker thread is held while the final frame is sent"
        yield response, audit, up


def test_o6_a_reader_stalled_past_the_deadline_is_cut_and_gets_todays_answer_within_the_grace(
        tmp_path, data_root):
    """A reader stalled past the deadline, back one second inside the grace: the upstream was
    released at the cut, one record says sent, the reply is the status, no whole body. #1412 O6."""
    with _stalled_exchange(tmp_path, data_root) as (response, audit, up):
        assert up.hung_up.wait(5), "the upstream connection outlived the deadline"
        time.sleep(CALLER_GRACE_SEC - 1)
        forwarded, final = W.decoded(b"".join(response.iter_raw()))

    assert (final["status"], final["fault"], final["body_whole"], final["system_side"]) == (
        200, "TransportFault", False, False)
    assert len(forwarded) < W.DEFAULT_LIMIT, "the stall cut nothing"
    assert [record["outcome"] for record in audit.records] == ["sent 200"]


def test_o6_a_reader_stalled_past_the_grace_gets_the_connection_closed_unfinished(
        tmp_path, data_root):
    """A reader still stalled `CALLER_GRACE_SEC` after the cut sees a broken stream when it
    resumes, and the audit still says the call was sent. #1412 O6."""
    with _stalled_exchange(tmp_path, data_root) as (response, audit, _up):
        time.sleep(CALLER_GRACE_SEC + 1)
        with pytest.raises(httpx.RemoteProtocolError):
            for _chunk in response.iter_raw():
                pass

    assert [record["outcome"] for record in audit.records] == ["sent 200"]
