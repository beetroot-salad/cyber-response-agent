"""#1163 run side, adapter and ticket writer: a refusal or failure never carries the request
token, the proxy address is the run's alone, and an `http-proxy` system with no token is never
reached any other way."""
from __future__ import annotations

import json
import logging
import socket
import time
from datetime import timedelta

import httpx
import pytest

from defender.integrations import _stub_transport as transport
from defender.integrations import identity_adapter
from defender.kit.faults import AdapterFault, ConfigFault, TransportFault
from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A
from defender.tests.integrations.credential_proxy_1163 import _harness as H
from defender.tests.integrations.credential_proxy_1163 import _stream1412 as W
from defender.tests.integrations.credential_proxy_1163 import _tenant as T
from defender.tests.integrations.credential_proxy_1163 import test_query_flow as Q
from defender.tests.integrations.credential_proxy_1163 import test_ticket_flow as K
from defender.tests.integrations.credential_proxy_1163._target import PROXY_PATH, transport_uses_proxy
from defender.tests.tenancy.tenant_1107_settings import _spec1107 as S
from defender.tests.tenancy.tenant_1108_p4.test_r6_issuer import tls_issuer  # noqa: F401 — fixture

GRANT = {("identity", "r")}
EXPIRED = timedelta(minutes=-1)

#: kind -> (token lifetime, proxy verdict on signatures, proxy reachable): the three refusals
#: whose text must not carry the token.
KINDS = {"proxy-down": (timedelta(hours=1), True, False),
         "expired": (EXPIRED, True, True),
         "bad-signature": (timedelta(hours=1), False, True)}


def _carries(text: str, tok: str) -> bool:
    return tok in text or tok.rpartition(".")[2] in text


@pytest.mark.parametrize("kind", KINDS)
def test_x1_a_refused_query_shows_neither_the_token_nor_its_signature(
        tmp_path, data_root, caplog, kind):
    """Proxy down, expired token and a bad signature each raise a fault, and the answer, the
    fault text, the log and the audit record carry neither the token nor its signature. O4, O7."""
    caplog.set_level(logging.DEBUG)
    lifetime, verdict, reachable = KINDS[kind]
    with H.upstream() as up, Q._published(tmp_path, data_root, up) as t:
        tok = T.token(t.tenant_id, GRANT, signer=A.MarkedSigner(), expires_in=lifetime)
        audit = H.AuditRecorder()
        with A.proxy_for(t, Q._store(t), verifier=H.FakeVerifier(verdict), audit=audit) as (
                url, tap):
            address = url if reachable else f"http://127.0.0.1:{H.free_port()}"
            ctx = A.ctx_for(tmp_path, T.run_record(t), address, tok)
            with pytest.raises(AdapterFault) as raised:
                identity_adapter.get_user(ctx, user="dev.dana")
            body = {"system": "identity", "method": "GET",
                    "url": f"{up.url}{Q.API}/users/dev.dana", "headers": {}, "body": None}
            direct = httpx.post(url + PROXY_PATH, headers={"Authorization": f"Bearer {tok}"},
                                json=body).content if reachable else b""

    assert type(raised.value) is (ConfigFault if reachable else TransportFault), raised.value
    assert str(raised.value).strip(), "positive control: the fault has a text"
    if reachable:
        assert tap.tokens == [tok, tok], "positive control: the proxy was sent the token"
        refusal = T.answer_of(direct)
        assert refusal["fault"] == "ConfigFault", refusal
        assert refusal["detail"].strip(), "positive control: the answer has a detail"
    assert up.seen == []
    for text in (str(raised.value), repr(raised.value), direct.decode("latin-1"), caplog.text,
                 repr(audit.records)):
        assert not _carries(text, tok), "the request token or its signature shows in a text"


@pytest.mark.parametrize("kind", KINDS)
def test_x2_a_refused_ticket_leg_leaves_a_receipt_without_the_token_or_its_signature(
        tmp_path, data_root, caplog, kind):
    """The same three refusals at the record leg: an error receipt and logs that carry
    neither the token nor its signature. O4, O7."""
    caplog.set_level(logging.DEBUG)
    lifetime, verdict, reachable = KINDS[kind]
    with H.upstream() as up, K._published(tmp_path / "forge", data_root, K._decl(up)) as t:
        tok = T.token(t.tenant_id, {(K.SYSTEM, "rw")}, signer=A.MarkedSigner(),
                      expires_in=lifetime)
        store = H.FakeStore({(t.tenant_id, K.SYSTEM): T.static_set()})
        rec, run = K._run(tmp_path)
        with A.proxy_for(t, store, verifier=H.FakeVerifier(verdict)) as (url, tap):
            address = url if reachable else f"http://127.0.0.1:{H.free_port()}"
            receipt = K._leg(t, run, rec, address, tok)

    assert receipt is not None, receipt
    assert receipt["ok"] is False, receipt
    assert (receipt.get("reason") or "").strip(), "positive control: the receipt says why"
    assert (tap.tokens != []) is reachable, "positive control: the proxy was asked or not"
    assert up.seen == []
    for text in (json.dumps(receipt), caplog.text, H.text_under(rec.run_dir_at.parent)):
        assert not _carries(text, tok), "the request token or its signature shows in a text"


def test_x3_the_ticket_writer_takes_the_proxy_address_from_the_run_not_the_environment(
        tmp_path, data_root):
    """An address in the writer's `env` is not used when the run handed none; the one the run
    handed in is. A9."""
    from defender.box import run_env
    from defender.tests.tenancy.tenant_1108_p4._support import DEFENDER

    shim = S.DockerShim(tmp_path / "shim")
    with H.upstream() as up, K._published(tmp_path / "forge", data_root, K._decl(up)) as t:
        up.replies[K.COMMENT] = (201, {}, json.dumps({"id": 1}).encode())
        store = H.FakeStore({(t.tenant_id, K.SYSTEM): T.static_set()})
        tok = T.token(t.tenant_id, {(K.SYSTEM, "rw")})
        with A.proxy_for(t, store) as (url, tap):
            rec, run = K._run(tmp_path / "env-only")
            env = shim.env(run_env(DEFENDER, rec.run_dir_at), **{A.DECOY_PROXY_ENV: url})
            S.ticket_writer().record_case_ticket(run, tenant=T.run_record(t), defender_dir=DEFENDER,
                                                 env=env, request_token=tok, proxy_url=None)
            env_only = S.receipt(rec.run_dir_at)
            reached_by_env = list(tap.tokens)
            control_rec, control_run = K._run(tmp_path / "via-run")
            control = K._leg(t, control_run, control_rec, url, tok)

    assert reached_by_env == [], "the writer reached the proxy through the environment's address"
    assert env_only is not None, env_only
    assert env_only["ok"] is False, env_only
    assert control is not None, control
    assert control["ok"] is True, control
    assert tap.tokens, "positive control: the proxy is reachable at that address"
    assert shim.calls() == []


def test_x4_an_http_proxy_system_with_no_token_is_refused_as_a_proxy_fault_and_never_reaches_docker(
        tmp_path, data_root):
    """No request token on the context: the query raises a fault naming the proxy, nothing is
    sent, and docker is never called. A6, A9."""
    shim = S.DockerShim(tmp_path / "shim")
    with (H.upstream() as up, Q._published(tmp_path, data_root, up) as t,
          A.proxy_for(t, Q._store(t)) as (url, tap)):
        record = T.run_record(t)
        tokenless = A.ctx_for(tmp_path, record, url, None, env=shim.env({}))
        with pytest.raises(AdapterFault) as raised:
            identity_adapter.get_user(tokenless, user="dev.dana")
        addressless = A.ctx_for(tmp_path, record, None, T.token(t.tenant_id, GRANT),
                                env=shim.env({}))
        with pytest.raises(AdapterFault) as no_address:
            identity_adapter.get_user(addressless, user="dev.dana")
        control = A.ctx_for(tmp_path, record, url, T.token(t.tenant_id, GRANT),
                            env=shim.env({}))
        assert identity_adapter.get_user(control, user="dev.dana")["path"]

    for fault in (raised.value, no_address.value):
        assert "proxy" in str(fault).lower(), fault
    assert shim.calls() == [], "docker was reached for an http-proxy system"
    assert len(up.seen) == 1, "only the control call was sent"


def test_x5_the_docker_transport_refuses_an_http_proxy_system(tmp_path, data_root):
    """The docker access check names an `http-proxy` system as not its own and gives it no
    default context. A5, A6."""
    with H.upstream() as up, Q._published(tmp_path, data_root, up) as t:
        record = T.run_record(t)
        with pytest.raises(ConfigFault):
            transport.record_access_context(record, "identity")
        assert transport_uses_proxy(record, "identity"), "positive control: it is http-proxy"


class _BlipThenToken:
    """A run's read-token source whose OpenBao is down for the first ask (r7 A20, A18)."""

    def __init__(self, token: str) -> None:
        self.token, self.asked = token, 0

    def __call__(self) -> str:
        self.asked += 1
        if self.asked == 1:
            raise TransportFault("OpenBao is unreachable for signing (ConnectError)")
        return self.token


def test_x9_a_read_token_that_cannot_be_minted_is_the_calls_transport_fault(
        tmp_path, data_root):
    """The read token is minted inside the adapter's call (r7 A20): OpenBao down at that moment
    is the call's `TransportFault` (the system is not marked down) and nothing reaches the
    proxy; the next call mints and is served."""
    with H.upstream() as up, Q._published(tmp_path, data_root, up) as t:
        source = _BlipThenToken(T.token(t.tenant_id, GRANT))
        with A.proxy_for(t, Q._store(t)) as (url, tap):
            ctx = A.ctx_for(tmp_path, T.run_record(t), url, None, token_source=source)
            with pytest.raises(TransportFault):
                identity_adapter.get_user(ctx, user="dev.dana")
            assert tap.tokens == [], "a call without a token reached the proxy"
            served = identity_adapter.get_user(ctx, user="dev.dana")

    assert source.asked == 2
    assert served["path"].endswith("/users/dev.dana")
    assert len(up.seen) == 1


def test_the_run_reaches_the_proxy_directly_never_through_a_web_proxy_from_the_environment(tls_issuer, monkeypatch):  # noqa: F811
    """A run's request (and its bearer token) goes straight to the proxy address it was handed, even when the
    environment names a web proxy (P-1: the token reaches no third party). The stand-in's reply is not the
    proxy's format, so the call is refused as the proxy's own (#1412 O9)."""
    from defender import _proxy_client
    port, got, folder = tls_issuer
    monkeypatch.delenv("SSL_CERT_DIR", raising=False)
    monkeypatch.setenv("SSL_CERT_FILE", str(folder / "server.pem"))
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
        monkeypatch.setenv(name, "http://127.0.0.1:9")
    _proxy_client._client.cache_clear()  # noqa: SLF001 — the pooled client reads trust once per process
    try:
        with pytest.raises(TransportFault) as refused:
            _proxy_client.proxy_call(f"https://localhost:{port}", "tok", system="identity", method="GET",
                                     url="https://idp.example/users")
    finally:
        _proxy_client._client.cache_clear()  # noqa: SLF001
    assert got, "the request reached the proxy address itself"
    assert json.loads(got[0])["system"] == "identity"
    assert refused.value.proxy_own is True


def test_x7_a_fault_is_the_proxys_own_only_when_the_system_neither_answered_nor_was_seen_failing(
        tmp_path, data_root):
    """#1404 P1, on the read path: the system answering 401 through a healthy proxy is the
    system's (`proxy_own` false); the proxy refusing an expired token, with no system status, is
    the proxy's; a token source that cannot mint, before the proxy is asked, is the proxy's too."""
    def cannot_mint() -> str:
        raise TransportFault("the token source could not mint a request token")

    with H.upstream() as up, Q._published(tmp_path, data_root, up) as t:
        up.replies[f"{Q.API}/users/dev.dana"] = (401, {}, b'{"detail": "who are you"}')
        live = T.token(t.tenant_id, GRANT)
        expired = T.token(t.tenant_id, GRANT, expires_in=EXPIRED)
        seen = {}
        with A.proxy_for(t, Q._store(t)) as (url, tap):
            for name, kw in {"system-401": {"token": live},
                             "proxy-refuses": {"token": expired},
                             "no-token-minted": {"token": None, "token_source": cannot_mint}}.items():
                token = kw.pop("token")
                ctx = A.ctx_for(tmp_path / name, T.run_record(t), url, token, **kw)
                with pytest.raises(AdapterFault) as raised:
                    identity_adapter.get_user(ctx, user="dev.dana")
                seen[name] = raised.value
    assert [s.path.split("?")[0] for s in up.seen] == [f"{Q.API}/users/dev.dana"], (
        "positive control: only the live token's call reached the system")
    assert tap.tokens == [live, expired], "the minting failure still asked the proxy"
    assert seen["system-401"].proxy_own is False, seen["system-401"]
    assert seen["proxy-refuses"].proxy_own is True, seen["proxy-refuses"]
    assert seen["no-token-minted"].proxy_own is True, seen["no-token-minted"]
    assert isinstance(seen["no-token-minted"], TransportFault), seen["no-token-minted"]


def test_x8_a_system_answer_the_proxy_could_not_hand_on_keeps_the_proxys_reason(
        tmp_path, data_root):
    """#1404 follow-up, read path: a status that arrived with no body to hand on (the reply broke
    after its status; a body withheld as too large) is the system's (`proxy_own` false) and the
    fault's detail is the proxy's reason, not an empty vendor body ("{}")."""
    import types

    seen = {}
    with H.breaks_after_status(200) as base, Q._published(
            tmp_path, data_root, types.SimpleNamespace(url=base)) as t:
        tok = T.token(t.tenant_id, GRANT)
        with A.proxy_for(t, Q._store(t)) as (url, _tap):
            with pytest.raises(AdapterFault) as raised:
                identity_adapter.get_user(A.ctx_for(tmp_path / "broke", T.run_record(t), url, tok),
                                          user="dev.dana")
            seen["broke"] = raised.value
    with H.upstream() as up, Q._published(tmp_path / "big", data_root, up) as t:
        tok = T.token(t.tenant_id, GRANT)
        with A.proxy_for(t, Q._store(t), max_response_bytes=8) as (url, _tap):
            with pytest.raises(AdapterFault) as raised:
                identity_adapter.get_user(A.ctx_for(tmp_path / "big", T.run_record(t), url, tok),
                                          user="dev.dana")
            seen["withheld"] = raised.value
        assert up.seen, "positive control: the system was asked"
    for name, why in (("broke", "did not arrive whole"), ("withheld", "more than 8 bytes")):
        fault = seen[name]
        assert fault.proxy_own is False, (name, fault)
        assert why in fault.detail, (name, fault.detail)
        assert not fault.detail.endswith("{}"), (name, fault.detail)
    assert "narrow" in seen["withheld"].detail, "a 2xx too large for the limit says to narrow it (#1412 O3)"
    assert "narrow" not in seen["broke"].detail


# --- #1412 the run reads the proxy's framed reply whole, then decodes it once ------------------

PARTIAL = b"PARTIAL-BODY-1412"


def _reply(body: bytes = PARTIAL, **over) -> bytes:
    f = W.fmt()
    return f.encode_body(body) + f.encode_final(W.final_record(**over))


def _refused_as_broken(payload: bytes, *, ended: bool) -> None:
    with W.fake_proxy(payload, ended=ended) as url, pytest.raises(TransportFault) as raised:
        W.call(url, "tok", f"{url}/x")

    assert raised.value.proxy_own is True
    assert "unreachable" not in raised.value.detail
    assert "broke" in raised.value.detail
    assert PARTIAL.decode() not in str(raised.value)


@pytest.mark.parametrize(("build", "ended"), [
    pytest.param(lambda f: f.encode_body(PARTIAL) + f.encode_body(PARTIAL)[:4], False, id="cut-inside-a-frame"),
    pytest.param(lambda f: f.encode_body(PARTIAL), True, id="ended-with-no-final-frame"),
    pytest.param(lambda f: f.encode_body(PARTIAL), False, id="cut-between-frames"),
    pytest.param(lambda f: f.encode_body(PARTIAL) + f.encode_final(W.final_record()) + b"x", True,
                 id="bytes-after-the-final-frame"),
    pytest.param(lambda f: f.encode_body(PARTIAL) + f.encode_final(W.final_record()) * 2, True,
                 id="two-final-frames"),
    pytest.param(lambda f: f.encode_final(W.final_record()) + f.encode_body(PARTIAL), True,
                 id="a-body-frame-after-the-final"),
    pytest.param(lambda f: f.encode_body(PARTIAL) + f.encode_final(W.final_record()), False,
                 id="final-frame-then-cut"),
])
def test_o2_a_broken_stream_is_the_proxys_own_fault_with_no_answer(build, ended):
    """A reply that breaks anywhere is `TransportFault`, the proxy's own, saying it broke, with no
    partial body even in its detail. O2."""
    _refused_as_broken(build(W.fmt()), ended=ended)


def test_o2_a_reply_cut_at_every_byte_is_refused_and_the_whole_reply_is_the_answer():
    """Cut at each byte of a complete reply, whether or not HTTP ends cleanly there, is
    `TransportFault`; the uncut reply on the same stand-in is the answer. O2."""
    whole = _reply()
    with W.fake_proxy(whole, ended=True) as url:
        answer = W.call(url, "tok", f"{url}/x")
    assert (answer.status, answer.body, answer.fault) == (200, PARTIAL.decode(), None)
    for cut in range(len(whole)):
        for ended in (True, False):
            _refused_as_broken(whole[:cut], ended=ended)


def test_o2_a_proxy_that_closes_before_its_head_is_unreachable_not_broken():
    """No response head at all keeps today's wording, reached by the close and not by a timeout. O2."""
    started = time.monotonic()
    with W.scripted(lambda conn: conn.shutdown(socket.SHUT_RDWR)) as proxy, \
            pytest.raises(TransportFault) as raised:
        W.call(proxy.url, "tok", f"{proxy.url}/x")

    assert time.monotonic() - started < 10, "the close was not what ended the wait"
    assert raised.value.proxy_own is True
    assert "unreachable" in raised.value.detail


def test_o2_a_proxy_that_goes_silent_after_its_head_is_broken_not_unreachable():
    """Head received, then nothing until the caller's wait runs out (about 26 s): "broke". O2."""
    with W.scripted(lambda conn: conn.sendall(W.reply_head())) as proxy, \
            pytest.raises(TransportFault) as raised:
        W.call(proxy.url, "tok", f"{proxy.url}/x", timeout_sec=1)

    assert raised.value.proxy_own is True
    assert "broke" in raised.value.detail
    assert "unreachable" not in raised.value.detail


def test_o3_the_run_adds_no_limit_to_a_reply_of_exactly_the_proxys_limit():
    """A whole body of exactly 8 MiB, the proxy's default limit, is the answer. O3."""
    body = b"x" * W.DEFAULT_LIMIT
    f = W.fmt()
    with W.fake_proxy(f.encode_body(body) + f.encode_final(W.final_record()), ended=True) as url:
        answer = W.call(url, "tok", f"{url}/x")

    assert (answer.status, answer.fault, len(answer.body)) == (200, None, W.DEFAULT_LIMIT)


def test_o3_the_run_adds_no_limit_to_a_reply_well_over_the_default():
    """The proxy's limit is configurable, so the run must not assume 8 MiB: a 12 MiB whole body
    is the answer. O3."""
    size = 12 * W.MIB
    f = W.fmt()
    with W.fake_proxy(f.encode_body(b"x" * size) + f.encode_final(W.final_record()), ended=True) as url:
        answer = W.call(url, "tok", f"{url}/x")

    assert (answer.status, answer.fault, len(answer.body)) == (200, None, size)


@pytest.mark.parametrize(("over", "kept"), [
    pytest.param({}, True, id="whole"),
    pytest.param({"status": 500, "fault": "TransportFault", "detail": "d", "body_whole": False}, False,
                 id="not-whole"),
    pytest.param({"status": None, "fault": "TransportFault", "detail": "withheld", "body_whole": False}, False,
                 id="refused"),
])
def test_o2_body_bytes_reach_the_caller_only_when_the_final_record_says_they_count(over, kept):
    """Body frames followed by a record that does not call the body whole leave the answer's body
    empty, with the record's status, fault and detail. O2."""
    with W.fake_proxy(_reply(**over), ended=True) as url:
        answer = W.call(url, "tok", f"{url}/x")

    assert answer.body == (PARTIAL.decode() if kept else "")
    assert (answer.status, answer.fault, answer.detail) == (
        over.get("status", 200) or 0, over.get("fault"), over.get("detail") or "")


def test_o2_a_write_accepted_then_dropped_keeps_its_status_and_no_body(tmp_path, data_root):
    """A 201 whose reply breaks mid-body: the status stands, the bytes already forwarded are not
    returned. O2, O8 (#1404)."""
    with H.breaks_after_status(201) as base, T.rig(
            tmp_path / "forge", data_root,
            lambda _u: H.declaration(base + T.BASE_PATH, writes=(("POST", "/tickets"),))) as r, \
            A.proxy_for(r.t, r.store) as (url, _tap):
        answer = W.call(url, r.tok({("identity", "rw")}), f"{base}{T.BASE_PATH}/tickets", method="POST")

    assert (answer.status, answer.fault, answer.body) == (201, "TransportFault", "")
    assert answer.from_system is True


@pytest.mark.parametrize(("pieces", "text"), [
    pytest.param([b"caf\xe9"], "caf\ufffd", id="not-utf8"),
    pytest.param([b"\xe2\x98", b"\x83"], "\u2603", id="character-split-across-frames"),
])
def test_o8_the_body_is_decoded_once_with_replacement_characters(pieces, text):
    """Non-UTF-8 bytes become replacement characters on the run side; a character split between
    two frames is whole. O8."""
    f = W.fmt()
    payload = b"".join(f.encode_body(piece) for piece in pieces) + f.encode_final(W.final_record())
    with W.fake_proxy(payload, ended=True) as url:
        answer = W.call(url, "tok", f"{url}/x")

    assert answer.body == text


def test_o9_a_reply_in_any_other_content_type_is_the_proxys_own_fault():
    """The old proxy's JSON answer, and the new frames under another content type, are refused as
    `TransportFault`, the proxy's own; the same frames under the right type are the answer. O9."""
    old = json.dumps({"status": 200, "headers": {}, "body": "OLD-1412", "fault": None,
                      "detail": None}).encode()
    frames = _reply(b"NEW-1412")
    with H.upstream() as fake:
        target = f"{fake.url}/x"
        for reply in ((200, {"Content-Type": "application/json"}, old),
                      (200, {"Content-Type": "application/json"}, frames),
                      (200, {"Content-Type": "text/plain"}, frames), (200, {}, frames)):
            fake.replies[PROXY_PATH] = reply
            with pytest.raises(TransportFault) as raised:
                W.call(fake.url, "tok", target)
            assert raised.value.proxy_own is True, reply
            assert "-1412" not in str(raised.value), "a body reached the fault's text"
        fake.replies[PROXY_PATH] = (200, {"Content-Type": W.fmt().REPLY_CONTENT_TYPE}, frames)
        assert W.call(fake.url, "tok", target).body == "NEW-1412"


def test_o9_only_a_200_in_exactly_the_proxys_content_type_is_its_reply():
    """Valid frames under another status, or a content type that merely extends the proxy's (a
    prefix or suffix of it, or containing it), are the proxy's own `TransportFault`, naming a
    non-200 status; the real type with parameters or in another case is accepted. O9."""
    real = W.fmt().REPLY_CONTENT_TYPE
    frames = _reply(b"NEW-1412")
    wrong_types = [real + "-v2", real + "+json", real + "2", real + ".x", "x" + real,
                   "application/vnd.acme." + real.split("/")[1] + ".v3", "vendor/" + real,
                   "Application/JSON", "TEXT/PLAIN; charset=utf-8", "application/json; q=1",
                   "text/html", real.split("/")[0], real.split("/")[0] + "/", "application/x-" + real]
    wrong_statuses = [201, 202, 204, 206, 299, 301, 400, 401, 404, 429, 500, 503]
    accepted = [real, real + "; charset=utf-8", real.upper(), real.title() + " ;x=y"]
    cases = [(200, t) for t in wrong_types] + [(s, real) for s in wrong_statuses] + [
        (s, t) for s, t in ((201, real + "-v2"), (404, "text/html"), (500, real + "+json"))]
    with H.upstream() as fake:
        target = f"{fake.url}/x"
        for status, kind in cases:
            fake.replies[PROXY_PATH] = (status, {"Content-Type": kind}, frames)
            with pytest.raises(TransportFault) as raised:
                W.call(fake.url, "tok", target)
            assert raised.value.proxy_own is True, (status, kind)
            assert getattr(raised.value, "status", None) is None, (status, kind)
            assert "-1412" not in str(raised.value), "a body reached the fault's text"
            if status != 200:
                assert str(status) in raised.value.detail, (status, kind, raised.value.detail)
        for kind in accepted:
            fake.replies[PROXY_PATH] = (200, {"Content-Type": kind}, frames)
            assert W.call(fake.url, "tok", target).body == "NEW-1412", kind
