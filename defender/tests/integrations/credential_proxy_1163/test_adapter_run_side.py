"""#1163 run side, adapter and ticket writer: a refusal or failure never carries the request
token, the proxy address is the run's alone, and an `http-proxy` system with no token is never
reached any other way."""
from __future__ import annotations

import json
import logging
from datetime import timedelta

import httpx
import pytest

from defender.integrations import _stub_transport as transport
from defender.integrations import identity_adapter
from defender.kit.faults import AdapterFault, ConfigFault, TransportFault
from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A
from defender.tests.integrations.credential_proxy_1163 import _harness as H
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
                                json=body).text if reachable else ""

    assert type(raised.value) is (ConfigFault if reachable else TransportFault), raised.value
    assert str(raised.value).strip(), "positive control: the fault has a text"
    if reachable:
        assert tap.tokens == [tok, tok], "positive control: the proxy was sent the token"
        assert json.loads(direct)["fault"] == "ConfigFault", direct
        assert json.loads(direct)["detail"].strip(), "positive control: the answer has a detail"
    assert up.seen == []
    for text in (str(raised.value), repr(raised.value), direct, caplog.text, repr(audit.records)):
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
    environment names a web proxy (P-1: the token reaches no third party)."""
    from defender import _proxy_client
    port, got, folder = tls_issuer
    monkeypatch.delenv("SSL_CERT_DIR", raising=False)
    monkeypatch.setenv("SSL_CERT_FILE", str(folder / "server.pem"))
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
        monkeypatch.setenv(name, "http://127.0.0.1:9")
    _proxy_client._client.cache_clear()  # noqa: SLF001 — the pooled client reads trust once per process
    try:
        with pytest.raises(TransportFault, match="no usable answer"):
            _proxy_client.proxy_call(f"https://localhost:{port}", "tok", system="identity", method="GET",
                                     url="https://idp.example/users")
    finally:
        _proxy_client._client.cache_clear()  # noqa: SLF001
    assert got, "the request reached the proxy address itself"
    assert json.loads(got[0])["system"] == "identity"


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
