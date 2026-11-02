"""#1163 the ticket writer reaches an `http-proxy` case-history store through the same transport
and fault mapping as a query; a failure is still reported as text, never raised."""
from __future__ import annotations

import json
import logging

from defender.box import run_env
from defender.investigation import ticket_writer
from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A
from defender.tests.integrations.credential_proxy_1163 import _harness as H
from defender.tests.integrations.credential_proxy_1163 import _tenant as T
from defender.tests.support.tenancy import _tenants1106
from defender.tests.tenancy.tenant_1107_settings import _spec1107 as S
from defender.tests.tenancy.tenant_1108_p4._support import DEFENDER

STORE = "/store"
WRITES = (("POST", "/tickets"), ("POST", "/tickets/*/comments"))  # glob grammar: contract's pick
SYSTEM = "case-history"


def _decl(up):
    return H.declaration(up.url + STORE, writes=WRITES)


def _run(tmp_path):
    rec = S.RunRecorder(tmp_path / "run")
    return rec, rec.materialize(S.plant_alert(tmp_path / "in"))


def _legs(tmp_path, t, run, rec, url, tok, shim=None):
    env = run_env(DEFENDER, rec.run_dir_at)
    if shim is not None:
        env = shim.env(env)
    record = T.run_record(t)
    kw = dict(tenant=record, defender_dir=DEFENDER, env=env, request_token=tok, proxy_url=url)
    ticket_writer.open_case_ticket(run, **kw)
    S.ticket_writer().record_case_ticket(run, **kw)
    return S.receipt(rec.run_dir_at)


def test_t1_open_and_record_reach_the_store_through_the_proxy_and_leak_nothing(
        tmp_path, data_root, caplog):
    """Both legs POST through the proxy with the key injected; the receipt is ok and nothing
    of the credential or the token reaches the run's files, logs or receipt. O4, O10, A7."""
    caplog.set_level(logging.DEBUG)
    shim = S.DockerShim(tmp_path / "shim")
    with H.upstream() as up, A.published(tmp_path / "forge", data_root, {SYSTEM: _decl(up)}) as t:
        up.replies[f"{STORE}/tickets"] = (201, {}, json.dumps({"key": "INC-1"}).encode())
        store = H.FakeStore({(t.tenant_id, SYSTEM): T.static_set()})
        tok = T.token(t.tenant_id, {(SYSTEM, "rw")})
        rec, run = _run(tmp_path)
        with A.proxy_for(t, store) as (url, tap):
            receipt = _legs(tmp_path, t, run, rec, url, tok, shim)

    methods = [(s.method, s.path.split("?")[0]) for s in up.seen]
    assert methods[0] == ("POST", f"{STORE}/tickets")
    assert methods[1][0] == "POST"
    assert methods[1][1].startswith(f"{STORE}/tickets/")
    assert all(s.headers.get("Authorization") == f"Bearer {H.CANARY_KEY}" for s in up.seen)
    assert receipt is not None, receipt
    assert receipt["ok"] is True, receipt
    assert shim.calls() == [], "the writer used docker for an http-proxy system"
    assert tap.tokens == [tok, tok], "positive control: the proxy was sent the token on each leg"
    for channel in (caplog.text, H.text_under(rec.run_dir_at.parent), json.dumps(receipt)):
        assert H.CANARY_KEY not in channel
        assert tok not in channel
    assert "run_dir=" in caplog.text or "open" in caplog.text, "positive control: logs are read"


def test_t2_the_docker_exec_writer_still_uses_docker(tmp_path, data_root):
    """Control for t1: the fixture's docker-exec case-history system reaches the docker shim and
    needs no token. A7, regression guard."""
    shim = S.DockerShim(tmp_path / "shim", S.store_answers_ok("r-1"))
    rec, run = _run(tmp_path)
    ticket_writer.open_case_ticket(
        run, tenant=_tenants1106.fixture_run_tenant(), defender_dir=DEFENDER,
        env=shim.env(run_env(DEFENDER, rec.run_dir_at)))
    assert shim.calls(), "the docker-exec writer never reached docker"


def test_t3_failures_are_text_in_the_receipt_and_carry_no_credential(tmp_path, data_root, caplog):
    """An upstream 401 whose body echoes the key, a missing credential, an unreachable proxy
    and a read-only token each leave an error receipt (no raise), the key absent, and nothing
    sent where the proxy refused. O4, O7, A9, O3."""
    caplog.set_level(logging.DEBUG)
    with H.upstream() as up, A.published(tmp_path / "forge", data_root, {SYSTEM: _decl(up)}) as t:
        cases = {
            "401-echo": (T.token(t.tenant_id, {(SYSTEM, "rw")}), True, True, True),
            "no-credential": (T.token(t.tenant_id, {(SYSTEM, "rw")}), False, True, False),
            "proxy-down": (T.token(t.tenant_id, {(SYSTEM, "rw")}), True, False, False),
            "read-only-token": (T.token(t.tenant_id, {(SYSTEM, "r")}), True, True, False),
        }
        up.replies[f"{STORE}/tickets"] = (401, {}, json.dumps(
            {"detail": f"bad key {H.CANARY_KEY}"}).encode())
        for name, (tok, has_set, proxy_up, reaches) in cases.items():
            before = len(up.seen)
            store = H.FakeStore({(t.tenant_id, SYSTEM): T.static_set()} if has_set else {})
            rec, run = _run(tmp_path / name)
            with A.proxy_for(t, store) as (url, _tap):
                receipt = _legs(tmp_path, t, run, rec, url if proxy_up else
                                f"http://127.0.0.1:{H.free_port()}", tok)
            assert receipt is not None, (name, receipt)
            assert receipt["ok"] is False, (name, receipt)
            assert (receipt.get("reason") or "").strip()
            assert H.CANARY_KEY not in json.dumps(receipt), name
            assert (len(up.seen) > before) is reaches, name
    assert H.CANARY_KEY not in caplog.text


def test_t6_a_write_the_declaration_does_not_allow_is_a_refusal_not_a_transport_error(tmp_path, data_root):
    """A store whose declaration allows no write route: the open leg's refusal is reported as the proxy's refusal (not a
    transport error) in the receipt, and the record leg does not ask again. O7, A6, A9."""
    with H.upstream() as up, A.published(tmp_path / "forge", data_root,
                                         {SYSTEM: H.declaration(up.url + STORE, writes=())}) as t:
        store = H.FakeStore({(t.tenant_id, SYSTEM): T.static_set()})
        tok = T.token(t.tenant_id, {(SYSTEM, "rw")})
        rec, run = _run(tmp_path)
        with A.proxy_for(t, store) as (url, tap):
            receipt = _legs(tmp_path, t, run, rec, url, tok)
    assert receipt is not None
    assert receipt["ok"] is False
    reason = receipt.get("reason") or ""
    assert reason.startswith(ticket_writer.PROXY_REFUSED), reason
    assert "ConfinementFault" in reason, reason
    assert "transport error" not in reason, reason
    assert tap.tokens == [tok], "the record leg asked again after the open leg was refused"
    assert up.seen == []
