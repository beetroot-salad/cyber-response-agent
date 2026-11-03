"""#1163/#1359 the record leg reaches an `http-proxy` case system through the same transport and
fault mapping as a query; a failure is still reported as text, never raised. No open leg."""
from __future__ import annotations

import json
import logging
from contextlib import contextmanager

from defender.box import run_env
from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A
from defender.tests.integrations.credential_proxy_1163 import _harness as H
from defender.tests.integrations.credential_proxy_1163 import _tenant as T
from defender.tests.support.tenancy import _tenants1106
from defender.tests.tenancy.tenant_1107_settings import _spec1107 as S
from defender.tests.tenancy.tenant_1108_p4._support import DEFENDER, published_tenant

STORE = "/store"
WRITES = (("POST", "/tickets/*/comments"),)  # glob grammar: contract's pick
SYSTEM = "ticket"
KEY = "a-1107"  # `S.plant_alert`'s `alert_id`: the ticket the fixture tenant's mapping names
KEY_PATTERN = 'TICKET_KEY_PATTERN="[A-Za-z0-9-]+"\n'
COMMENT = f"{STORE}/tickets/{KEY}/comments"


def _decl(up, writes=WRITES):
    return H.declaration(up.url + STORE, writes=writes)


@contextmanager
def _published(scratch, root, decl):
    """The fixture tenant (its case-record file names `ticket`) with `ticket` on `http-proxy`;
    `decl=None` leaves `ticket` with no `access.yaml` at all."""
    files = A.system_files(SYSTEM, decl or "", env_extra=KEY_PATTERN)
    if decl is None:
        files.pop(H.ACCESS_FILE.format(system=SYSTEM))
    with published_tenant(scratch, root=root, files=files) as t:
        yield t


def _run(tmp_path):
    rec = S.RunRecorder(tmp_path / "run")
    return rec, rec.materialize(S.plant_alert(tmp_path / "in", alert_id=KEY))


def _leg(t, run, rec, url, tok, shim=None):
    env = run_env(DEFENDER, rec.run_dir_at)
    if shim is not None:
        env = shim.env(env)
    S.ticket_writer().record_case_ticket(
        run, tenant=T.run_record(t), defender_dir=DEFENDER, env=env, request_token=tok,
        proxy_url=url)
    return S.receipt(rec.run_dir_at)


def test_t1_the_comment_reaches_the_store_through_the_proxy_and_leaks_nothing(
        tmp_path, data_root, caplog):
    """The leg POSTs one comment on the alert's key through the proxy with the key injected; the
    receipt is ok and nothing of the credential or the token reaches files, logs or receipt.
    O3, O4, O1."""
    caplog.set_level(logging.DEBUG)
    shim = S.DockerShim(tmp_path / "shim")
    with H.upstream() as up, _published(tmp_path / "forge", data_root, _decl(up)) as t:
        up.replies[COMMENT] = (201, {}, json.dumps({"id": 1}).encode())
        store = H.FakeStore({(t.tenant_id, SYSTEM): T.static_set()})
        tok = T.token(t.tenant_id, {(SYSTEM, "rw")})
        rec, run = _run(tmp_path)
        with A.proxy_for(t, store) as (url, tap):
            receipt = _leg(t, run, rec, url, tok, shim)

    assert [(s.method, s.path.split("?")[0]) for s in up.seen] == [("POST", COMMENT)]
    assert all(s.headers.get("Authorization") == f"Bearer {H.CANARY_KEY}" for s in up.seen)
    assert receipt is not None, receipt
    assert (receipt["key"], receipt["status"], receipt["ok"]) == (KEY, "commented", True), receipt
    assert receipt["url"] == f"{up.url}{STORE}/tickets/{KEY}", receipt
    assert shim.calls() == [], "the leg used docker for an http-proxy system"
    assert tap.tokens == [tok], "positive control: the proxy was sent the token"
    for channel in (caplog.text, H.text_under(rec.run_dir_at.parent), json.dumps(receipt)):
        assert H.CANARY_KEY not in channel
        assert tok not in channel
    assert "run_dir=" in caplog.text, "positive control: logs are read"


def test_t2_the_docker_exec_case_system_still_uses_docker(tmp_path, data_root):
    """Control for t1: the fixture's docker-exec `ticket` system reaches the docker shim with one
    comment POST and needs no token. O3, regression guard."""
    shim = S.DockerShim(tmp_path / "shim", S.store_answers_ok())
    rec, run = _run(tmp_path)
    S.ticket_writer().record_case_ticket(
        run, tenant=_tenants1106.fixture_run_tenant(), defender_dir=DEFENDER,
        env=shim.env(run_env(DEFENDER, rec.run_dir_at)))
    posts = [c["argv"] for c in shim.calls() if "POST" in c["argv"]]
    assert len(posts) == 1, shim.calls()
    assert (S.curl_url(posts[0]) or "").endswith(f"/tickets/{KEY}/comments"), posts


def test_t3_failures_are_text_in_the_receipt_and_carry_no_credential(tmp_path, data_root, caplog):
    """An upstream 401 whose body echoes the key, a missing credential, an unreachable proxy and a
    read-only token each leave an error receipt (no raise), the key absent, and nothing sent where
    the proxy refused; proxy refusals say "the credential proxy refused". O5, O4, O3."""
    caplog.set_level(logging.DEBUG)
    with H.upstream() as up, _published(tmp_path / "forge", data_root, _decl(up)) as t:
        cases = {
            "401-echo": (T.token(t.tenant_id, {(SYSTEM, "rw")}), True, True, True),
            "no-credential": (T.token(t.tenant_id, {(SYSTEM, "rw")}), False, True, False),
            "proxy-down": (T.token(t.tenant_id, {(SYSTEM, "rw")}), True, False, False),
            "read-only-token": (T.token(t.tenant_id, {(SYSTEM, "r")}), True, True, False),
        }
        up.replies[COMMENT] = (401, {}, json.dumps({"detail": f"bad key {H.CANARY_KEY}"}).encode())
        for name, (tok, has_set, proxy_up, reaches) in cases.items():
            before = len(up.seen)
            store = H.FakeStore({(t.tenant_id, SYSTEM): T.static_set()} if has_set else {})
            rec, run = _run(tmp_path / name)
            with A.proxy_for(t, store) as (url, _tap):
                receipt = _leg(t, run, rec, url if proxy_up else
                               f"http://127.0.0.1:{H.free_port()}", tok)
            assert receipt is not None, (name, receipt)
            assert (receipt["ok"], receipt["status"], receipt["key"]) == (False, "error", KEY)
            reason = (receipt.get("reason") or "").lower()
            assert reason.strip()
            assert H.CANARY_KEY not in json.dumps(receipt), name
            assert (len(up.seen) > before) is reaches, name
            if name == "401-echo":
                assert "the store refused" in reason
                assert "401" in reason
            elif name == "proxy-down":
                # O5 (r4): an unreachable proxy is "could not be reached", not a refusal.
                assert "could not be reached" in reason, (name, reason)
                assert "the credential proxy refused" not in reason, (name, reason)
            elif name in ("no-credential", "read-only-token"):
                assert "the credential proxy refused" in reason, (name, reason)
    assert H.CANARY_KEY not in caplog.text


def test_t6_an_access_file_with_no_write_route_is_named_by_the_receipt_and_nothing_is_sent(
        tmp_path, data_root):
    """A case system on `http-proxy` whose `access.yaml` declares no write route, is unparsable or
    is absent: the leg's own judgement names `systems/ticket/access.yaml` in the receipt and makes
    no call, not even to the proxy. D-16, O5."""
    for label in ("no write route", "unparsable", "absent"):
        with H.upstream() as up:
            decl = {"no write route": _decl(up, writes=()), "unparsable": "access: [unclosed\n",
                    "absent": None}[label]
            with _published(tmp_path / label / "forge", data_root, decl) as t:
                store = H.FakeStore({(t.tenant_id, SYSTEM): T.static_set()})
                tok = T.token(t.tenant_id, {(SYSTEM, "rw")})
                rec, run = _run(tmp_path / label)
                with A.proxy_for(t, store) as (url, tap):
                    receipt = _leg(t, run, rec, url, tok)
            assert receipt is not None, label
            assert (receipt["ok"], receipt["status"], receipt["url"]) == (False, "error", None), receipt
            assert f"systems/{SYSTEM}/access.yaml" in receipt["reason"], (label, receipt)
            assert tap.tokens == [], f"{label}: the proxy was called"
            assert up.seen == [], f"{label}: the store was reached"


def test_t6b_a_write_the_proxy_refuses_at_call_time_is_a_refusal_not_a_transport_error(
        tmp_path, data_root):
    """The declaration holds a write route, but not the comment's path: the leg's judgement
    passes, the proxy refuses the call, and the receipt says so (not an access.yaml fault, not
    "could not be reached"); nothing reaches the store. Control: t1 (matching route). O5, O4."""
    other = (("POST", "/elsewhere/*"),)
    with H.upstream() as up, _published(tmp_path / "forge", data_root, _decl(up, writes=other)) as t:
        store = H.FakeStore({(t.tenant_id, SYSTEM): T.static_set()})
        tok = T.token(t.tenant_id, {(SYSTEM, "rw")})
        rec, run = _run(tmp_path)
        with A.proxy_for(t, store) as (url, tap):
            receipt = _leg(t, run, rec, url, tok)
    assert receipt is not None
    assert receipt["ok"] is False
    reason = (receipt.get("reason") or "").lower()
    assert "the credential proxy refused" in reason, reason
    assert "could not be reached" not in reason, reason
    assert "access.yaml" not in reason, reason
    assert tap.tokens == [tok]
    assert up.seen == []


def test_t8_a_proxy_the_leg_cannot_use_is_named_in_the_receipt_not_the_store(tmp_path, data_root):
    """#1404: a proxy that is down or answers a non-200 status (readable or not) is "the
    credential proxy could not be reached; check that it is running"; a call handed no proxy
    address is "the run was not given the credential proxy's address or token"; neither blames
    the store, and nothing reaches it. Control: a store down behind a healthy proxy is still "the
    store could not be reached", and the proxy is not blamed. O5."""
    unreachable = "the credential proxy could not be reached; check that it is running"
    unwired = "the run was not given the credential proxy's address or token"
    with H.upstream() as up, H.upstream() as broken, _published(
            tmp_path / "forge", data_root, _decl(up)) as t:
        broken.replies["/v1/request"] = (502, {}, b"bad gateway")
        store = H.FakeStore({(t.tenant_id, SYSTEM): T.static_set()})
        tok = T.token(t.tenant_id, {(SYSTEM, "rw")})
        cases = {
            "proxy-down": (f"http://127.0.0.1:{H.free_port()}", unreachable),
            "proxy-502": (broken.url, unreachable),
            "no-address": (None, unwired),
        }
        for name, (url, expected) in cases.items():
            rec, run = _run(tmp_path / name)
            receipt = _leg(t, run, rec, url, tok)
            assert receipt is not None, name
            assert (receipt["ok"], receipt["status"]) == (False, "error"), (name, receipt)
            reason = receipt.get("reason") or ""
            assert reason.startswith(expected), (name, reason)
            assert "the store" not in reason, (name, reason)
        assert len(broken.seen) == 1, "positive control: the 502 proxy was called"
        assert up.seen == [], "the store was reached"

        # A proxy answering a readable body with a non-200 status is still the proxy's failure.
        broken.replies["/v1/request"] = (503, {"Content-Type": "application/json"}, json.dumps(
            {"status": 0, "headers": {}, "body": "", "fault": None, "detail": ""}).encode())
        rec, run = _run(tmp_path / "proxy-503-json")
        reason = (_leg(t, run, rec, broken.url, tok) or {}).get("reason") or ""
        assert reason.startswith(unreachable), reason

    # Control: the proxy is healthy and the store behind it is down.
    down = H.declaration(f"http://127.0.0.1:{H.free_port()}{STORE}", writes=WRITES)
    with _published(tmp_path / "forge-down", data_root, down) as t:
        store = H.FakeStore({(t.tenant_id, SYSTEM): T.static_set()})
        tok = T.token(t.tenant_id, {(SYSTEM, "rw")})
        rec, run = _run(tmp_path / "store-down")
        with A.proxy_for(t, store) as (url, tap):
            receipt = _leg(t, run, rec, url, tok)
        assert tap.tokens == [tok], "positive control: the proxy was called"
    reason = (receipt or {}).get("reason") or ""
    assert reason.startswith("the store could not be reached"), reason
    assert "credential proxy could not be reached" not in reason, reason
