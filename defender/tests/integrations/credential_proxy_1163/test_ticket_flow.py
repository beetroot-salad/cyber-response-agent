"""#1163/#1359 the record leg reaches an `http-proxy` case system through the same transport and
fault mapping as a query; a failure is still reported as text, never raised. No open leg."""
from __future__ import annotations

import json
import logging
from contextlib import contextmanager

import pytest

from defender.box import run_env
from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A
from defender.tests.integrations.credential_proxy_1163 import _harness as H
from defender.tests.integrations.credential_proxy_1163 import _tenant as T
from defender.tests.support.tenancy import _systems1366 as R
from defender.tests.tenancy.tenant_1107_settings import _spec1107 as S
from defender.tests.tenancy.tenant_1108_p4._support import DEFENDER, export_dir, published_tenant
from defender.tests.support.tenancy import _tenants1106 as T1106

STORE = "/store"
WRITES = (("POST", "/tickets/*/comments"),)  # glob grammar: contract's pick
SYSTEM = "ticket"
KEY = "a-1107"  # `S.plant_alert`'s `alert_id`: the ticket the fixture tenant's mapping names
KEY_PATTERN = 'TICKET_KEY_PATTERN="[A-Za-z0-9-]+"\n'
COMMENT = f"{STORE}/tickets/{KEY}/comments"
#: The receipt's subject for a fault the credential proxy itself caused (#1404 r2, O1).
PROXY_FAILED = "the credential proxy failed: "
#: How an `unknown` receipt's reason frames the write's own fault (#1374): "...store (<it>), and".
LOST = "the comment may have reached the store ("


def write_fault(receipt: dict) -> str:
    """The reason the write's own fault gave: the whole reason, or the part an `unknown` receipt
    frames after a read-back (#1374), so subject checks apply to that fault and not to the frame."""
    reason = receipt.get("reason") or ""
    return reason[len(LOST):].split("), and ", 1)[0] if reason.startswith(LOST) else reason


def _decl(up, writes=WRITES):
    return H.declaration(up.url + STORE, writes=writes)


@contextmanager
def _published(scratch, root, decl):
    """The fixture tenant (its case-record file names `ticket`) with `ticket` on `http-proxy`;
    `decl=None` leaves `ticket` with no `access.yaml` at all."""
    files = A.system_files(SYSTEM, decl or "", env_extra=KEY_PATTERN)
    if decl is None:  # no declaration file at all: the record's access text is then empty (#1366 O9; the fixture folders are retired)
        del files[H.ACCESS_FILE.format(system=SYSTEM)]
    with published_tenant(scratch, root=root, files=files) as t:
        yield t


def _run(tmp_path):
    rec = S.RunRecorder(tmp_path / "run")
    return rec, rec.materialize(S.plant_alert(tmp_path / "in", alert_id=KEY))


def _leg(t, run, rec, url, tok, shim=None, record=None):
    """The record leg over `record` (default: the run's record built from `t`'s records now)."""
    env = run_env(DEFENDER, rec.run_dir_at)
    if shim is not None:
        env = shim.env(env)
    tenant = record if record is not None else T.run_record(t)
    S.ticket_writer().record_case_ticket(
        run, tenant=tenant, defender_dir=DEFENDER, env=env, request_token=tok,
        proxy_url=url, case=T1106.case_for(tenant))
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


# t2 (the docker-exec `ticket` system still used docker) is retired: #1391 O1 removed the
# Docker access method; every case system is reached through the proxy, as t1 shows.


def test_t3_failures_are_text_in_the_receipt_and_carry_no_credential(tmp_path, data_root, caplog):
    """An upstream 401, a missing credential, an unreachable proxy and a
    read-only token each leave an error receipt (no raise), the key absent, and nothing sent where
    the proxy refused; proxy refusals say "the credential proxy refused". O5, O4, O3."""
    caplog.set_level(logging.DEBUG)
    with H.upstream() as up, _published(tmp_path / "forge", data_root, _decl(up)) as t:
        cases = {
            "401": (T.token(t.tenant_id, {(SYSTEM, "rw")}), True, True, True),
            "no-credential": (T.token(t.tenant_id, {(SYSTEM, "rw")}), False, True, False),
            "proxy-down": (T.token(t.tenant_id, {(SYSTEM, "rw")}), True, False, False),
            "read-only-token": (T.token(t.tenant_id, {(SYSTEM, "r")}), True, True, False),
        }
        up.replies[COMMENT] = (401, {}, json.dumps({"detail": "bad key"}).encode())
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
            if name == "401":
                assert "the store refused" in reason
                assert "401" in reason
            elif name == "proxy-down":
                # O5 (r4), amended by #1404 r2: an unreachable proxy is the proxy's failure, not
                # a refusal, and never the store's.
                assert reason.startswith(PROXY_FAILED), (name, reason)
                assert "the credential proxy refused" not in reason, (name, reason)
            elif name in ("no-credential", "read-only-token"):
                assert "the credential proxy refused" in reason, (name, reason)
    assert H.CANARY_KEY not in caplog.text


def test_t6_an_access_file_with_no_write_route_is_named_by_the_receipt_and_nothing_is_sent(
        tmp_path, data_root):
    """A case system on `http-proxy` whose access declaration declares no write route, is unparsable or
    is absent: the leg's own judgement names the record, `system ticket access` (#1366 DC6), in the receipt and makes
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
            # C5 words no part for a stored uncovered declaration: that arm names only the system (the discriminators are
            # "no call, nothing sent"); the two judged by `parse_access` name its access (DC6).
            named = SYSTEM if label == "no write route" else f"system {SYSTEM} access"
            assert named in receipt["reason"], (label, receipt)
            assert tap.tokens == [], f"{label}: the proxy was called"
            assert up.seen == [], f"{label}: the store was reached"


@pytest.mark.parametrize("base_moved", [False, True], ids=["control-base-unmoved", "base-moved"])
def test_t6b_a_write_the_proxy_refuses_at_call_time_is_a_refusal_not_a_transport_error(
        tmp_path, data_root, base_moved):
    """The run STARTED over a record whose access covers the comment's route (so the leg's own judgement passes), then the
    system's record changed to a new version at the next credential generation whose routes still cover the comment but
    whose BASE is elsewhere: the run's call falls outside the current base, and the proxy, which enforces the CURRENT
    record at each call, refuses; the receipt says so (not an access declaration fault, not "could not be reached");
    nothing reaches the store. Control: the same new version at generation 2 with the base UNMOVED comments (so the base is
    what is refused, not the version or the generation). This is the design's flow, "in-flight runs' later calls fall
    outside the new base and are refused", in a state the store accepts (the routes still cover, C4: a route-only change
    that uncovered the comment would be refused at write); the test writes the record into the proxy's records port, it
    does not drive the operator command (its write door is pinned in `test_system_records_1366.py`). (#1366 O7, Flows,
    P5/R4; O5, O4)"""
    with H.upstream() as up, _published(tmp_path / "forge", data_root, _decl(up)) as t:
        up.replies[COMMENT] = (201, {}, json.dumps({"id": 1}).encode())
        store = H.FakeStore({(t.tenant_id, SYSTEM): T.static_set()})
        tok = T.token(t.tenant_id, {(SYSTEM, "rw")})
        rec, run = _run(tmp_path)
        started = R.derive(export_dir(t.tenant, t.commit) / "settings")  # covers the comment route at the published base
        started_with = T.run_record(t, records=started)
        held = {t.tenant_id: started}  # the records the proxy reads, one lookup per call
        base = up.url + ("/moved-store" if base_moved else STORE)
        held[t.tenant_id] = R.edited(started, SYSTEM, version=2, generation=2,
                                     access=H.declaration(base, writes=WRITES))  # written after the run started
        with A.proxy_for(t, store, records=R.RecordsPort(held)) as (url, tap):
            receipt = _leg(t, run, rec, url, tok, record=started_with)
    assert receipt is not None
    if not base_moved:
        assert (receipt["status"], receipt["ok"]) == ("commented", True), receipt
        assert [(s.method, s.path.split("?")[0]) for s in up.seen] == [("POST", COMMENT)]
        return
    assert receipt["ok"] is False
    reason = (receipt.get("reason") or "").lower()
    assert "the credential proxy refused" in reason, reason
    assert "could not be reached" not in reason, reason
    assert f"system {SYSTEM} access" not in reason, reason  # #1366 DC6: no record fault
    assert tap.tokens == [tok]
    assert up.seen == []


def test_t10_a_proxy_the_leg_cannot_use_is_the_proxys_failure_not_the_stores(tmp_path, data_root):
    """#1404 O1: a proxy that is down, answers a non-200 status (readable or not), or whose
    address was never handed to the call leaves "the credential proxy failed: <cause>", never the
    store's wording, and the cause is said once. Controls for the store side are in
    `test_ticket_flow_proxy_side.py` (t7, t12). A non-200 from the proxy follows a request that
    reached it, so it may have reached the store: the case is read back (#1374), and the read
    meeting the same proxy, the receipt is `unknown`."""
    with H.upstream() as up, H.upstream() as broken, _published(
            tmp_path / "forge", data_root, _decl(up)) as t:
        tok = T.token(t.tenant_id, {(SYSTEM, "rw")})
        cases = {
            "proxy-down": (lambda: None, f"http://127.0.0.1:{H.free_port()}", "unreachable"),
            "proxy-502-unreadable": (
                lambda: broken.replies.update({"/v1/request": (502, {}, b"bad gateway")}),
                broken.url, "HTTP 502"),
            "proxy-503-readable": (
                lambda: broken.replies.update({"/v1/request": (
                    503, {"Content-Type": "application/json"},
                    json.dumps({"status": 0, "headers": {}, "body": "", "fault": None,
                                "detail": ""}).encode())}),
                broken.url, "HTTP 503"),
            "no-address": (lambda: None, None, "no credential proxy address"),
        }
        for name, (arrange, url, cause) in cases.items():
            arrange()
            rec, run = _run(tmp_path / name)
            receipt = _leg(t, run, rec, url, tok)
            assert receipt is not None, name
            expected = "unknown" if name.startswith(("proxy-502", "proxy-503")) else "error"
            assert (receipt["ok"], receipt["status"]) == (False, expected), (name, receipt)
            reason = write_fault(receipt)
            assert reason.startswith(PROXY_FAILED), (name, reason)
            assert cause in reason, (name, reason)
            assert "store" not in reason, (name, reason)
        assert len(broken.seen) == 4, "positive control: a write and a read at each broken proxy"
