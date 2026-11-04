"""#1163/#1359 (proxy side): the record leg reports the case system's own refusal by its status
and the store's unreachability as such, as on the docker path."""
from __future__ import annotations

import dataclasses
import json
import logging
import time
import types

import pytest

from defender.box import run_env
from defender.integrations._stub_transport import raise_proxy_fault
from defender.kit.faults import AdapterFault, ConfigFault, TransportFault
from defender.kit.settings import config_pointer
from defender.systems import case_system
from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A
from defender.tests.integrations.credential_proxy_1163 import _harness as H
from defender.tests.integrations.credential_proxy_1163 import _tenant as T
from defender.tests.integrations.credential_proxy_1163.test_ticket_flow import (
    COMMENT,
    KEY,
    PROXY_FAILED,
    STORE,
    WRITES,
    SYSTEM,
    _decl,
    _leg,
    _published,
    _run,
)
from defender.tests.integrations.credential_proxy_1163.test_proxy_faults_proxy_side import _BrokenStore
from defender.tests.tenancy.tenant_1107_settings import _spec1107 as S
from defender.tests.tenancy.tenant_1108_p4._support import DEFENDER

REASON = "store says no: duplicate-or-invalid"


def _comment_leg(tmp_path, data_root, status: int, caplog):
    """The record leg against a store answering `status` to the comment; returns the receipt and
    the recording upstream."""
    caplog.set_level(logging.INFO)
    with H.upstream() as up, _published(tmp_path / "forge", data_root, _decl(up)) as t:
        rec, run = _run(tmp_path)
        up.replies[COMMENT] = (status, {"Content-Type": "application/json"},
                               json.dumps({"detail": REASON}).encode())
        store = H.FakeStore({(t.tenant_id, SYSTEM): T.static_set()})
        with A.proxy_for(t, store) as (url, _tap):
            receipt = _leg(t, run, rec, url, T.token(t.tenant_id, {(SYSTEM, "rw")}))
        return receipt, up


@pytest.mark.parametrize(("status", "words"), [
    (403, ("the store refused", "403")),
    (404, ("the store refused", "404", "not found")),
    (409, ("the store refused", "409")),
    (422, ("the store refused", "422")),
    (500, ("the store could not be reached",)),
    (503, ("the store could not be reached",)),
])
def test_t4_a_store_refusing_the_comment_is_reported_by_class_and_status(
        tmp_path, data_root, caplog, status, words):
    """A 4xx leaves an error receipt "the store refused" with the status (a 404 also "not found");
    a 5xx is "the store could not be reached". O5, UpstreamFault status."""
    receipt, up = _comment_leg(tmp_path, data_root, status, caplog)

    assert [s.method for s in up.seen] == ["POST"], "control: the store was asked"
    assert receipt is not None, "the refusal left no receipt"
    assert (receipt["ok"], receipt["key"]) == (False, KEY)
    assert all(w in receipt["reason"].lower() for w in words), receipt
    assert H.CANARY_KEY not in json.dumps(receipt)


def test_t7_a_store_nothing_listens_at_is_reported_as_could_not_be_reached(tmp_path, data_root):
    """The declared base has no listener behind the proxy: an error receipt saying the store could
    not be reached (as a 5xx and the docker path's unreachable bastion do), not that the credential
    proxy refused. O5."""
    from defender.tests.integrations.credential_proxy_1163.test_ticket_flow import STORE, WRITES

    dead = H.declaration(f"http://127.0.0.1:{H.free_port()}{STORE}", writes=WRITES)
    with _published(tmp_path / "forge", data_root, dead) as t:
        rec, run = _run(tmp_path)
        store = H.FakeStore({(t.tenant_id, SYSTEM): T.static_set()})
        with A.proxy_for(t, store) as (url, tap):
            receipt = _leg(t, run, rec, url, T.token(t.tenant_id, {(SYSTEM, "rw")}))
    assert tap.tokens, "control: the proxy was reached"
    assert receipt is not None
    assert (receipt["ok"], receipt["status"], receipt["key"]) == (False, "error", KEY), receipt
    reason = receipt["reason"].lower()
    assert "could not be reached" in reason, receipt
    assert "the credential proxy refused" not in reason, receipt


class _DownOnce(H.FakeStore):
    """A store that is unreachable for its first read (an OpenBao blip), then answers."""

    def read(self, tenant_id: str, system: str):
        first = not self.reads
        found = super().read(tenant_id, system)
        if first:
            raise TransportFault("OpenBao is unreachable for the credential read")
        return found


def test_t5_a_proxy_blip_loses_the_comment_not_the_run_and_the_next_one_posts(
        tmp_path, data_root, caplog):
    """The proxy's store is down for the first comment: an error receipt, no raise; the same leg
    over a fresh run then posts. O5."""
    caplog.set_level(logging.INFO)
    with H.upstream() as up, _published(tmp_path / "forge", data_root, _decl(up)) as t:
        store = _DownOnce({(t.tenant_id, SYSTEM): T.static_set()})
        tok = T.token(t.tenant_id, {(SYSTEM, "rw")})
        with A.proxy_for(t, store) as (url, _tap):
            first_rec, first_run = _run(tmp_path / "a")
            lost = _leg(t, first_run, first_rec, url, tok)
            assert up.paths() == [], "the first comment was lost to the blip"
            second_rec, second_run = _run(tmp_path / "b")
            kept = _leg(t, second_run, second_rec, url, tok)

    assert lost is not None
    assert (lost["ok"], lost["status"]) == (False, "error"), lost
    assert lost["reason"].strip()
    assert [s.path for s in up.seen] == [COMMENT]
    assert kept["ok"] is True, kept
    assert S.receipt(second_rec.run_dir_at) == kept


def _leg_with_adapter_raising(tmp_path, data_root, raises):
    """The record leg on the proxied `ticket` system with its comment action replaced by `raises`
    (the case seam run start uses); returns the receipt."""
    with H.upstream() as up, _published(tmp_path / "forge", data_root, _decl(up)) as t:
        rec, run = _run(tmp_path)
        tenant = T.run_record(t)
        real = case_system.case_verdict(tenant, defender_dir=DEFENDER)
        assert isinstance(real, case_system.CaseTarget), real
        stub = dataclasses.replace(real, module=types.SimpleNamespace(add_case_comment=raises))
        S.ticket_writer().record_case_ticket(
            run, tenant=tenant, defender_dir=DEFENDER, env=run_env(DEFENDER, rec.run_dir_at),
            request_token=T.token(t.tenant_id, {(SYSTEM, "rw")}), proxy_url=up.url, case=stub)
        return S.receipt(rec.run_dir_at)


def test_t8_a_settings_fault_the_adapter_raises_itself_points_at_config_not_the_proxy(
        tmp_path, data_root):
    """The adapter's own settings fault, raised before any request, on a system reached through
    the proxy: the receipt names that system's `config.env`, not a proxy refusal. #1398."""
    def own_settings_fault(*_a, **_k):
        raise ConfigFault("TICKET_BASE_URL is blank")

    receipt = _leg_with_adapter_raising(tmp_path, data_root, own_settings_fault)
    assert receipt is not None
    assert receipt["ok"] is False
    assert config_pointer(SYSTEM) in receipt["reason"], receipt
    assert "the credential proxy refused" not in receipt["reason"].lower(), receipt


def test_t9_a_settings_fault_the_proxy_raises_is_still_a_proxy_refusal(tmp_path, data_root):
    """Control for t8, from the other side: the same fault class arriving through the proxy's
    answer (the way the transport raises it) is the proxy's refusal, not a `config.env` fault."""
    def proxy_says_config(*_a, **_k):
        raise_proxy_fault("ConfigFault", "the declaration holds no route for this call")

    receipt = _leg_with_adapter_raising(tmp_path, data_root, proxy_says_config)
    assert receipt is not None
    assert "the credential proxy refused" in receipt["reason"].lower(), receipt
    assert config_pointer(SYSTEM) not in receipt["reason"], receipt


class _Slow(H.FakeStore):
    """The proxy's credential store taking `seconds` to answer each read."""

    def __init__(self, sets, seconds: float) -> None:
        super().__init__(sets)
        self.seconds = seconds

    def read(self, tenant_id: str, system: str):
        time.sleep(self.seconds)
        return super().read(tenant_id, system)


def _proxied_leg(tmp_path, data_root, make_store, *, decl=None, before=None, **deps_kw):
    """The record leg through the real proxy built with `make_store(sets)` and `deps_kw`; returns
    (receipt, proxy tap, recording store upstream)."""
    with H.upstream() as up, _published(tmp_path / "forge", data_root,
                                        decl if decl is not None else _decl(up)) as t:
        if before is not None:
            before(up)
        rec, run = _run(tmp_path)
        store = make_store({(t.tenant_id, SYSTEM): T.static_set()})
        with A.proxy_for(t, store, **deps_kw) as (url, tap):
            receipt = _leg(t, run, rec, url, T.token(t.tenant_id, {(SYSTEM, "rw")}))
        return receipt, tap, up


@pytest.mark.parametrize("kind", ["openbao-unreachable", "unforeseen", "out-of-time-before-call",
                                  "audit-unwritable"])
def test_t11_a_failure_inside_the_proxy_is_the_proxys_not_the_stores(tmp_path, data_root, kind):
    """#1404 O1: the proxy is reached but fails itself (its credential store unreachable, an
    exception nobody foresaw, its deadline spent before the store is called, its audit record
    unwritable): "the credential proxy failed: <cause>", never the store's wording. The audit case
    may follow a store that accepted the comment, so the subject claims no non-delivery."""
    stores = {
        "openbao-unreachable": _DownOnce,
        "unforeseen": _BrokenStore,
        "out-of-time-before-call": lambda sets: _Slow(sets, 0.5),
        "audit-unwritable": H.FakeStore,
    }
    deps_kw = {"out-of-time-before-call": {"upstream_timeout_sec": 0.2, "proxy_overhead_sec": 0.1},
               "audit-unwritable": {"audit": H.FailingAudit()}}.get(kind, {})
    causes = {"openbao-unreachable": "OpenBao is unreachable",
              "unforeseen": "could not be processed",
              "out-of-time-before-call": "ran out of time before calling",
              "audit-unwritable": "audit could not be written"}
    receipt, tap, up = _proxied_leg(tmp_path, data_root, stores[kind], **deps_kw)
    assert tap.tokens, "positive control: the proxy was reached"
    assert receipt is not None, kind
    assert (receipt["ok"], receipt["status"]) == (False, "error"), receipt
    reason = receipt["reason"]
    assert reason.startswith(PROXY_FAILED), (kind, reason)
    assert causes[kind] in reason, (kind, reason)
    assert not reason.startswith("the store"), (kind, reason)
    if kind == "audit-unwritable":
        assert [s.path for s in up.seen] == [COMMENT], "positive control: the store was called"
    else:
        assert up.seen == [], f"{kind}: the store was called"


@pytest.mark.parametrize("kind", ["store-not-listening", "store-cut-by-the-deadline"])
def test_t12_a_store_the_proxy_saw_fail_keeps_the_store_wording(tmp_path, data_root, kind):
    """#1404 O2, control for t11: where the proxy's call to the store itself failed (nothing
    listening; the deadline cutting the call after the proxy's own legs spent part of it) the
    receipt's subject is the store and the proxy is not blamed. The subject is checked, not a
    substring the cause could carry."""
    if kind == "store-not-listening":
        dead = H.declaration(f"http://127.0.0.1:{H.free_port()}{STORE}", writes=WRITES)
        receipt, tap, _up = _proxied_leg(tmp_path, data_root, H.FakeStore, decl=dead)
    else:
        # Deadline 3.0s; the proxy's own read spends 1.0s, so the store call gets ~2.0s of its
        # 2.5s budget and is cut there. The proxy's other steps would need another ~2s to spend
        # the deadline before the call (t11's case) instead.
        def slow_store(up):
            up.replies[COMMENT] = lambda _seen: (time.sleep(3.5), (201, {}, b"{}"))[1]
        receipt, tap, _up = _proxied_leg(
            tmp_path, data_root, lambda sets: _Slow(sets, 1.0), before=slow_store,
            upstream_timeout_sec=2.5, proxy_overhead_sec=0.5)
    assert tap.tokens, "positive control: the proxy was reached"
    assert receipt is not None, kind
    reason = receipt["reason"]
    assert reason.startswith("the store could not be reached: "), (kind, reason)
    assert "credential proxy" not in reason, (kind, reason)


def test_t13_a_relayed_status_is_the_systems_however_the_fault_is_raised():
    """#1404 P1: a fault carrying the system's status is the system's even when the caller does
    not say so; one with neither a status nor the system mark is the proxy's."""
    with pytest.raises(AdapterFault) as relayed:
        raise_proxy_fault("UpstreamFault", "HTTP 409 from ticket: duplicate", 409)
    with pytest.raises(AdapterFault) as unmarked:
        raise_proxy_fault("TransportFault", "the proxy's audit could not be written")
    assert relayed.value.proxy_own is False, relayed.value
    assert unmarked.value.proxy_own is True, unmarked.value
