"""#1163 repair (proxy side): the ticket writer reports the case-history store's own refusal
(its status and reason), as on the docker path, not as a transport failure."""
from __future__ import annotations

import json
import logging

import pytest

from defender.box import run_env
from defender.investigation import ticket_writer
from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A
from defender.tests.integrations.credential_proxy_1163 import _harness as H
from defender.tests.integrations.credential_proxy_1163 import _tenant as T
from defender.tests.integrations.credential_proxy_1163.test_ticket_flow import (
    STORE,
    SYSTEM,
    _decl,
    _run,
)
from defender.tests.tenancy.tenant_1107_settings import _spec1107 as S
from defender.tests.tenancy.tenant_1108_p4._support import DEFENDER

REASON = "store says no: duplicate-or-invalid"


def _leg(tmp_path, data_root, status: int, leg: str, caplog):
    """Run one ticket leg against a store answering `status` to its call; returns the receipt
    after it (None when the leg wrote none) and the recording upstream."""
    caplog.set_level(logging.INFO)
    with H.upstream() as up, A.published(tmp_path / "forge", data_root, {SYSTEM: _decl(up)}) as t:
        rec, run = _run(tmp_path)
        path = "/tickets" if leg == "open" else f"/tickets/{rec.run_dir_at.name}/comments"
        up.replies[f"{STORE}{path}"] = (status, {"Content-Type": "application/json"},
                                        json.dumps({"detail": REASON}).encode())
        store = H.FakeStore({(t.tenant_id, SYSTEM): T.static_set()})
        kw = dict(tenant=T.run_record(t), defender_dir=DEFENDER,
                  env=run_env(DEFENDER, rec.run_dir_at),
                  request_token=T.token(t.tenant_id, {(SYSTEM, "rw")}))
        with A.proxy_for(t, store) as (url, _tap):
            if leg == "open":
                ticket_writer.open_case_ticket(run, proxy_url=url, **kw)
            else:
                S.ticket_writer().record_case_ticket(run, proxy_url=url, **kw)
        return S.receipt(rec.run_dir_at), up


@pytest.mark.parametrize("status", [404, 422, 500])
def test_t4_a_store_refusing_the_open_leg_is_reported_with_its_status_and_reason(
        tmp_path, data_root, caplog, status):
    """The store answering the case ticket with a 4xx or 5xx leaves an error receipt quoting
    `HTTP <status>` and the store's reason, as the docker path does. O7, A9."""
    receipt, up = _leg(tmp_path, data_root, status, "open", caplog)

    assert [s.method for s in up.seen] == ["POST"], "control: the store was asked"
    assert receipt is not None, "the refusal left no receipt"
    assert receipt["ok"] is False
    assert f"HTTP {status}" in receipt["reason"], receipt
    assert REASON in receipt["reason"], receipt
    assert H.CANARY_KEY not in json.dumps(receipt)


def test_t4_a_409_on_the_open_leg_is_the_case_already_existing(tmp_path, data_root, caplog):
    """A 409 on the open leg is logged as the case already existing and leaves no error
    receipt, so the record leg goes on. O7, A9."""
    receipt, up = _leg(tmp_path, data_root, 409, "open", caplog)

    assert [s.method for s in up.seen] == ["POST"], "control: the store was asked"
    assert "already exists (409)" in caplog.text
    assert receipt is None


@pytest.mark.parametrize("status", [404, 409, 422, 500])
def test_t4_a_store_refusing_the_record_comment_is_reported_with_its_status_and_reason(
        tmp_path, data_root, caplog, status):
    """The store answering the record comment with a 4xx or 5xx leaves an error receipt quoting
    `HTTP <status>` and the store's reason. O7, A9."""
    receipt, up = _leg(tmp_path, data_root, status, "record", caplog)

    assert [s.method for s in up.seen] == ["POST"], "control: the store was asked"
    assert receipt is not None, "the refusal left no receipt"
    assert receipt["ok"] is False
    assert f"HTTP {status}" in receipt["reason"], receipt
    assert REASON in receipt["reason"], receipt
