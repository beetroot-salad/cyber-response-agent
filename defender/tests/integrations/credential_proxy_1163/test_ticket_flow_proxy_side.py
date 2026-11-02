"""#1163/#1359 (proxy side): the record leg reports the case system's own refusal by its status
and the store's unreachability as such, as on the docker path."""
from __future__ import annotations

import json
import logging

import pytest

from defender.kit.faults import TransportFault
from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A
from defender.tests.integrations.credential_proxy_1163 import _harness as H
from defender.tests.integrations.credential_proxy_1163 import _tenant as T
from defender.tests.integrations.credential_proxy_1163.test_ticket_flow import (
    COMMENT,
    KEY,
    SYSTEM,
    _decl,
    _leg,
    _published,
    _run,
)
from defender.tests.tenancy.tenant_1107_settings import _spec1107 as S

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
