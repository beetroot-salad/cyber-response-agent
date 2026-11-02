"""#1163 r7 A21: the system's own timeout travels with the request, the proxy runs the whole
request inside one deadline built from it, and the caller waits past that deadline, so the proxy
has given up before the caller does."""
from __future__ import annotations

import json
import time

import pytest

from defender.integrations import identity_adapter
from defender.kit.faults import TransportFault
from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A
from defender.tests.integrations.credential_proxy_1163 import _harness as H
from defender.tests.integrations.credential_proxy_1163 import _tenant as T
from defender.tests.integrations.credential_proxy_1163._target import PROXY_PATH
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
    than that timeout: a proxy answering after it still gets its answer through. r7 A21."""
    answer = {"status": 200, "headers": {}, "body": json.dumps({"user": "dev.dana"}),
              "fault": None, "detail": None}
    with H.upstream() as up, _identity_with_timeout(tmp_path / "forge", data_root, up, "1") as t, \
            H.upstream() as fake_proxy:
        fake_proxy.replies[PROXY_PATH] = _slow(
            (200, {"Content-Type": "application/json"}, json.dumps(answer).encode()))
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
