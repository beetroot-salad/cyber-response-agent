"""#1163 the proxy obeys only the declaration in the export `current` names: never the clone's
working tree, and a merged, published change applies from the next request."""
from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from defender.integrations import identity_adapter
from defender.kit.faults import ConfigFault
from defender.systems.verbs import VerbContext
from defender.tests.integrations.credential_proxy_1163 import _harness as H
from defender.tests.integrations.credential_proxy_1163 import _tenant as T
from defender.tests.integrations.credential_proxy_1163._target import (
    ACCESS_FILE,
    PROXY_URL_ENV,
    proxy,
)
from defender.tests.tenancy.tenant_1108_p4._support import DEFENDER, current_commit

GRANT = {("identity", "r")}
ACCESS = ACCESS_FILE.format(system="identity")


def test_d1_a_merged_removal_applies_from_the_next_request(tmp_path, data_root):
    """A base removed by a merged, published change is refused on the next request with the
    same token, which names no commit. O2, P-2."""
    with H.upstream() as up, T.identity_via_proxy(
            tmp_path / "forge", data_root, H.declaration(up.url + "/")) as t:
        store = H.FakeStore({(t.tenant_id, "identity"): T.static_set()})
        client = TestClient(proxy().create_app(T.deps({t.tenant_id: T.exports_of(t)}, store)))
        tok = T.token(t.tenant_id, GRANT)
        before = T.ask(client, tok, "identity", "GET", f"{up.url}/users/x")

        merged = t.merge({ACCESS: H.declaration(f"http://127.0.0.1:{H.free_port()}/")},
                         "remove the old base")
        t.publish()
        assert current_commit(t.tenant) == merged
        after = T.ask(client, tok, "identity", "GET", f"{up.url}/users/x")

    assert (before["fault"], before["status"]) == (None, 200)
    assert after["fault"] == "ConfigFault"
    assert up.paths() == ["/users/x"]


def test_d2_a_working_tree_edit_has_no_effect(tmp_path, data_root):
    """A base added only in the clone's working tree is refused; the merged base still works.
    O2, C28."""
    with H.upstream() as merged_up, H.upstream() as wt_up, T.identity_via_proxy(
            tmp_path / "forge", data_root, H.declaration(merged_up.url + "/")) as t:
        (Path(t.clone) / ACCESS).write_text(
            H.declaration(wt_up.url + "/"),
            encoding="utf-8")
        store = H.FakeStore({(t.tenant_id, "identity"): T.static_set()})
        client = TestClient(proxy().create_app(T.deps({t.tenant_id: T.exports_of(t)}, store)))
        tok = T.token(t.tenant_id, GRANT)
        refused = T.ask(client, tok, "identity", "GET", f"{wt_up.url}/users/x")
        control = T.ask(client, tok, "identity", "GET", f"{merged_up.url}/users/x")

    assert refused["fault"] == "ConfigFault"
    assert wt_up.seen == []
    assert (control["fault"], merged_up.paths()) == (None, ["/users/x"])


def test_d3_learning_preflight_over_the_working_tree_is_refused_not_widened(tmp_path, data_root):
    """Preflight resolves its record over the working tree (C34); a base present only there
    reaches nothing and is a `ConfigFault`, as for a run. O2."""
    from defender.systems.run_tenant import run_tenant_for

    with H.upstream() as merged_up, H.upstream() as wt_up, T.identity_via_proxy(
            tmp_path / "forge", data_root, H.declaration(merged_up.url + "/")) as t:
        (Path(t.clone) / ACCESS).write_text(H.declaration(wt_up.url + "/"),
                                            encoding="utf-8")
        record = run_tenant_for(t.tenant, dispatches_lead_zero=False)  # the working tree (C34)
        store = H.FakeStore({(t.tenant_id, "identity"): T.static_set()})
        app = proxy().create_app(T.deps({t.tenant_id: T.exports_of(t)}, store))
        with H.serve_asgi(app) as proxy_url:
            ctx = VerbContext(defender_dir=DEFENDER, run_dir=tmp_path / "episode",
                              env={PROXY_URL_ENV: proxy_url}, tenant=record,
                              request_token=T.token(t.tenant_id, GRANT))
            with pytest.raises(ConfigFault):
                identity_adapter.get_user(ctx, user="dev.dana")

    assert wt_up.seen == []
    assert merged_up.seen == []
