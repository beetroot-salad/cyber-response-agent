"""#1163 learning preflight reaches an `http-proxy` system through the proxy with a read grant on
the source run's http-proxy systems (H12), and a working-tree base that differs from `current`
degrades to drift `unknown` with nothing sent outside the merged declaration (A3)."""
from __future__ import annotations

import json

import pytest

from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A
from defender.tests.integrations.credential_proxy_1163 import _harness as H
from defender.tests.integrations.credential_proxy_1163 import _tenant as T
from defender.tests.integrations.credential_proxy_1163._target import ACCESS_FILE, proxy
from defender.tests.learning.oracle.live_contracts import _spec1224 as S
from defender.tests.tenancy.tenant_1108_p4._support import (
    bind_forge,
    default_issuer_config,
    published_tenant,
)

pytestmark = pytest.mark.e2e

API = "/api"
ROLE, SECRET = "role-1163-learning", "secret-1163-learning"
FIXTURE_SYSTEMS = ("identity", "ticket", "host-state", "threat-intel", "change-mgmt",
                   "elastic", "cmdb", "case-history")
#: `idp` is a tenant-only name: no product allowlist knows it (A6). Its `query` goes through the
#: shared transport; its other verbs answer locally.
IDP_ADAPTER = '''\
from defender.integrations import _stub_transport as transport
from defender.kit.verbs import VerbContext, verb


def check_settings(*_a, **_k):
    return None


@verb()
def query(ctx: VerbContext, *, q: str = "*", start: str = "", end: str = "",
          limit: int = 50) -> dict:
    config = transport.load_config(ctx, "idp", "IDP")
    return transport.http_get(ctx, config, "/events", system="idp", params={"q": q})


@verb()
def lookup(ctx: VerbContext, *, entity: str) -> dict:
    return {}


@verb()
def health_check(ctx: VerbContext) -> dict:
    return {}


@verb(verb_class="rw")
def isolate(ctx: VerbContext, *, host: str) -> dict:
    return {}


VERBS = {"query": query, "lookup": lookup, "health-check": health_check, "isolate": isolate}
'''


def _preflight(tmp_path, monkeypatch, data_root, *, working_tree_edit: bool):
    S.T.isolate_learning_state(tmp_path, monkeypatch)
    est = S.estate(tmp_path)
    (est.adapters / "idp_adapter.py").write_text(IDP_ADAPTER, encoding="utf-8")
    calls = S.default_calls()
    idp = [c for c in calls if c.system == "idp"][0]
    with H.upstream() as merged, H.upstream() as wt:
        merged.replies[f"{API}/events"] = (200, {"Content-Type": "application/json"},
                                           json.dumps(idp.payload).encode())
        files = {"settings/verb-grants.yaml": est.table(),
                 **{f"settings/systems/{s}/config.env": None for s in FIXTURE_SYSTEMS},
                 **A.system_files("idp", H.declaration(merged.url + API))}
        with published_tenant(tmp_path / "forge", root=data_root, tenant_id=S.FIXTURE_TENANT,
                              files=files) as t:
            if working_tree_edit:  # an unmerged edit in the clone's working tree (C28, C34)
                (t.clone / ACCESS_FILE.format(system="idp")).write_text(
                    H.declaration(wt.url + API), encoding="utf-8")
            # The launcher signs in-process with the tenant's own issuer config (A11): no signer
            # is injected, the OpenBao stand-in is the transport.
            bind_forge(t)
            A.bind_issuer(data_root, S.FIXTURE_TENANT, default_issuer_config(t).parent,
                          role_id=ROLE, secret_id=SECRET)
            bao, tap_holder = A.OpenBaoStandIn({ROLE: SECRET}), {}
            store = H.FakeStore({(S.FIXTURE_TENANT, "idp"): T.static_set()})
            with A.proxy_for(t, store) as (url, tap):
                tap_holder["tap"] = tap
                run = S.launch(tmp_path, est, calls=calls, oracle=S.oracle(
                    then=S.submit(idp.payload, S.EMPTY_CLAIM)),
                    verifier=S.passing_verifier(), issuer_transport=bao, proxy_url=url)
        outcome = S.read_outcome(run.ep)
    return run, outcome, bao, tap_holder["tap"], merged, wt


def test_p1_preflight_reads_idp_through_the_proxy_with_a_read_grant_on_http_proxy_systems(
        tmp_path, monkeypatch, data_root):
    """Control: served by the merged base, read grant on idp alone, signed with the tenant's own
    login and key; spawned children carry no token. H12, A7, A11, O10."""
    run, outcome, bao, tap, merged, wt = _preflight(
        tmp_path, monkeypatch, data_root, working_tree_edit=False)
    assert run.rc == 0, run.message
    assert merged.paths() == [f"{API}/events"]
    assert merged.seen[0].headers.get("Authorization") == f"Bearer {H.CANARY_KEY}"
    assert bao.logins == [(ROLE, SECRET)], "the tenant's own issuer login"
    (sign,) = bao.signs
    assert bao.role_of(sign) == ROLE
    assert sign.key == proxy().transit_key_for(S.FIXTURE_TENANT), "the tenant's own transit key (A11)"
    claims = A.claims_of_payload(sign.payload)
    assert (claims["tenant"], A.grant_of(claims)) == (S.FIXTURE_TENANT, [("idp", "r")])
    assert tap.tokens
    assert all(A.SIGNATURE_CANARY in tok for tok in tap.tokens)
    assert [d for d in outcome["drift"] if d["system"] == "idp"] == []
    assert wt.seen == []
    # O10: curators and the author carry no token or signature in argv or env.
    assert run.spawn.launches, "positive control: children were spawned"
    for launch in run.spawn.launches:
        assert A.SIGNATURE_CANARY not in " ".join(launch["argv"])
        assert A.SIGNATURE_CANARY not in "\n".join(f"{k}={v}" for k, v in launch["env"].items())
        assert not [t for t in tap.tokens if t in " ".join(launch["argv"]) + str(launch["env"])]


def test_p2_a_working_tree_base_that_differs_from_current_is_drift_unknown_and_sent_nowhere(
        tmp_path, monkeypatch, data_root):
    """The proxy refuses the working tree's base (it applies `current`); preflight records the
    idp call as drift `unknown`, and neither upstream is reached. A3, O2."""
    run, outcome, bao, tap, merged, wt = _preflight(
        tmp_path, monkeypatch, data_root, working_tree_edit=True)
    assert outcome is not None, run.message  # the outcome is written before any sibling
    assert [d["status"] for d in outcome["drift"] if d["system"] == "idp"] == ["unknown"]
    assert tap.tokens, "positive control: the proxy was asked"
    assert merged.seen == []
    assert wt.seen == []
